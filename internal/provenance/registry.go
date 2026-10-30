package provenance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const registryResponseLimit = 4 << 20

// RegistryResolver resolves public registry metadata without using local registry
// configuration or credentials. Metadata identifies bytes, not a publishing run.
type RegistryResolver struct {
	client *http.Client
}

// NewRegistryResolver creates an isolated, anonymous metadata client.
func NewRegistryResolver() *RegistryResolver {
	return &RegistryResolver{client: &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			IdleConnTimeout:        30 * time.Second,
			MaxIdleConns:           10,
			MaxConnsPerHost:        4,
			MaxResponseHeaderBytes: 64 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("registry redirects are disabled")
		},
	}}
}

var (
	registryVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+!-]{0,199}$`)
	registrySemverPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	registryNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	npmNamePattern         = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	ociPartPattern         = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	ociTagPattern          = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	mavenGroupPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$`)
)

// Resolve retrieves only metadata, never package payloads. An unresolved
// identity is returned with Problem set; a failed lookup returns an error.
func (r *RegistryResolver) Resolve(ctx context.Context, c Candidate) ([]Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pinnedOCI := c.Kind == "oci" && ValidDigest(c.Digest)
	if !pinnedOCI {
		c.Digest = ""
	}
	c.URL = ""
	if !pinnedOCI && !exactRegistryVersion(c.Version) && !(c.Kind == "oci" && ValidDigest(c.Version)) {
		return unresolvedRegistry(c, "an exact literal version is required"), nil
	}
	switch c.Kind {
	case "oci":
		return r.resolveOCI(ctx, c)
	case "npm":
		return r.resolveNPM(ctx, c)
	case "pypi":
		return r.resolvePyPI(ctx, c)
	case "crate":
		return r.resolveCrate(ctx, c)
	case "gem":
		return r.resolveGem(ctx, c)
	case "maven":
		return r.resolveMaven(ctx, c)
	default:
		return unresolvedRegistry(c, "unsupported public registry kind"), nil
	}
}

func exactRegistryVersion(version string) bool {
	if !registryVersionPattern.MatchString(version) || version == "." || version == ".." {
		return false
	}
	for _, component := range strings.Split(version, ".") {
		if strings.EqualFold(component, "x") {
			return false
		}
	}
	switch strings.ToLower(version) {
	case "latest", "release", "stable", "next", "nightly", "edge", "main", "master", "dev":
		return false
	}
	return true
}

func unresolvedRegistry(c Candidate, problem string) []Candidate {
	if c.Kind != "oci" || !ValidDigest(c.Digest) {
		c.Digest = ""
	}
	c = registryProblem(c, problem)
	return []Candidate{c}
}

func registryProblem(c Candidate, problem string) Candidate {
	if c.Problem != "" {
		c.Problem += "; "
	}
	c.Problem += problem
	return c
}

func registryEvidence(c Candidate) Candidate {
	if c.Evidence != "" {
		c.Evidence += "; "
	}
	c.Evidence += "public registry metadata alone does not establish producer identity"
	return c
}

type registryHTTPError struct{ status int }

func (e *registryHTTPError) Error() string {
	return fmt.Sprintf("public registry metadata request failed (HTTP %d)", e.status)
}

func allowedRegistryURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return false
	}
	switch u.Host {
	case "ghcr.io", "registry-1.docker.io", "auth.docker.io", "registry.npmjs.org",
		"pypi.org", "crates.io", "rubygems.org", "repo.maven.apache.org":
		return true
	default:
		return false
	}
}

func (r *RegistryResolver) get(ctx context.Context, endpoint, accept, bearer string, limit int64) ([]byte, http.Header, error) {
	u, err := url.Parse(endpoint)
	if err != nil || !allowedRegistryURL(u) {
		return nil, nil, errors.New("public registry endpoint is not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, errors.New("cannot construct public registry request")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "gh-secure-provenance")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := r.client
	if client == nil {
		client = NewRegistryResolver().client
	}
	// Copy to enforce the policy even when a test supplies a custom client.
	isolated := *client
	isolated.Jar = nil
	isolated.Timeout = 20 * time.Second
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("registry redirects are disabled")
	}
	resp, err := isolated.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("public registry metadata request canceled: %w", ctx.Err())
		}
		return nil, nil, errors.New("public registry metadata request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, &registryHTTPError{status: resp.StatusCode}
	}
	if resp.ContentLength > limit {
		return nil, nil, errors.New("public registry metadata response exceeds size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("public registry metadata read canceled: %w", ctx.Err())
		}
		return nil, nil, errors.New("cannot read public registry metadata")
	}
	if int64(len(body)) > limit {
		return nil, nil, errors.New("public registry metadata response exceeds size limit")
	}
	return body, resp.Header, nil
}

func (r *RegistryResolver) getJSON(ctx context.Context, endpoint string, target any) error {
	body, _, err := r.get(ctx, endpoint, "application/json", "", registryResponseLimit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return errors.New("invalid public registry metadata JSON")
	}
	return nil
}

func registrySHA(value string) string {
	digest := "sha256:" + value
	if !ValidDigest(digest) {
		return ""
	}
	return digest
}

func publicDownloadURL(raw, host string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != host || u.User != nil ||
		u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" || u.Path == "" {
		return ""
	}
	return u.String()
}

func (r *RegistryResolver) resolveNPM(ctx context.Context, c Candidate) ([]Candidate, error) {
	if !registrySemverPattern.MatchString(c.Version) {
		return unresolvedRegistry(c, "an exact npm semantic version is required; dist-tags and ranges are not immutable"), nil
	}
	if len(c.Name) > 214 || !npmNamePattern.MatchString(c.Name) || strings.Contains(c.Name, "..") {
		return unresolvedRegistry(c, "invalid npm package name"), nil
	}
	var metadata struct {
		Dist struct {
			Integrity string `json:"integrity"`
			Tarball   string `json:"tarball"`
		} `json:"dist"`
	}
	endpoint := "https://registry.npmjs.org/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Version)
	if err := r.getJSON(ctx, endpoint, &metadata); err != nil {
		return nil, err
	}
	c = registryEvidence(c)
	c.URL = publicDownloadURL(metadata.Dist.Tarball, "registry.npmjs.org")
	for _, integrity := range strings.Fields(metadata.Dist.Integrity) {
		encoded, ok := strings.CutPrefix(integrity, "sha256-")
		if !ok {
			continue
		}
		digest, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, errors.New("npm metadata has malformed SHA256 integrity encoding")
		}
		if len(digest) != sha256.Size {
			return unresolvedRegistry(c, "npm metadata has invalid SHA256 integrity"), nil
		}
		value := "sha256:" + hex.EncodeToString(digest)
		if c.Digest != "" && c.Digest != value {
			return unresolvedRegistry(c, "npm metadata has conflicting SHA256 integrity"), nil
		}
		c.Digest = value
	}
	if c.Digest == "" {
		return unresolvedRegistry(c, "npm metadata has no SHA256 integrity (SHA1 and SHA512 are not SHA256 identities)"), nil
	}
	return []Candidate{c}, nil
}

func (r *RegistryResolver) resolvePyPI(ctx context.Context, c Candidate) ([]Candidate, error) {
	if !registryNamePattern.MatchString(c.Name) || c.Name == "." || c.Name == ".." {
		return unresolvedRegistry(c, "invalid PyPI project name"), nil
	}
	var metadata struct {
		URLs []struct {
			URL     string            `json:"url"`
			Digests map[string]string `json:"digests"`
		} `json:"urls"`
	}
	endpoint := "https://pypi.org/pypi/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Version) + "/json"
	if err := r.getJSON(ctx, endpoint, &metadata); err != nil {
		return nil, err
	}
	c = registryEvidence(c)
	if len(metadata.URLs) == 0 {
		return unresolvedRegistry(c, "PyPI metadata has no distribution files"), nil
	}
	results := make([]Candidate, 0, len(metadata.URLs))
	for _, file := range metadata.URLs {
		output := c
		output.Digest = registrySHA(file.Digests["sha256"])
		output.URL = publicDownloadURL(file.URL, "files.pythonhosted.org")
		if output.Digest == "" {
			output = registryProblem(output, "PyPI distribution has no valid SHA256 digest")
		}
		if output.URL == "" {
			output = registryProblem(output, "PyPI distribution URL is not an allowed public download")
		}
		results = append(results, output)
	}
	return results, nil
}

func (r *RegistryResolver) resolveCrate(ctx context.Context, c Candidate) ([]Candidate, error) {
	if !registrySemverPattern.MatchString(c.Version) {
		return unresolvedRegistry(c, "an exact crate semantic version is required"), nil
	}
	if !registryNamePattern.MatchString(c.Name) || strings.Contains(c.Name, ".") {
		return unresolvedRegistry(c, "invalid crate name"), nil
	}
	var metadata struct {
		Version struct {
			Checksum string `json:"checksum"`
		} `json:"version"`
	}
	endpoint := "https://crates.io/api/v1/crates/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Version)
	if err := r.getJSON(ctx, endpoint, &metadata); err != nil {
		return nil, err
	}
	c = registryEvidence(c)
	c.URL = "https://static.crates.io/crates/" + url.PathEscape(c.Name) + "/" + url.PathEscape(c.Name+"-"+c.Version+".crate")
	c.Digest = registrySHA(metadata.Version.Checksum)
	if c.Digest == "" {
		return unresolvedRegistry(c, "crate metadata has no valid SHA256 checksum"), nil
	}
	return []Candidate{c}, nil
}

func (r *RegistryResolver) resolveGem(ctx context.Context, c Candidate) ([]Candidate, error) {
	if !registryNamePattern.MatchString(c.Name) || c.Name == "." || c.Name == ".." {
		return unresolvedRegistry(c, "invalid gem name"), nil
	}
	var metadata struct {
		SHA string `json:"sha"`
	}
	endpoint := "https://rubygems.org/api/v2/rubygems/" + url.PathEscape(c.Name) + "/versions/" + url.PathEscape(c.Version) + ".json"
	if err := r.getJSON(ctx, endpoint, &metadata); err != nil {
		return nil, err
	}
	c = registryEvidence(c)
	c.URL = "https://rubygems.org/downloads/" + url.PathEscape(c.Name+"-"+c.Version+".gem")
	c.Digest = registrySHA(metadata.SHA)
	if c.Digest == "" {
		return unresolvedRegistry(c, "RubyGems metadata has no valid SHA256 checksum"), nil
	}
	return []Candidate{c}, nil
}

func (r *RegistryResolver) resolveMaven(ctx context.Context, c Candidate) ([]Candidate, error) {
	group, artifact, ok := strings.Cut(c.Name, ":")
	if !ok || !mavenGroupPattern.MatchString(group) || !registryNamePattern.MatchString(artifact) ||
		artifact == "." || artifact == ".." || strings.Contains(artifact, "..") ||
		strings.HasSuffix(strings.ToUpper(c.Version), "-SNAPSHOT") {
		return unresolvedRegistry(c, "invalid or mutable Maven coordinates"), nil
	}
	c.URL = "https://repo.maven.apache.org/maven2/" + strings.ReplaceAll(group, ".", "/") + "/" +
		url.PathEscape(artifact) + "/" + url.PathEscape(c.Version) + "/" + url.PathEscape(artifact+"-"+c.Version+".jar")
	body, _, err := r.get(ctx, c.URL+".sha256", "text/plain", "", 1024)
	c = registryEvidence(c)
	if err != nil {
		var status *registryHTTPError
		if errors.As(err, &status) && status.status == http.StatusNotFound {
			return unresolvedRegistry(c, "Maven SHA256 checksum is unavailable; immutable identity is unknown"), nil
		}
		return nil, err
	}
	c.Digest = registrySHA(strings.TrimSpace(string(body)))
	if c.Digest == "" {
		return unresolvedRegistry(c, "Maven metadata has no valid SHA256 checksum"), nil
	}
	return []Candidate{c}, nil
}

const manifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"

func (r *RegistryResolver) resolveOCI(ctx context.Context, c Candidate) ([]Candidate, error) {
	reference := c.Version
	if ValidDigest(c.Digest) {
		if ValidDigest(c.Version) && c.Version != c.Digest {
			return nil, errors.New("conflicting pinned OCI digests")
		}
		reference = c.Digest
	}
	host, repository, ok := strings.Cut(c.Name, "/")
	if !ok || (host != "ghcr.io" && host != "docker.io") || len(repository) > 255 ||
		!strings.Contains(repository, "/") || (!ValidDigest(reference) && !ociTagPattern.MatchString(reference)) {
		return unresolvedRegistry(c, "invalid or unsupported fully qualified OCI reference"), nil
	}
	for _, part := range strings.Split(repository, "/") {
		if !ociPartPattern.MatchString(part) {
			return unresolvedRegistry(c, "invalid OCI repository name"), nil
		}
	}
	apiHost, service, tokenEndpoint := "ghcr.io", "ghcr.io", "https://ghcr.io/token"
	if host == "docker.io" {
		apiHost, service, tokenEndpoint = "registry-1.docker.io", "registry.docker.io", "https://auth.docker.io/token"
	}
	endpoint := "https://" + apiHost + "/v2/" + repository + "/manifests/" + url.PathEscape(reference)
	body, headers, err := r.get(ctx, endpoint, manifestAccept, "", registryResponseLimit)
	var status *registryHTTPError
	if errors.As(err, &status) && status.status == http.StatusUnauthorized {
		bearer, tokenErr := r.ociToken(ctx, headers.Values("WWW-Authenticate"), tokenEndpoint, service, repository)
		if tokenErr != nil {
			return nil, tokenErr
		}
		body, headers, err = r.get(ctx, endpoint, manifestAccept, bearer, registryResponseLimit)
	}
	if err != nil {
		return nil, err
	}
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil || manifest.SchemaVersion != 2 {
		return nil, errors.New("invalid public OCI manifest")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	for _, reported := range headers.Values("Docker-Content-Digest") {
		if reported != digest {
			return nil, errors.New("OCI manifest digest does not match registry header")
		}
	}
	if ValidDigest(reference) && reference != digest {
		return nil, errors.New("OCI manifest digest does not match requested digest")
	}
	c.Digest = digest
	c.URL = endpoint
	c = registryEvidence(c)
	if !ValidDigest(reference) {
		c.Evidence += "; OCI tag resolved at lookup time and is not immutable"
	}
	return []Candidate{c}, nil
}

var bearerParameterPattern = regexp.MustCompile(`^([A-Za-z]+)="([^"\\]*)"`)

func (r *RegistryResolver) ociToken(ctx context.Context, challenges []string, endpoint, service, repository string) (string, error) {
	badChallenge := errors.New("public OCI registry supplied an unsupported authentication challenge")
	if len(challenges) != 1 {
		return "", badChallenge
	}
	scheme, parameters, ok := strings.Cut(challenges[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", badChallenge
	}
	values := make(map[string]string)
	for {
		parameters = strings.TrimSpace(parameters)
		matches := bearerParameterPattern.FindStringSubmatch(parameters)
		if matches == nil {
			return "", badChallenge
		}
		key := strings.ToLower(matches[1])
		if _, exists := values[key]; exists {
			return "", badChallenge
		}
		values[key] = matches[2]
		parameters = strings.TrimSpace(parameters[len(matches[0]):])
		if parameters == "" {
			break
		}
		if !strings.HasPrefix(parameters, ",") {
			return "", badChallenge
		}
		parameters = parameters[1:]
	}
	scope := "repository:" + repository + ":pull"
	if len(values) != 3 || values["realm"] != endpoint || values["service"] != service || values["scope"] != scope {
		return "", badChallenge
	}
	query := url.Values{"service": {service}, "scope": {scope}}
	body, _, err := r.get(ctx, endpoint+"?"+query.Encode(), "application/json", "", 64<<10)
	if err != nil {
		return "", err
	}
	var response struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", errors.New("invalid public OCI token response")
	}
	token := response.Token
	if token == "" {
		token = response.AccessToken
	}
	if token == "" || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("invalid public OCI anonymous token")
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return "", errors.New("invalid public OCI anonymous token")
		}
	}
	return token, nil
}

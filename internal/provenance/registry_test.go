package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type registryRoundTripper func(*http.Request) (*http.Response, error)

func (f registryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func registryTestResolver(t *testing.T, handler func(*http.Request) (int, http.Header, string)) *RegistryResolver {
	t.Helper()
	return &RegistryResolver{client: &http.Client{Transport: registryRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", req.Method)
		}
		if req.URL.Scheme != "https" || req.URL.User != nil {
			t.Errorf("unsafe request URL: %v", req.URL)
		}
		status, headers, body := handler(req)
		return &http.Response{
			StatusCode: status,
			Header:     headers,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})}}
}

func TestRegistryMetadataResolvers(t *testing.T) {
	hash := strings.Repeat("a", 64)
	integrity := base64.StdEncoding.EncodeToString(bytesForRegistryTest(32, 0xaa))
	tests := []struct {
		name      string
		candidate Candidate
		endpoint  string
		body      string
		download  string
	}{
		{
			name:      "scoped npm",
			candidate: Candidate{Kind: "npm", Name: "@owner/pkg", Version: "1.2.3-beta+build"},
			endpoint:  "https://registry.npmjs.org/@owner%2Fpkg/1.2.3-beta+build",
			body:      `{"unknown":{"future":true},"dist":{"integrity":"sha512-ignored sha256-` + integrity + `","tarball":"https://registry.npmjs.org/@owner/pkg/-/pkg-1.2.3.tgz","shasum":"ignored"}}`,
			download:  "https://registry.npmjs.org/@owner/pkg/-/pkg-1.2.3.tgz",
		},
		{
			name:      "pypi",
			candidate: Candidate{Kind: "pypi", Name: "My_Project", Version: "1.2.3"},
			endpoint:  "https://pypi.org/pypi/My_Project/1.2.3/json",
			body:      `{"urls":[{"digests":{"sha256":"` + hash + `"},"url":"https://files.pythonhosted.org/packages/pkg.whl"}],"future":true}`,
			download:  "https://files.pythonhosted.org/packages/pkg.whl",
		},
		{
			name:      "crate",
			candidate: Candidate{Kind: "crate", Name: "some-crate", Version: "1.2.3"},
			endpoint:  "https://crates.io/api/v1/crates/some-crate/1.2.3",
			body:      `{"version":{"checksum":"` + hash + `","future":true},"future":{}}`,
			download:  "https://static.crates.io/crates/some-crate/some-crate-1.2.3.crate",
		},
		{
			name:      "gem",
			candidate: Candidate{Kind: "gem", Name: "some_gem", Version: "1.2.3"},
			endpoint:  "https://rubygems.org/api/v2/rubygems/some_gem/versions/1.2.3.json",
			body:      `{"sha":"` + hash + `","future":null}`,
			download:  "https://rubygems.org/downloads/some_gem-1.2.3.gem",
		},
		{
			name:      "maven",
			candidate: Candidate{Kind: "maven", Name: "org.example:artifact", Version: "1.2.3"},
			endpoint:  "https://repo.maven.apache.org/maven2/org/example/artifact/1.2.3/artifact-1.2.3.jar.sha256",
			body:      hash + "\n",
			download:  "https://repo.maven.apache.org/maven2/org/example/artifact/1.2.3/artifact-1.2.3.jar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			resolver := registryTestResolver(t, func(req *http.Request) (int, http.Header, string) {
				calls++
				if got := req.URL.String(); got != tt.endpoint {
					t.Errorf("endpoint = %s, want %s", got, tt.endpoint)
				}
				if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
					t.Error("metadata request contains credentials")
				}
				return http.StatusOK, nil, tt.body
			})
			input := tt.candidate
			input.Workflow, input.Job, input.RunID = "publish.yml", "publish", 42
			input.SHA, input.RunURL, input.Evidence = "source-sha", "https://github.com/o/r/actions/runs/42", "workflow"
			input.Problem = "publication execution is unproven"
			results, err := resolver.Resolve(context.Background(), input)
			if err != nil || len(results) != 1 {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
			got := results[0]
			if got.Digest != "sha256:"+hash || got.URL != tt.download || got.Problem != input.Problem {
				t.Errorf("result = %#v", got)
			}
			if got.RunID != input.RunID || got.Workflow != input.Workflow || got.Job != input.Job ||
				got.SHA != input.SHA || got.RunURL != input.RunURL || !strings.Contains(got.Evidence, "metadata alone does not establish producer") {
				t.Errorf("lost run context or overstated evidence: %#v", got)
			}
			if calls != 1 {
				t.Errorf("calls = %d, want metadata only", calls)
			}
		})
	}
}

func TestRegistryPreservesAndAppendsDiagnostics(t *testing.T) {
	tests := []struct {
		candidate Candidate
		body      string
		want      []string
	}{
		{Candidate{Kind: "npm", Name: "pkg", Version: "latest"}, "", []string{"exact literal version"}},
		{Candidate{Kind: "npm", Name: "pkg", Version: "1.2.3"}, `{"dist":{}}`, []string{"no SHA256 integrity"}},
		{Candidate{Kind: "pypi", Name: "pkg", Version: "1"}, `{"urls":[{"url":"https://evil.example/pkg"}]}`,
			[]string{"no valid SHA256 digest", "not an allowed public download"}},
	}
	for _, tt := range tests {
		t.Run(tt.candidate.Kind+"/"+tt.candidate.Version, func(t *testing.T) {
			r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				return 200, nil, tt.body
			})
			input := tt.candidate
			input.Problem = "publishing-run association is unproven"
			input.Evidence = "parent scanner evidence"
			input.Workflow, input.Job, input.RunID = "publish.yml", "publish", 42
			input.RunURL, input.SHA = "https://github.com/o/r/actions/runs/42", "source-sha"
			results, err := r.Resolve(context.Background(), input)
			if err != nil || len(results) != 1 {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
			got := results[0]
			if !strings.HasPrefix(got.Problem, input.Problem+"; ") {
				t.Errorf("lost incoming diagnostic: %q", got.Problem)
			}
			for _, diagnostic := range tt.want {
				if !strings.Contains(got.Problem, diagnostic) {
					t.Errorf("missing appended diagnostic %q: %q", diagnostic, got.Problem)
				}
			}
			if got.Workflow != input.Workflow || got.Job != input.Job || got.RunID != input.RunID ||
				got.RunURL != input.RunURL || got.SHA != input.SHA || !strings.HasPrefix(got.Evidence, input.Evidence) ||
				got.Kind != input.Kind || got.Name != input.Name || got.Version != input.Version {
				t.Errorf("lost parent context: %#v", got)
			}
		})
	}
}

func TestRegistryMetadataPreservesProvenPublicationEvidence(t *testing.T) {
	r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
		return 200, nil, `{"sha":"` + strings.Repeat("a", 64) + `"}`
	})
	input := Candidate{Kind: "gem", Name: "pkg", Version: "1.2.3", Evidence: "literal publication proven by parent"}
	results, err := r.Resolve(context.Background(), input)
	if err != nil || len(results) != 1 {
		t.Fatalf("Resolve = %#v, %v", results, err)
	}
	if results[0].Problem != "" || !strings.HasPrefix(results[0].Evidence, input.Evidence+"; ") ||
		strings.Contains(results[0].Evidence, "association is unproven") {
		t.Fatalf("registry contradicted stronger evidence: %#v", results[0])
	}
}

func TestRegistryOCIPinnedCandidateDigest(t *testing.T) {
	manifest := `{"schemaVersion":2,"manifests":[]}`
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manifest)))
	for _, version := range []string{"", "v1", "latest", digest} {
		t.Run(version, func(t *testing.T) {
			r := registryTestResolver(t, func(req *http.Request) (int, http.Header, string) {
				if req.URL.String() != "https://ghcr.io/v2/owner/image/manifests/"+digest {
					t.Errorf("did not use pinned candidate digest: %s", req.URL)
				}
				return 200, http.Header{"Docker-Content-Digest": {digest}}, manifest
			})
			input := Candidate{
				Kind: "oci", Name: "ghcr.io/owner/image", Version: version, Digest: digest,
				Workflow: "publish.yml", Job: "publish", RunID: 42, RunURL: "run-url", SHA: "source-sha",
				Problem: "parent association remains unproven", Evidence: "parent evidence",
			}
			results, err := r.Resolve(context.Background(), input)
			if err != nil || len(results) != 1 {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
			got := results[0]
			if got.Digest != digest || got.Version != version || got.Problem != input.Problem ||
				got.Workflow != input.Workflow || got.Job != input.Job || got.RunID != input.RunID ||
				got.RunURL != input.RunURL || got.SHA != input.SHA || !strings.HasPrefix(got.Evidence, input.Evidence+"; ") ||
				strings.Contains(got.Evidence, "tag resolved") {
				t.Fatalf("pinned identity or parent context lost: %#v", got)
			}
		})
	}
	for _, tt := range []struct {
		name, version, body string
	}{
		{"mismatch", "", `{"schemaVersion":2}`},
		{"conflicting pins", "sha256:" + strings.Repeat("0", 64), manifest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				if tt.name == "conflicting pins" {
					t.Fatal("conflicting pins made a request")
				}
				return 200, nil, tt.body
			})
			if _, err := r.Resolve(context.Background(), Candidate{
				Kind: "oci", Name: "ghcr.io/owner/image", Version: tt.version, Digest: digest,
			}); err == nil {
				t.Fatal("conflicting manifest digest accepted")
			}
		})
	}
}

func bytesForRegistryTest(n int, value byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func TestRegistryPyPIAllDistributions(t *testing.T) {
	hash := strings.Repeat("b", 64)
	resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
		return 200, nil, `{"urls":[
			{"digests":{"sha256":"` + hash + `"},"url":"https://files.pythonhosted.org/a.whl"},
			{"digests":{"sha256":"` + hash + `"},"url":"https://files.pythonhosted.org/a.tar.gz"},
			{"digests":{},"url":"https://files.pythonhosted.org/b.whl"},
			{"digests":{"sha256":"` + hash + `"},"url":"https://evil.example/a.whl"}]}`
	})
	results, err := resolver.Resolve(context.Background(), Candidate{Kind: "pypi", Name: "pkg", Version: "1.0"})
	if err != nil || len(results) != 4 {
		t.Fatalf("Resolve = %#v, %v", results, err)
	}
	if results[0].URL == results[1].URL || results[0].Problem != "" || results[1].Problem != "" ||
		results[2].Digest != "" || results[2].Problem == "" || results[3].URL != "" || results[3].Problem == "" {
		t.Fatalf("distribution identities not retained safely: %#v", results)
	}
}

func TestRegistryUnresolvedMetadata(t *testing.T) {
	tests := []struct {
		kind, name, body string
		status           int
	}{
		{"npm", "pkg", `{"dist":{"shasum":"` + strings.Repeat("a", 40) + `"}}`, 200},
		{"npm", "pkg", `{"dist":{"integrity":"sha512-YWJj"}}`, 200},
		{"npm", "pkg", `{"dist":{"integrity":"sha256-YWJj"}}`, 200},
		{"npm", "pkg", `{"dist":{"integrity":"sha256-` + base64.StdEncoding.EncodeToString(bytesForRegistryTest(32, 1)) + ` sha256-` + base64.StdEncoding.EncodeToString(bytesForRegistryTest(32, 2)) + `"}}`, 200},
		{"pypi", "pkg", `{"urls":[]}`, 200},
		{"crate", "pkg", `{"version":{}}`, 200},
		{"gem", "pkg", `{"sha":"` + strings.Repeat("A", 64) + `"}`, 200},
		{"gem", "pkg", `null`, 200},
		{"maven", "org.example:pkg", "", 404},
		{"maven", "org.example:pkg", strings.Repeat("a", 40), 200},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%s-%d", tt.kind, i), func(t *testing.T) {
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				return tt.status, nil, tt.body
			})
			results, err := resolver.Resolve(context.Background(), Candidate{
				Kind: tt.kind, Name: tt.name, Version: "1.0.0", Digest: "sha256:" + strings.Repeat("a", 64),
			})
			if err != nil || len(results) != 1 || results[0].Problem == "" || results[0].Digest != "" {
				t.Fatalf("Resolve = %#v, %v; want explicit unresolved identity", results, err)
			}
		})
	}
}

func TestRegistryRejectsUnresolvedVersions(t *testing.T) {
	kinds := map[string]string{
		"npm": "pkg", "pypi": "pkg", "crate": "pkg", "gem": "pkg",
		"maven": "org.example:pkg", "oci": "ghcr.io/owner/image",
	}
	versions := []string{"", "latest", "LATEST", "stable", "nightly", "RELEASE", "${{ inputs.version }}",
		"$VERSION", "{{version}}", "^1.0", "~1.0", ">=1.0", "1.x", "1.*", "../1.0", ".", "..", "1 2"}
	for kind, name := range kinds {
		for _, version := range versions {
			t.Run(kind+"/"+version, func(t *testing.T) {
				resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
					t.Fatal("unresolved version triggered network request")
					return 0, nil, ""
				})
				results, err := resolver.Resolve(context.Background(), Candidate{Kind: kind, Name: name, Version: version})
				if err != nil || len(results) != 1 || results[0].Problem == "" {
					t.Fatalf("Resolve = %#v, %v", results, err)
				}
			})
		}
	}
}

func TestRegistryMalformedNPMIntegrity(t *testing.T) {
	r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
		return 200, nil, `{"dist":{"integrity":"sha256-secret-invalid-base64"}}`
	})
	results, err := r.Resolve(context.Background(), Candidate{Kind: "npm", Name: "pkg", Version: "1.2.3"})
	if err == nil || len(results) != 0 || strings.Contains(err.Error(), "secret") {
		t.Fatalf("malformed integrity not safely reported: %#v, %v", results, err)
	}
}

func TestRegistryRejectsUnsafeNames(t *testing.T) {
	for _, c := range []Candidate{
		{Kind: "npm", Name: "https://evil.example/pkg", Version: "1.0.0"},
		{Kind: "npm", Name: "@owner/../pkg", Version: "1.0.0"},
		{Kind: "pypi", Name: "../pkg", Version: "1.0"},
		{Kind: "crate", Name: "foo/bar", Version: "1.0.0"},
		{Kind: "gem", Name: "foo?token=secret", Version: "1.0"},
		{Kind: "maven", Name: "org/evil:pkg", Version: "1.0"},
		{Kind: "maven", Name: "org.example:../pkg", Version: "1.0"},
		{Kind: "maven", Name: "org.example:pkg:classifier", Version: "1.0"},
		{Kind: "maven", Name: "org.example:pkg", Version: "1.0-SNAPSHOT"},
		{Kind: "oci", Name: "evil.example/owner/image", Version: "1.0"},
		{Kind: "oci", Name: "ghcr.io/owner/../image", Version: "1.0"},
		{Kind: "oci", Name: "ghcr.io/image", Version: "1.0"},
	} {
		t.Run(c.Kind+"/"+c.Name, func(t *testing.T) {
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				t.Fatal("invalid coordinates triggered network request")
				return 0, nil, ""
			})
			results, err := resolver.Resolve(context.Background(), c)
			if err != nil || len(results) != 1 || results[0].Problem == "" {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
		})
	}
}

func TestRegistryRejectsSemanticVersionAliases(t *testing.T) {
	for _, kind := range []string{"npm", "crate"} {
		for _, version := range []string{"1", "1.0", "beta", "canary", "v1.2.3", "01.2.3", "1.2.3-"} {
			t.Run(kind+"/"+version, func(t *testing.T) {
				r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
					t.Fatal("version alias triggered network request")
					return 0, nil, ""
				})
				results, err := r.Resolve(context.Background(), Candidate{Kind: kind, Name: "pkg", Version: version})
				if err != nil || len(results) != 1 || results[0].Problem == "" {
					t.Fatalf("Resolve = %#v, %v", results, err)
				}
			})
		}
	}
}

func TestRegistryDownloadURLAllowlist(t *testing.T) {
	for _, raw := range []string{
		"http://registry.npmjs.org/pkg.tgz", "https://evil.example/pkg.tgz",
		"https://registry.npmjs.org.evil.example/pkg.tgz", "https://user:secret@registry.npmjs.org/pkg.tgz",
		"https://registry.npmjs.org:443/pkg.tgz", "//registry.npmjs.org/pkg.tgz",
		"https://registry.npmjs.org/pkg.tgz?token=secret", "https://registry.npmjs.org/pkg.tgz#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				return 200, nil, `{"dist":{"integrity":"sha256-` +
					base64.StdEncoding.EncodeToString(bytesForRegistryTest(32, 1)) + `","tarball":"` + raw + `"}}`
			})
			results, err := resolver.Resolve(context.Background(), Candidate{Kind: "npm", Name: "pkg", Version: "1.0.0"})
			if err != nil || len(results) != 1 || results[0].URL != "" || !ValidDigest(results[0].Digest) {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
		})
	}
}

func TestRegistryOCIAnonymousBearer(t *testing.T) {
	manifest := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"future":true}`
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manifest)))
	for _, host := range []string{"ghcr.io", "docker.io"} {
		for _, byDigest := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/digest=%t", host, byDigest), func(t *testing.T) {
				api, service, tokenHost := "ghcr.io", "ghcr.io", "ghcr.io"
				if host == "docker.io" {
					api, service, tokenHost = "registry-1.docker.io", "registry.docker.io", "auth.docker.io"
				}
				version := "v1.0"
				if byDigest {
					version = digest
				}
				calls := 0
				resolver := registryTestResolver(t, func(req *http.Request) (int, http.Header, string) {
					calls++
					switch calls {
					case 1, 3:
						if req.URL.String() != "https://"+api+"/v2/owner/image/manifests/"+url.PathEscape(version) {
							t.Errorf("unexpected manifest endpoint: %s", req.URL)
						}
						if !strings.Contains(req.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") {
							t.Error("missing OCI content negotiation")
						}
						if calls == 1 {
							if req.Header.Get("Authorization") != "" {
								t.Error("first OCI request was not anonymous")
							}
							return 401, http.Header{"Www-Authenticate": {
								`Bearer realm="https://` + tokenHost + `/token",service="` + service + `",scope="repository:owner/image:pull"`,
							}}, ""
						}
						if req.Header.Get("Authorization") != "Bearer anonymous-scoped-token" {
							t.Error("manifest request did not use scoped token")
						}
						return 200, http.Header{"Docker-Content-Digest": {digest}}, manifest
					case 2:
						if req.URL.Host != tokenHost || req.URL.Path != "/token" || req.URL.Query().Get("service") != service ||
							req.URL.Query().Get("scope") != "repository:owner/image:pull" || len(req.URL.Query()) != 2 {
							t.Errorf("unsafe token exchange: %s", req.URL)
						}
						if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
							t.Error("token exchange sent credentials")
						}
						return 200, nil, `{"token":"anonymous-scoped-token","unknown":true}`
					default:
						t.Fatal("unexpected extra request")
						return 0, nil, ""
					}
				})
				results, err := resolver.Resolve(context.Background(), Candidate{Kind: "oci", Name: host + "/owner/image", Version: version})
				if err != nil || len(results) != 1 || results[0].Digest != digest || calls != 3 {
					t.Fatalf("Resolve = %#v, %v; calls=%d", results, err, calls)
				}
				if !strings.Contains(results[0].Evidence, "metadata alone does not establish producer") {
					t.Fatal("metadata must not establish publishing run")
				}
			})
		}
	}
}

func TestRegistryOCIRejectsUnsafeChallenges(t *testing.T) {
	valid := `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/image:pull"`
	for _, challenge := range []string{
		strings.Replace(valid, "https://ghcr.io/token", "https://evil.example/token", 1),
		strings.Replace(valid, "https://ghcr.io/token", "https://ghcr.io/token?secret=1", 1),
		strings.Replace(valid, `service="ghcr.io"`, `service="evil.example"`, 1),
		strings.Replace(valid, "repository:owner/image:pull", "repository:owner/image:pull,push", 1),
		strings.Replace(valid, "repository:owner/image:pull", "repository:other/image:pull", 1),
		`Basic realm="https://ghcr.io/token"`,
		valid + `,realm="https://evil.example/token"`,
		valid + ",",
		`Bearer realm="https://ghcr.io/token",service="ghcr.io"`,
	} {
		t.Run(challenge, func(t *testing.T) {
			calls := 0
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				calls++
				return 401, http.Header{"Www-Authenticate": {challenge}}, "secret-response-body"
			})
			_, err := resolver.Resolve(context.Background(), Candidate{Kind: "oci", Name: "ghcr.io/owner/image", Version: "v1"})
			if err == nil || calls != 1 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe challenge accepted: err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestRegistryOCIManifestValidation(t *testing.T) {
	for _, tt := range []struct {
		name, body, header, version string
		wantError                   bool
	}{
		{"raw bytes", "{ \"schemaVersion\": 2 }\n", "", "v1", false},
		{"mismatched header", `{"schemaVersion":2}`, "sha256:" + strings.Repeat("0", 64), "v1", true},
		{"malformed header", `{"schemaVersion":2}`, "sha512:abcd", "v1", true},
		{"mismatched requested digest", `{"schemaVersion":2}`, "", "sha256:" + strings.Repeat("0", 64), true},
		{"invalid JSON", `{"schemaVersion":`, "", "v1", true},
		{"schema v1", `{"schemaVersion":1}`, "", "v1", true},
		{"empty object", `{}`, "", "v1", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				headers := make(http.Header)
				if tt.header != "" {
					headers.Set("Docker-Content-Digest", tt.header)
				}
				return 200, headers, tt.body
			})
			results, err := resolver.Resolve(context.Background(), Candidate{Kind: "oci", Name: "ghcr.io/owner/image", Version: tt.version})
			if (err != nil) != tt.wantError {
				t.Fatalf("Resolve = %#v, %v", results, err)
			}
			if !tt.wantError && results[0].Digest != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(tt.body))) {
				t.Fatalf("digest was not computed over raw manifest bytes: %#v", results)
			}
		})
	}
}

func TestRegistryOCITokenValidation(t *testing.T) {
	for _, tt := range []struct {
		body      string
		status    int
		wantError bool
	}{
		{`{"access_token":"anonymous-token","future":true}`, 200, false},
		{`{"token":"anonymous-token"}`, 200, false},
		{`{"token":""}`, 200, true},
		{`{"token":"secret\ninjected"}`, 200, true},
		{`{"token":"secret\u0001control"}`, 200, true},
		{`{"token":"secret with spaces"}`, 200, true},
		{`{"token":"secret`, 200, true},
		{`{"token":"` + strings.Repeat("x", 16385) + `"}`, 200, true},
		{strings.Repeat("s", (64<<10)+1), 200, true},
		{`secret-response`, 500, true},
	} {
		t.Run(fmt.Sprintf("%d-%d", len(tt.body), tt.status), func(t *testing.T) {
			r := registryTestResolver(t, func(req *http.Request) (int, http.Header, string) {
				if req.URL.Host != "ghcr.io" || req.URL.Path != "/token" || req.Header.Get("Authorization") != "" {
					t.Errorf("unsafe anonymous exchange: %v", req.URL)
				}
				return tt.status, nil, tt.body
			})
			token, err := r.ociToken(context.Background(), []string{
				`Bearer scope="repository:owner/image:pull", realm="https://ghcr.io/token", service="ghcr.io"`,
			}, "https://ghcr.io/token", "ghcr.io", "owner/image")
			if (err != nil) != tt.wantError {
				t.Fatalf("token error = %v, wantError = %t", err, tt.wantError)
			}
			if err != nil && (token != "" || strings.Contains(err.Error(), "secret")) {
				t.Fatal("token error leaks response content")
			}
		})
	}
}

func TestRegistryMalformedAndFailedMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
	}{
		{"bad JSON", `{"secret-token":`, 200},
		{"trailing JSON", `{} {}`, 200},
		{"bad type", `{"sha":["secret-token"]}`, 200},
		{"not found", "secret-token", 404},
		{"rate limit", "secret-token", 429},
		{"server error", "secret-token", 500},
		{"too large", strings.Repeat("s", registryResponseLimit+1), 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolver := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
				return tt.status, nil, tt.body
			})
			results, err := resolver.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"})
			if err == nil || len(results) != 0 || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("lookup failure was not safely reported: %#v, %v", results, err)
			}
		})
	}
}

type registryTrackingBody struct {
	io.Reader
	closed bool
}

type registryErrorReader struct{}

func (registryErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("secret-response-read-error")
}

func TestRegistryReadFailure(t *testing.T) {
	body := &registryTrackingBody{Reader: registryErrorReader{}}
	r := NewRegistryResolver()
	r.client.Transport = registryRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: req}, nil
	})
	results, err := r.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"})
	if err == nil || len(results) != 0 || !body.closed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("read failure not safely handled: %#v, %v; closed=%t", results, err, body.closed)
	}
}

func (b *registryTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestRegistryBodyCleanup(t *testing.T) {
	for _, status := range []int{200, 401, 500} {
		for _, length := range []int64{-1, registryResponseLimit + 1} {
			t.Run(fmt.Sprintf("%d/%d", status, length), func(t *testing.T) {
				body := &registryTrackingBody{Reader: strings.NewReader(`{"sha":"invalid"}`)}
				r := &RegistryResolver{client: &http.Client{Transport: registryRoundTripper(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Body: body, ContentLength: length, Header: make(http.Header), Request: req}, nil
				})}}
				_, err := r.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"})
				wantError := status != http.StatusOK || length > registryResponseLimit
				if (err != nil) != wantError {
					t.Errorf("Resolve error = %v, wantError = %t", err, wantError)
				}
				if !body.closed {
					t.Fatal("response body was not closed")
				}
			})
		}
	}
}

func TestRegistryRedirectRefusal(t *testing.T) {
	for _, destination := range []string{"https://rubygems.org/redirected", "https://evil.example/secret"} {
		t.Run(destination, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				http.Redirect(w, req, destination, http.StatusFound)
			}))
			defer server.Close()
			local, parseErr := url.Parse(server.URL)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			defaultTransport, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				t.Fatal("default HTTP transport is not *http.Transport")
			}
			transport := defaultTransport.Clone()
			defer transport.CloseIdleConnections()
			r := NewRegistryResolver()
			r.client.Transport = registryRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "rubygems.org" {
					t.Fatalf("redirect followed to %s", req.URL.Host)
				}
				cloned := req.Clone(req.Context())
				localURL := *req.URL
				localURL.Scheme, localURL.Host = local.Scheme, local.Host
				cloned.URL = &localURL
				return transport.RoundTrip(cloned)
			})
			_, err := r.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"})
			if err == nil || calls.Load() != 1 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("redirect not safely refused: err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestRegistryCancellationAndSafeTransportErrors(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
			t.Fatal("canceled context made a request")
			return 0, nil, ""
		})
		_, err := r.Resolve(ctx, Candidate{Kind: "gem", Name: "pkg", Version: "1"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("in flight", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := NewRegistryResolver()
		r.client.Transport = registryRoundTripper(func(req *http.Request) (*http.Response, error) {
			cancel()
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
		_, err := r.Resolve(ctx, Candidate{Kind: "gem", Name: "pkg", Version: "1"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("transport error redaction", func(t *testing.T) {
		r := NewRegistryResolver()
		r.client.Transport = registryRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("sensitive-secret-token and internal network information")
		})
		_, err := r.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"})
		if err == nil || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRegistryCredentialIsolation(t *testing.T) {
	t.Setenv("GH_TOKEN", "ambient-gh-token")
	t.Setenv("GITHUB_TOKEN", "ambient-github-token")
	t.Setenv("NPM_TOKEN", "ambient-npm-token")
	t.Setenv("NODE_AUTH_TOKEN", "ambient-node-token")
	t.Setenv("DOCKER_AUTH_CONFIG", `{"auths":{"ghcr.io":{"auth":"ambient-auth"}}}`)
	t.Setenv("HTTP_PROXY", "http://secret:password@proxy.invalid")
	t.Setenv("HTTPS_PROXY", "http://secret:password@proxy.invalid")
	r := NewRegistryResolver()
	if transport, ok := r.client.Transport.(*http.Transport); !ok || transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default transport uses ambient proxy settings or insecure TLS")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := url.Parse("https://rubygems.org")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(origin, []*http.Cookie{{Name: "auth", Value: "ambient-cookie", Path: "/"}})
	r.client.Jar = jar
	r.client.Transport = registryRoundTripper(func(req *http.Request) (*http.Response, error) {
		for key, values := range req.Header {
			if strings.Contains(strings.Join(values, " "), "ambient") || strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") {
				t.Errorf("ambient credentials leaked in header %s", key)
			}
		}
		if _, ok := req.Context().Deadline(); !ok {
			t.Error("request has no deadline")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: req}, nil
	})
	if _, err := r.Resolve(context.Background(), Candidate{Kind: "gem", Name: "pkg", Version: "1"}); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryEndpointAllowlist(t *testing.T) {
	r := registryTestResolver(t, func(*http.Request) (int, http.Header, string) {
		t.Fatal("unsafe endpoint caused a request")
		return 0, nil, ""
	})
	for _, endpoint := range []string{
		"http://rubygems.org/api", "https://evil.example/api", "https://user:secret@rubygems.org/api",
		"https://rubygems.org:444/api", "https://rubygems.org.evil.example/api",
		"https://files.pythonhosted.org/package.whl", "https://static.crates.io/pkg.crate",
	} {
		_, _, err := r.get(context.Background(), endpoint, "application/json", "", 100)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("endpoint was not safely rejected: %s, %v", endpoint, err)
		}
	}
}

package provenance

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

const githubActionsIssuer = "https://token.actions.githubusercontent.com"

var (
	provenanceRepoPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	provenanceSHAPattern      = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	provenanceWorkflowPattern = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$`)
)

// BundleVerifier verifies digest-only GitHub Actions SLSA provenance against the
// public-good Sigstore instance. Private deployments and reusable signers outside
// the selected repository/workflow are deliberately not inferred or trusted.
type BundleVerifier struct {
	mu sync.Mutex
	// Only package tests can substitute offline trust; callers cannot supply roots
	// or select a network service from untrusted bundle contents.
	trustedMaterial      root.TrustedMaterial
	fetchTrustedMaterial func(context.Context) (root.TrustedMaterial, error)
}

// NewBundleVerifier creates a verifier using authenticated public-good Sigstore trust.
func NewBundleVerifier() *BundleVerifier {
	return &BundleVerifier{fetchTrustedMaterial: publicGoodTrustedMaterial}
}

// Verify authenticates the certificate, signature, transparency-log inclusion,
// observer timestamp, artifact digest and selected producer. It never fetches an
// artifact or follows URLs supplied by a bundle.
func (v *BundleVerifier) Verify(ctx context.Context, bundleJSON []byte, expected Candidate, repo string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !provenanceRepoPattern.MatchString(repo) {
		return errors.New("provenance requires a github.com owner/name repository")
	}
	if ValidateIdentity(expected) != nil {
		return errors.New("provenance requires an artifact name and canonical SHA256 digest")
	}
	if !provenanceSHAPattern.MatchString(expected.SHA) ||
		!provenanceWorkflowPattern.MatchString(expected.Workflow) || expected.RunID <= 0 {
		return errors.New("provenance producer workflow, immutable source SHA and run ID must be resolved")
	}
	repositoryURI := "https://github.com/" + repo
	runURI := repositoryURI + "/actions/runs/" + strconv.FormatInt(expected.RunID, 10)
	runPattern := regexp.MustCompile("^" + regexp.QuoteMeta(runURI) + `(?:/attempts/[1-9][0-9]*)?$`)
	if expected.RunURL != "" && !runPattern.MatchString(expected.RunURL) {
		return errors.New("provenance run URL does not match the selected repository and run")
	}

	entity := &bundle.Bundle{}
	if err := entity.UnmarshalJSON(bundleJSON); err != nil {
		return errors.New("invalid Sigstore attestation bundle")
	}
	if entity.GetDsseEnvelope() == nil {
		return errors.New("provenance requires a signed in-toto SLSA statement")
	}
	// WithTransparencyLog also accepts inclusion promises. Require proofs on
	// every entry so a promise alone cannot satisfy our inclusion policy.
	entries, err := entity.TlogEntries()
	if err != nil || len(entries) == 0 {
		return errors.New("public-good transparency-log inclusion proof is required; private Sigstore deployments are unsupported")
	}
	for _, entry := range entries {
		if !entry.HasInclusionProof() {
			return errors.New("provenance requires a transparency-log inclusion proof, not only an inclusion promise")
		}
	}

	identity, err := verify.NewShortCertificateIdentity(githubActionsIssuer, "", "",
		"^"+regexp.QuoteMeta(repositoryURI+"/"+expected.Workflow)+`@[^?#\s]+$`)
	if err != nil {
		return errors.New("could not configure provenance signer identity")
	}
	identity.Extensions = certificate.Extensions{
		SourceRepositoryURI:                 repositoryURI,
		SourceRepositoryDigest:              expected.SHA,
		SourceRepositoryVisibilityAtSigning: "public",
	}
	trusted, err := v.trustedRoot(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("could not authenticate public-good Sigstore trust material")
	}
	verifier, err := verify.NewVerifier(trusted,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1))
	if err != nil {
		return errors.New("could not configure public-good Sigstore verification")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(expected.Digest, "sha256:"))
	if err != nil {
		return errors.New("provenance requires a canonical SHA256 digest")
	}
	result, err := verifier.Verify(entity, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(identity)))
	if err != nil {
		return errors.New("provenance signature, transparency evidence, digest or authenticated producer identity did not verify; reusable workflow signers require explicit supported identity mapping")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if result.Signature == nil || result.Signature.Certificate == nil ||
		!runPattern.MatchString(result.Signature.Certificate.RunInvocationURI) {
		return errors.New("authenticated provenance certificate does not identify the selected workflow run")
	}
	if strings.Contains(expected.RunURL, "/attempts/") &&
		result.Signature.Certificate.RunInvocationURI != expected.RunURL {
		return errors.New("authenticated provenance certificate does not identify the selected run attempt")
	}
	return validateProvenanceStatement(result.Statement)
}

func validateProvenanceStatement(statement *in_toto.Statement) error {
	if statement == nil || statement.Type != "https://in-toto.io/Statement/v1" ||
		statement.PredicateType != "https://slsa.dev/provenance/v1" || statement.Predicate == nil {
		return errors.New("attestation is not an in-toto SLSA provenance v1 statement")
	}
	// Predicate repository/run fields are signer-controlled, not OIDC claims.
	// They cannot substitute for the authenticated certificate extensions above.
	build := statement.Predicate.GetFields()["buildDefinition"].GetStructValue()
	run := statement.Predicate.GetFields()["runDetails"].GetStructValue()
	if build == nil || build.GetFields()["buildType"].GetStringValue() == "" ||
		run == nil || run.GetFields()["builder"].GetStructValue().GetFields()["id"].GetStringValue() == "" {
		return errors.New("SLSA provenance v1 build definition and builder are required")
	}
	return nil
}

// Trust is authenticated once per verifier (inspection), never persisted across
// invocations. Failed or cancelled initialization is retried on the next call.
func (v *BundleVerifier) trustedRoot(ctx context.Context) (root.TrustedMaterial, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.trustedMaterial != nil {
		return v.trustedMaterial, nil
	}
	fetch := v.fetchTrustedMaterial
	if fetch == nil {
		fetch = publicGoodTrustedMaterial
	}
	material, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.trustedMaterial = material
	return material, nil
}

// The TUF fetcher has no context parameter. Attach the bounded verification
// context to every HTTP request rather than leaving refreshes uncancellable.
type provenanceTUFClient struct {
	ctx    context.Context
	client *http.Client
}

func (c provenanceTUFClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req.Clone(c.ctx))
}

func publicGoodTrustedMaterial(ctx context.Context) (root.TrustedMaterial, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "tuf-repo-cdn.sigstore.dev" {
				return errors.New("sigstore TUF redirect outside public-good mirror")
			}
			return nil
		},
	}
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(provenanceTUFClient{ctx: ctx, client: client})
	options := &tuf.Options{
		Root:              tuf.DefaultRoot(),
		RepositoryBaseURL: tuf.DefaultMirror,
		DisableLocalCache: true,
		Fetcher:           f,
		Context:           ctx,
	}
	return root.FetchTrustedRootWithOptions(options)
}

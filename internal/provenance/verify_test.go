package provenance

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"google.golang.org/protobuf/types/known/structpb"
)

func signedProvenanceFixture(t *testing.T) ([]byte, Candidate, string) {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(signedConformanceFixture), ""))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately use certificate claims, not the unrelated repository/SHA/run
	// in this fixture's signer-controlled SLSA predicate.
	return raw, Candidate{
		Name:     "a.txt",
		Digest:   "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf",
		Workflow: ".github/workflows/extremely-dangerous-oidc-beacon.yml",
		SHA:      "82a3bfe6dd50fe9c71d6315eae66da15307856cf",
		RunID:    12359147651,
		RunURL:   "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/actions/runs/12359147651",
	}, "sigstore-conformance/extremely-dangerous-public-oidc-beacon"
}

func offlineBundleVerifier(t *testing.T) *BundleVerifier {
	t.Helper()
	return &BundleVerifier{trustedMaterial: data.TrustedRoot(t, "public-good.json")}
}

func TestBundleVerifierSignedPublicGood(t *testing.T) {
	raw, expected, repo := signedProvenanceFixture(t)
	v := offlineBundleVerifier(t)
	if err := v.Verify(context.Background(), raw, expected, repo); err != nil {
		t.Fatal(err)
	}
	expected.RunURL += "/attempts/1"
	if err := v.Verify(context.Background(), raw, expected, repo); err != nil {
		t.Fatal(err)
	}
}

func TestBundleVerifierExpectedIdentity(t *testing.T) {
	raw, original, originalRepo := signedProvenanceFixture(t)
	tests := []struct {
		name   string
		change func(*Candidate, *string)
	}{
		{"wrong digest", func(c *Candidate, _ *string) { c.Digest = "sha256:" + strings.Repeat("0", 64) }},
		{"malformed digest", func(c *Candidate, _ *string) { c.Digest = "sha256:abc" }},
		{"uppercase digest", func(c *Candidate, _ *string) { c.Digest = strings.ToUpper(c.Digest) }},
		{"missing name", func(c *Candidate, _ *string) { c.Name = "" }},
		{"wrong repository", func(c *Candidate, repo *string) { *repo = "other/repository"; c.RunURL = "" }},
		{"repository suffix", func(c *Candidate, repo *string) { *repo += ".attacker"; c.RunURL = "" }},
		{"non GitHub host", func(_ *Candidate, repo *string) { *repo = "https://example.com/owner/repo" }},
		{"wrong workflow", func(c *Candidate, _ *string) { c.Workflow = ".github/workflows/other.yml" }},
		{"missing workflow", func(c *Candidate, _ *string) { c.Workflow = "" }},
		{"workflow traversal", func(c *Candidate, _ *string) { c.Workflow = ".github/workflows/../other.yml" }},
		{"wrong SHA", func(c *Candidate, _ *string) { c.SHA = strings.Repeat("1", 40) }},
		{"missing SHA", func(c *Candidate, _ *string) { c.SHA = "" }},
		{"abbreviated SHA", func(c *Candidate, _ *string) { c.SHA = c.SHA[:7] }},
		{"wrong run", func(c *Candidate, _ *string) { c.RunID++; c.RunURL = "" }},
		{"missing run", func(c *Candidate, _ *string) { c.RunID = 0 }},
		{"inconsistent run URL", func(c *Candidate, _ *string) { c.RunURL += "0" }},
		{"run URL query", func(c *Candidate, _ *string) { c.RunURL += "?attempt=1" }},
		{"wrong run attempt", func(c *Candidate, _ *string) { c.RunURL += "/attempts/2" }},
		{"predicate source is not authenticated source", func(c *Candidate, repo *string) {
			*repo = "loosebazooka/aa-test"
			c.Workflow = ".github/workflows/provenance.yaml"
			c.SHA = "ebff8dfbd609b7b22237c7719ce07f2dc7934f5f"
			c.RunID = 11941425487
			c.RunURL = ""
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected, repo := original, originalRepo
			tt.change(&expected, &repo)
			if err := offlineBundleVerifier(t).Verify(context.Background(), raw, expected, repo); err == nil {
				t.Fatal("incorrect or unresolved producer identity was accepted")
			}
		})
	}
}

func TestBundleVerifierInvalidBundles(t *testing.T) {
	_, expected, repo := signedProvenanceFixture(t)
	for _, payload := range []string{"", "null", "{}", "[]", "{", `{"mediaType":"untrusted"}`, `{"dsseEnvelope":{"payload":"not-base64"}}`} {
		t.Run(payload, func(t *testing.T) {
			if err := NewBundleVerifier().Verify(context.Background(), []byte(payload), expected, repo); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func TestBundleVerifierTampering(t *testing.T) {
	raw, expected, repo := signedProvenanceFixture(t)
	tests := []struct {
		name   string
		change func(*bundle.Bundle)
	}{
		{"invalid signature", func(b *bundle.Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 }},
		{"missing signature", func(b *bundle.Bundle) { b.GetDsseEnvelope().Signatures = nil }},
		{"unsigned predicate", func(b *bundle.Bundle) {
			b.GetDsseEnvelope().Payload = bytes.ReplaceAll(b.GetDsseEnvelope().Payload, []byte("loosebazooka"), []byte("not-the-source"))
		}},
		{"SBOM", func(b *bundle.Bundle) {
			b.GetDsseEnvelope().Payload = bytes.ReplaceAll(b.GetDsseEnvelope().Payload,
				[]byte("https://slsa.dev/provenance/v1"), []byte("https://spdx.dev/Document"))
		}},
		{"release attestation", func(b *bundle.Bundle) {
			b.GetDsseEnvelope().Payload = bytes.ReplaceAll(b.GetDsseEnvelope().Payload,
				[]byte("https://slsa.dev/provenance/v1"), []byte("https://in-toto.io/attestation/release/v0.1"))
		}},
		{"missing transparency log", func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries = nil }},
		{"inclusion promise only", func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionProof = nil }},
		{"corrupt inclusion proof", func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionProof.RootHash[0] ^= 1 }},
		{"corrupt observer timestamp", func(b *bundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionPromise.SignedEntryTimestamp[0] ^= 1
		}},
		{"no signed observer timestamp", func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionPromise = nil }},
		{"untrusted log key", func(b *bundle.Bundle) { b.VerificationMaterial.TlogEntries[0].LogId.KeyId[0] ^= 1 }},
		{"unsigned replacement certificate", func(b *bundle.Bundle) {
			// Remove authenticated source SHA extension by corrupting its OID.
			der := b.VerificationMaterial.GetCertificate().RawBytes
			oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x0d}
			i := bytes.Index(der, oid)
			if i < 0 {
				t.Fatal("fixture is missing source repository digest extension")
			}
			der[i+len(oid)-1] = 0x7f
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &bundle.Bundle{}
			if err := b.UnmarshalJSON(raw); err != nil {
				t.Fatal(err)
			}
			tt.change(b)
			tampered, err := b.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			err = offlineBundleVerifier(t).Verify(context.Background(), tampered, expected, repo)
			if err == nil {
				t.Fatal("tampered bundle accepted")
			}
			if strings.Contains(err.Error(), "MEYCI") || strings.Contains(err.Error(), "loosebazooka") {
				t.Fatal("verification diagnostic leaked bundle content")
			}
		})
	}
}

func TestBundleVerifierCancelled(t *testing.T) {
	raw, expected, repo := signedProvenanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewBundleVerifier().Verify(ctx, raw, expected, repo); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
}

func TestBundleVerifierCachesAuthenticatedTrust(t *testing.T) {
	raw, expected, repo := signedProvenanceFixture(t)
	trusted := data.TrustedRoot(t, "public-good.json")
	fetches := 0
	v := &BundleVerifier{fetchTrustedMaterial: func(context.Context) (root.TrustedMaterial, error) {
		fetches++
		return trusted, nil
	}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if err := v.Verify(context.Background(), raw, expected, repo); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if fetches != 1 {
		t.Fatalf("trust fetched %d times, want once per inspection", fetches)
	}
}

func TestBundleVerifierDoesNotCacheTrustFailures(t *testing.T) {
	raw, expected, repo := signedProvenanceFixture(t)
	trusted := data.TrustedRoot(t, "public-good.json")
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "fetch failure", true: "cancelled fetch"}[cancelled], func(t *testing.T) {
			fetches := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v := &BundleVerifier{fetchTrustedMaterial: func(context.Context) (root.TrustedMaterial, error) {
				fetches++
				if fetches == 1 {
					if cancelled {
						cancel()
						return trusted, nil
					}
					return nil, errors.New("untrusted network error with sensitive details")
				}
				return trusted, nil
			}}
			err := v.Verify(ctx, raw, expected, repo)
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("expected safe initialization failure, got %v", err)
			}
			if err := v.Verify(context.Background(), raw, expected, repo); err != nil {
				t.Fatal(err)
			}
			if fetches != 2 {
				t.Fatalf("trust fetched %d times, want retry after failure", fetches)
			}
		})
	}
}

type provenanceRoundTripper func(*http.Request) (*http.Response, error)

func (f provenanceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestProvenanceTUFClientPropagatesCancellation(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "caller"))
	defer cancel()
	client := provenanceTUFClient{ctx: ctx, client: &http.Client{
		Transport: provenanceRoundTripper(func(req *http.Request) (*http.Response, error) {
			if req.Context().Value(contextKey{}) != "caller" {
				t.Fatal("TUF request did not receive caller context")
			}
			cancel()
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
		Timeout: time.Second,
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://tuf-repo-cdn.sigstore.dev/root.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if response != nil {
		defer response.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
}

func TestBundleVerifierRejectsUnrelatedSignedStatement(t *testing.T) {
	_, expected, repo := signedProvenanceFixture(t)
	// This is an actually signed upstream public-good statement, but its SHA512
	// subject cannot be substituted for an expected SHA256 artifact identity.
	b := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")
	raw, err := b.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := offlineBundleVerifier(t).Verify(context.Background(), raw, expected, repo); err == nil {
		t.Fatal("unrelated signed statement accepted")
	}
}

func TestProvenanceStatementType(t *testing.T) {
	tests := []struct {
		name          string
		statementType string
		predicateType string
		predicate     map[string]any
		valid         bool
	}{
		{"SLSA v1", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1",
			map[string]any{
				"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"},
				"runDetails":      map[string]any{"builder": map[string]any{"id": "https://github.com/actions/runner/github-hosted"}},
			}, true},
		{"old statement", "https://in-toto.io/Statement/v0.1", "https://slsa.dev/provenance/v1", nil, false},
		{"old provenance", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v0.2", nil, false},
		{"SBOM", "https://in-toto.io/Statement/v1", "https://spdx.dev/Document", nil, false},
		{"release", "https://in-toto.io/Statement/v1", "https://in-toto.io/attestation/release/v0.1", nil, false},
		{"missing predicate", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1", nil, false},
		{"missing builder", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1",
			map[string]any{"buildDefinition": map[string]any{"buildType": "build"}}, false},
		{"missing build type", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1",
			map[string]any{"runDetails": map[string]any{"builder": map[string]any{"id": "builder"}}}, false},
	}
	if err := validateProvenanceStatement(nil); err == nil {
		t.Fatal("nil statement accepted")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var predicate *structpb.Struct
			if tt.predicate != nil {
				var err error
				predicate, err = structpb.NewStruct(tt.predicate)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := validateProvenanceStatement(&in_toto.Statement{
				Type: tt.statementType, PredicateType: tt.predicateType, Predicate: predicate,
			})
			if (err == nil) != tt.valid {
				t.Fatalf("validation error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

// Fixed signed upstream test data, gzip/base64 encoded to keep it in this file.
// Apache-2.0, sigstore/sigstore-conformance commit
// 8b45823fd0d82236ff42aea5b06c98d5109a0e6d,
// test/assets/bundle-verify/happy-path-intoto-in-dsse-v3/bundle.sigstore.json.
// No live services, artifacts, OIDC tokens, or signing keys are used by tests.
const signedConformanceFixture = `
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
`

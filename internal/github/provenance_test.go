package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

func TestProvenanceReadOnlyDiscovery(t *testing.T) {
	requests := 0
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/repos/o/r/actions/runs":
			if r.URL.Query().Get("status") != "completed" || r.URL.Query().Get("per_page") != "20" {
				t.Error("unbounded run selection")
			}
			encodeProvenanceFixture(t, w, map[string]any{"total_count": 21, "workflow_runs": []any{
				map[string]any{"id": 42, "head_sha": strings.Repeat("a", 40), "path": ".github/workflows/release.yml", "head_repository": map[string]string{"full_name": "o/r"}},
				map[string]any{"id": 43, "head_sha": strings.Repeat("b", 40), "path": ".github/workflows/release.yml", "head_repository": map[string]string{"full_name": "fork/r"}},
			}})
		case "/repos/o/r/actions/runs/42/jobs":
			writeProvenanceFixture(t, w, `{"total_count":1,"jobs":[{"name":"publish","steps":[{"name":"Publish","conclusion":"success"}]}]}`)
		case "/repos/o/r/contents/.github/workflows/release.yml":
			if r.URL.Query().Get("ref") != strings.Repeat("a", 40) {
				t.Error("file was not fetched at immutable commit")
			}
			encodeProvenanceFixture(t, w, map[string]any{"type": "file", "encoding": "base64", "size": 6, "content": base64.StdEncoding.EncodeToString([]byte("hello\n"))})
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := ProvenanceReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	runs, truncated, err := reader.Runs(context.Background(), 20)
	if err != nil || len(runs) != 1 || !truncated || runs[0].ID != 42 {
		t.Fatalf("%+v %v %v", runs, truncated, err)
	}
	executions, partial, err := reader.Executions(context.Background(), 42)
	if err != nil || partial || len(executions) != 1 || executions[0].Conclusion != "success" {
		t.Fatalf("%+v %v %v", executions, partial, err)
	}
	data, err := reader.File(context.Background(), ".github/workflows/release.yml", strings.Repeat("a", 40))
	if err != nil || string(data) != "hello\n" {
		t.Fatalf("%q %v", data, err)
	}
	if requests != 3 {
		t.Fatalf("got %d requests", requests)
	}
}

func TestAttestationAbsenceRequiresSuccessfulExplicitEmptyCollection(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"empty", `{"attestations":[]}`, 200, false},
		{"missing", `{}`, 200, true},
		{"null", `{"attestations":null}`, 200, true},
		{"404", `{}`, 404, true},
		{"403", `{}`, 403, true},
		{"429", `{}`, 429, true},
		{"malformed", `{"attestations":`, 200, true},
		{"URL SSRF", `{"attestations":[{"bundle_url":"http://127.0.0.1/secret"}]}`, 200, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("predicate_type") != "provenance" {
					t.Error("predicate not scoped to provenance")
				}
				w.WriteHeader(tt.status)
				writeProvenanceFixture(t, w, tt.body)
			})
			reader := ProvenanceReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
			_, _, err := reader.Attestations(context.Background(), "sha256:"+strings.Repeat("a", 64))
			if (err != nil) != tt.wantError {
				t.Fatalf("error %v", err)
			}

		})
	}
}

func TestProvenanceInputValidationPrecedesNetwork(t *testing.T) {
	reader := ProvenanceReader{}
	if _, _, err := reader.Runs(context.Background(), 101); err == nil {
		t.Fatal("invalid limit accepted")
	}
	if _, err := reader.File(context.Background(), "../secret", "a"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, _, err := reader.Attestations(context.Background(), "not a digest"); err == nil {
		t.Fatal("invalid digest accepted")
	}
}

func encodeProvenanceFixture(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode fixture: %v", err)
	}
}

func writeProvenanceFixture(t *testing.T, w http.ResponseWriter, value string) {
	t.Helper()
	if _, err := w.Write([]byte(value)); err != nil {
		t.Errorf("write fixture: %v", err)
	}
}

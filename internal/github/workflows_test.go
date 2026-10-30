package github

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

func TestWorkflowSourcesAreImmutableAndNeverQueryRuns(t *testing.T) {
	sha := strings.Repeat("a", 40)
	calls := 0
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet {
			t.Fatal("mutating request")
		}
		switch r.URL.Path {
		case "/repos/o/r/commits/main":
			encodeProvenanceFixture(t, w, map[string]string{"sha": sha})
		case "/repos/o/r/contents/.github/workflows":
			if r.URL.Query().Get("ref") != sha {
				t.Error("mutable source directory")
			}
			writeProvenanceFixture(t, w, `[{"path":".github/workflows/release.yml","type":"file"}]`)
		case "/repos/o/r/contents/.github/workflows/release.yml":
			if r.URL.Query().Get("ref") != sha {
				t.Error("mutable workflow")
			}
			encodeProvenanceFixture(t, w, map[string]any{"type": "file", "encoding": "base64", "size": 6, "content": base64.StdEncoding.EncodeToString([]byte("hello\n"))})
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := ProvenanceReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	got, sources, err := reader.WorkflowSources(context.Background(), "main")
	if err != nil || got != sha || len(sources) != 1 || calls != 3 {
		t.Fatalf("%s %+v %v (%d requests)", got, sources, err, calls)
	}
}

func TestWorkflowDirectoryUnavailableIsNotClean(t *testing.T) {
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/commits/") {
			encodeProvenanceFixture(t, w, map[string]string{"sha": strings.Repeat("a", 40)})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := ProvenanceReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	if _, _, err := reader.WorkflowSources(context.Background(), "main"); err == nil {
		t.Fatal("unavailable workflows reported clean")
	}
}

func TestWorkflowSourceDiscoveryStopsAtAdoption(t *testing.T) {
	source := "jobs:\n  ship:\n    steps:\n      - uses: actions/attest@v4\n"
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/commits/main":
			encodeProvenanceFixture(t, w, map[string]string{"sha": strings.Repeat("a", 40)})
		case "/repos/o/r/contents/.github/workflows":
			writeProvenanceFixture(t, w, `[{"path":".github/workflows/attest.yml","type":"file"},{"path":".github/workflows/other.yml","type":"file"}]`)
		case "/repos/o/r/contents/.github/workflows/attest.yml":
			encodeProvenanceFixture(t, w, map[string]any{"type": "file", "encoding": "base64", "size": len(source), "content": base64.StdEncoding.EncodeToString([]byte(source))})
		default:
			t.Errorf("early exit should prevent %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := ProvenanceReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	_, sources, err := reader.WorkflowSources(context.Background(), "main")
	if err != nil || len(sources) != 1 {
		t.Fatalf("%+v %v", sources, err)
	}
}

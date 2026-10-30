package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
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
	reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
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
	reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	_, sources, err := reader.WorkflowSources(context.Background(), "main")
	if err != nil || len(sources) != 1 {
		t.Fatalf("%+v %v", sources, err)
	}
}

func encodeProvenanceFixture(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func writeProvenanceFixture(t *testing.T, w http.ResponseWriter, value string) {
	t.Helper()
	if _, err := w.Write([]byte(value)); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowSourceReadRejectsUnavailableMalformedOrOversizedContent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", http.StatusForbidden, `{}`},
		{"invalid metadata", http.StatusOK, `{`},
		{"not a file", http.StatusOK, `{"type":"symlink","encoding":"base64","content":"eA==","size":1}`},
		{"wrong encoding", http.StatusOK, `{"type":"file","encoding":"none","size":0}`},
		{"invalid base64", http.StatusOK, `{"type":"file","encoding":"base64","content":"!","size":1}`},
		{"declared oversized", http.StatusOK, `{"type":"file","encoding":"base64","size":1048577}`},
		{"actual oversized", http.StatusOK, `{"type":"file","encoding":"base64","size":1,"content":"` + base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1)) + `"}`},
		{"metadata oversized", http.StatusOK, strings.Repeat(" ", (8<<20)+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/repos/o/r/contents/.github/workflows/release.yml" {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL)
				}
				w.WriteHeader(tt.status)
				writeProvenanceFixture(t, w, tt.body)
			})
			reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
			if _, err := reader.File(t.Context(), ".github/workflows/release.yml", strings.Repeat("a", 40)); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}

func TestWorkflowSourceIdentityRejectsNonWorkflowAndMutableRefsBeforeHTTP(t *testing.T) {
	client := fixtureClient(t, "github.com", func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid source identity reached network")
	})
	reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
	for _, identity := range [][2]string{
		{"package.json", strings.Repeat("a", 40)},
		{".github/workflows/../../secret.yml", strings.Repeat("a", 40)},
		{".github/workflows/release.yml", "main"},
		{".github/workflows/release.yml", strings.Repeat("z", 40)},
	} {
		if _, err := reader.File(t.Context(), identity[0], identity[1]); err == nil {
			t.Fatalf("accepted %v", identity)
		}
	}
}

func TestWorkflowDiscoveryBoundsAreNotReportedClean(t *testing.T) {
	for _, mode := range []string{"missing listing", "truncated listing", "workflow limit", "non-file", "invalid commit"} {
		t.Run(mode, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/commits/"):
					sha := strings.Repeat("a", 40)
					if mode == "invalid commit" {
						sha = strings.Repeat("z", 40)
					}
					encodeProvenanceFixture(t, w, map[string]string{"sha": sha})
				case r.URL.Path == "/repos/o/r/contents/.github/workflows":
					if mode == "missing listing" {
						writeProvenanceFixture(t, w, "null")
						return
					}
					count := 101
					if mode == "truncated listing" {
						count = 1000
					}
					var entries []map[string]string
					for i := range count {
						kind := "file"
						if mode == "non-file" {
							kind = "symlink"
						}
						entries = append(entries, map[string]string{"path": fmt.Sprintf(".github/workflows/%d.yml", i), "type": kind})
					}
					encodeProvenanceFixture(t, w, entries)
				case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/.github/workflows/"):
					encodeProvenanceFixture(t, w, map[string]any{"type": "file", "encoding": "base64", "size": 6, "content": base64.StdEncoding.EncodeToString([]byte("hello\n"))})
				default:
					t.Fatalf("unexpected request %s", r.URL)
				}
			})
			reader := WorkflowReader{client, repository.Target{Host: "github.com", Owner: "o", Name: "r"}}
			if _, _, err := reader.WorkflowSources(t.Context(), "main"); err == nil {
				t.Fatal("incomplete workflow discovery reported clean")
			}
		})
	}
}

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
			encodeWorkflowSource(t, w, "hello\n")
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := WorkflowReader{
		Client: client,
		Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
	}
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
	reader := WorkflowReader{
		Client: client,
		Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
	}
	if _, _, err := reader.WorkflowSources(context.Background(), "main"); err == nil {
		t.Fatal("unavailable workflows reported clean")
	}
}

func TestWorkflowSourceDiscoveryStopsAtAdoption(t *testing.T) {
	source := `jobs:
  ship:
    steps:
      - uses: actions/attest@v4
`
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/commits/main":
			encodeProvenanceFixture(t, w, map[string]string{"sha": strings.Repeat("a", 40)})
		case "/repos/o/r/contents/.github/workflows":
			writeProvenanceFixture(t, w, `[
				{"path":".github/workflows/attest.yml","type":"file"},
				{"path":".github/workflows/other.yml","type":"file"}
			]`)
		case "/repos/o/r/contents/.github/workflows/attest.yml":
			encodeWorkflowSource(t, w, source)
		default:
			t.Errorf("early exit should prevent %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	reader := WorkflowReader{
		Client: client,
		Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
	}
	_, sources, err := reader.WorkflowSources(context.Background(), "main")
	if err != nil || len(sources) != 1 {
		t.Fatalf("%+v %v", sources, err)
	}
}

func TestWorkflowSourceDiscoveryContinuesPastSBOM(t *testing.T) {
	const sbomSource = `jobs:
  attest:
    steps:
      - uses: actions/attest-sbom@v3
`
	const provenanceSource = `jobs:
  attest:
    steps:
      - uses: actions/attest@v4
`
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/repos/o/r/commits/main":
			encodeProvenanceFixture(t, w, map[string]string{"sha": strings.Repeat("a", 40)})
		case "/repos/o/r/contents/.github/workflows":
			writeProvenanceFixture(t, w, `[
				{"path":".github/workflows/sbom.yml","type":"file"},
				{"path":".github/workflows/provenance.yml","type":"file"},
				{"path":".github/workflows/not-needed.yml","type":"file"}
			]`)
		case "/repos/o/r/contents/.github/workflows/sbom.yml":
			encodeWorkflowSource(t, w, sbomSource)
		case "/repos/o/r/contents/.github/workflows/provenance.yml":
			encodeWorkflowSource(t, w, provenanceSource)
		default:
			t.Fatalf("source retrieval should stop only after provenance: %s", r.URL)
		}
	})
	reader := WorkflowReader{
		Client: client,
		Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
	}

	_, sources, err := reader.WorkflowSources(t.Context(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if string(sources[".github/workflows/sbom.yml"]) != sbomSource ||
		string(sources[".github/workflows/provenance.yml"]) != provenanceSource ||
		len(sources) != 2 {
		t.Fatalf("expected SBOM and provenance sources, got %v", sources)
	}
}

func encodeWorkflowSource(t *testing.T, w http.ResponseWriter, source string) {
	t.Helper()
	encodeProvenanceFixture(t, w, map[string]any{
		"type":     "file",
		"encoding": "base64",
		"size":     len(source),
		"content":  base64.StdEncoding.EncodeToString([]byte(source)),
	})
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
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "forbidden",
			status: http.StatusForbidden,
			body:   `{}`,
		},
		{
			name:   "invalid metadata",
			status: http.StatusOK,
			body:   `{`,
		},
		{
			name:   "not a file",
			status: http.StatusOK,
			body: `{
				"type": "symlink",
				"encoding": "base64",
				"content": "eA==",
				"size": 1
			}`,
		},
		{
			name:   "wrong encoding",
			status: http.StatusOK,
			body: `{
				"type": "file",
				"encoding": "none",
				"size": 0
			}`,
		},
		{
			name:   "invalid base64",
			status: http.StatusOK,
			body: `{
				"type": "file",
				"encoding": "base64",
				"content": "!",
				"size": 1
			}`,
		},
		{
			name:   "declared oversized",
			status: http.StatusOK,
			body: `{
				"type": "file",
				"encoding": "base64",
				"size": 1048577
			}`,
		},
		{
			name:   "actual oversized",
			status: http.StatusOK,
			body: `{
				"type": "file",
				"encoding": "base64",
				"size": 1,
				"content": "` + base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1)) + `"
			}`,
		},
		{
			name:   "metadata oversized",
			status: http.StatusOK,
			body:   strings.Repeat(" ", (8<<20)+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/repos/o/r/contents/.github/workflows/release.yml" {
					t.Fatalf("unexpected request %s %s", r.Method, r.URL)
				}
				w.WriteHeader(tt.status)
				writeProvenanceFixture(t, w, tt.body)
			})
			reader := WorkflowReader{
				Client: client,
				Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
			}
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
	reader := WorkflowReader{
		Client: client,
		Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
	}
	tests := []struct {
		name string
		file string
		ref  string
	}{
		{
			name: "not a workflow",
			file: "package.json",
			ref:  strings.Repeat("a", 40),
		},
		{
			name: "path traversal",
			file: ".github/workflows/../../secret.yml",
			ref:  strings.Repeat("a", 40),
		},
		{
			name: "mutable ref",
			file: ".github/workflows/release.yml",
			ref:  "main",
		},
		{
			name: "invalid SHA",
			file: ".github/workflows/release.yml",
			ref:  strings.Repeat("z", 40),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := reader.File(t.Context(), tt.file, tt.ref); err == nil {
				t.Fatal("invalid source identity accepted")
			}
		})
	}
}

func TestWorkflowDiscoveryBoundsAreNotReportedClean(t *testing.T) {
	tests := []struct {
		name           string
		sha            string
		entryCount     int
		entryType      string
		missingListing bool
	}{
		{
			name:           "missing listing",
			sha:            strings.Repeat("a", 40),
			missingListing: true,
		},
		{
			name:       "truncated listing",
			sha:        strings.Repeat("a", 40),
			entryCount: 1000,
			entryType:  "file",
		},
		{
			name:       "workflow limit",
			sha:        strings.Repeat("a", 40),
			entryCount: 101,
			entryType:  "file",
		},
		{
			name:       "non-file",
			sha:        strings.Repeat("a", 40),
			entryCount: 1,
			entryType:  "symlink",
		},
		{
			name: "invalid commit",
			sha:  strings.Repeat("z", 40),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/commits/"):
					encodeProvenanceFixture(t, w, map[string]string{"sha": tt.sha})
				case r.URL.Path == "/repos/o/r/contents/.github/workflows":
					if tt.missingListing {
						writeProvenanceFixture(t, w, "null")
						return
					}
					var entries []map[string]string
					for i := range tt.entryCount {
						entries = append(entries, map[string]string{
							"path": fmt.Sprintf(".github/workflows/%d.yml", i),
							"type": tt.entryType,
						})
					}
					encodeProvenanceFixture(t, w, entries)
				case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/.github/workflows/"):
					encodeWorkflowSource(t, w, "hello\n")
				default:
					t.Fatalf("unexpected request %s", r.URL)
				}
			})
			reader := WorkflowReader{
				Client: client,
				Target: repository.Target{Host: "github.com", Owner: "o", Name: "r"},
			}
			if _, _, err := reader.WorkflowSources(t.Context(), "main"); err == nil {
				t.Fatal("incomplete workflow discovery reported clean")
			}
		})
	}
}

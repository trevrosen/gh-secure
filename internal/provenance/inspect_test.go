package provenance

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fixtureReader struct {
	bundles   [][]byte
	err       error
	truncated bool
	runs      []Run
	workflow  string
}

func (r fixtureReader) Runs(context.Context, int) ([]Run, bool, error) {
	return r.runs, r.truncated, nil
}
func (r fixtureReader) File(_ context.Context, name, _ string) ([]byte, error) {
	if WorkflowPath(name) {
		return []byte(r.workflow), nil
	}
	return []byte(`{"name":"pkg","version":"1.2.3"}`), nil
}
func (r fixtureReader) Executions(context.Context, int64) ([]Execution, bool, error) {
	return []Execution{{"publish", "Publish", "success"}}, false, nil
}
func (r fixtureReader) Attestations(context.Context, string) ([][]byte, bool, error) {
	return r.bundles, r.truncated, r.err
}

type fixtureVerifier struct{ err error }

func (v fixtureVerifier) Verify(context.Context, []byte, Candidate, string) error { return v.err }

type fixtureResolver struct{}

func (fixtureResolver) Resolve(_ context.Context, c Candidate) ([]Candidate, error) {
	c.Digest = "sha256:" + strings.Repeat("a", 64)
	return []Candidate{c}, nil
}

type incompleteRunReader struct {
	fixtureReader
	fileErr, executionErr error
	partial               bool
}

func (r incompleteRunReader) File(ctx context.Context, file, sha string) ([]byte, error) {
	if r.fileErr != nil {
		return nil, r.fileErr
	}
	return r.fixtureReader.File(ctx, file, sha)
}

func (r incompleteRunReader) Executions(ctx context.Context, id int64) ([]Execution, bool, error) {
	executions, _, err := r.fixtureReader.Executions(ctx, id)
	if err != nil {
		return nil, false, err
	}
	return executions, r.partial, r.executionErr
}

func TestRunDiscoveryPreservesIncompleteEvidence(t *testing.T) {
	const workflow = "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: Publish\n        run: npm publish\n"
	for _, partial := range []bool{false, true} {
		reader := incompleteRunReader{fixtureReader: fixtureReader{workflow: workflow}, partial: partial}
		if !partial {
			reader.executionErr = errors.New("unavailable")
		}
		candidates, gaps := discoverRun(t.Context(), "o/r", reader, testRun())
		if len(candidates) != 1 || candidates[0].Problem != "incomplete job evidence" ||
			len(gaps) != 1 || gaps[0] != "run 42: job/step evidence unavailable or truncated" {
			t.Fatalf("%+v %v", candidates, gaps)
		}
	}
}

func TestRunDiscoveryFailureDiagnostics(t *testing.T) {
	reader := incompleteRunReader{fileErr: errors.New("unavailable")}
	candidates, gaps := discoverRun(t.Context(), "o/r", reader, testRun())
	if len(candidates) != 0 || len(gaps) != 1 || gaps[0] != "run 42: cannot read workflow revision: unavailable" {
		t.Fatalf("%+v %v", candidates, gaps)
	}
	reader = incompleteRunReader{fixtureReader: fixtureReader{workflow: "jobs: ["}, partial: true}
	candidates, gaps = discoverRun(t.Context(), "o/r", reader, testRun())
	if len(candidates) != 0 || len(gaps) != 2 ||
		gaps[0] != "run 42: job/step evidence unavailable or truncated" ||
		gaps[1] != "run 42: workflow is not supported YAML" {
		t.Fatalf("%+v %v", candidates, gaps)
	}
}

func TestAssessmentNeverConvertsUnknownToMissing(t *testing.T) {
	artifact := Candidate{Kind: "npm", Name: "pkg", Digest: "sha256:" + strings.Repeat("a", 64)}
	tests := []struct {
		name   string
		reader fixtureReader
		state  State
	}{
		{"empty success", fixtureReader{}, Missing},
		{"404 or permissions", fixtureReader{err: errors.New("HTTP 404")}, Unknown},
		{"truncated", fixtureReader{truncated: true}, Unknown},
		{"malformed bundle", fixtureReader{bundles: [][]byte{[]byte("malformed")}}, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, _ := assess(context.Background(), "o/r", tt.reader, fixtureVerifier{errors.New("invalid")}, artifact)
			if state != tt.state {
				t.Fatalf("got %s want %s", state, tt.state)
			}
		})
	}
	artifact.Problem = "unproven publisher"
	if state, _ := assess(context.Background(), "o/r", fixtureReader{}, fixtureVerifier{}, artifact); state != Unknown {
		t.Fatalf("unproven publication became %s", state)
	}
}

func TestInspectionReportsWindowAndNoOutputs(t *testing.T) {
	report, err := Inspect(context.Background(), "o/r", fixtureReader{truncated: true}, fixtureResolver{}, fixtureVerifier{}, InspectOptions{RunLimit: 20})
	if err != nil || report.Err() == nil || !strings.Contains(Render(report), "no distributed outputs") {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestInspectionRequiresVerificationNotYAMLPresence(t *testing.T) {
	workflow := "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: Publish\n        run: npm publish\n      - uses: actions/attest@pin\n"
	reader := fixtureReader{runs: []Run{testRun()}, workflow: workflow}
	report, err := Inspect(context.Background(), "o/r", reader, fixtureResolver{}, fixtureVerifier{}, InspectOptions{RunLimit: 20})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].State != Missing || report.Err() == nil {
		t.Fatalf("%+v %v", report, err)
	}
	reader.bundles = [][]byte{[]byte("{}")}
	report, err = Inspect(context.Background(), "o/r", reader, fixtureResolver{}, fixtureVerifier{}, InspectOptions{RunLimit: 20})
	if err != nil || report.Findings[0].State != Verified || report.Err() != nil {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestGHReleaseDetectionDoesNotResolveOrVerifyAssets(t *testing.T) {
	reader := fixtureReader{
		runs: []Run{testRun()},
		workflow: `jobs:
  publish:
    steps:
      - uses: actions/checkout@pin
      - name: Publish
        run: gh release create v1.2.3 dist/app
`,
	}
	report, err := Inspect(context.Background(), "o/r", reader, fixtureResolver{}, fixtureVerifier{}, InspectOptions{RunLimit: 20})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].State != Unsupported || report.Findings[0].Artifact.RunID != 42 ||
		report.Findings[0].Artifact.Digest != "" || !strings.Contains(report.Findings[0].Detail, "not implemented") {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestReleasePublishingRecognitionIsLimitedToGH(t *testing.T) {
	for _, tt := range []struct {
		name string
		step step
		kind string
	}{
		{"create", step{Run: "gh release create v1 dist/app"}, "release"},
		{"upload", step{Run: "gh release upload v1 dist/app --clobber"}, "release"},
		{"multiline", step{Run: "echo ready\ngh release create \"$TAG\" dist/app"}, "release"},
		{"list", step{Run: "gh release list"}, ""},
		{"view", step{Run: "gh release view v1"}, ""},
		{"download", step{Run: "gh release download v1"}, ""},
		{"delete", step{Run: "gh release delete v1"}, ""},
		{"other executable", step{Run: "not-gh release create v1"}, ""},
		{"softprops", step{Uses: "softprops/action-gh-release@pin"}, "unsupported"},
		{"precompile", step{Uses: "cli/gh-extension-precompile@pin"}, "unsupported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := publisher(tt.step); got != tt.kind {
				t.Fatalf("kind %q, want %q", got, tt.kind)
			}
		})
	}
}

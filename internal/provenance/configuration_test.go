package provenance

import (
	"strings"
	"testing"
)

func TestConfigurationAdoptionIsNotRuntimeProof(t *testing.T) {
	tests := []struct{ name, source, state string }{
		{"attestation", "jobs:\n  ship:\n    steps:\n      - uses: actions/attest@v4\n", "adopted"},
		{"legacy action", "jobs:\n  ship:\n    steps:\n      - uses: actions/attest-build-provenance@v3\n", "adopted"},
		{"SBOM awareness", "jobs:\n  ship:\n    steps:\n      - uses: actions/attest-sbom@v3\n", "adopted"},
		{"conditional awareness", "jobs:\n  ship:\n    steps:\n      - if: false\n        uses: actions/attest@v4\n", "adopted"},
		{"publisher", "jobs:\n  ship:\n    steps:\n      - run: npm publish\n", "missing"},
		{"reusable", "jobs:\n  ship:\n    uses: o/r/.github/workflows/release.yml@v1\n", "review"},
		{"script", "jobs:\n  ship:\n    steps:\n      - run: ./scripts/build-and-ship.sh\n", "review"},
		{"github script", "jobs:\n  ship:\n    steps:\n      - uses: actions/github-script@v8\n", "review"},
		{"native provenance", "jobs:\n  ship:\n    steps:\n      - run: npm publish --provenance\n", "adopted"},
		{"native disabled", "jobs:\n  ship:\n    steps:\n      - run: npm publish --provenance=false\n", "missing"},
		{"native OCI", "jobs:\n  ship:\n    steps:\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          provenance: mode=max\n", "adopted"},
		{"gh release", "jobs:\n  ship:\n    steps:\n      - run: gh release create v1 dist/app\n", "missing"},
		{"release action", "jobs:\n  ship:\n    steps:\n      - uses: softprops/action-gh-release@pin\n", "review"},
		{"precompile action", "jobs:\n  ship:\n    steps:\n      - uses: cli/gh-extension-precompile@pin\n", "review"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := CheckConfiguration([]byte(tt.source), ".github/workflows/release.yml")
			if err != nil || len(findings) != 1 || findings[0].State != tt.state {
				t.Fatalf("%+v %v", findings, err)
			}
			text, issue := RenderConfiguration(findings, strings.Repeat("a", 40))
			if issue != (tt.state != "adopted") || !strings.Contains(text, "no artifact signatures verified") {
				t.Fatalf("issue %v: %s", issue, text)
			}
		})
	}
}

func TestConfigurationUploadsAreNotDistributionPublishers(t *testing.T) {
	source := "jobs:\n  test:\n    steps:\n      - uses: actions/upload-artifact@v4\n      - uses: actions/cache@v4\n"
	findings, err := CheckConfiguration([]byte(source), ".github/workflows/test.yml")
	if err != nil || len(findings) != 0 {
		t.Fatalf("%+v %v", findings, err)
	}
	text, _ := RenderConfiguration(findings, "sha")
	if !strings.Contains(text, "not proof") {
		t.Fatal(text)
	}
	if _, err := CheckConfiguration([]byte("jobs: ["), ".github/workflows/test.yml"); err == nil {
		t.Fatal("invalid source accepted")
	}
}

func TestAdoptionStopsBeforeOtherJobs(t *testing.T) {
	source := "jobs:\n  other:\n    steps:\n      - run: npm publish\n  attest:\n    steps:\n      - uses: actions/attest@v4\n"
	findings, err := CheckConfiguration([]byte(source), ".github/workflows/release.yml")
	if err != nil || len(findings) != 1 || findings[0].State != "adopted" {
		t.Fatalf("%+v %v", findings, err)
	}
}

func TestWorkflowSourceAssessmentPreservesAdoptionPrecedence(t *testing.T) {
	sources := map[string][]byte{
		".github/workflows/a-invalid.yml": []byte("jobs: ["),
		".github/workflows/z-adopted.yml": []byte("jobs:\n  ship:\n    steps:\n      - uses: actions/attest@v4\n"),
	}
	findings, err := CheckWorkflowSources(sources)
	if err != nil || len(findings) != 1 || findings[0].State != "adopted" ||
		findings[0].Workflow != ".github/workflows/z-adopted.yml" {
		t.Fatalf("%+v %v", findings, err)
	}
	delete(sources, ".github/workflows/z-adopted.yml")
	if _, err := CheckWorkflowSources(sources); err == nil {
		t.Fatal("invalid workflow ignored without adoption evidence")
	}
}

func TestWorkflowSourceFindingsAreSorted(t *testing.T) {
	source := []byte("jobs:\n  ship:\n    steps:\n      - run: npm publish\n")
	findings, err := CheckWorkflowSources(map[string][]byte{
		".github/workflows/z.yml": source,
		".github/workflows/a.yml": source,
	})
	if err != nil || len(findings) != 2 || findings[0].Workflow != ".github/workflows/a.yml" ||
		findings[1].Workflow != ".github/workflows/z.yml" {
		t.Fatalf("%+v %v", findings, err)
	}
}

func TestAdoptionRecognitionBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name string
		step step
		want bool
	}{
		{"unversioned official", step{Uses: "actions/attest"}, false},
		{"empty official ref", step{Uses: "actions/attest@"}, false},
		{"explicit native OCI", step{Uses: "docker/build-push-action", With: map[string]string{"provenance": "true"}}, true},
		{"disabled native OCI", step{Uses: "docker/build-push-action@v6", With: map[string]string{"provenance": "false"}}, false},
		{"native PyPI", step{Uses: "pypa/gh-action-pypi-publish@v1", With: map[string]string{"attestations": "true"}}, true},
		{"other publisher", step{Uses: "vendor/publish@v1", With: map[string]string{"attestations": "true"}}, false},
		{"literal npm", step{Run: "npm publish --provenance=true"}, true},
		{"dynamic npm", step{Run: "npm publish --provenance=$FLAG"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := stepDeclaresAttestations(tt.step); got != tt.want {
				t.Fatalf("adoption %v, want %v", got, tt.want)
			}
		})
	}
}

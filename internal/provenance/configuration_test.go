package provenance

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWorkflowDetectionFixtures(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		want     []ConfigurationFinding
	}{
		{
			name:     "SBOM does not cover the image publisher",
			fixtures: []string{"sbom-only.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/sbom-only.yml",
					Job:       "publish",
					Publisher: "docker/build-push-action@v6",
					State:     "missing",
				},
			},
		},
		{
			name:     "unified SBOM action does not cover the image publisher",
			fixtures: []string{"unified-sbom.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/unified-sbom.yml",
					Job:       "publish",
					Publisher: "docker/build-push-action@v6",
					State:     "missing",
				},
				{
					Workflow:  ".github/workflows/unified-sbom.yml",
					Job:       "publish",
					Publisher: "actions/attest@v4",
					State:     "review",
				},
			},
		},
		{
			name:     "provenance action establishes adoption",
			fixtures: []string{"provenance.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/provenance.yml",
					Job:       "publish",
					Publisher: "actions/attest@v4",
					State:     "adopted",
				},
			},
		},
		{
			name:     "native npm provenance establishes adoption",
			fixtures: []string{"npm-native.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/npm-native.yml",
					Job:       "publish",
					Publisher: "npm publisher with --provenance",
					State:     "adopted",
				},
			},
		},
		{
			name:     "reusable publishing needs review",
			fixtures: []string{"reusable.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/reusable.yml",
					Job:       "publish",
					Publisher: "example/build/.github/workflows/publish.yml@v1",
					State:     "review",
				},
			},
		},
		{
			name:     "uploads and caches are not publishers",
			fixtures: []string{"upload-only.yml"},
		},
		{
			name:     "provenance in another workflow supersedes SBOM-only findings",
			fixtures: []string{"sbom-only.yml", "provenance.yml", "reusable.yml"},
			want: []ConfigurationFinding{
				{
					Workflow:  ".github/workflows/provenance.yml",
					Job:       "publish",
					Publisher: "actions/attest@v4",
					State:     "adopted",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := make(map[string][]byte)
			for _, file := range tt.fixtures {
				data, err := os.ReadFile(filepath.Join("testdata", "workflows", file))
				if err != nil {
					t.Fatal(err)
				}
				sources[".github/workflows/"+file] = data
			}

			findings, err := CheckWorkflowSources(sources)
			if err != nil {
				t.Fatal(err)
			}
			for i := range findings {
				if findings[i].Detail == "" {
					t.Fatal("finding has no explanation")
				}
				// Compare stable detection fields without coupling fixtures to prose.
				findings[i].Detail = ""
			}
			if !reflect.DeepEqual(findings, tt.want) {
				t.Fatalf("findings:\n%+v\nwant:\n%+v", findings, tt.want)
			}
		})
	}
}

func TestConfigurationAdoptionBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		source string
		state  string
	}{
		{
			name: "legacy provenance action",
			source: `jobs:
  ship:
    steps:
      - uses: actions/attest-build-provenance@v3
`,
			state: "adopted",
		},
		{
			name: "conditional provenance still signals adoption",
			source: `jobs:
  ship:
    steps:
      - if: false
        uses: actions/attest@v4
`,
			state: "adopted",
		},
		{
			name: "publisher without provenance",
			source: `jobs:
  ship:
    steps:
      - run: npm publish
`,
			state: "missing",
		},
		{
			name: "opaque script needs review",
			source: `jobs:
  ship:
    steps:
      - run: ./scripts/build-and-ship.sh
`,
			state: "review",
		},
		{
			name: "github script needs review",
			source: `jobs:
  ship:
    steps:
      - uses: actions/github-script@v8
`,
			state: "review",
		},
		{
			name: "disabled npm provenance",
			source: `jobs:
  ship:
    steps:
      - run: npm publish --provenance=false
`,
			state: "missing",
		},
		{
			name: "native Docker provenance",
			source: `jobs:
  ship:
    steps:
      - uses: docker/build-push-action@v6
        with:
          push: true
          provenance: mode=max
`,
			state: "adopted",
		},
		{
			name: "gh release publication",
			source: `jobs:
  ship:
    steps:
      - run: gh release create v1 dist/app
`,
			state: "missing",
		},
		{
			name: "release action needs review",
			source: `jobs:
  ship:
    steps:
      - uses: softprops/action-gh-release@pin
`,
			state: "review",
		},
		{
			name: "precompile action needs review",
			source: `jobs:
  ship:
    steps:
      - uses: cli/gh-extension-precompile@pin
`,
			state: "review",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := CheckConfiguration([]byte(tt.source), ".github/workflows/release.yml")
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].State != tt.state {
				t.Fatalf("findings %+v, want state %s", findings, tt.state)
			}
			text, issue := RenderConfiguration(findings, strings.Repeat("a", 40))
			if issue != (tt.state != "adopted") || !strings.Contains(text, "no artifact signatures verified") {
				t.Fatalf("issue %v: %s", issue, text)
			}
		})
	}
}

func TestSBOMOnlyIsNotProvenanceAdoption(t *testing.T) {
	source := []byte(`jobs:
  attest:
    steps:
      - uses: actions/attest-sbom@v3
        with:
          sbom-path: sbom.spdx.json
`)
	if _, adopted := AttestationConfiguration(source, ".github/workflows/sbom.yml"); adopted {
		t.Fatal("SBOM attestation incorrectly established provenance adoption")
	}
	findings, err := CheckConfiguration(source, ".github/workflows/sbom.yml")
	if err != nil || len(findings) != 0 {
		t.Fatalf("SBOM action alone is not a publisher: %+v, error %v", findings, err)
	}
}

func TestAdoptionStopsBeforeOtherJobs(t *testing.T) {
	source := []byte(`jobs:
  other:
    steps:
      - run: npm publish
  attest:
    steps:
      - uses: actions/attest@v4
`)
	findings, err := CheckConfiguration(source, ".github/workflows/release.yml")
	if err != nil || len(findings) != 1 || findings[0].State != "adopted" {
		t.Fatalf("findings %+v, error %v", findings, err)
	}
}

func TestWorkflowSourceAssessmentPreservesAdoptionPrecedence(t *testing.T) {
	sources := map[string][]byte{
		".github/workflows/a-invalid.yml": []byte("jobs: ["),
		".github/workflows/z-adopted.yml": []byte(`jobs:
  ship:
    steps:
      - uses: actions/attest@v4
`),
	}
	findings, err := CheckWorkflowSources(sources)
	if err != nil || len(findings) != 1 || findings[0].State != "adopted" ||
		findings[0].Workflow != ".github/workflows/z-adopted.yml" {
		t.Fatalf("findings %+v, error %v", findings, err)
	}
	delete(sources, ".github/workflows/z-adopted.yml")
	if _, err := CheckWorkflowSources(sources); err == nil {
		t.Fatal("invalid workflow ignored without adoption evidence")
	}
}

func TestWorkflowSourceFindingsAreSorted(t *testing.T) {
	source := []byte(`jobs:
  ship:
    steps:
      - run: npm publish
`)
	findings, err := CheckWorkflowSources(map[string][]byte{
		".github/workflows/z.yml": source,
		".github/workflows/a.yml": source,
	})
	if err != nil || len(findings) != 2 || findings[0].Workflow != ".github/workflows/a.yml" ||
		findings[1].Workflow != ".github/workflows/z.yml" {
		t.Fatalf("findings %+v, error %v", findings, err)
	}
}

func TestProvenanceRecognitionBoundaries(t *testing.T) {
	tests := []struct {
		name string
		step step
		want bool
	}{
		{
			name: "unversioned official action",
			step: step{Uses: "actions/attest"},
		},
		{
			name: "empty official ref",
			step: step{Uses: "actions/attest@"},
		},
		{
			name: "SBOM-specific action",
			step: step{Uses: "actions/attest-sbom@v3"},
		},
		{
			name: "unified action in SBOM mode",
			step: step{
				Uses: "actions/attest@v4",
				With: map[string]string{"sbom-path": "sbom.spdx.json"},
			},
		},
		{
			name: "unified action with a custom predicate",
			step: step{
				Uses: "actions/attest@v4",
				With: map[string]string{
					"predicate-type": "https://example.com/custom",
					"predicate-path": "predicate.json",
				},
			},
		},
		{
			name: "explicit native OCI",
			step: step{
				Uses: "docker/build-push-action",
				With: map[string]string{"provenance": "true"},
			},
			want: true,
		},
		{
			name: "disabled native OCI",
			step: step{
				Uses: "docker/build-push-action@v6",
				With: map[string]string{"provenance": "false"},
			},
		},
		{
			name: "native PyPI",
			step: step{
				Uses: "pypa/gh-action-pypi-publish@v1",
				With: map[string]string{"attestations": "true"},
			},
			want: true,
		},
		{
			name: "other publisher",
			step: step{
				Uses: "vendor/publish@v1",
				With: map[string]string{"attestations": "true"},
			},
		},
		{
			name: "literal npm provenance",
			step: step{Run: "npm publish --provenance=true"},
			want: true,
		},
		{
			name: "dynamic npm provenance",
			step: step{Run: "npm publish --provenance=$FLAG"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stepDeclaresProvenance(tt.step); got != tt.want {
				t.Fatalf("adoption %v, want %v", got, tt.want)
			}
		})
	}
}

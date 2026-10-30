package provenance

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func testRun() Run {
	return Run{ID: 42, URL: "https://github.com/o/r/actions/runs/42", SHA: strings.Repeat("a", 40), Path: ".github/workflows/release.yml", RefName: "v1.2.3", Repo: "o/r"}
}

func TestPublicationDirectoryPrecedence(t *testing.T) {
	var jobDefaults, workflowDefaults defaults
	jobDefaults.Run.WorkingDirectory = "job-dir"
	workflowDefaults.Run.WorkingDirectory = "workflow-dir"
	for _, tt := range []struct {
		name          string
		step          step
		job, workflow defaults
		want          string
	}{
		{"step", step{WorkingDir: "step-dir"}, jobDefaults, workflowDefaults, "step-dir"},
		{"job", step{}, jobDefaults, workflowDefaults, "job-dir"},
		{"workflow", step{}, defaults{}, workflowDefaults, "workflow-dir"},
		{"root", step{}, defaults{}, defaults{}, "."},
		{"empty expansion", step{WorkingDir: "${{ env.EMPTY }}"}, jobDefaults, workflowDefaults, "."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			expand := func(value string) string { return expandLiteral(value, testRun(), map[string]string{"EMPTY": ""}) }
			if got := publicationDirectory(tt.step, tt.job, tt.workflow, expand); got != tt.want {
				t.Fatalf("directory %q, want %q", got, tt.want)
			}
		})
	}
}

func TestActionPoliciesRemainDistinct(t *testing.T) {
	for _, tt := range []struct {
		uses                      string
		unexpanded, changesSource bool
	}{
		{"", false, false},
		{"actions/checkout@pin", false, false},
		{"actions/setup-node@pin", false, false},
		{"actions/github-script@pin", false, true},
		{"docker/setup-buildx-action@pin", false, false},
		{"docker/setup-custom@pin", true, false},
		{"docker/metadata-action@pin", false, true},
		{"docker/login-action@pin", false, false},
		{"./local-action", true, true},
		{"vendor/action@pin", true, true},
	} {
		t.Run(tt.uses, func(t *testing.T) {
			action, _, _ := strings.Cut(tt.uses, "@")
			if unexpandedPublisherAction(action) != tt.unexpanded || actionMayChangeSource(tt.uses) != tt.changesSource {
				t.Fatal("publisher and source-change policies changed")
			}
		})
	}
}

func TestUnsupportedManifestDoesNotReadFiles(t *testing.T) {
	for _, kind := range []string{"gem", "unsupported", ""} {
		_, _, err := manifestIdentity(t.Context(), kind, ".", func(context.Context, string) ([]byte, error) {
			t.Fatal("unsupported manifest must be rejected before file access")
			return nil, nil
		})
		if err == nil {
			t.Fatalf("kind %q accepted", kind)
		}
	}
}

func TestImageResolutionPreservesDiagnostics(t *testing.T) {
	base := Candidate{Kind: "oci", Workflow: testRun().Path, Job: "publish", Problem: "existing uncertainty"}
	images, gap := resolveImages(base, "false", "ghcr.io/o/r:v1")
	if len(images) != 0 || gap != ".github/workflows/release.yml job publish: image push is disabled or dynamic" {
		t.Fatalf("%+v %q", images, gap)
	}
	images, gap = resolveImages(base, "true", "")
	if gap != "" || len(images) != 1 || images[0].Problem != "existing uncertainty; image tags are absent or dynamic" {
		t.Fatalf("%+v %q", images, gap)
	}
	images, gap = resolveImages(base, "true", "ghcr.io/o/r:v1,${{ matrix.image }}")
	if gap != "" || len(images) != 2 || images[0].Name != "ghcr.io/o/r" ||
		images[1].Problem != "existing uncertainty; image name/tag requires unsupported expression evaluation; mutable image tag has no run-bound manifest digest" {
		t.Fatalf("%+v %q", images, gap)
	}
}

func TestWorkflowPublicationIdentities(t *testing.T) {
	tests := []struct {
		name, run, manifest, file, kind, expected string
	}{
		{"npm", "npm publish", `{"name":"@o/pkg","version":"1.2.3"}`, "package.json", "npm", "@o/pkg"},
		{"crate", "cargo publish", "[package]\nname = \"crate-name\"\nversion = \"1.2.3\"\n", "Cargo.toml", "crate", "crate-name"},
		{"maven", "mvn deploy", "<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1.2.3</version></project>", "pom.xml", "maven", "org.example:app"},
		{"gem", "gem push pkg/my-gem-1.2.3.gem", "", "", "gem", "my-gem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow := "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: Publish\n        run: " + tt.run + "\n"
			read := func(_ context.Context, file string) ([]byte, error) {
				if file != tt.file {
					t.Fatalf("unexpected manifest path %s", file)
				}
				return []byte(tt.manifest), nil
			}
			candidates, gaps, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(),
				[]Execution{{Job: "publish", Step: "Publish", Conclusion: "success"}}, read)
			if err != nil || len(gaps) != 0 || len(candidates) != 1 {
				t.Fatalf("candidates=%+v gaps=%v err=%v", candidates, gaps, err)
			}
			c := candidates[0]
			if c.Kind != tt.kind || c.Name != tt.expected || c.Version != "1.2.3" || c.Problem != "" || c.SHA != testRun().SHA {
				t.Fatalf("unexpected identity %+v", c)
			}
		})
	}
}

func TestWorkflowOCIAndPyPI(t *testing.T) {
	const workflow = `env:
  REGISTRY: ghcr.io
jobs:
  publish:
    steps:
      - uses: actions/checkout@pin
      - name: Image
        uses: docker/build-push-action@pin
        with:
          push: true
          tags: ${{ env.REGISTRY }}/${{ github.repository }}:v1.2.3
      - name: Package
        uses: pypa/gh-action-pypi-publish@pin
`
	candidates, _, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(),
		[]Execution{{"publish", "Image", "success"}, {"publish", "Package", "success"}},
		func(_ context.Context, file string) ([]byte, error) {
			if file != "pyproject.toml" {
				t.Fatalf("file %s", file)
			}
			return []byte("[project]\nname = \"example\"\nversion = \"1.2.3\""), nil
		})
	if err != nil || len(candidates) != 2 {
		t.Fatalf("%+v %v", candidates, err)
	}
	if candidates[0].Name != "ghcr.io/o/r" || !strings.Contains(candidates[0].Problem, "mutable") {
		t.Fatalf("tag must remain unbound to past run: %+v", candidates[0])
	}
	if candidates[1].Name != "example" || candidates[1].Kind != "pypi" {
		t.Fatalf("%+v", candidates[1])
	}
}

func TestDockerHubReferenceNormalization(t *testing.T) {
	for _, tt := range []struct{ tag, name string }{
		{"owner/image:v1", "docker.io/owner/image"},
		{"ubuntu:v1", "docker.io/library/ubuntu"},
		{"docker.io/owner/image:v1", "docker.io/owner/image"},
		{"ghcr.io/owner/image:v1", "ghcr.io/owner/image"},
		{"unknown.example/owner/image:v1", "unknown.example/owner/image"},
	} {
		name, version, _ := imageIdentity(tt.tag)
		if name != tt.name || version != "v1" {
			t.Fatalf("%s resolved to %s:%s", tt.tag, name, version)
		}
	}
}

func TestGemspecExecutionIsExplicitlyUnsupported(t *testing.T) {
	const workflow = "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: Publish\n        uses: rubygems/release-gem@pin\n"
	candidates, _, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(),
		[]Execution{{"publish", "Publish", "success"}}, nil)
	if err != nil || len(candidates) != 1 || candidates[0].Kind != "unsupported" || candidates[0].Problem == "" {
		t.Fatalf("%+v %v", candidates, err)
	}
}

func TestWorkflowDoesNotInferExecutedPublications(t *testing.T) {
	for _, name := range []string{"", "Publish"} {
		for _, conclusion := range []string{"failure", "skipped", ""} {
			workflow := "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: " + name + "\n        run: npm publish\n"
			candidates, _, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(),
				[]Execution{{"publish", "Publish", conclusion}},
				func(context.Context, string) ([]byte, error) { return []byte(`{"name":"pkg","version":"1"}`), nil })
			if err != nil || len(candidates) != 1 || candidates[0].Problem == "" {
				t.Fatalf("must retain uncertain publisher: %+v %v", candidates, err)
			}
		}
	}
}

func TestWorkflowEphemeralArtifactsIgnored(t *testing.T) {
	const workflow = `jobs:
  build:
    steps:
      - uses: actions/cache@pin
      - uses: actions/upload-artifact@pin
      - uses: actions/attest@pin
`
	candidates, gaps, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(), nil, nil)
	if err != nil || len(candidates) != 0 || len(gaps) != 0 {
		t.Fatalf("ephemeral uploads/attest actions are not distributions: %+v %v %v", candidates, gaps, err)
	}
}

func TestWorkflowUnknownsRemainVisible(t *testing.T) {
	tests := []string{
		"jobs:\n  publish:\n    uses: o/r/.github/workflows/publish.yml@main\n",
		"jobs:\n  publish:\n    steps:\n      - uses: ./publish\n",
		"jobs:\n  publish:\n    steps:\n      - run: docker push $IMAGE\n",
	}
	for _, data := range tests {
		candidates, gaps, err := ScanWorkflow(context.Background(), []byte(data), testRun(), nil, nil)
		if err != nil || len(candidates)+len(gaps) == 0 {
			t.Fatalf("publishing coverage was silently dropped: %+v %v %v", candidates, gaps, err)
		}
	}
}

func TestWorkflowRejectsDynamicManifestsAndCheckout(t *testing.T) {
	const workflow = `jobs:
  publish:
    steps:
      - uses: actions/checkout@pin
        with:
          ref: other
      - name: Publish
        run: |
          cd other
          npm publish --tag $TAG
`
	candidates, _, err := ScanWorkflow(context.Background(), []byte(workflow), testRun(),
		[]Execution{{"publish", "Publish", "success"}},
		func(context.Context, string) ([]byte, error) { return nil, errors.New("unavailable manifest") })
	if err != nil || len(candidates) != 1 || candidates[0].Problem == "" {
		t.Fatalf("%+v %v", candidates, err)
	}

}

func TestTwineShellPublishingIsExplicitlyUnsupported(t *testing.T) {
	source := "jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@pin\n      - name: Publish\n        run: twine upload dist/*\n"
	candidates, gaps, err := ScanWorkflow(t.Context(), []byte(source), testRun(),
		[]Execution{{"publish", "Publish", "success"}},
		func(context.Context, string) ([]byte, error) {
			t.Fatal("unsupported Twine shell command must not resolve a guessed package identity")
			return nil, nil
		})
	if err != nil || len(gaps) != 0 || len(candidates) != 1 || candidates[0].Kind != "unsupported" {
		t.Fatalf("%+v %v %v", candidates, gaps, err)
	}
	findings, err := CheckConfiguration([]byte(source), testRun().Path)
	if err != nil || len(findings) != 1 || findings[0].State != "review" {
		t.Fatalf("%+v %v", findings, err)
	}
}

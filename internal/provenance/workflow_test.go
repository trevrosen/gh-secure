package provenance

import (
	"strings"
	"testing"
)

func TestPublishingConfigurationNeedsNoArtifactResolution(t *testing.T) {
	tests := []struct {
		script string
		kind   string
	}{
		{script: "npm publish", kind: "npm"},
		{script: "twine upload dist/*", kind: "pypi"},
		{script: "cargo publish", kind: "crate"},
		{script: "gem push pkg/app-1.gem", kind: "gem"},
		{script: "mvn -B deploy", kind: "maven"},
		{script: "docker push image", kind: "oci"},
		{script: "gh release create v1 dist/app", kind: "release"},
		{script: "gh release upload v1 dist/app", kind: "release"},
		{script: "gh release list", kind: ""},
		{script: "gh release download v1", kind: ""},
		{script: "gh release delete v1", kind: ""},
	}

	for _, tt := range tests {
		t.Run(tt.script, func(t *testing.T) {
			if got := publisher(step{Run: tt.script}); got != tt.kind {
				t.Fatalf("publisher %q, want %q", got, tt.kind)
			}
		})
	}
}

func TestAssistanceTargetUsesFutureBuildOutputWithoutAnArtifactDigest(t *testing.T) {
	for _, tag := range []string{"ghcr.io/o/r:v1", "ghcr.io/${{ github.repository }}:${{ github.ref_name }}"} {
		source := strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", tag)
		target, err := AssistanceTarget([]byte(source), ".github/workflows/release.yml", "publish", strings.Repeat("a", 40), "o/r")
		if err != nil || target.Name != "ghcr.io/o/r" {
			t.Fatalf("target %+v error %v", target, err)
		}
		digest, err := assistanceSubject([]byte(source), target, "o/r")
		if err != nil || digest != "${{ steps.image.outputs.digest }}" {
			t.Fatalf("digest expression %s error %v", digest, err)
		}
	}
}

func TestAssistanceTargetRejectsAmbiguousOrUnsupportedPublishers(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name:   "malformed YAML",
			source: "jobs: [",
		},
		{
			name: "missing selected job",
			source: `jobs:
  other:
    steps: []
`,
		},
		{
			name: "package publishing requires manual guidance",
			source: `jobs:
  publish:
    steps:
      - run: npm publish
`,
		},
		{
			name:   "dynamic image names",
			source: strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "${{ steps.meta.outputs.tags }}"),
		},
		{
			name:   "multiple image names",
			source: strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "ghcr.io/o/r:v1,ghcr.io/o/other:v1"),
		},
		{
			name:   "push disabled",
			source: strings.ReplaceAll(originalImageWorkflow, "push: true", "push: false"),
		},
		{
			name: "multiple publishing steps",
			source: originalImageWorkflow + `      - uses: docker/build-push-action@pin
        with:
          push: true
          tags: ghcr.io/o/r:v2
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AssistanceTarget([]byte(tt.source), ".github/workflows/release.yml", "publish", strings.Repeat("a", 40), "o/r")
			if err == nil {
				t.Fatalf("accepted ambiguous or unsupported source:\n%s", tt.source)
			}
		})
	}
}

func TestPublisherSubjectNamesAreStaticAndUnambiguous(t *testing.T) {
	tests := []struct {
		tags string
		want string
	}{
		{
			tags: "app:v1",
			want: "docker.io/library/app",
		},
		{
			tags: "o/app:v1,o/app:latest",
			want: "docker.io/o/app",
		},
		{
			tags: "ghcr.io/${{ github.repository }}:latest",
			want: "ghcr.io/o/r",
		},
		{
			tags: "${{ env.REGISTRY }}/${{ github.repository }}:latest",
			want: "ghcr.io/o/r",
		},
		{
			tags: "ghcr.io/o/app@sha256:anything",
			want: "ghcr.io/o/app",
		},
		{
			tags: "${{ steps.meta.outputs.tags }}",
			want: "",
		},
		{
			tags: "ghcr.io/o/app:v1,ghcr.io/o/other:v1",
			want: "",
		},
		{
			tags: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.tags, func(t *testing.T) {
			workflowEnv := map[string]string{"REGISTRY": "wrong"}
			jobEnv := map[string]string{"REGISTRY": "ghcr.io"}
			got, err := publisherSubject(tt.tags, "o/r", workflowEnv, jobEnv)
			if tt.want == "" {
				if err == nil {
					t.Fatal("expected an unresolved subject error")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("name %q error %v, want %q", got, err, tt.want)
			}
		})
	}
}

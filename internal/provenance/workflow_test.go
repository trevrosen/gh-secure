package provenance

import (
	"strings"
	"testing"
)

func TestPublishingConfigurationNeedsNoArtifactResolution(t *testing.T) {
	for _, tt := range []struct{ script, kind string }{
		{"npm publish", "npm"}, {"twine upload dist/*", "pypi"},
		{"cargo publish", "crate"}, {"gem push pkg/app-1.gem", "gem"},
		{"mvn -B deploy", "maven"}, {"docker push image", "oci"},
		{"gh release create v1 dist/app", "release"}, {"gh release upload v1 dist/app", "release"},
		{"gh release list", ""}, {"gh release download v1", ""}, {"gh release delete v1", ""},
	} {
		if got := publisher(step{Run: tt.script}); got != tt.kind {
			t.Errorf("%s: got %s want %s", tt.script, got, tt.kind)
		}
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
	for _, source := range []string{
		"jobs: [",
		"jobs:\n  other:\n    steps: []\n",
		"jobs:\n  publish:\n    steps:\n      - run: npm publish\n",
		strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "${{ steps.meta.outputs.tags }}"),
		strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "ghcr.io/o/r:v1,ghcr.io/o/other:v1"),
		strings.ReplaceAll(originalImageWorkflow, "push: true", "push: false"),
		originalImageWorkflow + "      - uses: docker/build-push-action@pin\n        with:\n          push: true\n          tags: ghcr.io/o/r:v2\n",
	} {
		if _, err := AssistanceTarget([]byte(source), ".github/workflows/release.yml", "publish", strings.Repeat("a", 40), "o/r"); err == nil {
			t.Fatalf("accepted ambiguous or unsupported source: %s", source)
		}
	}

}

func TestPublisherSubjectNamesAreStaticAndUnambiguous(t *testing.T) {
	for _, tt := range []struct {
		tags, want string
	}{
		{"app:v1", "docker.io/library/app"},
		{"o/app:v1,o/app:latest", "docker.io/o/app"},
		{"ghcr.io/${{ github.repository }}:latest", "ghcr.io/o/r"},
		{"${{ env.REGISTRY }}/${{ github.repository }}:latest", "ghcr.io/o/r"},
		{"ghcr.io/o/app@sha256:anything", "ghcr.io/o/app"},
		{"${{ steps.meta.outputs.tags }}", ""},
		{"ghcr.io/o/app:v1,ghcr.io/o/other:v1", ""},
		{"", ""},
	} {
		got, err := publisherSubject(tt.tags, "o/r", map[string]string{"REGISTRY": "wrong"}, map[string]string{"REGISTRY": "ghcr.io"})
		if tt.want == "" && err == nil || tt.want != "" && (err != nil || got != tt.want) {
			t.Errorf("%s: name %q error %v, want %q", tt.tags, got, err, tt.want)
		}
	}
}

// Package provenance detects workflow attestation adoption and helps enable it.
// It does not resolve published artifacts or verify attestations.
package provenance

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

type workflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]job    `yaml:"jobs"`
}

type job struct {
	Uses  string            `yaml:"uses"`
	Env   map[string]string `yaml:"env"`
	Steps []step            `yaml:"steps"`
}

type step struct {
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

var exactSHA = regexp.MustCompile(`^[a-f0-9]{40}$`)

// WorkflowPath permits only ordinary repository workflow files.
func WorkflowPath(value string) bool {
	return strings.HasPrefix(value, ".github/workflows/") &&
		path.Dir(value) == ".github/workflows" &&
		!strings.ContainsAny(value, "\\\x00\r\n$") && path.Clean(value) == value &&
		(strings.HasSuffix(value, ".yml") || strings.HasSuffix(value, ".yaml"))
}

// publisher recognizes publishing configuration, not successful publication.
func publisher(s step) string {
	action, _, _ := strings.Cut(strings.ToLower(s.Uses), "@")
	switch action {
	case "docker/build-push-action":
		return "oci"
	case "pypa/gh-action-pypi-publish":
		return "pypi"
	case "rubygems/release-gem":
		return "gem"
	}
	if ghReleaseCommand.MatchString(s.Run) {
		return "release"
	}
	text := strings.ToLower(s.Run)
	for _, item := range []struct{ match, kind string }{
		{"npm publish", "npm"}, {"pnpm publish", "npm"}, {"yarn npm publish", "npm"},
		{"twine upload", "pypi"}, {"cargo publish", "crate"}, {"gem push", "gem"},
		{"mvn deploy", "maven"}, {"mvn --batch-mode deploy", "maven"}, {"mvn -b deploy", "maven"},
		{"docker push", "oci"}, {"buildx", "unsupported"},
		{"publish", "unsupported"}, {"deploy", "unsupported"},
	} {
		if strings.Contains(text, item.match) {
			return item.kind
		}
	}
	return ""
}

var ghReleaseCommand = regexp.MustCompile(`(?:^|[\s;&|])gh[ \t]+release[ \t]+(?:create|upload)(?:[\s;&|]|$)`)

func literalNPMPublish(text string) bool {
	return slices.Contains([]string{"npm publish", "npm publish --access public", "pnpm publish", "yarn npm publish"}, strings.TrimSpace(text))
}

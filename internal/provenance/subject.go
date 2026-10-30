package provenance

import (
	"errors"
	"regexp"
	"strings"
)

var subjectExpression = regexp.MustCompile(`\$\{\{\s*([^{}]+?)\s*\}\}`)
var imageName = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// publisherSubject reads the name to put in a future attestation step. Tags and
// digests are not resolved: the new step references the build step's digest output.
func publisherSubject(tags, repo string, environments ...map[string]string) (string, error) {
	env := make(map[string]string)
	for _, values := range environments {
		for key, value := range values {
			env[key] = value
		}
	}
	tags = subjectExpression.ReplaceAllStringFunc(tags, func(token string) string {
		key := strings.TrimSpace(subjectExpression.FindStringSubmatch(token)[1])
		if key == "github.repository" {
			return strings.ToLower(repo)
		}
		if strings.HasPrefix(key, "env.") {
			if value, ok := env[strings.TrimPrefix(key, "env.")]; ok && !strings.Contains(value, "${{") {
				return value
			}
		}
		return token
	})
	subject := ""
	for _, tag := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == '\n' }) {
		name := strings.TrimSpace(tag)
		// Remove unresolved tag expressions before examining the repository name.
		name, _, _ = strings.Cut(name, "@")
		if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
			name = name[:i]
		}
		if !imageName.MatchString(name) {
			return "", errors.New("OCI subject name is dynamic or unsupported; use manual guidance")
		}
		first, _, hasPath := strings.Cut(name, "/")
		if !strings.Contains(first, ".") && first != "localhost" {
			if !hasPath {
				name = "library/" + name
			}
			name = "docker.io/" + name
		}
		if subject != "" && subject != name {
			return "", errors.New("OCI publisher has multiple subject names; use manual guidance")
		}
		subject = name
	}
	if subject == "" {
		return "", errors.New("OCI publisher has no identifiable subject name; use manual guidance")
	}
	return subject, nil
}

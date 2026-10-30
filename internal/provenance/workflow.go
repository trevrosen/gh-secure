package provenance

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Run identifies the immutable workflow revision and the inspected execution.
type Run struct {
	ID      int64
	URL     string
	SHA     string
	Path    string
	RefName string
	Repo    string
}

// Execution is a successful or failed job step disclosed by the Actions API.
type Execution struct {
	Job, Step, Conclusion string
}

// ReadFile reads a repository file at the run's immutable commit.
type ReadFile func(context.Context, string) ([]byte, error)

type workflow struct {
	Env      map[string]string `yaml:"env"`
	Defaults defaults          `yaml:"defaults"`
	Jobs     map[string]job    `yaml:"jobs"`
}

type job struct {
	Name     string            `yaml:"name"`
	Uses     string            `yaml:"uses"`
	Env      map[string]string `yaml:"env"`
	Defaults defaults          `yaml:"defaults"`
	Steps    []step            `yaml:"steps"`
}

type defaults struct {
	Run struct {
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type step struct {
	Name       string            `yaml:"name"`
	Uses       string            `yaml:"uses"`
	Run        string            `yaml:"run"`
	WorkingDir string            `yaml:"working-directory"`
	With       map[string]string `yaml:"with"`
	Env        map[string]string `yaml:"env"`
}

var expression = regexp.MustCompile(`\$\{\{\s*([^{}]+?)\s*\}\}`)
var exactSHA = regexp.MustCompile(`^[a-f0-9]{40}$`)
var literalGem = regexp.MustCompile(`^gem push (?:pkg/)?([A-Za-z0-9_][A-Za-z0-9_-]*)-([0-9][A-Za-z0-9_.-]*)\.gem$`)

// ScanWorkflow extracts publication candidates without evaluating shell, matrix,
// repository code, or arbitrary Actions expressions. Dynamic cases remain gaps.
func ScanWorkflow(ctx context.Context, data []byte, run Run, executions []Execution, read ReadFile) ([]Candidate, []string, error) {
	if !exactSHA.MatchString(run.SHA) || !WorkflowPath(run.Path) {
		return nil, nil, errors.New("run has no supported immutable workflow revision")
	}
	var document workflow
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, nil, errors.New("workflow is not supported YAML")
	}
	var candidates []Candidate
	var gaps []string
	for _, key := range sortedJobs(document) {
		current := document.Jobs[key]
		if current.Uses != "" {
			gaps = append(gaps, fmt.Sprintf("%s job %s: reusable workflow is not expanded", run.Path, key))
			continue
		}
		for stepIndex, action := range current.Steps {
			if err := ctx.Err(); err != nil {
				return candidates, gaps, err
			}
			kind := publisher(action)
			if kind == "" {
				continue
			}
			candidate := publicationCandidate(run, key, current, stepIndex, kind, executions)
			env := mergeEnv(document.Env, current.Env, action.Env)
			expand := func(value string) string { return expandLiteral(value, run, env) }
			switch kind {
			case "oci":
				images, gap := resolveImages(candidate, expand(action.With["push"]), expand(action.With["tags"]))
				candidates = append(candidates, images...)
				if gap != "" {
					gaps = append(gaps, gap)
				}
			case "release":
				candidate.Evidence = "workflow shell contains gh release create/upload; detection only"
				candidate.Problem = joinProblem(candidate.Problem, "gh release publication detected; release asset resolution and attestation verification are not implemented")
				candidates = append(candidates, candidate)
			case "unsupported":
				candidate.Problem = joinProblem(candidate.Problem, "publication outputs require explicit digest and producer association")
				candidates = append(candidates, candidate)
			default:
				dir := publicationDirectory(action, current.Defaults, document.Defaults, expand)
				candidates = append(candidates, resolvePackage(ctx, candidate, action, dir, env, read))
			}
		}
	}
	return candidates, gaps, nil
}

func publicationCandidate(run Run, jobID string, current job, stepIndex int, kind string, executions []Execution) Candidate {
	jobName := current.Name
	if jobName == "" {
		jobName = jobID
	}
	candidate := Candidate{
		Kind: kind, Workflow: run.Path, Job: jobID, RunID: run.ID,
		RunURL: run.URL, SHA: run.SHA,
		Evidence: "workflow publication candidate; execution and immutable identity must be established",
	}
	if !successfulPublisher(jobName, current.Steps[stepIndex].Name, executions) {
		candidate.Problem = "publisher execution cannot be uniquely established from named job/step results"
	}
	if !defaultCheckout(current.Steps) {
		candidate.Problem = joinProblem(candidate.Problem, "source checkout is absent, overridden, or ambiguous")
	}
	if priorSourceMayChange(current.Steps[:stepIndex]) {
		candidate.Problem = joinProblem(candidate.Problem, "earlier workflow steps may change publication identity or configuration")
	}
	return candidate
}

func resolveImages(candidate Candidate, push, tags string) ([]Candidate, string) {
	if push != "true" {
		return nil, fmt.Sprintf("%s job %s: image push is disabled or dynamic", candidate.Workflow, candidate.Job)
	}
	references := strings.FieldsFunc(tags, func(r rune) bool { return r == '\n' || r == ',' })
	if len(references) == 0 {
		candidate.Problem = joinProblem(candidate.Problem, "image tags are absent or dynamic")
		return []Candidate{candidate}, ""
	}
	var images []Candidate
	for _, tag := range references {
		image := candidate
		image.Name, image.Version, image.Digest = imageIdentity(strings.TrimSpace(tag))
		if image.Name == "" {
			image.Problem = joinProblem(image.Problem, "image name/tag requires unsupported expression evaluation")
		}
		// Resolving a mutable tag now does not prove which digest a past run pushed.
		if image.Digest == "" {
			image.Problem = joinProblem(image.Problem, "mutable image tag has no run-bound manifest digest")
		}
		images = append(images, image)
	}
	return images, ""
}

func publicationDirectory(action step, jobDefaults, workflowDefaults defaults, expand func(string) string) string {
	dir := action.WorkingDir
	if dir == "" {
		dir = jobDefaults.Run.WorkingDirectory
	}
	if dir == "" {
		dir = workflowDefaults.Run.WorkingDirectory
	}
	dir = expand(dir)
	if dir == "" {
		return "."
	}
	return dir
}

func resolvePackage(ctx context.Context, candidate Candidate, action step, dir string, env map[string]string, read ReadFile) Candidate {
	kind := candidate.Kind
	if kind == "gem" && strings.HasPrefix(action.Uses, "rubygems/release-gem@") {
		candidate.Kind = "unsupported"
		candidate.Problem = "RubyGems release action requires gemspec evaluation; only literal gem push publication is currently resolved"
		return candidate
	}
	switch {
	case kind == "gem" && literalGem.MatchString(strings.TrimSpace(action.Run)):
		matches := literalGem.FindStringSubmatch(strings.TrimSpace(action.Run))
		candidate.Name, candidate.Version = matches[1], matches[2]
	case !safeRelative(dir):
		candidate.Problem = joinProblem(candidate.Problem, "working directory is dynamic or outside the repository")
	default:
		name, version, err := manifestIdentity(ctx, kind, dir, read)
		candidate.Name, candidate.Version = name, version
		if err != nil {
			candidate.Problem = joinProblem(candidate.Problem, err.Error())
		}
	}
	if action.Run != "" && !simplePublish(kind, action.Run) {
		candidate.Problem = joinProblem(candidate.Problem, "publisher shell script has unsupported arguments or dynamic behavior")
	}
	if kind == "pypi" && action.With["repository-url"] != "" {
		candidate.Problem = joinProblem(candidate.Problem, "custom PyPI repository is outside public pypi.org coverage")
	}
	if kind == "npm" && (env["NPM_CONFIG_REGISTRY"] != "" || env["npm_config_registry"] != "") {
		candidate.Problem = joinProblem(candidate.Problem, "npm registry override cannot establish publication to registry.npmjs.org")
	}
	if candidate.Problem == "" {
		candidate.Evidence = "named publisher succeeded; literal package identity read from workflow source commit"
	}
	return candidate
}

// WorkflowPath permits only ordinary repository workflow files.
func WorkflowPath(value string) bool {
	return strings.HasPrefix(value, ".github/workflows/") &&
		path.Dir(value) == ".github/workflows" && safeRelative(value) &&
		(strings.HasSuffix(value, ".yml") || strings.HasSuffix(value, ".yaml"))
}

func safeRelative(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\\\x00\r\n$") &&
		!strings.HasPrefix(value, "/") && path.Clean(value) == value &&
		value != ".." && !strings.HasPrefix(value, "../")
}

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
	text := strings.ToLower(s.Run)
	if ghReleasePublisher(s.Run) {
		return "release"
	}
	for _, item := range []struct{ match, kind string }{
		{"npm publish", "npm"}, {"pnpm publish", "npm"}, {"yarn npm publish", "npm"},
		{"twine upload", "unsupported"}, {"cargo publish", "crate"}, {"gem push", "gem"},
		{"mvn deploy", "maven"}, {"mvn --batch-mode deploy", "maven"}, {"mvn -b deploy", "maven"},
		{"docker push", "unsupported"}, {"buildx", "unsupported"},
		{"publish", "unsupported"}, {"deploy", "unsupported"},
	} {
		if strings.Contains(text, item.match) {
			return item.kind
		}
	}
	if unexpandedPublisherAction(action) {
		return "unsupported"
	}
	return ""
}

func unexpandedPublisherAction(action string) bool {
	if action == "" || strings.HasPrefix(action, "actions/") {
		return false
	}
	switch action {
	case "docker/login-action", "docker/metadata-action", "docker/setup-buildx-action", "docker/setup-qemu-action":
		return false
	}
	return true
}

var ghReleaseCommand = regexp.MustCompile(`(?:^|[\s;&|])gh[ \t]+release[ \t]+(?:create|upload)(?:[\s;&|]|$)`)

func ghReleasePublisher(script string) bool {
	return ghReleaseCommand.MatchString(script)
}

func simplePublish(kind, text string) bool {
	switch kind {
	case "npm":
		return slices.Contains([]string{"npm publish", "npm publish --access public", "pnpm publish", "yarn npm publish"}, strings.TrimSpace(text))
	case "crate":
		return strings.TrimSpace(text) == "cargo publish"
	case "maven":
		return slices.Contains([]string{"mvn deploy", "mvn --batch-mode deploy", "mvn -B deploy"}, strings.TrimSpace(text))
	case "gem":
		return literalGem.MatchString(strings.TrimSpace(text))
	}
	return false
}

func defaultCheckout(steps []step) bool {
	count := 0
	for _, s := range steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			count++
			for _, key := range []string{"ref", "repository", "path"} {
				if s.With[key] != "" {
					return false
				}
			}
		}
	}
	return count == 1
}

func priorSourceMayChange(steps []step) bool {
	for _, s := range steps {
		// Toolchain setup and checkout do not establish that arbitrary scripts,
		// composite actions or build steps left source manifests/config unchanged.
		if s.Run != "" || actionMayChangeSource(s.Uses) {
			return true
		}
	}
	return false
}

func actionMayChangeSource(uses string) bool {
	if uses == "" {
		return false
	}
	for _, prefix := range []string{"actions/checkout@", "actions/setup-", "docker/setup-", "docker/login-action@"} {
		if strings.HasPrefix(uses, prefix) {
			return false
		}
	}
	return true
}

func successfulPublisher(jobName, stepName string, executions []Execution) bool {
	if stepName == "" || strings.Contains(jobName+stepName, "${{") {
		return false
	}
	count := 0
	for _, execution := range executions {
		if execution.Job == jobName && execution.Step == stepName {
			if execution.Conclusion != "success" {
				return false
			}
			count++
		}
	}
	return count == 1
}

func mergeEnv(maps ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, values := range maps {
		for key, value := range values {
			out[key] = value
		}
	}
	return out
}

func expandLiteral(value string, run Run, env map[string]string) string {
	return expression.ReplaceAllStringFunc(value, func(token string) string {
		key := strings.TrimSpace(expression.FindStringSubmatch(token)[1])
		switch key {
		case "github.repository":
			return run.Repo
		case "github.ref_name":
			return run.RefName
		case "github.sha":
			return run.SHA
		}
		if strings.HasPrefix(key, "env.") {
			v, ok := env[strings.TrimPrefix(key, "env.")]
			if ok && !strings.Contains(v, "${{") {
				return v
			}
		}
		return token
	})
}

func imageIdentity(value string) (string, string, string) {
	if strings.ContainsAny(value, "$ {}'\"\\\r\n") || value == "" {
		return "", "", ""
	}
	name, digest, pinned := strings.Cut(value, "@")
	if pinned {
		if !ValidDigest(digest) {
			return "", "", ""
		}
		return normalizeImageName(name), "", digest
	}
	index := strings.LastIndex(value, ":")
	if index <= strings.LastIndex(value, "/") {
		return normalizeImageName(value), "latest", ""
	}
	return normalizeImageName(value[:index]), value[index+1:], ""
}

func normalizeImageName(name string) string {
	first, _, hasPath := strings.Cut(name, "/")
	if !strings.ContainsAny(first, ".:") && first != "localhost" {
		if !hasPath {
			return "docker.io/library/" + name
		}
		return "docker.io/" + name
	}
	return name
}

func joinProblem(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func manifestIdentity(ctx context.Context, kind, dir string, read ReadFile) (string, string, error) {
	var file string
	switch kind {
	case "npm":
		file = "package.json"
	case "pypi":
		file = "pyproject.toml"
	case "crate":
		file = "Cargo.toml"
	case "maven":
		file = "pom.xml"
	case "gem":
		return "", "", errors.New("RubyGems gemspec identity requires an explicit literal gem push filename; gemspec code is never executed")
	default:
		return "", "", errors.New("unsupported publication manifest")
	}
	data, err := read(ctx, path.Join(dir, file))
	if err != nil {
		return "", "", fmt.Errorf("cannot read publication manifest %s: %w", path.Join(dir, file), err)
	}
	switch kind {
	case "npm":
		var manifest struct {
			Name, Version string
			PublishConfig struct {
				Registry string `json:"registry"`
			} `json:"publishConfig"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return "", "", errors.New("invalid package.json")
		}
		if manifest.PublishConfig.Registry != "" && manifest.PublishConfig.Registry != "https://registry.npmjs.org/" &&
			manifest.PublishConfig.Registry != "https://registry.npmjs.org" {
			return manifest.Name, manifest.Version, errors.New("package publishConfig selects an unsupported npm registry")
		}
		return checkedManifest(manifest.Name, manifest.Version)
	case "pypi", "crate":
		section := "project"
		if kind == "crate" {
			section = "package"
		}
		name, version := tomlLiteral(data, section, "name"), tomlLiteral(data, section, "version")
		return checkedManifest(name, version)
	case "maven":
		var manifest struct {
			Group    string `xml:"groupId"`
			Artifact string `xml:"artifactId"`
			Version  string `xml:"version"`
		}
		if err := xml.Unmarshal(data, &manifest); err != nil {
			return "", "", errors.New("invalid pom.xml")
		}
		return checkedManifest(manifest.Group+":"+manifest.Artifact, manifest.Version)
	}
	return "", "", errors.New("unsupported publication manifest")
}

func checkedManifest(name, version string) (string, string, error) {
	if name == "" || version == "" || strings.ContainsAny(name+version, "$\r\n{}") {
		return name, version, errors.New("manifest identity is missing or dynamic")
	}
	return name, version, nil
}

func tomlLiteral(data []byte, section, key string) string {
	current := ""
	value := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			current = line
		}
		if current != "["+section+"]" {
			continue
		}
		lhs, rhs, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(lhs) != key {
			continue
		}
		rhs = strings.TrimSpace(rhs)
		if value != "" || len(rhs) < 2 || rhs[0] != '"' || rhs[len(rhs)-1] != '"' {
			return ""
		}
		value = rhs[1 : len(rhs)-1]
	}
	return value
}

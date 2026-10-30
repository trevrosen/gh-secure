package provenance

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigurationFinding concerns source configuration, never a published digest.
type ConfigurationFinding struct {
	Workflow, Job, Publisher, State, Detail string
}

// AttestationConfiguration recognizes provenance adoption, not complete coverage.
// SBOM and custom-predicate attestations do not establish provenance adoption.
func AttestationConfiguration(data []byte, file string) (ConfigurationFinding, bool) {
	var w workflow
	if yaml.Unmarshal(data, &w) != nil {
		return ConfigurationFinding{}, false
	}
	return workflowAdoption(w, file)
}

func workflowAdoption(w workflow, file string) (ConfigurationFinding, bool) {
	for _, key := range sortedJobs(w) {
		for _, s := range w.Jobs[key].Steps {
			if !stepDeclaresProvenance(s) {
				continue
			}
			label := s.Uses
			if label == "" {
				label = "npm publisher with --provenance"
			}
			return ConfigurationFinding{
				Workflow: file, Job: key, Publisher: label, State: "adopted",
				Detail: "provenance attestation configuration is present; adoption check stops here, without assessing correctness, completeness or published artifacts",
			}, true
		}
	}
	return ConfigurationFinding{}, false
}

func stepDeclaresProvenance(s step) bool {
	if nativeNPMProvenance(s.Run) {
		return true
	}
	action, ref, _ := strings.Cut(s.Uses, "@")
	switch action {
	case "actions/attest-build-provenance":
		return ref != ""
	case "actions/attest":
		// The unified action defaults to provenance, but can instead attest
		// an SBOM or a custom predicate. Neither substitutes for provenance.
		return ref != "" && s.With["sbom-path"] == "" &&
			s.With["predicate-path"] == "" && s.With["predicate-type"] == ""
	case "docker/build-push-action":
		value := s.With["provenance"]
		return value == "true" || strings.HasPrefix(value, "mode=")
	case "pypa/gh-action-pypi-publish":
		return s.With["attestations"] == "true"
	default:
		return false
	}
}

// CheckWorkflowSources gives repository-wide adoption precedence over other
// findings, including malformed workflows, regardless of source traversal order.
func CheckWorkflowSources(sources map[string][]byte) ([]ConfigurationFinding, error) {
	paths := make([]string, 0, len(sources))
	for file := range sources {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	for _, file := range paths {
		if adopted, ok := AttestationConfiguration(sources[file], file); ok {
			return []ConfigurationFinding{adopted}, nil
		}
	}
	var findings []ConfigurationFinding
	for _, file := range paths {
		result, err := CheckConfiguration(sources[file], file)
		if err != nil {
			return nil, err
		}
		findings = append(findings, result...)
	}
	return findings, nil
}

// CheckConfiguration performs no execution, registry lookup, or run enumeration.
func CheckConfiguration(data []byte, file string) ([]ConfigurationFinding, error) {
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%s: unsupported workflow YAML", file)
	}
	if adopted, ok := workflowAdoption(w, file); ok {
		return []ConfigurationFinding{adopted}, nil
	}
	if len(w.Jobs) == 0 {
		return nil, fmt.Errorf("%s: workflow has no supported jobs", file)
	}
	var findings []ConfigurationFinding
	for _, key := range sortedJobs(w) {
		j := w.Jobs[key]
		if j.Uses != "" {
			findings = append(findings, ConfigurationFinding{
				Workflow: file, Job: key, Publisher: j.Uses, State: "review",
				Detail: "reusable workflow is not expanded; publication coverage is unknown",
			})
			continue
		}
		for i, s := range j.Steps {
			if finding, relevant := stepConfiguration(s, i); relevant {
				finding.Workflow, finding.Job = file, key
				findings = append(findings, finding)
			}
		}
	}
	return findings, nil
}

func stepConfiguration(s step, index int) (ConfigurationFinding, bool) {
	kind := publisher(s)
	if kind == "" && s.Uses != "" && !nonPublishingAction(s.Uses) {
		kind = "unsupported"
	}
	if kind == "" && s.Run == "" {
		return ConfigurationFinding{}, false
	}
	if kind == "oci" && s.With["push"] == "false" {
		return ConfigurationFinding{}, false
	}
	finding := ConfigurationFinding{Publisher: s.Uses, State: "review"}
	if finding.Publisher == "" {
		finding.Publisher = fmt.Sprintf("shell step %d", index+1)
	}
	switch kind {
	case "", "unsupported":
		finding.Detail = "script or action is not expanded; cannot rule out publishing or establish provenance configuration"
	default:
		finding.State = "missing"
		finding.Detail = "recognized " + kind + " publisher has no identifiable attestation path; publisher-native provenance may exist"
	}
	return finding, true
}

func sortedJobs(w workflow) []string {
	keys := make([]string, 0, len(w.Jobs))
	for key := range w.Jobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nativeNPMProvenance(script string) bool {
	args := strings.Fields(script)
	for i, arg := range args {
		if arg == "--provenance" || arg == "--provenance=true" {
			withoutFlag := append(append([]string{}, args[:i]...), args[i+1:]...)
			return literalNPMPublish(strings.Join(withoutFlag, " "))
		}
	}
	return false
}

func nonPublishingAction(uses string) bool {
	action, _, _ := strings.Cut(uses, "@")
	switch action {
	case "actions/checkout", "actions/cache", "actions/cache/save", "actions/cache/restore",
		"actions/upload-artifact", "actions/download-artifact",
		"actions/setup-node", "actions/setup-go", "actions/setup-python", "actions/setup-java",
		"actions/setup-dotnet", "actions/attest-sbom", "docker/login-action", "docker/metadata-action",
		"docker/setup-buildx-action", "docker/setup-qemu-action":
		return true
	}
	return false
}

func RenderConfiguration(findings []ConfigurationFinding, sha string) (string, bool) {
	var out strings.Builder
	fmt.Fprintf(&out, "\nWorkflow provenance attestation adoption (default branch at %s)\n", sha)
	out.WriteString("Static source inspection only; no Actions runs or registries queried, no artifact signatures verified. Other branches and historical releases are outside coverage.\n")
	issue := false
	for _, f := range findings {
		fmt.Fprintf(&out, "  %s %s job %s [%s]: %s\n", f.State, f.Workflow, f.Job, f.Publisher, f.Detail)
		issue = issue || f.State != "adopted"
	}
	if len(findings) == 0 {
		out.WriteString("  No recognized distribution publishers found; this is not proof that this repository publishes nothing.\n")
	}
	if issue {
		out.WriteString("Guidance: add build provenance to distributed packages/images/release files using actions/attest or publisher-native provenance with appropriately scoped permissions. Inspect scripts/reusable workflows manually. Local Copilot assistance requires gh secure provenance assist --workflow PATH --job ID --consent. To verify an attested artifact, use gh attestation verify.\n")
	}
	return out.String(), issue
}

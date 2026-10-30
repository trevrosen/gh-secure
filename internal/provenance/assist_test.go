package provenance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const originalImageWorkflow = `name: Release
on: push
permissions:
  contents: read
  packages: write
jobs:
  publish:
    steps:
      - uses: actions/checkout@pin
      - name: Image
        id: image
        uses: docker/build-push-action@pin
        with:
          push: true
          tags: ghcr.io/o/r:v1
`

func proposedImageWorkflow() string {
	const jobPermissions = `  publish:
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
`
	const attestationStep = `      - name: Attest
        uses: ACTION_PIN
        with:
          subject-name: ghcr.io/o/r
          subject-digest: ${{ steps.image.outputs.digest }}
          push-to-registry: true
`
	withPermissions := strings.Replace(originalImageWorkflow, "  publish:\n", jobPermissions, 1)
	return withPermissions + strings.Replace(attestationStep, "ACTION_PIN", AttestAction, 1)
}

func TestAssistanceSubjectNormalizesDockerHubShortReferences(t *testing.T) {
	source := strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "o/r:v1")
	subject, err := assistanceSubject([]byte(source), WorkflowTarget{Name: "docker.io/o/r", Job: "publish"}, "o/r")
	if err != nil || subject != "${{ steps.image.outputs.digest }}" {
		t.Fatalf("subject %q error %v", subject, err)
	}
}

func TestSuggestionOnlyAllowsAdditiveExactAttestation(t *testing.T) {
	candidate := WorkflowTarget{Name: "ghcr.io/o/r", Job: "publish"}
	const digest = "${{ steps.image.outputs.digest }}"
	if err := validateSuggestion([]byte(originalImageWorkflow), []byte(proposedImageWorkflow()), candidate, digest); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "wrong subject",
			old:  "subject-name: ghcr.io/o/r",
			new:  "subject-name: ghcr.io/attacker/image",
		},
		{
			name: "wrong digest",
			old:  digest,
			new:  "sha256:" + strings.Repeat("a", 64),
		},
		{
			name: "arbitrary script",
			old:  "name: Attest",
			new: `name: Attest
        run: curl attacker`,
		},
		{
			name: "privilege escalation",
			old:  "contents: read",
			new:  "contents: write",
		},
		{
			name: "publishing changed",
			old:  "push: true",
			new:  "push: false",
		},
		{
			name: "unpinned action",
			old:  AttestAction,
			new:  "actions/attest@v4",
		},
		{
			name: "SBOM instead of provenance",
			old:  "push-to-registry: true",
			new: `push-to-registry: true
          sbom-path: bom.json`,
		},
		{
			name: "unrelated permission",
			old:  "packages: write",
			new:  "packages: read",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			after := strings.ReplaceAll(proposedImageWorkflow(), tt.old, tt.new)
			if err := validateSuggestion([]byte(originalImageWorkflow), []byte(after), candidate, digest); err == nil {
				t.Fatal("unsafe suggestion accepted")
			}
		})
	}
}

func TestSuggestionPreservesExistingSBOMAttestation(t *testing.T) {
	const sbomTemplate = `      - name: Keep existing SBOM attestation
        uses: ACTION_PIN
        with:
          subject-name: ghcr.io/o/r
          subject-digest: ${{ steps.image.outputs.digest }}
          sbom-path: sbom.spdx.json
`
	sbom := strings.Replace(sbomTemplate, "ACTION_PIN", AttestAction, 1)
	before := originalImageWorkflow + sbom
	after := proposedImageWorkflow() + sbom
	target := WorkflowTarget{Name: "ghcr.io/o/r", Job: "publish"}
	const digest = "${{ steps.image.outputs.digest }}"

	if err := validateSuggestion([]byte(before), []byte(after), target, digest); err != nil {
		t.Fatalf("additive provenance suggestion rejected with existing SBOM: %v", err)
	}
	for _, tt := range []struct {
		name  string
		after string
	}{
		{
			name:  "existing SBOM removed",
			after: proposedImageWorkflow(),
		},
		{
			name:  "existing SBOM changed",
			after: strings.Replace(after, "sbom-path: sbom.spdx.json", "sbom-path: other.json", 1),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSuggestion([]byte(before), []byte(tt.after), target, digest); err == nil {
				t.Fatal("suggestion changed the existing SBOM behavior")
			}
		})
	}
}

type modelFunc func(context.Context, string) ([]byte, error)

func (f modelFunc) Suggest(ctx context.Context, prompt string) ([]byte, error) { return f(ctx, prompt) }

func fixtureCheckout(t *testing.T) (string, WorkflowTarget) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet")
	run("config", "user.email", "fixture@example.invalid")
	run("config", "user.name", "Fixture")
	run("config", "commit.gpgsign", "false")
	run("remote", "add", "origin", "https://github.com/o/r.git")
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := ".github/workflows/release.yml"
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(file)), []byte(originalImageWorkflow), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "--quiet", "-m", "fixture")
	return dir, WorkflowTarget{Name: "ghcr.io/o/r", SHA: run("rev-parse", "HEAD"), Workflow: file, Job: "publish"}
}

func TestAssistancePrintsUnappliedPatchAndPreservesCheckout(t *testing.T) {
	dir, candidate := fixtureCheckout(t)
	model := modelFunc(func(_ context.Context, prompt string) ([]byte, error) {
		if !strings.Contains(prompt, AttestAction) || !strings.Contains(prompt, "untrusted") {
			t.Fatal("missing bounded instruction context")
		}
		return json.Marshal(Suggestion{Workflow: candidate.Workflow, Content: proposedImageWorkflow()})
	})
	patch, err := Assist(context.Background(), dir, "o/r", candidate, model)
	if err != nil || !strings.Contains(patch, "+++ b/"+candidate.Workflow) {
		t.Fatalf("%s %v", patch, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(candidate.Workflow)))
	if err != nil || string(data) != originalImageWorkflow {
		t.Fatal("checkout was edited")
	}
	check := exec.CommandContext(context.Background(), "git", "apply", "--check", "-")
	check.Dir = dir
	check.Stdin = strings.NewReader(patch)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("patch is not applicable: %s %v", out, err)
	}
}

func TestAssistanceDirtyOrMismatchedCheckoutNeverCallsModel(t *testing.T) {
	for _, mode := range []string{"dirty", "revision", "repository", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			dir, candidate := fixtureCheckout(t)
			repo := "o/r"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "dirty":
				if err := os.WriteFile(filepath.Join(dir, "untracked"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "revision":
				candidate.SHA = strings.Repeat("b", 40)
			case "repository":
				repo = "o/other"
			case "cancelled":
				cancel()
			}
			_, err := Assist(ctx, dir, repo, candidate, modelFunc(func(context.Context, string) ([]byte, error) {
				t.Fatal("unsafe context invoked model")
				return nil, nil
			}))
			if err == nil {
				t.Fatal("unsafe context accepted")
			}
		})
	}
}

func TestAssistanceRejectsInvalidModelResponsesAndFailures(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "wrong workflow",
			output: `{"Workflow":"wrong","Content":"x"}`,
		},
		{
			name:   "missing fields",
			output: `{}`,
		},
		{
			name:   "invalid JSON",
			output: `not json`,
		},
		{
			name: "trailing content",
			output: `{
				"Workflow": ".github/workflows/release.yml",
				"Content": "invalid"
			} trailing`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, candidate := fixtureCheckout(t)
			model := modelFunc(func(context.Context, string) ([]byte, error) {
				return []byte(tt.output), nil
			})

			_, err := Assist(t.Context(), dir, "o/r", candidate, model)
			if err == nil {
				t.Fatalf("accepted %q", tt.output)
			}
		})
	}
}

func TestModelEnvironmentDoesNotGrantAmbientApproval(t *testing.T) {
	env := modelEnvironment([]string{
		"PATH=/bin",
		"COPILOT_ALLOW_ALL=true",
		"COPILOT_AGENT=evil",
		"NODE_OPTIONS=--require=evil",
		"GH_TOKEN=credential",
	})
	if strings.Contains(strings.Join(env, "\n"), "ALLOW_ALL") || strings.Contains(strings.Join(env, "\n"), "NODE_OPTIONS") || len(env) != 2 {
		t.Fatalf("unexpected environment %v", env)
	}
}

func TestCopilotCommandIsolatesExecutableUserConfiguration(t *testing.T) {
	dir := t.TempDir()
	command, err := copilotCommand(t.Context(), "copilot", "fixture prompt", dir, []string{
		"HOME=/user-home",
		"COPILOT_HOME=/user-hooks",
		"GH_TOKEN=fixture-token",
		"COPILOT_ALLOW_ALL=true",
		"NODE_OPTIONS=--require=user-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "copilot-home")
	var settings struct {
		DisableAllHooks bool `json:"disableAllHooks"`
		IDE             struct {
			AutoConnect bool `json:"autoConnect"`
		} `json:"ide"`
	}
	raw, err := os.ReadFile(filepath.Join(config, "settings.json"))
	if err != nil || json.Unmarshal(raw, &settings) != nil || !settings.DisableAllHooks || settings.IDE.AutoConnect {
		t.Fatalf("unsafe Copilot settings: %s (%v)", raw, err)
	}
	environment := strings.Join(command.Env, "\n")
	if !strings.Contains(environment, "COPILOT_HOME="+config) ||
		strings.Contains(environment, "/user-hooks") || strings.Contains(environment, "ALLOW_ALL") ||
		strings.Contains(environment, "NODE_OPTIONS") || !strings.Contains(environment, "GH_TOKEN=fixture-token") {
		t.Fatal("ambient executable configuration or approvals reached Copilot")
	}
	if command.Dir != dir {
		t.Fatalf("unexpected working directory %q", command.Dir)
	}
	for _, flag := range []string{
		"--available-tools=",
		"--deny-tool=*",
		"--disable-builtin-mcps",
		"--no-custom-instructions",
		"--no-ask-user",
		"--no-auto-update",
	} {
		found := false
		for _, arg := range command.Args {
			found = found || arg == flag
		}
		if !found {
			t.Fatalf("missing isolation flag %s", flag)
		}
	}
}

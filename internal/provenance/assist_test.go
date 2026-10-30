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
	return strings.Replace(originalImageWorkflow, "  publish:\n", "  publish:\n    permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write\n", 1) +
		"      - name: Attest\n        uses: " + AttestAction +
		"\n        with:\n          subject-name: ghcr.io/o/r\n          subject-digest: ${{ steps.image.outputs.digest }}\n          push-to-registry: true\n"
}

func TestAssistanceSubjectNormalizesDockerHubShortReferences(t *testing.T) {
	source := strings.ReplaceAll(originalImageWorkflow, "ghcr.io/o/r:v1", "o/r:v1")
	subject, err := assistanceSubject([]byte(source), Candidate{Name: "docker.io/o/r", Job: "publish"})
	if err != nil || subject != "${{ steps.image.outputs.digest }}" {
		t.Fatalf("subject %q error %v", subject, err)
	}
}

func TestSuggestionOnlyAllowsAdditiveExactAttestation(t *testing.T) {
	candidate := Candidate{Name: "ghcr.io/o/r", Job: "publish"}
	const digest = "${{ steps.image.outputs.digest }}"
	if err := validateSuggestion([]byte(originalImageWorkflow), []byte(proposedImageWorkflow()), candidate, digest); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, old, new string }{
		{"wrong subject", "subject-name: ghcr.io/o/r", "subject-name: ghcr.io/attacker/image"},
		{"wrong digest", digest, "sha256:" + strings.Repeat("a", 64)},
		{"arbitrary script", "name: Attest", "name: Attest\n        run: curl attacker"},
		{"privilege escalation", "contents: read", "contents: write"},
		{"publishing changed", "push: true", "push: false"},
		{"unpinned action", AttestAction, "actions/attest@v4"},
		{"SBOM", "push-to-registry: true", "push-to-registry: true\n          sbom-path: bom.json"},
		{"unrelated permission", "packages: write", "packages: read"},
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

type modelFunc func(context.Context, string) ([]byte, error)

func (f modelFunc) Suggest(ctx context.Context, prompt string) ([]byte, error) { return f(ctx, prompt) }

func fixtureCheckout(t *testing.T) (string, Candidate) {
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
	return dir, Candidate{Kind: "oci", Name: "ghcr.io/o/r", Digest: "sha256:" + strings.Repeat("a", 64), SHA: run("rev-parse", "HEAD"), Workflow: file, Job: "publish"}
}

func TestAssistancePrintsUnappliedPatchAndPreservesCheckout(t *testing.T) {
	dir, candidate := fixtureCheckout(t)
	model := modelFunc(func(_ context.Context, prompt string) ([]byte, error) {
		if !strings.Contains(prompt, AttestAction) || !strings.Contains(prompt, "untrusted") {
			t.Fatal("missing bounded instruction context")
		}
		return json.Marshal(Suggestion{Workflow: candidate.Workflow, Content: proposedImageWorkflow()})
	})
	patch, err := Assist(context.Background(), dir, "o/r", Finding{Artifact: candidate, State: Unknown}, model)
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
			_, err := Assist(ctx, dir, repo, Finding{Artifact: candidate}, modelFunc(func(context.Context, string) ([]byte, error) {
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
	for _, output := range []string{`{"Workflow":"wrong","Content":"x"}`, `{}`, `not json`, `{"Workflow":".github/workflows/release.yml","Content":"invalid"} trailing`} {
		dir, candidate := fixtureCheckout(t)
		_, err := Assist(context.Background(), dir, "o/r", Finding{Artifact: candidate}, modelFunc(func(context.Context, string) ([]byte, error) {
			return []byte(output), nil
		}))
		if err == nil {
			t.Fatalf("accepted %q", output)
		}
	}
}

func TestModelEnvironmentDoesNotGrantAmbientApproval(t *testing.T) {
	env := modelEnvironment([]string{"PATH=/bin", "COPILOT_ALLOW_ALL=true", "COPILOT_AGENT=evil", "NODE_OPTIONS=--require=evil", "GH_TOKEN=credential"})
	if strings.Contains(strings.Join(env, "\n"), "ALLOW_ALL") || strings.Contains(strings.Join(env, "\n"), "NODE_OPTIONS") || len(env) != 2 {
		t.Fatalf("unexpected environment %v", env)
	}
}

func TestCopilotCommandIsolatesExecutableUserConfiguration(t *testing.T) {
	dir := t.TempDir()
	command, err := copilotCommand(t.Context(), "copilot", "fixture prompt", dir, []string{
		"HOME=/user-home", "COPILOT_HOME=/user-hooks", "GH_TOKEN=fixture-token",
		"COPILOT_ALLOW_ALL=true", "NODE_OPTIONS=--require=user-code",
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
	for _, flag := range []string{"--available-tools=", "--deny-tool=*", "--disable-builtin-mcps", "--no-custom-instructions", "--no-ask-user", "--no-auto-update"} {
		found := false
		for _, arg := range command.Args {
			found = found || arg == flag
		}
		if !found {
			t.Fatalf("missing isolation flag %s", flag)
		}
	}
}

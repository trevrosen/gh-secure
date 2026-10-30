package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"

	"github.com/GitHubSecurityLab/gh-secure/internal/github"
	"github.com/GitHubSecurityLab/gh-secure/internal/provenance"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

// NewWorkflowCheckHandler performs the default source-only adoption check.
func NewWorkflowCheckHandler(streams ui.Streams, resolve func(context.Context, string) (repository.Target, error)) func(context.Context, StatusOptions) error {
	check := NewProvenanceHandler(streams, resolve)
	return func(ctx context.Context, options StatusOptions) error {
		return check(ctx, ProvenanceOptions{Repository: options.Repository})
	}
}

// ProvenanceOptions selects workflow configuration or consented enablement assistance.
type ProvenanceOptions struct {
	Repository, Workflow, Job string
	Assist, Consent, DryRun   bool
}

func provenanceCommand(version string, repo *string, deps Dependencies) *cobra.Command {
	var options ProvenanceOptions
	execute := func(assist bool) func(*cobra.Command, []string) error {
		return func(command *cobra.Command, args []string) error {
			if len(args) > 0 {
				return invalidInvocation(errors.New("provenance does not accept positional arguments"))
			}
			if err := validateRepository(*repo, command.Flags().Changed("repo")); err != nil {
				return invalidInvocation(err)
			}
			options.Repository, options.Assist = *repo, assist
			if assist && (!provenance.WorkflowPath(options.Workflow) || options.Job == "") {
				return invalidInvocation(errors.New("assist requires --workflow .github/workflows/file.yml and --job job-id"))
			}
			if assist && !options.Consent && !options.DryRun {
				return invalidInvocation(errors.New("assist requires --consent: workflow content will be sent to local Copilot using your account allowance"))
			}
			if deps.Provenance == nil {
				return errors.New("provenance execution handler is unavailable")
			}
			return deps.Provenance(command.Context(), options)
		}
	}
	parent := &cobra.Command{
		Use: "provenance", Short: "Check workflow attestation adoption",
		Version: version, RunE: execute(false),
	}
	parent.PersistentFlags().BoolVarP(&options.DryRun, "dry-run", "n", false, "Inspect workflow configuration only; never invoke Copilot or edit files")
	assist := &cobra.Command{
		Use: "assist", Short: "Print an unapplied Copilot-assisted attestation enablement patch",
		Version: version, RunE: execute(true),
	}
	assist.Flags().StringVar(&options.Workflow, "workflow", "", "Workflow path to extend")
	assist.Flags().StringVar(&options.Job, "job", "", "Publishing job ID")
	assist.Flags().BoolVar(&options.Consent, "consent", false, "Consent to sending workflow source to Copilot and consuming your allowance")
	parent.AddCommand(assist)
	return parent
}

// NewProvenanceHandler checks source configuration, never published artifacts.
func NewProvenanceHandler(
	streams ui.Streams,
	resolve func(context.Context, string) (repository.Target, error),
) func(context.Context, ProvenanceOptions) error {
	return func(ctx context.Context, options ProvenanceOptions) error {
		target, err := resolve(ctx, options.Repository)
		if err != nil {
			return err
		}
		client, err := github.NewClient(api.ClientOptions{Host: target.Host})
		if err != nil {
			return err
		}
		meta, err := client.Repository(ctx, target)
		if err != nil {
			return err
		}
		reader := github.WorkflowReader{Client: client, Target: target}
		sha, sources, err := reader.WorkflowSources(ctx, meta.DefaultBranch)
		if err != nil {
			return fmt.Errorf("workflow attestation configuration: %w", err)
		}
		findings, err := provenance.CheckWorkflowSources(sources)
		if err != nil {
			return err
		}
		return handleWorkflowSources(ctx, streams, options, target.Owner+"/"+target.Name, sha, sources, findings)
	}
}

func handleWorkflowSources(ctx context.Context, streams ui.Streams, options ProvenanceOptions, repo, sha string, sources map[string][]byte, findings []provenance.ConfigurationFinding) error {
	text, issue := provenance.RenderConfiguration(findings, sha)
	if _, err := fmt.Fprint(streams.Out, text); err != nil {
		return err
	}
	if !issue {
		// Adoption anywhere means no enablement work, including no model invocation.
		return nil
	}
	if options.Assist && !options.DryRun {
		return suggestWorkflowPatch(ctx, streams, options, repo, sha, sources)
	}
	return errors.New("workflow attestation configuration is missing or requires review")
}

func suggestWorkflowPatch(ctx context.Context, streams ui.Streams, options ProvenanceOptions, repo, sha string, sources map[string][]byte) error {
	if !options.Consent {
		return errors.New("copilot consent was not provided")
	}
	source, ok := sources[options.Workflow]
	if !ok {
		return errors.New("selected workflow was not found in the default-branch sources")
	}
	target, err := provenance.AssistanceTarget(source, options.Workflow, options.Job, sha, repo)
	if err != nil {
		return err
	}
	directory, err := os.Getwd()
	if err != nil {
		return err
	}
	patch, err := provenance.Assist(ctx, directory, repo, target, provenance.CopilotModel{})
	if err != nil {
		return err
	}
	fmt.Fprintln(streams.ErrOut, "Unapplied enablement suggestion only: review the patch, OIDC/attestation permissions and publishing behavior. Then apply, commit and open a PR yourself.")
	_, err = fmt.Fprint(streams.Out, "\n"+strings.TrimSpace(patch)+"\n")
	return err
}

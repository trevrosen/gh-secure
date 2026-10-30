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

// NewWorkflowCheckHandler performs the inexpensive default source-only check.
func NewWorkflowCheckHandler(streams ui.Streams, resolve func(context.Context, string) (repository.Target, error)) func(context.Context, StatusOptions) error {
	return func(ctx context.Context, options StatusOptions) error {
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
		reader := github.ProvenanceReader{Client: client, Target: target}
		sha, sources, err := reader.WorkflowSources(ctx, meta.DefaultBranch)
		if err != nil {
			return fmt.Errorf("workflow provenance configuration: %w", err)
		}
		findings, err := provenance.CheckWorkflowSources(sources)
		if err != nil {
			return err
		}
		text, issue := provenance.RenderConfiguration(findings, sha)
		if _, err := fmt.Fprint(streams.Out, text); err != nil {
			return err
		}
		if issue {
			return finishWorkflowCheck(ctx, streams, options, NewProvenanceHandler(streams, resolve))
		}
		return nil
	}
}

func finishWorkflowCheck(ctx context.Context, streams ui.Streams, options StatusOptions, inspect func(context.Context, ProvenanceOptions) error) error {
	finding := errors.New("workflow provenance configuration is missing or requires review; published artifacts have not been assessed by the static check")
	if !options.OfferDeepProvenance || options.DryRun {
		return finding
	}
	approved, err := ui.NewApprover(streams).ConfirmProvenanceScan(ctx)
	if err != nil {
		return errors.Join(finding, err)
	}
	if !approved {
		return finding
	}
	return errors.Join(finding, inspect(ctx, ProvenanceOptions{Repository: options.Repository, RunLimit: 20}))
}

// ProvenanceOptions selects bounded inspection or explicitly consented assistance.
type ProvenanceOptions struct {
	Repository, Workflow, Job string
	RunLimit                  int
	Assist, Consent, DryRun   bool
}

func provenanceCommand(version string, repo *string, deps Dependencies) *cobra.Command {
	options := ProvenanceOptions{RunLimit: 20}
	parent := &cobra.Command{
		Use: "provenance", Short: "Inspect distributed build outputs and their provenance",
		Version: version,
	}
	execute := func(assist bool) func(*cobra.Command, []string) error {
		return func(command *cobra.Command, args []string) error {
			if len(args) > 0 {
				return invalidInvocation(errors.New("provenance does not accept positional arguments"))
			}
			if err := validateRepository(*repo, command.Flags().Changed("repo")); err != nil {
				return invalidInvocation(err)
			}
			if options.RunLimit < 1 || options.RunLimit > 100 {
				return invalidInvocation(errors.New("history limits must be between 1 and 100"))
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
	parent.RunE = execute(false)
	parent.PersistentFlags().IntVar(&options.RunLimit, "run-limit", 20, "Maximum completed Actions runs (1-100)")
	parent.PersistentFlags().BoolVarP(&options.DryRun, "dry-run", "n", false, "Inspect only; never invoke Copilot or edit files")
	assist := &cobra.Command{
		Use: "assist", Short: "Print an unapplied Copilot-assisted workflow patch (requires consent)",
		Version: version, RunE: execute(true),
	}
	assist.Flags().StringVar(&options.Workflow, "workflow", "", "Producing workflow path")
	assist.Flags().StringVar(&options.Job, "job", "", "Producing workflow job ID")
	assist.Flags().BoolVar(&options.Consent, "consent", false, "Consent to sending workflow evidence to Copilot and consuming your allowance")
	parent.AddCommand(assist)
	return parent
}

// NewProvenanceHandler wires read-only discovery and optional text-only suggestions.
func NewProvenanceHandler(
	streams ui.Streams,
	resolve func(context.Context, string) (repository.Target, error),
) func(context.Context, ProvenanceOptions) error {
	return func(ctx context.Context, options ProvenanceOptions) error {
		target, err := resolve(ctx, options.Repository)
		if err != nil {
			return err
		}
		if target.Host != "github.com" {
			return errors.New("provenance inspection is currently supported only on github.com; GHES coverage is unsupported")
		}
		client, err := github.NewClient(api.ClientOptions{Host: target.Host})
		if err != nil {
			return err
		}
		meta, err := client.Repository(ctx, target)
		if err != nil {
			return err
		}
		if meta.Private {
			return errors.New("private repository attestation trust and entitlement are not yet supported; no clean assessment can be made")
		}
		repo := target.Owner + "/" + target.Name
		report, inspectErr := provenance.Inspect(ctx, repo,
			github.ProvenanceReader{Client: client, Target: target},
			provenance.NewRegistryResolver(), provenance.NewBundleVerifier(),
			provenance.InspectOptions{RunLimit: options.RunLimit})
		if _, renderErr := fmt.Fprint(streams.Out, provenance.Render(report)); renderErr != nil {
			return renderErr
		}
		if inspectErr != nil {
			return inspectErr
		}
		if !options.Assist || options.DryRun {
			return report.Err()
		}
		return suggestWorkflowPatch(ctx, streams, options, repo, report)
	}
}

func suggestWorkflowPatch(ctx context.Context, streams ui.Streams, options ProvenanceOptions, repo string, report provenance.Report) error {
	if !options.Consent {
		return errors.New("copilot consent was not provided")
	}
	directory, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, finding := range report.Findings {
		a := finding.Artifact
		if a.Workflow != options.Workflow || a.Job != options.Job || finding.State == provenance.Verified {
			continue
		}
		patch, err := provenance.Assist(ctx, directory, repo, finding, provenance.CopilotModel{})
		if err != nil {
			return err
		}
		fmt.Fprintln(streams.ErrOut, "Unapplied suggestion only: review the patch, OIDC/attestation permissions and publishing behavior. Then apply, commit and open a PR yourself. Earlier outputs remain unresolved until subsequent builds are verified.")
		if _, err := fmt.Fprint(streams.Out, "\n"+strings.TrimSpace(patch)+"\n"); err != nil {
			return err
		}
		return report.Err()
	}
	return errors.New("no unresolved supported publication matches this workflow/job; use manual attestation guidance")
}

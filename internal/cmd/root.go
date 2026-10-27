// Package cmd builds the command tree and maps execution results to exit codes.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
	"github.com/spf13/cobra"
)

// EnableOptions contains validated command-line input for enablement.
type EnableOptions struct {
	// Repository is an explicit owner/repo target, or empty for later discovery.
	Repository string
	// Features contains unique feature groups in canonical execution order.
	Features []security.Feature
	// ExplicitSelection distinguishes feature arguments from the default selection.
	ExplicitSelection bool
	// Yes bypasses ordinary confirmations, but never the active-ruleset safeguard.
	Yes bool
	// DryRun requests inspection and planning without mutations.
	DryRun bool
}

// StatusOptions contains validated command-line input for repository inspection.
type StatusOptions struct {
	// Repository is an explicit owner/repo target, or empty for later discovery.
	Repository string
}

// Dependencies supplies execution handlers invoked only after input validation.
// A nil handler makes its command fail explicitly as unavailable.
type Dependencies struct {
	// Enable handles the selected feature groups and enablement flags.
	Enable func(context.Context, EnableOptions) error
	// Status handles inspection of all six security checks.
	Status func(context.Context, StatusOptions) error
}

type invocationError struct {
	err error
}

// Error returns the invalid-invocation diagnostic.
func (e *invocationError) Error() string { return e.err.Error() }

// Unwrap exposes the underlying validation or flag-parsing error.
func (e *invocationError) Unwrap() error { return e.err }

func invalidInvocation(err error) error {
	return &invocationError{err: err}
}

// NewRoot constructs an independent command tree with injected streams and handlers.
// Construction performs no repository discovery or API requests.
func NewRoot(version string, streams ui.Streams, deps Dependencies) *cobra.Command {
	var repo string
	var yes, dryRun bool
	var selected []security.Feature

	root := &cobra.Command{
		Use:           "gh-secure [flags] [feature ...]",
		Short:         "Configure repository security features",
		Long:          helpText(),
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		Args: func(command *cobra.Command, args []string) error {
			if err := validateRepository(repo, command.Flags().Changed("repo")); err != nil {
				return invalidInvocation(err)
			}
			var err error
			selected, err = security.SelectFeatures(args)
			if err != nil {
				return invalidInvocation(err)
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			if err := command.Context().Err(); err != nil {
				return err
			}
			if deps.Enable == nil {
				return errors.New("Go enablement is not implemented yet (task 005); no repository was inspected or changed")
			}
			return deps.Enable(command.Context(), EnableOptions{
				Repository:        repo,
				Features:          selected,
				ExplicitSelection: len(args) > 0,
				Yes:               yes,
				DryRun:            dryRun,
			})
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.ErrOut)
	root.SetVersionTemplate("gh-secure {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return invalidInvocation(err)
	})
	root.PersistentFlags().StringVarP(&repo, "repo", "r", "", "Target owner/repo (default: current repository)")
	root.PersistentFlags().BoolP("version", "v", false, "Print version")
	root.Flags().BoolVarP(&yes, "yes", "y", false, "Bypass ordinary confirmations, never the active-ruleset safeguard")
	root.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Inspect and preview without mutations")

	root.AddCommand(&cobra.Command{
		Use:     "status",
		Short:   "Inspect all six security checks without making changes",
		Long:    "Inspect all six security checks without making changes.\n\nActive rulesets are reported separately and do not count as legacy branch protection.",
		Version: version,
		Args: func(command *cobra.Command, args []string) error {
			if len(args) > 0 {
				return invalidInvocation(fmt.Errorf("status does not accept feature selectors or positional arguments: %q", args[0]))
			}
			if err := validateRepository(repo, command.Flags().Changed("repo")); err != nil {
				return invalidInvocation(err)
			}
			return nil
		},
		RunE: func(command *cobra.Command, _ []string) error {
			if err := command.Context().Err(); err != nil {
				return err
			}
			if deps.Status == nil {
				return errors.New("status execution handler is unavailable; no repository was inspected or changed")
			}
			return deps.Status(command.Context(), StatusOptions{Repository: repo})
		},
	})
	return root
}

// Execute runs args, writes diagnostics to streams.ErrOut, and returns an exit code:
// 0 for success, 1 for operational failure or cancellation, and 2 for invalid input.
func Execute(ctx context.Context, args []string, version string, streams ui.Streams, deps Dependencies) int {
	root := NewRoot(version, streams, deps)
	root.SetArgs(append([]string{}, args...))
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}

	fmt.Fprintf(streams.ErrOut, "Error: %s\n", err)
	var invocation *invocationError
	if errors.As(err, &invocation) {
		fmt.Fprintln(streams.ErrOut, "Run 'gh secure --help' for usage.")
		return 2
	}
	return 1
}

func validateRepository(repo string, explicit bool) error {
	if !explicit {
		return nil
	}
	return repository.ValidateName(repo)
}

func helpText() string {
	var text strings.Builder
	text.WriteString("Configure security features for one repository.\n\n")
	text.WriteString("The Go port is in development: enablement is not implemented yet.\n")
	text.WriteString("Status inspection is read-only. The root Bash extension remains the shipping tool.\n\n")
	text.WriteString("Features (default: all; selected features run once in this order):\n")
	for _, feature := range security.Features() {
		fmt.Fprintf(&text, "  %-25s (%s)  %s\n", feature.Name, feature.Alias, feature.Description)
	}
	text.WriteString("\n--yes never approves overlapping legacy protection when active rulesets exist.")
	return text.String()
}

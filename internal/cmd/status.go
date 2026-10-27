package cmd

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/github"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

// DefaultDependencies wires read-only status lazily; enablement remains unavailable.
// Construction performs neither discovery nor authenticated client initialization.
func DefaultDependencies(streams ui.Streams) Dependencies {
	resolver := repository.NewResolver(streams.PromptRepository)
	return Dependencies{
		Status: NewStatusHandler(streams, resolver.Resolve, func(target repository.Target) (security.Reader, error) {
			return github.NewClient(api.ClientOptions{Host: target.Host})
		}),
	}
}

// NewStatusHandler composes injected resolution, read-client creation, and rendering.
// It does not run the enablement permission preflight or request the policy advisory.
func NewStatusHandler(
	streams ui.Streams,
	resolve func(context.Context, string) (repository.Target, error),
	newReader func(repository.Target) (security.Reader, error),
) func(context.Context, StatusOptions) error {
	return func(ctx context.Context, options StatusOptions) error {
		target, err := resolve(ctx, options.Repository)
		if err != nil {
			return fmt.Errorf("resolve repository: %w", err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		reader, err := newReader(target)
		if err != nil {
			return err
		}
		report, err := security.InspectStatus(ctx, reader, target)
		if len(report.Checks) > 0 {
			if renderErr := streams.RenderStatus(report); renderErr != nil {
				return renderErr
			}
		}
		if err != nil {
			return err
		}
		return report.Err()
	}
}

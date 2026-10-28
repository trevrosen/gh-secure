package cmd

import (
	"context"
	"fmt"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

// EnablementClient reads, writes, and looks up the advisory security policy.
type EnablementClient interface {
	security.Reader
	security.Writer
	// Policy looks up the advisory security policy without affecting results.
	Policy(context.Context, repository.Repository) security.Policy
}

// NewEnableHandler composes resolution, permission preflight, inspection,
// planning, confirmation, apply or preview, and summary rendering. Every
// confirmation is collected before the first write; dry-run never receives a writer.
func NewEnableHandler(
	streams ui.Streams,
	resolve func(context.Context, string) (repository.Target, error),
	newClient func(repository.Target) (EnablementClient, error),
) func(context.Context, EnableOptions) error {
	return func(ctx context.Context, options EnableOptions) error {
		target, err := resolve(ctx, options.Repository)
		if err != nil {
			return fmt.Errorf("resolve repository: %w", err)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		client, err := newClient(target)
		if err != nil {
			return err
		}
		repo, err := client.Repository(ctx, target)
		if err != nil {
			return fmt.Errorf("inspect repository metadata: %w", err)
		}
		if err = streams.RenderPreflight(repo); err != nil {
			return err
		}
		if err = security.RequireEnablementPermission(repo); err != nil {
			return err
		}
		report, err := security.InspectFeatures(ctx, client, repo, options.Features)
		if err != nil {
			return err
		}
		plans, err := security.PlanFeatures(report, options.Features)
		if err != nil {
			return err
		}
		if err = streams.RenderPlan(plans, options.DryRun); err != nil {
			return err
		}
		decisions, err := security.Approve(ctx, ui.NewApprover(streams), plans, security.ApprovalOptions{
			Yes:               options.Yes,
			ExplicitSelection: options.ExplicitSelection,
		})
		if err != nil {
			return fmt.Errorf("confirmation incomplete; no changes were made: %w", err)
		}
		var result security.EnablementResult
		if options.DryRun {
			result = security.PreviewPlans(ctx, plans, decisions)
		} else {
			result = security.ApplyPlans(ctx, client, plans, decisions)
		}
		var policy *security.Policy
		if result.Interrupted == nil {
			lookup := client.Policy(ctx, repo)
			policy = &lookup
		}
		if err = streams.RenderEnablement(result, policy); err != nil {
			return err
		}
		return result.Err()
	}
}

package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

var (
	errConfirmationUnavailable = errors.New("terminal input is unavailable for confirmation; rerun with --yes to approve ordinary confirmations")
	errOverlapUnavailable      = errors.New("terminal input is unavailable for the active-ruleset safeguard, which --yes cannot approve")
)

// Approver collects enablement confirmations from terminal input.
type Approver struct {
	streams Streams
}

var _ security.Approver = Approver{}

// NewApprover prompts on streams.ErrOut and reads answers from streams.In.
func NewApprover(streams Streams) Approver {
	return Approver{streams: streams}
}

// ChooseMode offers one confirmation for all features or one per feature.
// Invalid choices re-prompt; EOF and unavailable input are errors.
func (a Approver) ChooseMode(ctx context.Context) (security.ApprovalMode, error) {
	if err := a.streams.requireTerminal(ctx, errConfirmationUnavailable); err != nil {
		return 0, err
	}
	question := "How should changes be confirmed?\n" +
		"  1) Confirm all features at once\n" +
		"  2) Confirm each feature step by step\n" +
		"Choose 1 or 2: "
	for {
		answer, err := a.streams.ask(ctx, question)
		if err != nil {
			return 0, fmt.Errorf("read confirmation mode: %w", err)
		}
		switch strings.TrimSpace(answer) {
		case "1":
			return security.ApproveAll, nil
		case "2":
			return security.ApproveEach, nil
		}
		question = "Please choose 1 or 2: "
	}
}

// ConfirmFeatures asks once for every listed feature.
func (a Approver) ConfirmFeatures(ctx context.Context, repo repository.Repository, features []security.Feature) (bool, error) {
	names := make([]string, len(features))
	for index, feature := range features {
		names[index] = string(feature)
	}
	question := fmt.Sprintf("Enable %d security feature(s) on %s (%s)?", len(features), repo.Target, strings.Join(names, ", "))
	return a.confirm(ctx, question, errConfirmationUnavailable)
}

// ConfirmFeature asks for one feature in step-by-step mode.
func (a Approver) ConfirmFeature(ctx context.Context, feature security.Feature) (bool, error) {
	return a.confirm(ctx, fmt.Sprintf("Enable %s?", feature), errConfirmationUnavailable)
}

// ConfirmRulesetOverlap asks the safeguard that --yes never answers.
func (a Approver) ConfirmRulesetOverlap(ctx context.Context, rulesets security.Rulesets) (bool, error) {
	question := fmt.Sprintf("Active rulesets exist (%s) and may already govern the default branch.\n"+
		"Add legacy branch protection anyway? Rulesets will not be changed.", rulesetsSummary(rulesets))
	return a.confirm(ctx, question, errOverlapUnavailable)
}

// confirm accepts y/yes or n/no case-insensitively; empty means no and other
// input re-prompts. Without terminal input it returns unavailable, untouched.
func (a Approver) confirm(ctx context.Context, question string, unavailable error) (bool, error) {
	if err := a.streams.requireTerminal(ctx, unavailable); err != nil {
		return false, err
	}
	prompt := question + " [y/N]: "
	for {
		answer, err := a.streams.ask(ctx, prompt)
		if err != nil {
			return false, fmt.Errorf("read confirmation: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		}
		prompt = "Please answer y or n [y/N]: "
	}
}

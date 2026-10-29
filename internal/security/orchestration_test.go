package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// TestInspectFeaturesSelectsChecks checks that only selected settings are read
// and rulesets are inspected only with branch protection.
func TestInspectFeaturesSelectsChecks(t *testing.T) {
	active := Rulesets{Known: true, Active: []string{"policy"}}
	tests := []struct {
		features []Feature
		calls    []CheckID
		rulesets Rulesets
	}{
		{[]Feature{Dependabot, CodeScanning}, []CheckID{DependabotAlerts, DependabotUpdates, CodeQLSetup}, Rulesets{Detail: "not inspected"}},
		{[]Feature{BranchProtection, SecretScanning}, []CheckID{LegacyProtection, PushProtection}, active},
	}
	for _, test := range tests {
		reader := &fakeReader{states: map[CheckID]State{}, rulesets: active}
		report, err := InspectFeatures(t.Context(), reader, repository.Repository{}, test.features)
		if err != nil || !slices.Equal(reader.calls, test.calls) || !reflect.DeepEqual(report.Rulesets, test.rulesets) {
			t.Fatalf("features=%v calls=%v rulesets=%+v err=%v", test.features, reader.calls, report.Rulesets, err)
		}
	}
	reader := &fakeReader{}
	if _, err := InspectFeatures(t.Context(), reader, repository.Repository{}, []Feature{"unknown"}); err == nil || len(reader.calls) != 0 {
		t.Fatalf("unrecognized feature inspected: calls=%v err=%v", reader.calls, err)
	}
}

// TestRequireEnablementPermission checks that only reported admin or maintain passes.
func TestRequireEnablementPermission(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		admin, maintain *bool
		allowed         bool
	}{
		{&yes, nil, true},
		{nil, &yes, true},
		{&no, &yes, true},
		{&no, &no, false},
		{nil, nil, false},
	}
	for _, test := range tests {
		repo := repository.Repository{Permissions: repository.Permissions{Admin: test.admin, Maintain: test.maintain}}
		if err := RequireEnablementPermission(repo); (err == nil) != test.allowed {
			t.Errorf("admin=%v maintain=%v err=%v", test.admin, test.maintain, err)
		}
	}
}

// TestFeatureResultOutcomePrecedence checks that failures dominate successes and
// declines, and that planned results are distinct from applied results.
func TestFeatureResultOutcomePrecedence(t *testing.T) {
	failure := errors.New("write failed")
	operation := func(outcome Outcome) OperationResult {
		result := OperationResult{ID: DependabotAlerts, Outcome: outcome}
		if outcome == OutcomeFailed {
			result.Err = failure
		}
		return result
	}
	tests := []struct {
		outcomes []Outcome
		want     Outcome
	}{
		{nil, OutcomeFailed},
		{[]Outcome{OutcomeDeclined, OutcomeFailed}, OutcomeFailed},
		{[]Outcome{OutcomePlanned, OutcomeFailed}, OutcomePartial},
		{[]Outcome{OutcomeAlreadyEnabled, OutcomeDeclined}, OutcomeDeclined},
		{[]Outcome{OutcomeAlreadyEnabled, OutcomePlanned}, OutcomePlanned},
		{[]Outcome{OutcomeAlreadyEnabled, OutcomeApplied}, OutcomeApplied},
		{[]Outcome{OutcomeAlreadyEnabled, OutcomeAlreadyEnabled}, OutcomeAlreadyEnabled},
	}
	for _, test := range tests {
		result := FeatureResult{Feature: Dependabot}
		for _, outcome := range test.outcomes {
			result.Operations = append(result.Operations, operation(outcome))
		}
		if got := result.Outcome(); got != test.want {
			t.Errorf("outcomes=%v: got %q; want %q", test.outcomes, got, test.want)
		}
	}
}

type scriptedApprover struct {
	mode       ApprovalMode
	answers    []bool
	err        error
	overlap    bool
	overlapErr error
	cancel     context.CancelFunc
	calls      []string
}

// ChooseMode records the call and returns the scripted mode or error.
func (a *scriptedApprover) ChooseMode(context.Context) (ApprovalMode, error) {
	a.calls = append(a.calls, "mode")
	return a.mode, a.err
}

// ConfirmFeatures records the listed features and returns the next answer.
func (a *scriptedApprover) ConfirmFeatures(_ context.Context, _ repository.Repository, features []Feature) (bool, error) {
	a.calls = append(a.calls, fmt.Sprintf("features %v", features))
	return a.next()
}

// ConfirmFeature records the feature and returns the next answer.
func (a *scriptedApprover) ConfirmFeature(_ context.Context, feature Feature) (bool, error) {
	a.calls = append(a.calls, "feature "+string(feature))
	return a.next()
}

// ConfirmRulesetOverlap records the safeguard and returns its scripted answer.
func (a *scriptedApprover) ConfirmRulesetOverlap(context.Context, Rulesets) (bool, error) {
	a.calls = append(a.calls, "overlap")
	if a.cancel != nil {
		a.cancel()
	}
	return a.overlap, a.overlapErr
}

func (a *scriptedApprover) next() (bool, error) {
	if a.err != nil {
		return false, a.err
	}
	answer := a.answers[0]
	a.answers = a.answers[1:]
	return answer, nil
}

// overlapPlans plans branch protection with active rulesets, private reporting,
// and Dependabot with only security updates missing.
func overlapPlans(t *testing.T) []FeaturePlan {
	t.Helper()
	report := enablementReport(map[CheckID]State{
		LegacyProtection: Disabled, PrivateReporting: Disabled, DependabotAlerts: Enabled, DependabotUpdates: Disabled,
	})
	report.Rulesets = Rulesets{Known: true, Active: []string{"policy"}}
	plans, err := PlanFeatures(report, []Feature{BranchProtection, VulnerabilityReporting, Dependabot})
	if err != nil {
		t.Fatal(err)
	}
	return plans
}

// TestApproveCollectsConfirmations checks prompt order, mode selection, declines,
// --yes, and the independent active-ruleset safeguard.
func TestApproveCollectsConfirmations(t *testing.T) {
	unavailable := errors.New("no terminal")
	allFeatures := "features [branch-protection vulnerability-reporting dependabot]"
	tests := []struct {
		name      string
		approver  scriptedApprover
		options   ApprovalOptions
		calls     []string
		decisions []Decision
	}{
		{
			name: "all at once", approver: scriptedApprover{mode: ApproveAll, answers: []bool{true}, overlap: true},
			calls:     []string{"mode", allFeatures, "overlap"},
			decisions: []Decision{{AllowRulesetOverlap: true}, {}, {}},
		},
		{
			name: "initial decline skips the safeguard", approver: scriptedApprover{mode: ApproveAll, answers: []bool{false}},
			calls:     []string{"mode", allFeatures},
			decisions: []Decision{{Declined: true}, {Declined: true}, {Declined: true}},
		},
		{
			name: "step by step", approver: scriptedApprover{mode: ApproveEach, answers: []bool{true, false, true}, overlap: false},
			calls:     []string{"mode", "feature branch-protection", "overlap", "feature vulnerability-reporting", "feature dependabot"},
			decisions: []Decision{{Declined: true}, {Declined: true}, {}},
		},
		{
			name: "declined step skips its safeguard", approver: scriptedApprover{mode: ApproveEach, answers: []bool{false, true, true}},
			calls:     []string{"mode", "feature branch-protection", "feature vulnerability-reporting", "feature dependabot"},
			decisions: []Decision{{Declined: true}, {}, {}},
		},
		{
			name: "explicit selection skips mode", options: ApprovalOptions{ExplicitSelection: true},
			approver:  scriptedApprover{answers: []bool{true}, overlap: true},
			calls:     []string{allFeatures, "overlap"},
			decisions: []Decision{{AllowRulesetOverlap: true}, {}, {}},
		},
		{
			name: "yes still asks the safeguard", options: ApprovalOptions{Yes: true},
			approver:  scriptedApprover{overlap: true},
			calls:     []string{"overlap"},
			decisions: []Decision{{AllowRulesetOverlap: true}, {}, {}},
		},
		{
			name: "unanswerable safeguard blocks only branch protection", options: ApprovalOptions{Yes: true},
			approver:  scriptedApprover{overlapErr: unavailable},
			calls:     []string{"overlap"},
			decisions: []Decision{{Blocked: fmt.Errorf("active-ruleset overlap was not approved: %w", unavailable)}, {}, {}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decisions, err := Approve(t.Context(), &test.approver, overlapPlans(t), test.options)
			if err != nil || !slices.Equal(test.approver.calls, test.calls) || !reflect.DeepEqual(decisions, test.decisions) {
				t.Fatalf("calls=%q decisions=%+v err=%v", test.approver.calls, decisions, err)
			}
		})
	}
}

// TestApproveAbortsWithoutDecisions checks that ordinary prompt failures,
// unsupported modes, and cancellation return errors instead of partial decisions.
func TestApproveAbortsWithoutDecisions(t *testing.T) {
	unavailable := errors.New("no terminal")
	tests := []struct {
		name     string
		approver scriptedApprover
		cancel   bool
		calls    []string
		wantErr  error
	}{
		{name: "ordinary prompt unavailable", approver: scriptedApprover{err: unavailable}, calls: []string{"mode"}, wantErr: unavailable},
		{name: "unsupported mode fails closed", approver: scriptedApprover{}, calls: []string{"mode"}},
		{
			name:     "cancellation during safeguard",
			approver: scriptedApprover{mode: ApproveEach, answers: []bool{true}, overlapErr: unavailable},
			cancel:   true, calls: []string{"mode", "feature branch-protection", "overlap"}, wantErr: context.Canceled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				test.approver.cancel = cancel
			}
			decisions, err := Approve(ctx, &test.approver, overlapPlans(t), ApprovalOptions{})
			if err == nil || (test.wantErr != nil && !errors.Is(err, test.wantErr)) ||
				decisions != nil || !slices.Equal(test.approver.calls, test.calls) {
				t.Fatalf("calls=%q decisions=%+v err=%v", test.approver.calls, decisions, err)
			}
		})
	}
}

// TestApproveSkipsSettledPlans checks no prompt when nothing can be written.
func TestApproveSkipsSettledPlans(t *testing.T) {
	report := enablementReport(map[CheckID]State{PrivateReporting: Enabled, CodeQLSetup: Unknown})
	plans, err := PlanFeatures(report, []Feature{VulnerabilityReporting, CodeScanning})
	if err != nil {
		t.Fatal(err)
	}
	approver := &scriptedApprover{err: errors.New("prompted")}
	decisions, err := Approve(t.Context(), approver, plans, ApprovalOptions{})
	if err != nil || len(approver.calls) != 0 || !reflect.DeepEqual(decisions, []Decision{{}, {}}) {
		t.Fatalf("calls=%q decisions=%+v err=%v", approver.calls, decisions, err)
	}
}

// TestApplyAndPreviewPlans checks that declined and blocked plans never write,
// dry run uses no writer, and outcomes stay distinct.
func TestApplyAndPreviewPlans(t *testing.T) {
	blocked := errors.New("safeguard unanswered")
	decisions := []Decision{{Blocked: blocked}, {Declined: true}, {}}

	writer := &recordingWriter{}
	applied := ApplyPlans(t.Context(), writer, overlapPlans(t), decisions)
	if !slices.Equal(writer.calls, []CheckID{DependabotUpdates}) {
		t.Fatalf("writes=%v", writer.calls)
	}
	if got := outcomes(applied); !slices.Equal(got, []Outcome{OutcomeFailed, OutcomeDeclined, OutcomeApplied}) {
		t.Errorf("apply outcomes=%v", got)
	}
	if err := applied.Err(); !errors.Is(err, blocked) {
		t.Errorf("blocked safeguard lost: %v", err)
	}

	previewed := PreviewPlans(t.Context(), overlapPlans(t), []Decision{{AllowRulesetOverlap: true}, {Declined: true}, {}})
	if got := outcomes(previewed); !previewed.DryRun || !slices.Equal(got, []Outcome{OutcomePlanned, OutcomeDeclined, OutcomePlanned}) {
		t.Errorf("preview dryRun=%v outcomes=%v", previewed.DryRun, got)
	}
	if err := previewed.Err(); err != nil {
		t.Errorf("successful preview failed: %v", err)
	}
	if updates := previewed.Features[2].Operations; updates[0].Outcome != OutcomeAlreadyEnabled || updates[1].Outcome != OutcomePlanned {
		t.Errorf("preview lost Dependabot sub-operations: %+v", updates)
	}
}

// TestApplyPlansStopsOnCancellation checks later features are reported as not attempted.
func TestApplyPlansStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer := &recordingWriter{cancel: cancel}
	result := ApplyPlans(ctx, writer, overlapPlans(t), []Decision{{AllowRulesetOverlap: true}, {}, {}})
	if !slices.Equal(writer.calls, []CheckID{LegacyProtection}) ||
		!slices.Equal(outcomes(result), []Outcome{OutcomeApplied}) ||
		!slices.Equal(result.NotAttempted, []Feature{VulnerabilityReporting, Dependabot}) ||
		!errors.Is(result.Err(), context.Canceled) {
		t.Fatalf("writes=%v outcomes=%v notAttempted=%v err=%v", writer.calls, outcomes(result), result.NotAttempted, result.Err())
	}
}

// TestApplyPlansRejectsMismatchedDecisions checks a wiring error cannot apply anything.
func TestApplyPlansRejectsMismatchedDecisions(t *testing.T) {
	writer := &recordingWriter{}
	result := ApplyPlans(t.Context(), writer, overlapPlans(t), []Decision{{}})
	if len(writer.calls) != 0 || len(result.Features) != 0 || len(result.NotAttempted) != 3 || result.Err() == nil {
		t.Fatalf("writes=%v result=%+v", writer.calls, result)
	}
}

func outcomes(result EnablementResult) []Outcome {
	got := make([]Outcome, len(result.Features))
	for index, feature := range result.Features {
		got[index] = feature.Outcome()
	}
	return got
}

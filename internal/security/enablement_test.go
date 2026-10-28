package security

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

type recordingWriter struct {
	calls    []CheckID
	targets  []repository.Repository
	failures map[CheckID]error
	cancel   context.CancelFunc
}

func (w *recordingWriter) Enable(_ context.Context, repo repository.Repository, id CheckID) (Mutation, error) {
	w.calls = append(w.calls, id)
	w.targets = append(w.targets, repo)
	if w.cancel != nil {
		w.cancel()
	}
	if err := w.failures[id]; err != nil {
		return Mutation{}, err
	}
	if id == CodeQLSetup {
		return Mutation{RunURL: "https://api.github.com/repos/owner/repo/code-scanning/default-setup/runs/123"}, nil
	}
	return Mutation{}, nil
}

func enablementReport(states map[CheckID]State) StatusReport {
	report := StatusReport{
		Repository: repository.Repository{
			Target:        repository.Target{Host: "github.com", Owner: "owner", Name: "repo"},
			DefaultBranch: "release/security",
		},
		Rulesets: Rulesets{Known: true},
	}
	for _, id := range []CheckID{LegacyProtection, PrivateReporting, PushProtection, DependabotAlerts, DependabotUpdates, CodeQLSetup} {
		if state, found := states[id]; found {
			report.Checks = append(report.Checks, Check{
				ID: id, Label: string(id), Inspection: Inspection{State: state, Detail: "fixture inspection detail"},
			})
		}
	}
	return report
}

func TestFeaturePlansOnlyApplyDisabledSettings(t *testing.T) {
	features := []struct {
		feature Feature
		ids     []CheckID
	}{
		{BranchProtection, []CheckID{LegacyProtection}},
		{VulnerabilityReporting, []CheckID{PrivateReporting}},
		{SecretScanning, []CheckID{PushProtection}},
		{Dependabot, []CheckID{DependabotAlerts, DependabotUpdates}},
		{CodeScanning, []CheckID{CodeQLSetup}},
	}
	for _, feature := range features {
		for _, state := range []State{Enabled, Disabled, Unknown, Unsupported} {
			t.Run(string(feature.feature)+"/"+string(state), func(t *testing.T) {
				states := make(map[CheckID]State)
				for _, id := range feature.ids {
					states[id] = state
				}
				report := enablementReport(states)
				plan, err := PlanFeature(report, feature.feature)
				if err != nil {
					t.Fatal(err)
				}
				writer := &recordingWriter{}
				result := plan.Apply(t.Context(), writer, ApplyOptions{})
				wantOutcome := OutcomeFailed
				switch state {
				case Enabled:
					wantOutcome = OutcomeAlreadyEnabled
				case Disabled:
					wantOutcome = OutcomeApplied
				}
				if result.Feature != feature.feature || result.Outcome() != wantOutcome || len(result.Operations) != len(feature.ids) {
					t.Fatalf("result=%+v outcome=%s", result, result.Outcome())
				}
				if state == Disabled {
					if !reflect.DeepEqual(writer.calls, feature.ids) {
						t.Errorf("writes=%v; want %v", writer.calls, feature.ids)
					}
				} else if len(writer.calls) != 0 {
					t.Errorf("non-disabled inspection triggered writes: %v", writer.calls)
				}
				for _, target := range writer.targets {
					if !reflect.DeepEqual(target, report.Repository) {
						t.Errorf("write lost inspected repository metadata: %+v", target)
					}
				}
				for index, operation := range result.Operations {
					if operation.ID != feature.ids[index] || operation.Outcome != wantOutcome {
						t.Errorf("operation=%+v", operation)
					}
					if wantOutcome == OutcomeFailed && (operation.Err == nil || !strings.Contains(operation.Err.Error(), "fixture inspection detail")) {
						t.Errorf("inspection diagnostic lost: %+v", operation)
					}
				}
				if (result.Err() != nil) != (wantOutcome == OutcomeFailed) {
					t.Errorf("result error=%v for %s", result.Err(), wantOutcome)
				}
				if feature.feature == CodeScanning && state == Disabled && result.Operations[0].RunURL != "https://api.github.com/repos/owner/repo/code-scanning/default-setup/runs/123" {
					t.Error("accepted CodeQL configuration lost its run URL")
				}
			})
		}
	}
}

func TestDependabotIndependentOutcomes(t *testing.T) {
	alertsFailure := errors.New("alerts permission denied")
	updatesFailure := errors.New("security updates unavailable")
	tests := []struct {
		name     string
		alerts   State
		updates  State
		failures map[CheckID]error
		calls    []CheckID
		outcomes []Outcome
		outcome  Outcome
	}{
		{"only alerts missing", Disabled, Enabled, nil, []CheckID{DependabotAlerts}, []Outcome{OutcomeApplied, OutcomeAlreadyEnabled}, OutcomeApplied},
		{"only updates missing", Enabled, Disabled, nil, []CheckID{DependabotUpdates}, []Outcome{OutcomeAlreadyEnabled, OutcomeApplied}, OutcomeApplied},
		{"first fails second succeeds", Disabled, Disabled, map[CheckID]error{DependabotAlerts: alertsFailure}, []CheckID{DependabotAlerts, DependabotUpdates}, []Outcome{OutcomeFailed, OutcomeApplied}, OutcomePartial},
		{"first succeeds second fails", Disabled, Disabled, map[CheckID]error{DependabotUpdates: updatesFailure}, []CheckID{DependabotAlerts, DependabotUpdates}, []Outcome{OutcomeApplied, OutcomeFailed}, OutcomePartial},
		{"both fail", Disabled, Disabled, map[CheckID]error{DependabotAlerts: alertsFailure, DependabotUpdates: updatesFailure}, []CheckID{DependabotAlerts, DependabotUpdates}, []Outcome{OutcomeFailed, OutcomeFailed}, OutcomeFailed},
		{"existing alerts updates fail", Enabled, Disabled, map[CheckID]error{DependabotUpdates: updatesFailure}, []CheckID{DependabotUpdates}, []Outcome{OutcomeAlreadyEnabled, OutcomeFailed}, OutcomePartial},
		{"alerts unknown updates missing", Unknown, Disabled, nil, []CheckID{DependabotUpdates}, []Outcome{OutcomeFailed, OutcomeApplied}, OutcomePartial},
		{"alerts missing updates unknown", Disabled, Unknown, nil, []CheckID{DependabotAlerts}, []Outcome{OutcomeApplied, OutcomeFailed}, OutcomePartial},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanFeature(enablementReport(map[CheckID]State{
				DependabotAlerts: test.alerts, DependabotUpdates: test.updates,
			}), Dependabot)
			if err != nil {
				t.Fatal(err)
			}
			writer := &recordingWriter{failures: test.failures}
			result := plan.Apply(t.Context(), writer, ApplyOptions{})
			if !reflect.DeepEqual(writer.calls, test.calls) || result.Outcome() != test.outcome || len(result.Operations) != 2 {
				t.Fatalf("calls=%v result=%+v outcome=%s", writer.calls, result, result.Outcome())
			}
			for index, want := range test.outcomes {
				if result.Operations[index].Outcome != want {
					t.Errorf("operation %d=%+v; want %s", index, result.Operations[index], want)
				}
			}
			for id, failure := range test.failures {
				if !errors.Is(result.Err(), failure) || !strings.Contains(result.Err().Error(), string(id)) {
					t.Errorf("lost %s failure: %v", id, result.Err())
				}
			}
			if (result.Err() != nil) != (test.outcome == OutcomePartial || test.outcome == OutcomeFailed) {
				t.Errorf("incorrect aggregate error: %v", result.Err())
			}
		})
	}
}

func TestBranchProtectionPlanSafeguards(t *testing.T) {
	tests := []struct {
		name     string
		rulesets Rulesets
		approved bool
		wantCall bool
	}{
		{"no active rulesets", Rulesets{Known: true}, false, true},
		{"overlap unapproved", Rulesets{Known: true, Active: []string{"organization policy"}}, false, false},
		{"overlap approved", Rulesets{Known: true, Active: []string{"organization policy"}}, true, true},
		{"rulesets unknown", Rulesets{Detail: "ruleset read failed"}, false, false},
		{"approval cannot bypass unknown", Rulesets{Detail: "ruleset read failed"}, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := enablementReport(map[CheckID]State{LegacyProtection: Disabled})
			report.Rulesets = test.rulesets
			plan, err := PlanFeature(report, BranchProtection)
			if err != nil {
				t.Fatal(err)
			}
			if plan.RequiresRulesetConfirmation() != (test.rulesets.Known && len(test.rulesets.Active) > 0) {
				t.Fatal("incorrect overlap confirmation requirement")
			}
			writer := &recordingWriter{}
			result := plan.Apply(t.Context(), writer, ApplyOptions{AllowRulesetOverlap: test.approved})
			if (len(writer.calls) == 1) != test.wantCall || (result.Err() == nil) != test.wantCall {
				t.Fatalf("writes=%v result=%+v error=%v", writer.calls, result, result.Err())
			}
		})
	}
}

func TestFeaturePlanValidationAndSnapshot(t *testing.T) {
	for _, test := range []struct {
		name    string
		feature Feature
		checks  []Check
	}{
		{"unknown feature", "invalid", nil},
		{"missing inspection", SecretScanning, nil},
		{"duplicate inspection", SecretScanning, []Check{{ID: PushProtection, Inspection: Inspection{State: Disabled}}, {ID: PushProtection, Inspection: Inspection{State: Disabled}}}},
		{"invalid inspection", SecretScanning, []Check{{ID: PushProtection, Inspection: Inspection{State: "invalid"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PlanFeature(StatusReport{Checks: test.checks}, test.feature); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	report := enablementReport(map[CheckID]State{PushProtection: Enabled})
	plan, err := PlanFeature(report, SecretScanning)
	if err != nil {
		t.Fatal(err)
	}
	report.Checks[0].Inspection.State = Disabled
	checks := plan.Checks()
	checks[0].Inspection.State = Disabled
	result := plan.Apply(t.Context(), nil, ApplyOptions{})
	if result.Err() != nil || result.Outcome() != OutcomeAlreadyEnabled {
		t.Fatalf("caller changed planned inspection: %+v error=%v", result, result.Err())
	}
	if result := (FeaturePlan{}).Apply(t.Context(), nil, ApplyOptions{}); result.Err() == nil || result.Outcome() != OutcomeFailed {
		t.Fatalf("empty plan succeeded: %+v", result)
	}
	plan, err = PlanFeature(enablementReport(map[CheckID]State{PushProtection: Disabled}), SecretScanning)
	if err != nil {
		t.Fatal(err)
	}
	if result := plan.Apply(t.Context(), nil, ApplyOptions{}); result.Err() == nil || result.Outcome() != OutcomeFailed {
		t.Fatalf("missing writer succeeded: %+v", result)
	}
}

func TestFeatureApplyCancellation(t *testing.T) {
	for _, duringWrite := range []bool{false, true} {
		name := "before apply"
		if duringWrite {
			name = "during first write"
		}
		t.Run(name, func(t *testing.T) {
			plan, err := PlanFeature(enablementReport(map[CheckID]State{DependabotAlerts: Disabled, DependabotUpdates: Disabled}), Dependabot)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writer := &recordingWriter{}
			wantCalls, wantOutcome := 0, OutcomeFailed
			if duringWrite {
				writer.cancel = cancel
				wantCalls, wantOutcome = 1, OutcomePartial
			} else {
				cancel()
			}
			result := plan.Apply(ctx, writer, ApplyOptions{})
			if !errors.Is(result.Err(), context.Canceled) || len(writer.calls) != wantCalls || result.Outcome() != wantOutcome {
				t.Fatalf("calls=%v outcome=%s error=%v", writer.calls, result.Outcome(), result.Err())
			}
		})
	}
}

package security

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

type fakeReader struct {
	states      map[CheckID]State
	calls       []CheckID
	metadataErr error
	rulesets    Rulesets
	cancel      context.CancelFunc
}

// Repository returns metadata without requiring enablement permissions.
func (r *fakeReader) Repository(_ context.Context, target repository.Target) (repository.Repository, error) {
	return repository.Repository{Target: target, DefaultBranch: "release/test"}, r.metadataErr
}

// Inspect records the checks and returns an injected inspection state.
func (r *fakeReader) Inspect(_ context.Context, _ repository.Repository, id CheckID) Inspection {
	r.calls = append(r.calls, id)
	if r.cancel != nil {
		r.cancel()
	}
	return Inspection{State: r.states[id]}
}

// Rulesets returns the injected advisory metadata.
func (r *fakeReader) Rulesets(context.Context, repository.Repository) Rulesets { return r.rulesets }

// TestInspectStatusStates checks every setting's enabled, disabled, and failure states.
func TestInspectStatusStates(t *testing.T) {
	ids := []CheckID{LegacyProtection, PrivateReporting, PushProtection, DependabotAlerts, DependabotUpdates, CodeQLSetup}
	for _, id := range ids {
		for _, state := range []State{Enabled, Disabled, Unknown, Unsupported} {
			t.Run(string(id)+"/"+string(state), func(t *testing.T) {
				reader := &fakeReader{states: make(map[CheckID]State), rulesets: Rulesets{Known: true, Active: []string{"organization policy"}}}
				for _, id := range ids {
					reader.states[id] = Enabled
				}
				reader.states[id] = state
				report, err := InspectStatus(context.Background(), reader, repository.Target{Host: "github.com", Owner: "owner", Name: "repo"})
				if err != nil || !reflect.DeepEqual(reader.calls, ids) || len(report.Checks) != 6 {
					t.Fatalf("report=%+v calls=%v err=%v", report, reader.calls, err)
				}
				wantEnabled := 5
				if state == Enabled {
					wantEnabled = 6
				}
				if report.EnabledCount() != wantEnabled {
					t.Errorf("enabled=%d; want %d", report.EnabledCount(), wantEnabled)
				}
				for _, countedState := range []State{Enabled, Disabled, Unknown, Unsupported} {
					wantCount := 0
					if countedState == Enabled {
						wantCount = wantEnabled
					} else if countedState == state {
						wantCount = 1
					}
					if got := report.Count(countedState); got != wantCount {
						t.Errorf("Count(%s)=%d; want %d", countedState, got, wantCount)
					}
				}
				wantFailure := state == Unknown || state == Unsupported
				if (report.Err() != nil) != wantFailure {
					t.Errorf("status error=%v for %s", report.Err(), state)
				}
			})
		}
	}
}

// TestInspectStatusStops checks fatal metadata, cancellation, and ruleset failures.
func TestInspectStatusStops(t *testing.T) {
	reader := &fakeReader{metadataErr: errors.New("metadata unavailable")}
	if _, err := InspectStatus(context.Background(), reader, repository.Target{}); err == nil || len(reader.calls) != 0 {
		t.Fatalf("metadata failure did not stop checks: calls=%v err=%v", reader.calls, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader = &fakeReader{cancel: cancel}
	report, err := InspectStatus(ctx, reader, repository.Target{})
	if !errors.Is(err, context.Canceled) || len(reader.calls) != 1 || len(report.Checks) != 1 {
		t.Fatalf("cancellation did not stop reads: calls=%v report=%+v err=%v", reader.calls, report, err)
	}
	report, err = InspectStatus(context.Background(), &fakeReader{}, repository.Target{})
	if err != nil || report.Err() == nil || report.Rulesets.Known {
		t.Fatalf("ruleset failure must remain incomplete: report=%+v err=%v", report, err)
	}
}

// TestStatusReportDiagnostics identifies each unresolved source without changing
// the success semantics of known enabled or disabled checks.
func TestStatusReportDiagnostics(t *testing.T) {
	tests := []struct {
		name   string
		change func(*StatusReport)
		want   string
	}{
		{"complete", func(*StatusReport) {}, ""},
		{"unknown", func(r *StatusReport) { r.Checks[0].Inspection.State = Unknown }, "security inspection incomplete: Legacy branch protection: unknown"},
		{"unsupported", func(r *StatusReport) { r.Checks[1].Inspection.State = Unsupported }, "security inspection incomplete: Private vulnerability reporting: unsupported"},
		{"rulesets", func(r *StatusReport) { r.Rulesets.Known = false }, "security inspection incomplete: active rulesets: unknown"},
		{"partial", func(r *StatusReport) { r.Checks = r.Checks[:1] }, "security inspection incomplete: 1/6 checks completed"},
		{"invalid", func(r *StatusReport) { r.Checks[0].Inspection.State = "invalid" }, "security inspection incomplete: Legacy branch protection: invalid inspection state"},
		{"multiple", func(r *StatusReport) {
			r.Checks[0].Inspection.State = Unknown
			r.Checks[1].Inspection.State = Unsupported
			r.Rulesets.Known = false
		}, "security inspection incomplete: Legacy branch protection: unknown; Private vulnerability reporting: unsupported; active rulesets: unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeReader{
				states: map[CheckID]State{
					LegacyProtection: Enabled, PrivateReporting: Disabled,
					PushProtection: Disabled, DependabotAlerts: Enabled,
					DependabotUpdates: Disabled, CodeQLSetup: Disabled,
				},
				rulesets: Rulesets{Known: true},
			}
			report, err := InspectStatus(context.Background(), reader, repository.Target{})
			if err != nil {
				t.Fatal(err)
			}
			test.change(&report)
			err = report.Err()
			if test.want == "" {
				if err != nil {
					t.Fatalf("complete report failed: %v", err)
				}
			} else if err == nil || err.Error() != test.want {
				t.Fatalf("error=%v; want %q", err, test.want)
			}
		})
	}
}

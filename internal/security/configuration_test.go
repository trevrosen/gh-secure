package security

import (
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

func TestConfigurationControl(t *testing.T) {
	tests := []struct {
		name          string
		visibility    repository.Visibility
		configuration *repository.SecurityConfiguration
		lookupError   string
		check         CheckID
		blocked       bool
		state         State
		managed       bool
	}{
		{"public skips lookup", repository.VisibilityPublic, nil, "", PushProtection, false, "", false},
		{"missing result", repository.VisibilityPrivate, nil, "", PushProtection, true, Unknown, false},
		{"failed lookup", repository.VisibilityInternal, nil, "HTTP 404", PushProtection, true, Unknown, false},
		{"unknown visibility", repository.VisibilityUnknown, nil, "", PushProtection, true, Unknown, false},
		{"detached", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "detached"}, "", PushProtection, false, "", false},
		{"attached unenforced", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "attached", Enforcement: "unenforced"}, "", PushProtection, false, "", false},
		{"missing status", repository.VisibilityPrivate, &repository.SecurityConfiguration{Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"missing enforcement", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "attached"}, "", PushProtection, true, Unknown, false},
		{"inconsistent attached", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "attached", Enforcement: "enforced"}, "", PushProtection, true, Unknown, false},
		{"inconsistent enforced", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"attaching", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "attaching", Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"updating", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "updating", Enforcement: "enforced"}, "", PushProtection, true, Unknown, false},
		{"failed", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "failed", Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"removed by enterprise", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "removed_by_enterprise", Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"unrecognized status", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "other", Enforcement: "unenforced"}, "", PushProtection, true, Unknown, false},
		{"enforced not set", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enforced", PushProtection: "not_set"}, "", PushProtection, false, "", false},
		{"enforced enabled", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enforced", Name: "baseline", PushProtection: "enabled"}, "", PushProtection, true, Enabled, true},
		{"enterprise disabled", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enterprise_enforced", PushProtection: "disabled"}, "", PushProtection, true, Disabled, true},
		{"enforced missing setting", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enforced"}, "", PushProtection, true, Unknown, false},
		{"enforced unrecognized setting", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enforced", PushProtection: "other"}, "", PushProtection, true, Unknown, false},
		{"branch outside configuration", repository.VisibilityPrivate, &repository.SecurityConfiguration{Status: "enforced", Enforcement: "enforced"}, "", LegacyProtection, false, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := repository.Repository{
				Visibility: test.visibility, SecurityConfiguration: test.configuration,
				SecurityConfigurationError: test.lookupError,
			}
			control, blocked := ConfigurationControl(repo, test.check)
			if blocked != test.blocked || control.State != test.state || (control.ManagedBy != "") != test.managed {
				t.Fatalf("control=%+v blocked=%t; want state=%s blocked=%t managed=%t",
					control, blocked, test.state, test.blocked, test.managed)
			}
			if blocked && !strings.Contains(control.Detail, "contact the organization or enterprise administrator") {
				t.Fatalf("missing administrator guidance: %+v", control)
			}
		})
	}
}

func TestConfigurationControlEvaluatesEachFeatureIndependently(t *testing.T) {
	repo := repository.Repository{
		Visibility: repository.VisibilityPrivate,
		SecurityConfiguration: &repository.SecurityConfiguration{
			Status: "enforced", Enforcement: "enforced", PrivateVulnerabilityReporting: "enabled",
			PushProtection: "disabled", DependabotAlerts: "not_set",
			DependabotUpdates: "enabled", CodeScanning: "disabled",
		},
	}
	for _, test := range []struct {
		check   CheckID
		blocked bool
		state   State
	}{
		{PrivateReporting, true, Enabled},
		{PushProtection, true, Disabled},
		{DependabotAlerts, false, ""},
		{DependabotUpdates, true, Enabled},
		{CodeQLSetup, true, Disabled},
	} {
		control, blocked := ConfigurationControl(repo, test.check)
		if blocked != test.blocked || control.State != test.state {
			t.Errorf("%s: control=%+v blocked=%t", test.check, control, blocked)
		}
	}
}

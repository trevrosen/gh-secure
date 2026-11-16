package security

import (
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// ConfigurationControl reports policy control or uncertainty that blocks a write.
// The check state is populated only when an enforced configuration sets it.
func ConfigurationControl(repo repository.Repository, check CheckID) (Inspection, bool) {
	if repo.Visibility == repository.VisibilityPublic {
		return Inspection{}, false
	}
	if repo.SecurityConfigurationError != "" {
		return unknownConfiguration(repo.SecurityConfigurationError), true
	}
	configuration := repo.SecurityConfiguration
	if configuration == nil {
		return unknownConfiguration("no configuration result was received"), true
	}
	switch {
	case configuration.Status == "detached":
		return Inspection{}, false
	case configuration.Status == "attached" && configuration.Enforcement == "unenforced":
		return Inspection{}, false
	case configuration.Status == "enforced" &&
		(configuration.Enforcement == "enforced" || configuration.Enforcement == "enterprise_enforced"):
		return enforcedConfigurationControl(configuration, check)
	default:
		return unknownConfiguration("configuration attachment or enforcement is missing, inconsistent, or in transition"), true
	}
}

func enforcedConfigurationControl(configuration *repository.SecurityConfiguration, check CheckID) (Inspection, bool) {
	var value string
	switch check {
	case LegacyProtection:
		// Code security configurations do not configure legacy branch protection.
		return Inspection{}, false
	case PrivateReporting:
		value = configuration.PrivateVulnerabilityReporting
	case PushProtection:
		value = configuration.PushProtection
	case DependabotAlerts:
		value = configuration.DependabotAlerts
	case DependabotUpdates:
		value = configuration.DependabotUpdates
	case CodeQLSetup:
		value = configuration.CodeScanning
	default:
		return unknownConfiguration("the selected setting is not recognized"), true
	}
	state := State("")
	switch value {
	case "not_set":
		return Inspection{}, false
	case "enabled":
		state = Enabled
	case "disabled":
		state = Disabled
	default:
		return unknownConfiguration("the configuration's setting is missing or unrecognized"), true
	}
	name := strings.TrimSpace(configuration.Name)
	if name == "" {
		name = "an organization or enterprise security configuration"
	}
	return Inspection{
		State: state, ManagedBy: name,
		Detail: "controlled by enforced security configuration " + name +
			"; contact the organization or enterprise administrator to change it",
	}, true
}

func unknownConfiguration(reason string) Inspection {
	return Inspection{
		State: Unknown,
		Detail: "security configuration control is unknown: " + reason +
			"; contact the organization or enterprise administrator before changing settings",
	}
}

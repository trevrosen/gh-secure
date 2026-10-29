package github

import (
	"context"
	"net/http"
	"net/url"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// Inspect performs one endpoint-specific check without issuing mutations.
// Ambiguous failures and omitted security fields remain unknown, never disabled.
func (c *Client) Inspect(ctx context.Context, repo repository.Repository, check security.CheckID) security.Inspection {
	if err := ctx.Err(); err != nil {
		return unknown(err)
	}
	base := repoPath(repo.Target)
	switch check {
	case security.LegacyProtection:
		path := base + "/branches/" + url.PathEscape(repo.DefaultBranch) + "/protection"
		var response struct {
			// URL identifies the returned legacy protection configuration.
			URL *string `json:"url"`
		}
		if _, err := c.get(ctx, path, &response, http.StatusOK); err != nil {
			return unknown(err)
		}
		if response.URL == nil || *response.URL == "" {
			return security.Inspection{State: security.Unknown, Detail: "branch protection response is missing its URL"}
		}
		return security.Inspection{State: security.Enabled}
	case security.PrivateReporting:
		if repo.Private {
			return security.Inspection{State: security.Unsupported, Detail: "private vulnerability reporting is available only for public repositories"}
		}
		return c.enabledSetting(ctx, base+"/private-vulnerability-reporting")
	case security.PushProtection:
		switch repo.PushProtection {
		case "enabled":
			return security.Inspection{State: security.Enabled}
		case "disabled":
			return security.Inspection{State: security.Disabled}
		default:
			return security.Inspection{State: security.Unknown, Detail: "push-protection status is missing or unrecognized; check security-setting permissions and feature availability"}
		}
	case security.DependabotAlerts:
		if _, err := c.get(ctx, base+"/vulnerability-alerts", nil, http.StatusNoContent); err != nil {
			return unknown(err)
		}
		return security.Inspection{State: security.Enabled}
	case security.DependabotUpdates:
		var response struct {
			// Enabled reports security-update configuration.
			Enabled *bool `json:"enabled"`
			// Paused distinguishes configured updates from active updates.
			Paused *bool `json:"paused"`
		}
		if _, err := c.get(ctx, base+"/automated-security-fixes", &response, http.StatusOK); err != nil {
			return unknown(err)
		}
		if response.Enabled == nil || response.Paused == nil {
			return security.Inspection{State: security.Unknown, Detail: "security-updates response is missing enabled or paused"}
		}
		result := booleanInspection(response.Enabled)
		if *response.Paused {
			result.Detail = "security updates are paused"
		}
		return result
	case security.CodeQLSetup:
		var response struct {
			// State reports default-setup configuration, not analysis completion.
			State *string `json:"state"`
		}
		if _, err := c.get(ctx, base+"/code-scanning/default-setup", &response, http.StatusOK); err != nil {
			return unknown(err)
		}
		state := ""
		if response.State != nil {
			state = *response.State
		}
		switch state {
		case "configured":
			return security.Inspection{State: security.Enabled}
		case "not-configured":
			return security.Inspection{State: security.Disabled}
		default:
			return security.Inspection{State: security.Unknown, Detail: "CodeQL default-setup state is missing or unrecognized"}
		}
	default:
		return security.Inspection{State: security.Unknown, Detail: "unrecognized security check"}
	}
}

func (c *Client) enabledSetting(ctx context.Context, path string) security.Inspection {
	var response struct {
		// Enabled preserves the difference between false and absent.
		Enabled *bool `json:"enabled"`
	}
	if _, err := c.get(ctx, path, &response, http.StatusOK); err != nil {
		return unknown(err)
	}
	return booleanInspection(response.Enabled)
}

func booleanInspection(enabled *bool) security.Inspection {
	if enabled == nil {
		return security.Inspection{State: security.Unknown, Detail: "enabled field is missing from the setting response"}
	}
	if *enabled {
		return security.Inspection{State: security.Enabled}
	}
	return security.Inspection{State: security.Disabled}
}

func unknown(err error) security.Inspection {
	return security.Inspection{State: security.Unknown, Detail: err.Error()}
}

package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

type branchProtectionRequest struct {
	RequiredStatusChecks           *struct{}                 `json:"required_status_checks"`
	EnforceAdmins                  bool                      `json:"enforce_admins"`
	RequiredPullRequestReviews     pullRequestReviewsRequest `json:"required_pull_request_reviews"`
	Restrictions                   *struct{}                 `json:"restrictions"`
	AllowForcePushes               bool                      `json:"allow_force_pushes"`
	AllowDeletions                 bool                      `json:"allow_deletions"`
	RequiredConversationResolution bool                      `json:"required_conversation_resolution"`
}

type pullRequestReviewsRequest struct {
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
}

type pushProtectionRequest struct {
	SecurityAndAnalysis struct {
		PushProtection struct {
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
}

type codeQLSetupRequest struct {
	State      string `json:"state"`
	QuerySuite string `json:"query_suite"`
}

// Enable sends one typed mutation. The caller must establish a disabled state
// and obtain approvals first; this method never inspects, retries, or reconciles.
func (c *Client) Enable(ctx context.Context, repo repository.Repository, check security.CheckID) (security.Mutation, error) {
	if err := ctx.Err(); err != nil {
		return security.Mutation{}, err
	}
	if err := repository.ValidateName(repo.Target.Owner + "/" + repo.Target.Name); err != nil {
		return security.Mutation{}, err
	}
	base := repoPath(repo.Target)
	switch check {
	case security.LegacyProtection:
		if strings.TrimSpace(repo.DefaultBranch) == "" {
			return security.Mutation{}, errors.New("cannot protect a missing default branch")
		}
		path := base + "/branches/" + url.PathEscape(repo.DefaultBranch) + "/protection"
		payload := branchProtectionRequest{
			RequiredPullRequestReviews: pullRequestReviewsRequest{
				RequiredApprovingReviewCount: 1,
				DismissStaleReviews:          true,
			},
			RequiredConversationResolution: true,
		}
		var response *struct {
			URL string `json:"url"`
		}
		if _, err := c.request(ctx, http.MethodPut, path, payload, &response, http.StatusOK); err != nil {
			return security.Mutation{}, err
		}
		if response == nil || response.URL == "" {
			return security.Mutation{}, fmt.Errorf("PUT %s: protection response is missing its URL; outcome unverified", path)
		}
	case security.PrivateReporting:
		if repo.Private {
			return security.Mutation{}, errors.New("private vulnerability reporting is available only for public repositories")
		}
		return security.Mutation{}, c.putWithoutBody(ctx, base+"/private-vulnerability-reporting")
	case security.DependabotAlerts:
		return security.Mutation{}, c.putWithoutBody(ctx, base+"/vulnerability-alerts")
	case security.DependabotUpdates:
		return security.Mutation{}, c.putWithoutBody(ctx, base+"/automated-security-fixes")
	case security.PushProtection:
		var payload pushProtectionRequest
		payload.SecurityAndAnalysis.PushProtection.Status = "enabled"
		var response *repositoryResponse
		if _, err := c.request(ctx, http.MethodPatch, base, payload, &response, http.StatusOK); err != nil {
			return security.Mutation{}, err
		}
		if response == nil {
			return security.Mutation{}, fmt.Errorf("PATCH %s: missing repository response; outcome unverified", base)
		}
		if status := response.SecurityAndAnalysis.PushProtection.Status; status != "" && status != "enabled" {
			return security.Mutation{}, fmt.Errorf("PATCH %s: response does not confirm enabled push protection; outcome unverified", base)
		}
	case security.CodeQLSetup:
		path := base + "/code-scanning/default-setup"
		var response *struct {
			RunID  *int64 `json:"run_id"`
			RunURL string `json:"run_url"`
		}
		if _, err := c.request(ctx, http.MethodPatch, path, codeQLSetupRequest{
			State: "configured", QuerySuite: "default",
		}, &response, http.StatusOK, http.StatusAccepted); err != nil {
			return security.Mutation{}, err
		}
		if response == nil {
			return security.Mutation{}, fmt.Errorf("PATCH %s: missing configuration response; outcome unverified", path)
		}
		if response.RunURL != "" {
			address, err := url.Parse(response.RunURL)
			if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil {
				return security.Mutation{}, fmt.Errorf("PATCH %s: invalid CodeQL run URL; outcome unverified", path)
			}
		}
		return security.Mutation{RunURL: response.RunURL}, nil
	default:
		return security.Mutation{}, fmt.Errorf("cannot enable unrecognized security check %q", check)
	}
	return security.Mutation{}, nil
}

// putWithoutBody enables a setting whose endpoint accepts no payload and returns 204.
func (c *Client) putWithoutBody(ctx context.Context, path string) error {
	_, err := c.request(ctx, http.MethodPut, path, nil, nil, http.StatusNoContent)
	return err
}

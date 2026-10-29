package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// Rulesets paginates repository and inherited rulesets and counts only active ones.
// Any failed or malformed page invalidates the aggregate rather than hiding rulesets.
func (c *Client) Rulesets(ctx context.Context, repo repository.Repository) security.Rulesets {
	active := make([]string, 0)
	seen := make(map[int64]bool)
	for page := 1; page != 0; {
		path := repoPath(repo.Target) + "/rulesets?includes_parents=true&per_page=100&page=" + strconv.Itoa(page)
		var items []rulesetResponse
		header, err := c.get(ctx, path, &items, http.StatusOK)
		if err != nil {
			return security.Rulesets{Detail: err.Error()}
		}
		if items == nil {
			return security.Rulesets{Detail: "ruleset response is not an array"}
		}
		for _, item := range items {
			if problem := item.problem(); problem != "" {
				return security.Rulesets{Detail: problem}
			}
			if seen[*item.ID] {
				return security.Rulesets{Detail: "ruleset pagination returned a duplicate id; retry inspection"}
			}
			seen[*item.ID] = true
			if *item.Enforcement == "active" {
				active = append(active, *item.Name)
			}
		}
		page, err = nextPage(header, page)
		if err != nil {
			return security.Rulesets{Detail: err.Error()}
		}
	}
	return security.Rulesets{Known: true, Active: active}
}

type rulesetResponse struct {
	// ID identifies a repository or inherited ruleset.
	ID *int64 `json:"id"`
	// Name is the ruleset's display name.
	Name *string `json:"name"`
	// Enforcement distinguishes active, disabled, and evaluation-only rules.
	Enforcement *string `json:"enforcement"`
}

// problem describes missing or unrecognized ruleset fields, or returns "".
func (r rulesetResponse) problem() string {
	if r.ID == nil || *r.ID <= 0 || r.Name == nil || *r.Name == "" || r.Enforcement == nil {
		return "ruleset response is missing id, name, or enforcement"
	}
	if !slices.Contains([]string{"active", "disabled", "evaluate"}, *r.Enforcement) {
		return "ruleset response has an unrecognized enforcement value"
	}
	return ""
}

// Policy inspects the community-profile advisory without changing primary results.
// The public API does not document a security file field, so omission or null
// cannot establish absence. An explicit valid policy URL is retained if supplied.
func (c *Client) Policy(ctx context.Context, repo repository.Repository) security.Policy {
	path := repoPath(repo.Target) + "/community/profile"
	var response struct {
		// Files contains community-file metadata.
		Files *struct {
			// Security retains optional, undocumented policy metadata if supplied.
			Security json.RawMessage `json:"security"`
		} `json:"files"`
	}
	if _, err := c.get(ctx, path, &response, http.StatusOK); err != nil {
		return security.Policy{State: security.Unknown, Detail: err.Error()}
	}
	if response.Files == nil {
		return security.Policy{State: security.Unknown, Detail: "community profile is missing files metadata"}
	}
	if len(response.Files.Security) == 0 || bytes.Equal(bytes.TrimSpace(response.Files.Security), []byte("null")) {
		return security.Policy{State: security.Unknown, Detail: "security policy not assessed: community-profile API does not document security-policy metadata"}
	}
	var file struct {
		// URL identifies an explicitly supplied security-policy file.
		URL *string `json:"url"`
	}
	if err := json.Unmarshal(response.Files.Security, &file); err != nil || file.URL == nil {
		return security.Policy{State: security.Unknown, Detail: "invalid security-policy metadata"}
	}
	address, err := url.Parse(*file.URL)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil {
		return security.Policy{State: security.Unknown, Detail: fmt.Sprintf("GET %s: invalid security-policy URL", path)}
	}
	return security.Policy{State: security.Enabled, URL: address.String()}
}

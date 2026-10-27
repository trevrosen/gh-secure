// Package github provides typed, authenticated GitHub REST operations.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/cli/go-gh/v2/pkg/api"
)

// Client adapts GitHub CLI authentication and host routing for security inspection.
type Client struct {
	rest *api.RESTClient
}

// NewClient builds a read adapter with no persistent cache or environment-driven
// HTTP logging. Authentication and API-host overrides follow GitHub CLI conventions.
func NewClient(options api.ClientOptions) (*Client, error) {
	options.EnableCache = false
	options.LogIgnoreEnv = true
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	options.Headers = maps.Clone(options.Headers)
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}
	options.Headers["Accept"] = "application/vnd.github+json"
	options.Headers["X-GitHub-Api-Version"] = "2022-11-28"
	options.Headers["User-Agent"] = "gh-secure"
	options.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many API redirects")
		}
		if request.URL.Host != via[0].URL.Host || request.URL.Scheme != via[0].URL.Scheme {
			return errors.New("refusing API redirect to another origin")
		}
		return nil
	}
	rest, err := api.NewRESTClient(options)
	if err != nil {
		return nil, fmt.Errorf("initialize authenticated GitHub client: %w", err)
	}
	return &Client{rest: rest}, nil
}

func repoPath(target repository.Target) string {
	return "repos/" + url.PathEscape(target.Owner) + "/" + url.PathEscape(target.Name)
}

func (c *Client) get(ctx context.Context, path string, destination any, status int) (http.Header, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := c.rest.RequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, &requestError{path: path, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return nil, fmt.Errorf("GET %s: unexpected HTTP %d (expected %d)", path, response.StatusCode, status)
	}
	if destination != nil {
		decoder := json.NewDecoder(response.Body)
		if err := decoder.Decode(destination); err != nil {
			return nil, fmt.Errorf("GET %s: invalid JSON response", path)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("GET %s: unexpected trailing response content", path)
		}
	}
	return response.Header, nil
}

type requestError struct {
	path  string
	cause error
}

// Error describes a failed request without echoing arbitrary bodies or credentials.
func (e *requestError) Error() string {
	if errors.Is(e.cause, context.Canceled) || errors.Is(e.cause, context.DeadlineExceeded) {
		return fmt.Sprintf("GET %s: %v", e.path, contextError(e.cause))
	}
	var failure *api.HTTPError
	if !errors.As(e.cause, &failure) {
		return fmt.Sprintf("GET %s: request failed; check network and host configuration", e.path)
	}
	hint := "check repository access, feature availability, and host support"
	switch failure.StatusCode {
	case http.StatusUnauthorized:
		hint = "check GitHub CLI authentication for this host"
	case http.StatusForbidden:
		hint = "check token permissions, organization policy, and feature availability"
	case http.StatusTooManyRequests:
		hint = "rate limited; retry after the limit resets"
	case http.StatusNotFound:
		hint = "not found or inaccessible; this does not establish that the setting is disabled"
	}
	if failure.StatusCode == http.StatusForbidden &&
		(failure.Headers.Get("X-RateLimit-Remaining") == "0" ||
			failure.Headers.Get("Retry-After") != "" ||
			strings.Contains(strings.ToLower(failure.Message), "rate limit")) {
		hint = "rate limited; retry after the limit resets"
	}
	return fmt.Sprintf("GET %s: HTTP %d; %s", e.path, failure.StatusCode, hint)
}

// Unwrap preserves cancellation and typed HTTP error inspection.
func (e *requestError) Unwrap() error { return e.cause }

func contextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return context.DeadlineExceeded
}

type repositoryResponse struct {
	// DefaultBranch preserves missing branch metadata.
	DefaultBranch *string `json:"default_branch"`
	// Private preserves missing visibility metadata.
	Private *bool `json:"private"`
	// Permissions contains any permissions disclosed by GitHub.
	Permissions struct {
		// Admin records administrator permission when disclosed.
		Admin *bool `json:"admin"`
		// Maintain records maintainer permission when disclosed.
		Maintain *bool `json:"maintain"`
	} `json:"permissions"`
	// SecurityAndAnalysis contains visible security-setting metadata.
	SecurityAndAnalysis struct {
		// PushProtection contains the secret push-protection setting.
		PushProtection struct {
			// Status is enabled, disabled, or absent.
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
}

// Repository fetches metadata once and rejects missing branch or visibility data.
// Permissions are retained when disclosed but do not gate status inspection.
func (c *Client) Repository(ctx context.Context, target repository.Target) (repository.Repository, error) {
	var response repositoryResponse
	path := repoPath(target)
	if _, err := c.get(ctx, path, &response, http.StatusOK); err != nil {
		return repository.Repository{}, err
	}
	if response.DefaultBranch == nil || strings.TrimSpace(*response.DefaultBranch) == "" || response.Private == nil {
		return repository.Repository{}, fmt.Errorf("GET %s: missing default_branch or private metadata", path)
	}
	return repository.Repository{
		Target: target, DefaultBranch: *response.DefaultBranch, Private: *response.Private,
		Permissions:    repository.Permissions{Admin: response.Permissions.Admin, Maintain: response.Permissions.Maintain},
		PushProtection: response.SecurityAndAnalysis.PushProtection.Status,
	}, nil
}

func nextPage(header http.Header, page int) (int, error) {
	nextNumber := 0
	for _, link := range strings.Split(strings.Join(header.Values("Link"), ","), ",") {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		address, attributes, found := strings.Cut(link, ">")
		if !found || !strings.HasPrefix(address, "<") {
			return 0, errors.New("malformed pagination link")
		}
		_, parameters, err := mime.ParseMediaType("link" + attributes)
		if err != nil || parameters["rel"] == "" {
			return 0, errors.New("malformed pagination relation")
		}
		hasNext := false
		for _, relation := range strings.Fields(parameters["rel"]) {
			hasNext = hasNext || relation == "next"
		}
		if !hasNext {
			continue
		}
		next, err := url.Parse(strings.TrimPrefix(address, "<"))
		if err != nil {
			return 0, errors.New("invalid next-page link")
		}
		number, err := strconv.Atoi(next.Query().Get("page"))
		if err != nil || number != page+1 || nextNumber != 0 {
			return 0, errors.New("invalid or nonsequential next-page link")
		}
		// Only use the page number, never a server-supplied host or request path.
		nextNumber = number
	}
	return nextNumber, nil
}

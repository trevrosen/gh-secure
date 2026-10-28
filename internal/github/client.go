// Package github provides typed, authenticated GitHub REST operations.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// Client adapts GitHub CLI authentication and host routing for security operations.
type Client struct {
	rest *api.RESTClient
}

// NewClient builds an adapter with no persistent cache or environment-driven
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
		if via[0].Method != http.MethodGet && via[0].Method != http.MethodHead {
			return http.ErrUseLastResponse
		}
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
	return c.request(ctx, http.MethodGet, path, nil, destination, status)
}

func (c *Client) request(ctx context.Context, method, path string, payload, destination any, statuses ...int) (http.Header, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("%s %s: encode request body: %w", method, path, err)
		}
		body = bytes.NewReader(encoded)
	}
	response, err := c.rest.RequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, &requestError{method: method, path: path, cause: err}
	}
	defer response.Body.Close()
	if !slices.Contains(statuses, response.StatusCode) {
		return nil, fmt.Errorf("%s %s: unexpected HTTP %d (expected %v)", method, path, response.StatusCode, statuses)
	}
	if destination == nil {
		return response.Header, nil
	}
	problem := singleValueProblem(json.NewDecoder(response.Body), destination)
	// Cancellation takes precedence because an interrupted body can look malformed.
	if err := ctx.Err(); err != nil {
		return nil, &requestError{method: method, path: path, cause: err}
	}
	if problem != "" {
		return nil, fmt.Errorf("%s %s: %s", method, path, problem)
	}
	return response.Header, nil
}

// singleValueProblem decodes exactly one JSON value and describes any violation.
func singleValueProblem(decoder *json.Decoder, destination any) string {
	if decoder.Decode(destination) != nil {
		return "invalid JSON response"
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "unexpected trailing response content"
	}
	return ""
}

type requestError struct {
	method string
	path   string
	cause  error
}

// Error describes a failed request without echoing arbitrary bodies or credentials.
func (e *requestError) Error() string {
	if errors.Is(e.cause, context.Canceled) || errors.Is(e.cause, context.DeadlineExceeded) {
		return fmt.Sprintf("%s %s: %v", e.method, e.path, contextError(e.cause))
	}
	var failure *api.HTTPError
	if !errors.As(e.cause, &failure) {
		return fmt.Sprintf("%s %s: request failed; check network and host configuration", e.method, e.path)
	}
	return fmt.Sprintf("%s %s: HTTP %d; %s", e.method, e.path, failure.StatusCode, statusHint(failure))
}

// statusHint suggests a next step for an HTTP failure without echoing its body.
func statusHint(failure *api.HTTPError) string {
	if rateLimited(failure) {
		return "rate limited; retry after the limit resets"
	}
	switch failure.StatusCode {
	case http.StatusUnauthorized:
		return "check GitHub CLI authentication for this host"
	case http.StatusForbidden:
		return "check token permissions, organization policy, and feature availability"
	case http.StatusNotFound:
		return "not found or inaccessible; this does not establish that the setting is disabled"
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return "redirect refused; inspect the resolved repository before retrying"
	case http.StatusConflict:
		return "conflicting configuration or an operation is in progress; inspect before retrying"
	case http.StatusUnprocessableEntity:
		return "request rejected; check repository state, feature requirements, and validation constraints"
	default:
		return "check repository access, feature availability, and host support"
	}
}

// rateLimited recognizes 429 responses and GitHub's rate-limited 403 responses.
func rateLimited(failure *api.HTTPError) bool {
	if failure.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return failure.StatusCode == http.StatusForbidden &&
		(failure.Headers.Get("X-RateLimit-Remaining") == "0" ||
			failure.Headers.Get("Retry-After") != "" ||
			strings.Contains(strings.ToLower(failure.Message), "rate limit"))
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
		if !slices.Contains(strings.Fields(parameters["rel"]), "next") {
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

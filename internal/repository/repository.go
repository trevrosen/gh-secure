// Package repository resolves GitHub targets and describes repository metadata.
package repository

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	ghrepository "github.com/cli/go-gh/v2/pkg/repository"
)

// Target identifies a repository on its authenticated GitHub web host.
type Target struct {
	// Host is the GitHub web hostname, not the API hostname.
	Host string
	// Owner is the repository owner.
	Owner string
	// Name is the repository name.
	Name string
}

// String returns the host-qualified repository name.
func (t Target) String() string { return t.Host + "/" + t.Owner + "/" + t.Name }

// WebURL returns the repository's HTTPS URL on the resolved web host.
func (t Target) WebURL() string {
	return "https://" + t.Host + "/" + url.PathEscape(t.Owner) + "/" + url.PathEscape(t.Name)
}

// Permissions preserves known permissions without treating absent fields as false.
type Permissions struct {
	// Admin is nil if GitHub did not disclose administrator permission.
	Admin *bool
	// Maintain is nil if GitHub did not disclose maintainer permission.
	Maintain *bool
}

// Repository describes metadata fetched once for an inspection.
type Repository struct {
	// Target identifies the resolved repository.
	Target Target
	// DefaultBranch is the server-reported default branch, never a guessed value.
	DefaultBranch string
	// Private reports repository visibility.
	Private bool
	// Permissions contains any permissions disclosed in metadata.
	Permissions Permissions
	// PushProtection is the server-reported status, or empty if not disclosed.
	PushProtection string
}

// ValidateName checks the explicit and prompted owner/repo command-line format.
func ValidateName(name string) error {
	owner, repo, found := strings.Cut(name, "/")
	if !found || !component(owner) || !component(repo) {
		return fmt.Errorf("repository must be in owner/repo format with nonempty name components, got %q", name)
	}
	return nil
}

func component(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

// Resolver selects an explicit, discovered, or prompted target without API calls.
type Resolver struct {
	current func() (ghrepository.Repository, error)
	prompt  func(context.Context) (string, error)
}

// NewResolver uses GitHub CLI discovery and the supplied repository-input prompt.
// A nil prompt disables interactive fallback.
func NewResolver(prompt func(context.Context) (string, error)) Resolver {
	return Resolver{current: ghrepository.Current, prompt: prompt}
}

// Resolve respects explicit input first, then GH_REPO and git remotes, then input.
// Discovery failure is retained when interactive fallback is unavailable.
func (r Resolver) Resolve(ctx context.Context, explicit string) (Target, error) {
	if err := ctx.Err(); err != nil {
		return Target{}, err
	}
	if explicit != "" {
		return parseName(explicit)
	}
	current, err := r.current()
	if err == nil {
		return checkedTarget(current)
	}
	if r.prompt == nil {
		return Target{}, fmt.Errorf("cannot discover repository: %w; specify --repo owner/repo", err)
	}
	name, promptErr := r.prompt(ctx)
	if promptErr != nil {
		return Target{}, fmt.Errorf("cannot discover repository (%v); repository input failed: %w", err, promptErr)
	}
	if err := ctx.Err(); err != nil {
		return Target{}, err
	}
	return parseName(name)
}

func parseName(name string) (Target, error) {
	if err := ValidateName(name); err != nil {
		return Target{}, err
	}
	repo, err := ghrepository.Parse(name)
	if err != nil {
		return Target{}, err
	}
	return checkedTarget(repo)
}

func checkedTarget(repo ghrepository.Repository) (Target, error) {
	if err := ValidateName(repo.Owner + "/" + repo.Name); err != nil {
		return Target{}, err
	}
	host, err := url.Parse("//" + repo.Host)
	if err != nil || host.Host != repo.Host || host.Hostname() == "" ||
		strings.ContainsAny(repo.Host, ":\\ \t\r\n") {
		return Target{}, fmt.Errorf("invalid GitHub hostname %q", repo.Host)
	}
	return Target{Host: repo.Host, Owner: repo.Owner, Name: repo.Name}, nil
}

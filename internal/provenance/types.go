// Package provenance inspects distributed build outputs without executing them.
package provenance

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// State describes evidence, not the presence of an action in a workflow.
type State string

const (
	// Verified means cryptographic verification and producer identity checks passed.
	Verified State = "verified"
	// Missing means a complete, successful lookup found no GitHub provenance.
	Missing State = "missing"
	// Unknown means identity, discovery, or verification was inconclusive.
	Unknown State = "unknown"
	// Unsupported means the host or publishing pattern is outside implemented coverage.
	Unsupported State = "unsupported"
)

// Candidate describes one publication mentioned by an immutable workflow revision.
// Empty or unresolved identities are retained as coverage gaps, never guessed.
type Candidate struct {
	Kind     string
	Name     string
	Version  string
	Digest   string
	URL      string
	Workflow string
	Job      string
	RunID    int64
	RunURL   string
	SHA      string
	Evidence string
	Problem  string
}

// Finding carries an artifact identity and its assessment.
type Finding struct {
	Artifact Candidate
	State    State
	Detail   string
}

// Report describes the inspected window and all incomplete coverage.
type Report struct {
	Findings []Finding
	Gaps     []string
	Runs     int
}

// Err prevents unknown, missing, or empty observations from becoming a clean result.
func (r Report) Err() error {
	if len(r.Gaps) > 0 || len(r.Findings) == 0 {
		return errors.New("provenance inspection is incomplete; see coverage diagnostics")
	}
	for _, finding := range r.Findings {
		if finding.State != Verified {
			return errors.New("provenance inspection found missing or unresolved provenance")
		}
	}
	return nil
}

// Resolver resolves a publication's immutable identity using read-only metadata.
type Resolver interface {
	Resolve(context.Context, Candidate) ([]Candidate, error)
}

var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ValidDigest accepts canonical SHA256 identities only.
func ValidDigest(value string) bool { return sha256Pattern.MatchString(value) }

// ValidateIdentity rejects nonimmutable or incomplete assessment inputs.
func ValidateIdentity(c Candidate) error {
	if c.Name == "" || !ValidDigest(c.Digest) {
		return fmt.Errorf("unresolved immutable identity for %q", c.Name)
	}
	return nil
}

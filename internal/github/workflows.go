package github

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/GitHubSecurityLab/gh-secure/internal/provenance"
)

// WorkflowSources pins a default-branch scan without reading Actions run history.
// Finding adoption deliberately stops retrieval before complete workflow coverage.
func (r ProvenanceReader) WorkflowSources(ctx context.Context, branch string) (string, map[string][]byte, error) {
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := r.read(ctx, "/commits/"+url.PathEscape(branch), &commit); err != nil {
		return "", nil, err
	}
	if len(commit.SHA) != 40 {
		return "", nil, errors.New("default branch commit SHA is unavailable")
	}
	var entries []struct{ Path, Type string }
	if _, err := r.read(ctx, "/contents/.github/workflows?ref="+url.QueryEscape(commit.SHA), &entries); err != nil {
		// A 404 can also mean inaccessible content. Never report that as no workflows.
		return commit.SHA, nil, fmt.Errorf("workflow directory unavailable; publication coverage unknown: %w", err)
	}
	if entries == nil || len(entries) >= 1000 {
		return commit.SHA, nil, errors.New("workflow directory listing absent or potentially truncated")
	}
	sources := make(map[string][]byte)
	for _, entry := range entries {
		if !provenance.WorkflowPath(entry.Path) {
			continue
		}
		if entry.Type != "file" || len(sources) >= 100 {
			return commit.SHA, nil, errors.New("unsupported workflow entry or workflow source limit (100) reached")
		}
		data, err := r.File(ctx, entry.Path, commit.SHA)
		if err != nil {
			return commit.SHA, nil, err
		}
		sources[entry.Path] = data
		if _, adopted := provenance.AttestationConfiguration(data, entry.Path); adopted {
			break
		}
	}
	return commit.SHA, sources, nil
}

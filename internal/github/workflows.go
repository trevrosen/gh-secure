package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/provenance"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// WorkflowReader reads workflow source in one resolved repository.
type WorkflowReader struct {
	Client *Client
	Target repository.Target
}

func (r WorkflowReader) read(ctx context.Context, suffix string, dest any) error {
	p := repoPath(r.Target) + suffix
	response, err := r.Client.rest.RequestWithContext(ctx, http.MethodGet, p, nil)
	if err != nil {
		return &requestError{method: http.MethodGet, path: p, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected HTTP %d", p, response.StatusCode)
	}
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fmt.Errorf("GET %s: response read failed", p)
	}
	if len(data) > limit {
		return fmt.Errorf("GET %s: metadata exceeds 8 MiB limit", p)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("GET %s: invalid JSON metadata", p)
	}
	return nil
}

// WorkflowSources pins a default-branch scan without reading Actions run history.
// Finding adoption deliberately stops retrieval before complete workflow coverage.
func (r WorkflowReader) WorkflowSources(ctx context.Context, branch string) (string, map[string][]byte, error) {
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := r.read(ctx, "/commits/"+url.PathEscape(branch), &commit); err != nil {
		return "", nil, err
	}
	if len(commit.SHA) != 40 || strings.Trim(commit.SHA, "0123456789abcdef") != "" {
		return "", nil, errors.New("default branch commit SHA is unavailable")
	}
	var entries []struct{ Path, Type string }
	if err := r.read(ctx, "/contents/.github/workflows?ref="+url.QueryEscape(commit.SHA), &entries); err != nil {
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

// File reads only an immutable workflow revision, never an artifact or manifest.
func (r WorkflowReader) File(ctx context.Context, file, sha string) ([]byte, error) {
	if !provenance.WorkflowPath(file) || len(sha) != 40 || strings.Trim(sha, "0123456789abcdef") != "" {
		return nil, errors.New("invalid workflow source identity")
	}
	var response struct {
		Encoding, Content string
		Size              int
		Type              string
	}
	err := r.read(ctx, "/contents/"+url.PathEscape(file)+"?ref="+url.QueryEscape(sha), &response)
	if err != nil {
		return nil, err
	}
	if response.Type != "file" || response.Encoding != "base64" || response.Size > 1<<20 || response.Size < 0 {
		return nil, errors.New("workflow source is unsupported or exceeds 1 MiB")
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("invalid workflow source encoding or size")
	}
	return data, nil
}

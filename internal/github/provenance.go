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
	"time"

	"github.com/klauspost/compress/snappy"

	"github.com/GitHubSecurityLab/gh-secure/internal/provenance"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// ProvenanceReader scopes read-only discovery to one already resolved repository.
type ProvenanceReader struct {
	Client *Client
	Target repository.Target
}

func (r ProvenanceReader) read(ctx context.Context, suffix string, dest any) (http.Header, error) {
	p := repoPath(r.Target) + suffix
	response, err := r.Client.rest.RequestWithContext(ctx, http.MethodGet, p, nil)
	if err != nil {
		return nil, &requestError{method: http.MethodGet, path: p, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected HTTP %d", p, response.StatusCode)
	}
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: response read failed", p)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("GET %s: metadata exceeds 8 MiB limit", p)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return nil, fmt.Errorf("GET %s: invalid JSON metadata", p)
	}
	return response.Header, nil
}

// Runs lists a bounded window of completed runs, including failed publications.
func (r ProvenanceReader) Runs(ctx context.Context, limit int) ([]provenance.Run, bool, error) {
	var response struct {
		Total int `json:"total_count"`
		Runs  []struct {
			ID         int64  `json:"id"`
			URL        string `json:"html_url"`
			SHA        string `json:"head_sha"`
			Path       string `json:"path"`
			Branch     string `json:"head_branch"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"head_repository"`
		} `json:"workflow_runs"`
	}
	if limit < 1 || limit > 100 {
		return nil, false, errors.New("run limit must be between 1 and 100")
	}
	header, err := r.read(ctx, fmt.Sprintf("/actions/runs?status=completed&per_page=%d", limit), &response)
	if err != nil {
		return nil, false, err
	}
	var runs []provenance.Run
	partial := response.Total > len(response.Runs) || strings.Contains(header.Get("Link"), `rel="next"`)
	for _, run := range response.Runs {
		p, _, _ := strings.Cut(run.Path, "@")
		if !strings.EqualFold(run.Repository.FullName, r.Target.Owner+"/"+r.Target.Name) || !provenance.WorkflowPath(p) {
			partial = true
			continue
		}
		runs = append(runs, provenance.Run{ID: run.ID, URL: run.URL, SHA: run.SHA, Path: p, RefName: run.Branch})
	}
	return runs, partial, nil
}

// File reads only an immutable repository revision, never an arbitrary download URL.
func (r ProvenanceReader) File(ctx context.Context, file, sha string) ([]byte, error) {
	if sha == "" || file == "" || strings.HasPrefix(file, "/") ||
		strings.Contains(file, "..") || strings.ContainsAny(file, "\\\x00\r\n") {
		return nil, errors.New("invalid source file identity")
	}
	var response struct {
		Encoding, Content string
		Size              int
		Type              string
	}
	_, err := r.read(ctx, "/contents/"+url.PathEscape(file)+"?ref="+url.QueryEscape(sha), &response)
	if err != nil {
		return nil, err
	}
	if response.Type != "file" || response.Encoding != "base64" || response.Size > 1<<20 {
		return nil, errors.New("source file is unsupported or exceeds 1 MiB")
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("invalid source file encoding or size")
	}
	return data, nil
}

// Executions reads job and step conclusions without downloading logs.
func (r ProvenanceReader) Executions(ctx context.Context, id int64) ([]provenance.Execution, bool, error) {
	var response struct {
		Total int `json:"total_count"`
		Jobs  []struct {
			Name  string
			Steps []struct{ Name, Conclusion string }
		}
	}
	header, err := r.read(ctx, fmt.Sprintf("/actions/runs/%d/jobs?filter=latest&per_page=100", id), &response)
	if err != nil {
		return nil, false, err
	}
	var executions []provenance.Execution
	for _, job := range response.Jobs {
		for _, step := range job.Steps {
			executions = append(executions, provenance.Execution{Job: job.Name, Step: step.Name, Conclusion: step.Conclusion})
		}
	}
	return executions, response.Total > len(response.Jobs) || strings.Contains(header.Get("Link"), `rel="next"`), nil
}

// Attestations returns inline bundles or bounded anonymous GitHub blob bundles.
// Only a successful explicit empty array establishes absence; a 404 is unknown.
func (r ProvenanceReader) Attestations(ctx context.Context, digest string) ([][]byte, bool, error) {
	if !provenance.ValidDigest(digest) {
		return nil, false, errors.New("invalid attestation subject digest")
	}
	var response struct {
		Attestations *[]struct {
			Bundle json.RawMessage `json:"bundle"`
			URL    string          `json:"bundle_url"`
		} `json:"attestations"`
	}
	header, err := r.read(ctx, "/attestations/"+url.PathEscape(digest)+"?per_page=100&predicate_type=provenance", &response)
	if err != nil {
		return nil, false, err
	}
	if response.Attestations == nil {
		return nil, false, errors.New("attestation collection is absent or malformed")
	}
	var bundles [][]byte
	for _, item := range *response.Attestations {
		if len(item.Bundle) == 0 || string(item.Bundle) == "null" {
			data, err := fetchBundle(ctx, item.URL)
			if err != nil {
				return nil, false, err
			}
			bundles = append(bundles, data)
			continue
		}
		bundles = append(bundles, item.Bundle)
	}
	return bundles, strings.Contains(header.Get("Link"), `rel="next"`), nil
}

func fetchBundle(ctx context.Context, address string) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		!(strings.HasSuffix(u.Hostname(), ".blob.core.windows.net") || u.Hostname() == "artifactattestations.githubusercontent.com") {
		return nil, errors.New("unsupported attestation bundle storage origin")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("invalid attestation bundle request")
	}
	// Deliberately separate from authenticated GitHub transports.
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("attestation bundle download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation bundle storage returned HTTP %d", response.StatusCode)
	}
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(data) > limit {
		return nil, errors.New("attestation bundle download failed or exceeded 8 MiB")
	}
	size, err := snappy.DecodedLen(data)
	if err != nil || size > limit {
		return nil, errors.New("invalid or oversized compressed attestation bundle")
	}
	return snappy.Decode(nil, data)
}

package provenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Reader supplies bounded, authenticated read-only GitHub data.
type Reader interface {
	Runs(context.Context, int) ([]Run, bool, error)
	File(context.Context, string, string) ([]byte, error)
	Executions(context.Context, int64) ([]Execution, bool, error)
	Attestations(context.Context, string) ([][]byte, bool, error)
}

// Verifier checks signatures, timestamps, digest, and authenticated producer identity.
type Verifier interface {
	Verify(context.Context, []byte, Candidate, string) error
}

// InspectOptions bounds history and network work for one invocation.
type InspectOptions struct {
	RunLimit int
}

// Inspect resolves publication candidates and evaluates GitHub-hosted provenance.
// Registry lookup and matching a YAML action alone cannot establish provenance.
func Inspect(ctx context.Context, repo string, reader Reader, resolver Resolver, verifier Verifier, options InspectOptions) (Report, error) {
	var report Report
	runs, truncated, runErr := reader.Runs(ctx, options.RunLimit)
	if runErr != nil {
		return report, fmt.Errorf("list Actions runs: %w", runErr)
	}
	report.Runs = len(runs)
	candidateCount := 0
	if truncated {
		report.Gaps = append(report.Gaps, "Actions run history is truncated by --run-limit")
	}
	for _, run := range runs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		candidates, gaps := discoverRun(ctx, repo, reader, run)
		report.Gaps = append(report.Gaps, gaps...)
		for _, candidate := range candidates {
			candidateCount++
			if candidateCount > 200 || len(report.Findings) >= 200 {
				report.Gaps = append(report.Gaps, "publication candidate limit (200) reached")
				return report, nil
			}
			findings := inspectCandidate(ctx, repo, reader, resolver, verifier, candidate)
			if len(findings) > 200-len(report.Findings) {
				findings = findings[:200-len(report.Findings)]
				report.Gaps = append(report.Gaps, "resolved distribution limit (200) reached")
			}
			report.Findings = append(report.Findings, findings...)
		}
	}
	if len(report.Findings) == 0 {
		report.Gaps = append(report.Gaps, "no distributed outputs identified in the inspected window; this is not proof that none are published")
	}
	return report, ctx.Err()
}

func discoverRun(ctx context.Context, repo string, reader Reader, run Run) ([]Candidate, []string) {
	run.Repo = repo
	data, err := reader.File(ctx, run.Path, run.SHA)
	if err != nil {
		return nil, []string{fmt.Sprintf("run %d: cannot read workflow revision: %s", run.ID, err)}
	}
	executions, partial, executionErr := reader.Executions(ctx, run.ID)
	incompleteExecution := executionErr != nil || partial
	var gaps []string
	if incompleteExecution {
		gaps = append(gaps, fmt.Sprintf("run %d: job/step evidence unavailable or truncated", run.ID))
	}
	candidates, workflowGaps, err := ScanWorkflow(ctx, data, run, executions, func(ctx context.Context, file string) ([]byte, error) {
		return reader.File(ctx, file, run.SHA)
	})
	if err != nil {
		return nil, append(gaps, fmt.Sprintf("run %d: %s", run.ID, err))
	}
	if incompleteExecution {
		for i := range candidates {
			candidates[i].Problem = joinProblem(candidates[i].Problem, "incomplete job evidence")
		}
	}
	return candidates, append(gaps, workflowGaps...)
}

func inspectCandidate(ctx context.Context, repo string, reader Reader, resolver Resolver, verifier Verifier, candidate Candidate) []Finding {
	if candidate.Kind == "unsupported" || candidate.Kind == "release" {
		return []Finding{{Artifact: candidate, State: Unsupported, Detail: candidate.Problem}}
	}
	if candidate.Name == "" || candidate.Version == "" && candidate.Digest == "" {
		return []Finding{{Artifact: candidate, State: Unknown, Detail: joinProblem(candidate.Problem, "publication identity is unresolved")}}
	}
	resolved, err := resolver.Resolve(ctx, candidate)
	if err != nil {
		return []Finding{{Artifact: candidate, State: Unknown, Detail: fmt.Sprintf("registry lookup incomplete: %s", err)}}
	}
	if len(resolved) == 0 {
		return []Finding{{Artifact: candidate, State: Unknown, Detail: "registry returned no immutable distribution identities"}}
	}
	var findings []Finding
	for _, artifact := range resolved {
		finding := Finding{Artifact: artifact, State: Unknown}
		if err := ValidateIdentity(artifact); err != nil {
			finding.Detail = err.Error()
		} else {
			finding.State, finding.Detail = assess(ctx, repo, reader, verifier, artifact)
		}
		findings = append(findings, finding)
	}
	return findings
}

func assess(ctx context.Context, repo string, reader Reader, verifier Verifier, artifact Candidate) (State, string) {
	bundles, truncated, err := reader.Attestations(ctx, artifact.Digest)
	if err != nil {
		return Unknown, fmt.Sprintf("GitHub provenance lookup failed: %s", err)
	}
	for _, bundle := range bundles {
		if err := ctx.Err(); err != nil {
			return Unknown, "verification interrupted"
		}
		if verifier.Verify(ctx, bundle, artifact, repo) == nil {
			return Verified, "SLSA provenance signature, subject digest, and authenticated workflow/source/run identity verified"
		}
	}
	if len(bundles) > 0 {
		return Unknown, "bundles found but none verified for this artifact and producer; inspect signatures, predicate, digest, and authenticated workflow identity"
	}
	if truncated {
		return Unknown, "GitHub provenance lookup was truncated"
	}
	if artifact.Problem != "" {
		return Unknown, joinProblem(artifact.Problem, "no GitHub-hosted provenance found; publisher association remains unproven")
	}
	return Missing, "complete GitHub lookup found no GitHub-hosted build provenance for this digest; registry-native attestations are outside this assessment"
}

// Render prints evidence and limitations without implying that unknown means safe.
func Render(report Report) string {
	var text strings.Builder
	fmt.Fprintf(&text, "Provenance coverage: %d completed runs; at most 200 publication candidates. Releases: gh create/upload detection only, no release asset inspection.\n", report.Runs)
	text.WriteString("Scope: GitHub-hosted SLSA build provenance; registry-native attestations may require separate verification.\n")
	for _, finding := range report.Findings {
		a := finding.Artifact
		fmt.Fprintf(&text, "\n[%s] %s %s %s\n", finding.State, a.Kind, a.Name, a.Version)
		if a.Digest != "" {
			fmt.Fprintf(&text, "  Digest: %s\n", a.Digest)
		}
		fmt.Fprintf(&text, "  Workflow: %s, job: %s, source: %s\n", a.Workflow, a.Job, a.SHA)
		if a.RunURL != "" {
			fmt.Fprintf(&text, "  Run: %s\n", a.RunURL)
		}
		if a.URL != "" {
			fmt.Fprintf(&text, "  Distribution: %s\n", a.URL)
		}
		fmt.Fprintf(&text, "  Evidence: %s\n  Assessment: %s\n", a.Evidence, finding.Detail)
		text.WriteString("  Guidance: attest the exact distributed bytes or OCI manifest digest in the producing build job; see https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations\n")
	}
	for _, gap := range report.Gaps {
		fmt.Fprintf(&text, "\nCoverage gap: %s\n", gap)
	}
	return text.String()
}

// ErrAssistanceUnavailable signals that inspection can still be used independently.
var ErrAssistanceUnavailable = errors.New("local assistance is unavailable; inspection remains usable")

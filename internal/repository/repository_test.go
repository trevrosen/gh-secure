package repository

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ghrepository "github.com/cli/go-gh/v2/pkg/repository"
)

func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	t.Setenv("GH_HOST", "github.com")
	t.Setenv("GH_REPO", "")
}

// TestResolveExplicit checks strict names, selected hosts, and discovery bypass.
func TestResolveExplicit(t *testing.T) {
	isolateConfig(t)
	t.Setenv("GH_HOST", "github.example.com")
	resolver := NewResolver(func(context.Context) (string, error) {
		t.Fatal("explicit target prompted")
		return "", nil
	})
	resolver.current = func() (ghrepository.Repository, error) {
		t.Fatal("explicit target triggered discovery")
		return ghrepository.Repository{}, nil
	}
	got, err := resolver.Resolve(context.Background(), "owner/repo")
	if err != nil || got != (Target{"github.example.com", "owner", "repo"}) {
		t.Fatalf("target=%v err=%v", got, err)
	}
	if got.WebURL() != "https://github.example.com/owner/repo" {
		t.Fatalf("incorrect web URL: %s", got.WebURL())
	}
	for _, name := range []string{"repo", "host/owner/repo", "owner/", "owner/../repo", "owner/repo?query"} {
		if _, err := resolver.Resolve(context.Background(), name); err == nil {
			t.Errorf("accepted malformed target %q", name)
		}
	}
}

// TestResolveGHRepo checks the library's environment override without invoking git.
func TestResolveGHRepo(t *testing.T) {
	isolateConfig(t)
	t.Setenv("GH_REPO", "github.example.com/team/project")
	t.Setenv("PATH", "")
	got, err := NewResolver(nil).Resolve(context.Background(), "")
	if err != nil || got != (Target{"github.example.com", "team", "project"}) {
		t.Fatalf("target=%v err=%v", got, err)
	}
}

// TestResolveCurrentRemote exercises library discovery using an offline git fixture.
func TestResolveCurrentRemote(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[core]\nrepositoryformatversion = 0\nbare = false\n[remote \"origin\"]\nurl = https://github.com/team/project.git\n"
	for path, content := range map[string]string{
		"config": config, "HEAD": "ref: refs/heads/main\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, ".git", path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"objects", "refs"} {
		if err := os.Mkdir(filepath.Join(dir, ".git", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	got, err := NewResolver(nil).Resolve(context.Background(), "")
	if err != nil || got != (Target{"github.com", "team", "project"}) {
		t.Fatalf("target=%v err=%v", got, err)
	}
}

// TestResolveFallback checks discovery failures, prompt errors, and cancellation.
func TestResolveFallback(t *testing.T) {
	isolateConfig(t)
	tests := []struct {
		name   string
		prompt func(context.Context) (string, error)
		want   string
	}{
		{"input", func(context.Context) (string, error) { return "owner/repo", nil }, ""},
		{"disabled", nil, "specify --repo"},
		{"EOF", func(context.Context) (string, error) { return "", io.EOF }, "EOF"},
		{"invalid", func(context.Context) (string, error) { return "owner/", nil }, "owner/repo format"},
		{"bad host form", func(context.Context) (string, error) { return "host/owner/repo", nil }, "owner/repo format"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := NewResolver(test.prompt)
			resolver.current = func() (ghrepository.Repository, error) {
				return ghrepository.Repository{}, errors.New("no remote")
			}
			got, err := resolver.Resolve(context.Background(), "")
			if test.want == "" {
				if err != nil || got.Name != "repo" {
					t.Fatalf("target=%v err=%v", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v; want %q", err, test.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewResolver(nil).Resolve(ctx, "owner/repo"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// TestResolveRejectsMalformedDiscoveredHost prevents invalid API and link targets.
func TestResolveRejectsMalformedDiscoveredHost(t *testing.T) {
	for _, host := range []string{"", "https://github.com", "github.com/path", "user@github.com", "github.com:443"} {
		resolver := NewResolver(nil)
		resolver.current = func() (ghrepository.Repository, error) {
			return ghrepository.Repository{Host: host, Owner: "owner", Name: "repo"}, nil
		}
		if _, err := resolver.Resolve(context.Background(), ""); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
}

package ui

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSystemStreamsDoNotInferInputCapabilityFromForcedOutput checks prompt capability
// independently of forced terminal rendering.
func TestSystemStreamsDoNotInferInputCapabilityFromForcedOutput(t *testing.T) {
	t.Setenv("GH_FORCE_TTY", "120")
	if os.Getenv("GH_SECURE_TEST_STREAMS_SUBPROCESS") == "1" {
		streams := SystemStreams()
		if streams.In != os.Stdin || streams.Out != os.Stdout || streams.ErrOut != os.Stderr {
			t.Fatal("system streams do not use standard process streams")
		}
		if streams.CanPrompt {
			t.Fatal("forced terminal output enabled prompting with piped input")
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestSystemStreamsDoNotInferInputCapabilityFromForcedOutput$")
	command.Env = append(os.Environ(), "GH_SECURE_TEST_STREAMS_SUBPROCESS=1")
	command.Stdin = strings.NewReader("owner/repo\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("system streams subprocess failed: %v\n%s", err, output)
	}
}

package ui

import (
	"os"
	"testing"

	"github.com/cli/go-gh/v2/pkg/term"
)

// TestSystemStreamsDoNotInferInputCapabilityFromForcedOutput checks prompt capability
// independently of forced terminal rendering.
func TestSystemStreamsDoNotInferInputCapabilityFromForcedOutput(t *testing.T) {
	t.Setenv("GH_FORCE_TTY", "120")
	streams := SystemStreams()
	if streams.In != os.Stdin || streams.Out != os.Stdout || streams.ErrOut != os.Stderr {
		t.Fatal("system streams do not use standard process streams")
	}
	if streams.CanPrompt != term.IsTerminal(os.Stdin) {
		t.Fatal("forced terminal output must not determine prompt input capability")
	}
}

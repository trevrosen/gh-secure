// Package ui provides terminal streams and prompt capability for command interaction.
package ui

import (
	"io"
	"os"

	"github.com/cli/go-gh/v2/pkg/term"
)

// Streams separates command input, normal output, diagnostics, and prompt capability.
type Streams struct {
	// In supplies command input.
	In io.Reader
	// Out receives normal command output.
	Out io.Writer
	// ErrOut receives error diagnostics.
	ErrOut io.Writer
	// CanPrompt reports whether interactive input is available, independent of styling.
	CanPrompt bool
}

// SystemStreams uses the process's standard streams and GitHub CLI terminal conventions.
// Prompt capability depends on actual terminal input, not forced terminal output.
func SystemStreams() Streams {
	terminal := term.FromEnv()
	return Streams{
		In:        terminal.In(),
		Out:       terminal.Out(),
		ErrOut:    terminal.ErrOut(),
		CanPrompt: term.IsTerminal(os.Stdin),
	}
}

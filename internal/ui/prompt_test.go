package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestPromptRepository checks interactive input, EOF, and nonterminal safeguards.
func TestPromptRepository(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		canPrompt bool
		want      string
		wantErr   bool
	}{
		{"line", "owner/repo\n", true, "owner/repo", false},
		{"CRLF", "owner/repo\r\n", true, "owner/repo", false},
		{"EOF", "", true, "", true},
		{"unterminated", "owner/repo", true, "", true},
		{"nonterminal", "owner/repo\n", false, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			input := strings.NewReader(test.input)
			streams := Streams{In: input, Out: &out, ErrOut: &out, CanPrompt: test.canPrompt}
			got, err := streams.PromptRepository(context.Background())
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("answer=%q err=%v", got, err)
			}
			if !test.canPrompt && (out.Len() != 0 || input.Len() != len(test.input)) {
				t.Fatal("nonterminal prompt consumed input or produced a prompt")
			}
		})
	}
}

// TestPromptRepositoryCancellation checks interruption while awaiting terminal input.
func TestPromptRepositoryCancellation(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streams := Streams{In: input, ErrOut: &out, CanPrompt: true}
	started := make(chan struct{})
	streams.In = signalingReader{Reader: input, started: started}
	result := make(chan error, 1)
	go func() {
		_, err := streams.PromptRepository(ctx)
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

type signalingReader struct {
	// Reader supplies blocking input for cancellation tests.
	io.Reader
	started chan struct{}
}

// Read signals that a prompt has begun reading before delegating to its input.
func (r signalingReader) Read(buffer []byte) (int, error) {
	close(r.started)
	return r.Reader.Read(buffer)
}

package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waitContext, stopWaiting := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopWaiting()
	streams := Streams{In: input, ErrOut: &out, CanPrompt: true}
	started := make(chan struct{})
	streams.In = &signalingReader{Reader: input, started: started}
	result := make(chan error, 1)
	go func() {
		_, err := streams.PromptRepository(ctx)
		result <- err
	}()
	select {
	case <-started:
	case err := <-result:
		t.Fatalf("prompt returned before reading input: %v", err)
	case <-waitContext.Done():
		t.Fatal("timed out waiting for prompt to read input")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-waitContext.Done():
		t.Fatal("prompt did not return after cancellation")
	}
}

type signalingReader struct {
	// Reader supplies blocking input for cancellation tests.
	io.Reader
	started chan struct{}
	once    sync.Once
}

// Read signals once that a prompt has begun reading, then delegates to its input.
func (r *signalingReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.Reader.Read(buffer)
}

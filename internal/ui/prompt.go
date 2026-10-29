package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

var errRepositoryUnavailable = errors.New("terminal input is unavailable; specify --repo owner/repo")

// PromptRepository reads a repository name only when interactive input is available.
// EOF and cancellation are errors, including EOF after an unterminated answer.
func (s Streams) PromptRepository(ctx context.Context) (string, error) {
	if err := s.requireTerminal(ctx, errRepositoryUnavailable); err != nil {
		return "", err
	}
	answer, err := s.ask(ctx, "Enter repository (owner/repo): ")
	if err != nil {
		return "", fmt.Errorf("read repository input: %w", err)
	}
	return answer, nil
}

// requireTerminal reports cancellation first, then unavailable when input is not a terminal.
func (s Streams) requireTerminal(ctx context.Context, unavailable error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.CanPrompt {
		return unavailable
	}
	return nil
}

// ask writes question to ErrOut and reads one answer line from In.
func (s Streams) ask(ctx context.Context, question string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(s.ErrOut, question); err != nil {
		return "", fmt.Errorf("write prompt: %w", err)
	}
	type answer struct {
		text string
		err  error
	}
	result := make(chan answer, 1)
	go func() {
		text, err := readLine(s.In)
		result <- answer{text: text, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-result:
		if value.err != nil {
			return "", value.err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return value.text, nil
	}
}

// readLine reads one newline-terminated line without buffering past it, so
// consecutive prompts sharing one input never lose answers. CRLF is accepted.
// EOF before the newline is an error, even after partial input.
func readLine(input io.Reader) (string, error) {
	var line strings.Builder
	buffer := make([]byte, 1)
	for {
		count, err := input.Read(buffer)
		if count == 1 {
			if buffer[0] == '\n' {
				return strings.TrimSuffix(line.String(), "\r"), nil
			}
			line.WriteByte(buffer[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("input ended before an answer: %w", err)
			}
			return "", err
		}
	}
}

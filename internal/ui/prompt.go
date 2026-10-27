package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
)

// PromptRepository reads a repository name only when interactive input is available.
// EOF and cancellation are errors, including EOF after an unterminated answer.
func (s Streams) PromptRepository(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !s.CanPrompt {
		return "", errors.New("terminal input is unavailable; specify --repo owner/repo")
	}
	if _, err := fmt.Fprint(s.ErrOut, "Enter repository (owner/repo): "); err != nil {
		return "", fmt.Errorf("write repository prompt: %w", err)
	}
	type answer struct {
		text string
		err  error
	}
	result := make(chan answer, 1)
	go func() {
		text, err := bufio.NewReader(s.In).ReadString('\n')
		result <- answer{text: text, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-result:
		if value.err != nil {
			return "", fmt.Errorf("read repository input: %w", value.err)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return strings.TrimSuffix(strings.TrimSuffix(value.text, "\n"), "\r"), nil
	}
}

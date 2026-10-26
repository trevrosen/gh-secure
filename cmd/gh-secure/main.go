package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/GitHubSecurityLab/gh-secure/internal/cmd"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return cmd.Execute(ctx, os.Args[1:], version, ui.SystemStreams(), cmd.Dependencies{})
}

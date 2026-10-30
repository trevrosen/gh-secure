#!/bin/sh
set -eu

cd "$(git rev-parse --show-toplevel)"
if [ ! -x .githooks/pre-push ]; then
    echo "hooks: .githooks/pre-push must be executable before installation." >&2
    exit 1
fi

if configured=$(git config --get core.hooksPath); then
    if [ "$configured" != ".githooks" ]; then
        echo "hooks: refusing to replace core.hooksPath=$configured; integrate .githooks/pre-push manually." >&2
        exit 1
    fi
    echo "hooks: repository hooks already configured via core.hooksPath=.githooks"
    exit 0
else
    status=$?
    if [ "$status" -ne 1 ]; then
        exit "$status"
    fi
fi

hooks_dir=$(git rev-parse --git-path hooks)
for hook in "$hooks_dir"/*; do
    case "$hook" in
        *.sample) continue ;;
    esac
    if [ -f "$hook" ] && [ -x "$hook" ]; then
        echo "hooks: refusing to hide existing hook $hook; integrate .githooks/pre-push manually." >&2
        exit 1
    fi
done

git config --local core.hooksPath .githooks
echo "hooks: installed repository hooks via core.hooksPath=.githooks"

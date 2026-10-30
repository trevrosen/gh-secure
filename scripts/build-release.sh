#!/usr/bin/env bash
set -euo pipefail

release_tag="${1:?release tag is required}"
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  printf 'invalid release tag: %s\n' "$release_tag" >&2
  exit 2
fi

mkdir -p dist

for target in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64 windows-arm64; do
  goos="${target%-*}"
  goarch="${target#*-}"
  extension=""
  if [[ "$goos" == windows ]]; then
    extension=".exe"
  fi

  output="dist/gh-secure_${release_tag}_${target}${extension}"
  rm -f "$output"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w -X main.version=${release_tag}" \
    -o "$output" \
    ./cmd/gh-secure
done

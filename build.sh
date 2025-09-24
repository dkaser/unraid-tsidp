#!/usr/bin/env bash
set -euo pipefail

mkdir -p ./src/usr/local/sbin
cd tsidp

# Build static linux/amd64 binary
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../src/usr/local/sbin/tsidp

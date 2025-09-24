#!/usr/bin/env bash
set -euo pipefail

# Build static linux/amd64 binary
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o tsidp

mkdir -p ../src/usr/local/sbin
cp tsidp ../src/usr/local/sbin/
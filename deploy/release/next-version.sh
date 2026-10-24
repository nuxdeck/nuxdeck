#!/usr/bin/env bash
# Prints the next pre-release tag, v0.1.0-alpha.N, one above the highest existing N.
# Pre-v0.1.0 only: once v0.1.0 exists the scheme must be extended deliberately.
set -euo pipefail

if git rev-parse -q --verify refs/tags/v0.1.0 >/dev/null; then
  echo "v0.1.0 already exists; extend next-version.sh before releasing again" >&2
  exit 1
fi

last=$(git tag --list 'v0.1.0-alpha.*' | sed 's/^v0\.1\.0-alpha\.//' | grep -E '^[0-9]+$' | sort -n | tail -n1 || true)
echo "v0.1.0-alpha.$((${last:-0} + 1))"

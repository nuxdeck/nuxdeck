#!/usr/bin/env bash
# Succeeds only when both cmd/nuxd and cmd/nux are buildable main packages.
# Lets the release gates stay green until NUX-5 and NUX-6 add the entry points.
set -euo pipefail

for cmd in nuxd nux; do
  [ "$(go list -f '{{.Name}}' "./cmd/${cmd}" 2>/dev/null || true)" = main ] || exit 1
done

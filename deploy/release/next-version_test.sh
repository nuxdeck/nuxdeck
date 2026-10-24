#!/usr/bin/env bash
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q .
git -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m init

check() {
  local want=$1 got
  got=$("$script")
  [ "$got" = "$want" ] || { echo "FAIL: want $want, got $got" >&2; exit 1; }
}

check v0.1.0-alpha.1
git tag v0.1.0-alpha.1
git tag v0.1.0-alpha.9
check v0.1.0-alpha.10
git tag v0.1.0-alpha.10
git tag v0.0.9 # unrelated tags are ignored
check v0.1.0-alpha.11
git tag v0.1.0
if "$script" 2>/dev/null; then echo "FAIL: expected error once v0.1.0 exists" >&2; exit 1; fi
echo ok

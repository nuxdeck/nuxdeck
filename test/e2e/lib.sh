#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the e2e scripts. Sourced, not run.

e2e_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$e2e_dir/../.." && pwd)"
stack_dir="$e2e_dir/.stack"
compose_file="$e2e_dir/compose.yaml"

die() {
	echo "e2e: $*" >&2
	exit 1
}

# compose runs Docker Compose against the recorded project only. Every e2e command goes through
# it, so no call can address a container outside the stack.
compose() {
	docker compose --env-file "$stack_dir/compose.env" -p "$(cat "$stack_dir/project")" -f "$compose_file" "$@"
}

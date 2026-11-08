#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Removes the e2e stack recorded in test/e2e/.stack: its containers, networks, volumes and the
# images it built. Only the recorded project is touched. make e2e-down and the make e2e trap run it.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ ! -e "$stack_dir/project" ]; then
	echo "e2e: no stack recorded in $stack_dir; nothing to tear down"
	exit 0
fi

status=0
compose --profile '*' down --volumes --remove-orphans --rmi local --timeout 10 || status=$?
if [ "$status" -ne 0 ]; then
	echo "e2e: teardown of $(cat "$stack_dir/project") failed (exit $status); remove it with docker compose -p $(cat "$stack_dir/project") down -v" >&2
	exit "$status"
fi
rm -rf "$stack_dir"
echo "e2e: stack removed"

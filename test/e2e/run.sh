#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# make e2e: brings the stack up, runs the Go scenarios, then the Playwright suite when it exists,
# and always tears the stack down. Exits non-zero if any part failed.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cleanup() {
	bash "$e2e_dir/stack-down.sh"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

bash "$e2e_dir/stack-up.sh" || exit 1
set -a
# shellcheck source=/dev/null
source "$stack_dir/env"
set +a

failed=0

(cd "$repo_dir" && go test -tags e2e -count=1 -timeout 30m -v ./test/e2e/) || failed=1

if [ -f "$e2e_dir/ui/package.json" ]; then
	(cd "$e2e_dir/ui" && npm ci && npx playwright test) || failed=1
else
	echo "e2e: test/e2e/ui/package.json not found; skipping the Playwright suite"
fi

if [ "$failed" -ne 0 ]; then
	echo "e2e: FAILED" >&2
	exit 1
fi
echo "e2e: all parts passed"

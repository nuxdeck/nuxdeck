#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the e2e images and starts the stack under a fresh project name, then writes
# test/e2e/.stack/env for the Go tests and the Playwright suite. make e2e-up runs it.
# Teardown is stack-down.sh; make e2e always runs both.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v docker >/dev/null || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
[ -S /var/run/docker.sock ] || die "/var/run/docker.sock is missing; the agents' sockguard sidecars need it"

if [ -e "$stack_dir/project" ]; then
	die "a stack is already recorded in $stack_dir (project $(cat "$stack_dir/project")); run make e2e-down first"
fi

# pick_port prints the given port, or the next free one when it is taken on 127.0.0.1.
pick_port() {
	local port="$1"
	while (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do
		port=$((port + 1))
	done
	echo "$port"
}

rand_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
rand_secret() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }

project="nux-e2e-$(rand_hex 4)"
mkdir -p "$stack_dir/bin" "$stack_dir/backup"
chmod 0777 "$stack_dir/backup" # the backup container writes here as uid 65532
printf '%s' "$project" >"$stack_dir/project"

# Compiled on the host: the images need no network, and the binaries match this checkout.
goarch="$(go env GOARCH)"
(cd "$repo_dir" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$stack_dir/bin/nuxd" ./cmd/nuxd &&
	CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$stack_dir/bin/nux" ./cmd/nux)

# The defaults are 18443 and up, but another nuxd may already hold them, so each port is the
# first free one from its default (an explicit E2E_*_PORT is the starting point).
https_port="$(pick_port "${E2E_HTTPS_PORT:-18443}")"
gateway_port="$(pick_port "${E2E_GATEWAY_PORT:-$((https_port + 1))}")"
restore_port="$(pick_port "${E2E_RESTORE_PORT:-$((gateway_port + 1))}")"
docker_gid="$(stat -c %g /var/run/docker.sock)"

admin_email="e2e-admin@nuxdeck.test"
admin_password="$(rand_secret 24)"
printf '%s' "$(rand_secret 24)" >"$stack_dir/backup-passphrase"

cat >"$stack_dir/compose.env" <<ENV
E2E_PROJECT=$project
E2E_DOCKER_GID=$docker_gid
E2E_HTTPS_PORT=$https_port
E2E_GATEWAY_PORT=$gateway_port
E2E_RESTORE_PORT=$restore_port
ENV

compose --profile '*' build
compose up -d --wait nuxd nginx sockguard-a sockguard-b
compose up -d failing

# nuxd writes its certificate on first start; the browser and the Go tests trust that file.
compose cp nuxd:/var/lib/nuxd/tls/server.crt "$stack_dir/ca.pem"

cat >"$stack_dir/env" <<ENV
E2E_PROJECT='$project'
E2E_COMPOSE_FILE='$compose_file'
E2E_STACK_DIR='$stack_dir'
E2E_BASE_URL='https://localhost:$https_port'
E2E_RESTORE_URL='https://localhost:$restore_port'
E2E_ADMIN_EMAIL='$admin_email'
E2E_ADMIN_PASSWORD='$admin_password'
E2E_CA_PEM='$stack_dir/ca.pem'
ENV
# The backup container runs as uid 65532 and reads the passphrase through a bind mount, so the
# file must be readable by that user. It is per-run, git-ignored and deleted by stack-down.sh.
chmod 0600 "$stack_dir/env" "$stack_dir/compose.env"
chmod 0644 "$stack_dir/backup-passphrase"
echo "e2e: stack $project is up at https://localhost:$https_port (env in $stack_dir/env)"

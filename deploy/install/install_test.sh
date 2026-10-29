#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests install.sh against a fake release served from loopback, with a fake
# cosign that records how it was called. No network, root or systemd needed.
# The check helper eval's single-quoted expressions on purpose, so they expand inside the helper.
# shellcheck disable=SC2016
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/install.sh"

case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*)
	echo "skipping: unsupported test host architecture $(uname -m)"
	exit 0
	;;
esac

work="$(mktemp -d)"
server_pid=""
cleanup() {
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { printf '  ok   %s\n' "$1"; }
fail() {
	printf '  FAIL %s\n' "$1"
	failures=$((failures + 1))
}
check() { # check DESCRIPTION CONDITION...
	local desc="$1"
	shift
	if "$@"; then pass "$desc"; else fail "$desc"; fi
}

tag="v0.1.0-alpha.1"
ver="${tag#v}"
archive="nuxd_${ver}_linux_${arch}.tar.gz"
agent_archive="nux_${ver}_linux_${arch}.tar.gz"
site="$work/site"
dest="$work/dest"

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

make_release() { # make_release [binary content]
	local content="${1:-#!/bin/sh\necho nuxd v1}" rel="$site/$tag" build="$work/build"
	rm -rf "$site" "$build"
	mkdir -p "$rel" "$build" "$site/cosign"
	printf '%b\n' "$content" >"$build/nuxd"
	chmod 0755 "$build/nuxd"
	printf '[Service]\nExecStart=/usr/local/bin/nuxd\n' >"$build/nuxd.service"
	tar -czf "$rel/$archive" -C "$build" nuxd nuxd.service
	printf '#!/bin/sh\necho nux agent\n' >"$build/nux"
	chmod 0755 "$build/nux"
	printf '[Service]\nExecStart=/usr/local/bin/nux agent run\n' >"$build/nux-agent.service"
	printf '[Service]\nExecStart=/usr/local/bin/nux sockguard\n' >"$build/nux-sockguard.service"
	tar -czf "$rel/$agent_archive" -C "$build" nux nux-agent.service nux-sockguard.service
	(cd "$rel" && sha256sum "$archive" "$agent_archive" >checksums.txt)
	echo '{"mediaType":"fake-bundle"}' >"$rel/checksums.txt.sigstore.json"
	printf '[{"tag_name": "%s", "prerelease": true}]\n' "$tag" >"$site/releases"
}

cat >"$work/fake-cosign" <<'COSIGN'
#!/bin/sh
echo "$@" >"$FAKE_COSIGN_ARGS"
exit "${FAKE_COSIGN_EXIT:-0}"
COSIGN
chmod +x "$work/fake-cosign"
export FAKE_COSIGN_ARGS="$work/cosign.args"

# A fake runuser records how the agent was enrolled: its arguments and exactly what arrived on stdin.
cat >"$work/fake-runuser" <<'RUNUSER'
#!/bin/sh
echo "$@" >"$FAKE_RUNUSER_ARGS"
cat >"$FAKE_RUNUSER_STDIN"
exit "${FAKE_RUNUSER_EXIT:-0}"
RUNUSER
chmod +x "$work/fake-runuser"
export FAKE_RUNUSER_ARGS="$work/runuser.args" FAKE_RUNUSER_STDIN="$work/runuser.stdin"

make_release
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$site" >/dev/null 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
	curl -sf "http://127.0.0.1:$port/releases" -o /dev/null && break
	sleep 0.1
done

# run_install ARGS... sets $out and $rc.
run_install() {
	rm -f "$FAKE_COSIGN_ARGS" "$FAKE_RUNUSER_ARGS" "$FAKE_RUNUSER_STDIN"
	out="$(NUX_RUNUSER="$work/fake-runuser" NUX_DESTDIR="$dest" NUX_ALLOW_HTTP=1 NUX_API_URL="http://127.0.0.1:$port" NUX_DOWNLOAD_URL="http://127.0.0.1:$port" \
		NUX_COSIGN_URL="http://127.0.0.1:$port/cosign" sh "$script" "$@" 2>&1)" && rc=0 || rc=$?
}
installed() { [ -e "$dest/usr/local/bin/nuxd" ]; }
fresh() { rm -rf "$dest"; }
contains() { [[ "$out" == *"$1"* ]]; }
# not COMMAND...: succeeds when the command fails, usable as a check command.
not() { ! "$@"; }
# matches TEXT PATTERN: shell-glob match, usable as a check command.
matches() {
	# shellcheck disable=SC2254 # the caller passes a glob on purpose
	case "$1" in
	$2) return 0 ;;
	esac
	return 1
}

echo "install.sh"

echo " happy path"
fresh
run_install --version "$tag" --cosign "$work/fake-cosign"
check "exits 0" [ "$rc" -eq 0 ]
check "installs the binary, executable" [ -x "$dest/usr/local/bin/nuxd" ]
check "installs the unit from the archive" grep -q 'ExecStart=/usr/local/bin/nuxd' "$dest/etc/systemd/system/nuxd.service"
check "binary is mode 755" [ "$(stat -c %a "$dest/usr/local/bin/nuxd")" = 755 ]
check "unit is mode 644" [ "$(stat -c %a "$dest/etc/systemd/system/nuxd.service")" = 644 ]
check "leaves no .new file behind" [ ! -e "$dest/usr/local/bin/nuxd.new" ]
args="$(cat "$FAKE_COSIGN_ARGS")"
check "verifies with cosign verify-blob" matches "$args" "verify-blob*"
check "verifies the checksums file against its bundle" matches "$args" "*checksums.txt --bundle*checksums.txt.sigstore.json*"
check "pins the release workflow identity" matches "$args" "*--certificate-identity https://github.com/nuxdeck/nuxdeck/.github/workflows/release.yml@refs/heads/main*"
check "pins the GitHub OIDC issuer" matches "$args" "*--certificate-oidc-issuer https://token.actions.githubusercontent.com*"
check "tells the operator how to get the setup token" contains "nuxd setup-token"

echo " newest release"
fresh
run_install --cosign "$work/fake-cosign"
check "resolves the newest tag from the releases list" contains "Installing Nux Deck $tag"
check "installs it" installed

echo " upgrade"
make_release '#!/bin/sh\necho nuxd v2'
run_install --version "$tag" --cosign "$work/fake-cosign"
check "replaces the binary" grep -q 'nuxd v2' "$dest/usr/local/bin/nuxd"
make_release

echo " refusals (nothing may be installed)"
fresh
FAKE_COSIGN_EXIT=1 run_install --version "$tag" --cosign "$work/fake-cosign"
check "a failing signature check aborts" [ "$rc" -ne 0 ]
check "and says so" contains "signature verification failed"
check "and installs nothing" [ ! -e "$dest" ] || [ ! -e "$dest/usr/local/bin/nuxd" ]

fresh
printf 'tampered' >>"$site/$tag/$archive"
run_install --version "$tag" --cosign "$work/fake-cosign"
check "a tampered archive aborts" [ "$rc" -ne 0 ]
check "with a checksum error" contains "checksum mismatch"
check "and installs nothing" [ ! -e "$dest/usr/local/bin/nuxd" ]
make_release

fresh
grep -v "$archive" "$site/$tag/checksums.txt" >"$work/empty-sums" || true
cp "$work/empty-sums" "$site/$tag/checksums.txt"
run_install --version "$tag" --cosign "$work/fake-cosign"
check "an archive missing from the signed checksums aborts" [ "$rc" -ne 0 ]
check "and installs nothing" [ ! -e "$dest/usr/local/bin/nuxd" ]
make_release

fresh
run_install --version v9.9.9 --cosign "$work/fake-cosign"
check "a missing release aborts with a download error" contains "download failed"

for bad in 'v1.0.0; touch /tmp/pwned' '../../etc' 'v1.0.0/../x' '1.0.0' 'v1.0' 'v1.0.0 extra' ''; do
	fresh
	run_install --version "$bad" --cosign "$work/fake-cosign"
	check "rejects version \"$bad\"" [ "$rc" -ne 0 ]
done
check "no injected command ran" [ ! -e /tmp/pwned ]

fresh
run_install --version "$tag" --cosign "$work/does-not-exist"
check "a missing cosign path aborts" contains "cosign not found"

echo " pinned cosign"
fresh
printf '#!/bin/sh\ntouch %s/cosign-ran\n' "$work" >"$site/cosign/cosign-linux-$arch"
run_install --version "$tag"
check "refuses a downloaded cosign with the wrong checksum" contains "pinned checksum"
check "and never runs it" [ ! -e "$work/cosign-ran" ]
check "and installs nothing" [ ! -e "$dest/usr/local/bin/nuxd" ]

echo " agent mode (--agent --token)"
token='nuxtok1.aHR0cHM6Ly9udXguZXhhbXBsZS5jb206ODQ0NA.8224ef67ccdc192ad6459f4fbf341ce2fcbe16decc79a0a11ccd402f13f392f4.nJRtSqRbn_lJDt8PiAvlqQEYlgVAa43fqyz7vR0QJf8'
fresh
run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$token"
check "exits 0" [ "$rc" -eq 0 ]
check "installs the nux binary, executable" [ -x "$dest/usr/local/bin/nux" ]
check "installs the agent unit from the archive" grep -q 'nux agent run' "$dest/etc/systemd/system/nux-agent.service"
check "installs the sockguard unit from the archive" grep -q 'nux sockguard' "$dest/etc/systemd/system/nux-sockguard.service"
check "units are mode 644" [ "$(stat -c %a "$dest/etc/systemd/system/nux-agent.service")" = 644 ]
check "does not install the server" [ ! -e "$dest/usr/local/bin/nuxd" ]
check "leaves no .new file behind" [ ! -e "$dest/usr/local/bin/nux.new" ]
check "verifies the agent archive through the same signed checksums" matches "$(cat "$FAKE_COSIGN_ARGS")" "verify-blob*checksums.txt --bundle*"
check "creates the state directory private to its owner" [ "$(stat -c %a "$dest/var/lib/nux-agent")" = 700 ]
check "enrols as the nux user with the token read from stdin" matches "$(cat "$FAKE_RUNUSER_ARGS")" "-u nux -- $dest/usr/local/bin/nux agent enroll --token-file - --state-dir $dest/var/lib/nux-agent"
check "the token arrives on stdin exactly" [ "$(cat "$FAKE_RUNUSER_STDIN")" = "$token" ]
check "the token is not in the enrolment arguments" not grep -q "nuxtok1" "$FAKE_RUNUSER_ARGS"
check "the token is never printed" not contains "nuxtok1"
check "says the agent is installed" contains "agent"

echo " agent mode: token from the environment"
fresh
out="$(NUX_ENROLL_TOKEN="$token" NUX_RUNUSER="$work/fake-runuser" NUX_DESTDIR="$dest" NUX_ALLOW_HTTP=1 NUX_API_URL="http://127.0.0.1:$port" NUX_DOWNLOAD_URL="http://127.0.0.1:$port" \
	sh "$script" --agent --version "$tag" --cosign "$work/fake-cosign" 2>&1)" && rc=0 || rc=$?
check "NUX_ENROLL_TOKEN is used when --token is absent" eval '[ "$rc" -eq 0 ] && [ "$(cat "$FAKE_RUNUSER_STDIN")" = "$token" ]'

echo " agent mode: refusals (nothing may be installed or enrolled)"
fresh
run_install --version "$tag" --cosign "$work/fake-cosign" --agent
check "no token and no identity aborts" [ "$rc" -ne 0 ]
check "and says how to get one" contains "Add host"
check "before anything was installed" [ ! -e "$dest/usr/local/bin/nux" ]

for bad in 'x' 'nuxtok1' 'nuxtok1.a b' 'nuxtok1.a;touch /tmp/pwned-agent' 'nuxtok1.$(touch /tmp/pwned-agent)' "nuxtok1.a'b" 'nuxtok1.a|b' 'nuxtok2.a.b.c' "nuxtok1.$(printf 'a%.0s' $(seq 1 1100))"; do
	fresh
	run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$bad"
	check "rejects token \"${bad:0:30}\"" [ "$rc" -ne 0 ]
	check "  installs nothing and enrols nobody" eval '[ ! -e "$dest/usr/local/bin/nux" ] && [ ! -e "$FAKE_RUNUSER_ARGS" ]'
done
check "no injected command ran" [ ! -e /tmp/pwned-agent ]

fresh
FAKE_COSIGN_EXIT=1 run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$token"
check "a failing signature check aborts the agent install" [ "$rc" -ne 0 ]
check "and installs and enrols nothing" eval '[ ! -e "$dest/usr/local/bin/nux" ] && [ ! -e "$FAKE_RUNUSER_ARGS" ]'

fresh
printf 'tampered' >>"$site/$tag/$agent_archive"
run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$token"
check "a tampered agent archive aborts" eval '[ "$rc" -ne 0 ] && contains "checksum mismatch"'
check "and enrols nobody" [ ! -e "$FAKE_RUNUSER_ARGS" ]
make_release

fresh
FAKE_RUNUSER_EXIT=1 run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$token"
check "a failed enrolment aborts" [ "$rc" -ne 0 ]
check "with an actionable message" contains "enrolment failed"
check "and does not claim success" not contains "is installed"

fresh
run_install --version "$tag" --cosign "$work/fake-cosign" --token "$token"
check "--token without --agent is refused" eval '[ "$rc" -ne 0 ] && contains "--token only makes sense with --agent"'

echo " agent mode: an enrolled host keeps its identity"
fresh
mkdir -p "$dest/var/lib/nux-agent"
echo '{}' >"$dest/var/lib/nux-agent/agent.json"
run_install --version "$tag" --cosign "$work/fake-cosign" --agent
check "re-running without a token upgrades the binary" eval '[ "$rc" -eq 0 ] && [ -x "$dest/usr/local/bin/nux" ]'
check "and does not enrol again" eval '[ ! -e "$FAKE_RUNUSER_ARGS" ] && contains "already enrolled"'
run_install --version "$tag" --cosign "$work/fake-cosign" --agent --token "$token"
check "a token given to an enrolled host is not used" eval '[ "$rc" -eq 0 ] && [ ! -e "$FAKE_RUNUSER_ARGS" ]'
check "the identity file is untouched" grep -q '{}' "$dest/var/lib/nux-agent/agent.json"

echo " environment"
fresh
mkdir -p "$work/fakebin"
# shellcheck disable=SC2016 # the fake script must expand its own arguments
printf '#!/bin/sh\nif [ "$1" = -m ]; then echo armv7l; else exec /usr/bin/uname "$@"; fi\n' >"$work/fakebin/uname"
chmod +x "$work/fakebin/uname"
out="$(PATH="$work/fakebin:$PATH" NUX_DESTDIR="$dest" sh "$script" --version "$tag" 2>&1)" && rc=0 || rc=$?
check "rejects an unsupported architecture" [ "$rc" -ne 0 ]
check "with a clear message" contains "unsupported architecture"

if [ "$(id -u)" -ne 0 ]; then
	out="$(sh "$script" --version "$tag" 2>&1)" && rc=0 || rc=$?
	check "refuses to run as a normal user" contains "run as root"
fi

out="$(sh "$script" --bogus 2>&1)" && rc=0 || rc=$?
check "rejects unknown options" [ "$rc" -ne 0 ]
out="$(sh "$script" --help 2>&1)" && rc=0 || rc=$?
check "--help exits 0 and shows usage" [ "$rc" -eq 0 ]
check "--help documents --version" contains "--version TAG"
check "--help documents --agent and --token" eval 'contains "--agent" && contains "--token TOKEN"'

echo
if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
echo "all install.sh checks passed"

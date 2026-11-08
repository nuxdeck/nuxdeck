#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Nux Deck installer: downloads a release, verifies its cosign signature and
# checksum, and installs either the server (nuxd) or a host agent, each with
# hardened systemd units.
#
#   curl -fsSL https://get.nuxdeck.com | sudo sh
#   curl -fsSL https://get.nuxdeck.com | sudo sh -s -- --agent --token TOKEN
#   sudo sh install.sh --version v0.1.0-alpha.1
#
# Options:
#   --version TAG   install this release instead of the newest one
#   --agent         install the host agent and nux-sockguard instead of the server
#   --token TOKEN   the single-use enrolment token from Nux Deck (Inventory, Add host);
#                   with --agent. NUX_ENROLL_TOKEN is read if --token is not given
#   --cosign PATH   use this cosign binary instead of downloading the pinned one
#   -h, --help      show this help
#
# Nothing is installed unless the signature and the checksum both verify. The
# whole script lives in main() so a truncated download cannot run half of it.
set -eu

REPO="${NUX_REPO:-nuxdeck/nuxdeck}"
API_URL="${NUX_API_URL:-https://api.github.com/repos/${REPO}}"
DOWNLOAD_URL="${NUX_DOWNLOAD_URL:-https://github.com/${REPO}/releases/download}"

# Releases are signed by the release workflow on main; anything else is rejected.
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/heads/main"
CERT_ISSUER="https://token.actions.githubusercontent.com"

# The cosign used to verify, pinned by version and SHA-256 so the verifier cannot be swapped.
COSIGN_VERSION="v3.1.4"
COSIGN_URL="${NUX_COSIGN_URL:-https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}}"
COSIGN_SHA256_AMD64="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"
COSIGN_SHA256_ARM64="ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2"

# NUX_DESTDIR installs into a staging root without touching users or services (packaging and tests).
DESTDIR="${NUX_DESTDIR:-}"
# Tests serve fake releases over plain HTTP on loopback.
ALLOW_HTTP="${NUX_ALLOW_HTTP:-}"
# Tests replace runuser, which drops to the agent's user for enrolment.
RUNUSER="${NUX_RUNUSER:-runuser}"

log() { printf '%s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//'
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

fetch() { # fetch URL DEST
	if [ -n "$ALLOW_HTTP" ]; then
		curl -fsSL "$1" -o "$2" || die "download failed: $1"
	else
		curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2" || die "download failed: $1"
	fi
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture $(uname -m): Nux Deck v0.1 supports linux/amd64 and linux/arm64" ;;
	esac
}

latest_tag() {
	body="$tmp/releases.json"
	fetch "${API_URL}/releases?per_page=1" "$body"
	sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$body" | head -n 1
}

valid_tag() {
	case "$1" in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) return 1 ;;
	esac
	# Only characters that are safe in a URL path and a file name.
	case "$1" in
	*[!0-9A-Za-z.+-]*) return 1 ;;
	esac
	return 0
}

sha256_of() { sha256sum "$1" | cut -d ' ' -f 1; }

get_cosign() { # prints the path of the cosign to use
	if [ -n "$cosign_path" ]; then
		[ -x "$cosign_path" ] || die "cosign not found or not executable: $cosign_path"
		echo "$cosign_path"
		return
	fi
	case "$arch" in
	amd64) want="$COSIGN_SHA256_AMD64" ;;
	arm64) want="$COSIGN_SHA256_ARM64" ;;
	esac
	bin="$tmp/cosign"
	fetch "${COSIGN_URL}/cosign-linux-${arch}" "$bin"
	[ "$(sha256_of "$bin")" = "$want" ] || die "the downloaded cosign ${COSIGN_VERSION} does not match its pinned checksum; refusing to run it"
	chmod 0755 "$bin"
	echo "$bin"
}

install_files() { # install_files BINARY UNIT...
	bin="$1"
	shift
	dest_bin="${DESTDIR}/usr/local/bin"
	dest_unit="${DESTDIR}/etc/systemd/system"
	mkdir -p "$dest_bin" "$dest_unit"

	# Install next to the target and rename, so a running binary is never overwritten in place.
	install -m 0755 "$tmp/extract/$bin" "$dest_bin/$bin.new"
	mv -f "$dest_bin/$bin.new" "$dest_bin/$bin"
	for unit in "$@"; do
		install -m 0644 "$tmp/extract/$unit" "$dest_unit/$unit"
	done
}

ensure_user() {
	id nuxd >/dev/null 2>&1 && return
	nologin="$(command -v nologin || echo /usr/sbin/nologin)"
	useradd --system --user-group --no-create-home --home-dir /var/lib/nuxd --shell "$nologin" nuxd ||
		die "could not create the nuxd system user"
}

start_service() {
	systemctl daemon-reload
	systemctl enable nuxd >/dev/null 2>&1
	systemctl restart nuxd
	i=0
	while [ "$i" -lt 30 ]; do
		if curl -ksf -o /dev/null "https://127.0.0.1:8443/readyz"; then
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	systemctl is-active --quiet nuxd || die "nuxd did not start; see: journalctl -u nuxd"
	log "warning: nuxd is running but did not answer on https://127.0.0.1:8443 (custom ports?)"
}

# A token is "nuxtok1." followed by URL-safe characters only, so nothing in it can be read as shell syntax.
valid_token() {
	case "$1" in
	nuxtok1.*) ;;
	*) return 1 ;;
	esac
	case "$1" in
	*[!A-Za-z0-9._-]*) return 1 ;;
	esac
	[ "${#1}" -le 1024 ]
}

ensure_agent_users() {
	getent group nux >/dev/null 2>&1 || groupadd --system nux || die "could not create the nux group"
	nologin="$(command -v nologin || echo /usr/sbin/nologin)"
	for account in nux nux-sg; do
		id "$account" >/dev/null 2>&1 && continue
		useradd --system --gid nux --no-create-home --home-dir /nonexistent --shell "$nologin" "$account" ||
			die "could not create the $account system user"
	done
	# Only nux-sg reaches the container runtime (through its socket proxy); the agent's own user never does.
	if getent group docker >/dev/null 2>&1; then
		usermod -aG docker nux-sg || die "could not add nux-sg to the docker group"
	else
		log "note: no docker group found, so nux-sockguard cannot read a Docker socket; container inventory stays empty until it can"
	fi
	if id -nG nux 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
		log "warning: the nux user is in the docker group; remove it (gpasswd -d nux docker), the agent must not reach the container socket"
	fi
}

enrol_agent() {
	state="${DESTDIR}/var/lib/nux-agent"
	if [ -e "$state/agent.json" ]; then
		log "This host is already enrolled; keeping its identity."
		return
	fi
	[ -n "$token" ] || die "no enrolment token: create one in Nux Deck (Inventory, Add host) and pass it with --token"
	if [ -n "$DESTDIR" ]; then
		install -d -m 0700 "$state"
	else
		install -d -o nux -g nux -m 0700 "$state"
	fi
	log "Enrolling this host"
	# The token goes in on standard input, so it never appears in the enrolment process's arguments.
	printf '%s' "$token" | "$RUNUSER" -u nux -- "$dest_bin/nux" agent enroll --token-file - --state-dir "$state" >/dev/null ||
		die "enrolment failed: the token works once and expires after an hour, and this host must reach the server; nothing is running yet"
}

start_agent() {
	systemctl daemon-reload
	systemctl enable nux-sockguard nux-agent >/dev/null 2>&1
	systemctl restart nux-sockguard nux-agent
	i=0
	while [ "$i" -lt 10 ]; do
		systemctl is-active --quiet nux-agent && return 0
		i=$((i + 1))
		sleep 1
	done
	die "nux-agent did not start; see: journalctl -u nux-agent"
}

main() {
	version=""
	version_given=""
	agent=""
	token_given=""
	token="${NUX_ENROLL_TOKEN:-}"
	cosign_path="${NUX_COSIGN:-}"
	while [ $# -gt 0 ]; do
		case "$1" in
		--version)
			[ $# -ge 2 ] || die "--version needs a value"
			version="$2"
			version_given=1
			shift 2
			;;
		--agent)
			agent=1
			shift
			;;
		--token)
			[ $# -ge 2 ] || die "--token needs a value"
			token="$2"
			token_given=1
			shift 2
			;;
		--cosign)
			[ $# -ge 2 ] || die "--cosign needs a value"
			cosign_path="$2"
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*) die "unknown option: $1 (see --help)" ;;
		esac
	done

	if [ -n "$agent" ]; then
		[ -z "$token" ] || valid_token "$token" || die "the enrolment token is malformed; copy it again in full from Nux Deck"
		# Fail before downloading anything when there is nothing to enrol with.
		[ -n "$token" ] || [ -e "${DESTDIR}/var/lib/nux-agent/agent.json" ] ||
			die "no enrolment token: create one in Nux Deck (Inventory, Add host) and pass it with --token"
	else
		[ -z "$token_given" ] || die "--token only makes sense with --agent"
	fi

	[ "$(uname -s)" = Linux ] || die "Nux Deck v0.1 supports Linux hosts only"
	arch="$(detect_arch)"
	if [ -z "$DESTDIR" ]; then
		[ "$(id -u)" = 0 ] || die "run as root, for example: curl -fsSL https://get.nuxdeck.com | sudo sh"
		[ -d /run/systemd/system ] || die "systemd is required to run Nux Deck as a service"
		need systemctl
		need useradd
		if [ -n "$agent" ]; then
			need groupadd
			need usermod
			need "$RUNUSER"
		fi
	fi
	need curl
	need tar
	need sha256sum
	need install
	need mktemp

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	if [ -z "$version" ] && [ -z "$version_given" ]; then
		version="$(latest_tag)"
		[ -n "$version" ] || die "could not find a release of ${REPO}"
	fi
	valid_tag "$version" || die "invalid version \"$version\": expected a tag such as v0.1.0 or v0.1.0-alpha.1"
	ver="${version#v}"

	if [ -n "$agent" ]; then
		component=nux
		units="nux-agent.service nux-sockguard.service"
	else
		component=nuxd
		units="nuxd.service"
	fi
	archive="${component}_${ver}_linux_${arch}.tar.gz"
	base="${DOWNLOAD_URL}/${version}"
	log "Installing Nux Deck ${version} ${agent:+agent }(linux/${arch})"
	fetch "${base}/${archive}" "$tmp/${archive}"
	fetch "${base}/checksums.txt" "$tmp/checksums.txt"
	fetch "${base}/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json"

	cosign="$(get_cosign)"
	log "Verifying the signature on checksums.txt"
	"$cosign" verify-blob "$tmp/checksums.txt" \
		--bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity "$CERT_IDENTITY" \
		--certificate-oidc-issuer "$CERT_ISSUER" >/dev/null 2>&1 ||
		die "signature verification failed for ${version}; nothing was installed"

	log "Verifying the archive checksum"
	expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
	[ -n "$expected" ] && [ "$(printf '%s\n' "$expected" | wc -l)" -eq 1 ] || die "${archive} is not listed in the signed checksums; nothing was installed"
	[ "$(sha256_of "$tmp/${archive}")" = "$expected" ] || die "checksum mismatch for ${archive}; nothing was installed"

	mkdir -p "$tmp/extract"
	# shellcheck disable=SC2086 # $units is a fixed list of file names without spaces or globs
	tar -xzf "$tmp/${archive}" -C "$tmp/extract" --no-same-owner "$component" $units ||
		die "the archive does not contain ${component} and its systemd units"

	if [ -n "$agent" ]; then
		if [ -z "$DESTDIR" ]; then
			ensure_agent_users
		fi
		# shellcheck disable=SC2086
		install_files nux $units
		enrol_agent
		if [ -z "$DESTDIR" ]; then
			start_agent
		fi
		log ""
		log "The Nux Deck agent ${version} is installed${DESTDIR:+ (staged, not started)}."
		log "This host should appear in Nux Deck within a few seconds of the agent starting."
		log ""
		log "Logs: journalctl -u nux-agent -u nux-sockguard"
		return 0
	fi

	if [ -z "$DESTDIR" ]; then
		ensure_user
	fi
	install_files nuxd nuxd.service
	if [ -z "$DESTDIR" ]; then
		start_service
	fi

	log ""
	log "Nux Deck ${version} is installed."
	log ""
	log "Next:"
	log "  1. Get the one-time setup token:   sudo nuxd setup-token"
	log "  2. Open https://<this-server>:8443 and create the administrator."
	log "     Your browser will warn about the self-signed certificate; that is expected on first start."
	log ""
	log "Configuration (optional): /etc/nuxd/nuxd.yaml, then: sudo systemctl restart nuxd"
	log "Logs: journalctl -u nuxd"
}

main "$@"

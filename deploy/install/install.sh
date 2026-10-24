#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Nux Deck installer: downloads a release, verifies its cosign signature and
# checksum, and installs nuxd with a hardened systemd unit.
#
#   curl -fsSL https://get.nuxdeck.com | sudo sh
#   sudo sh install.sh --version v0.1.0-alpha.1
#
# Options:
#   --version TAG   install this release instead of the newest one
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

log() { printf '%s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '4,16p' "$0" | sed 's/^# \{0,1\}//'
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

install_files() {
	dest_bin="${DESTDIR}/usr/local/bin"
	dest_unit="${DESTDIR}/etc/systemd/system"
	mkdir -p "$dest_bin" "$dest_unit"

	# Install next to the target and rename, so a running nuxd is never overwritten in place.
	install -m 0755 "$tmp/extract/nuxd" "$dest_bin/nuxd.new"
	mv -f "$dest_bin/nuxd.new" "$dest_bin/nuxd"
	install -m 0644 "$tmp/extract/nuxd.service" "$dest_unit/nuxd.service"
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

main() {
	version=""
	version_given=""
	cosign_path="${NUX_COSIGN:-}"
	while [ $# -gt 0 ]; do
		case "$1" in
		--version)
			[ $# -ge 2 ] || die "--version needs a value"
			version="$2"
			version_given=1
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

	[ "$(uname -s)" = Linux ] || die "Nux Deck v0.1 supports Linux hosts only"
	arch="$(detect_arch)"
	if [ -z "$DESTDIR" ]; then
		[ "$(id -u)" = 0 ] || die "run as root, for example: curl -fsSL https://get.nuxdeck.com | sudo sh"
		[ -d /run/systemd/system ] || die "systemd is required to run nuxd as a service"
		need systemctl
		need useradd
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

	archive="nuxd_${ver}_linux_${arch}.tar.gz"
	base="${DOWNLOAD_URL}/${version}"
	log "Installing Nux Deck ${version} (linux/${arch})"
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
	tar -xzf "$tmp/${archive}" -C "$tmp/extract" --no-same-owner nuxd nuxd.service ||
		die "the archive does not contain nuxd and nuxd.service"

	if [ -z "$DESTDIR" ]; then
		ensure_user
	fi
	install_files
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

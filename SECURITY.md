# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately; do not open a public issue.

- Email **security@nuxdeck.com**, or
- use GitHub private vulnerability reporting on the `nuxdeck/nuxdeck` repository (Security tab → Report a vulnerability).

Include the affected version, a description, reproduction steps and the impact you see.

## What to expect

| Severity (CVSS)   | Acknowledged within | Fix released within  |
| ----------------- | ------------------- | -------------------- |
| Critical (9.0+)   | 2 days              | 7 days               |
| High (7.0 to 8.9) | 3 days              | 30 days              |
| Medium and low    | 7 days              | Next planned release |

Each fix gets a GitHub Security Advisory and a CVE where applicable. Reporters are credited unless they ask not to be.

## Supported versions

Nux Deck is pre-release. Until v0.1.0 only the latest `v0.1.0-alpha.N` is supported.

From v0.1.0, fixes ship as patch releases for the latest minor version, and the previous minor version receives critical fixes for 3 months after a new minor release.

## Verifying a release

Every release archive set and container image is signed with keyless [cosign](https://docs.sigstore.dev/) from the release workflow, and ships SPDX SBOMs and SLSA build provenance. Verify before you run anything.

```
# Checksums, then the archives
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/nuxdeck/nuxdeck/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
sha256sum --check --ignore-missing checksums.txt

# Images
cosign verify ghcr.io/nuxdeck/nuxd:<tag> \
  --certificate-identity 'https://github.com/nuxdeck/nuxdeck/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

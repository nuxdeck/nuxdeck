// SPDX-License-Identifier: AGPL-3.0-only

// Package statuspages manages public status pages (STP-1 to STP-3). The operator-facing
// documents live in the database; the anonymous public surface reads only a separate
// projection (PublicPage) that is rebuilt from them and cannot carry hostnames, IPs, check
// IDs, names, targets or error details.
package statuspages

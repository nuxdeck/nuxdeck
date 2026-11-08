// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Snapshot is what the builder needs from the rest of nuxd: counts and type names only.
type Snapshot struct {
	AgentVersions map[string]int // raw agent version -> count; reduced to minor versions by the builder
	Clusters      int
	Checks        int
	Features      map[string]bool
	NotifierTypes []string
}

// Source reports the current scale and feature use.
type Source interface {
	Snapshot(ctx context.Context) (Snapshot, error)
}

// DBSource reads the counts straight from the tables, selecting no names, targets or addresses.
type DBSource struct {
	DB *sql.DB
	// SSO reports whether single sign-on is configured; nil means no.
	SSO func(ctx context.Context) bool
}

// Snapshot implements Source.
func (s DBSource) Snapshot(ctx context.Context) (Snapshot, error) {
	snap := Snapshot{AgentVersions: map[string]int{}, Features: map[string]bool{"sso": false, "status_pages": false, "k8s_actions": false}}
	if s.SSO != nil {
		snap.Features["sso"] = s.SSO(ctx)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT version, COUNT(*) FROM agents WHERE revoked_at IS NULL GROUP BY version`)
	if err != nil {
		return snap, fmt.Errorf("count agents: %w", err)
	}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			_ = rows.Close()
			return snap, fmt.Errorf("scan agents: %w", err)
		}
		snap.AgentVersions[v] += n
	}
	if err := rows.Close(); err != nil {
		return snap, err
	}
	var pages int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM checks`).Scan(&snap.Checks); err != nil {
		return snap, fmt.Errorf("count checks: %w", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM status_pages`).Scan(&pages); err != nil {
		return snap, fmt.Errorf("count status pages: %w", err)
	}
	snap.Features["status_pages"] = pages > 0
	types, err := s.DB.QueryContext(ctx, `SELECT DISTINCT type FROM channels ORDER BY type`)
	if err != nil {
		return snap, fmt.Errorf("list channel types: %w", err)
	}
	defer func() { _ = types.Close() }()
	for types.Next() {
		var t string
		if err := types.Scan(&t); err != nil {
			return snap, fmt.Errorf("scan channel type: %w", err)
		}
		snap.NotifierTypes = append(snap.NotifierTypes, t)
	}
	return snap, types.Err()
}

// minorVersion reduces "0.1.3-alpha.2" to "0.1"; anything unparsable becomes "unknown".
func minorVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || !digits(parts[0]) || !digits(parts[1]) {
		return "unknown"
	}
	return parts[0] + "." + parts[1]
}

func digits(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

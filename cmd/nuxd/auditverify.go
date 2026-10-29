// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// verifyAuditAtStartup walks the audit chain and logs the result (AUD-2). A broken chain is
// loud but does not stop nuxd: an operator needs the server up to investigate.
func verifyAuditAtStartup(ctx context.Context, db *store.Store, log *slog.Logger) {
	v, err := db.VerifyAudit(ctx)
	switch {
	case err != nil:
		log.Error("audit chain could not be read", "error", err)
	case !v.OK:
		log.Error("audit chain is broken", "code", errcode.AUDChain001, "broken_at", v.BrokenAt, "reason", v.Reason, "entries_verified", v.Entries)
	default:
		log.Info("audit chain verified", "entries", v.Entries)
	}
}

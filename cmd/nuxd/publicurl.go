// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// adoptStoredPublicURL lets the address saved by the setup wizard stand in for
// server.public_url when the config file and environment leave it empty. The
// file wins so automated installs stay in control; a change made in the wizard
// applies after the next restart.
func adoptStoredPublicURL(ctx context.Context, db *store.Store, cfg *config.Config, log *slog.Logger) {
	if cfg.Server.PublicURL != "" {
		return
	}
	raw, ok, err := db.Setting(ctx, "server.public_url")
	if err != nil {
		log.Warn("could not read the saved public address", "error", err)
		return
	}
	if !ok {
		return
	}
	var u string
	if err := json.Unmarshal([]byte(raw), &u); err != nil || u == "" {
		return
	}
	cfg.Server.PublicURL = u
}

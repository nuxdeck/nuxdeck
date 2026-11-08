// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

// notifierDrain is how long shutdown waits for queued notifications to be delivered.
const notifierDrain = 10 * time.Second

// startAlerting builds the alerting module and starts its evaluation loop and delivery workers.
// The returned stop function ends both, delivering what is queued, and must run before the
// database is closed.
func startAlerting(ctx context.Context, db *store.Store, box *secrets.Box, chk *checks.Service, inv *inventory.Service, mt *metrics.Service, cfg config.Config, log *slog.Logger) (*alerting.Service, *alerting.Channels, func()) {
	sender := notify.NewSender(notify.Options{Log: log})
	channels := alerting.NewChannels(alerting.ChannelOptions{DB: db, Secrets: box, Sender: sender, Log: log})
	notifier := alerting.NewNotifier(alerting.NotifierOptions{Channels: channels, QueueSize: cfg.Alerting.QueueSize, Workers: cfg.Alerting.Workers, Log: log})
	svc := alerting.New(alerting.Options{
		DB: db, Checks: chk, Inventory: alerting.FromInventory(inv), Metrics: mt, Sink: notifier, Log: log,
		PublicURL: publicURL(cfg), RepeatInterval: time.Duration(cfg.Alerting.RepeatIntervalMinutes) * time.Minute,
	})
	notifier.Start()
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := svc.Run(runCtx); err != nil {
			log.Error("alerting stopped", "error", err)
		}
	}()
	return svc, channels, func() {
		cancel()
		<-done
		if !notifier.Close(notifierDrain) {
			log.Warn("notification queue did not drain before shutdown", "queued", notifier.Stats().Queued)
		}
	}
}

// publicURL is the base of the deep links in alert messages: server.public_url, or this
// machine's host name on the port of the https listener.
func publicURL(cfg config.Config) string {
	if cfg.Server.PublicURL != "" {
		return strings.TrimSuffix(cfg.Server.PublicURL, "/")
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	_, port, err := net.SplitHostPort(cfg.HTTP.HTTPSAddr)
	if err != nil || port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(host, port)
}

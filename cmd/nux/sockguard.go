// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"

	"github.com/nuxdeck/nuxdeck/cmd/nux/internal/cli"
	"github.com/nuxdeck/nuxdeck/internal/agent/sockguard"
)

const defaultSockguardSocket = "/run/nux/sockguard.sock"

// runSockguard serves nux-sockguard: the one process that reads the container runtime socket.
func runSockguard(ctx context.Context, args []string, settings cli.Settings, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("nux sockguard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", defaultSockguardSocket, "Unix socket to listen on (mode 0660)")
	upstream := fs.String("upstream", "", "Docker or Podman socket (default: the first of /run/podman/podman.sock, /var/run/docker.sock, $XDG_RUNTIME_DIR/podman/podman.sock)")
	group := fs.String("group", "", "give the listening socket to this group (default: the process's group)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	var level slog.Level
	_ = level.UnmarshalText([]byte(settings.LogLevel))
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))

	ln, err := sockguard.Listen(*socket, *group)
	if err != nil {
		return fail(stderr, err, 1)
	}
	defer func() { _ = os.Remove(*socket) }()

	log.Info("nux-sockguard listening", "socket", *socket, "upstream", *upstream)
	g := sockguard.New(sockguard.Config{Upstream: *upstream, Candidates: sockguard.Candidates(getenv), Log: log})
	if err := g.Serve(ctx, ln); err != nil {
		return fail(stderr, err, 1)
	}
	return 0
}

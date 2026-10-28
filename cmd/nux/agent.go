// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/nuxdeck/nuxdeck/cmd/nux/internal/cli"
	"github.com/nuxdeck/nuxdeck/internal/agent/checks"
	"github.com/nuxdeck/nuxdeck/internal/agent/enroll"
	"github.com/nuxdeck/nuxdeck/internal/agent/inventory"
	"github.com/nuxdeck/nuxdeck/internal/agent/logs"
	"github.com/nuxdeck/nuxdeck/internal/agent/metrics"
	agentrun "github.com/nuxdeck/nuxdeck/internal/agent/run"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	defaultStateDir = "/var/lib/nux-agent"
	// exitNoRetry tells systemd not to restart the agent (RestartPreventExitStatus): retrying
	// cannot fix a revoked agent, a damaged identity or an expired certificate.
	exitNoRetry = 78
)

const agentUsage = `Usage: nux agent <command> [flags]

Commands:
  enroll   trade a single-use token for this host's identity
  run      connect to nuxd and stay connected

`

func runAgent(ctx context.Context, args []string, settings cli.Settings, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, agentUsage)
		return fail(stderr, errcode.New(errcode.CLIArg001, "nux agent needs a command"), 2)
	}
	switch args[0] {
	case "enroll":
		return agentEnroll(ctx, args[1:], stdin, stdout, stderr, getenv)
	case "run":
		return agentRun(ctx, args[1:], settings, stderr, getenv)
	default:
		_, _ = fmt.Fprint(stderr, agentUsage)
		return fail(stderr, errcode.New(errcode.CLIArg001, "unknown agent command %q", args[0]), 2)
	}
}

func stateDirFlag(fs *flag.FlagSet, getenv func(string) string) *string {
	def := defaultStateDir
	if v := getenv("NUX_STATE_DIR"); v != "" {
		def = v
	}
	return fs.String("state-dir", def, "directory for the agent's key, certificate and identity (env NUX_STATE_DIR)")
}

func agentEnroll(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("nux agent enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "enrolment token (visible in the process list; prefer --token-file or NUX_ENROLL_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the enrolment token from this file, or from standard input if -")
	force := fs.Bool("force", false, "replace an existing identity")
	stateDir := stateDirFlag(fs, getenv)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	raw, err := tokenFrom(*token, *tokenFile, stdin, getenv)
	if err != nil {
		return fail(stderr, err, 2)
	}
	host, _ := os.Hostname()
	id, err := enroll.Do(ctx, enroll.Request{
		StateDir: *stateDir, Token: raw, Force: *force, Version: version, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
	})
	if err != nil {
		return fail(stderr, err, 1)
	}
	_, _ = fmt.Fprintf(stdout, "Enrolled as agent %s. Identity stored in %s.\nStart it with: systemctl enable --now nux-agent   (or: nux agent run --state-dir %s)\n", id, *stateDir, *stateDir)
	return 0
}

func tokenFrom(flagValue, file string, stdin io.Reader, getenv func(string) string) (string, error) {
	switch {
	case flagValue != "":
		return flagValue, nil
	case file == "-":
		b, err := io.ReadAll(io.LimitReader(stdin, 4<<10))
		if err != nil {
			return "", errcode.Wrap(errcode.CLIArg002, "read token from standard input", err)
		}
		return strings.TrimSpace(string(b)), nil
	case file != "":
		b, err := os.ReadFile(file) //nolint:gosec // user-supplied path to their own token
		if err != nil {
			return "", errcode.Wrap(errcode.CLIArg002, "read token file", err)
		}
		return strings.TrimSpace(string(b)), nil
	case getenv("NUX_ENROLL_TOKEN") != "":
		return getenv("NUX_ENROLL_TOKEN"), nil
	}
	return "", errcode.New(errcode.CLIArg002, "no token: pass --token-file, set NUX_ENROLL_TOKEN or pass --token")
}

func agentRun(ctx context.Context, args []string, settings cli.Settings, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("nux agent run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := stateDirFlag(fs, getenv)
	sockSocket := fs.String("sockguard-socket", envOr(getenv, "NUX_SOCKGUARD_SOCKET", defaultSockguardSocket), "nux-sockguard's socket, the agent's only route to Docker and Podman (env NUX_SOCKGUARD_SOCKET)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	var level slog.Level
	_ = level.UnmarshalText([]byte(settings.LogLevel))
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))

	inv := inventory.New(inventory.Config{SockguardSocket: *sockSocket, Log: log})
	go inv.Run(ctx)
	met := metrics.New(metrics.Config{SockguardSocket: *sockSocket, Log: log, Containers: func() []*agentv1.Container {
		snap, _, detach := inv.Attach()
		detach()
		return snap.GetContainers()
	}})
	go met.Run(ctx)
	err := agentrun.Run(ctx, agentrun.Config{
		StateDir: *stateDir, Version: version, Log: log, Inventory: inv, Metrics: met,
		Logs: logs.New(logs.Config{SockguardSocket: *sockSocket, Log: log}), Checks: checks.New(log, 0),
	})
	switch errcode.CodeOf(err) {
	case "":
		if err != nil {
			return fail(stderr, err, 1)
		}
		return 0
	case errcode.AGTRev001, errcode.AGTID001, errcode.AGTID002:
		return fail(stderr, err, exitNoRetry)
	default:
		return fail(stderr, err, 1)
	}
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

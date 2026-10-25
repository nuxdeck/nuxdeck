// SPDX-License-Identifier: Apache-2.0

// Command nux is the Nux Deck agent and CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/nuxdeck/nuxdeck/cmd/nux/internal/cli"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Set at build time with -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `Usage: nux [flags] <command>

Commands:
  version   print the nux version
  agent     enrol this host and run the host agent (nux agent enroll | run)
  sockguard serve the read-only container API proxy (used by the agent, not by hand)
  login     sign in to nuxd (not implemented yet)

Flags:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	var flags cli.Flags
	fs := flag.NewFlagSet("nux", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags.Register(fs)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if fs.NArg() == 0 {
		fs.Usage()
		return fail(stderr, errcode.New(errcode.CLIArg001, "no command given"), 2)
	}

	switch cmd := fs.Arg(0); cmd {
	case "version":
		_, _ = fmt.Fprintf(stdout, "nux %s (commit %s, built %s) %s/%s %s\n", version, commit, date, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "agent":
		settings, err := cli.Resolve(flags, getenv, os.UserConfigDir)
		if err != nil {
			return fail(stderr, err, 2)
		}
		return runAgent(ctx, fs.Args()[1:], settings, stdin, stdout, stderr, getenv)
	case "sockguard":
		settings, err := cli.Resolve(flags, getenv, os.UserConfigDir)
		if err != nil {
			return fail(stderr, err, 2)
		}
		return runSockguard(ctx, fs.Args()[1:], settings, stderr, getenv)
	case "login":
		if _, err := cli.Resolve(flags, getenv, os.UserConfigDir); err != nil {
			return fail(stderr, err, 2)
		}
		return fail(stderr, errcode.New(errcode.CLIArg003, "nux %s is not implemented yet", cmd), 1)
	default:
		fs.Usage()
		return fail(stderr, errcode.New(errcode.CLIArg001, "unknown command %q", cmd), 2)
	}
}

func fail(stderr io.Writer, err error, code int) int {
	_, _ = fmt.Fprintln(stderr, "nux:", err)
	return code
}

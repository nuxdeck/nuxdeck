// SPDX-License-Identifier: Apache-2.0

// Command nux is the Nux Deck agent and CLI.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

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
  agent     run the host agent (not implemented yet)
  login     sign in to nuxd (not implemented yet)

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
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
	case "agent", "login":
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

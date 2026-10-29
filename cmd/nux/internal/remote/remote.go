// SPDX-License-Identifier: Apache-2.0

// Package remote implements the nux commands that talk to nuxd over its REST and WebSocket API.
// It depends only on pkg/client and the public packages, never on internal/server.
package remote

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/nuxdeck/nuxdeck/cmd/nux/internal/cli"
	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Env is everything a command touches outside its arguments, so tests can replace it.
type Env struct {
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	UserConfigDir func() (string, error)
}

// Commands lists the first words Run handles, so the caller can route to it.
var Commands = []string{"login", "logout", "hosts", "containers", "checks", "alerts", "silences", "agents", "telemetry", "logs", "help"}

const usage = `Usage: nux <command> [flags]

Commands:
  login                    sign in to nuxd and store the API token
  logout                   forget the stored sign-in on this machine
  hosts ls|get ID          list hosts, or show one
  containers ls|get ID     list containers, or show one
  checks ls|get|run ID     list checks, show one, or run one now
  alerts ls|get|ack ID     list alerts, show one, or acknowledge one
  silences ls|create|rm    list silences, create one, or remove one
  agents ls                list enrolled agents
  agents token create      create a single-use agent enrolment token (shown once)
  agents revoke ID         revoke an agent
  telemetry show           print the exact telemetry payload nuxd would send
  logs TARGET [-f]         stream container or journal logs
  help                     show this help

Run "nux <command> -h" for the flags of a command. Connection flags (--server, --token,
--ca-file, --pin, --insecure-skip-verify) and --output table|json go after the command word.

Environment: NUX_SERVER, NUX_TOKEN, NUX_CA_FILE. NO_COLOR is accepted; nux never prints colour.
Exit codes: 0 ok, 1 error, 2 usage, 3 not signed in or not allowed, 4 not found.
`

// IsCommand reports whether cmd is handled by Run.
func IsCommand(cmd string) bool {
	return slices.Contains(Commands, cmd)
}

// Run executes one remote command and returns its exit code. serverFlag is the --server value
// given before the command word, if any.
func Run(ctx context.Context, cmd string, args []string, env Env, serverFlag string) int {
	a := &app{env: env, serverFlag: serverFlag}
	err := a.dispatch(ctx, cmd, args)
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	report(env.Stderr, err)
	return exitCode(err)
}

type app struct {
	env        Env
	serverFlag string
}

func (a *app) dispatch(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "help":
		_, err := fmt.Fprint(a.env.Stdout, usage)
		return err
	case "login":
		return a.login(ctx, args)
	case "logout":
		return a.logout(args)
	case "hosts":
		return a.hosts(ctx, args)
	case "containers":
		return a.containers(ctx, args)
	case "checks":
		return a.checks(ctx, args)
	case "alerts":
		return a.alerts(ctx, args)
	case "silences":
		return a.silences(ctx, args)
	case "agents":
		return a.agents(ctx, args)
	case "telemetry":
		return a.telemetry(ctx, args)
	case "logs":
		return a.logs(ctx, args)
	}
	return errcode.New(errcode.CLIArg001, "unknown command %q", cmd)
}

// report prints the error with its code and the hint that goes with it. Tokens never reach
// an error message, so nothing here needs redaction.
func report(w io.Writer, err error) {
	_, _ = fmt.Fprintf(w, "nux: %v\n", err)
	if hint := hintFor(err); hint != "" {
		_, _ = fmt.Fprintf(w, "hint: %s\n", hint)
	}
}

func hintFor(err error) string {
	var api *APIError
	if errors.As(err, &api) {
		return api.Hint
	}
	if entry, ok := errcode.Lookup(errcode.CodeOf(err)); ok {
		return entry.Hint
	}
	return ""
}

// exitCode maps an error to the documented exit codes.
func exitCode(err error) int {
	var api *APIError
	if errors.As(err, &api) {
		switch api.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return 3
		case http.StatusNotFound:
			return 4
		}
		return 1
	}
	switch errcode.CodeOf(err) {
	case errcode.CLIAuth001, errcode.AuthToken001, errcode.AuthDeny001, errcode.AuthDeny002, errcode.AuthDeny003, errcode.AuthDeny004, errcode.AuthDeny005:
		return 3
	case errcode.APINF001:
		return 4
	case errcode.CLIArg001, errcode.CLIArg002, errcode.CLIArg003, errcode.CLIArg004:
		return 2
	}
	return 1
}

// shared holds the connection and output flags every remote command accepts.
type shared struct {
	Server   string
	Token    string
	CAFile   string
	Pin      string
	Insecure bool
	Output   string
}

func (s *shared) register(fs *flag.FlagSet, withOutput bool) {
	fs.StringVar(&s.Server, "server", "", "nuxd URL (default: NUX_SERVER, the saved server, then "+cli.DefaultServer+")")
	fs.StringVar(&s.Token, "token", "", "API token; prefer NUX_TOKEN, since command lines are visible to other users")
	fs.StringVar(&s.CAFile, "ca-file", "", "PEM file with the CA that signed the server certificate")
	fs.StringVar(&s.Pin, "pin", "", "trust only the server certificate with this fingerprint, sha256:HEX")
	fs.BoolVar(&s.Insecure, "insecure-skip-verify", false, "skip server certificate verification (discouraged)")
	if withOutput {
		fs.StringVar(&s.Output, "output", "table", "output format: table or json")
	}
}

func (s *shared) validateOutput() error {
	if s.Output != "table" && s.Output != "json" {
		return errcode.New(errcode.CLIArg002, "--output must be table or json, got %q", s.Output)
	}
	return nil
}

// newFlagSet builds a flag set whose -h prints the command's man-style usage.
func (a *app) newFlagSet(name, synopsis, description string) *flag.FlagSet {
	fs := flag.NewFlagSet("nux "+name, flag.ContinueOnError)
	fs.SetOutput(a.env.Stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(a.env.Stderr, "Usage: nux %s\n\n%s\n\nFlags:\n", synopsis, description)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses flags wherever they appear, so "nux logs web -f" works as well as "nux logs -f web".
// It returns the positional arguments in order.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageErr(err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func usageErr(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return errcode.Wrap(errcode.CLIArg002, "flags", err)
}

// exactArgs rejects missing or extra positional arguments with the command's usage line.
func exactArgs(fs *flag.FlagSet, pos []string, n int) error {
	if len(pos) != n {
		fs.Usage()
		return errcode.New(errcode.CLIArg002, "expected %d argument(s), got %d", n, len(pos))
	}
	return nil
}

// splitSub returns the subcommand word and the arguments after it. A flag in that position means no subcommand.
func splitSub(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

func unknownSub(cmd, sub string) error {
	if sub == "" {
		return errcode.New(errcode.CLIArg001, "%s needs a subcommand; run nux help", cmd)
	}
	return errcode.New(errcode.CLIArg001, "%s has no subcommand %q", cmd, sub)
}

// settings is the resolved connection: flag, then environment, then the saved sign-in, then the default.
type settings struct {
	server string
	token  string
	trust  trust
	path   string
	cfg    Config
}

func (a *app) configPath() (string, error) {
	return ConfigPath(a.env.Getenv, a.env.UserConfigDir)
}

func (a *app) resolve(s shared) (settings, error) {
	path, err := a.configPath()
	if err != nil {
		return settings{}, err
	}
	cfg, _, err := LoadConfig(path)
	if err != nil {
		return settings{}, err
	}
	if cfg.Token != "" && LooseMode(path) {
		_, _ = fmt.Fprintf(a.env.Stderr, "warning: %s is readable by other users; run chmod 600 on it\n", path)
	}
	st := settings{
		server: firstNonEmpty(s.Server, a.serverFlag, a.env.Getenv("NUX_SERVER"), cfg.Server, cli.DefaultServer),
		token:  firstNonEmpty(s.Token, a.env.Getenv("NUX_TOKEN"), cfg.Token),
		trust: trust{
			CAFile:   firstNonEmpty(s.CAFile, a.env.Getenv("NUX_CA_FILE"), cfg.CAFile),
			Pin:      firstNonEmpty(s.Pin, cfg.Pin),
			Insecure: s.Insecure,
		},
		path: path,
		cfg:  cfg,
	}
	if err := validateServer(st.server); err != nil {
		return settings{}, err
	}
	if s.Token != "" {
		_, _ = fmt.Fprintln(a.env.Stderr, "warning: --token is visible in the process list and shell history; prefer NUX_TOKEN")
	}
	if s.Insecure {
		_, _ = fmt.Fprintln(a.env.Stderr, "warning: server certificate verification is disabled for this command")
	}
	return st, nil
}

func (a *app) connect(s shared) (*conn, error) {
	st, err := a.resolve(s)
	if err != nil {
		return nil, err
	}
	if st.token == "" {
		return nil, errcode.New(errcode.CLIAuth001, "no API token; set NUX_TOKEN or run nux login")
	}
	return dial(st.server, st.token, st.trust)
}

func validateServer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return errcode.New(errcode.CLIArg002, "server must be an http(s) URL without credentials, got %q", s)
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return errcode.New(errcode.CLIArg002, "plain http is only allowed for localhost, got %q", s)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// emitJSON writes v as indented JSON followed by a newline.
func (a *app) emitJSON(v any) error {
	enc := json.NewEncoder(a.env.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table writes headers and rows aligned in columns.
func (a *app) table(headers []string, rows [][]string) error {
	w := tabwriter.NewWriter(a.env.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
	for _, r := range rows {
		_, _ = fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	return w.Flush()
}

// fields writes one object as FIELD VALUE pairs.
func (a *app) fields(pairs [][2]string) error {
	w := tabwriter.NewWriter(a.env.Stdout, 0, 0, 2, ' ', 0)
	for _, p := range pairs {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", p[0], p[1])
	}
	return w.Flush()
}

// hintMore tells the user how to fetch the next page, on stderr so table output stays clean.
func (a *app) hintMore(cursor *string, cmd string) {
	if cursor != nil && *cursor != "" {
		_, _ = fmt.Fprintf(a.env.Stderr, "more results: nux %s --cursor %s\n", cmd, *cursor)
	}
}

// confirm reads a yes or no answer from stdin; anything but y or yes is no.
func (a *app) confirm(prompt string) bool {
	_, _ = fmt.Fprint(a.env.Stderr, prompt)
	line, _ := bufio.NewReader(a.env.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// readFile reads a token file and trims the trailing newline.
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the user names the token file on purpose
	if err != nil {
		return "", errcode.Wrap(errcode.CLIArg002, "read "+path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

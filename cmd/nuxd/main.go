// SPDX-License-Identifier: AGPL-3.0-only

// Command nuxd is the Nux Deck server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/api"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/logging"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/tlsutil"
	"github.com/nuxdeck/nuxdeck/web"
)

// Set at build time with -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) > 0 && args[0] == "setup-token" {
		return setupToken(args[1:], stdout, stderr, getenv)
	}
	fs := flag.NewFlagSet("nuxd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", getenvDefault(getenv, "NUXD_CONFIG", config.DefaultPath), "path to the YAML configuration file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "nuxd %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	explicit := getenv("NUXD_CONFIG") != ""
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })

	if err := serve(ctx, *configPath, explicit, stderr, getenv); err != nil {
		_, _ = fmt.Fprintln(stderr, "nuxd:", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, configPath string, explicit bool, stderr io.Writer, getenv func(string) string) error {
	cfg, err := config.Load(configPath, explicit, getenv)
	if err != nil {
		return err
	}
	log, err := logging.New(stderr, cfg.Log.Level)
	if err != nil {
		return errcode.Wrap(errcode.SRVCfg002, "logger", err)
	}

	db, err := store.Open(ctx, cfg.DataDir, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("close database", "error", err)
		}
	}()

	hostnames := cfg.TLS.Hostnames
	if h, err := os.Hostname(); err == nil && h != "" {
		hostnames = append(hostnames, h)
	}
	cert, err := tlsutil.Certificate(tlsutil.Options{
		CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile, DataDir: cfg.DataDir, Hostnames: hostnames,
	})
	if err != nil {
		return err
	}

	ui, err := web.FS()
	if err != nil {
		return errcode.Wrap(errcode.SRVIO001, "load embedded web UI", err)
	}
	svc, err := newAuthService(ctx, db, cfg.DataDir, log)
	if err != nil {
		return err
	}
	handler := api.Handler(api.Options{Log: log, Ready: db, Version: version, UI: ui, Auth: svc})
	srv, err := api.NewServer(cfg.HTTP, cert, handler, log)
	if err != nil {
		return err
	}

	log.Info("nuxd started", "version", version, "https_addr", srv.HTTPSAddr(), "redirect_addr", srv.RedirectAddr(), "data_dir", cfg.DataDir)
	if err := srv.Serve(ctx); err != nil {
		return err
	}
	log.Info("nuxd stopped")
	return nil
}

// newAuthService builds the auth module. While no account exists it makes sure
// a setup token is on disk; the token itself is never logged.
func newAuthService(ctx context.Context, db *store.Store, dataDir string, log *slog.Logger) (*auth.Service, error) {
	token := auth.NewSetupToken(dataDir)
	svc, err := auth.NewService(ctx, auth.Config{
		Repo: db, Hasher: auth.NewHasher(), Passwords: auth.NewPasswordPolicy(), SetupToken: token, Log: log,
	})
	if err != nil {
		return nil, errcode.Wrap(errcode.APIInt001, "start auth", err)
	}
	required, err := svc.SetupRequired(ctx)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "check for accounts", err)
	}
	if required {
		if err := token.Ensure(); err != nil {
			return nil, errcode.Wrap(errcode.SRVIO001, "create setup token", err)
		}
		log.Info("first-run setup is required: run `nuxd setup-token` on this host and enter its output in the setup page", "token_file", token.Path())
	}
	return svc, nil
}

// setupToken prints the first-run setup token, so it never has to appear in logs.
func setupToken(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs2 := flag.NewFlagSet("nuxd setup-token", flag.ContinueOnError)
	fs2.SetOutput(stderr)
	configPath := fs2.String("config", getenvDefault(getenv, "NUXD_CONFIG", config.DefaultPath), "path to the YAML configuration file")
	if err := fs2.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	explicit := getenv("NUXD_CONFIG") != ""
	fs2.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })

	cfg, err := config.Load(*configPath, explicit, getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "nuxd:", err)
		return 1
	}
	token, err := auth.NewSetupToken(cfg.DataDir).Read()
	if errors.Is(err, fs.ErrNotExist) {
		_, _ = fmt.Fprintln(stderr, "nuxd:", errcode.New(errcode.AuthSetup002, "no setup token in %s: setup is complete, or nuxd has not started yet", cfg.DataDir))
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "nuxd:", errcode.Wrap(errcode.SRVIO001, "read setup token", err))
		return 1
	}
	_, _ = fmt.Fprintln(stdout, token)
	return 0
}

func getenvDefault(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

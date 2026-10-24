// SPDX-License-Identifier: AGPL-3.0-only

// Command nuxd is the Nux Deck server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/api"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/logging"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/tlsutil"
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

	handler := api.Handler(api.Options{Log: log, Ready: db, Version: version})
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

func getenvDefault(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

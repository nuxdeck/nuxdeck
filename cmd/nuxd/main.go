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
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/api"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/gateway"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/logging"
	"github.com/nuxdeck/nuxdeck/internal/server/logs"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/tlsutil"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
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
	ca, err := pki.LoadOrCreateCA(filepath.Join(cfg.DataDir, "pki"), time.Now())
	if err != nil {
		return err
	}
	gwURL := gatewayURL(cfg.Gateway.PublicURL)
	pkiSvc := pki.NewService(db, ca)
	inv, err := inventory.NewService(db, log)
	if err != nil {
		return err
	}
	mt, err := metrics.Open(metrics.Options{
		Dir: filepath.Join(cfg.DataDir, "tsdb"), Log: log, Inventory: inv.Index(),
		FullRetention:        time.Duration(cfg.Metrics.RetentionDays) * 24 * time.Hour,
		DownsampledRetention: time.Duration(cfg.Metrics.DownsampledRetentionDays) * 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	mt.Run(ctx)
	defer func() {
		if err := mt.Close(); err != nil {
			log.Error("close metrics store", "error", err)
		}
	}()
	var gw *gateway.Gateway // set below; the log broker sends through it
	logBroker := logs.NewBroker(logs.Options{Log: log, Sender: senderFunc(func(agentID string, m *agentv1.ServerMessage) error {
		return gw.SendToAgent(agentID, m)
	})})
	defer logBroker.Close()
	gw, err = gateway.New(ctx, gateway.Options{
		Log: log, Repo: db, Enroller: pkiSvc, Renewer: pkiSvc, CA: ca,
		OnMessage: func(agentID string, m *agentv1.AgentMessage) {
			inv.HandleMessage(agentID, m)
			mt.HandleMessage(agentID, m)
			logBroker.HandleMessage(agentID, m)
		}, OnPresence: func(agentID string, online bool) {
			inv.SetPresence(agentID, online)
			logBroker.AgentGone(agentID) // a new or lost connection ends the streams of the old one
		},
		ServerCert: ca.ServerCertificates(gatewayHosts(gwURL, hostnames)).GetCertificate,
	})
	if err != nil {
		return err
	}
	handler := api.Handler(api.Options{
		Log: log, Ready: db, Version: version, UI: ui, Auth: svc,
		PKI: pkiSvc, GatewayURL: gwURL, Revoker: gw, Inventory: inv, Metrics: mt, Logs: logBroker, Audit: db,
	})
	srv, err := api.NewServer(cfg.HTTP, cert, handler, log)
	if err != nil {
		return err
	}
	gwLn, err := gateway.Listen(cfg.Gateway.Addr)
	if err != nil {
		return err
	}

	log.Info("nuxd started", "version", version, "https_addr", srv.HTTPSAddr(), "redirect_addr", srv.RedirectAddr(), "data_dir", cfg.DataDir)
	log.Info("agent gateway listening", "addr", gwLn.Addr().String(), "public_url", gwURL)
	if err := serveAll(ctx, srv, gw, gwLn); err != nil {
		return err
	}
	log.Info("nuxd stopped")
	return nil
}

// senderFunc adapts a function to logs.Sender.
type senderFunc func(agentID string, m *agentv1.ServerMessage) error

func (f senderFunc) SendToAgent(agentID string, m *agentv1.ServerMessage) error { return f(agentID, m) }

// serveAll runs the web server and the agent gateway; when either stops, so does the other.
func serveAll(ctx context.Context, srv *api.Server, gw *gateway.Gateway, gwLn net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- srv.Serve(ctx) }()
	go func() { errs <- gw.Serve(ctx, gwLn) }()
	first := <-errs
	cancel()
	return errors.Join(first, <-errs)
}

// gatewayHosts lists the names and addresses the gateway certificate must cover.
func gatewayHosts(publicURL string, configured []string) []string {
	hosts := append([]string{"localhost"}, configured...)
	if u, err := url.Parse(publicURL); err == nil && u.Hostname() != "" {
		hosts = append(hosts, u.Hostname())
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// gatewayURL is the address embedded in enrolment tokens: the configured public
// URL, or this machine's host name on the agent port.
func gatewayURL(configured string) string {
	if configured != "" {
		return strings.TrimSuffix(configured, "/")
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return "https://" + net.JoinHostPort(host, "8444")
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

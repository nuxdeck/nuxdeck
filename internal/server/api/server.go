// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
)

const shutdownTimeout = 15 * time.Second

var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// Server owns the HTTPS listener and the plain-HTTP redirect listener.
type Server struct {
	https, redirect     *http.Server
	httpsLn, redirectLn net.Listener
}

// NewServer binds both addresses. It does not serve until Serve is called.
func NewServer(cfg config.HTTP, cert tls.Certificate, handler http.Handler, log *slog.Logger) (*Server, error) {
	httpsLn, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO003, "listen on "+cfg.HTTPSAddr, err)
	}
	redirectLn, err := net.Listen("tcp", cfg.RedirectAddr)
	if err != nil {
		_ = httpsLn.Close()
		return nil, errcode.Wrap(errcode.SRVIO003, "listen on "+cfg.RedirectAddr, err)
	}
	_, httpsPort, _ := net.SplitHostPort(httpsLn.Addr().String())

	errLog := slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	return &Server{
		httpsLn:    httpsLn,
		redirectLn: redirectLn,
		https: &http.Server{
			Handler:           handler,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 16,
			ErrorLog:          errLog,
		},
		redirect: &http.Server{
			Handler:           redirectHandler(httpsPort),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    1 << 14,
			ErrorLog:          errLog,
		},
	}, nil
}

// HTTPSAddr is the bound HTTPS address.
func (s *Server) HTTPSAddr() string { return s.httpsLn.Addr().String() }

// RedirectAddr is the bound redirect address.
func (s *Server) RedirectAddr() string { return s.redirectLn.Addr().String() }

// Serve runs both listeners until ctx is cancelled, then drains connections.
func (s *Server) Serve(ctx context.Context) error {
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	run(func() error { return s.https.ServeTLS(s.httpsLn, "", "") })
	run(func() error { return s.redirect.Serve(s.redirectLn) })

	var first error
	select {
	case <-ctx.Done():
	case first = <-errs:
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	first = errors.Join(first, s.https.Shutdown(shutdownCtx), s.redirect.Shutdown(shutdownCtx))
	wg.Wait()
	return first
}

// redirectHandler sends every request to the same path on HTTPS. The host is
// taken from the request, so it is validated to keep it a bare host name or IP.
func redirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil && !hostName.MatchString(host) {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		authority := net.JoinHostPort(host, httpsPort)
		if httpsPort == "443" {
			authority = host
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			}
		}
		//nolint:gosec // host is validated above and the scheme and port are fixed
		http.Redirect(w, r, "https://"+authority+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

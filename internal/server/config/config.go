// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads nuxd settings in layers: built-in defaults, then the
// YAML file, then NUXD_* environment variables.
package config

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// DefaultPath is read when no --config flag or NUXD_CONFIG is given.
const DefaultPath = "/etc/nuxd/nuxd.yaml"

// Config holds every nuxd setting.
type Config struct {
	DataDir string  `yaml:"data_dir"`
	Log     Log     `yaml:"log"`
	HTTP    HTTP    `yaml:"http"`
	TLS     TLS     `yaml:"tls"`
	Gateway Gateway `yaml:"gateway"`
}

// Log configures structured logging.
type Log struct {
	Level string `yaml:"level"`
}

// HTTP configures the listeners.
type HTTP struct {
	// HTTPSAddr serves the UI and API.
	HTTPSAddr string `yaml:"https_addr"`
	// RedirectAddr only redirects to HTTPS.
	RedirectAddr string `yaml:"redirect_addr"`
}

// TLS configures the server certificate. Without CertFile and KeyFile nuxd
// generates and renews a self-signed certificate in the data directory.
type TLS struct {
	CertFile  string   `yaml:"cert_file"`
	KeyFile   string   `yaml:"key_file"`
	Hostnames []string `yaml:"hostnames"`
}

// Gateway configures how agents reach nuxd.
type Gateway struct {
	// PublicURL is the https URL agents dial (port 8444), embedded in enrolment tokens.
	// Empty means https://<host name of this machine>:8444.
	PublicURL string `yaml:"public_url"`
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		DataDir: "/var/lib/nuxd",
		Log:     Log{Level: "info"},
		HTTP:    HTTP{HTTPSAddr: ":8443", RedirectAddr: ":8080"},
	}
}

// Load builds the configuration. A missing file is an error only when
// explicit is true (the operator named it).
func Load(path string, explicit bool, getenv func(string) string) (Config, error) {
	cfg := Defaults()

	if path != "" {
		if err := applyFile(&cfg, path, explicit); err != nil {
			return Config{}, err
		}
	}
	if err := applyEnv(&cfg, getenv); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyFile(cfg *Config, path string, explicit bool) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied configuration path
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil
	}
	if err != nil {
		return errcode.Wrap(errcode.SRVCfg001, "read "+path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return errcode.Wrap(errcode.SRVCfg001, "parse "+path, err)
	}
	return nil
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	set := func(dst *string, name string) {
		if v := getenv(name); v != "" {
			*dst = v
		}
	}
	set(&cfg.DataDir, "NUXD_DATA_DIR")
	set(&cfg.Log.Level, "NUXD_LOG_LEVEL")
	set(&cfg.HTTP.HTTPSAddr, "NUXD_HTTPS_ADDR")
	set(&cfg.HTTP.RedirectAddr, "NUXD_REDIRECT_ADDR")
	set(&cfg.TLS.CertFile, "NUXD_TLS_CERT_FILE")
	set(&cfg.TLS.KeyFile, "NUXD_TLS_KEY_FILE")
	set(&cfg.Gateway.PublicURL, "NUXD_GATEWAY_PUBLIC_URL")

	if v := getenv("NUXD_TLS_HOSTNAMES"); v != "" {
		cfg.TLS.Hostnames = nil
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.TLS.Hostnames = append(cfg.TLS.Hostnames, h)
			}
		}
	}
	return nil
}

// Validate checks the settings and returns the first problem with its code.
func (c Config) Validate() error {
	if !filepath.IsAbs(c.DataDir) {
		return errcode.New(errcode.SRVCfg002, "data_dir must be an absolute path, got %q", c.DataDir)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return errcode.New(errcode.SRVCfg002, "log.level must be debug, info, warn or error, got %q", c.Log.Level)
	}
	for name, addr := range map[string]string{"http.https_addr": c.HTTP.HTTPSAddr, "http.redirect_addr": c.HTTP.RedirectAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return errcode.New(errcode.SRVCfg002, "%s must be host:port, got %q", name, addr)
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return errcode.New(errcode.SRVCfg002, "tls.cert_file and tls.key_file must be set together")
	}
	if c.Gateway.PublicURL != "" {
		u, err := url.Parse(c.Gateway.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" {
			return errcode.New(errcode.SRVCfg002, "gateway.public_url must be an https URL without a path, got %q", c.Gateway.PublicURL)
		}
	}
	for _, h := range c.TLS.Hostnames {
		if strings.ContainsAny(h, " /@:") {
			return errcode.New(errcode.SRVCfg002, "tls.hostnames entry %q is not a bare host name or IP", h)
		}
	}
	return nil
}

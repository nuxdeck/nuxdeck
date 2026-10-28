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
	"strconv"
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
	Metrics Metrics `yaml:"metrics"`
	Secrets Secrets `yaml:"secrets"`
	Checks  Checks  `yaml:"checks"`
	// Server holds settings about the server as users reach it.
	Server Server `yaml:"server"`
	// Alerting tunes alert notifications (ALR-2, ALR-3).
	Alerting Alerting `yaml:"alerting"`
}

// Server describes how browsers reach nuxd.
type Server struct {
	// PublicURL is the https base URL users open, used for deep links in alert messages. Empty
	// means https://<host name of this machine>:<port of http.https_addr>.
	PublicURL string `yaml:"public_url"`
}

// Alerting tunes the notification queue and reminders.
type Alerting struct {
	// RepeatIntervalMinutes re-sends a still-firing, unacknowledged alert; 0 turns reminders off. Default 240.
	RepeatIntervalMinutes int `yaml:"repeat_interval_minutes"`
	// QueueSize bounds queued notifications; a full queue drops new ones. Default 256.
	QueueSize int `yaml:"queue_size"`
	// Workers is the number of concurrent deliveries. Default 4.
	Workers int `yaml:"workers"`
}

// Checks configures the uptime-check engine (UPT-1 to UPT-3).
type Checks struct {
	// BlockPrivate refuses private-range targets (RFC 1918, ULA, CGNAT) for every server-run
	// check, even those an operator marked allow_private.
	BlockPrivate bool `yaml:"block_private"`
	// MaxConcurrent bounds checks running at once on the server; 0 means 32.
	MaxConcurrent int `yaml:"max_concurrent"`
}

// Secrets configures the master key that seals stored secrets (T7). The key itself is
// never a setting: give it as NUXD_MASTER_KEY (base64, 32 bytes) or in a file.
type Secrets struct {
	// MasterKeyFile is an absolute path to a file holding the base64 master key, mode 0600.
	// Empty means <data_dir>/master.key, which nuxd creates on first start. Setting it together
	// with NUXD_MASTER_KEY is refused.
	MasterKeyFile string `yaml:"master_key_file"`
}

// Metrics configures retention of the embedded metrics store (MET-5).
type Metrics struct {
	// RetentionDays is how long samples are kept at full resolution.
	RetentionDays int `yaml:"retention_days"`
	// DownsampledRetentionDays is how long 5-minute averages are kept; at least RetentionDays.
	DownsampledRetentionDays int `yaml:"downsampled_retention_days"`
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
	// Addr is where the agent gateway listens.
	Addr string `yaml:"addr"`
	// PublicURL is the https URL agents dial (port 8444), embedded in enrolment tokens.
	// Empty means https://<host name of this machine>:8444.
	PublicURL string `yaml:"public_url"`
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		DataDir:  "/var/lib/nuxd",
		Log:      Log{Level: "info"},
		Gateway:  Gateway{Addr: ":8444"},
		HTTP:     HTTP{HTTPSAddr: ":8443", RedirectAddr: ":8080"},
		Metrics:  Metrics{RetentionDays: 15, DownsampledRetentionDays: 90},
		Alerting: Alerting{RepeatIntervalMinutes: 240, QueueSize: 256, Workers: 4},
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
	set(&cfg.Secrets.MasterKeyFile, "NUXD_MASTER_KEY_FILE")
	set(&cfg.Gateway.Addr, "NUXD_GATEWAY_ADDR")
	set(&cfg.Gateway.PublicURL, "NUXD_GATEWAY_PUBLIC_URL")
	set(&cfg.Server.PublicURL, "NUXD_PUBLIC_URL")
	if v := getenv("NUXD_CHECKS_BLOCK_PRIVATE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return errcode.New(errcode.SRVCfg002, "NUXD_CHECKS_BLOCK_PRIVATE must be true or false, got %q", v)
		}
		cfg.Checks.BlockPrivate = b
	}
	for name, dst := range map[string]*int{"NUXD_METRICS_RETENTION_DAYS": &cfg.Metrics.RetentionDays, "NUXD_METRICS_DOWNSAMPLED_RETENTION_DAYS": &cfg.Metrics.DownsampledRetentionDays} {
		if v := getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return errcode.New(errcode.SRVCfg002, "%s must be a whole number of days, got %q", name, v)
			}
			*dst = n
		}
	}

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
	for name, addr := range map[string]string{"http.https_addr": c.HTTP.HTTPSAddr, "http.redirect_addr": c.HTTP.RedirectAddr, "gateway.addr": c.Gateway.Addr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return errcode.New(errcode.SRVCfg002, "%s must be host:port, got %q", name, addr)
		}
	}
	if c.Metrics.RetentionDays < 1 || c.Metrics.RetentionDays > 3650 {
		return errcode.New(errcode.SRVCfg002, "metrics.retention_days must be from 1 to 3650, got %d", c.Metrics.RetentionDays)
	}
	if c.Metrics.DownsampledRetentionDays < c.Metrics.RetentionDays || c.Metrics.DownsampledRetentionDays > 3650 {
		return errcode.New(errcode.SRVCfg002, "metrics.downsampled_retention_days must be from metrics.retention_days to 3650, got %d", c.Metrics.DownsampledRetentionDays)
	}
	if c.Checks.MaxConcurrent < 0 || c.Checks.MaxConcurrent > 1024 {
		return errcode.New(errcode.SRVCfg002, "checks.max_concurrent must be from 0 to 1024, got %d", c.Checks.MaxConcurrent)
	}
	if c.Secrets.MasterKeyFile != "" && !filepath.IsAbs(c.Secrets.MasterKeyFile) {
		return errcode.New(errcode.SRVCfg002, "secrets.master_key_file must be an absolute path, got %q", c.Secrets.MasterKeyFile)
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
	if c.Server.PublicURL != "" {
		u, err := url.Parse(c.Server.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			return errcode.New(errcode.SRVCfg002, "server.public_url must be an https URL without a path, got %q", c.Server.PublicURL)
		}
	}
	if c.Alerting.RepeatIntervalMinutes < 0 || c.Alerting.RepeatIntervalMinutes > 10080 {
		return errcode.New(errcode.SRVCfg002, "alerting.repeat_interval_minutes must be from 0 to 10080, got %d", c.Alerting.RepeatIntervalMinutes)
	}
	if c.Alerting.QueueSize < 1 || c.Alerting.QueueSize > 100000 {
		return errcode.New(errcode.SRVCfg002, "alerting.queue_size must be from 1 to 100000, got %d", c.Alerting.QueueSize)
	}
	if c.Alerting.Workers < 1 || c.Alerting.Workers > 64 {
		return errcode.New(errcode.SRVCfg002, "alerting.workers must be from 1 to 64, got %d", c.Alerting.Workers)
	}
	for _, h := range c.TLS.Hostnames {
		if strings.ContainsAny(h, " /@:") {
			return errcode.New(errcode.SRVCfg002, "tls.hostnames entry %q is not a bare host name or IP", h)
		}
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nuxd.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadLayering(t *testing.T) {
	file := writeFile(t, "data_dir: /srv/nux\nlog:\n  level: warn\nhttp:\n  https_addr: \":9443\"\n")

	tests := []struct {
		name string
		env  map[string]string
		want func(Config) bool
	}{
		{"file overrides defaults", nil, func(c Config) bool {
			return c.DataDir == "/srv/nux" && c.Log.Level == "warn" && c.HTTP.HTTPSAddr == ":9443" && c.HTTP.RedirectAddr == ":8080"
		}},
		{"env overrides file", map[string]string{"NUXD_LOG_LEVEL": "debug", "NUXD_DATA_DIR": "/data"}, func(c Config) bool {
			return c.Log.Level == "debug" && c.DataDir == "/data" && c.HTTP.HTTPSAddr == ":9443"
		}},
		{"hostnames from env", map[string]string{"NUXD_TLS_HOSTNAMES": "a.example, b.example,"}, func(c Config) bool {
			return len(c.TLS.Hostnames) == 2 && c.TLS.Hostnames[1] == "b.example"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(file, true, env(tt.env))
			if err != nil {
				t.Fatal(err)
			}
			if !tt.want(cfg) {
				t.Errorf("unexpected config: %+v", cfg)
			}
		})
	}
}

func TestLoadDefaultsWhenImplicitFileMissing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), false, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.HTTPSAddr != ":8443" || cfg.DataDir != "/var/lib/nuxd" {
		t.Errorf("not the defaults: %+v", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		explicit bool
		body     string
		env      map[string]string
		want     errcode.Code
	}{
		{"explicit file missing", "/nonexistent/nuxd.yaml", true, "", nil, errcode.SRVCfg001},
		{"unknown key", "", true, "bogus: 1\n", nil, errcode.SRVCfg001},
		{"bad yaml", "", true, "data_dir: [\n", nil, errcode.SRVCfg001},
		{"relative data dir", "", true, "data_dir: data\n", nil, errcode.SRVCfg002},
		{"bad log level", "", true, "log:\n  level: loud\n", nil, errcode.SRVCfg002},
		{"bad address", "", true, "http:\n  https_addr: nope\n", nil, errcode.SRVCfg002},
		{"cert without key", "", true, "tls:\n  cert_file: /c.pem\n", nil, errcode.SRVCfg002},
		{"hostname with slash", "", true, "tls:\n  hostnames: [\"a/b\"]\n", nil, errcode.SRVCfg002},
		{"bad env override", "", true, "", map[string]string{"NUXD_LOG_LEVEL": "loud"}, errcode.SRVCfg002},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = writeFile(t, tt.body)
			}
			_, err := Load(path, tt.explicit, env(tt.env))
			if got := errcode.CodeOf(err); got != tt.want {
				t.Fatalf("code = %q (err %v), want %q", got, err, tt.want)
			}
		})
	}
}

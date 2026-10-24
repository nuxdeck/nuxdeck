// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func noConfigDir() (string, error) { return "", errors.New("no home") }

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolvePrecedence(t *testing.T) {
	file := writeConfig(t, "server: https://file.example\nlog_level: warn\n")

	tests := []struct {
		name       string
		flags      Flags
		env        map[string]string
		wantServer string
		wantLevel  string
	}{
		{"defaults", Flags{}, nil, DefaultServer, "info"},
		{"file", Flags{Config: file}, nil, "https://file.example", "warn"},
		{"env beats file", Flags{Config: file}, map[string]string{"NUX_SERVER": "https://env.example", "NUX_LOG_LEVEL": "debug"}, "https://env.example", "debug"},
		{"flag beats env", Flags{Config: file, Server: "https://flag.example"}, map[string]string{"NUX_SERVER": "https://env.example"}, "https://flag.example", "warn"},
		{"config from env var", Flags{}, map[string]string{"NUX_CONFIG": file}, "https://file.example", "warn"},
		{"http allowed for localhost", Flags{Server: "http://localhost:8443"}, nil, "http://localhost:8443", "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.flags, env(tt.env), noConfigDir)
			if err != nil {
				t.Fatal(err)
			}
			if got.Server != tt.wantServer || got.LogLevel != tt.wantLevel {
				t.Errorf("got %+v, want server %q level %q", got, tt.wantServer, tt.wantLevel)
			}
		})
	}
}

func TestResolveUsesUserConfigDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nux"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nux", "config.yaml"), []byte("server: https://home.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(Flags{}, env(nil), func() (string, error) { return dir, nil })
	if err != nil || got.Server != "https://home.example" {
		t.Errorf("got %+v, err %v", got, err)
	}
}

func TestResolveErrors(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		env   map[string]string
	}{
		{"explicit file missing", Flags{Config: "/nonexistent/config.yaml"}, nil},
		{"unknown key", Flags{Config: writeConfig(t, "bogus: 1\n")}, nil},
		{"credentials in url", Flags{Server: "https://user:pw@host"}, nil}, //nolint:gosec // deliberately invalid URL under test
		{"plain http to remote host", Flags{Server: "http://nux.example"}, nil},
		{"not a url", Flags{Server: "nux.example"}, nil},
		{"bad log level", Flags{}, map[string]string{"NUX_LOG_LEVEL": "loud"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(tt.flags, env(tt.env), noConfigDir)
			if got := errcode.CodeOf(err); got != errcode.CLIArg002 {
				t.Fatalf("code = %q (err %v), want %q", got, err, errcode.CLIArg002)
			}
		})
	}
}

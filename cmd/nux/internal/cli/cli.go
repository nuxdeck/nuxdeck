// SPDX-License-Identifier: Apache-2.0

// Package cli holds the flag and config handling shared by every nux command.
// Precedence, highest first: flag, NUX_* environment variable, config file,
// built-in default.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// DefaultServer is where nux looks for nuxd when nothing else is configured.
const DefaultServer = "https://localhost:8443"

// Flags are the global flags; empty means "not set".
type Flags struct {
	Config   string
	Server   string
	LogLevel string
}

// Register adds the global flags to fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Config, "config", "", "path to the nux config file (default: the user config directory, nux/config.yaml)")
	fs.StringVar(&f.Server, "server", "", "nuxd URL (default "+DefaultServer+")")
	fs.StringVar(&f.LogLevel, "log-level", "", "log level: debug, info, warn or error (default info)")
}

// Settings are the resolved values.
type Settings struct {
	Server   string
	LogLevel string
}

type fileConfig struct {
	Server   string `yaml:"server"`
	LogLevel string `yaml:"log_level"`
}

// Resolve merges the flags, environment and config file into Settings.
func Resolve(f Flags, getenv func(string) string, userConfigDir func() (string, error)) (Settings, error) {
	s := Settings{Server: DefaultServer, LogLevel: "info"}

	path, explicit := f.Config, f.Config != ""
	if !explicit {
		if path, explicit = getenv("NUX_CONFIG"), getenv("NUX_CONFIG") != ""; !explicit {
			if dir, err := userConfigDir(); err == nil {
				path = filepath.Join(dir, "nux", "config.yaml")
			}
		}
	}
	if path != "" {
		fc, err := readFile(path, explicit)
		if err != nil {
			return Settings{}, err
		}
		override(&s.Server, fc.Server)
		override(&s.LogLevel, fc.LogLevel)
	}

	override(&s.Server, getenv("NUX_SERVER"))
	override(&s.LogLevel, getenv("NUX_LOG_LEVEL"))
	override(&s.Server, f.Server)
	override(&s.LogLevel, f.LogLevel)

	return s, s.validate()
}

func override(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func readFile(path string, explicit bool) (fileConfig, error) {
	var fc fileConfig
	data, err := os.ReadFile(path) //nolint:gosec // user-supplied configuration path
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return fc, nil
	}
	if err != nil {
		return fc, errcode.Wrap(errcode.CLIArg002, "read config "+path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
		return fc, errcode.Wrap(errcode.CLIArg002, "parse config "+path, err)
	}
	return fc, nil
}

func (s Settings) validate() error {
	u, err := url.Parse(s.Server)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return errcode.New(errcode.CLIArg002, "server must be an http(s) URL without credentials, got %q", s.Server)
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return errcode.New(errcode.CLIArg002, "plain http is only allowed for localhost, got %q", s.Server)
	}
	switch s.LogLevel {
	case "debug", "info", "warn", "error":
		return nil
	}
	return errcode.New(errcode.CLIArg002, "log level must be debug, info, warn or error, got %q", s.LogLevel)
}

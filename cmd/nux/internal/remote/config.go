// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

const (
	configDirMode  = 0o700
	configFileMode = 0o600
)

// Config is the sign-in state written by nux login. The token is kept in clear text because
// nux runs unattended on servers; the file is created 0600 inside a 0700 directory and nux
// warns when the mode is looser.
type Config struct {
	Server string `json:"server,omitempty"`
	Token  string `json:"token,omitempty"`
	CAFile string `json:"ca_file,omitempty"`
	Pin    string `json:"pin,omitempty"`
}

// ConfigPath returns $XDG_CONFIG_HOME/nux/config.json, falling back to the user config directory.
func ConfigPath(getenv func(string) string, userConfigDir func() (string, error)) (string, error) {
	dir := getenv("XDG_CONFIG_HOME")
	if dir == "" {
		d, err := userConfigDir()
		if err != nil {
			return "", errcode.Wrap(errcode.CLICfg001, "locate the config directory", err)
		}
		dir = d
	}
	return filepath.Join(dir, "nux", "config.json"), nil
}

// LoadConfig reads the config file. A missing file is not an error; found reports whether it exists.
func LoadConfig(path string) (cfg Config, found bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the user's own config file
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, errcode.Wrap(errcode.CLICfg001, "read "+path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, true, errcode.Wrap(errcode.CLICfg001, "parse "+path, err)
	}
	return cfg, true, nil
}

// SaveConfig writes cfg atomically: a temporary file in the same directory is renamed over the old one.
func SaveConfig(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, configDirMode); err != nil {
		return errcode.Wrap(errcode.CLICfg001, "create "+dir, err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return errcode.Wrap(errcode.CLICfg001, "encode config", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return errcode.Wrap(errcode.CLICfg001, "create temporary config in "+dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(configFileMode); err != nil {
		_ = tmp.Close()
		return errcode.Wrap(errcode.CLICfg001, "restrict "+tmp.Name(), err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return errcode.Wrap(errcode.CLICfg001, "write temporary config", err)
	}
	if err := tmp.Close(); err != nil {
		return errcode.Wrap(errcode.CLICfg001, "close temporary config", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errcode.Wrap(errcode.CLICfg001, "replace "+path, err)
	}
	return nil
}

// RemoveConfig deletes the config file; a missing file is not an error.
func RemoveConfig(path string) (removed bool, err error) {
	err = os.Remove(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, errcode.Wrap(errcode.CLICfg001, "remove "+path, err)
	}
}

// LooseMode reports whether group or other can access the file.
func LooseMode(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&0o077 != 0
}

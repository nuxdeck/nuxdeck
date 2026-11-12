// SPDX-License-Identifier: AGPL-3.0-only

package secrets_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func b64(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

func TestMasterKeyGeneratedOnFirstStart(t *testing.T) {
	dir := t.TempDir()
	key, created, err := secrets.LoadMasterKey(dir, "", env(nil))
	if err != nil || !created || len(key) != secrets.KeyLen {
		t.Fatalf("first start: len %d created %v err %v", len(key), created, err)
	}
	path := filepath.Join(dir, "master.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
	again, created, err := secrets.LoadMasterKey(dir, "", env(nil))
	if err != nil || created || string(again) != string(key) {
		t.Fatalf("second start: created %v err %v same %v", created, err, string(again) == string(key))
	}
}

func TestMasterKeyFileRefusesLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := secrets.LoadMasterKey(dir, "", env(nil)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "master.key")
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := secrets.LoadMasterKey(dir, "", env(nil))
		if errcode.CodeOf(err) != errcode.SRVSec001 {
			t.Errorf("mode %o accepted: %v", mode, err)
		}
	}
	// 0400 is stricter than 0600 and fine.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := secrets.LoadMasterKey(dir, "", env(nil)); err != nil {
		t.Errorf("mode 0400 refused: %v", err)
	}
}

func TestMasterKeyRejectsBadContent(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"short": b64(16), "long": b64(33), "not base64": "!!!not-base64!!!", "empty": "", "raw bytes": strings.Repeat("\xff", 32),
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := secrets.LoadMasterKey(dir, path, env(nil))
		if errcode.CodeOf(err) != errcode.SRVSec001 {
			t.Errorf("%s accepted: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), body) && body != "" {
			t.Errorf("%s: error text leaks the file content", name)
		}
	}
	if _, _, err := secrets.LoadMasterKey(dir, dir, env(nil)); errcode.CodeOf(err) != errcode.SRVSec001 {
		t.Errorf("directory accepted as key file: %v", err)
	}
	if _, _, err := secrets.LoadMasterKey(dir, filepath.Join(dir, "missing"), env(nil)); err == nil {
		t.Error("a configured but missing key file must not be auto-generated")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing configured key file was created")
	}
}

func TestMasterKeyFromEnvironmentAndConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	want := make([]byte, secrets.KeyLen)
	for i := range want {
		want[i] = byte(i)
	}
	enc := base64.StdEncoding.EncodeToString(want)

	key, created, err := secrets.LoadMasterKey(dir, "", env(map[string]string{secrets.EnvMasterKey: enc}))
	if err != nil || created || string(key) != string(want) {
		t.Fatalf("env: %v created %v", err, created)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); err == nil {
		t.Error("master.key generated although the environment supplied a key")
	}
	if _, _, err := secrets.LoadMasterKey(dir, "", env(map[string]string{secrets.EnvMasterKey: b64(8)})); errcode.CodeOf(err) != errcode.SRVSec001 {
		t.Errorf("short env key accepted: %v", err)
	}

	path := filepath.Join(dir, "custom.key")
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _, err = secrets.LoadMasterKey(dir, path, env(nil))
	if err != nil || string(key) != string(want) {
		t.Fatalf("file: %v", err)
	}
	_, _, err = secrets.LoadMasterKey(dir, path, env(map[string]string{secrets.EnvMasterKey: enc}))
	if errcode.CodeOf(err) != errcode.SRVSec001 {
		t.Errorf("env and file together accepted: %v", err)
	}
}

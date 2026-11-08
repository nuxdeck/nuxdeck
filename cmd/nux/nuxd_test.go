// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func TestRunNuxdForwardsExitCode(t *testing.T) {
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true binary")
	}
	falseBin, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false binary")
	}
	var out, errOut bytes.Buffer
	env := func(k string) string {
		if k == "NUX_NUXD_BIN" {
			return trueBin
		}
		return ""
	}
	if code := runNuxd(context.Background(), "backup", []string{"--out", "x"}, &bytes.Buffer{}, &out, &errOut, env); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	env = func(k string) string {
		if k == "NUX_NUXD_BIN" {
			return falseBin
		}
		return ""
	}
	if code := runNuxd(context.Background(), "restore", nil, &bytes.Buffer{}, &out, &errOut, env); code != 1 {
		t.Fatalf("exit %d, want the child's 1", code)
	}
}

func TestRunNuxdReportsMissingBinary(t *testing.T) {
	var errOut bytes.Buffer
	env := func(k string) string {
		if k == "NUX_NUXD_BIN" {
			return filepath.Join(t.TempDir(), "absent")
		}
		return ""
	}
	code := runNuxd(context.Background(), "backup", nil, &bytes.Buffer{}, &bytes.Buffer{}, &errOut, env)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !bytes.Contains(errOut.Bytes(), []byte(string(errcode.CLINuxd001))) {
		t.Fatalf("stderr %q does not carry %s", errOut.String(), errcode.CLINuxd001)
	}
}

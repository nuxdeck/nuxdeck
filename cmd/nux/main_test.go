// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

func TestRun(t *testing.T) {
	noEnv := func(string) string { return "" }
	tests := []struct {
		name       string
		args       []string
		env        func(string) string
		wantCode   int
		wantOut    string
		wantStderr string
	}{
		{"version", []string{"version"}, noEnv, 0, "nux dev", ""},
		{"global flag before command", []string{"--server", "https://x.example", "version"}, noEnv, 0, "nux dev", ""},
		{"no command", nil, noEnv, 2, "", string(errcode.CLIArg001)},
		{"unknown command", []string{"frobnicate"}, noEnv, 2, "", string(errcode.CLIArg001)},
		{"agent needs a subcommand", []string{"agent"}, noEnv, 2, "", string(errcode.CLIArg001)},
		{"login needs a token source", []string{"login"}, noEnv, 2, "", string(errcode.CLIArg002)},
		{"help lists remote commands", []string{"help"}, noEnv, 0, "Exit codes", ""},
		{"bad shared setting", []string{"agent"}, func(k string) string {
			if k == "NUX_SERVER" {
				return "not a url"
			}
			return ""
		}, 2, "", string(errcode.CLIArg002)},
		{"unknown flag", []string{"--nope", "version"}, noEnv, 2, "", ""},
		{"help", []string{"-h"}, noEnv, 0, "", "Usage: nux"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), tt.args, strings.NewReader(""), &out, &errOut, tt.env)
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d (stderr %q)", code, tt.wantCode, errOut.String())
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout %q lacks %q", out.String(), tt.wantOut)
			}
			if !strings.Contains(errOut.String(), tt.wantStderr) {
				t.Errorf("stderr %q lacks %q", errOut.String(), tt.wantStderr)
			}
		})
	}
}

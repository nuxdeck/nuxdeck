// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// runNuxd forwards `nux backup` and `nux restore` to nuxd. Only nuxd can read the server data
// directory and the master key, and the archive logic must stay in one place (NFR-6). nux is
// Apache-2.0 and must not import the AGPL server packages, so it delegates instead. Arguments
// and standard streams pass through unchanged, and the exit code is nuxd's.
func runNuxd(ctx context.Context, sub string, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	bin := getenv("NUX_NUXD_BIN")
	if bin == "" {
		found, err := exec.LookPath("nuxd")
		if err != nil {
			return fail(stderr, errcode.Wrap(errcode.CLINuxd001, "look up nuxd", err), 1)
		}
		bin = found
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{sub}, args...)...) //nolint:gosec // the operator chooses the binary
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		return fail(stderr, errcode.Wrap(errcode.CLINuxd001, "run nuxd "+sub, err), 1)
	}
	return 0
}

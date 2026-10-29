// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"regexp"
	"strconv"
)

var agentIDPattern = regexp.MustCompile(`^[0-9A-Z]{26}$`)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

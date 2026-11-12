// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// reading is one value a collector observed. Counters are raw and get reset handling in the Service.
type reading struct {
	target  agentv1.TargetKind
	id      string
	metric  string
	labels  map[string]string
	value   float64
	counter bool
}

func lbl(kv ...string) map[string]string {
	if len(kv) == 0 {
		return nil
	}
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func (r reading) key() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d|%s|%s", r.target, r.id, r.metric)
	// labels are tiny; a sorted join keeps the key stable
	keys := make([]string, 0, len(r.labels))
	for k := range r.labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString("|" + k + "=" + r.labels[k])
	}
	return sb.String()
}

// readFile reads a small file (bounded); nothing under Root is ever opened for writing.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // collectors pass fixed names below the configured root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	const limit = 8 << 20
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

func parseU(s string) (float64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return float64(v), err
}

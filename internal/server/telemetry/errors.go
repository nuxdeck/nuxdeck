// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"regexp"
	"sort"
	"sync"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// maxErrorCodes is the spec's cap on distinct codes per report.
const maxErrorCodes = 10

var codeShape = regexp.MustCompile(`^[A-Z]{2,4}-[A-Z]{2,6}-[0-9]{3}$`)

// Counter tallies error codes since the last successful report. It never sees a message.
type Counter struct {
	mu     sync.Mutex
	counts map[string]int
}

// Record counts one occurrence. Anything that is not shaped like a registered code is dropped,
// so free text can never reach a report.
func (c *Counter) Record(code errcode.Code) {
	s := string(code)
	if !codeShape.MatchString(s) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[s]++
}

// Top returns up to ten codes with the highest counts.
func (c *Counter) Top() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.counts))
	for k := range c.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c.counts[keys[i]] != c.counts[keys[j]] {
			return c.counts[keys[i]] > c.counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > maxErrorCodes {
		keys = keys[:maxErrorCodes]
	}
	out := make(map[string]int, len(keys))
	for _, k := range keys {
		out[k] = c.counts[k]
	}
	return out
}

// Reset starts a new window after a report was delivered.
func (c *Counter) Reset() {
	c.mu.Lock()
	c.counts = nil
	c.mu.Unlock()
}

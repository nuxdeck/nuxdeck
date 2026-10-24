// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"sync"
)

// syncBuffer lets a test read logs while the server goroutine writes them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

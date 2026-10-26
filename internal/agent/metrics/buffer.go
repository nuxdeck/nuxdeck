// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	// Retention is how long unsent samples are kept (AGT-5).
	Retention = 15 * time.Minute
	// DefaultMaxSamples bounds memory: about 24 bytes a sample, so roughly 14 MB.
	DefaultMaxSamples = 600_000
	// MaxBatchBytes keeps each MetricBatch well under the 1 MB split limit.
	MaxBatchBytes = 900 << 10

	perPointBytes  = 22 // two tags, a varint timestamp (up to 9 bytes) and a double
	perSeriesExtra = 16 // list framing and slack around the series header
)

type seriesID struct {
	target agentv1.TargetKind
	id     string
	metric string
	labels map[string]string
	header int // encoded size of the series without points
}

type sample struct {
	s  *seriesID
	ts int64
	v  float64
}

// Buffer is a bounded FIFO of samples that have not been sent yet.
type Buffer struct {
	mu        sync.Mutex
	now       func() time.Time
	retention time.Duration
	max       int
	samples   []sample
	head      int
	base      uint64 // sequence number of samples[head]
	dropped   uint64
}

// NewBuffer creates a buffer; zero arguments take the defaults.
func NewBuffer(retention time.Duration, maxSamples int, now func() time.Time) *Buffer {
	if retention <= 0 {
		retention = Retention
	}
	if maxSamples <= 0 {
		maxSamples = DefaultMaxSamples
	}
	if now == nil {
		now = time.Now
	}
	return &Buffer{retention: retention, max: maxSamples, now: now}
}

func (b *Buffer) len() int { return len(b.samples) - b.head }

// Len is the number of buffered samples.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.len()
}

// Dropped counts samples discarded because of age or overflow.
func (b *Buffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

func (b *Buffer) push(in []sample) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.samples = append(b.samples, in...)
	b.dropLocked(b.len() - b.max)
	cutoff := b.now().Add(-b.retention).UnixMilli()
	n := sort.Search(b.len(), func(i int) bool { return b.samples[b.head+i].ts >= cutoff })
	b.dropLocked(n)
	if b.head > 4096 && b.head > len(b.samples)/2 { // reclaim the dropped prefix
		b.samples = append([]sample(nil), b.samples[b.head:]...)
		b.head = 0
	}
}

func (b *Buffer) dropLocked(n int) {
	if n <= 0 {
		return
	}
	b.head += n
	b.base += uint64(n)
	b.dropped += uint64(n)
}

// next builds the oldest batch of samples that is homogeneous in replay state: samples
// older than replayBefore (unix ms) are replayed, newer ones live. It returns nil when empty.
// commit removes exactly the samples in the batch, even if more arrived meanwhile.
func (b *Buffer) next(replayBefore int64) (batch *agentv1.MetricBatch, commit func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.len() == 0 {
		return nil, nil
	}
	replayed := b.samples[b.head].ts < replayBefore
	batch = &agentv1.MetricBatch{Replayed: replayed}
	index := map[*seriesID]*agentv1.Series{}
	size, n := 0, 0
	for _, sm := range b.samples[b.head:] {
		if (sm.ts < replayBefore) != replayed {
			break
		}
		ser, ok := index[sm.s]
		cost := perPointBytes
		if !ok {
			cost += sm.s.header + perSeriesExtra
		}
		if size+cost > MaxBatchBytes && n > 0 {
			break
		}
		if !ok {
			ser = &agentv1.Series{
				Target: &agentv1.Target{Kind: sm.s.target, Id: sm.s.id}, Metric: sm.s.metric, Labels: sm.s.labels,
			}
			index[sm.s] = ser
			batch.Series = append(batch.Series, ser)
		}
		ser.Points = append(ser.Points, &agentv1.Point{TsUnixMs: sm.ts, Value: sm.v})
		size += cost
		n++
	}
	end := b.base + uint64(n)
	return batch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if end > b.base {
			k := int(end - b.base) //nolint:gosec // bounded by the buffer length
			b.head += k
			b.base = end
		}
	}
}

func newSeriesID(target agentv1.TargetKind, id, metric string, labels map[string]string) *seriesID {
	s := &seriesID{target: target, id: id, metric: metric, labels: labels}
	s.header = proto.Size(&agentv1.Series{Target: &agentv1.Target{Kind: target, Id: id}, Metric: metric, Labels: labels})
	return s
}

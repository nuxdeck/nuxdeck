// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"os"
	"runtime"
	runtimemetrics "runtime/metrics"
	"syscall"
	"testing"
	"time"
)

// NFR-1 says the whole agent stays under 40 MB of RAM and under 1% of one core at 15-second
// collection. The collectors are most of the agent's steady-state work, so these tests measure
// them alone, on the fixture host, with the buffer drained every cycle as a connected agent does.
const (
	budgetCadence   = 15 * time.Second
	budgetWarmup    = 20
	budgetCycles    = 400
	budgetDutyCycle = 0.01    // CPU seconds per cycle divided by the cadence
	budgetHeapBytes = 8 << 20 // collectors' heap in use after steady state; the agent's whole budget is 40 MB
	budgetAllocs    = 1500    // heap allocations per cycle; deterministic, so the ceiling is tight
)

// steadyCycler runs collection cycles on a simulated clock that advances one cadence per cycle.
type steadyCycler struct {
	s   *Service
	now time.Time
}

func newSteadyCycler(t testing.TB) *steadyCycler {
	t.Helper()
	c := &steadyCycler{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
	c.s = New(Config{Root: budgetRoot(t), Containers: running, statfs: fakeStatfs, Now: func() time.Time { return c.now }})
	return c
}

// cycle is one 15-second collection followed by the stream taking the batch.
func (c *steadyCycler) cycle() {
	c.now = c.now.Add(budgetCadence)
	c.s.Tick(context.Background())
	if _, commit := c.s.Next(time.Time{}); commit != nil {
		commit()
	}
}

// budgetRoot copies the fixture host so the benchmark owns its files.
func budgetRoot(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/root")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func processCPU(t testing.TB) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// heapInUse returns live heap object bytes after a full collection.
func heapInUse() uint64 {
	runtime.GC()
	sample := []runtimemetrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	runtimemetrics.Read(sample)
	return sample[0].Value.Uint64()
}

// TestNFR1_CollectorSteadyStateBudget fails when the collectors cost more than their share of NFR-1.
// CPU is measured as process CPU time, not wall time, and the race detector is excluded because it
// multiplies CPU and allocations; make bench runs this test without -race.
func TestNFR1_CollectorSteadyStateBudget(t *testing.T) {
	if raceEnabled {
		t.Skip("CPU and allocation budgets are not meaningful under -race; make bench runs them")
	}
	c := newSteadyCycler(t)
	for range budgetWarmup {
		c.cycle()
	}

	before := processCPU(t)
	for range budgetCycles {
		c.cycle()
	}
	cpuPerCycle := (processCPU(t) - before) / budgetCycles
	duty := cpuPerCycle.Seconds() / budgetCadence.Seconds()
	heap := heapInUse()
	allocs := testing.AllocsPerRun(10, c.cycle)

	t.Logf("collectors: %.3f ms CPU per cycle, duty cycle %.4f%% of a core, heap in use %.2f MiB, %.0f allocs per cycle",
		float64(cpuPerCycle)/float64(time.Millisecond), duty*100, float64(heap)/(1<<20), allocs)
	if duty >= budgetDutyCycle {
		t.Errorf("collector duty cycle %.4f%% of a core at a 15 s cadence; ceiling is %.2f%% (NFR-1 allows 1%%)", duty*100, budgetDutyCycle*100)
	}
	if heap >= budgetHeapBytes {
		t.Errorf("collector heap in use %d bytes after steady state; budget is %d", heap, budgetHeapBytes)
	}
	if allocs > budgetAllocs {
		t.Errorf("%.0f allocations per collection cycle; ceiling is %d", allocs, budgetAllocs)
	}
}

// BenchmarkCollectCycle reports the cost of one 15-second cycle on the fixture host.
func BenchmarkCollectCycle(b *testing.B) {
	c := newSteadyCycler(b)
	for range budgetWarmup {
		c.cycle()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		c.cycle()
	}
}

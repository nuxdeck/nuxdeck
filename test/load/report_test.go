// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	var samples []time.Duration
	for i := 1; i <= 100; i++ {
		samples = append(samples, time.Duration(i)*time.Millisecond)
	}
	if got := percentile(samples, 0.95); got != 95*time.Millisecond {
		t.Errorf("p95 of 1..100 ms = %v, want 95ms", got)
	}
	if got := percentile(samples, 0.50); got != 50*time.Millisecond {
		t.Errorf("p50 = %v, want 50ms", got)
	}
	if got := percentile([]time.Duration{7 * time.Millisecond}, 0.95); got != 7*time.Millisecond {
		t.Errorf("single sample p95 = %v", got)
	}
	if got := percentile(nil, 0.95); got != 0 {
		t.Errorf("empty p95 = %v, want 0", got)
	}
}

func TestPercentileDoesNotReorderInput(t *testing.T) {
	in := []time.Duration{3, 1, 2}
	percentile(in, 0.5)
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Errorf("input was reordered: %v", in)
	}
}

// NFR-2 and NFR-4: a ceiling passes at the limit and fails above it; a floor fails below.
func TestAssertionDirections(t *testing.T) {
	if !newAssertion("NFR-2", "rss", "MiB", 512, 512, true).Pass {
		t.Error("value at a ceiling must pass")
	}
	if newAssertion("NFR-2", "rss", "MiB", 512.1, 512, true).Pass {
		t.Error("value above a ceiling must fail")
	}
	if newAssertion("NUX-44", "agents", "agents", 199, 200, false).Pass {
		t.Error("count below a floor must fail")
	}
	if !newAssertion("NUX-44", "agents", "agents", 200, 200, false).Pass {
		t.Error("count at a floor must pass")
	}
}

// NFR-4 budget: GOMAXPROCS above 2 vCPU fails, so a misconfigured run cannot pass as the 2 vCPU point.
func TestNFR4BudgetRejectsWrongGOMAXPROCS(t *testing.T) {
	p := PhaseReport{RSSPeakMiB: 100, CPUCoresAvg: 1, APIP95Ms: 10}
	nfr4Budgets(&p, 32)
	for _, a := range p.Assertions {
		if a.Name == "GOMAXPROCS applied to nuxd" && a.Pass {
			t.Fatal("GOMAXPROCS=32 passed the 2 vCPU budget")
		}
	}
}

func TestCountLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nuxd.log")
	body := "{\"msg\":\"dropping metric data\"}\nother\n{\"msg\":\"dropping metric data\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := countLines(path, "dropping metric data"); got != 2 {
		t.Errorf("countLines = %d, want 2", got)
	}
	if got := countLines(filepath.Join(t.TempDir(), "missing"), "x"); got != 0 {
		t.Errorf("missing log counted %d", got)
	}
}

func TestProfilePhases(t *testing.T) {
	smoke, err := profilePhases(options{profile: "smoke"})
	if err != nil || len(smoke) != 1 || smoke[0].agents != 20 || smoke[0].checks != 100 || smoke[0].window != 30*time.Second {
		t.Fatalf("smoke profile = %+v, %v", smoke, err)
	}
	full, err := profilePhases(options{profile: "full"})
	if err != nil || len(full) != 2 || full[0].agents != 50 || full[0].checks != 200 || full[1].agents != 200 || full[1].checks != 1000 {
		t.Fatalf("full profile = %+v, %v", full, err)
	}
	if _, err := profilePhases(options{profile: "bogus"}); err == nil {
		t.Error("unknown profile accepted")
	}
}

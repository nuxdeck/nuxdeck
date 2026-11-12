// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"time"
)

const (
	mib = 1 << 20
	kib = 1 << 10
)

// Assertion is one pass/fail line in the report. Limit and Value share Unit.
type Assertion struct {
	Requirement string  `json:"requirement"`
	Name        string  `json:"name"`
	Unit        string  `json:"unit"`
	Value       float64 `json:"value"`
	Limit       float64 `json:"limit"`
	// AtMost is true for ceilings (memory, latency) and false for floors (agents connected).
	AtMost bool `json:"at_most"`
	Pass   bool `json:"pass"`
}

// newAssertion builds a ceiling or floor check and sets Pass.
func newAssertion(req, name, unit string, value, limit float64, atMost bool) Assertion {
	pass := value >= limit
	if atMost {
		pass = value <= limit
	}
	return Assertion{Requirement: req, Name: name, Unit: unit, Value: value, Limit: limit, AtMost: atMost, Pass: pass}
}

// PhaseReport is the outcome of one ramp step.
type PhaseReport struct {
	Name             string  `json:"name"`
	Agents           int     `json:"agents_target"`
	AgentsOnline     int     `json:"agents_online_server"`
	AgentsConnected  int64   `json:"agents_connected_harness"`
	Containers       int     `json:"containers"`
	Checks           int     `json:"checks_target"`
	ChecksWithResult int     `json:"checks_with_result"`
	WindowSeconds    float64 `json:"window_seconds"`
	RSSPeakMiB       float64 `json:"rss_peak_mib"`
	RSSFinalMiB      float64 `json:"rss_final_mib"`
	CPUCoresAvg      float64 `json:"cpu_cores_avg"`
	CPUCoresPeak     float64 `json:"cpu_cores_peak"`
	APIRequests      int     `json:"api_requests"`
	APIErrors        int     `json:"api_errors"`
	APIP50Ms         float64 `json:"api_p50_ms"`
	APIP95Ms         float64 `json:"api_p95_ms"`
	AgentMetricBatch uint64  `json:"agent_metric_batches"`
	AgentHeartbeats  uint64  `json:"agent_heartbeats"`
	AgentEvents      uint64  `json:"agent_inventory_events"`
	AgentStreamErrs  uint64  `json:"agent_stream_errors"`
	// MetricDropLogs counts server log lines reporting dropped metric data, one per agent and reason.
	MetricDropLogs int           `json:"metric_drop_log_lines"`
	Assertions     []Assertion   `json:"assertions"`
	Pass           bool          `json:"pass"`
	Elapsed        time.Duration `json:"-"`
}

// Report is the whole run.
type Report struct {
	Profile    string        `json:"profile"`
	TimeScale  float64       `json:"time_scale"`
	GOMAXPROCS int           `json:"gomaxprocs"`
	StartedAt  time.Time     `json:"started_at"`
	Phases     []PhaseReport `json:"phases"`
	Pass       bool          `json:"pass"`
	Notes      []string      `json:"notes"`
}

func (r *Report) finish() {
	r.Pass = len(r.Phases) > 0
	for _, p := range r.Phases {
		r.Pass = r.Pass && p.Pass
	}
}

// writeHuman prints a table a person can read in a terminal.
func (r *Report) writeHuman(w io.Writer) {
	out := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	out("nux load report: profile=%s time-scale=%g GOMAXPROCS=%d started=%s\n",
		r.Profile, r.TimeScale, r.GOMAXPROCS, r.StartedAt.Format(time.RFC3339))
	for _, p := range r.Phases {
		out("\n== phase %s: %d agents (%d containers), %d checks, window %.0fs\n",
			p.Name, p.Agents, p.Containers, p.Checks, p.WindowSeconds)
		out("   agents online (server) %d, connected (harness) %d, checks with a result %d/%d\n",
			p.AgentsOnline, p.AgentsConnected, p.ChecksWithResult, p.Checks)
		out("   nuxd RSS peak %.1f MiB, final %.1f MiB; CPU avg %.2f cores, peak %.2f cores\n",
			p.RSSPeakMiB, p.RSSFinalMiB, p.CPUCoresAvg, p.CPUCoresPeak)
		out("   API %d requests, %d errors, p50 %.1f ms, p95 %.1f ms\n",
			p.APIRequests, p.APIErrors, p.APIP50Ms, p.APIP95Ms)
		out("   agent traffic (cumulative since start): %d metric batches, %d heartbeats, %d inventory events, %d stream errors\n",
			p.AgentMetricBatch, p.AgentHeartbeats, p.AgentEvents, p.AgentStreamErrs)
		for _, a := range p.Assertions {
			verdict := "PASS"
			if !a.Pass {
				verdict = "FAIL"
			}
			op := ">="
			if a.AtMost {
				op = "<="
			}
			out("   [%s] %-8s %-34s %.2f %s %s %.2f %s\n",
				verdict, a.Requirement, a.Name, a.Value, a.Unit, op, a.Limit, a.Unit)
		}
	}
	for _, n := range r.Notes {
		out("note: %s\n", n)
	}
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	out("\nresult: %s\n", verdict)
}

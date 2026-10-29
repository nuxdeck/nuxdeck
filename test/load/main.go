// SPDX-License-Identifier: Apache-2.0

// Command load drives a real nuxd with simulated agents and checks, then measures the
// server against the NFR-2 (512 MB at 50 agents, 500 containers, 200 checks) and NFR-4
// (200 agents and 1,000 checks on 2 vCPU and 4 GB) budgets.
//
// nuxd runs as a child process, so this harness links only the Apache-2.0 agent packages and
// never internal/server (ADR-006). Agents enrol and connect over real mutual TLS gRPC; their
// inventory and metrics are generated. Checks run on the server against a loopback listener.
//
// Usage: go run ./test/load -profile smoke   (or make load / make load-full)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	checkIntervalSeconds = 20 // the server's minimum
	checkSettleExtra     = 30 * time.Second
	onlineSettle         = 60 * time.Second
	smokeRSSCeilingMiB   = 512
	nfr2RSSCeilingMiB    = 512
	nfr4RSSCeilingMiB    = 4096
	nfr4VCPU             = 2
	apiP95CeilingMs      = 1000
)

// phaseSpec is one ramp step. Counts are totals after the step, so later steps add to earlier ones.
type phaseSpec struct {
	name   string
	agents int
	checks int
	window time.Duration
	// budgets adds the phase's NFR assertions to the common ones.
	budgets func(p *PhaseReport, gomaxprocs int)
}

// options are the parsed command-line settings.
type options struct {
	nuxd       string
	profile    string
	timeScale  float64
	gomaxprocs int
	containers int
	window     time.Duration
	workDir    string
	keep       bool
	jsonOut    string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.nuxd, "nuxd", "bin/nuxd", "path to the nuxd binary (make build produces it)")
	fs.StringVar(&o.profile, "profile", "smoke", "smoke (20 agents, 100 checks, 30 s) or full (50 then 200 agents, 200 then 1,000 checks)")
	fs.Float64Var(&o.timeScale, "time-scale", 1, "divide agent cadences (15 s collection, 10 s heartbeat, 60 s inventory event) by this factor")
	fs.IntVar(&o.gomaxprocs, "gomaxprocs", 2, "GOMAXPROCS for the child nuxd, matching the 2 vCPU budget")
	fs.IntVar(&o.containers, "containers-per-agent", 10, "containers each simulated host reports")
	fs.DurationVar(&o.window, "window", 0, "measurement window per phase (default: 30 s smoke, 5 min full)")
	fs.StringVar(&o.workDir, "work-dir", "", "directory for nuxd data and logs (default: a new temporary directory)")
	fs.BoolVar(&o.keep, "keep", false, "keep the work directory after the run")
	fs.StringVar(&o.jsonOut, "json", "-", "where to write the JSON report (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.timeScale <= 0 {
		_, _ = fmt.Fprintln(stderr, "load: --time-scale must be positive")
		return 2
	}
	phases, err := profilePhases(o)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "load:", err)
		return 2
	}

	rep := &Report{Profile: o.profile, TimeScale: o.timeScale, GOMAXPROCS: o.gomaxprocs, StartedAt: time.Now().UTC(), Notes: []string{
		"heap and goroutine counts are not exposed by nuxd; memory is sampled as RSS from /proc, CPU as utime+stime at USER_HZ=100",
		"simulated agents share one process and one host; their CPU is included in nuxd only through the server's own work",
	}}
	runErr := execute(ctx, o, phases, rep)
	if runErr != nil {
		rep.Notes = append(rep.Notes, "run aborted: "+runErr.Error())
	}
	rep.finish()
	if runErr != nil {
		rep.Pass = false
	}
	rep.writeHuman(stderr)
	if err := writeJSON(o.jsonOut, stdout, rep); err != nil {
		_, _ = fmt.Fprintln(stderr, "load: write report:", err)
		return 1
	}
	if !rep.Pass {
		return 1
	}
	return 0
}

// profilePhases returns the ramp for a profile; --window overrides every phase's window.
func profilePhases(o options) ([]phaseSpec, error) {
	switch o.profile {
	case "smoke":
		w := pick(o.window, 30*time.Second)
		return []phaseSpec{{name: "smoke", agents: 20, checks: 100, window: w, budgets: smokeBudgets}}, nil
	case "full":
		w := pick(o.window, 5*time.Minute)
		return []phaseSpec{
			{name: "nfr2", agents: 50, checks: 200, window: w, budgets: nfr2Budgets},
			{name: "nfr4", agents: 200, checks: 1000, window: w, budgets: nfr4Budgets},
		}, nil
	default:
		return nil, fmt.Errorf("unknown profile %q (want smoke or full)", o.profile)
	}
}

func pick(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// execute runs the whole scenario and appends one PhaseReport per step. A failure stops the run
// but keeps the phases already measured.
func execute(ctx context.Context, o options, phases []phaseSpec, rep *Report) error {
	workDir := o.workDir
	if workDir == "" {
		dir, err := os.MkdirTemp("", "nux-load-")
		if err != nil {
			return err
		}
		workDir = dir
		if !o.keep {
			defer func() { _ = os.RemoveAll(dir) }()
		}
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}

	srv, err := startNuxd(ctx, serverOptions{Binary: o.nuxd, WorkDir: workDir, GOMAXPROCS: o.gomaxprocs})
	if err != nil {
		return err
	}
	defer srv.Stop()
	api, err := newAPIClient(srv.BaseURL)
	if err != nil {
		return err
	}
	setup, err := srv.SetupToken(ctx)
	if err != nil {
		return err
	}
	if err := api.setupAdmin(ctx, setup); err != nil {
		return fmt.Errorf("setup admin: %w", err)
	}

	target, err := startTarget()
	if err != nil {
		return err
	}
	defer target.Close()

	fl := newFleet(ctx, workDir, o.containers, o.timeScale)
	defer fl.stop()
	checksCreated := 0
	for _, ph := range phases {
		start := time.Now()
		if err := fl.grow(ph.agents-fl.agents, api.newAgentToken); err != nil {
			return fmt.Errorf("phase %s: %w", ph.name, err)
		}
		if err := createChecks(ctx, api, target.Listener.Addr().(*net.TCPAddr), target.URL, ph.checks-checksCreated); err != nil {
			return fmt.Errorf("phase %s: %w", ph.name, err)
		}
		checksCreated = ph.checks

		online, onlineErr := awaitOnline(ctx, api, ph.agents)
		if onlineErr != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("phase %s: list online agents: %v", ph.name, onlineErr))
		}
		withResult := awaitChecks(ctx, api, ph.checks, time.Duration(2*checkIntervalSeconds)*time.Second+checkSettleExtra)
		win, err := measure(ctx, srv.Pid, api, readPaths, ph.window)
		if err != nil {
			return fmt.Errorf("phase %s: sample: %w", ph.name, err)
		}
		if err := fl.firstStreamError(); err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("phase %s: %v", ph.name, err))
		}
		pr := buildPhase(ph, fl, win, online, withResult, o.containers, o.gomaxprocs)
		pr.MetricDropLogs = countLines(filepath.Join(workDir, "nuxd.log"), "dropping metric data")
		pr.Elapsed = time.Since(start)
		rep.Phases = append(rep.Phases, pr)
	}
	return nil
}

// startTarget serves the checks' HTTP and TCP targets on a private, non-loopback address of this
// host. nuxd refuses loopback for server-run checks even with allow_private (pkg/probe Policy has
// AllowLoopback false and no API path sets it), so loopback cannot be the load target. A private
// RFC 1918 address is accepted when allow_private is set.
func startTarget() (*httptest.Server, error) {
	ip, err := privateIPv4()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", ip, err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	return ts, nil
}

// privateIPv4 returns the first RFC 1918 address on this host.
func privateIPv4() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() {
			return ipn.IP, nil
		}
	}
	return nil, errors.New("no private IPv4 address on this host; the check targets need one (loopback is refused for server-run checks)")
}

// readPaths are the list reads a dashboard makes; their latency is the API measurement.
var readPaths = []string{"/api/v1/hosts?limit=50", "/api/v1/checks?limit=50", "/api/v1/containers?limit=50"}

// createChecks adds n checks, alternating TCP and HTTP, all run by the server.
func createChecks(ctx context.Context, api *apiClient, addr *net.TCPAddr, base string, n int) error {
	for i := range n {
		name := fmt.Sprintf("load check %04d", i)
		body := map[string]any{
			"name": name, "runner": "server", "interval_s": checkIntervalSeconds, "timeout_s": 5,
			"retries": 0, "enabled": true, "allow_private": true,
		}
		if i%2 == 0 {
			body["type"] = "tcp"
			body["tcp"] = map[string]any{"host": addr.IP.String(), "port": addr.Port}
		} else {
			body["type"] = "http"
			body["http"] = map[string]any{"url": base + "/ok", "expected_status": []int{200}}
		}
		if _, err := api.createCheck(ctx, body); err != nil {
			return fmt.Errorf("create check %d: %w", i, err)
		}
	}
	return nil
}

// awaitOnline polls the server until it reports want hosts online or the settle time runs out.
// The last error is returned so a failing query is reported rather than read as zero agents.
func awaitOnline(ctx context.Context, api *apiClient, want int) (int, error) {
	deadline := time.Now().Add(onlineSettle)
	for {
		n, err := api.onlineHosts(ctx)
		if (err == nil && n >= want) || time.Now().After(deadline) || ctx.Err() != nil {
			return n, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// awaitChecks waits until want checks have a result, or the settle time runs out, and returns how many do.
func awaitChecks(ctx context.Context, api *apiClient, want int, settle time.Duration) int {
	deadline := time.Now().Add(settle)
	for {
		rows, err := listAll[checkRow](ctx, api, "/api/v1/checks")
		n := 0
		if err == nil {
			for _, r := range rows {
				if r.Status.LastChecked != nil {
					n++
				}
			}
		}
		if n >= want || time.Now().After(deadline) || ctx.Err() != nil {
			return n
		}
		time.Sleep(2 * time.Second)
	}
}

func buildPhase(ph phaseSpec, fl *fleet, win windowResult, online, withResult, containers, gomaxprocs int) PhaseReport {
	pr := PhaseReport{
		Name: ph.name, Agents: ph.agents, AgentsOnline: online, AgentsConnected: fl.stats.connected.Load(),
		Containers: ph.agents * containers, Checks: ph.checks, ChecksWithResult: withResult,
		WindowSeconds: win.Duration.Seconds(),
		RSSPeakMiB:    float64(win.RSSPeakKiB) / kib, RSSFinalMiB: float64(win.RSSFinalKiB) / kib,
		CPUCoresAvg: win.CPUCoresAvg, CPUCoresPeak: win.CPUCoresPeak,
		APIRequests: win.APIRequests, APIErrors: win.APIErrors,
		APIP50Ms:         ms(percentile(win.Latencies, 0.50)),
		APIP95Ms:         ms(percentile(win.Latencies, 0.95)),
		AgentMetricBatch: fl.stats.metricBatches.Load(), AgentHeartbeats: fl.stats.heartbeats.Load(),
		AgentEvents: fl.stats.events.Load(), AgentStreamErrs: fl.stats.streamErrors.Load(),
	}
	pr.Assertions = commonAssertions(pr, ph.agents)
	ph.budgets(&pr, gomaxprocs)
	pr.Pass = true
	for _, a := range pr.Assertions {
		pr.Pass = pr.Pass && a.Pass
	}
	return pr
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// commonAssertions hold for every phase: the fleet is healthy and every check produced results.
func commonAssertions(p PhaseReport, agents int) []Assertion {
	return []Assertion{
		newAssertion("NUX-44", "agents online on the server", "agents", float64(p.AgentsOnline), float64(agents), false),
		newAssertion("NUX-44", "agent streams without error", "errors", float64(p.AgentStreamErrs), 0, true),
		newAssertion("NUX-44", "checks with a result", "checks", float64(p.ChecksWithResult), float64(p.Checks), false),
		newAssertion("NUX-44", "API errors during window", "errors", float64(p.APIErrors), 0, true),
		newAssertion("NUX-44", "metric drops logged by nuxd", "agent+reason", float64(p.MetricDropLogs), 0, true),
	}
}

// smokeBudgets applies the NFR-2 memory ceiling at smoke scale. It is a ceiling, not a claim
// about the 50-agent budget, so it passes easily; the smoke run is a health check.
func smokeBudgets(p *PhaseReport, _ int) {
	p.Assertions = append(p.Assertions,
		newAssertion("NFR-2", "nuxd RSS peak (smoke ceiling)", "MiB", p.RSSPeakMiB, smokeRSSCeilingMiB, true),
		newAssertion("NUX-44", "API p95 latency", "ms", p.APIP95Ms, apiP95CeilingMs, true),
	)
}

// nfr2Budgets is the 50 agents, 500 containers, 200 checks point of NFR-2.
func nfr2Budgets(p *PhaseReport, _ int) {
	p.Assertions = append(p.Assertions,
		newAssertion("NFR-2", "containers reported", "containers", float64(p.Containers), 500, false),
		newAssertion("NFR-2", "nuxd RSS peak", "MiB", p.RSSPeakMiB, nfr2RSSCeilingMiB, true),
	)
}

// nfr4Budgets is the 200 agents, 1,000 checks point of NFR-4, on 2 vCPU and 4 GB. The API p95
// ceiling is the harness's own threshold, not part of NFR-4, and is labelled as such.
func nfr4Budgets(p *PhaseReport, gomaxprocs int) {
	p.Assertions = append(p.Assertions,
		newAssertion("NFR-4", "nuxd RSS peak (4 GB ceiling)", "MiB", p.RSSPeakMiB, nfr4RSSCeilingMiB, true),
		newAssertion("NFR-4", "nuxd average CPU", "cores", p.CPUCoresAvg, nfr4VCPU, true),
		newAssertion("NFR-4", "GOMAXPROCS applied to nuxd", "procs", float64(gomaxprocs), nfr4VCPU, true),
		newAssertion("NUX-44", "API p95 latency (harness threshold)", "ms", p.APIP95Ms, apiP95CeilingMs, true),
	)
}

// countLines counts log lines containing substr. A missing log counts as zero, which the run's
// other checks already cover.
func countLines(path, substr string) int {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0
	}
	n := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func writeJSON(path string, stdout io.Writer, rep *Report) error {
	w := stdout
	if path != "-" {
		f, err := os.Create(filepath.Clean(path))
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

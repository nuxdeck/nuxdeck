// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	maxCgroupWalk     = 20000 // directories visited while looking for a container's cgroup
	maxCgroupDepth    = 4
	maxFallbackFails  = 3 // consecutive stats API failures before a tick stops trying
	statsCallTimeout  = 3 * time.Second
	containerRunState = "running"
)

type cpuPrev struct {
	usec float64
	at   time.Time
}

// containerCollector reads cgroups v2 below root and falls back to the stats API.
type containerCollector struct {
	root       string
	containers func() []*agentv1.Container
	stats      *statsClient // nil when no socket is configured

	dirs map[string]string
	prev map[string]cpuPrev
}

func newContainerCollector(root, socket string, containers func() []*agentv1.Container) *containerCollector {
	c := &containerCollector{root: root, containers: containers, dirs: map[string]string{}, prev: map[string]cpuPrev{}}
	if socket != "" {
		c.stats = newStatsClient(socket)
	}
	return c
}

func (c *containerCollector) collect(ctx context.Context, now time.Time) ([]reading, error) {
	if c.containers == nil {
		return nil, nil
	}
	var out []reading
	var errs []error
	live := map[string]bool{}
	fails := 0
	for _, ct := range c.containers() {
		id := ct.GetRuntimeId()
		if id == "" || ct.GetState() != containerRunState {
			continue
		}
		live[id] = true
		rs, err := c.fromCgroup(id, now)
		if err != nil && c.stats != nil && fails < maxFallbackFails {
			sctx, cancel := context.WithTimeout(ctx, statsCallTimeout)
			var serr error
			rs, serr = c.stats.read(sctx, id, now, c.prev)
			cancel()
			if serr != nil {
				fails++
				err = fmt.Errorf("%w; stats api: %w", err, serr)
			} else {
				err, fails = nil, 0
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("container %.12s: %w", id, err))
			continue
		}
		rs = append(rs, reading{target: agentv1.TargetKind_TARGET_KIND_CONTAINER, id: id, metric: "nux_container_restart_count", value: float64(ct.GetRestartCount())})
		out = append(out, rs...)
	}
	for id := range c.prev {
		if !live[id] {
			delete(c.prev, id)
			delete(c.dirs, id)
		}
	}
	return out, errors.Join(errs...)
}

func (c *containerCollector) cgroupRoot() string { return filepath.Join(c.root, "sys", "fs", "cgroup") }

// locate finds the container's cgroup directory: the usual Docker and Podman layouts first,
// then a bounded search by name.
func (c *containerCollector) locate(id string) (string, bool) {
	if d, ok := c.dirs[id]; ok {
		if _, err := os.Stat(filepath.Join(d, "cpu.stat")); err == nil {
			return d, true
		}
		delete(c.dirs, id)
	}
	base := c.cgroupRoot()
	for _, rel := range []string{
		"system.slice/docker-" + id + ".scope", "docker/" + id,
		"machine.slice/libpod-" + id + ".scope", "machine.slice/libpod-" + id + ".scope/container",
	} {
		d := filepath.Join(base, rel)
		if _, err := os.Stat(filepath.Join(d, "cpu.stat")); err == nil {
			c.dirs[id] = d
			return d, true
		}
	}
	visited := 0
	var found string
	_ = filepath.WalkDir(base, func(p string, e fs.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return nil //nolint:nilerr // unreadable subtrees are skipped
		}
		if visited++; visited > maxCgroupWalk {
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(base, p)
		if depth := strings.Count(rel, string(filepath.Separator)) + 1; rel != "." && depth > maxCgroupDepth {
			return fs.SkipDir
		}
		if strings.Contains(e.Name(), id) {
			if _, err := os.Stat(filepath.Join(p, "cpu.stat")); err == nil {
				found = p
				return fs.SkipAll
			}
		}
		return nil
	})
	if found != "" {
		c.dirs[id] = found
	}
	return found, found != ""
}

func (c *containerCollector) fromCgroup(id string, now time.Time) ([]reading, error) {
	dir, ok := c.locate(id)
	if !ok {
		return nil, errors.New("cgroup not found")
	}
	cpu, err := readFlat(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return nil, err
	}
	cur, err := readFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return nil, err
	}
	usage, err := strconv.ParseFloat(strings.TrimSpace(string(cur)), 64)
	if err != nil {
		return nil, fmt.Errorf("memory.current: %w", err)
	}
	t := agentv1.TargetKind_TARGET_KIND_CONTAINER
	g := func(metric string, v float64, kv ...string) reading {
		return reading{target: t, id: id, metric: metric, labels: lbl(kv...), value: v}
	}
	ctr := func(metric string, v float64, kv ...string) reading {
		r := g(metric, v, kv...)
		r.counter = true
		return r
	}
	rs := []reading{
		ctr("nux_container_cpu_seconds_total", cpu["user_usec"]/1e6, "mode", "user"),
		ctr("nux_container_cpu_seconds_total", cpu["system_usec"]/1e6, "mode", "system"),
		ctr("nux_container_cpu_throttled_seconds_total", cpu["throttled_usec"]/1e6),
		g("nux_container_memory_bytes", usage, "type", "usage"),
	}
	if r, ok := c.cpuRatio(id, cpu["usage_usec"], now); ok {
		rs = append(rs, r)
	}
	if st, err := readFlat(filepath.Join(dir, "memory.stat")); err == nil {
		rs = append(rs, g("nux_container_memory_bytes", max(usage-st["inactive_file"], 0), "type", "working_set"))
	}
	if b, err := readFile(filepath.Join(dir, "memory.max")); err == nil {
		if lim, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil { // "max" does not parse: unlimited
			rs = append(rs, g("nux_container_memory_bytes", lim, "type", "limit"))
		}
	}
	if ev, err := readFlat(filepath.Join(dir, "memory.events")); err == nil {
		rs = append(rs, ctr("nux_container_memory_oom_kills_total", ev["oom_kill"]))
	}
	if b, err := readFile(filepath.Join(dir, "io.stat")); err == nil {
		io := parseIOStat(b)
		rs = append(rs,
			ctr("nux_container_blkio_bytes_total", io["rbytes"], "direction", "read"),
			ctr("nux_container_blkio_bytes_total", io["wbytes"], "direction", "write"),
			ctr("nux_container_blkio_ops_total", io["rios"], "direction", "read"),
			ctr("nux_container_blkio_ops_total", io["wios"], "direction", "write"))
	}
	if nets, err := c.netFromPID(dir); err == nil {
		rs = append(rs, netReadings(nets, t, id, "nux_container_network", "")...)
	} else if c.stats != nil {
		// Reading another user's /proc/<pid>/net is often denied; the stats API has the same numbers.
		ctx, cancel := context.WithTimeout(context.Background(), statsCallTimeout)
		defer cancel()
		if sr, err := c.stats.readNetwork(ctx, id); err == nil {
			rs = append(rs, sr...)
		}
	}
	return rs, nil
}

func (c *containerCollector) cpuRatio(id string, usec float64, now time.Time) (reading, bool) {
	p, had := c.prev[id]
	c.prev[id] = cpuPrev{usec: usec, at: now}
	dt := now.Sub(p.at).Seconds()
	if !had || dt <= 0 || usec < p.usec {
		return reading{}, false
	}
	return reading{target: agentv1.TargetKind_TARGET_KIND_CONTAINER, id: id, metric: "nux_container_cpu_usage_ratio", value: (usec - p.usec) / 1e6 / dt}, true
}

// netFromPID sums the interfaces seen by the container's first process.
func (c *containerCollector) netFromPID(dir string) ([]netCounters, error) {
	var pid string
	for _, p := range []string{filepath.Join(dir, "cgroup.procs"), filepath.Join(dir, "container", "cgroup.procs")} {
		if b, err := readFile(p); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				pid = f[0]
				break
			}
		}
	}
	if pid == "" {
		return nil, errors.New("no process in cgroup")
	}
	b, err := readFile(filepath.Join(c.root, "proc", pid, "net", "dev"))
	if err != nil {
		return nil, err
	}
	return sumNets(parseNetDev(b, maxInterfaces)), nil
}

func sumNets(in []netCounters) []netCounters {
	var s netCounters
	for _, n := range in {
		s.rxBytes += n.rxBytes
		s.rxPackets += n.rxPackets
		s.rxErrors += n.rxErrors
		s.txBytes += n.txBytes
		s.txPackets += n.txPackets
		s.txErrors += n.txErrors
	}
	return []netCounters{s}
}

// readFlat parses "key value" files such as cpu.stat and memory.stat.
func readFlat(path string) (map[string]float64, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseFlat(b), nil
}

func parseFlat(b []byte) map[string]float64 {
	m := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			if v, err := strconv.ParseFloat(f[1], 64); err == nil {
				m[f[0]] = v
			}
		}
	}
	return m
}

// parseIOStat sums io.stat ("8:0 rbytes=1 wbytes=2 rios=3 wios=4 ...") over all devices.
func parseIOStat(b []byte) map[string]float64 {
	m := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		for _, kv := range strings.Fields(sc.Text())[min(1, len(strings.Fields(sc.Text()))):] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				m[k] += x
			}
		}
	}
	return m
}

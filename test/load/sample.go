// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// clockTicksPerSecond is USER_HZ, which is 100 on every Linux build nuxd targets (amd64 and arm64).
const clockTicksPerSecond = 100

const (
	sampleEvery = time.Second
	probeEvery  = 500 * time.Millisecond
)

// procReading is one look at the server process: resident memory and cumulative CPU time.
type procReading struct {
	at         time.Time
	rssKiB     uint64
	cpuSeconds float64
}

func readProc(pid int) (procReading, error) {
	rss, err := readRSSKiB(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return procReading{}, err
	}
	cpu, err := readCPUSeconds(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procReading{}, err
	}
	return procReading{at: time.Now(), rssKiB: rss, cpuSeconds: cpu}, nil
}

func readRSSKiB(path string) (uint64, error) {
	f, err := os.Open(path) //nolint:gosec // procfs entry of the child nuxd
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "VmRSS:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			break
		}
		return strconv.ParseUint(fields[0], 10, 64)
	}
	return 0, fmt.Errorf("%s: no VmRSS", path)
}

// readCPUSeconds returns utime+stime. The comm field can contain spaces, so parsing starts after the last ')'.
func readCPUSeconds(path string) (float64, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // procfs entry of the child nuxd
	if err != nil {
		return 0, err
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("%s: malformed", path)
	}
	fields := strings.Fields(s[i+1:])
	// Fields start at state (field 3), so utime (14) and stime (15) are at offsets 11 and 12.
	if len(fields) < 13 {
		return 0, fmt.Errorf("%s: too few fields", path)
	}
	ut, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	st, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return float64(ut+st) / clockTicksPerSecond, nil
}

// windowResult is what the samplers saw during one measurement window.
type windowResult struct {
	Duration     time.Duration
	RSSPeakKiB   uint64
	RSSFinalKiB  uint64
	CPUCoresAvg  float64
	CPUCoresPeak float64
	Latencies    []time.Duration
	APIErrors    int
	APIRequests  int
}

// measure samples the server for d while a single dashboard-style reader polls the REST API.
// Agents and checks keep running in the background; this only observes.
func measure(ctx context.Context, pid int, c *apiClient, paths []string, d time.Duration) (windowResult, error) {
	first, err := readProc(pid)
	if err != nil {
		return windowResult{}, err
	}
	res := windowResult{RSSPeakKiB: first.rssKiB, RSSFinalKiB: first.rssKiB}
	prev := first
	var cpuTotal float64

	deadline := time.NewTimer(d)
	defer deadline.Stop()
	sampleTick := time.NewTicker(sampleEvery)
	defer sampleTick.Stop()
	probeTick := time.NewTicker(probeEvery)
	defer probeTick.Stop()

	start := time.Now()
	next := 0
	for {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-deadline.C:
			res.Duration = time.Since(start)
			if wall := prev.at.Sub(first.at).Seconds(); wall > 0 {
				res.CPUCoresAvg = cpuTotal / wall
			}
			return res, nil
		case <-sampleTick.C:
			cur, err := readProc(pid)
			if err != nil {
				return res, err
			}
			res.RSSFinalKiB = cur.rssKiB
			res.RSSPeakKiB = max(res.RSSPeakKiB, cur.rssKiB)
			if wall := cur.at.Sub(prev.at).Seconds(); wall > 0 {
				cores := (cur.cpuSeconds - prev.cpuSeconds) / wall
				res.CPUCoresPeak = max(res.CPUCoresPeak, cores)
			}
			cpuTotal = cur.cpuSeconds - first.cpuSeconds
			prev = cur
		case <-probeTick.C:
			lat, err := c.timedGET(ctx, paths[next%len(paths)])
			next++
			res.APIRequests++
			if err != nil {
				res.APIErrors++
				continue
			}
			res.Latencies = append(res.Latencies, lat)
		}
	}
}

// percentile returns the nearest-rank p-quantile (p in (0,1]) of the samples, or 0 when there are none.
func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	rank := min(max(int(float64(len(s))*p+0.999999999), 1), len(s))
	return s[rank-1]
}

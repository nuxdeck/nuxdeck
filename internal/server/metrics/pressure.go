// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"fmt"
	"sort"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/tsdb/chunkenc"

	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// Pressure is one row of the overview grid (MET-7). A percentage is nil when no sample
// arrived in the last five minutes, e.g. the agent is offline.
type Pressure struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	HostID        string   `json:"host_id,omitempty"`
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryPercent *float64 `json:"memory_percent"`
	DiskPercent   *float64 `json:"disk_percent"`
	// Score is the highest of the three percentages; nil when none is known.
	Score *float64 `json:"score"`
	// Rank holds the 1-based position among the listed items by each dimension, worst first.
	Rank map[string]int `json:"rank"`
}

// PressureReport lists hosts and containers, worst first by Score.
type PressureReport struct {
	GeneratedAt   int64      `json:"generated_at"`
	WindowSeconds int        `json:"window_seconds"`
	Hosts         []Pressure `json:"hosts"`
	Containers    []Pressure `json:"containers"`
}

type sample struct {
	metric string
	lbl    map[string]string
	value  float64
}

type latest map[string][]sample // target ID -> newest sample of each series

// Pressure ranks every live host and container by its newest samples. limit caps each list.
func (s *Service) Pressure(ctx context.Context, limit int) (PressureReport, error) {
	now := s.now().UnixMilli()
	vals, err := s.latest(ctx, now-pressureLookback, now)
	if err != nil {
		return PressureReport{}, err
	}
	rep := PressureReport{GeneratedAt: now, WindowSeconds: pressureLookback / 1000, Hosts: []Pressure{}, Containers: []Pressure{}}
	inv := s.opts.Inventory

	hosts := map[string]inventory.Host{}
	for cursor := ""; ; {
		p := inv.Hosts(inventory.HostFilter{}, cursor, 500)
		for _, h := range p.Items {
			hosts[h.ID] = h
			v := vals[h.ID]
			row := Pressure{ID: h.ID, Name: h.Hostname}
			if r := find(v, hostCPURatio, "cpu", "all"); r != nil {
				x := *r * 100
				row.CPUPercent = clamp(&x)
			}
			row.MemoryPercent = clamp(ratioPct(find(v, hostMemory, "type", "used"), find(v, hostMemory, "type", "total"), float64(h.MemoryBytes)))
			row.DiskPercent = clamp(worstFilesystem(v))
			rep.Hosts = append(rep.Hosts, row)
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	for cursor := ""; ; {
		p := inv.Containers(inventory.ContainerFilter{}, cursor, 500)
		for _, c := range p.Items {
			v := vals[c.ID]
			h := hosts[c.HostID]
			row := Pressure{ID: c.ID, Name: c.Name, HostID: c.HostID}
			if cores := find(v, ctrCPURatio, "", ""); cores != nil && h.CPUCount > 0 {
				x := *cores / float64(h.CPUCount) * 100
				row.CPUPercent = clamp(&x)
			}
			used := find(v, ctrMemory, "type", "working_set")
			if used == nil {
				used = find(v, ctrMemory, "type", "usage")
			}
			row.MemoryPercent = clamp(ratioPct(used, find(v, ctrMemory, "type", "limit"), float64(h.MemoryBytes)))
			rep.Containers = append(rep.Containers, row)
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	rep.Hosts = rankPressure(rep.Hosts, limit)
	rep.Containers = rankPressure(rep.Containers, limit)
	return rep, nil
}

// latest returns the newest full-resolution sample per series of the metrics the ranking reads.
func (s *Service) latest(ctx context.Context, from, to int64) (latest, error) {
	m, err := labels.NewMatcher(labels.MatchRegexp, nameLabel,
		hostCPURatio+"|"+hostMemory+"|"+hostFilesystem+"|"+ctrCPURatio+"|"+ctrMemory)
	if err != nil {
		return nil, err
	}
	q, err := s.store.full.Querier(from, to)
	if err != nil {
		return nil, fmt.Errorf("open querier: %w", err)
	}
	defer func() { _ = q.Close() }()
	out := latest{}
	set := q.Select(ctx, false, nil, m)
	for set.Next() {
		series := set.At()
		l := series.Labels()
		var last float64
		have := false
		it := series.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			if t, v := it.At(); t >= from && t <= to {
				last, have = v, true
			}
		}
		if it.Err() != nil || !have {
			continue
		}
		id := l.Get("target")
		out[id] = append(out[id], sample{metric: l.Get(nameLabel), lbl: l.Map(), value: last})
	}
	return out, set.Err()
}

// find returns the value of metric whose label key equals val (key "" means any labels).
func find(v []sample, metric, key, val string) *float64 {
	for _, s := range v {
		if s.metric == metric && (key == "" || s.lbl[key] == val) {
			x := s.value
			return &x
		}
	}
	return nil
}

// worstFilesystem is the highest used/size percentage over the host's filesystems.
func worstFilesystem(v []sample) *float64 {
	size := map[string]float64{}
	used := map[string]float64{}
	for _, s := range v {
		if s.metric != hostFilesystem {
			continue
		}
		switch s.lbl["type"] {
		case "size":
			size[s.lbl["mount"]] = s.value
		case "used":
			used[s.lbl["mount"]] = s.value
		}
	}
	var worst *float64
	for mount, u := range used {
		if sz := size[mount]; sz > 0 {
			if p := u / sz * 100; worst == nil || p > *worst {
				worst = &p
			}
		}
	}
	return worst
}

// ratioPct is used/total in percent; total falls back to fallbackBytes (the inventory's memory
// size) when the agent reports none, e.g. a container without a limit.
func ratioPct(used, total *float64, fallbackBytes float64) *float64 {
	if used == nil {
		return nil
	}
	t := fallbackBytes
	if total != nil && *total > 0 {
		t = *total
	}
	if t <= 0 {
		return nil
	}
	p := *used / t * 100
	return &p
}

func clamp(p *float64) *float64 {
	if p == nil {
		return nil
	}
	x := min(max(*p, 0), 100)
	return &x
}

// rankPressure fills Score and Rank, sorts worst first (unknown last, then by name) and truncates.
func rankPressure(rows []Pressure, limit int) []Pressure {
	for i := range rows {
		r := &rows[i]
		for _, p := range []*float64{r.CPUPercent, r.MemoryPercent, r.DiskPercent} {
			if p != nil && (r.Score == nil || *p > *r.Score) {
				x := *p
				r.Score = &x
			}
		}
		r.Rank = map[string]int{}
	}
	dims := map[string]func(Pressure) *float64{
		"cpu":    func(p Pressure) *float64 { return p.CPUPercent },
		"memory": func(p Pressure) *float64 { return p.MemoryPercent },
		"disk":   func(p Pressure) *float64 { return p.DiskPercent },
	}
	for name, pick := range dims {
		idx := make([]int, 0, len(rows))
		for i := range rows {
			if pick(rows[i]) != nil {
				idx = append(idx, i)
			}
		}
		sort.SliceStable(idx, func(a, b int) bool { return *pick(rows[idx[a]]) > *pick(rows[idx[b]]) })
		for pos, i := range idx {
			rows[i].Rank[name] = pos + 1
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		sa, sb := rows[a].Score, rows[b].Score
		switch {
		case sa != nil && sb != nil && *sa != *sb:
			return *sa > *sb
		case (sa == nil) != (sb == nil):
			return sa != nil
		}
		return rows[a].Name < rows[b].Name
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

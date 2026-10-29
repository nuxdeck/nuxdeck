// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"

	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Ingest bounds. A batch over a limit is truncated at the limit, not accepted whole.
const (
	maxSeriesPerBatch  = 5000
	maxPointsPerSeries = 1000
	maxPointsPerBatch  = 50000
	maxTargetIDLen     = 128
	maxWarnKeys        = 4096
	maxLabelsPerSeries = 4
	// maxSeriesPerTarget bounds distinct label sets per target since start; a host with many
	// mounts, disks and interfaces stays well below it.
	maxSeriesPerTarget = 2000

	containerCacheTTL = time.Minute
	containerMissWait = 10 * time.Second
)

// Inventory is the part of the inventory index the metrics module reads;
// *inventory.Index implements it.
type Inventory interface {
	HostByAgent(agentID string) (inventory.Host, bool)
	Host(id string) (inventory.Host, bool)
	Container(id string) (inventory.Container, bool)
	Hosts(f inventory.HostFilter, cursor string, limit int) inventory.Page[inventory.Host]
	Containers(f inventory.ContainerFilter, cursor string, limit int) inventory.Page[inventory.Container]
}

// Drop reasons, also the keys of Stats.Dropped.
const (
	dropNoHost     = "unknown_host"
	dropTarget     = "unknown_target"
	dropMetric     = "metric_not_allowed"
	dropTimestamp  = "timestamp_out_of_range"
	dropValue      = "invalid_value"
	dropLimit      = "batch_limit"
	dropLabels     = "labels_not_allowed"
	dropCardinal   = "series_limit_per_target"
	dropWrite      = "write_rejected"
	dropBadMessage = "malformed"
)

type ingestor struct {
	log *slog.Logger
	inv Inventory
	app func(context.Context) storage.Appender
	now func() time.Time

	accepted atomic.Uint64
	dropped  sync.Map // reason -> *atomic.Uint64

	warnMu sync.Mutex
	warned map[string]struct{}

	cacheMu sync.Mutex
	hosts   map[string]*runtimeMap         // host ID -> runtime ID -> container ID
	series  map[string]map[uint64]struct{} // target ID -> hashes of accepted label sets
}

type runtimeMap struct {
	ids      map[string]string
	loadedAt time.Time
	lastMiss time.Time
}

// Stats counts what ingest did since start.
type Stats struct {
	Accepted uint64
	Dropped  map[string]uint64
}

func newIngestor(log *slog.Logger, inv Inventory, app func(context.Context) storage.Appender, now func() time.Time) *ingestor {
	return &ingestor{log: log, inv: inv, app: app, now: now, warned: map[string]struct{}{}, hosts: map[string]*runtimeMap{}, series: map[string]map[uint64]struct{}{}}
}

func (g *ingestor) stats() Stats {
	s := Stats{Accepted: g.accepted.Load(), Dropped: map[string]uint64{}}
	g.dropped.Range(func(k, v any) bool {
		s.Dropped[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return s
}

func (g *ingestor) drop(agentID, reason string, n uint64, attrs ...any) {
	c, _ := g.dropped.LoadOrStore(reason, new(atomic.Uint64))
	c.(*atomic.Uint64).Add(n)
	key := agentID + "/" + reason
	g.warnMu.Lock()
	_, seen := g.warned[key]
	if !seen && len(g.warned) < maxWarnKeys {
		g.warned[key] = struct{}{}
	}
	g.warnMu.Unlock()
	if !seen {
		g.log.Warn("dropping metric data (logged once per agent and reason)", append([]any{"agent_id", agentID, "reason", reason}, attrs...)...)
	}
}

// handle writes one batch. The host comes from agentID, which the gateway took
// from the mTLS certificate; a container is accepted only if it belongs to that
// host, so no message content can address another agent's series.
func (g *ingestor) handle(ctx context.Context, agentID string, b *agentv1.MetricBatch) {
	host, ok := g.inv.HostByAgent(agentID)
	if !ok || host.GoneAt != nil {
		g.drop(agentID, dropNoHost, uint64(len(b.GetSeries())))
		return
	}
	now := g.now()
	minTS := now.Add(-replayWindow).UnixMilli()
	maxTS := now.Add(futureSkew).UnixMilli()

	app := g.app(ctx)
	var accepted uint64
	totalPoints := 0
	for i, s := range b.GetSeries() {
		if i >= maxSeriesPerBatch {
			g.drop(agentID, dropLimit, uint64(max(0, len(b.GetSeries())-i)), "limit", "series")
			break
		}
		def, ok := Lookup(s.GetMetric())
		if !ok || len(s.GetMetric()) > maxMetricNameSize {
			g.drop(agentID, dropMetric, uint64(len(s.GetPoints())))
			continue
		}
		lset, ok := g.labelsFor(host, s.GetTarget(), def)
		if !ok {
			g.drop(agentID, dropTarget, uint64(len(s.GetPoints())))
			continue
		}
		lset, ok = withDimensions(lset, s.GetLabels())
		if !ok {
			g.drop(agentID, dropLabels, uint64(len(s.GetPoints())))
			continue
		}
		if !g.admit(lset) {
			g.drop(agentID, dropCardinal, uint64(len(s.GetPoints())))
			continue
		}
		pts := s.GetPoints()
		if len(pts) > maxPointsPerSeries {
			g.drop(agentID, dropLimit, uint64(max(0, len(pts)-maxPointsPerSeries)), "limit", "points_per_series")
			pts = pts[:maxPointsPerSeries]
		}
		for _, p := range pts {
			if totalPoints++; totalPoints > maxPointsPerBatch {
				g.drop(agentID, dropLimit, 1, "limit", "points_per_batch")
				break
			}
			switch {
			case p.GetTsUnixMs() < minTS || p.GetTsUnixMs() > maxTS:
				g.drop(agentID, dropTimestamp, 1)
			case math.IsNaN(p.GetValue()) || math.IsInf(p.GetValue(), 0):
				g.drop(agentID, dropValue, 1)
			default:
				if _, err := app.Append(0, lset, p.GetTsUnixMs(), p.GetValue()); err != nil {
					if !errors.Is(err, storage.ErrDuplicateSampleForTimestamp) {
						g.drop(agentID, dropWrite, 1, "error", err.Error())
					}
					continue
				}
				accepted++
			}
		}
	}
	if err := app.Commit(); err != nil {
		g.drop(agentID, dropWrite, accepted, "error", err.Error())
		return
	}
	g.accepted.Add(accepted)
}

// labelsFor builds the series labels for a target of host.
func (g *ingestor) labelsFor(host inventory.Host, t *agentv1.Target, def Def) (labels.Labels, bool) {
	switch t.GetKind() {
	case agentv1.TargetKind_TARGET_KIND_HOST:
		if !def.Host {
			return labels.EmptyLabels(), false
		}
		return labels.FromStrings(nameLabel, def.Name, "target_type", TargetHost, "target", host.ID), true
	case agentv1.TargetKind_TARGET_KIND_CONTAINER:
		if !def.Container || t.GetId() == "" || len(t.GetId()) > maxTargetIDLen {
			return labels.EmptyLabels(), false
		}
		cid, ok := g.containerID(host.ID, t.GetId())
		if !ok {
			return labels.EmptyLabels(), false
		}
		return labels.FromStrings(nameLabel, def.Name, "target_type", TargetContainer, "target", cid, "host", host.ID), true
	}
	return labels.EmptyLabels(), false
}

// containerID maps a runtime ID to the inventory ID within one host. The map is
// reloaded after containerCacheTTL, or on a miss at most every containerMissWait.
func (g *ingestor) containerID(hostID, runtimeID string) (string, bool) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	now := g.now()
	rm := g.hosts[hostID]
	if rm == nil {
		rm = &runtimeMap{}
		g.hosts[hostID] = rm
	}
	if rm.ids == nil || now.Sub(rm.loadedAt) > containerCacheTTL {
		g.reloadLocked(hostID, rm, now)
	}
	if id, ok := rm.ids[runtimeID]; ok {
		return id, true
	}
	if now.Sub(rm.lastMiss) > containerMissWait {
		rm.lastMiss = now
		g.reloadLocked(hostID, rm, now)
		id, ok := rm.ids[runtimeID]
		return id, ok
	}
	return "", false
}

func (g *ingestor) reloadLocked(hostID string, rm *runtimeMap, now time.Time) {
	ids := map[string]string{}
	cursor := ""
	for {
		p := g.inv.Containers(inventory.ContainerFilter{HostID: hostID}, cursor, 500)
		for _, c := range p.Items {
			ids[c.RuntimeID] = c.ID
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	rm.ids, rm.loadedAt = ids, now
}

// withDimensions adds the agent's labels to base. Only allowlisted names are accepted, with
// bounded counts and sizes; anything else rejects the whole series.
func withDimensions(base labels.Labels, dims map[string]string) (labels.Labels, bool) {
	if len(dims) > maxLabelsPerSeries {
		return base, false
	}
	b := labels.NewBuilder(base)
	for k, v := range dims {
		if !allowedLabels[k] || len(v) > maxLabelValueSize || !utf8.ValidString(v) {
			return base, false
		}
		b.Set(k, v)
	}
	return b.Labels(), true
}

// admit enforces maxSeriesPerTarget.
func (g *ingestor) admit(l labels.Labels) bool {
	target := l.Get("target")
	h := l.Hash()
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	set := g.series[target]
	if set == nil {
		set = map[uint64]struct{}{}
		g.series[target] = set
	}
	if _, ok := set[h]; ok {
		return true
	}
	if len(set) >= maxSeriesPerTarget {
		return false
	}
	set[h] = struct{}{}
	return true
}

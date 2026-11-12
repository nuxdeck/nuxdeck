// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"maps"
	"slices"
	"sort"
	"sync"
)

// Index is the in-memory copy of the inventory that reads are served from.
type Index struct {
	mu         sync.RWMutex
	hosts      map[string]Host
	byAgent    map[string]string // agent ID -> host ID
	containers map[string]Container
}

// NewIndex builds an index from stored rows.
func NewIndex(hosts []Host, containers []Container) *Index {
	ix := &Index{hosts: map[string]Host{}, byAgent: map[string]string{}, containers: map[string]Container{}}
	for _, h := range hosts {
		ix.putHost(h)
	}
	for _, c := range containers {
		ix.containers[c.ID] = clone(c)
	}
	return ix
}

func (ix *Index) putHost(h Host) {
	h.Facts = maps.Clone(h.Facts)
	h.Tags = nonNil(h.Tags)
	h.ETag = MetaETag(h.Owner, h.Tags)
	ix.hosts[h.ID] = h
	ix.byAgent[h.AgentID] = h.ID
}

func (ix *Index) setHost(h Host) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.putHost(h)
}

func (ix *Index) setContainer(c Container) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	c = clone(c)
	c.ETag = MetaETag(c.Owner, c.Tags)
	ix.containers[c.ID] = c
}

// HostByAgent finds the host of an agent.
func (ix *Index) HostByAgent(agentID string) (Host, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	id, ok := ix.byAgent[agentID]
	if !ok {
		return Host{}, false
	}
	return cloneHost(ix.hosts[id]), true
}

// Host returns one host by ID.
func (ix *Index) Host(id string) (Host, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	h, ok := ix.hosts[id]
	return cloneHost(h), ok
}

// Container returns one container by ID.
func (ix *Index) Container(id string) (Container, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	c, ok := ix.containers[id]
	return clone(c), ok
}

// HostFilter selects hosts for List.
type HostFilter struct {
	Status      string // empty means online and offline
	IncludeGone bool
	Tags        []TagSelector // all must match
	// Allow, if set, keeps only hosts it accepts: the caller's scope (ACC-5). It runs under the index lock.
	Allow func(Host) bool
}

// ContainerFilter selects containers for List.
type ContainerFilter struct {
	HostID      string
	State       string
	IncludeGone bool
	Tags        []TagSelector // all must match
	// Allow, if set, keeps only containers it accepts, given the container and its host (whose tags
	// scope it too). It runs under the index lock.
	Allow func(Container, Host) bool
}

// Page is one page of a cursor-paginated list ordered by ID (which sorts by creation time).
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// Hosts lists hosts after cursor, at most limit.
func (ix *Index) Hosts(f HostFilter, cursor string, limit int) Page[Host] {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	ids := make([]string, 0, len(ix.hosts))
	for id, h := range ix.hosts {
		if (h.Status == StatusGone && !f.IncludeGone) || (f.Status != "" && h.Status != f.Status) || !matchesAll(h.Tags, f.Tags) || (f.Allow != nil && !f.Allow(h)) {
			continue
		}
		ids = append(ids, id)
	}
	return paginate(ids, cursor, limit, func(id string) Host {
		return cloneHost(ix.hosts[id])
	})
}

// Containers lists containers after cursor, at most limit.
func (ix *Index) Containers(f ContainerFilter, cursor string, limit int) Page[Container] {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	ids := make([]string, 0, len(ix.containers))
	for id, c := range ix.containers {
		if (c.GoneAt != nil && !f.IncludeGone) || (f.HostID != "" && c.HostID != f.HostID) || (f.State != "" && c.State != f.State) || !matchesAll(c.Tags, f.Tags) || (f.Allow != nil && !f.Allow(c, ix.hosts[c.HostID])) {
			continue
		}
		ids = append(ids, id)
	}
	return paginate(ids, cursor, limit, func(id string) Container { return clone(ix.containers[id]) })
}

func paginate[T any](ids []string, cursor string, limit int, get func(string) T) Page[T] {
	sort.Strings(ids)
	start := 0
	if cursor != "" {
		start, _ = slices.BinarySearch(ids, cursor)
		if start < len(ids) && ids[start] == cursor {
			start++
		}
	}
	end := min(start+limit, len(ids))
	page := Page[T]{Items: make([]T, 0, end-start)}
	for _, id := range ids[start:end] {
		page.Items = append(page.Items, get(id))
	}
	if end < len(ids) && end > start {
		page.NextCursor = ids[end-1]
	}
	return page
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func cloneHost(h Host) Host {
	h.Facts = maps.Clone(h.Facts)
	h.Tags = maps.Clone(h.Tags)
	return h
}

func clone(c Container) Container {
	c.Labels = maps.Clone(c.Labels)
	c.Tags = nonNil(maps.Clone(c.Tags))
	c.Ports = slices.Clone(c.Ports)
	return c
}

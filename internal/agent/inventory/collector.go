// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

const (
	// maxContainers keeps a full snapshot under the 4 MB message limit (about 2 KB per container at most).
	maxContainers = 1500
	inspectJobs   = 4
	subscriberBuf = 256
	maxEventLine  = 1 << 20

	collectorHost       = "host"
	collectorContainers = "containers"
)

// Config is the collector's settings. Zero values take sensible defaults.
type Config struct {
	// SockguardSocket is nux-sockguard's socket, normally /run/nux/sockguard.sock.
	SockguardSocket string
	// Root is the filesystem root host facts are read from; "" means /.
	Root string
	Log  *slog.Logger

	HostPoll      time.Duration // how often host facts are rechecked (default 30 s)
	RetryInterval time.Duration // wait after the runtime fails or is absent (default 30 s)
	Resync        time.Duration // full container resync as a safety net (default 5 min)
	// ReconnectDelay is the pause before following events again after the stream ended (default 1 s).
	ReconnectDelay time.Duration

	sources hostSources // tests replace the host's inputs
}

func (c *Config) defaults() {
	if c.Root == "" {
		c.Root = "/"
	}
	if c.HostPoll <= 0 {
		c.HostPoll = 30 * time.Second
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = 30 * time.Second
	}
	if c.Resync <= 0 {
		c.Resync = 5 * time.Minute
	}
	if c.ReconnectDelay <= 0 {
		c.ReconnectDelay = time.Second
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.sources.hostname == nil {
		c.sources = defaultSources(c.Root)
	}
}

// Collector keeps the agent's picture of its host and containers and publishes changes.
type Collector struct {
	cfg Config
	cli *runtimeClient

	mu         sync.Mutex
	host       *agentv1.HostFacts
	containers map[string]*agentv1.Container
	runtime    agentv1.Runtime
	subs       map[chan *agentv1.InventoryEvent]struct{}
	errs       map[string]*agentv1.CollectorError
}

// New reads the host facts once, so a snapshot always has them, and prepares the container collector.
func New(cfg Config) *Collector {
	cfg.defaults()
	c := &Collector{
		cfg: cfg, cli: newRuntimeClient(cfg.SockguardSocket),
		containers: map[string]*agentv1.Container{},
		subs:       map[chan *agentv1.InventoryEvent]struct{}{},
		errs:       map[string]*agentv1.CollectorError{},
	}
	c.refreshHost(false)
	return c
}

// Run keeps host facts and containers current until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.hostLoop(ctx) }()
	go func() { defer wg.Done(); c.containerLoop(ctx) }()
	wg.Wait()
}

// Attach returns the current state and a channel of the changes that follow it, atomically,
// so nothing falls between the two. The channel is closed if the caller falls too far behind;
// it should then Attach again and send the new snapshot. Call detach when done.
func (c *Collector) Attach() (snap *agentv1.InventorySnapshot, events <-chan *agentv1.InventoryEvent, detach func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap = &agentv1.InventorySnapshot{Host: proto.Clone(c.host).(*agentv1.HostFacts), TakenAtUnixMs: time.Now().UnixMilli()}
	for _, ct := range c.sortedContainers() {
		snap.Containers = append(snap.Containers, proto.Clone(ct).(*agentv1.Container))
	}
	ch := make(chan *agentv1.InventoryEvent, subscriberBuf)
	c.subs[ch] = struct{}{}
	return snap, ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, ok := c.subs[ch]; ok {
			delete(c.subs, ch)
			close(ch)
		}
	}
}

// Errors lists the collectors that currently fail, for the agent's heartbeat.
func (c *Collector) Errors() []*agentv1.CollectorError {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*agentv1.CollectorError, 0, len(c.errs))
	for _, e := range c.errs {
		out = append(out, proto.Clone(e).(*agentv1.CollectorError))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Collector < out[j].Collector })
	return out
}

// ---- host facts ----------------------------------------------------------

func (c *Collector) hostLoop(ctx context.Context) {
	t := time.NewTicker(c.cfg.HostPoll)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.refreshHost(true)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) refreshHost(announce bool) {
	facts, err := c.cfg.sources.collectHost()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.cfg.Log.Warn("some host facts are unavailable", "code", errcode.AGTCol002, "error", err)
		c.setErrLocked(collectorHost, errcode.AGTCol002)
	} else {
		delete(c.errs, collectorHost)
	}
	if c.host != nil && proto.Equal(c.host, facts) {
		return
	}
	c.host = facts
	if announce {
		c.emitLocked(&agentv1.InventoryEvent{Change: &agentv1.InventoryEvent_Host{Host: &agentv1.HostFactsChange{Host: proto.Clone(facts).(*agentv1.HostFacts)}}})
	}
}

// ---- containers ----------------------------------------------------------

func (c *Collector) containerLoop(ctx context.Context) {
	for ctx.Err() == nil {
		since, err := c.resync(ctx)
		if err != nil {
			c.fail(err)
			if !sleep(ctx, jitter(c.cfg.RetryInterval)) {
				return
			}
			continue
		}
		c.clearErr(collectorContainers)

		// The stream ends at the resync interval at the latest, which forces the next full resync.
		wctx, cancel := context.WithTimeout(ctx, c.cfg.Resync)
		err = c.watch(wctx, since)
		resyncDue := wctx.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return
		}
		if resyncDue {
			continue
		}
		// The stream ended early (sockguard or the runtime restarted): resync after a short pause.
		wait := c.cfg.ReconnectDelay
		if err != nil {
			c.fail(err)
			wait = c.cfg.RetryInterval
		}
		if !sleep(ctx, jitter(wait)) {
			return
		}
	}
}

func (c *Collector) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, already := c.errs[collectorContainers]; !already {
		c.cfg.Log.Warn("container inventory unavailable", "code", errcode.AGTCol001, "error", err)
	}
	c.setErrLocked(collectorContainers, errcode.AGTCol001)
}

func (c *Collector) clearErr(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.errs, name)
}

func (c *Collector) setErrLocked(name string, code errcode.Code) {
	if _, ok := c.errs[name]; !ok {
		c.errs[name] = &agentv1.CollectorError{Collector: name, Code: string(code), AtUnixMs: time.Now().UnixMilli()}
	}
}

// resync lists and inspects every container, announces what differs from what is known, and
// returns the time to resume the event stream from (taken before listing, so nothing is missed).
func (c *Collector) resync(ctx context.Context) (time.Time, error) {
	started := time.Now()
	rt, err := c.cli.kind(ctx)
	if err != nil {
		return time.Time{}, err
	}
	ids, err := c.cli.list(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if len(ids) > maxContainers {
		c.cfg.Log.Warn("more containers than the agent reports; the rest are ignored", "limit", maxContainers, "found", len(ids))
		ids = ids[:maxContainers]
	}

	found := make(map[string]*agentv1.Container, len(ids))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, inspectJobs)
	var wg sync.WaitGroup
	for _, id := range ids {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ct, err := c.cli.inspect(ctx, id, rt)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, errNotFound): // removed between list and inspect
			case err != nil:
				if firstErr == nil {
					firstErr = err
				}
			default:
				found[ct.RuntimeId] = ct
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return time.Time{}, firstErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime = rt
	for id, old := range c.containers {
		if _, still := found[id]; !still {
			delete(c.containers, id)
			c.emitContainerLocked(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{Runtime: old.Runtime, RuntimeId: id})
		}
	}
	for id, ct := range found {
		old, existed := c.containers[id]
		if existed && proto.Equal(old, ct) {
			continue
		}
		c.containers[id] = ct
		kind := agentv1.ContainerChange_KIND_UPDATED
		if !existed {
			kind = agentv1.ContainerChange_KIND_CREATED
		}
		c.emitContainerLocked(kind, ct)
	}
	return started, nil
}

// watch follows container events until the stream ends.
func (c *Collector) watch(ctx context.Context, since time.Time) error {
	body, err := c.cli.events(ctx, since)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxEventLine)
	for sc.Scan() {
		var ev event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Type != "" && ev.Type != "container" {
			continue
		}
		if err := c.apply(ctx, ev); err != nil && ctx.Err() == nil {
			return err
		}
	}
	return sc.Err()
}

// apply updates one container after an event and announces the change if there is one.
func (c *Collector) apply(ctx context.Context, ev event) error {
	kind, removed, ok := changeKind(ev.action())
	id := ev.containerID()
	if !ok || id == "" {
		return nil
	}

	if removed {
		c.mu.Lock()
		defer c.mu.Unlock()
		if old, known := c.containers[id]; known {
			delete(c.containers, id)
			c.emitContainerLocked(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{Runtime: old.Runtime, RuntimeId: id})
		}
		return nil
	}

	c.mu.Lock()
	rt := c.runtime
	c.mu.Unlock()
	ct, err := c.cli.inspect(ctx, id, rt)
	if errors.Is(err, errNotFound) { // gone again before we looked
		c.mu.Lock()
		defer c.mu.Unlock()
		if old, known := c.containers[id]; known {
			delete(c.containers, id)
			c.emitContainerLocked(agentv1.ContainerChange_KIND_REMOVED, &agentv1.Container{Runtime: old.Runtime, RuntimeId: id})
		}
		return nil
	}
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	old, existed := c.containers[id]
	if existed && proto.Equal(old, ct) {
		return nil // already announced by an earlier event or a resync
	}
	if !existed {
		if len(c.containers) >= maxContainers {
			return nil
		}
		kind = agentv1.ContainerChange_KIND_CREATED
	}
	c.containers[id] = ct
	c.emitContainerLocked(kind, ct)
	return nil
}

// ---- publishing ----------------------------------------------------------

func (c *Collector) emitContainerLocked(kind agentv1.ContainerChange_Kind, ct *agentv1.Container) {
	c.emitLocked(&agentv1.InventoryEvent{Change: &agentv1.InventoryEvent_Container{Container: &agentv1.ContainerChange{
		Kind: kind, Container: proto.Clone(ct).(*agentv1.Container),
	}}})
}

// emitLocked hands an event to every subscriber. One that has fallen behind is closed rather
// than allowed to hold memory: it gets a fresh snapshot when it attaches again.
func (c *Collector) emitLocked(ev *agentv1.InventoryEvent) {
	ev.AtUnixMs = time.Now().UnixMilli()
	for ch := range c.subs {
		select {
		case ch <- ev:
		default:
			delete(c.subs, ch)
			close(ch)
		}
	}
}

func (c *Collector) sortedContainers() []*agentv1.Container {
	out := make([]*agentv1.Container, 0, len(c.containers))
	for _, ct := range c.containers {
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuntimeId < out[j].RuntimeId })
	return out
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Float64()*float64(d/2)) //nolint:gosec // spreads retries, not a secret
}

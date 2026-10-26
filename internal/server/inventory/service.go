// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// Limits on what an agent may send. The agent is authenticated but not trusted to be
// well-behaved, so everything is bounded before it reaches the database or a browser.
const (
	maxContainers = 1500
	maxPorts      = 256
	maxLabels     = 64
	maxFacts      = 64
	maxName       = 253
	maxImage      = 512
	maxShort      = 64
	maxFactValue  = 4096
	maxLabelValue = 512
)

var (
	runtimeIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	protocolNames    = map[string]bool{"tcp": true, "udp": true, "sctp": true}
)

// Service applies what agents report and publishes the changes.
type Service struct {
	repo  Repository
	log   *slog.Logger
	index *Index
	hub   *Hub
	// Now supplies the clock; nil means time.Now.
	Now func() time.Time

	// mu orders every write so database state, index and published events never disagree.
	mu     sync.Mutex
	online map[string]bool // agent ID -> has a live stream
}

// NewService loads the stored inventory into the index.
func NewService(repo Repository, log *slog.Logger) (*Service, error) {
	hosts, containers, err := repo.LoadInventory()
	if err != nil {
		return nil, fmt.Errorf("load inventory: %w", err)
	}
	s := &Service{repo: repo, log: log, index: NewIndex(hosts, containers), hub: NewHub(), online: map[string]bool{}}
	return s, nil
}

// Index serves reads.
func (s *Service) Index() *Index { return s.index }

// Subscribe starts a live feed of changes.
func (s *Service) Subscribe() (*Subscription, error) { return s.hub.Subscribe() }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SetPresence records that an agent's stream came up or went down. It is the source of a
// host's online/offline status (AGT-7). The host row may not exist yet: its first snapshot
// creates it with the status recorded here.
func (s *Service) SetPresence(agentID string, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if online {
		s.online[agentID] = true
	} else {
		delete(s.online, agentID)
	}
	h, ok := s.index.HostByAgent(agentID)
	if !ok {
		return
	}
	status := StatusOffline
	if online {
		status = StatusOnline
	}
	changed, err := s.repo.SetHostStatus(h.ID, status, s.now())
	if err != nil {
		s.log.Error("record host status", "agent_id", agentID, "error", err)
		return
	}
	if changed {
		h.Status, h.LastSeenAt = status, s.now()
		s.index.setHost(h)
		s.hub.Publish(EventHostUpdated, h)
	}
}

// HandleMessage consumes inventory messages from an agent stream. The agent ID comes from
// the authenticated certificate; nothing inside a message can name another host.
func (s *Service) HandleMessage(agentID string, m *agentv1.AgentMessage) {
	switch body := m.GetBody().(type) {
	case *agentv1.AgentMessage_Snapshot:
		s.applySnapshot(agentID, body.Snapshot)
	case *agentv1.AgentMessage_Event:
		s.applyEvent(agentID, body.Event)
	}
}

func (s *Service) applySnapshot(agentID string, snap *agentv1.InventorySnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host, ok := s.upsertHostLocked(agentID, snap.GetHost())
	if !ok {
		return
	}

	list := make([]Container, 0, len(snap.GetContainers()))
	seen := map[string]bool{}
	for _, pc := range snap.GetContainers() {
		c, ok := containerFromProto(host.ID, pc)
		if !ok || seen[c.RuntimeID] {
			continue
		}
		if len(list) >= maxContainers {
			break
		}
		seen[c.RuntimeID] = true
		list = append(list, c)
	}
	changes, err := s.repo.ReplaceContainers(host.ID, list, s.now())
	if err != nil {
		s.log.Error("apply snapshot", "agent_id", agentID, "error", err)
		return
	}
	for _, ch := range changes {
		s.publishContainerLocked(ch)
	}
}

func (s *Service) applyEvent(agentID string, ev *agentv1.InventoryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch change := ev.GetChange().(type) {
	case *agentv1.InventoryEvent_Host:
		s.upsertHostLocked(agentID, change.Host.GetHost())
	case *agentv1.InventoryEvent_Container:
		host, ok := s.index.HostByAgent(agentID)
		if !ok {
			return // no snapshot yet: the snapshot that follows carries the full state
		}
		cc := change.Container
		if cc.GetContainer() == nil || !runtimeIDPattern.MatchString(cc.GetContainer().GetRuntimeId()) {
			return
		}
		var ch *ContainerChange
		var err error
		if cc.GetKind() == agentv1.ContainerChange_KIND_REMOVED {
			ch, err = s.repo.RemoveContainer(host.ID, cc.GetContainer().GetRuntimeId(), s.now())
		} else if c, ok := containerFromProto(host.ID, cc.GetContainer()); ok {
			ch, err = s.repo.ApplyContainer(c)
		}
		if err != nil {
			s.log.Error("apply container change", "agent_id", agentID, "error", err)
			return
		}
		if ch != nil {
			s.publishContainerLocked(*ch)
		}
	}
}

// upsertHostLocked stores the host's facts and announces creation or a change.
func (s *Service) upsertHostLocked(agentID string, pf *agentv1.HostFacts) (Host, bool) {
	if pf == nil {
		return Host{}, false
	}
	now := s.now()
	h := hostFromProto(agentID, pf)
	h.Status, h.LastSeenAt = StatusOffline, now
	if s.online[agentID] {
		h.Status = StatusOnline
	}
	before, existed := s.index.HostByAgent(agentID)
	if existed {
		h.ID, h.Owner, h.FirstSeenAt = before.ID, before.Owner, before.FirstSeenAt
	}
	stored, created, err := s.repo.UpsertHost(h)
	if err != nil {
		s.log.Error("store host", "agent_id", agentID, "error", err)
		return Host{}, false
	}
	s.index.setHost(stored)
	switch {
	case created:
		s.hub.Publish(EventHostCreated, stored)
	case !sameHost(before, stored):
		s.hub.Publish(EventHostUpdated, stored)
	}
	return stored, true
}

func (s *Service) publishContainerLocked(ch ContainerChange) {
	s.index.setContainer(ch.Container)
	typ := EventContainerUpdated
	switch {
	case ch.Removed:
		typ = EventContainerRemoved
	case ch.Created:
		typ = EventContainerCreated
	}
	s.hub.Publish(typ, ch.Container)
}

// sameHost compares what viewers see, ignoring the last-seen time.
func sameHost(a, b Host) bool {
	a.LastSeenAt, b.LastSeenAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

func hostFromProto(agentID string, p *agentv1.HostFacts) Host {
	facts := map[string]string{}
	keys := make([]string, 0, len(p.GetFacts()))
	for k := range p.GetFacts() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(facts) >= maxFacts {
			break
		}
		facts[trim(k, maxShort)] = trim(p.GetFacts()[k], maxFactValue)
	}
	return Host{
		AgentID: agentID, Hostname: trim(p.GetHostname(), maxName), OS: trim(p.GetOs(), maxShort), Distro: trim(p.GetDistro(), maxName),
		Kernel: trim(p.GetKernel(), maxShort), Arch: trim(p.GetArch(), maxShort), CPUCount: int(min(p.GetCpuCount(), 1<<20)),
		MemoryBytes: int64(min(p.GetMemoryBytes(), 1<<62)), Facts: facts, //nolint:gosec // clamped above
	}
}

// containerFromProto converts and bounds a reported container. ok is false when it cannot be identified.
func containerFromProto(hostID string, p *agentv1.Container) (Container, bool) {
	if p == nil || !runtimeIDPattern.MatchString(p.GetRuntimeId()) {
		return Container{}, false
	}
	rt := ""
	switch p.GetRuntime() {
	case agentv1.Runtime_RUNTIME_DOCKER:
		rt = "docker"
	case agentv1.Runtime_RUNTIME_PODMAN:
		rt = "podman"
	default:
		return Container{}, false
	}
	c := Container{
		HostID: hostID, Runtime: rt, RuntimeID: p.GetRuntimeId(), Name: trim(p.GetName(), maxName), Image: trim(p.GetImage(), maxImage),
		State: trim(p.GetState(), maxShort), Ports: []Port{}, Labels: map[string]string{}, RestartCount: int(min(p.GetRestartCount(), 1<<30)),
	}
	for _, pm := range p.GetPorts() {
		if len(c.Ports) >= maxPorts {
			break
		}
		proto := strings.ToLower(pm.GetProtocol())
		if !protocolNames[proto] || pm.GetHostPort() > 65535 || pm.GetContainerPort() > 65535 {
			continue
		}
		c.Ports = append(c.Ports, Port{HostIP: trim(pm.GetHostIp(), 64), HostPort: int(pm.GetHostPort()), ContainerPort: int(pm.GetContainerPort()), Protocol: proto})
	}
	keys := make([]string, 0, len(p.GetLabels()))
	for k := range p.GetLabels() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(c.Labels) >= maxLabels {
			break
		}
		c.Labels[trim(k, maxName)] = trim(p.GetLabels()[k], maxLabelValue)
	}
	if ms := p.GetCreatedAtUnixMs(); ms > 0 {
		t := time.UnixMilli(ms).UTC()
		c.CreatedAt = &t
	}
	return c, true
}

// trim cuts s to n bytes on a rune boundary and drops control characters, which have no place in a name.
func trim(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

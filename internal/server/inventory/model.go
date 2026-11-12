// SPDX-License-Identifier: AGPL-3.0-only

// Package inventory holds the server's picture of hosts and containers. Agents
// send a snapshot after every connect and then change events; this package
// stores them, keeps an in-memory index for reads, and fans changes out to
// live subscribers (INV-1, INV-2).
package inventory

import (
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

// Host states.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusGone    = "gone"
)

// Host is one machine running an agent.
type Host struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	Distro      string            `json:"distro"`
	Kernel      string            `json:"kernel"`
	Arch        string            `json:"arch"`
	CPUCount    int               `json:"cpu_count"`
	MemoryBytes int64             `json:"memory_bytes"`
	Facts       map[string]string `json:"facts"`
	Owner       string            `json:"owner"`
	Tags        map[string]string `json:"tags"`
	ETag        string            `json:"etag"`
	Status      string            `json:"status"`
	FirstSeenAt time.Time         `json:"first_seen_at"`
	LastSeenAt  time.Time         `json:"last_seen_at"`
	GoneAt      *time.Time        `json:"gone_at"`
}

// Port is a published container port.
type Port struct {
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Container is one container on a host. Labels arrive already redacted by nux-sockguard.
type Container struct {
	ID           string            `json:"id"`
	HostID       string            `json:"host_id"`
	Runtime      string            `json:"runtime"`
	RuntimeID    string            `json:"runtime_id"`
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	State        string            `json:"state"`
	Ports        []Port            `json:"ports"`
	Labels       map[string]string `json:"labels"`
	Owner        string            `json:"owner"`
	Tags         map[string]string `json:"tags"`
	ETag         string            `json:"etag"`
	RestartCount int               `json:"restart_count"`
	CreatedAt    *time.Time        `json:"created_at"`
	GoneAt       *time.Time        `json:"gone_at"`
}

// Event types pushed to live subscribers.
const (
	EventHostCreated      = "host.created"
	EventHostUpdated      = "host.updated"
	EventContainerCreated = "container.created"
	EventContainerUpdated = "container.updated"
	EventContainerRemoved = "container.removed"
	// EventResync tells a subscriber it fell behind and must reload through the REST API.
	EventResync = "resync"
)

// Event is one change. Item is a Host or Container (absent for resync).
type Event struct {
	Seq  uint64    `json:"-"`
	Type string    `json:"type"`
	At   time.Time `json:"at"`
	Item any       `json:"item,omitempty"`
}

// Repository is the persistence the module needs. Writes are single transactions.
type Repository interface {
	// LoadInventory returns every stored host and container, to warm the index at start.
	LoadInventory() ([]Host, []Container, error)
	// UpsertHost creates the host for an agent or updates its facts. created reports a new row.
	UpsertHost(h Host) (stored Host, created bool, err error)
	// SetHostStatus changes a host's status and last-seen time. It reports whether the row changed.
	SetHostStatus(hostID, status string, at time.Time) (changed bool, err error)
	// ReplaceContainers makes the host's live containers exactly list (marking the others gone) in one
	// transaction and returns what changed.
	ReplaceContainers(hostID string, list []Container, at time.Time) ([]ContainerChange, error)
	// ApplyContainer upserts one container (gone cleared) and reports the change; no change means nil.
	ApplyContainer(c Container) (*ContainerChange, error)
	// RemoveContainer marks a container gone and reports the change; unknown or already gone means nil.
	RemoveContainer(hostID, runtimeID string, at time.Time) (*ContainerChange, error)
	// UpdateMeta changes the owner and/or tags of one item and appends ev, all in one transaction. It
	// returns ErrNotFound for an unknown item and ErrStale when the item's ETag is not ifMatch.
	UpdateMeta(itemType, itemID, ifMatch string, change MetaChange, ev audit.Event) (owner string, tags map[string]string, err error)
}

// ContainerChange is what a write changed.
type ContainerChange struct {
	Created   bool
	Removed   bool
	Container Container
}

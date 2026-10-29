// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"

	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
)

// CheckSource is what the engine needs from the checks module; *checks.Service implements it.
type CheckSource interface {
	States(ctx context.Context) ([]checks.State, error)
	Hub() *checks.Hub
}

// Inventory is what the engine needs from the inventory module. Use FromInventory to adapt
// *inventory.Service.
type Inventory interface {
	Hosts() []inventory.Host
	Containers() []inventory.Container
	Host(id string) (inventory.Host, bool)
	Container(id string) (inventory.Container, bool)
	Subscribe() (*inventory.Subscription, error)
}

// MetricSource is the latest-value accessor of the metrics module; *metrics.Service implements it.
type MetricSource interface {
	Pressure(ctx context.Context, limit int) (metrics.PressureReport, error)
}

// Sink takes notifications for delivery. Enqueue never blocks; false means the message was dropped.
type Sink interface {
	Enqueue(channelID string, m notify.Message) bool
}

type invAdapter struct{ s *inventory.Service }

// FromInventory adapts the inventory service.
func FromInventory(s *inventory.Service) Inventory { return invAdapter{s} }

func (a invAdapter) Hosts() []inventory.Host {
	var out []inventory.Host
	for cursor := ""; ; {
		p := a.s.Index().Hosts(inventory.HostFilter{IncludeGone: true}, cursor, 500)
		out = append(out, p.Items...)
		if p.NextCursor == "" {
			return out
		}
		cursor = p.NextCursor
	}
}

func (a invAdapter) Containers() []inventory.Container {
	var out []inventory.Container
	for cursor := ""; ; {
		p := a.s.Index().Containers(inventory.ContainerFilter{}, cursor, 500)
		out = append(out, p.Items...)
		if p.NextCursor == "" {
			return out
		}
		cursor = p.NextCursor
	}
}

func (a invAdapter) Host(id string) (inventory.Host, bool) { return a.s.Index().Host(id) }
func (a invAdapter) Container(id string) (inventory.Container, bool) {
	return a.s.Index().Container(id)
}
func (a invAdapter) Subscribe() (*inventory.Subscription, error) { return a.s.Subscribe() }

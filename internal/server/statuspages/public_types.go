// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import "time"

// Status levels shown publicly.
type Status string

// The only values a public status can take.
const (
	StatusOperational Status = "operational"
	StatusDegraded    Status = "degraded"
	StatusOutage      Status = "outage"
	StatusUnknown     Status = "unknown"
)

// PublicPage is the anonymous projection of a published page (STP-3). It is a separate type
// from every internal one on purpose: it has no field that could carry a hostname, address,
// check ID, check name, target or error message, and it is the only thing the public handler
// and renderers accept. Adding a field here is a security decision.
type PublicPage struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Status      Status            `json:"status"`
	GeneratedAt time.Time         `json:"generated_at"`
	Components  []PublicComponent `json:"components"`
	Incidents   []PublicIncident  `json:"incidents"`
}

// PublicComponent is one named group of checks.
type PublicComponent struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	// Uptime90d is a percentage, or null when there is no data.
	Uptime90d *float64    `json:"uptime_90d"`
	Days      []PublicDay `json:"days"`
}

// PublicDay is one UTC day of the history bar, oldest first.
type PublicDay struct {
	Date   string `json:"date"`
	Status Status `json:"status"`
}

// PublicIncident is an incident note posted by the team.
type PublicIncident struct {
	Title      string         `json:"title"`
	Body       string         `json:"body"`
	Status     string         `json:"status"`
	Impact     string         `json:"impact"`
	StartedAt  time.Time      `json:"started_at"`
	ResolvedAt *time.Time     `json:"resolved_at"`
	Updates    []PublicUpdate `json:"updates"`
}

// PublicUpdate is one timeline entry of an incident.
type PublicUpdate struct {
	Status string    `json:"status"`
	Body   string    `json:"body"`
	At     time.Time `json:"at"`
}

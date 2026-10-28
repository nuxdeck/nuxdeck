// SPDX-License-Identifier: AGPL-3.0-only

package statuspages

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"
)

//go:embed page.html
var pageTemplate string

//go:embed assets/status.css
var statusCSS []byte

var tmpl = template.Must(template.New("page").Parse(pageTemplate))

// maxHTML caps a rendered page; the document limits keep real pages far below it.
const maxHTML = 1 << 20

type viewDay struct{ Class, Title string }

type viewComponent struct {
	Name, StatusClass, StatusText, Summary string
	Days                                   []viewDay
}

type viewUpdate struct {
	StatusText, At, AtISO string
	Lines                 []string
}

type viewIncident struct {
	Title, StatusClass, StatusText, Started, StartedISO, Resolved, ResolvedISO string
	Lines                                                                      []string
	Updates                                                                    []viewUpdate
}

type viewPage struct {
	Title, StatusClass, StatusText, Generated, GeneratedISO string
	Description                                             string
	DescriptionLines                                        []string
	Components                                              []viewComponent
	Incidents                                               []viewIncident
}

var statusText = map[Status]string{
	StatusOperational: "All systems operational",
	StatusDegraded:    "Partial degradation",
	StatusOutage:      "Major outage",
	StatusUnknown:     "Status unknown",
}

var componentText = map[Status]string{
	StatusOperational: "Operational",
	StatusDegraded:    "Degraded",
	StatusOutage:      "Outage",
	StatusUnknown:     "Unknown",
}

var incidentText = map[string]string{
	IncInvestigating: "Investigating", IncIdentified: "Identified", IncMonitoring: "Monitoring", IncResolved: "Resolved",
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func incidentClass(status, impact string) string {
	switch {
	case status == IncResolved:
		return "st-operational"
	case impact == ImpactMajor:
		return "st-outage"
	case impact == ImpactMinor:
		return "st-degraded"
	}
	return "st-unknown"
}

// renderHTML renders p with html/template: every value is escaped for its context, and the
// page carries no script, inline style or external resource.
func renderHTML(p PublicPage) ([]byte, error) {
	v := viewPage{
		Title: p.Title, Description: p.Description, DescriptionLines: lines(p.Description),
		StatusClass: "st-" + string(p.Status), StatusText: statusText[p.Status],
		Generated: stamp(p.GeneratedAt), GeneratedISO: p.GeneratedAt.UTC().Format(time.RFC3339),
	}
	for _, c := range p.Components {
		vc := viewComponent{Name: c.Name, StatusClass: "st-" + string(c.Status), StatusText: componentText[c.Status]}
		if c.Uptime90d != nil {
			vc.Summary = fmt.Sprintf("%s over the last 90 days, %.3g%% uptime", componentText[c.Status], *c.Uptime90d)
		} else {
			vc.Summary = componentText[c.Status] + ", no uptime data for the last 90 days"
		}
		for _, d := range c.Days {
			vc.Days = append(vc.Days, viewDay{Class: "st-" + string(d.Status), Title: d.Date + ": " + componentText[d.Status]})
		}
		v.Components = append(v.Components, vc)
	}
	for _, in := range p.Incidents {
		vi := viewIncident{
			Title: in.Title, Lines: lines(in.Body), StatusClass: incidentClass(in.Status, in.Impact), StatusText: incidentText[in.Status],
			Started: stamp(in.StartedAt), StartedISO: in.StartedAt.UTC().Format(time.RFC3339),
		}
		if in.ResolvedAt != nil {
			vi.Resolved, vi.ResolvedISO = stamp(*in.ResolvedAt), in.ResolvedAt.UTC().Format(time.RFC3339)
		}
		// The first update repeats the opening note; the timeline shows only what followed.
		for i, u := range in.Updates {
			if i == 0 {
				continue
			}
			vi.Updates = append(vi.Updates, viewUpdate{StatusText: incidentText[u.Status], At: stamp(u.At), AtISO: u.At.UTC().Format(time.RFC3339), Lines: lines(u.Body)})
		}
		v.Incidents = append(v.Incidents, vi)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("render status page: %w", err)
	}
	if buf.Len() > maxHTML {
		return nil, fmt.Errorf("render status page: %d bytes exceeds the %d byte cap", buf.Len(), maxHTML)
	}
	return buf.Bytes(), nil
}

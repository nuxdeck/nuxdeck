// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"bytes"
	"encoding/json"
	"math"
)

// Params of each rule kind. Unknown fields are refused and every value has a bound.

// CommonParams is the for-duration every kind accepts: the condition must hold this long
// before the alert opens.
type CommonParams struct {
	ForS *int `json:"for_s,omitempty"`
}

// CheckDownParams holds the params of check_down.
type CheckDownParams struct {
	CommonParams
}

// HostOfflineParams holds the params of host_offline.
type HostOfflineParams struct {
	CommonParams
}

// ContainerParams holds the params of container_stopped.
type ContainerParams struct {
	// Mode is stopped (exited or dead), restart_loop, or either (default).
	Mode string `json:"mode,omitempty"`
	// Restarts and WindowS define a restart loop: at least Restarts restarts within WindowS.
	Restarts int `json:"restarts,omitempty"`
	WindowS  int `json:"window_s,omitempty"`
	CommonParams
}

// MetricParams holds the params of metric_threshold.
type MetricParams struct {
	Target    string   `json:"target"`    // host or container
	Metric    string   `json:"metric"`    // cpu, memory or disk (hosts only)
	Threshold *float64 `json:"threshold"` // percent, above which the condition holds
	CommonParams
}

// TLSParams holds the params of tls_expiring.
type TLSParams struct {
	Days int `json:"days"`
	CommonParams
}

// Container modes.
const (
	ModeStopped     = "stopped"
	ModeRestartLoop = "restart_loop"
	ModeEither      = "either"
)

const (
	maxForS          = 86400
	defaultMetricFor = 300
)

func (c CommonParams) forS(def int) int {
	if c.ForS == nil {
		return def
	}
	return *c.ForS
}

func (c *CommonParams) fill(def int) error {
	if c.ForS == nil {
		v := def
		c.ForS = &v
	}
	if *c.ForS < 0 || *c.ForS > maxForS {
		return bad("params.for_s", "Use 0 to 86400 seconds.")
	}
	return nil
}

func strictDecode(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return bad("params", "The parameters have an unknown or malformed field for this rule kind.")
	}
	if dec.More() {
		return bad("params", "Unexpected data after the parameters.")
	}
	return nil
}

// parseParams validates raw for kind and returns the typed value with defaults filled in.
func parseParams(kind string, raw json.RawMessage) (any, error) {
	switch kind {
	case KindCheckDown:
		var p CheckDownParams
		if err := strictDecode(raw, &p); err != nil {
			return nil, err
		}
		return &p, p.fill(0)
	case KindHostOffline:
		var p HostOfflineParams
		if err := strictDecode(raw, &p); err != nil {
			return nil, err
		}
		return &p, p.fill(0)
	case KindContainerStopped:
		var p ContainerParams
		if err := strictDecode(raw, &p); err != nil {
			return nil, err
		}
		if p.Mode == "" {
			p.Mode = ModeEither
		}
		if p.Mode != ModeStopped && p.Mode != ModeRestartLoop && p.Mode != ModeEither {
			return nil, bad("params.mode", "Use stopped, restart_loop or either.")
		}
		if p.Restarts == 0 {
			p.Restarts = 3
		}
		if p.WindowS == 0 {
			p.WindowS = 600
		}
		if p.Restarts < 2 || p.Restarts > 100 {
			return nil, bad("params.restarts", "Use 2 to 100 restarts.")
		}
		if p.WindowS < 60 || p.WindowS > 3600 {
			return nil, bad("params.window_s", "Use 60 to 3600 seconds.")
		}
		return &p, p.fill(0)
	case KindMetricThreshold:
		var p MetricParams
		if err := strictDecode(raw, &p); err != nil {
			return nil, err
		}
		if p.Target != ItemHost && p.Target != ItemContainer {
			return nil, bad("params.target", "Use host or container.")
		}
		if p.Metric != "cpu" && p.Metric != "memory" && p.Metric != "disk" {
			return nil, bad("params.metric", "Use cpu, memory or disk.")
		}
		if p.Metric == "disk" && p.Target != ItemHost {
			return nil, bad("params.metric", "Disk usage is only available for hosts.")
		}
		if p.Threshold == nil || math.IsNaN(*p.Threshold) || *p.Threshold <= 0 || *p.Threshold > 100 {
			return nil, bad("params.threshold", "Use a percentage above 0 and up to 100.")
		}
		return &p, p.fill(defaultMetricFor)
	case KindTLSExpiring:
		var p TLSParams
		if err := strictDecode(raw, &p); err != nil {
			return nil, err
		}
		if p.Days < 1 || p.Days > 825 {
			return nil, bad("params.days", "Use 1 to 825 days.")
		}
		return &p, p.fill(0)
	default:
		return nil, bad("kind", "Use check_down, host_offline, container_stopped, metric_threshold or tls_expiring.")
	}
}

// itemTypeOf is the kind of item a rule alerts on.
func itemTypeOf(kind string, p any) string {
	switch kind {
	case KindCheckDown, KindTLSExpiring:
		return ItemCheck
	case KindHostOffline:
		return ItemHost
	case KindContainerStopped:
		return ItemContainer
	default:
		return p.(*MetricParams).Target
	}
}

func marshalParams(p any) json.RawMessage {
	b, _ := json.Marshal(p)
	return b
}

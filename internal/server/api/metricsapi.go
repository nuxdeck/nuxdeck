// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/metrics"
)

type metricsAPI struct {
	*authAPI
	m   *metrics.Service
	inv *inventory.Service
}

func (a *metricsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/metrics/query", a.query)
	mux.HandleFunc("GET /api/v1/overview/pressure", a.pressure)
}

func (a *metricsAPI) bad(w http.ResponseWriter, field, hint string) {
	writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, field, hint)
}

// query serves chart data: target (host or container ID), metric, from, to (unix ms or
// RFC 3339), step (seconds, optional) and repeated label=name:value filters.
func (a *metricsAPI) query(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionMetricsRead); !ok {
		return
	}
	v := r.URL.Query()
	target := v.Get("target")
	if !ulid.MatchString(target) {
		a.bad(w, "target", "Use a host or container ID.")
		return
	}
	var targetType string
	switch {
	case hostExists(a.inv, target):
		targetType = metrics.TargetHost
	case containerExists(a.inv, target):
		targetType = metrics.TargetContainer
	default:
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	q := metrics.Query{TargetType: targetType, Target: target, Metric: v.Get("metric")}
	var ok bool
	if q.From, ok = parseTime(v.Get("from")); !ok {
		a.bad(w, "from", "Use unix milliseconds or an RFC 3339 time.")
		return
	}
	if q.To, ok = parseTime(v.Get("to")); !ok {
		a.bad(w, "to", "Use unix milliseconds or an RFC 3339 time.")
		return
	}
	if s := v.Get("step"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 86400 {
			a.bad(w, "step", "Use a whole number of seconds from 1 to 86400.")
			return
		}
		q.Step = time.Duration(n) * time.Second
	}
	if ls := v["label"]; len(ls) > 0 {
		if len(ls) > 4 {
			a.bad(w, "label", "Use at most 4 label filters.")
			return
		}
		q.Labels = map[string]string{}
		for _, l := range ls {
			k, val, found := strings.Cut(l, ":")
			if !found || k == "" {
				a.bad(w, "label", "Use name:value.")
				return
			}
			q.Labels[k] = val
		}
	}
	res, err := a.m.Query(r.Context(), q)
	var inv *metrics.ErrInvalidQuery
	switch {
	case errors.As(err, &inv):
		a.bad(w, inv.Field, inv.Hint)
	case err != nil:
		a.log.Error("metrics query failed", "request_id", requestID(r.Context()), "error", err)
		writeError(w, http.StatusInternalServerError, errcode.APIInt001)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

func (a *metricsAPI) pressure(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionMetricsRead); !ok {
		return
	}
	limit := defaultPageSize
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPageSize {
			a.bad(w, "limit", fmt.Sprintf("Use a whole number from 1 to %d.", maxPageSize))
			return
		}
		limit = n
	}
	rep, err := a.m.Pressure(r.Context(), limit)
	if err != nil {
		a.log.Error("pressure ranking failed", "request_id", requestID(r.Context()), "error", err)
		writeError(w, http.StatusInternalServerError, errcode.APIInt001)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func hostExists(inv *inventory.Service, id string) bool {
	_, ok := inv.Index().Host(id)
	return ok
}

func containerExists(inv *inventory.Service, id string) bool {
	_, ok := inv.Index().Container(id)
	return ok
}

// parseTime reads unix milliseconds (13+ digits or any integer) or RFC 3339.
func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 || n > 4102444800000 {
			return time.Time{}, false
		}
		return time.UnixMilli(n), true
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

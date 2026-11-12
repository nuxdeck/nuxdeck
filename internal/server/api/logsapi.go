// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/logs"
)

// Auditor appends an audit entry; *store.Store implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, ev audit.Event) error
}

// LogScope decides whether the caller may read logs of a host, and of one container on it
// (containerID is empty for a journal unit). It is the hook for tag-scoped roles (NUX-37);
// nil allows every host to anyone holding the viewer role.
type LogScope func(ctx context.Context, p auth.Principal, hostID, containerID string) bool

const (
	defaultTail   = 100
	maxTail       = 10000
	maxFilterLen  = 256
	wsWriteLimit  = 10 * time.Second
	wsReadLimit   = 1 << 10 // browsers send nothing; this only bounds a misbehaving client
	closeSlowText = "too slow"
)

// wsKeepalive is how often an idle log socket is pinged and its session rechecked; tests shorten it.
var wsKeepalive = 15 * time.Second

var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}$`)

type logsAPI struct {
	*authAPI
	inv    *inventory.Service
	broker *logs.Broker
	audit  Auditor
	scope  LogScope
}

func (a *logsAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/logs/stream", a.stream)
}

// logTarget is a validated target= value.
type logTarget struct {
	kind        string
	containerID string // inventory ID, for containers
	hostID      string // for journal units
	unit        string
	raw         string
}

// parseTarget accepts container:<container ID> and journal:<host ID>:<unit>.
func parseTarget(v string) (logTarget, bool) {
	kind, rest, ok := strings.Cut(v, ":")
	if !ok {
		return logTarget{}, false
	}
	switch kind {
	case logs.KindContainer:
		if ulid.MatchString(rest) {
			return logTarget{kind: kind, containerID: rest, raw: v}, true
		}
	case logs.KindJournal:
		host, unit, ok := strings.Cut(rest, ":")
		if ok && ulid.MatchString(host) && unitName.MatchString(unit) {
			return logTarget{kind: kind, hostID: host, unit: unit, raw: v}, true
		}
	}
	return logTarget{}, false
}

// stream serves GET /api/v1/logs/stream as a WebSocket. The order is fixed: authorise,
// validate, check the origin, resolve the target and the caller's scope, reserve a slot,
// audit, and only then upgrade. See logs.Event for the messages.
func (a *logsAPI) stream(w http.ResponseWriter, r *http.Request) {
	p, _, ok := a.begin(w, r, auth.ActionLogsStream)
	if !ok {
		return
	}

	q := r.URL.Query()
	target, ok := parseTarget(q.Get("target"))
	if !ok {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "target", "Use container:<container ID> or journal:<host ID>:<unit>.")
		return
	}
	tail := uint32(defaultTail)
	if v := q.Get("tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxTail {
			writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "tail", "Use a whole number from 0 to "+strconv.Itoa(maxTail)+".")
			return
		}
		tail = uint32(n) //nolint:gosec // bounded above
	}
	filter := q.Get("filter")
	if !validFilter(filter) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "filter", "Use plain text of up to 256 characters.")
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeErrorDetail(w, http.StatusBadRequest, errcode.APIVal001, "", "This endpoint speaks WebSocket.")
		return
	}
	if !sameOrigin(r) { // a page on another site must not borrow the visitor's session
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "cross-site WebSocket"))
		return
	}

	host, container, ok := a.resolve(target)
	if !ok {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	res := logResource(target, host, container)
	if err := auth.AuthorizeOn(p, auth.ActionLogsStream, res); err != nil { // LOG-7: per target, before any slot or audit entry
		a.fail(w, r, err)
		return
	}
	if a.scope != nil && !a.scope(r.Context(), p, host.ID, container.ID) {
		a.fail(w, r, errcode.New(errcode.AuthDeny005, "logs of host %s are outside the caller's scope", host.ID))
		return
	}
	if host.Status != inventory.StatusOnline {
		writeError(w, http.StatusConflict, errcode.LOGSrc003)
		return
	}

	t := logs.Target{AgentID: host.AgentID, Kind: target.kind, Source: target.unit}
	if target.kind == logs.KindContainer {
		t.Source = container.RuntimeID
	}
	watcher, err := a.broker.Watch(p.UserID, t, tail)
	switch {
	case errors.Is(err, logs.ErrLimit):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, errcode.LOGStr001)
		return
	case errors.Is(err, logs.ErrAgentOffline):
		writeError(w, http.StatusConflict, errcode.LOGSrc003)
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}
	defer watcher.Close()

	// Log content is never audited; the entry says who opened which source.
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: "logs.stream", TargetType: target.kind, IP: clientOf(r).IP, Result: audit.ResultSuccess,
		Details: map[string]any{"host_id": host.ID, "tail": tail, "filtered": filter != ""},
	}
	if target.kind == logs.KindContainer {
		ev.TargetID = container.ID
		ev.Details["container_name"] = container.Name
	} else {
		ev.TargetID = target.unit
	}
	if err := a.audit.RecordAudit(r.Context(), ev); err != nil { // fail closed: no audit entry, no stream
		a.fail(w, r, err)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept has answered the client
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(wsReadLimit)
	a.pump(r, conn, watcher, strings.ToLower(filter), a.streamRecheck(r, target))
}

// resolve finds the host (and container) behind a target in the inventory.
func (a *logsAPI) resolve(t logTarget) (inventory.Host, inventory.Container, bool) {
	ix := a.inv.Index()
	if t.kind == logs.KindJournal {
		h, ok := ix.Host(t.hostID)
		return h, inventory.Container{}, ok && h.GoneAt == nil
	}
	c, ok := ix.Container(t.containerID)
	if !ok || c.GoneAt != nil {
		return inventory.Host{}, inventory.Container{}, false
	}
	h, ok := ix.Host(c.HostID)
	return h, c, ok && h.GoneAt == nil
}

func validFilter(f string) bool {
	if len(f) > maxFilterLen || !utf8.ValidString(f) {
		return false
	}
	for _, r := range f {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// pump copies events to the socket until either side ends. The browser sends nothing, so
// CloseRead only watches for it going away.
// streamRecheck returns the check run on every keepalive. It looks the caller up again, resolves the
// target again and applies the scope rules again, so a revoked session, a changed role or a container or
// host that moved out of scope ends the stream without waiting for the browser to reconnect.
func (a *logsAPI) streamRecheck(r *http.Request, target logTarget) func(context.Context) bool {
	return func(ctx context.Context) bool {
		p, ok := a.reauthenticate(ctx, r)
		if !ok {
			return false
		}
		host, container, ok := a.resolve(target)
		if !ok || auth.AuthorizeOn(p, auth.ActionLogsStream, logResource(target, host, container)) != nil {
			return false
		}
		return a.scope == nil || a.scope(ctx, p, host.ID, container.ID)
	}
}

func (a *logsAPI) pump(r *http.Request, conn *websocket.Conn, wt *logs.Watcher, lowerFilter string, recheck func(context.Context) bool) {
	ctx := conn.CloseRead(r.Context())
	tick := time.NewTicker(wsKeepalive)
	defer tick.Stop()

	write := func(ev logs.Event) bool {
		b, err := json.Marshal(ev)
		if err != nil {
			a.log.Error("encode log event", "type", ev.Type, "error", err)
			return true
		}
		wctx, cancel := context.WithTimeout(ctx, wsWriteLimit)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, b) == nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-wt.C:
			if !ok {
				_ = conn.Close(websocket.StatusNormalClosure, "")
				return
			}
			if ev.Type == logs.TypeLine && lowerFilter != "" && !strings.Contains(strings.ToLower(ev.Text), lowerFilter) {
				continue
			}
			if !write(ev) {
				_ = conn.Close(websocket.StatusPolicyViolation, closeSlowText)
				return
			}
		case <-tick.C:
			// A long-lived stream must not outlive the authority that opened it.
			if !recheck(ctx) {
				write(logs.Event{Type: logs.TypeEnd, Reason: logs.ReasonSessionExpired})
				_ = conn.Close(websocket.StatusPolicyViolation, "session ended")
				return
			}
			pctx, cancel := context.WithTimeout(ctx, wsWriteLimit)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// logResource is the scope resource of a log target: the container's tags over its host's, or the host's for a journal unit.
func logResource(t logTarget, h inventory.Host, c inventory.Container) auth.Resource {
	if t.kind == logs.KindContainer {
		return containerResource(c, h)
	}
	return hostResource(h)
}

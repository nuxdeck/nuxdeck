// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

const (
	defaultPageSize = 50
	maxPageSize     = 500
	sseWriteTimeout = 10 * time.Second
)

// sseKeepalive is how often an idle event stream sends a comment and rechecks its session; tests shorten it.
var sseKeepalive = 15 * time.Second

var (
	statePattern = regexp.MustCompile(`^[a-z]{1,32}$`)
	hostStatuses = map[string]bool{inventory.StatusOnline: true, inventory.StatusOffline: true}
)

type inventoryAPI struct {
	*authAPI
	inv *inventory.Service
}

func (a *inventoryAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hosts", a.listHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", a.getHost)
	mux.HandleFunc("GET /api/v1/containers", a.listContainers)
	mux.HandleFunc("GET /api/v1/containers/{id}", a.getContainer)
	mux.HandleFunc("GET /api/v1/events", a.events)
}

type pageJSON[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func page[T any](p inventory.Page[T]) pageJSON[T] {
	out := pageJSON[T]{Items: p.Items}
	if p.NextCursor != "" {
		out.NextCursor = &p.NextCursor
	}
	return out
}

// listParams reads the shared pagination and gone-filter parameters.
func (a *inventoryAPI) listParams(w http.ResponseWriter, r *http.Request) (cursor string, limit int, includeGone, ok bool) {
	q := r.URL.Query()
	limit = defaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "limit", fmt.Sprintf("Use a whole number from 1 to %d.", maxPageSize))
			return "", 0, false, false
		}
		limit = n
	}
	if cursor = q.Get("cursor"); cursor != "" && !ulid.MatchString(cursor) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
		return "", 0, false, false
	}
	switch q.Get("include_gone") {
	case "", "0", "false":
	case "1", "true":
		includeGone = true
	default:
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "include_gone", "Use true or false.")
		return "", 0, false, false
	}
	return cursor, limit, includeGone, true
}

func (a *inventoryAPI) listHosts(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionInventoryRead); !ok {
		return
	}
	cursor, limit, gone, ok := a.listParams(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && !hostStatuses[status] {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "status", "Use online or offline.")
		return
	}
	writeJSON(w, http.StatusOK, page(a.inv.Index().Hosts(inventory.HostFilter{Status: status, IncludeGone: gone}, cursor, limit)))
}

func (a *inventoryAPI) listContainers(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionInventoryRead); !ok {
		return
	}
	cursor, limit, gone, ok := a.listParams(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if v := q.Get("host_id"); v != "" && !ulid.MatchString(v) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "host_id", "Use a host ID.")
		return
	}
	if v := q.Get("state"); v != "" && !statePattern.MatchString(v) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "state", "Use a container state such as running or exited.")
		return
	}
	f := inventory.ContainerFilter{HostID: q.Get("host_id"), State: q.Get("state"), IncludeGone: gone}
	writeJSON(w, http.StatusOK, page(a.inv.Index().Containers(f, cursor, limit)))
}

func (a *inventoryAPI) getHost(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionInventoryRead); !ok {
		return
	}
	id := r.PathValue("id")
	if h, found := a.inv.Index().Host(id); found && ulid.MatchString(id) {
		writeJSON(w, http.StatusOK, h)
		return
	}
	writeError(w, http.StatusNotFound, errcode.APINF001)
}

func (a *inventoryAPI) getContainer(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionInventoryRead); !ok {
		return
	}
	id := r.PathValue("id")
	if c, found := a.inv.Index().Container(id); found && ulid.MatchString(id) {
		writeJSON(w, http.StatusOK, c)
		return
	}
	writeError(w, http.StatusNotFound, errcode.APINF001)
}

// events streams inventory changes as Server-Sent Events. A client reloads through the REST
// API after connecting and after any `resync` event or reconnect; the stream carries changes only.
func (a *inventoryAPI) events(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionEventsStream); !ok {
		return
	}
	sub, err := a.inv.Subscribe()
	if errors.Is(err, inventory.ErrTooManySubscribers) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, errcode.APILim001)
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer sub.Close()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // proxies must not hold events back
	rc := http.NewResponseController(w)
	send := func(format string, args ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)) // a stalled client must not pin this goroutine
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.WriteHeader(http.StatusOK)
	if !send("retry: 3000\n: connected\n\n") {
		return
	}

	cookie, _ := r.Cookie(sessionCookie)
	tick := time.NewTicker(sseKeepalive)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			body, err := json.Marshal(ev)
			if err != nil {
				a.log.Error("encode event", "type", ev.Type, "error", err)
				continue
			}
			if !send("id: %d\nevent: %s\ndata: %s\n\n", ev.Seq, ev.Type, body) {
				return
			}
		case <-tick.C:
			// A long-lived stream must not outlive the session that opened it.
			if cookie == nil {
				return
			}
			if p, _, err := a.svc.Authenticate(r.Context(), cookie.Value); err != nil || !p.Authenticated() {
				return
			}
			if !send(": keepalive\n\n") {
				return
			}
		}
	}
}

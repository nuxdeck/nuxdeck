// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/checks"
)

// maxCheckBody bounds a check document: 20 headers of 1 KiB plus a 4 KiB body fit with room to spare.
const maxCheckBody = 64 << 10

// checkDoc is a request document: a check, tolerating the read-only status a GET adds, so a
// fetched document can be edited and sent back as it is. The status is ignored.
type checkDoc struct {
	checks.Check
	Status json.RawMessage `json:"status"`
}

type checksAPI struct {
	*authAPI
	checks *checks.Service
}

func (a *checksAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/checks", a.list)
	mux.HandleFunc("POST /api/v1/checks", a.create)
	mux.HandleFunc("GET /api/v1/checks/{id}", a.get)
	mux.HandleFunc("PUT /api/v1/checks/{id}", a.update)
	mux.HandleFunc("DELETE /api/v1/checks/{id}", a.remove)
	mux.HandleFunc("POST /api/v1/checks/{id}/run", a.run)
	mux.HandleFunc("GET /api/v1/checks/{id}/results", a.results)
	mux.HandleFunc("GET /api/v1/checks/{id}/uptime", a.uptime)
}

// pageParams reads limit and cursor; the cursor is opaque and validated by the service.
func pageParams(w http.ResponseWriter, r *http.Request) (cursor string, limit int, ok bool) {
	limit = defaultPageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxPageSize {
			writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "limit", "Use a whole number from 1 to 500.")
			return "", 0, false
		}
		limit = n
	}
	cursor = r.URL.Query().Get("cursor")
	if len(cursor) > 64 {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
		return "", 0, false
	}
	return cursor, limit, true
}

func (a *checksAPI) list(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionChecksRead); !ok {
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	if cursor != "" && !ulid.MatchString(cursor) {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "cursor", "Use the next_cursor value of the previous page.")
		return
	}
	items, next, err := a.checks.List(r.Context(), cursor, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := pageJSON[checks.View]{Items: items}
	if items == nil {
		out.Items = []checks.View{}
	}
	if next != "" {
		out.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *checksAPI) get(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionChecksRead); !ok {
		return
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	v, err := a.checks.Get(r.Context(), id)
	if a.checkErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", v.ETag())
	writeJSON(w, http.StatusOK, v)
}

// write is the shared head of the changing endpoints: authorise, CSRF and check ID.
func (a *checksAPI) write(w http.ResponseWriter, r *http.Request, action auth.Action, needID bool) (actor checks.Actor, id string, ok bool) {
	p, sess, ok := a.begin(w, r, action)
	if !ok {
		return checks.Actor{}, "", false
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return checks.Actor{}, "", false
	}
	if needID {
		id = r.PathValue("id")
		if !ulid.MatchString(id) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return checks.Actor{}, "", false
		}
	}
	return checks.Actor{UserID: p.UserID, IP: clientOf(r).IP}, id, true
}

func (a *checksAPI) create(w http.ResponseWriter, r *http.Request) {
	who, _, ok := a.write(w, r, auth.ActionChecksWrite, false)
	if !ok {
		return
	}
	var in checkDoc
	if !a.decodeMax(w, r, &in, maxCheckBody) {
		return
	}
	v, err := a.checks.Create(r.Context(), in.Check, who)
	if a.checkErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", v.ETag())
	w.Header().Set("Location", "/api/v1/checks/"+v.ID)
	writeJSON(w, http.StatusCreated, v)
}

func (a *checksAPI) update(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionChecksWrite, true)
	if !ok {
		return
	}
	ifMatch := strings.TrimPrefix(r.Header.Get("If-Match"), "W/")
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, errcode.APIPre002)
		return
	}
	var in checkDoc
	if !a.decodeMax(w, r, &in, maxCheckBody) {
		return
	}
	v, err := a.checks.Update(r.Context(), id, ifMatch, in.Check, who)
	if a.checkErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", v.ETag())
	writeJSON(w, http.StatusOK, v)
}

func (a *checksAPI) remove(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionChecksWrite, true)
	if !ok {
		return
	}
	if a.checkErr(w, r, a.checks.Delete(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *checksAPI) run(w http.ResponseWriter, r *http.Request) {
	who, id, ok := a.write(w, r, auth.ActionChecksRun, true)
	if !ok {
		return
	}
	res, err := a.checks.RunNow(r.Context(), id, who)
	if a.checkErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *checksAPI) results(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionChecksRead); !ok {
		return
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	cursor, limit, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, next, err := a.checks.Results(r.Context(), id, cursor, limit)
	if a.checkErr(w, r, err) {
		return
	}
	out := pageJSON[checks.Result]{Items: items}
	if items == nil {
		out.Items = []checks.Result{}
	}
	if next != "" {
		out.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *checksAPI) uptime(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, auth.ActionChecksRead); !ok {
		return
	}
	id := r.PathValue("id")
	if !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	u, err := a.checks.Uptime(r.Context(), id)
	if a.checkErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// checkErr renders a service error and reports whether there was one.
func (a *checksAPI) checkErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var ve *checks.ValidationError
	switch {
	case errors.As(err, &ve):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, ve.Field, ve.Msg)
	case errors.Is(err, checks.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.APINF001)
	case errors.Is(err, checks.ErrStale):
		writeError(w, http.StatusPreconditionFailed, errcode.APIPre001)
	case errors.Is(err, checks.ErrRateLimited):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, errcode.CHKRun004)
	default:
		a.fail(w, r, err)
	}
	return true
}

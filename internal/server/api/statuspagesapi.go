// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/statuspages"
)

// maxStatusPageBody bounds a page document: 20 components of 50 check IDs fit in about 40 KiB.
const maxStatusPageBody = 64 << 10

// pageDoc is a request document: a page input tolerating the read-only fields of a GET, so a
// fetched document can be edited and sent back as it is.
type pageDoc struct {
	statuspages.PageInput
	ID        json.RawMessage `json:"id"`
	CreatedAt json.RawMessage `json:"created_at"`
	UpdatedAt json.RawMessage `json:"updated_at"`
}

type statusPagesAPI struct {
	*authAPI
	pages *statuspages.Service
}

func (a *statusPagesAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/status-pages", a.list)
	mux.HandleFunc("POST /api/v1/status-pages", a.create)
	mux.HandleFunc("GET /api/v1/status-pages/{id}", a.get)
	mux.HandleFunc("PUT /api/v1/status-pages/{id}", a.update)
	mux.HandleFunc("DELETE /api/v1/status-pages/{id}", a.remove)
	mux.HandleFunc("GET /api/v1/status-pages/{id}/incidents", a.incidents)
	mux.HandleFunc("POST /api/v1/status-pages/{id}/incidents", a.createIncident)
	mux.HandleFunc("POST /api/v1/status-pages/{id}/incidents/{incidentId}/updates", a.addUpdate)
	mux.HandleFunc("POST /api/v1/status-pages/{id}/incidents/{incidentId}/resolve", a.resolve)
	mux.HandleFunc("DELETE /api/v1/status-pages/{id}/incidents/{incidentId}", a.removeIncident)
}

// write is the shared head of the changing endpoints: authorise, CSRF and path IDs.
func (a *statusPagesAPI) write(w http.ResponseWriter, r *http.Request, needID, needIncident bool) (who statuspages.Actor, id, incident string, ok bool) {
	p, sess, ok := a.begin(w, r, auth.ActionStatusPagesWrite)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return statuspages.Actor{}, "", "", false
	}
	if needID {
		if id = r.PathValue("id"); !ulid.MatchString(id) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return statuspages.Actor{}, "", "", false
		}
	}
	if needIncident {
		if incident = r.PathValue("incidentId"); !ulid.MatchString(incident) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return statuspages.Actor{}, "", "", false
		}
	}
	return statuspages.Actor{UserID: p.UserID, IP: clientOf(r).IP}, id, incident, true
}

// read authorises a viewer and validates the page ID, when the route has one.
func (a *statusPagesAPI) read(w http.ResponseWriter, r *http.Request, needID bool) (id string, ok bool) {
	if _, _, ok := a.begin(w, r, auth.ActionStatusPagesRead); !ok {
		return "", false
	}
	if needID {
		if id = r.PathValue("id"); !ulid.MatchString(id) {
			writeError(w, http.StatusNotFound, errcode.APINF001)
			return "", false
		}
	}
	return id, true
}

func (a *statusPagesAPI) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.read(w, r, false); !ok {
		return
	}
	items, err := a.pages.ListPages(r.Context())
	if a.pageErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *statusPagesAPI) get(w http.ResponseWriter, r *http.Request) {
	id, ok := a.read(w, r, true)
	if !ok {
		return
	}
	p, err := a.pages.GetPage(r.Context(), id)
	if a.pageErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", p.ETag())
	writeJSON(w, http.StatusOK, p)
}

func (a *statusPagesAPI) create(w http.ResponseWriter, r *http.Request) {
	who, _, _, ok := a.write(w, r, false, false)
	if !ok {
		return
	}
	var in pageDoc
	if !a.decodeMax(w, r, &in, maxStatusPageBody) {
		return
	}
	p, err := a.pages.CreatePage(r.Context(), in.PageInput, who)
	if a.pageErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", p.ETag())
	w.Header().Set("Location", "/api/v1/status-pages/"+p.ID)
	writeJSON(w, http.StatusCreated, p)
}

func (a *statusPagesAPI) update(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, true, false)
	if !ok {
		return
	}
	ifMatch := strings.TrimPrefix(r.Header.Get("If-Match"), "W/")
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, errcode.APIPre002)
		return
	}
	var in pageDoc
	if !a.decodeMax(w, r, &in, maxStatusPageBody) {
		return
	}
	p, err := a.pages.UpdatePage(r.Context(), id, ifMatch, in.PageInput, who)
	if a.pageErr(w, r, err) {
		return
	}
	w.Header().Set("ETag", p.ETag())
	writeJSON(w, http.StatusOK, p)
}

func (a *statusPagesAPI) remove(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, true, false)
	if !ok {
		return
	}
	if a.pageErr(w, r, a.pages.DeletePage(r.Context(), id, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *statusPagesAPI) incidents(w http.ResponseWriter, r *http.Request) {
	id, ok := a.read(w, r, true)
	if !ok {
		return
	}
	items, err := a.pages.ListIncidents(r.Context(), id)
	if a.pageErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *statusPagesAPI) createIncident(w http.ResponseWriter, r *http.Request) {
	who, id, _, ok := a.write(w, r, true, false)
	if !ok {
		return
	}
	var in statuspages.IncidentInput
	if !a.decodeMax(w, r, &in, 16<<10) {
		return
	}
	inc, err := a.pages.CreateIncident(r.Context(), id, in, who)
	if a.pageErr(w, r, err) {
		return
	}
	w.Header().Set("Location", "/api/v1/status-pages/"+id+"/incidents")
	writeJSON(w, http.StatusCreated, inc)
}

func (a *statusPagesAPI) addUpdate(w http.ResponseWriter, r *http.Request) {
	who, id, iid, ok := a.write(w, r, true, true)
	if !ok {
		return
	}
	var in statuspages.UpdateInput
	if !a.decodeMax(w, r, &in, 16<<10) {
		return
	}
	inc, err := a.pages.AddUpdate(r.Context(), id, iid, in, who)
	if a.pageErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (a *statusPagesAPI) resolve(w http.ResponseWriter, r *http.Request) {
	who, id, iid, ok := a.write(w, r, true, true)
	if !ok {
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if !a.decodeMax(w, r, &in, 16<<10) {
		return
	}
	inc, err := a.pages.AddUpdate(r.Context(), id, iid, statuspages.UpdateInput{Status: statuspages.IncResolved, Body: in.Body}, who)
	if a.pageErr(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (a *statusPagesAPI) removeIncident(w http.ResponseWriter, r *http.Request) {
	who, id, iid, ok := a.write(w, r, true, true)
	if !ok {
		return
	}
	if a.pageErr(w, r, a.pages.DeleteIncident(r.Context(), id, iid, who)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pageErr renders a service error and reports whether there was one.
func (a *statusPagesAPI) pageErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	var ve *statuspages.ValidationError
	switch {
	case errors.As(err, &ve):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, ve.Field, ve.Msg)
	case errors.Is(err, statuspages.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.APINF001)
	case errors.Is(err, statuspages.ErrStale):
		writeError(w, http.StatusPreconditionFailed, errcode.APIPre001)
	case errors.Is(err, statuspages.ErrSlugTaken):
		writeErrorDetail(w, http.StatusConflict, errcode.STPSlug001, "slug", "")
	default:
		a.fail(w, r, err)
	}
	return true
}

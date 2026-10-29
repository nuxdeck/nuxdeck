// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// maxTagSelectors bounds a filter so a request cannot make a list scan cost more than it should.
const maxTagSelectors = 10

// tagSelectors reads the repeatable ?tag=key:value filter.
func tagSelectors(w http.ResponseWriter, r *http.Request) ([]inventory.TagSelector, bool) {
	raw := r.URL.Query()["tag"]
	if len(raw) > maxTagSelectors {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "tag", "Use at most 10 tag filters.")
		return nil, false
	}
	out := make([]inventory.TagSelector, 0, len(raw))
	for _, v := range raw {
		sel, err := inventory.ParseSelector(v)
		if err != nil {
			var ve *inventory.ValidationError
			if errors.As(err, &ve) {
				writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, ve.Field, ve.Msg)
			}
			return nil, false
		}
		out = append(out, sel)
	}
	return out, true
}

func (a *inventoryAPI) putTags(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tags map[string]string `json:"tags"`
	}
	a.putMeta(w, r, &body, "item.tags.update", func() (inventory.MetaChange, map[string]any) {
		if body.Tags == nil {
			body.Tags = map[string]string{}
		}
		return inventory.MetaChange{Tags: body.Tags}, map[string]any{"tags": body.Tags}
	})
}

func (a *inventoryAPI) putOwner(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner *string `json:"owner"`
	}
	a.putMeta(w, r, &body, "item.owner.update", func() (inventory.MetaChange, map[string]any) {
		if body.Owner == nil {
			return inventory.MetaChange{}, nil
		}
		return inventory.MetaChange{Owner: body.Owner}, map[string]any{"owner": *body.Owner}
	})
}

// putMeta is the shared flow of the two PUT endpoints: authorise, CSRF, identify the item, require
// If-Match, decode, then write with the audit entry in the same transaction.
func (a *inventoryAPI) putMeta(w http.ResponseWriter, r *http.Request, body any, action string, build func() (inventory.MetaChange, map[string]any)) {
	p, sess, ok := a.begin(w, r, auth.ActionItemMetaUpdate)
	if !ok {
		return
	}
	if !sameOrigin(r) || !a.svc.CheckCSRF(*sess, r.Header.Get(csrfHeader)) {
		a.fail(w, r, errcode.New(errcode.AuthDeny004, "missing or wrong CSRF token"))
		return
	}
	itemType, id := r.PathValue("type"), r.PathValue("id")
	if (itemType != "hosts" && itemType != "containers") || !ulid.MatchString(id) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	itemType = strings.TrimSuffix(itemType, "s")
	cur, found := a.itemTags(itemType, id)
	if !found || !p.Covers(auth.ActionItemMetaUpdate, a.metaResource(itemType, id, cur)) {
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	}
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, errcode.APIPre002)
		return
	}
	if !a.decode(w, r, body) {
		return
	}
	change, details := build()
	if details == nil {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "owner", "Send the owner, or an empty string to clear it.")
		return
	}
	if change.Tags != nil && !p.Covers(auth.ActionItemMetaUpdate, a.metaResource(itemType, id, change.Tags)) {
		// A scoped operator must not tag an item out of their own scope.
		a.fail(w, r, errcode.New(errcode.AuthRBAC002, "new tags put %s %s outside the caller's scope", itemType, id))
		return
	}
	ev := audit.Event{
		ActorType: "user", ActorID: p.UserID, Action: action, TargetType: itemType, TargetID: id,
		IP: clientOf(r).IP, Result: audit.ResultSuccess, Details: details,
	}
	item, err := a.inv.UpdateMeta(itemType, id, strings.TrimPrefix(ifMatch, "W/"), change, ev)
	var ve *inventory.ValidationError
	switch {
	case errors.As(err, &ve):
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, ve.Field, ve.Msg)
		return
	case errors.Is(err, inventory.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.APINF001)
		return
	case errors.Is(err, inventory.ErrStale):
		writeError(w, http.StatusPreconditionFailed, errcode.APIPre001)
		return
	case err != nil:
		a.fail(w, r, err)
		return
	}
	switch it := item.(type) {
	case inventory.Host:
		w.Header().Set("ETag", it.ETag)
	case inventory.Container:
		w.Header().Set("ETag", it.ETag)
	}
	writeJSON(w, http.StatusOK, item)
}

// search serves the command palette (INV-5).
func (a *inventoryAPI) search(w http.ResponseWriter, r *http.Request) {
	p, _, ok := a.begin(w, r, auth.ActionSearch)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > inventory.MaxSearchQuery {
		writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "q", "Use 1 to 64 characters.")
		return
	}
	limit := inventory.DefaultSearchMax
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > inventory.MaxSearchResults {
			writeErrorDetail(w, http.StatusUnprocessableEntity, errcode.APIVal001, "limit", "Use a whole number from 1 to 50.")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": a.inv.Index().SearchAllowed(q, limit, hostAllow(p, auth.ActionSearch), containerAllow(p, auth.ActionSearch))})
}

// itemTags returns the current own tags of a host or container.
func (a *inventoryAPI) itemTags(itemType, id string) (map[string]string, bool) {
	ix := a.inv.Index()
	if itemType == "host" {
		h, ok := ix.Host(id)
		return h.Tags, ok
	}
	c, ok := ix.Container(id)
	return c.Tags, ok
}

// metaResource is the scope resource of an item as if it carried tags (its own, for a container
// laid over its host's).
func (a *inventoryAPI) metaResource(itemType, id string, tags map[string]string) auth.Resource {
	if itemType == "host" {
		return auth.ResourceOf(tags)
	}
	c, _ := a.inv.Index().Container(id)
	c.Tags = tags
	return a.containerRes(c)
}

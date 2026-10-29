// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting"
	"github.com/nuxdeck/nuxdeck/internal/server/auth"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

// hostResource is what a scope is matched against for a host: its tags.
func hostResource(h inventory.Host) auth.Resource { return auth.ResourceOf(h.Tags) }

// containerResource scopes a container by its own tags laid over its host's, so a container on a
// staging host is staging unless it says otherwise.
func containerResource(c inventory.Container, h inventory.Host) auth.Resource {
	tags := make(map[string]string, len(h.Tags)+len(c.Tags))
	for k, v := range h.Tags {
		tags[k] = v
	}
	for k, v := range c.Tags {
		tags[k] = v
	}
	return auth.ResourceOf(tags)
}

// itemResource resolves a host or container ID to its scope resource.
func itemResource(inv *inventory.Service, id string) (auth.Resource, bool) {
	if inv == nil {
		return auth.Resource{}, false
	}
	ix := inv.Index()
	if h, ok := ix.Host(id); ok {
		return hostResource(h), true
	}
	if c, ok := ix.Container(id); ok {
		h, _ := ix.Host(c.HostID)
		return containerResource(c, h), true
	}
	return auth.Resource{}, false
}

// unrestricted reports whether p holds an unscoped binding that allows a, so list filtering can be skipped.
func unrestricted(p auth.Principal, a auth.Action) bool { return p.Covers(a, auth.Resource{}) }

// hostAllow returns the host predicate for a list (nil when p may see everything).
func hostAllow(p auth.Principal, a auth.Action) func(inventory.Host) bool {
	if unrestricted(p, a) {
		return nil
	}
	return func(h inventory.Host) bool { return p.Covers(a, hostResource(h)) }
}

// containerAllow returns the container predicate for a list (nil when p may see everything).
func containerAllow(p auth.Principal, a auth.Action) func(inventory.Container, inventory.Host) bool {
	if unrestricted(p, a) {
		return nil
	}
	return func(c inventory.Container, h inventory.Host) bool { return p.Covers(a, containerResource(c, h)) }
}

// beginGlobal is begin for endpoints on resources that carry no environment or tags (checks, status
// pages): a scoped binding never covers them, so only an unscoped role passes.
func (a *authAPI) beginGlobal(w http.ResponseWriter, r *http.Request, action auth.Action) (auth.Principal, *auth.Session, bool) {
	p, sess, ok := a.begin(w, r, action)
	if !ok {
		return p, sess, false
	}
	if err := auth.AuthorizeOn(p, action, auth.Resource{}); err != nil {
		a.fail(w, r, err)
		return p, sess, false
	}
	return p, sess, true
}

// scopeDenied answers 404 for an item outside the caller's scope, so its existence is not revealed.
func scopeDenied(w http.ResponseWriter) { writeError(w, http.StatusNotFound, errcode.APINF001) }

// selectorCovered reports whether p may perform action on everything the selector can match: by
// its tags, or else by each listed ID. A selector that narrows nothing is global.
func selectorCovered(p auth.Principal, action auth.Action, inv *inventory.Service, sel alerting.Selector) bool {
	if unrestricted(p, action) {
		return true
	}
	if len(sel.Tags) > 0 && p.Covers(action, auth.ResourceOfSelector(sel.Tags)) {
		return true
	}
	if len(sel.IDs) > 0 {
		for _, id := range sel.IDs {
			res, ok := itemResource(inv, id)
			if !ok || !p.Covers(action, res) {
				return false
			}
		}
		return true
	}
	return len(sel.Tags) == 0 && p.Covers(action, auth.Resource{})
}

// alertResource scopes an alert by the item it fired on; alerts on checks are global.
func alertResource(inv *inventory.Service, al alerting.Alert) auth.Resource {
	res, _ := itemResource(inv, al.ItemID)
	return res
}

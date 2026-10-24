// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"slices"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// Action names what a handler is about to do. Every handler passes its action
// to Authorize before touching any other module (CLAUDE.md, "Authorise first").
type Action string

// The actions a handler can ask Authorize about.
const (
	ActionSetupStatus   Action = "setup.status"
	ActionSetupComplete Action = "setup.complete"
	ActionLogin         Action = "auth.login"
	ActionLogout        Action = "auth.logout"
	ActionMeRead        Action = "me.read"
)

// Principal is the caller. The zero value is anonymous.
type Principal struct {
	UserID string
	Email  string
	Name   string
	Roles  []Role
}

// Authenticated reports whether the caller has a valid session.
func (p Principal) Authenticated() bool { return p.UserID != "" }

// HasRole reports whether the caller holds role.
func (p Principal) HasRole(role Role) bool { return slices.Contains(p.Roles, role) }

type requirement int

const (
	public requirement = iota + 1 // anyone, signed in or not
	signedIn
)

// rules lists every known action. An action missing here is denied, so a new
// handler cannot ship unprotected by forgetting to register its rule.
var rules = map[Action]requirement{
	ActionSetupStatus:   public,
	ActionSetupComplete: public,
	ActionLogin:         public,
	ActionLogout:        signedIn,
	ActionMeRead:        signedIn,
}

// Authorize returns nil if p may perform a, and an AUTH-DENY error otherwise.
// It fails closed: unknown actions are denied.
func Authorize(p Principal, a Action) error {
	switch rules[a] {
	case public:
		return nil
	case signedIn:
		if p.Authenticated() {
			return nil
		}
		return errcode.New(errcode.AuthDeny003, "action %s needs a signed-in user", a)
	default:
		return errcode.New(errcode.AuthDeny005, "action %s is not permitted", a)
	}
}

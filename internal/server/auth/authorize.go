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
	ActionSetupStatus       Action = "setup.status"
	ActionSetupComplete     Action = "setup.complete"
	ActionLogin             Action = "auth.login"
	ActionLogout            Action = "auth.logout"
	ActionMeRead            Action = "me.read"
	ActionAgentTokenCreate  Action = "agents.token.create" //nolint:gosec // an action name, not a credential
	ActionAgentRevoke       Action = "agents.revoke"
	ActionInventoryRead     Action = "inventory.read"
	ActionEventsStream      Action = "events.stream"
	ActionLogsStream        Action = "logs.stream"
	ActionMetricsRead       Action = "metrics.read"
	ActionItemMetaUpdate    Action = "items.meta.update"
	ActionSearch            Action = "search.read"
	ActionChecksRead        Action = "checks.read"
	ActionChecksWrite       Action = "checks.write"
	ActionChecksRun         Action = "checks.run"
	ActionAlertsRead        Action = "alerts.read"
	ActionAlertsAck         Action = "alerts.ack"
	ActionRulesRead         Action = "rules.read"
	ActionRulesWrite        Action = "rules.write"
	ActionSilencesRead      Action = "silences.read"
	ActionSilencesWrite     Action = "silences.write"
	ActionChannelsRead      Action = "channels.read"
	ActionChannelsWrite     Action = "channels.write"
	ActionChannelsTest      Action = "channels.test"
	ActionRoutesRead        Action = "routes.read"
	ActionRoutesWrite       Action = "routes.write"
	ActionStatusPagesRead   Action = "statuspages.read"
	ActionStatusPagesWrite  Action = "statuspages.write"
	ActionUsersRead         Action = "users.read"
	ActionUsersWrite        Action = "users.write"
	ActionSessionsOwn       Action = "sessions.own"
	ActionSessionsAdmin     Action = "sessions.admin"
	ActionTokensOwn         Action = "tokens.own"
	ActionTOTPOwn           Action = "totp.own"
	ActionTOTPVerify        Action = "totp.verify"
	ActionOIDCLogin         Action = "auth.oidc"
	ActionSettingsRead      Action = "settings.read"
	ActionSettingsWrite     Action = "settings.write"
	ActionRoleBindingsRead  Action = "rolebindings.read"
	ActionRoleBindingsWrite Action = "rolebindings.write"
	ActionAuditRead         Action = "audit.read"
	ActionAuditExport       Action = "audit.export"
	ActionTelemetryRead     Action = "telemetry.read"
	ActionAPISpecRead       Action = "api.spec.read"
)

// Principal is the caller. The zero value is anonymous.
type Principal struct {
	UserID string
	Email  string
	Name   string
	Roles  []Role
	// Bindings carry the scope of each role; Roles is the unscoped summary kept for callers that do not need scope.
	Bindings []Binding
	// Via is "session" or "token"; empty for anonymous.
	Via string
}

// Authenticated reports whether the caller has a valid session.
func (p Principal) Authenticated() bool { return p.UserID != "" }

// HasRole reports whether the caller holds role.
func (p Principal) HasRole(role Role) bool { return slices.Contains(p.Roles, role) }

type requirement int

const (
	public requirement = iota + 1 // anyone, signed in or not
	signedIn
	viewer
	operator
	admin
)

// rules lists every known action. An action missing here is denied, so a new
// handler cannot ship unprotected by forgetting to register its rule.
var rules = map[Action]requirement{
	ActionSetupStatus:       public,
	ActionSetupComplete:     public,
	ActionLogin:             public,
	ActionLogout:            signedIn,
	ActionMeRead:            signedIn,
	ActionAgentTokenCreate:  admin,
	ActionAgentRevoke:       admin,
	ActionInventoryRead:     viewer,
	ActionEventsStream:      viewer,
	ActionLogsStream:        viewer,
	ActionMetricsRead:       viewer,
	ActionItemMetaUpdate:    operator,
	ActionSearch:            viewer,
	ActionChecksRead:        viewer,
	ActionChecksWrite:       operator,
	ActionChecksRun:         operator,
	ActionAlertsRead:        viewer,
	ActionAlertsAck:         operator,
	ActionRulesRead:         viewer,
	ActionRulesWrite:        operator,
	ActionSilencesRead:      viewer,
	ActionSilencesWrite:     operator,
	ActionChannelsRead:      admin,
	ActionChannelsWrite:     admin,
	ActionChannelsTest:      admin,
	ActionRoutesRead:        admin,
	ActionRoutesWrite:       admin,
	ActionStatusPagesRead:   viewer,
	ActionStatusPagesWrite:  operator,
	ActionUsersRead:         admin,
	ActionUsersWrite:        admin,
	ActionSessionsOwn:       signedIn,
	ActionSessionsAdmin:     admin,
	ActionTokensOwn:         signedIn,
	ActionTOTPOwn:           signedIn,
	ActionTOTPVerify:        public, // the pending-login ticket is the credential
	ActionOIDCLogin:         public,
	ActionSettingsRead:      admin,
	ActionSettingsWrite:     admin,
	ActionRoleBindingsRead:  admin,
	ActionRoleBindingsWrite: admin,
	ActionAuditRead:         admin,
	ActionAuditExport:       admin,
	ActionTelemetryRead:     admin,
	ActionAPISpecRead:       viewer,
}

// level orders the requirements a role can satisfy.
func (r requirement) rank() int { return int(r) }

func bindingRank(r Role) int {
	switch r {
	case RoleAdmin:
		return int(admin)
	case RoleOperator:
		return int(operator)
	case RoleViewer:
		return int(viewer)
	default:
		return 0
	}
}

// effective returns the caller's bindings. A principal built with Roles only (no scope data) holds
// those roles unscoped.
func (p Principal) effective() []Binding {
	if len(p.Bindings) > 0 {
		return p.Bindings
	}
	out := make([]Binding, 0, len(p.Roles))
	for _, r := range p.Roles {
		out = append(out, Binding{Role: r})
	}
	return out
}

// Actions lists every registered action, sorted; handlers and tests use it to stay in step with the rules.
func Actions() []Action {
	out := make([]Action, 0, len(rules))
	for a := range rules {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// Authorize returns nil if p may perform a somewhere. It is the gate every handler passes first: an
// action on inventory data passes for a scoped binding, and the handler then narrows by scope with
// AuthorizeOn, Covers or ScopeFilter. Actions that touch only global resources (channels, users,
// settings and the like, requirement admin) need an unscoped binding. It fails closed: unknown
// actions are denied.
func Authorize(p Principal, a Action) error {
	req, known := rules[a]
	if !known {
		return errcode.New(errcode.AuthRBAC001, "action %s is not permitted", a)
	}
	return decide(p, a, req, Resource{}, req == admin)
}

// AuthorizeOn returns nil if p may perform a on res: a binding of sufficient role must also cover res
// by its scope. A zero Resource is global and needs an unscoped binding.
func AuthorizeOn(p Principal, a Action, res Resource) error {
	req, known := rules[a]
	if !known {
		return errcode.New(errcode.AuthRBAC001, "action %s is not permitted", a)
	}
	return decide(p, a, req, res, true)
}

// Covers reports whether p may perform a on res. It is AuthorizeOn without the error, for filtering lists.
func (p Principal) Covers(a Action, res Resource) bool { return AuthorizeOn(p, a, res) == nil }

// ScopeFilter returns a predicate for list endpoints: it keeps the resources p may perform a on.
// A caller with an unscoped binding of sufficient role gets an allow-all predicate.
func ScopeFilter(p Principal, a Action) func(Resource) bool {
	return func(res Resource) bool { return p.Covers(a, res) }
}

func decide(p Principal, a Action, req requirement, res Resource, checkScope bool) error {
	switch req {
	case public:
		return nil
	case signedIn:
		if p.Authenticated() {
			return nil
		}
		return errcode.New(errcode.AuthDeny003, "action %s needs a signed-in user", a)
	case viewer, operator, admin:
		if !p.Authenticated() {
			return errcode.New(errcode.AuthDeny003, "action %s needs a signed-in user", a)
		}
		sufficient := false
		for _, b := range p.effective() {
			if bindingRank(b.Role) < req.rank() {
				continue
			}
			sufficient = true
			if !checkScope || b.Scope.Covers(res) {
				return nil
			}
		}
		if sufficient {
			return errcode.New(errcode.AuthRBAC002, "action %s is outside the scope of the caller's roles", a)
		}
		return errcode.New(errcode.AuthDeny005, "action %s needs the %s role", a, req.name())
	default:
		return errcode.New(errcode.AuthRBAC001, "action %s is not permitted", a)
	}
}

func (r requirement) name() string {
	switch r {
	case viewer:
		return "viewer"
	case operator:
		return "operator"
	case admin:
		return "admin"
	default:
		return "required"
	}
}

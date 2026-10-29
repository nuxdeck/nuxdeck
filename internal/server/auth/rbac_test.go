// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// minimum is the lowest requirement each action has, written out independently of the rules map so
// a wrong rule is caught. Levels: pub, any (signed in), V, O, A.
var minimum = map[Action]string{
	ActionSetupStatus: "pub", ActionSetupComplete: "pub", ActionLogin: "pub", ActionTOTPVerify: "pub", ActionOIDCLogin: "pub",
	ActionLogout: "any", ActionMeRead: "any", ActionSessionsOwn: "any", ActionTokensOwn: "any", ActionTOTPOwn: "any",
	ActionInventoryRead: "V", ActionEventsStream: "V", ActionLogsStream: "V", ActionMetricsRead: "V", ActionSearch: "V",
	ActionChecksRead: "V", ActionAlertsRead: "V", ActionRulesRead: "V", ActionSilencesRead: "V", ActionStatusPagesRead: "V",
	ActionItemMetaUpdate: "O", ActionChecksWrite: "O", ActionChecksRun: "O", ActionAlertsAck: "O", ActionRulesWrite: "O",
	ActionSilencesWrite: "O", ActionStatusPagesWrite: "O",
	ActionAgentTokenCreate: "A", ActionAgentRevoke: "A", ActionChannelsRead: "A", ActionChannelsWrite: "A", ActionChannelsTest: "A",
	ActionRoutesRead: "A", ActionRoutesWrite: "A", ActionUsersRead: "A", ActionUsersWrite: "A", ActionSessionsAdmin: "A",
	ActionSettingsRead: "A", ActionSettingsWrite: "A", ActionRoleBindingsRead: "A", ActionRoleBindingsWrite: "A",
	ActionAuditRead: "A", ActionAuditExport: "A", ActionTelemetryRead: "A", ActionAPISpecRead: "V",
}

// declaredActions parses authorize.go for every Action constant, so a new constant without a matrix row fails.
func declaredActions(t *testing.T) []Action {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "authorize.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []Action
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Action" {
				continue
			}
			for _, v := range vs.Values {
				if lit, ok := v.(*ast.BasicLit); ok {
					s, _ := strconv.Unquote(lit.Value)
					out = append(out, Action(s))
				}
			}
		}
	}
	return out
}

func TestACC4_EveryActionHasARuleAndAMatrixRow(t *testing.T) {
	declared := declaredActions(t)
	if len(declared) < 40 {
		t.Fatalf("found only %d action constants", len(declared))
	}
	for _, a := range declared {
		if _, ok := rules[a]; !ok {
			t.Errorf("action %s has no rule, so it is denied to everyone", a)
		}
		if _, ok := minimum[a]; !ok {
			t.Errorf("action %s has no row in the RBAC matrix test", a)
		}
	}
	if len(Actions()) != len(declared) || len(minimum) != len(declared) {
		t.Errorf("rules %d, matrix %d, constants %d must agree", len(Actions()), len(minimum), len(declared))
	}
}

func TestACC4_RoleByActionMatrix(t *testing.T) {
	who := map[string]Principal{
		"anonymous": {},
		"no role":   {UserID: "u0"},
		"viewer":    {UserID: "u1", Roles: []Role{RoleViewer}},
		"operator":  {UserID: "u2", Roles: []Role{RoleOperator}},
		"admin":     {UserID: "u3", Roles: []Role{RoleAdmin}},
		// Bindings take precedence over the Roles summary.
		"viewer binding": {UserID: "u4", Bindings: []Binding{{Role: RoleViewer}}},
		"scoped viewer":  {UserID: "u5", Bindings: []Binding{{Role: RoleViewer, Scope: Scope{Environments: []string{"staging"}}}}},
		"scoped admin":   {UserID: "u6", Bindings: []Binding{{Role: RoleAdmin, Scope: Scope{Environments: []string{"staging"}}}}},
	}
	rank := map[string]int{"anonymous": -1, "no role": 0, "viewer": 1, "operator": 2, "admin": 3, "viewer binding": 1, "scoped viewer": 1, "scoped admin": 3}
	need := map[string]int{"pub": -2, "any": 0, "V": 1, "O": 2, "A": 3}

	for _, a := range Actions() {
		lowest, ok := minimum[a]
		if !ok {
			t.Errorf("action %s missing from matrix", a)
			continue
		}
		for name, p := range who {
			want := rank[name] >= need[lowest]
			// Scoped bindings pass the gate for inventory-level actions, but admin actions are global.
			if lowest == "A" && (name == "scoped admin" || name == "scoped viewer") {
				want = false
			}
			err := Authorize(p, a)
			if (err == nil) != want {
				t.Errorf("%s as %s: err = %v, want allowed = %v", a, name, err, want)
			}
			if err != nil {
				code := errcode.CodeOf(err)
				if name == "anonymous" && code != errcode.AuthDeny003 {
					t.Errorf("%s anonymous code = %s, want AUTH-DENY-003", a, code)
				}
				if name == "scoped admin" && code != errcode.AuthRBAC002 {
					t.Errorf("%s as scoped admin code = %s, want AUTH-RBAC-002", a, code)
				}
			}
		}
	}
}

func TestACC5_ScopeMatching(t *testing.T) {
	staging := Scope{Environments: []string{"staging"}}
	tagged := Scope{TagSets: [][]string{{"team:web", "tier:1"}, {"owner"}}}
	tests := []struct {
		name  string
		scope Scope
		res   Resource
		want  bool
	}{
		{"unscoped covers an item", Scope{}, ResourceOf(map[string]string{"env": "production"}), true},
		{"unscoped covers a global resource", Scope{}, Resource{}, true},
		{"env match", staging, ResourceOf(map[string]string{"env": "staging"}), true},
		{"env mismatch", staging, ResourceOf(map[string]string{"env": "production"}), false},
		{"untagged item never matches a scoped binding", staging, ResourceOf(nil), false},
		{"global resource needs an unscoped binding", staging, Resource{}, false},
		{"tag set needs every tag", tagged, ResourceOf(map[string]string{"team": "web"}), false},
		{"tag set all present", tagged, ResourceOf(map[string]string{"team": "web", "tier": "1", "x": "y"}), true},
		{"tag set value must equal", tagged, ResourceOf(map[string]string{"team": "web", "tier": "2"}), false},
		{"tag sets are ORed, key-only tag matches any value", tagged, ResourceOf(map[string]string{"owner": "ana"}), true},
		{"env listed and tag sets ORed", Scope{Environments: []string{"staging"}, TagSets: [][]string{{"team:web"}}}, ResourceOf(map[string]string{"team": "web", "env": "production"}), true},
		{"env as a tag in a tag set", Scope{TagSets: [][]string{{"env:staging", "team:web"}}}, ResourceOf(map[string]string{"env": "staging", "team": "web"}), true},
		{"empty env in the resource never matches", Scope{Environments: []string{""}}, Resource{}, false},
		{"empty tag set never matches", Scope{TagSets: [][]string{{}}}, ResourceOf(map[string]string{"a": "b"}), false},
		{"selector resource within env", staging, ResourceOfSelector([]string{"env:staging", "team:web"}), true},
		{"selector without env is not inside env scope", staging, ResourceOfSelector([]string{"team:web"}), false},
	}
	for _, tt := range tests {
		if got := tt.scope.Covers(tt.res); got != tt.want {
			t.Errorf("%s: Covers = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestACC5_ParseScopeFailsClosed(t *testing.T) {
	for _, raw := range []string{`{"environments":`, `null`, `[]`, `{"envs":["x"]}`, `{"environments":[""]}`, `{"tag_sets":[[]]}`, `{"tag_sets":[[""]]}`, `{"environments":["a:b"]}`} {
		if _, err := ParseScope(raw); err == nil {
			t.Errorf("ParseScope(%s) accepted", raw)
		}
	}
	for _, raw := range []string{``, `{}`, `{"environments":["staging"]}`, `{"tag_sets":[["team:web","tier:1"]]}`} {
		if _, err := ParseScope(raw); err != nil {
			t.Errorf("ParseScope(%s) = %v", raw, err)
		}
	}
}

func TestACC5_AuthorizeOnNeedsRoleAndScope(t *testing.T) {
	stagingViewer := Principal{UserID: "u", Bindings: []Binding{{Role: RoleViewer, Scope: Scope{Environments: []string{"staging"}}}}}
	prod, stg := ResourceOf(map[string]string{"env": "production"}), ResourceOf(map[string]string{"env": "staging"})

	if err := AuthorizeOn(stagingViewer, ActionInventoryRead, stg); err != nil {
		t.Errorf("staging read: %v", err)
	}
	if err := AuthorizeOn(stagingViewer, ActionInventoryRead, prod); errcode.CodeOf(err) != errcode.AuthRBAC002 {
		t.Errorf("prod read: %v", err)
	}
	if err := AuthorizeOn(stagingViewer, ActionItemMetaUpdate, stg); errcode.CodeOf(err) != errcode.AuthDeny005 {
		t.Errorf("viewer writing staging: %v", err)
	}
	if err := AuthorizeOn(stagingViewer, "no.such.action", stg); errcode.CodeOf(err) != errcode.AuthRBAC001 {
		t.Errorf("unknown action: %v", err)
	}

	// Roles stack: a scoped operator plus an unscoped viewer reads everywhere and writes only in scope.
	mixed := Principal{UserID: "u", Bindings: []Binding{
		{Role: RoleViewer},
		{Role: RoleOperator, Scope: Scope{Environments: []string{"staging"}}},
	}}
	if !mixed.Covers(ActionInventoryRead, prod) || !mixed.Covers(ActionItemMetaUpdate, stg) || mixed.Covers(ActionItemMetaUpdate, prod) {
		t.Error("mixed bindings did not combine as expected")
	}
	if got := UnscopedRoles(mixed.Bindings); len(got) != 1 || got[0] != RoleViewer {
		t.Errorf("UnscopedRoles = %v", got)
	}

	pred := ScopeFilter(stagingViewer, ActionInventoryRead)
	if !pred(stg) || pred(prod) || pred(Resource{}) {
		t.Error("ScopeFilter let the wrong resources through")
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

func seedAPIAudit(t *testing.T, e *authEnv, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		err := e.db.RecordAudit(context.Background(), audit.Event{
			ActorType: "user", ActorID: "01SEED", Action: "seed.thing", TargetType: "seed", TargetID: strconv.Itoa(i), IP: "203.0.113.9",
			Result: audit.ResultSuccess, Details: map[string]any{"note": "needle-" + strconv.Itoa(i), "api_token": "SECRET-TOKEN-VALUE", "code": "424242"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAUD3_SearchFiltersPaginationAndMasking(t *testing.T) {
	e := newAuthEnv(t)
	admin := sessionCookieOf(t, e.setup())
	seedAPIAudit(t, e, 7)

	rec := e.do(req{method: "GET", path: "/api/v1/audit?action=seed.&limit=3", cookie: admin})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if body := rec.Body.String(); strings.Contains(body, "SECRET-TOKEN-VALUE") || strings.Contains(body, "424242") {
		t.Fatalf("sensitive details leaked: %s", body)
	}
	var page struct {
		Items      []auditEntryJSON `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 || page.NextCursor == nil || page.Items[0].TargetID != "7" {
		t.Fatalf("page = %+v", page)
	}
	rec = e.do(req{method: "GET", path: "/api/v1/audit?action=seed.&limit=50&cursor=" + *page.NextCursor, cookie: admin})
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if len(page.Items) != 4 || page.NextCursor != nil {
		t.Fatalf("second page = %d items, next %v", len(page.Items), page.NextCursor)
	}

	for path, want := range map[string]int{
		"/api/v1/audit?q=NEEDLE-5":                         1,
		"/api/v1/audit?target_type=seed&target_id=2":       1,
		"/api/v1/audit?actor=01SEED&result=success":        7,
		"/api/v1/audit?actor=01SEED&result=failure":        0,
		"/api/v1/audit?from=2000-01-01T00:00:00Z&q=needle": 7,
		"/api/v1/audit?to=2000-01-01T00:00:00Z":            0,
	} {
		rec = e.do(req{method: "GET", path: path, cookie: admin})
		_ = json.Unmarshal(rec.Body.Bytes(), &page)
		if rec.Code != 200 || len(page.Items) != want {
			t.Errorf("%s: status %d, %d items, want %d", path, rec.Code, len(page.Items), want)
		}
	}
	for _, path := range []string{"/api/v1/audit?limit=501", "/api/v1/audit?limit=0", "/api/v1/audit?cursor=abc", "/api/v1/audit?result=maybe", "/api/v1/audit?from=yesterday"} {
		if rec = e.do(req{method: "GET", path: path, cookie: admin}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", path, rec.Code)
		}
	}
}

func TestAUD3_AdminOnly(t *testing.T) {
	e := newAuthEnv(t)
	e.setup()
	viewer, _ := e.signInAs("viewer")
	operator, _ := e.signInAs("operator")
	for _, path := range []string{"/api/v1/audit", "/api/v1/audit/export", "/api/v1/audit/verify"} {
		if rec := e.do(req{method: "GET", path: path}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous: %d", path, rec.Code)
		}
		for _, c := range []*http.Cookie{viewer, operator} {
			if rec := e.do(req{method: "GET", path: path, cookie: c}); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: %d", path, c.Name, rec.Code)
			}
		}
	}
	if n := auditActions(t, e, "audit.export"); n != 0 {
		t.Errorf("denied exports were recorded as exports: %d", n)
	}
}

func TestAUD3_ExportStreamsJSONLinesAndIsAudited(t *testing.T) {
	e := newAuthEnv(t)
	admin := sessionCookieOf(t, e.setup())
	seedAPIAudit(t, e, 5)

	rec := e.do(req{method: "GET", path: "/api/v1/audit/export?action=seed.&q=needle", cookie: admin})
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content type %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="nux-audit-`) {
		t.Errorf("content disposition %q", cd)
	}
	if strings.Contains(rec.Body.String(), "SECRET-TOKEN-VALUE") {
		t.Fatal("export leaks sensitive details")
	}
	sc := bufio.NewScanner(rec.Body)
	lines := 0
	for sc.Scan() {
		var ent auditEntryJSON
		if err := json.Unmarshal(sc.Bytes(), &ent); err != nil || ent.Hash == "" {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines++
	}
	if lines != 5 {
		t.Errorf("lines = %d, want 5", lines)
	}
	if n := auditActions(t, e, "audit.export"); n != 1 {
		t.Errorf("export entries = %d, want 1", n)
	}
}

func TestAUD2_VerifyEndpointReportsBreak(t *testing.T) {
	e := newAuthEnv(t)
	admin := sessionCookieOf(t, e.setup())
	seedAPIAudit(t, e, 4)

	var v struct {
		OK       bool   `json:"ok"`
		Entries  int    `json:"entries"`
		BrokenAt int64  `json:"broken_at"`
		Code     string `json:"code"`
	}
	rec := e.do(req{method: "GET", path: "/api/v1/audit/verify", cookie: admin})
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || !v.OK || v.Entries < 4 {
		t.Fatalf("clean: %d %+v", rec.Code, v)
	}

	db := e.rawDBForAudit()
	defer func() { _ = db.Close() }()
	for _, s := range []string{`DROP TRIGGER audit_log_no_update`, `UPDATE audit_log SET action = 'x.y' WHERE id = 3`} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	rec = e.do(req{method: "GET", path: "/api/v1/audit/verify", cookie: admin})
	v.OK = true
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.OK || v.BrokenAt == 0 || v.Code != "AUD-CHAIN-001" {
		t.Fatalf("tampered: %+v", v)
	}
}

// AUD-2: no route can edit or delete audit entries.
func TestAUD2_NoMutatingAuditRoutes(t *testing.T) {
	for _, r := range registeredRoutes(t) {
		if r.method != http.MethodGet && r.method != http.MethodHead && strings.Contains(r.path, "/audit") {
			t.Errorf("%s %s: audit entries must be read-only", r.method, r.path)
		}
	}
	e := newAuthEnv(t)
	admin := sessionCookieOf(t, e.setup())
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		for _, p := range []string{"/api/v1/audit", "/api/v1/audit/1", "/api/v1/audit/export", "/api/v1/audit/verify"} {
			rec := e.do(req{method: m, path: p, cookie: admin, headers: map[string]string{csrfHeader: "x"}})
			if rec.Code < 400 {
				t.Errorf("%s %s: %d", m, p, rec.Code)
			}
		}
	}
}

type route struct{ method, path string }

var patternRE = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE) (/\S*)$`)

// registeredRoutes finds every "METHOD /path" literal passed to a mux Handle or HandleFunc call
// in the server code, so a new route cannot be added without this test seeing it.
func registeredRoutes(t *testing.T) []route {
	t.Helper()
	var out []route
	fset := token.NewFileSet()
	for _, root := range []string{"..", "../../../cmd/nuxd"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			src, rerr := os.ReadFile(p) //nolint:gosec // repository source under test
			if rerr != nil {
				return rerr
			}
			f, perr := parser.ParseFile(fset, p, src, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, _ := strconv.Unquote(lit.Value)
				if m := patternRE.FindStringSubmatch(s); m != nil {
					out = append(out, route{m[1], m[2]})
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

const audited = "writes an audit entry in the same transaction"

// auditCoverage lists every state-changing route (AUD-1): either it writes an audit entry or it
// is exempt with the reason. A new POST, PUT, PATCH or DELETE route fails the test until it is
// added here, which is the prompt to audit it.
var auditCoverage = map[string]string{
	"POST /api/v1/setup/admin":                                      audited + " (setup.admin_created)",
	"POST /api/v1/auth/login":                                       audited + ", failures included",
	"POST /api/v1/auth/logout":                                      audited,
	"POST /api/v1/rules":                                            audited,
	"PUT /api/v1/rules/{id}":                                        audited,
	"DELETE /api/v1/rules/{id}":                                     audited,
	"POST /api/v1/alerts/{id}/ack":                                  audited,
	"POST /api/v1/silences":                                         audited,
	"DELETE /api/v1/silences/{id}":                                  audited,
	"POST /api/v1/channels":                                         audited,
	"PUT /api/v1/channels/{id}":                                     audited,
	"DELETE /api/v1/channels/{id}":                                  audited,
	"POST /api/v1/channels/{id}/test":                               audited,
	"PUT /api/v1/routes":                                            audited,
	"POST /api/v1/checks":                                           audited,
	"PUT /api/v1/checks/{id}":                                       audited,
	"DELETE /api/v1/checks/{id}":                                    audited,
	"POST /api/v1/checks/{id}/run":                                  audited,
	"POST /api/v1/agents/tokens":                                    audited,
	"POST /api/v1/agents/{id}/revoke":                               audited,
	"PUT /api/v1/items/{type}/{id}/tags":                            audited,
	"PUT /api/v1/items/{type}/{id}/owner":                           audited,
	"POST /api/v1/status-pages":                                     audited,
	"PUT /api/v1/status-pages/{id}":                                 audited,
	"DELETE /api/v1/status-pages/{id}":                              audited,
	"POST /api/v1/status-pages/{id}/incidents":                      audited,
	"POST /api/v1/status-pages/{id}/incidents/{incidentId}/updates": audited,
	"POST /api/v1/status-pages/{id}/incidents/{incidentId}/resolve": audited,
	"DELETE /api/v1/status-pages/{id}/incidents/{incidentId}":       audited,
	"DELETE /api/v1/me/sessions/{handle}":                           audited,
	"DELETE /api/v1/me/tokens/{id}":                                 audited,
	"DELETE /api/v1/role-bindings/{id}":                             audited,
	"DELETE /api/v1/users/{id}":                                     audited,
	"DELETE /api/v1/users/{id}/sessions/{handle}":                   audited,
	"PATCH /api/v1/users/{id}":                                      audited,
	"POST /api/v1/auth/totp/enrol":                                  audited,
	"POST /api/v1/auth/totp/verify":                                 audited,
	"POST /api/v1/me/password":                                      audited,
	"POST /api/v1/me/tokens":                                        audited,
	"POST /api/v1/me/totp/confirm":                                  audited,
	"POST /api/v1/me/totp/disable":                                  audited,
	"POST /api/v1/me/totp/enrol":                                    audited,
	"POST /api/v1/role-bindings":                                    audited,
	"POST /api/v1/users":                                            audited,
	"POST /api/v1/users/{id}/reset":                                 audited,
	"PUT /api/v1/settings":                                          audited,
	"PUT /api/v1/settings/oidc":                                     audited + " (settings.oidc_update)",
	"DELETE /api/v1/settings/oidc":                                  audited + " (settings.oidc_delete)",
	"PUT /api/v1/settings/security":                                 audited,
}

func TestAUD1_EveryStateChangingRouteIsAuditedOrExempt(t *testing.T) {
	seen := map[string]bool{}
	var missing []string
	for _, r := range registeredRoutes(t) {
		switch r.method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		key := r.method + " " + r.path
		seen[key] = true
		if reason, ok := auditCoverage[key]; !ok || strings.TrimSpace(reason) == "" {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("state-changing routes without an audit entry or a documented exemption (AUD-1); add the audit write, then list them in auditCoverage:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(seen) < 10 {
		t.Fatalf("route scan found only %d state-changing routes; the scanner is broken", len(seen))
	}
	for key := range auditCoverage {
		if !seen[key] {
			t.Errorf("auditCoverage lists %q, which is no longer registered; remove it", key)
		}
	}
}

func (e *authEnv) rawDBForAudit() *sql.DB {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "nux.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		e.t.Fatal(err)
	}
	return db
}

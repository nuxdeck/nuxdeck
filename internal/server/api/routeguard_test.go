// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// publicRoutes are the only routes that may answer without authenticating. Each
// needs a reason that holds up in review; adding a route here is a security decision.
var publicRoutes = map[string]string{
	"GET /healthz": "liveness probe; returns only the build version",
	"GET /readyz":  "readiness probe; returns ok or unavailable, never the failing dependency",
	"/":            "serves the embedded UI and answers unknown /api paths with 404; the UI holds no data",
}

// authGuards are the calls that authenticate, authorize or both before a handler does any work.
var authGuards = map[string]bool{
	"begin": true, "beginGlobal": true, "beginToken": true, "Authorize": true, "AuthorizeOn": true,
}

// TestRouteGuard_EveryHandlerAuthenticatesOrIsPublic walks every route registered in this
// package and fails when a handler reaches its work without a guard call (see authGuards) and
// the route is not in publicRoutes. It complements the audit scanner (AUD-1) by covering authn/z.
func TestRouteGuard_EveryHandlerAuthenticatesOrIsPublic(t *testing.T) {
	fset := token.NewFileSet()
	files := parsePackageFiles(t, fset)
	decls := functionDecls(files)
	guards := guardedNames(decls)

	seen := map[string]bool{}
	var problems []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
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
			pattern, _ := strconv.Unquote(lit.Value)
			key := pattern
			if m := patternRE.FindStringSubmatch(pattern); m != nil {
				key = m[1] + " " + m[2]
			}
			seen[key] = true
			if _, public := publicRoutes[key]; public {
				return true
			}

			pos := fset.Position(call.Pos())
			switch h := call.Args[1].(type) {
			case *ast.FuncLit:
				if !guarded(h.Body, guards) {
					problems = append(problems, key+" at "+pos.String()+": inline handler does not authenticate")
				}
			case *ast.SelectorExpr, *ast.Ident:
				name := identName(h)
				handlers := handlerDecls(decls[name])
				if len(handlers) == 0 {
					problems = append(problems, key+" at "+pos.String()+": handler "+name+" not found in package")
				}
				for _, fn := range handlers {
					if !guarded(fn.Body, guards) {
						problems = append(problems, key+" at "+pos.String()+": handler "+name+" does not call a.begin, Authorize or a helper that does")
					}
				}
			default:
				problems = append(problems, key+" at "+pos.String()+": handler is not a named function; the guard test cannot follow it")
			}
			return true
		})
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("routes that reach their handler without authentication or authorisation (add a begin/Authorize guard, or justify a public route in publicRoutes):\n  %s", strings.Join(problems, "\n  "))
	}
	if len(seen) < 40 {
		t.Fatalf("route scan found only %d routes; the scanner is broken", len(seen))
	}
	for key := range publicRoutes {
		if !seen[key] {
			t.Errorf("publicRoutes lists %q, which is no longer registered in this package; remove it", key)
		}
	}
}

func parsePackageFiles(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no package files found")
	}
	return files
}

// functionDecls groups every function and method by name. Several types may share a name
// (get, list, write, ...), so each name holds a list.
func functionDecls(files []*ast.File) map[string][]*ast.FuncDecl {
	out := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				out[fn.Name.Name] = append(out[fn.Name.Name], fn)
			}
		}
	}
	return out
}

// handlerDecls keeps the declarations with the (http.ResponseWriter, *http.Request) signature.
// Helpers such as logsAPI.resolve share names with handlers but are not routes.
func handlerDecls(decls []*ast.FuncDecl) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, fn := range decls {
		if isHandlerSignature(fn.Type) {
			out = append(out, fn)
		}
	}
	return out
}

// guardedNames returns the helper names that guard every declaration sharing the name, such as
// alertsAPI.read, which calls begin. Guard status propagates through helpers until it settles.
func guardedNames(decls map[string][]*ast.FuncDecl) map[string]bool {
	guards := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, group := range decls {
			if guards[name] {
				continue
			}
			all := true
			for _, fn := range group {
				if !guarded(fn.Body, guards) {
					all = false
					break
				}
			}
			if all {
				guards[name] = true
				changed = true
			}
		}
	}
	return guards
}

func isHandlerSignature(ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) != 2 {
		return false
	}
	first, ok := ft.Params.List[0].Type.(*ast.SelectorExpr)
	if !ok || !isQualified(first, "http", "ResponseWriter") {
		return false
	}
	second, ok := ft.Params.List[1].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	req, ok := second.X.(*ast.SelectorExpr)
	return ok && isQualified(req, "http", "Request")
}

func isQualified(sel *ast.SelectorExpr, pkg, name string) bool {
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg && sel.Sel.Name == name
}

// guarded reports whether body calls an authentication or authorisation guard, directly or
// through a helper in guards.
func guarded(body *ast.BlockStmt, guards map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if name := identName(call.Fun); authGuards[name] || guards[name] {
			found = true
		}
		return !found
	})
	return found
}

// identName returns the trailing name of an identifier or selector expression, or "".
func identName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// The guard test must fail on a handler that skips authentication; this proves the
// detector sees both a direct guard and one reached through a helper.
func TestRouteGuard_DetectsUnguardedHandler(t *testing.T) {
	const src = `package api

func (a *x) direct(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.begin(w, r, action); !ok {
		return
	}
}

func (a *x) viaHelper(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.read(w, r); !ok {
		return
	}
}

func (a *x) read(w http.ResponseWriter, r *http.Request) (string, bool) {
	_, _, ok := a.begin(w, r, action)
	return "", ok
}

func (a *x) unguarded(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{})
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	decls := functionDecls([]*ast.File{f})
	guards := guardedNames(decls)
	for name, want := range map[string]bool{"direct": true, "viaHelper": true, "unguarded": false} {
		fn := handlerDecls(decls[name])
		if len(fn) != 1 {
			t.Fatalf("%s: found %d handler declarations", name, len(fn))
		}
		if got := guarded(fn[0].Body, guards); got != want {
			t.Errorf("%s guarded = %v, want %v", name, got, want)
		}
	}
	if !guards["read"] {
		t.Error("read calls begin and must be recognised as a guard helper")
	}
}

// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var (
	httpMethods  = map[string]bool{"get": true, "put": true, "post": true, "patch": true, "delete": true, "head": true, "options": true, "trace": true}
	statusCodeRE = regexp.MustCompile(`^([1-5][0-9]{2}|[1-5]XX|default)$`)
	jsonTypes    = map[string]bool{"string": true, "number": true, "integer": true, "boolean": true, "array": true, "object": true, "null": true}
	pathParamRE  = regexp.MustCompile(`\{([^}]+)\}`)
)

// document parses the embedded YAML into generic maps.
func document(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(Document, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	return doc
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// TestCLI1_DocumentIsWellFormedOpenAPI31 is a structural check of the OpenAPI 3.1 rules this document
// relies on: version, info, unique operation IDs, status codes, path parameters, JSON Schema types and
// references that all resolve. It does not replace a full validator; it keeps the common mistakes out.
func TestCLI1_DocumentIsWellFormedOpenAPI31(t *testing.T) {
	doc := document(t)
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Errorf("openapi = %q, want 3.1.x", v)
	}
	info, ok := asMap(doc["info"])
	if !ok || info["title"] == nil || info["version"] == nil {
		t.Error("info must carry title and version")
	}
	components, _ := asMap(doc["components"])
	schemes, _ := asMap(components["securitySchemes"])

	ops := map[string]bool{}
	paths, _ := asMap(doc["paths"])
	if len(paths) == 0 {
		t.Fatal("paths is empty")
	}
	for path, item := range paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			t.Errorf("path %s is outside /api/v1", path)
		}
		pi, ok := asMap(item)
		if !ok {
			t.Errorf("%s is not an object", path)
			continue
		}
		declared := map[string]bool{}
		collectParams(t, doc, pi["parameters"], declared)
		for method, rawOp := range pi {
			if !httpMethods[method] {
				continue
			}
			op, ok := asMap(rawOp)
			if !ok {
				t.Errorf("%s %s is not an object", method, path)
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				t.Errorf("%s %s has no operationId", method, path)
			} else if ops[id] {
				t.Errorf("operationId %s is used twice", id)
			}
			ops[id] = true
			opDeclared := map[string]bool{}
			for k := range declared {
				opDeclared[k] = true
			}
			collectParams(t, doc, op["parameters"], opDeclared)
			for _, name := range pathParams(path) {
				if !opDeclared[name] {
					t.Errorf("%s %s: path parameter {%s} is not declared", strings.ToUpper(method), path, name)
				}
			}
			responses, _ := asMap(op["responses"])
			if len(responses) == 0 {
				t.Errorf("%s %s has no responses", strings.ToUpper(method), path)
			}
			for code := range responses {
				if !statusCodeRE.MatchString(code) {
					t.Errorf("%s %s: response key %q is not a status code", strings.ToUpper(method), path, code)
				}
			}
			for _, name := range requirementNames(op["security"]) {
				if _, ok := schemes[name]; !ok {
					t.Errorf("%s %s requires undefined security scheme %q", strings.ToUpper(method), path, name)
				}
			}
		}
	}
	checkRefsAndTypes(t, doc, doc, "#")
}

// collectParams records the names of path parameters, following $ref into components.
func collectParams(t *testing.T, root map[string]any, raw any, into map[string]bool) {
	t.Helper()
	list, _ := raw.([]any)
	for _, p := range list {
		pm, ok := asMap(p)
		if !ok {
			t.Errorf("parameter %v is not an object", p)
			continue
		}
		if ref, isRef := pm["$ref"].(string); isRef {
			target, found := lookup(root, ref)
			resolved, isObj := asMap(target)
			if !found || !isObj {
				t.Errorf("parameter $ref %q does not resolve", ref)
				continue
			}
			pm = resolved
		}
		if in, _ := pm["in"].(string); in == "path" {
			name, _ := pm["name"].(string)
			into[name] = true
		}
	}
}

func pathParams(path string) []string {
	var out []string
	for _, m := range pathParamRE.FindAllStringSubmatch(path, -1) {
		out = append(out, m[1])
	}
	return out
}

func requirementNames(raw any) []string {
	var out []string
	list, _ := raw.([]any)
	for _, r := range list {
		if m, ok := asMap(r); ok {
			for name := range m {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkRefsAndTypes walks every node: each $ref must point at an existing node, and each schema
// type must be a JSON Schema type (or a list of them, the 3.1 way to express nullable).
func checkRefsAndTypes(t *testing.T, root map[string]any, node any, where string) {
	t.Helper()
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				ref, _ := v.(string)
				if !resolves(root, ref) {
					t.Errorf("%s: $ref %q does not resolve", where, ref)
				}
				continue
			}
			if k == "securitySchemes" {
				continue // security scheme types (apiKey, http) are not JSON Schema types
			}
			if k == "type" {
				checkType(t, where, v)
			}
			checkRefsAndTypes(t, root, v, where+"/"+k)
		}
	case []any:
		for i, v := range n {
			checkRefsAndTypes(t, root, v, fmt.Sprintf("%s[%d]", where, i))
		}
	}
}

func checkType(t *testing.T, where string, v any) {
	t.Helper()
	switch tv := v.(type) {
	case string:
		if !jsonTypes[tv] {
			t.Errorf("%s: unknown type %q", where, tv)
		}
	case []any:
		for _, x := range tv {
			if s, ok := x.(string); !ok || !jsonTypes[s] {
				t.Errorf("%s: unknown type %v", where, x)
			}
		}
	}
}

func resolves(root map[string]any, ref string) bool {
	_, ok := lookup(root, ref)
	return ok
}

// lookup follows a local JSON pointer such as #/components/parameters/ItemID.
func lookup(root map[string]any, ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	var cur any = root
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := asMap(cur)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

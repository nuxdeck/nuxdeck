// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"bytes"
	"encoding/json"
	"testing"
)

const (
	listFixture  = `[{"Id":"a","Names":["/web"],"Labels":{"app":"web","registry.password":"SECRET_VALUE"},"Mounts":[{"Source":"/srv/secret","Destination":"/d"}]},{"Id":"b","Labels":null}]`
	infoFixture  = `{"ID":"x","Containers":3,"RegistryConfig":{"auth":"SECRET_VALUE"},"IndexServerAddress":"https://index","Plugins":{"Volume":["local"]},"Swarm":{"NodeID":"n","RemoteManagers":[{"Addr":"10.0.0.1"}]},"HttpProxy":"http://user:SECRET_VALUE@proxy","HttpsProxy":"x","NoProxy":"y","Labels":["site=a","api_token=SECRET_VALUE"],"ServerVersion":"27.0"}` //nolint:gosec // a fake secret that the test expects to be removed
	eventFixture = `{"Type":"container","Action":"start","Actor":{"ID":"a","Attributes":{"name":"web","image":"nginx","com.example.api_key":"SECRET_VALUE","PASSWORD":"SECRET_VALUE"}}}`                                                                                                                                                                                  //nolint:gosec // a fake secret that the test expects to be removed
)

// bodyRoutes are the routes whose responses filterBody rewrites.
var bodyRoutes = []routeID{rInfo, rList, rInspect}

// FuzzFilterBody checks that no input to the response filter forwards an environment, a
// bind or mount source, or a dropped /info field, and that it never panics.
func FuzzFilterBody(f *testing.F) {
	for sel := range bodyRoutes {
		for _, s := range []string{inspectFixture, listFixture, infoFixture, `{}`, `[]`, `null`, `[{"Mounts":[{"Source":"/x"}]}]`} {
			f.Add(uint8(sel), []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, sel uint8, body []byte) {
		id := bodyRoutes[int(sel)%len(bodyRoutes)]
		out, err := filterBody(id, body)
		if err != nil {
			return
		}
		checkFilteredBody(t, id, out)
	})
}

// FuzzFilterEvent checks that each filtered event is one JSON object line with no secret
// attribute keys, and that the filter never panics.
func FuzzFilterEvent(f *testing.F) {
	for _, s := range []string{eventFixture, `{"Type":"container","Action":"die","Actor":{"ID":"a","Attributes":{"name":"web"}}}`, "this is not json", `{}`, `[]`, `{"Actor":{"Attributes":null}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		out, err := filterEvent(line)
		if err != nil {
			return
		}
		if bytes.ContainsAny(out, "\r\n") {
			t.Fatalf("event output spans lines: %q", out)
		}
		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("event output is not a JSON object: %v: %q", err, out)
		}
		actor, _ := v["Actor"].(map[string]any)
		attrs, _ := actor["Attributes"].(map[string]any)
		for k := range attrs {
			if secretKey.MatchString(k) {
				t.Fatalf("secret attribute %q survived: %q", k, out)
			}
		}
	})
}

func checkFilteredBody(t *testing.T, id routeID, out []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("filtered body is not JSON: %v: %q", err, out)
	}
	if id != rList {
		checkDocument(t, id, v)
		return
	}
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("list route forwarded a non-array: %q", out)
	}
	for _, item := range list {
		checkDocument(t, id, item)
	}
}

func checkDocument(t *testing.T, id routeID, v any) {
	t.Helper()
	doc, ok := v.(map[string]any)
	if !ok {
		return
	}
	if id == rInfo {
		for _, k := range []string{"RegistryConfig", "IndexServerAddress", "Plugins", "Swarm", "HttpProxy", "HttpsProxy", "NoProxy"} {
			if _, present := doc[k]; present {
				t.Fatalf("/info forwarded %s", k)
			}
		}
		return
	}
	for _, name := range []string{"Config", "ContainerConfig"} {
		if c, ok := doc[name].(map[string]any); ok {
			if _, present := c["Env"]; present {
				t.Fatalf("%s.Env survived", name)
			}
		}
	}
	// filterInspect scrubs Env at every depth; the list route only promises Config.Env.
	if id == rInspect && findKey(v, "Env") {
		t.Fatalf("an Env key survived somewhere in the inspect document")
	}
	checkMountList(t, doc["Mounts"], "Mounts")
	if h, ok := doc["HostConfig"].(map[string]any); ok {
		checkMountList(t, h["Mounts"], "HostConfig.Mounts")
		checkBinds(t, h["Binds"])
	}
}

// checkMountList requires Mounts to be a list whose entries carry no Source. A non-list
// value that still holds a Source would be forwarded untouched, so it fails too.
func checkMountList(t *testing.T, v any, name string) {
	t.Helper()
	if v == nil {
		return
	}
	list, ok := v.([]any)
	if !ok {
		if findKey(v, "Source") {
			t.Fatalf("%s is not a list and still carries a Source", name)
		}
		return
	}
	for _, m := range list {
		if o, ok := m.(map[string]any); ok {
			if _, present := o["Source"]; present {
				t.Fatalf("%s entry Source survived", name)
			}
		}
	}
}

// checkBinds requires every bind to be a string, since only strings are rewritten.
func checkBinds(t *testing.T, v any) {
	t.Helper()
	if v == nil {
		return
	}
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("Binds is not a list: %v", v)
	}
	for _, b := range list {
		if _, isString := b.(string); !isString && b != nil {
			t.Fatalf("non-string bind survived: %v", b)
		}
	}
}

// findKey reports whether any object in v, at any depth, has the given key.
func findKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[key]; ok {
			return true
		}
		for _, child := range t {
			if findKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if findKey(child, key) {
				return true
			}
		}
	}
	return false
}

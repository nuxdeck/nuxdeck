// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"strings"
	"testing"
)

// AGT-6: one row per line of the allowlist in docs/08-engineering-spec.md.
func TestAGT6_AllowlistRows(t *testing.T) {
	id := "0123abcd-web_1.x"
	tests := []struct {
		uri       string
		route     routeID
		want      string // the URI forwarded upstream
		streaming bool
	}{
		{"/_ping", rPing, "/_ping", false},
		{"/version", rVersion, "/version", false},
		{"/info", rInfo, "/info", false},
		{"/containers/json", rList, "/containers/json", false},
		{"/containers/json?all=1&size=true&filters=%7B%22status%22%3A%5B%22running%22%5D%7D", rList, "/containers/json?all=1&filters=%7B%22status%22%3A%5B%22running%22%5D%7D&size=true", false},
		{"/containers/" + id + "/json", rInspect, "/containers/" + id + "/json", false},
		{"/containers/" + id + "/json?size=0", rInspect, "/containers/" + id + "/json?size=0", false},
		{"/containers/" + id + "/logs", rLogs, "/containers/" + id + "/logs", false},
		{"/containers/" + id + "/logs?follow=true&stdout=1&stderr=1&since=1700000000&until=1700000000.5&tail=100&timestamps=1", rLogs, "/containers/" + id + "/logs?follow=true&since=1700000000&stderr=1&stdout=1&tail=100&timestamps=1&until=1700000000.5", true},
		{"/containers/" + id + "/logs?tail=all&since=2026-10-25T10:00:00Z", rLogs, "/containers/" + id + "/logs?since=2026-10-25T10%3A00%3A00Z&tail=all", false},
		{"/containers/" + id + "/stats", rStats, "/containers/" + id + "/stats", true},
		{"/containers/" + id + "/stats?stream=false", rStats, "/containers/" + id + "/stats?stream=false", false},
		{"/containers/" + id + "/stats?stream=0&one-shot=1", rStats, "/containers/" + id + "/stats?one-shot=1&stream=0", false},
		{"/containers/" + id + "/stats?one-shot=true", rStats, "/containers/" + id + "/stats?one-shot=true", false},
		{"/events", rEvents, "/events", true},
		{"/events?since=1700000000&until=1700000100&filters=%7B%7D", rEvents, "/events?filters=%7B%7D&since=1700000000&until=1700000100", false},
		{"/v1.41/containers/json", rList, "/v1.41/containers/json", false},
		{"/v1.43/containers/" + id + "/json", rInspect, "/v1.43/containers/" + id + "/json", false},
		{"/v1.4/_ping", rPing, "/v1.4/_ping", false},
	}
	for _, tt := range tests {
		got, err := Decide("GET", tt.uri)
		if err != nil {
			t.Errorf("%s: refused: %v", tt.uri, err)
			continue
		}
		if got.route != tt.route || got.URI != tt.want || got.Streaming != tt.streaming {
			t.Errorf("%s: route %d URI %q streaming %v, want route %d URI %q streaming %v", tt.uri, got.route, got.URI, got.Streaming, tt.route, tt.want, tt.streaming)
		}
	}
}

// AGT-6: everything outside the list is refused, including the calls that would hand over the host.
func TestAGT6_DangerousRequestsAreRefused(t *testing.T) {
	for _, tt := range refusedRequests {
		if got, err := Decide(tt.method, tt.uri); err == nil {
			t.Errorf("%s %q was allowed as %+v", tt.method, tt.uri, got)
		}
	}
}

type httpRequest struct{ method, uri string }

// refusedRequests is shared with the end-to-end test, which sends each one to a live guard.
var refusedRequests = func() []httpRequest {
	id := "abc123"
	long := strings.Repeat("a", 129)
	return []httpRequest{
		// Mutating methods on allowed paths.
		{"POST", "/containers/json"},
		{"PUT", "/containers/json"},
		{"DELETE", "/containers/" + id + "/json"},
		{"HEAD", "/_ping"},
		{"OPTIONS", "/info"},
		{"PATCH", "/version"},
		{"", "/info"},
		{"get", "/info"},
		{"CONNECT", "/events"},
		// Runtime operations.
		{"POST", "/containers/create"},
		{"GET", "/containers/create"},
		{"POST", "/containers/" + id + "/exec"},
		{"GET", "/containers/" + id + "/exec"},
		{"POST", "/exec/" + id + "/start"},
		{"GET", "/exec/" + id + "/json"},
		{"GET", "/containers/" + id + "/archive?path=/etc"},
		{"PUT", "/containers/" + id + "/archive?path=/"},
		{"POST", "/build"},
		{"GET", "/build"},
		{"POST", "/images/create?fromImage=evil"},
		{"GET", "/images/json"},
		{"POST", "/containers/" + id + "/attach"},
		{"GET", "/containers/" + id + "/attach"},
		{"GET", "/containers/" + id + "/attach/ws"},
		{"POST", "/containers/" + id + "/start"},
		{"POST", "/containers/" + id + "/kill"},
		{"POST", "/containers/" + id + "/stop"},
		{"POST", "/containers/" + id + "/restart"},
		{"DELETE", "/containers/" + id},
		{"POST", "/containers/" + id + "/update"},
		{"GET", "/containers/" + id + "/export"},
		{"GET", "/containers/" + id + "/changes"},
		{"GET", "/containers/" + id + "/top"},
		{"GET", "/containers/" + id + "/stats/extra"},
		{"GET", "/containers/" + id},
		{"GET", "/containers"},
		{"GET", "/volumes"},
		{"GET", "/networks"},
		{"GET", "/system/df"},
		{"POST", "/auth"},
		{"POST", "/commit"},
		{"GET", "/swarm"},
		{"GET", "/secrets"},
		{"GET", "/configs"},
		{"GET", "/plugins"},
		{"GET", "/services"},
		{"GET", "/nodes"},
		{"POST", "/session"},
		{"GET", "/distribution/x/json"},
		{"GET", "/libpod/containers/json"},
		{"GET", "/libpod/info"},
		// Traversal and encoding tricks.
		{"GET", "/containers/%2e%2e/json"},
		{"GET", "/containers/..%2fjson"},
		{"GET", "/containers/a%2Fb/json"},
		{"GET", "/containers/%2E%2E%2Fexec/json"},
		{"GET", "/containers/" + id + "%2fjson"},
		{"GET", "/%63ontainers/json"},
		{"GET", "/containers/../exec"},
		{"GET", "/containers/./json"},
		{"GET", "/containers/" + id + "/../json"},
		{"GET", "//containers/json"},
		{"GET", "/containers//json"},
		{"GET", "/containers/json/"},
		{"GET", "/containers/" + id + "/json/"},
		{"GET", "/v1.41/../containers/json"},
		{"GET", "/v1.41/%2e%2e/info"},
		{"GET", "/v2.0/info"},
		{"GET", "/v1.411/info"},
		{"GET", "/v1./info"},
		{"GET", "/v1.41"},
		{"GET", "/v1.41/v1.41/info"},
		{"GET", "/V1.41/info"},
		{"GET", "/containers/json\\..\\info"},
		{"GET", "/containers/%00/json"},
		{"GET", "/info%00"},
		{"GET", "/info\x00"},
		{"GET", "/info\r\nPOST /containers/create"},
		{"GET", "/info HTTP/1.1"},
		{"GET", "/info#x"},
		{"GET", "/ünfo"},
		{"GET", "http://docker/info"},
		{"GET", "*"},
		{"GET", ""},
		{"GET", "info"},
		// Case matters.
		{"GET", "/CONTAINERS/JSON"},
		{"GET", "/Info"},
		{"GET", "/containers/" + id + "/JSON"},
		// IDs outside ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$.
		{"GET", "/containers/" + long + "/json"},
		{"GET", "/containers/-x/json"},
		{"GET", "/containers/.x/json"},
		{"GET", "/containers/_x/json"},
		{"GET", "/containers/a b/json"},
		{"GET", "/containers/a:b/json"},
		{"GET", "/containers/é/json"},
		{"GET", "/containers/a;b/json"},
		// Parameters.
		{"GET", "/containers/json?exec=1"},
		{"GET", "/containers/json?all=1&all=0"},
		{"GET", "/containers/json?ALL=1"},
		{"GET", "/containers/json?all=yes"},
		{"GET", "/containers/json?all=1;size=1"},
		{"GET", "/containers/json?all=%"},
		{"GET", "/containers/json?all"},
		{"GET", "/containers/json?=1"},
		{"GET", "/containers/json?limit=1"},
		{"GET", "/_ping?x=1"},
		{"GET", "/info?x=1"},
		{"GET", "/version?x=1"},
		{"GET", "/containers/" + id + "/json?size=1&x=1"},
		{"GET", "/containers/" + id + "/logs?tail=-1"},
		{"GET", "/containers/" + id + "/logs?tail=abc"},
		{"GET", "/containers/" + id + "/logs?since=yesterday"},
		{"GET", "/containers/" + id + "/logs?follow=maybe"},
		{"GET", "/containers/" + id + "/logs?details=1"},
		{"GET", "/containers/" + id + "/stats?x=1"},
		{"GET", "/events?filters=" + strings.Repeat("a", 4097)},
		{"GET", "/events?since=1;2"},
		{"GET", "/" + strings.Repeat("a", 9000)},
	}
}()

func FuzzDecide(f *testing.F) {
	for _, s := range []string{
		"/containers/json", "/containers/abc/json?size=1", "/v1.41/events?since=1", "/containers/%2e%2e/json",
		"/containers/abc/logs?tail=10&follow=1", "//", "/containers/a/../b", "/info?x=y;z", "/containers/abc/exec", "/containers/0../logs",
	} {
		f.Add("GET", s)
	}
	f.Add("POST", "/containers/json")
	f.Fuzz(func(t *testing.T, method, uri string) {
		req, err := Decide(method, uri)
		if err != nil {
			return
		}
		// Whatever was allowed must be a plain, canonical request for exactly one allowlisted route.
		path, query, _ := strings.Cut(req.URI, "?")
		if method != "GET" || strings.ContainsAny(req.URI, "%\\#\x00\r\n ") && !strings.Contains(query, "%") {
			t.Fatalf("allowed %q %q as %q", method, uri, req.URI)
		}
		if strings.Contains(path, "%") || strings.Contains(path, "//") || strings.HasSuffix(path, "/") || !strings.HasPrefix(path, "/") {
			t.Fatalf("allowed %q with a non-canonical path %q", uri, path)
		}
		for _, seg := range strings.Split(path[1:], "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("allowed %q with a dot segment in %q", uri, path)
			}
		}
		again, err := Decide("GET", req.URI)
		if err != nil || again.URI != req.URI || again.route != req.route {
			t.Fatalf("the forwarded request %q does not decide to itself: %+v %v", req.URI, again, err)
		}
	})
}

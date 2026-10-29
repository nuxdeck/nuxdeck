// SPDX-License-Identifier: Apache-2.0

// Package sockguard is nux-sockguard: the only process on a host that touches the
// container runtime socket (ADR-011). It forwards a fixed list of read-only GET
// requests, filters what comes back and refuses everything else. It is security
// critical: keep it small and standard-library only.
package sockguard

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// kind names how a query value is validated.
type kind int

const (
	kBool kind = iota + 1 // 0, 1, true, false
	kTail                 // all or a number
	kTime                 // Unix time, optionally fractional, or an RFC 3339 timestamp
	kJSON                 // filters: any short string, the runtime parses it
)

var (
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^v1\.[0-9]{1,2}$`)
	boolPattern    = regexp.MustCompile(`^(0|1|true|false)$`)
	tailPattern    = regexp.MustCompile(`^(all|[0-9]{1,9})$`)
	timePattern    = regexp.MustCompile(`^([0-9]{1,12}(\.[0-9]{1,9})?|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+Z-]{1,32})$`)
)

const (
	maxURILength   = 8192
	maxValueLength = 4096
)

// ErrDenied is returned for every request outside the allowlist.
var ErrDenied = errors.New("request is not on the allowlist")

type routeID int

const (
	rPing routeID = iota + 1
	rVersion
	rInfo
	rList
	rInspect
	rLogs
	rStats
	rEvents
)

// routeSpec is one row of the allowlist in docs/08-engineering-spec.md.
type routeSpec struct {
	id     routeID
	params map[string]kind
}

var (
	noParams = map[string]kind{}
	routes   = map[string]routeSpec{
		"_ping":      {rPing, noParams},
		"version":    {rVersion, noParams},
		"info":       {rInfo, noParams},
		"containers": {rList, map[string]kind{"all": kBool, "filters": kJSON, "size": kBool}},
		"events":     {rEvents, map[string]kind{"since": kTime, "until": kTime, "filters": kJSON}},
	}
	inspectSpec = map[string]routeSpec{
		"json":  {rInspect, map[string]kind{"size": kBool}},
		"logs":  {rLogs, map[string]kind{"follow": kBool, "stdout": kBool, "stderr": kBool, "since": kTime, "until": kTime, "tail": kTail, "timestamps": kBool}},
		"stats": {rStats, map[string]kind{"stream": kBool, "one-shot": kBool}},
	}
)

// Request is an allowed request, rebuilt from validated parts. Only URI is sent upstream.
type Request struct {
	route     routeID
	URI       string
	Streaming bool
}

// Decide checks a request line against the allowlist. requestURI is the raw target as
// received. Any doubt is a refusal: encoded characters, dot segments, empty segments,
// unknown or repeated parameters and non-GET methods all fail.
func Decide(method, requestURI string) (Request, error) {
	if method != "GET" || len(requestURI) == 0 || len(requestURI) > maxURILength || requestURI[0] != '/' {
		return Request{}, ErrDenied
	}
	for i := 0; i < len(requestURI); i++ {
		if c := requestURI[i]; c <= 0x20 || c >= 0x7f || c == '#' || c == '\\' {
			return Request{}, ErrDenied
		}
	}
	path, rawQuery, _ := strings.Cut(requestURI, "?")
	if strings.Contains(path, "%") {
		return Request{}, ErrDenied
	}
	segs := strings.Split(path[1:], "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return Request{}, ErrDenied
		}
	}
	if versionPattern.MatchString(segs[0]) {
		segs = segs[1:] // the version prefix is checked here and passed through as received
	}
	if len(segs) == 0 {
		return Request{}, ErrDenied
	}

	var spec routeSpec
	var ok bool
	switch {
	case len(segs) == 1:
		spec, ok = routes[segs[0]]
		if segs[0] == "containers" {
			ok = false // only containers/json
		}
	case len(segs) == 2 && segs[0] == "containers" && segs[1] == "json":
		spec, ok = routes["containers"]
	case len(segs) == 3 && segs[0] == "containers" && idPattern.MatchString(segs[1]):
		spec, ok = inspectSpec[segs[2]]
	}
	if !ok {
		return Request{}, ErrDenied
	}

	q, err := url.ParseQuery(rawQuery) // rejects semicolons and bad escapes
	if err != nil {
		return Request{}, ErrDenied
	}
	for key, vals := range q {
		k, known := spec.params[key]
		if !known || len(vals) != 1 || len(vals[0]) > maxValueLength || !validValue(k, vals[0]) {
			return Request{}, ErrDenied
		}
	}

	uri := path // validated above: plain ASCII segments only, so it is safe to forward as is
	if enc := q.Encode(); enc != "" {
		uri += "?" + enc
	}
	return Request{route: spec.id, URI: uri, Streaming: streaming(spec.id, q)}, nil
}

func validValue(k kind, v string) bool {
	switch k {
	case kBool:
		return boolPattern.MatchString(v)
	case kTail:
		return tailPattern.MatchString(v)
	case kTime:
		return timePattern.MatchString(v)
	case kJSON:
		return true
	}
	return false
}

func truthy(v string) bool { return v == "1" || v == "true" }

// streaming reports whether the response is open-ended, so it gets no overall timeout.
func streaming(id routeID, q url.Values) bool {
	switch id {
	case rLogs:
		return truthy(q.Get("follow"))
	case rStats:
		return q.Get("stream") != "0" && q.Get("stream") != "false" && !truthy(q.Get("one-shot"))
	case rEvents:
		return q.Get("until") == ""
	}
	return false
}

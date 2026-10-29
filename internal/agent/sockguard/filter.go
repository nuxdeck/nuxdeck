// SPDX-License-Identifier: Apache-2.0

package sockguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

// secretKey is the label redaction rule from docs/08-engineering-spec.md.
var secretKey = regexp.MustCompile(`(?i)pass|secret|token|key|credential`)

var errShape = errors.New("response does not have the expected shape")

type object = map[string]any

// filterBody applies the response filtering of one route. It fails closed: a body
// that is not valid JSON of the expected shape is never forwarded.
func filterBody(id routeID, body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep large numbers exact
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errShape
	}

	switch id {
	case rInfo:
		o, ok := v.(object)
		if !ok {
			return nil, errShape
		}
		// Proxy settings can hold credentials; registry, plugin and swarm data is configuration the agent never needs.
		for _, k := range []string{"RegistryConfig", "IndexServerAddress", "Plugins", "Swarm", "HttpProxy", "HttpsProxy", "NoProxy"} {
			delete(o, k)
		}
		redactLabelList(o["Labels"])
	case rList:
		list, ok := v.([]any)
		if !ok {
			return nil, errShape
		}
		for _, item := range list {
			o, ok := item.(object)
			if !ok {
				return nil, errShape
			}
			redactLabels(o["Labels"])
			dropSources(o["Mounts"])
		}
	case rInspect:
		o, ok := v.(object)
		if !ok {
			return nil, errShape
		}
		filterInspect(o)
	default:
		return nil, errShape
	}
	return marshal(v)
}

// filterEvent applies the events filtering to one event object.
func filterEvent(line []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	o, ok := v.(object)
	if !ok {
		return nil, errShape
	}
	if actor, ok := o["Actor"].(object); ok {
		if attrs, ok := actor["Attributes"].(object); ok {
			for k := range attrs {
				if secretKey.MatchString(k) {
					delete(attrs, k)
				}
			}
		}
	}
	return marshal(o)
}

func filterInspect(o object) {
	for _, name := range []string{"Config", "ContainerConfig"} {
		if c, ok := o[name].(object); ok {
			delete(c, "Env")
			delete(c, "CreateCommand") // Podman records the full `podman run` command line, including -e flags
			redactLabels(c["Labels"])
		}
	}
	if h, ok := o["HostConfig"].(object); ok {
		if binds, ok := h["Binds"].([]any); ok {
			for i, b := range binds {
				if s, ok := b.(string); ok {
					binds[i] = dropBindSource(s)
				}
			}
		}
		dropSources(h["Mounts"])
	}
	dropSources(o["Mounts"])
	scrubKey(o, "Env") // belt and braces: no environment survives anywhere in the document
}

// dropBindSource turns "host:/container:ro" into "/container:ro"; a bare "/container" has no source.
func dropBindSource(b string) string {
	if _, rest, ok := strings.Cut(b, ":"); ok {
		return rest
	}
	return b
}

func dropSources(v any) {
	list, _ := v.([]any)
	for _, item := range list {
		if m, ok := item.(object); ok {
			delete(m, "Source")
		}
	}
}

func redactLabels(v any) {
	if m, ok := v.(object); ok {
		for k := range m {
			if secretKey.MatchString(k) {
				m[k] = redacted
			}
		}
	}
}

// redactLabelList handles the daemon's labels in /info, which are "key=value" strings.
func redactLabelList(v any) {
	list, _ := v.([]any)
	for i, item := range list {
		if s, ok := item.(string); ok {
			if k, _, found := strings.Cut(s, "="); found && secretKey.MatchString(k) {
				list[i] = k + "=" + redacted
			}
		}
	}
}

func scrubKey(v any, key string) {
	switch t := v.(type) {
	case object:
		delete(t, key)
		for _, child := range t {
			scrubKey(child, key)
		}
	case []any:
		for _, child := range t {
			scrubKey(child, key)
		}
	}
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

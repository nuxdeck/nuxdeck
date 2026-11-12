// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// JSON ops of an HTTP check.
const (
	JSONExists = "exists"
	JSONEquals = "equals"
)

type pathStep struct {
	key   string
	index int // -1 for an object key
}

// ParseJSONPath parses the supported subset: dotted keys and [n] indexes, such as a.b[0].c.
func ParseJSONPath(p string) ([]pathStep, error) {
	if p == "" || len(p) > 200 {
		return nil, fmt.Errorf("path must be 1 to 200 characters")
	}
	var steps []pathStep
	for _, part := range strings.Split(p, ".") {
		key, rest, hasIdx := strings.Cut(part, "[")
		if hasIdx && rest == "" {
			return nil, fmt.Errorf("unclosed index")
		}
		if key == "" && (len(steps) == 0 || !hasIdx) {
			return nil, fmt.Errorf("empty path segment")
		}
		if key != "" {
			if !validKey(key) {
				return nil, fmt.Errorf("bad key %q", key)
			}
			steps = append(steps, pathStep{key: key, index: -1})
		}
		for rest != "" {
			num, after, ok := strings.Cut(rest, "]")
			if !ok {
				return nil, fmt.Errorf("unclosed index")
			}
			n, err := strconv.Atoi(num)
			if err != nil || n < 0 || n > 10000 {
				return nil, fmt.Errorf("bad index %q", num)
			}
			steps = append(steps, pathStep{index: n})
			switch {
			case after == "":
				rest = ""
			case strings.HasPrefix(after, "["):
				rest = after[1:]
			default:
				return nil, fmt.Errorf("unexpected text after index")
			}
		}
	}
	return steps, nil
}

func validKey(k string) bool {
	for _, c := range k {
		if c == '[' || c == ']' || c == '.' || c < 0x20 {
			return false
		}
	}
	return len(k) <= 64
}

// matchJSON evaluates the path against body. found reports whether the path exists; for
// "equals" the scalar's text must equal want (numbers compare by their JSON text).
func matchJSON(body []byte, path, op, want string) (ok bool, err error) {
	steps, err := ParseJSONPath(path)
	if err != nil {
		return false, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return false, fmt.Errorf("not JSON")
	}
	cur := doc
	for _, st := range steps {
		if st.index >= 0 {
			arr, isArr := cur.([]any)
			if !isArr || st.index >= len(arr) {
				return false, nil
			}
			cur = arr[st.index]
			continue
		}
		obj, isObj := cur.(map[string]any)
		if !isObj {
			return false, nil
		}
		v, present := obj[st.key]
		if !present {
			return false, nil
		}
		cur = v
	}
	if op == JSONExists {
		return true, nil
	}
	switch v := cur.(type) {
	case string:
		return v == want, nil
	case json.Number:
		return v.String() == want, nil
	case bool:
		return strconv.FormatBool(v) == want, nil
	case nil:
		return want == "null", nil
	}
	return false, nil
}

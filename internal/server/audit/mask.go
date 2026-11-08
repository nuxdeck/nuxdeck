// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"encoding/json"
	"strings"
)

// Redacted replaces the value of a sensitive key.
const Redacted = "[redacted]"

// sensitiveKey reports whether a details key may hold a credential. Writers must never put
// secrets in details; this is the read-time backstop.
func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, frag := range []string{"token", "secret", "password", "passphrase", "private_key", "api_key", "apikey"} {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return k == "code" || k == "codes" || strings.HasSuffix(k, "_code") || strings.HasSuffix(k, "_codes")
}

// MaskDetails redacts sensitive keys, at any depth, in a stored details document. Input that
// cannot be parsed is replaced entirely rather than risk showing something unvetted.
func MaskDetails(detailsJSON string) string {
	var v any
	if err := json.Unmarshal([]byte(detailsJSON), &v); err != nil {
		return "{}"
	}
	b, err := json.Marshal(maskValue(v))
	if err != nil {
		return "{}"
	}
	return string(b)
}

func maskValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if sensitiveKey(k) {
				t[k] = Redacted
			} else {
				t[k] = maskValue(x)
			}
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = maskValue(x)
		}
		return t
	default:
		return v
	}
}

// Verification is the outcome of walking the whole chain.
type Verification struct {
	OK      bool `json:"ok"`
	Entries int  `json:"entries"`
	// BrokenAt is the ID of the first entry that does not verify; 0 when OK.
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

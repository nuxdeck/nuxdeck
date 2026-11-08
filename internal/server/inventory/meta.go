// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Item types that carry tags and an owner.
const (
	ItemHost      = "host"
	ItemContainer = "container"
)

// Bounds on tags and owners (INV-3). They are an allowlist: anything outside is rejected, never repaired.
const (
	MaxTags     = 50
	maxOwnerLen = 128
)

var (
	tagKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,62}$`)
	tagValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-/+@]{1,64}$`)
	ownerPattern    = regexp.MustCompile(`^[\p{L}\p{N} _.\-@+/]*$`)
)

// Errors of metadata updates.
var (
	ErrNotFound = errors.New("inventory: item not found")
	ErrStale    = errors.New("inventory: item changed since it was read")
)

// ValidationError names the offending field and carries a hint safe to show.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

// ValidTag reports whether key and value are allowed in a tag.
func ValidTag(key, value string) bool {
	return tagKeyPattern.MatchString(key) && tagValuePattern.MatchString(value)
}

// ValidateTags checks a full tag set.
func ValidateTags(tags map[string]string) error {
	if len(tags) > MaxTags {
		return &ValidationError{"tags", fmt.Sprintf("Use at most %d tags.", MaxTags)}
	}
	for k, v := range tags {
		if !ValidTag(k, v) {
			return &ValidationError{"tags", "Keys use letters, digits and _ . - / (up to 63 characters); values use letters, digits and _ . - / + @ (1 to 64 characters)."}
		}
	}
	return nil
}

// ValidateOwner checks an owner; empty clears it.
func ValidateOwner(owner string) error {
	if utf8.RuneCountInString(owner) > maxOwnerLen || !ownerPattern.MatchString(owner) || owner != strings.TrimSpace(owner) {
		return &ValidationError{"owner", "Use up to 128 letters, digits, spaces and _ . - @ + /, without leading or trailing spaces."}
	}
	return nil
}

// TagSelector is one `key:value` filter; an empty value matches any value of the key.
type TagSelector struct{ Key, Value string }

// ParseSelector reads `key:value` or `key`.
func ParseSelector(s string) (TagSelector, error) {
	key, value, _ := strings.Cut(s, ":")
	if !tagKeyPattern.MatchString(key) || (value != "" && !tagValuePattern.MatchString(value)) {
		return TagSelector{}, &ValidationError{"tag", "Use key:value, for example env:production."}
	}
	return TagSelector{Key: key, Value: value}, nil
}

func matchesAll(tags map[string]string, sel []TagSelector) bool {
	for _, s := range sel {
		v, ok := tags[s.Key]
		if !ok || (s.Value != "" && v != s.Value) {
			return false
		}
	}
	return true
}

// MetaETag identifies the current owner and tags of an item. Facts and state are left out: they change
// all the time and must not turn an edit of the tags into a conflict.
func MetaETag(owner string, tags map[string]string) string {
	h := sha256.New()
	h.Write([]byte(owner))
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		h.Write([]byte("\x00" + k + "\x00" + tags[k]))
	}
	return `"` + hex.EncodeToString(h.Sum(nil)[:12]) + `"`
}

// MetaChange is a requested edit: nil fields stay as they are; a non-nil Tags replaces the whole set.
type MetaChange struct {
	Owner *string
	Tags  map[string]string
}

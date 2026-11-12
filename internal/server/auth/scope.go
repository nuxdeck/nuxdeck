// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Scope narrows a role binding to part of the inventory (ACC-5). The zero
// value is unscoped: the binding applies everywhere, including to resources
// that carry no environment or tags, such as notification channels.
//
// A scoped binding covers an item when the item's environment is listed in
// Environments, or when the item carries every tag in one of the TagSets
// (a tag set is an AND; the sets are ORed). Items with neither never match a
// scoped binding.
type Scope struct {
	Environments []string   `json:"environments,omitempty"`
	TagSets      [][]string `json:"tag_sets,omitempty"`
}

// IsZero reports whether the scope is unscoped.
func (s Scope) IsZero() bool { return len(s.Environments) == 0 && len(s.TagSets) == 0 }

// Binding grants a role, optionally limited by a scope.
type Binding struct {
	Role  Role  `json:"role"`
	Scope Scope `json:"scope"`
}

// Resource describes what an action touches, for scope matching. The zero
// value is a global resource.
type Resource struct {
	Environment string
	Tags        []string
}

// Resource tag strings are "key:value".

// ResourceOf builds the Resource of an item from its tags; the environment is the env tag.
func ResourceOf(tags map[string]string) Resource {
	r := Resource{Environment: tags["env"]}
	for k, v := range tags {
		r.Tags = append(r.Tags, k+":"+v)
	}
	sort.Strings(r.Tags)
	return r
}

// ResourceOfSelector builds the Resource that a tag selector (`key` or `key:value`, all required)
// can only ever match, so a scope covers the selector only if it covers every item it could match.
func ResourceOfSelector(tags []string) Resource {
	var r Resource
	for _, t := range tags {
		r.Tags = append(r.Tags, t)
		if v, ok := strings.CutPrefix(t, "env:"); ok && v != "" {
			r.Environment = v
		}
	}
	return r
}

// Covers reports whether the scope applies to res. An unscoped binding covers everything; a scoped
// one covers only resources whose environment is listed or that carry every tag of one tag set.
// A global resource (no environment, no tags) is covered only by an unscoped binding.
func (s Scope) Covers(res Resource) bool {
	if s.IsZero() {
		return true
	}
	if res.Environment != "" {
		for _, e := range s.Environments {
			if e == res.Environment {
				return true
			}
		}
	}
	for _, set := range s.TagSets {
		if len(set) > 0 && hasAllTags(res, set) {
			return true
		}
	}
	return false
}

func hasAllTags(res Resource, set []string) bool {
	for _, want := range set {
		if want == "" || !hasTag(res, want) {
			return false
		}
	}
	return true
}

func hasTag(res Resource, want string) bool {
	if want == "env" && res.Environment != "" {
		return true
	}
	if k, ok := strings.CutPrefix(want, "env:"); ok && res.Environment == k && k != "" {
		return true
	}
	for _, t := range res.Tags {
		if t == want || (!strings.Contains(want, ":") && strings.HasPrefix(t, want+":")) {
			return true
		}
	}
	return false
}

// Limits on a stored scope, so a binding cannot make every authorisation expensive.
const (
	maxScopeEntries = 32
	maxScopeTagLen  = 128
)

// Validate rejects a scope that is empty-but-present, oversized or malformed.
func (s Scope) Validate() error {
	if len(s.Environments) > maxScopeEntries || len(s.TagSets) > maxScopeEntries {
		return fmt.Errorf("a scope holds at most %d environments and %d tag sets", maxScopeEntries, maxScopeEntries)
	}
	for _, e := range s.Environments {
		if e == "" || len(e) > maxScopeTagLen || strings.ContainsAny(e, ":\x00") {
			return fmt.Errorf("environment %q is not valid", e)
		}
	}
	for _, set := range s.TagSets {
		if len(set) == 0 || len(set) > maxScopeEntries {
			return fmt.Errorf("a tag set holds 1 to %d tags", maxScopeEntries)
		}
		for _, t := range set {
			if t == "" || len(t) > maxScopeTagLen || strings.HasPrefix(t, ":") || strings.HasSuffix(t, ":") {
				return fmt.Errorf("tag %q is not valid", t)
			}
		}
	}
	return nil
}

// ParseScope decodes a stored scope_json. Unknown fields or invalid content are an error, and callers
// must then drop the binding: a binding that cannot be read grants nothing (fail closed).
func ParseScope(raw string) (Scope, error) {
	var s Scope
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return s, nil
	}
	if raw == "null" { // would decode to the zero value, which is unscoped
		return Scope{}, fmt.Errorf("parse scope: null is not a scope")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Scope{}, fmt.Errorf("parse scope: %w", err)
	}
	if err := s.Validate(); err != nil {
		return Scope{}, err
	}
	return s, nil
}

// UnscopedRoles summarises bindings as the roles held everywhere, sorted and without duplicates.
func UnscopedRoles(bindings []Binding) []Role {
	var out []Role
	for _, b := range bindings {
		if b.Scope.IsZero() && !slices.Contains(out, b.Role) {
			out = append(out, b.Role)
		}
	}
	slices.Sort(out)
	return out
}

// Subject types of a role binding.
const (
	SubjectUser      = "user"
	SubjectOIDCGroup = "oidc_group"
)

// StoredBinding is a role binding as the admin API lists and edits it.
type StoredBinding struct {
	ID          string `json:"id"`
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
	Role        Role   `json:"role"`
	Scope       Scope  `json:"scope"`
	// Invalid marks a stored binding whose scope cannot be read; it grants nothing until fixed.
	Invalid bool `json:"invalid,omitempty"`
}

// ValidRole reports whether r is one of the three built-in roles.
func ValidRole(r Role) bool { return bindingRank(r) > 0 }

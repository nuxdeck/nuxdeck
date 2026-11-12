// SPDX-License-Identifier: Apache-2.0

package errcode

import (
	"errors"
	"fmt"
	"regexp"
	"testing"
)

func TestEntriesAreUniqueAndWellFormed(t *testing.T) {
	format := regexp.MustCompile(`^(SRV|GW|AGT|SKG|INV|MET|LOG|CHK|ALR|STP|AUTH|AUD|API|CLI|TEL|BAK)-[A-Z]+-\d{3}$`)
	seen := map[Code]bool{}
	for _, e := range Entries() {
		if seen[e.Code] {
			t.Errorf("duplicate code %s", e.Code)
		}
		seen[e.Code] = true
		if !format.MatchString(string(e.Code)) {
			t.Errorf("code %q does not match AREA-CATEGORY-NNN", e.Code)
		}
		if e.Title == "" || e.Message == "" || e.Hint == "" {
			t.Errorf("code %s needs a title, message and hint", e.Code)
		}
	}
}

func TestErrorChain(t *testing.T) {
	root := errors.New("disk full")
	err := fmt.Errorf("start: %w", Wrap(SRVIO001, "create data dir", root))

	if got := CodeOf(err); got != SRVIO001 {
		t.Errorf("CodeOf = %q, want %q", got, SRVIO001)
	}
	if !errors.Is(err, root) {
		t.Error("wrapped error lost its cause")
	}
	if got := CodeOf(errors.New("plain")); got != "" {
		t.Errorf("CodeOf(plain) = %q, want empty", got)
	}
	if _, ok := Lookup(SRVIO001); !ok {
		t.Error("Lookup(SRVIO001) not found")
	}
	if _, ok := Lookup("SRV-XXX-999"); ok {
		t.Error("Lookup found an undeclared code")
	}
}

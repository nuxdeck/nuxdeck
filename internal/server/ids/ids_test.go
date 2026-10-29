// SPDX-License-Identifier: AGPL-3.0-only

package ids

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var format = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// decodeTime reads the 48-bit timestamp back out of a ULID.
func decodeTime(t *testing.T, id string) int64 {
	t.Helper()
	var n int64
	for _, c := range id[:10] {
		n = n<<5 | int64(strings.IndexRune(alphabet, c))
	}
	return n
}

func TestAtEncodesTimeAndFormat(t *testing.T) {
	when := time.UnixMilli(1_790_000_000_123)
	id, err := At(when)
	if err != nil {
		t.Fatal(err)
	}
	if !format.MatchString(id) {
		t.Fatalf("%q is not a valid ULID", id)
	}
	if got := decodeTime(t, id); got != when.UnixMilli() {
		t.Errorf("decoded time = %d, want %d", got, when.UnixMilli())
	}
}

func TestSortsByCreationTime(t *testing.T) {
	earlier, _ := At(time.UnixMilli(1_790_000_000_000))
	later, _ := At(time.UnixMilli(1_790_000_000_001))
	if earlier >= later {
		t.Errorf("%s should sort before %s", earlier, later)
	}
}

func TestUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestNewIsMonotonicWithinOneMillisecond(t *testing.T) {
	prev, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for range 5000 {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if id <= prev {
			t.Fatalf("%s did not sort after %s", id, prev)
		}
		prev = id
	}
}

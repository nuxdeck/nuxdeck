// SPDX-License-Identifier: AGPL-3.0-only

package audit

import "testing"

func chain(t *testing.T, n int) []Entry {
	t.Helper()
	var out []Entry
	prev := ""
	for i := 1; i <= n; i++ {
		d, err := CanonicalDetails(map[string]any{"b": 2, "a": i})
		if err != nil {
			t.Fatal(err)
		}
		e := Entry{
			ID: int64(i), TS: int64(1000 + i), DetailsJSON: d, PrevHash: prev,
			Event: Event{ActorType: "user", ActorID: "u1", Action: "auth.login", Result: ResultSuccess, IP: "203.0.113.9"},
		}
		h, err := Hash(e)
		if err != nil {
			t.Fatal(err)
		}
		e.Hash = h
		prev = h
		out = append(out, e)
	}
	return out
}

func verify(entries []Entry) error {
	var v Verifier
	for _, e := range entries {
		if err := v.Add(e); err != nil {
			return err
		}
	}
	return nil
}

func TestValidChainVerifies(t *testing.T) {
	if err := verify(chain(t, 5)); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(es []Entry) []Entry
	}{
		{"edited field", func(es []Entry) []Entry { es[2].Event.Result = ResultFailure; return es }},
		{"edited details", func(es []Entry) []Entry { es[1].DetailsJSON = `{"a":99}`; return es }},
		{"edited timestamp", func(es []Entry) []Entry { es[3].TS++; return es }},
		{"deleted middle entry", func(es []Entry) []Entry { return append(es[:2], es[3:]...) }},
		{"deleted first entry", func(es []Entry) []Entry { return es[1:] }},
		{"swapped entries", func(es []Entry) []Entry { es[1], es[2] = es[2], es[1]; return es }},
		{"rewritten hash without chaining", func(es []Entry) []Entry { es[2].PrevHash = "00"; return es }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verify(tt.mutate(chain(t, 5))); err == nil {
				t.Fatal("tampering was not detected")
			}
		})
	}
}

func TestCanonicalDetailsSortsKeys(t *testing.T) {
	got, err := CanonicalDetails(map[string]any{"z": 1, "a": "x"})
	if err != nil || got != `{"a":"x","z":1}` {
		t.Errorf("got %q, err %v", got, err)
	}
	if empty, _ := CanonicalDetails(nil); empty != "{}" {
		t.Errorf("empty details = %q, want {}", empty)
	}
}

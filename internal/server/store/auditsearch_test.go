// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
)

func seedAudit(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		e := ev(fmt.Sprintf("thing.%d", i%3))
		e.ActorID = fmt.Sprintf("u%d", i%2)
		e.TargetType, e.TargetID = "check", fmt.Sprintf("c%d", i)
		e.Details = map[string]any{"note": fmt.Sprintf("Entry-%d", i)}
		if i%5 == 0 {
			e.Result = audit.ResultFailure
		}
		if err := s.RecordAudit(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

// AUD-2: a clean chain verifies.
func TestVerifyAuditClean(t *testing.T) {
	s := openStore(t)
	seedAudit(t, s, 7)
	v, err := s.VerifyAudit(context.Background())
	if err != nil || !v.OK || v.Entries != 7 || v.BrokenAt != 0 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	if v, err := openStore(t).VerifyAudit(context.Background()); err != nil || !v.OK || v.Entries != 0 {
		t.Fatalf("empty log = %+v, %v", v, err)
	}
}

// AUD-2: tampering by someone who bypasses the triggers is detected at the first affected entry.
func TestVerifyAuditDetectsTampering(t *testing.T) {
	ctx := context.Background()
	tamper := map[string]string{
		"modified": `UPDATE audit_log SET result = 'success', action = 'nothing.happened' WHERE id = 4`,
		"deleted":  `DELETE FROM audit_log WHERE id = 3`,
		"relinked": `UPDATE audit_log SET prev_hash = 'x' WHERE id = 5`,
	}
	want := map[string]int64{"modified": 4, "deleted": 4, "relinked": 5}
	for name, stmt := range tamper {
		t.Run(name, func(t *testing.T) {
			s := openStore(t)
			seedAudit(t, s, 8)
			for _, trg := range []string{"audit_log_no_update", "audit_log_no_delete"} {
				if _, err := s.DB().ExecContext(ctx, `DROP TRIGGER `+trg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB().ExecContext(ctx, stmt); err != nil {
				t.Fatal(err)
			}
			v, err := s.VerifyAudit(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if v.OK || v.BrokenAt != want[name] || v.Reason == "" {
				t.Fatalf("verify = %+v, want break at %d", v, want[name])
			}
		})
	}
}

// AUD-2: the triggers still refuse edits when intact.
func TestAuditTriggersRefuseEdits(t *testing.T) {
	s := openStore(t)
	seedAudit(t, s, 2)
	for _, stmt := range []string{`UPDATE audit_log SET result = 'failure'`, `DELETE FROM audit_log`} {
		if _, err := s.DB().Exec(stmt); err == nil {
			t.Errorf("%q succeeded", stmt)
		}
	}
}

// AUD-3: filters and cursor pagination.
func TestSearchAudit(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	seedAudit(t, s, 12)

	page, next, err := s.SearchAudit(ctx, AuditFilter{}, 0, 5)
	if err != nil || len(page) != 5 || page[0].ID != 12 || next != 8 {
		t.Fatalf("page 1 = %d entries first %d next %d, %v", len(page), page[0].ID, next, err)
	}
	page, next, _ = s.SearchAudit(ctx, AuditFilter{}, next, 5)
	if page[0].ID != 7 || next != 3 {
		t.Fatalf("page 2 first %d next %d", page[0].ID, next)
	}
	page, next, _ = s.SearchAudit(ctx, AuditFilter{}, next, 5)
	if len(page) != 2 || next != 0 {
		t.Fatalf("last page = %d next %d", len(page), next)
	}

	count := func(f AuditFilter) int {
		got, _, err := s.SearchAudit(ctx, f, 0, 500)
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	cases := map[string]struct {
		f    AuditFilter
		want int
	}{
		"actor":         {AuditFilter{ActorID: "u1"}, 6},
		"action prefix": {AuditFilter{ActionPrefix: "thing."}, 12},
		"action exact":  {AuditFilter{ActionPrefix: "thing.1"}, 4},
		"no wildcard":   {AuditFilter{ActionPrefix: "%"}, 0},
		"target":        {AuditFilter{TargetType: "check", TargetID: "c3"}, 1},
		"result":        {AuditFilter{Result: audit.ResultFailure}, 2},
		"from":          {AuditFilter{FromMS: 1}, 12},
		"to":            {AuditFilter{ToMS: 1}, 0},
		"text":          {AuditFilter{Text: "entry-12"}, 1},
		"text miss":     {AuditFilter{Text: "absent"}, 0},
		"combined":      {AuditFilter{ActorID: "u0", Result: audit.ResultFailure}, 1},
	}
	for name, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: got %d, want %d", name, got, c.want)
		}
	}
}

func TestStreamAuditOrderAndStop(t *testing.T) {
	s := openStore(t)
	seedAudit(t, s, 5)
	var ids []int64
	if err := s.StreamAudit(context.Background(), AuditFilter{}, func(e audit.Entry) error { ids = append(ids, e.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ids) != "[1 2 3 4 5]" {
		t.Errorf("ids = %v", ids)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

type fakeSource struct{}

func (fakeSource) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{
		AgentVersions: map[string]int{"0.1.0": 3, "0.1.2-alpha.1": 2, "weird": 1},
		Checks:        30, NotifierTypes: []string{"slack", "smtp"},
		Features: map[string]bool{"sso": false, "status_pages": true, "k8s_actions": false},
	}, nil
}

func newSvc(t *testing.T, mod func(*Options)) *Service {
	t.Helper()
	db, err := store.Open(context.Background(), t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	o := Options{DB: db, Source: fakeSource{}, Info: Info{Version: "0.1.0"}, Backoff: time.Millisecond}
	if mod != nil {
		mod(&o)
	}
	return New(o)
}

var ev = audit.Event{ActorType: "user", ActorID: "u", Action: "settings.update", TargetType: "setting", TargetID: "telemetry.enabled", Result: audit.ResultSuccess}

// TEL-3: the payload type is exactly schema v1.
func TestPayloadMatchesSchemaV1(t *testing.T) {
	f, err := os.Open("testdata/schema_v1.golden")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var want []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want = append(want, sc.Text())
	}
	typ := reflect.TypeOf(Payload{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		got = append(got, strings.Split(f.Tag.Get("json"), ",")[0]+" "+f.Type.String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload drifted from schema v1:\n got %v\nwant %v", got, want)
	}
}

// TEL-3: a fully populated payload marshals to exactly the schema keys.
func TestPopulatedPayloadHasNoUnknownKeys(t *testing.T) {
	s := newSvc(t, nil)
	raw, err := s.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	golden, _ := os.ReadFile("testdata/schema_v1.golden")
	allowed := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(golden)), "\n") {
		allowed[strings.Fields(l)[0]] = true
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("unknown key %q", k)
		}
	}
	if len(m) != len(allowed) {
		t.Errorf("keys = %d, want %d", len(m), len(allowed))
	}
}

func TestTEL1_BuilderBucketsAndNeverCarriesMessages(t *testing.T) {
	s := newSvc(t, nil)
	s.o.Errors.Record(errcode.AuthDeny004)
	s.o.Errors.Record("free text with a hostname.example.com")
	p, err := s.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.AgentsBucket != "6-20" || p.ChecksBucket != "21-100" || p.ClustersBucket != "0" {
		t.Errorf("buckets = %s %s %s", p.AgentsBucket, p.ChecksBucket, p.ClustersBucket)
	}
	if !reflect.DeepEqual(p.AgentVersions, map[string]int{"0.1": 5, "unknown": 1}) {
		t.Errorf("agent versions = %v", p.AgentVersions)
	}
	if !reflect.DeepEqual(p.ErrorCodes24h, map[string]int{"AUTH-DENY-004": 1}) {
		t.Errorf("codes = %v", p.ErrorCodes24h)
	}
	if p.ReleaseChannel != "stable" || p.ServerMemoryMBP95%10 != 0 || p.InstallID != previewInstallID {
		t.Errorf("payload = %+v", p)
	}
}

func TestErrorCounterKeepsTopTen(t *testing.T) {
	var c Counter
	for i := 0; i < 15; i++ {
		code := errcode.Code("AAA-BBB-0" + string(rune('0'+i/10)) + string(rune('0'+i%10)))
		for j := 0; j <= i; j++ {
			c.Record(code)
		}
	}
	if got := c.Top(); len(got) != 10 || got["AAA-BBB-014"] != 15 {
		t.Errorf("top = %v", got)
	}
}

func TestTEL2_OffByDefaultNeverSendsAndOffDeletesInstallID(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	s := newSvc(t, func(o *Options) { o.URL = srv.URL })
	ctx := context.Background()
	if err := s.Send(ctx); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Send while off = %v", err)
	}
	s.tick(ctx)
	if hits.Load() != 0 {
		t.Fatal("sent while disabled")
	}
	if err := s.SetEnabled(ctx, true, ev); err != nil {
		t.Fatal(err)
	}
	var id string
	_ = s.o.DB.DB().QueryRow(`SELECT install_id FROM telemetry_state`).Scan(&id)
	if len(id) != 36 || id[14] != '4' {
		t.Errorf("install id = %q", id)
	}
	if err := s.SetEnabled(ctx, false, ev); err != nil {
		t.Fatal(err)
	}
	_ = s.o.DB.DB().QueryRow(`SELECT install_id FROM telemetry_state`).Scan(&id)
	if id != "" {
		t.Errorf("install id survived disable: %q", id)
	}
}

func TestTEL2_SendsExactPreviewBytes(t *testing.T) {
	var got []byte
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(got)
		ct = r.Header.Get("Content-Type")
	}))
	defer srv.Close()
	s := newSvc(t, func(o *Options) { o.URL = srv.URL })
	ctx := context.Background()
	_ = s.SetEnabled(ctx, true, ev)
	want, _ := s.Preview(ctx)
	if err := s.Send(ctx); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) || ct != "application/json" {
		t.Errorf("sent %q (%s), previewed %q", got, ct, want)
	}
	var last *int64
	_ = s.o.DB.DB().QueryRow(`SELECT last_sent_at FROM telemetry_state`).Scan(&last)
	if last == nil {
		t.Error("last_sent_at not set")
	}
}

func TestTEL2_RetriesServerErrorsThenDropsWithCode(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	s := newSvc(t, func(o *Options) { o.URL = srv.URL })
	_ = s.SetEnabled(context.Background(), true, ev)
	err := s.Send(context.Background())
	if errcode.CodeOf(err) != errcode.TELSend002 || hits.Load() != maxAttempts {
		t.Errorf("err = %v after %d attempts", err, hits.Load())
	}
}

func TestTEL2_ClientErrorIsNotRetriedAndUnreachableHasCode(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	s := newSvc(t, func(o *Options) { o.URL = srv.URL })
	_ = s.SetEnabled(context.Background(), true, ev)
	if err := s.Send(context.Background()); errcode.CodeOf(err) != errcode.TELSend002 || hits.Load() != 1 {
		t.Errorf("4xx: err = %v, hits = %d", err, hits.Load())
	}
	srv.Close()
	err := s.Send(context.Background())
	if errcode.CodeOf(err) != errcode.TELSend001 || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("unreachable: %v", err)
	}
}

func TestTEL2_TickSendsOnceDueWithJitterAndLockedStaysOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	s := newSvc(t, func(o *Options) {
		o.URL, o.Jitter, o.Now = srv.URL, time.Minute, func() time.Time { return now }
	})
	ctx := context.Background()
	_ = s.SetEnabled(ctx, true, ev)
	s.tick(ctx) // schedules
	if hits.Load() != 0 {
		t.Fatal("sent before the jittered delay")
	}
	now = now.Add(2 * time.Minute)
	s.tick(ctx)
	s.tick(ctx)
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
	l := newSvc(t, func(o *Options) { o.Locked = true; o.URL = srv.URL })
	if err := l.SetEnabled(ctx, true, ev); !errors.Is(err, ErrLocked) {
		t.Errorf("locked enable = %v", err)
	}
}

func TestRestartsCountsEarlierStartsOnly(t *testing.T) {
	s := newSvc(t, nil)
	ctx := context.Background()
	for range 3 {
		if err := s.recordStart(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.restarts(ctx); n != 2 {
		t.Errorf("restarts = %d, want 2", n)
	}
}

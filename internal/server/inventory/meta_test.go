// SPDX-License-Identifier: AGPL-3.0-only

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
	"github.com/nuxdeck/nuxdeck/internal/server/pki"
)

var ev = audit.Event{ActorType: "user", ActorID: "01ADMIN", Action: "item.tags.update", Result: audit.ResultSuccess}

func TestINV3_TagsOwnerAndLabelsSurviveRestartsAndSnapshots(t *testing.T) {
	e := newEnv(t)
	tok, err := e.pki.CreateToken(context.Background(), pki.Actor{UserID: "01ADMIN"}, pki.TokenRequest{
		ServerURL: "https://nux.example.com:8444", Labels: map[string]string{"env": "production", "bad key": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	res, err := e.pki.Enroll(context.Background(), pki.EnrollRequest{Token: tok.Token, CSRDER: csr, Hostname: "h", OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	agent := res.AgentID
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("aaa111", "web", "running")))

	h, _ := e.svc.Index().HostByAgent(agent)
	if h.Tags["env"] != "production" || len(h.Tags) != 1 || h.ETag == "" {
		t.Fatalf("enrolment labels should become the valid host tags: %+v", h)
	}

	owner := "platform"
	c := e.svc.Index().Containers(inventory.ContainerFilter{}, "", 10).Items[0]
	if _, err := e.svc.UpdateMeta(inventory.ItemContainer, c.ID, c.ETag, inventory.MetaChange{Owner: &owner, Tags: map[string]string{"tier": "web"}}, ev); err != nil {
		t.Fatal(err)
	}
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1"), ctr("aaa111", "web", "running"))) // the agent knows nothing of tags

	again := e.newService()
	got, _ := again.Index().Container(c.ID)
	if got.Owner != "platform" || got.Tags["tier"] != "web" {
		t.Errorf("container after restart = %+v", got)
	}
	if hh, _ := again.Index().Host(h.ID); hh.Tags["env"] != "production" {
		t.Errorf("host after restart = %+v", hh)
	}
	if n, err := e.db.VerifyAuditChain(context.Background()); err != nil || n < 2 {
		t.Errorf("audit chain: %d entries, %v", n, err)
	}
}

func TestINV3_StaleETagIsRejected(t *testing.T) {
	e := newEnv(t)
	agent := e.agent()
	e.svc.HandleMessage(agent, snapshot(hostFacts("web-1")))
	h, _ := e.svc.Index().HostByAgent(agent)
	if _, err := e.svc.UpdateMeta(inventory.ItemHost, h.ID, h.ETag, inventory.MetaChange{Tags: map[string]string{"env": "a"}}, ev); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.UpdateMeta(inventory.ItemHost, h.ID, h.ETag, inventory.MetaChange{Tags: map[string]string{"env": "b"}}, ev)
	if !errors.Is(err, inventory.ErrStale) {
		t.Errorf("err = %v", err)
	}
	if _, err := e.svc.UpdateMeta(inventory.ItemHost, "nope", h.ETag, inventory.MetaChange{}, ev); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("unknown item: %v", err)
	}
}

func TestINV4_GroupingByEnvironmentTag(t *testing.T) {
	hosts := []inventory.Host{
		{ID: "1", Hostname: "a", Status: "online", Tags: map[string]string{"env": "production", "team": "x"}},
		{ID: "2", Hostname: "b", Status: "online", Tags: map[string]string{"env": "staging"}},
		{ID: "3", Hostname: "c", Status: "online"},
	}
	ix := inventory.NewIndex(hosts, nil)
	names := func(sel ...inventory.TagSelector) []string {
		var out []string
		for _, h := range ix.Hosts(inventory.HostFilter{Tags: sel}, "", 10).Items {
			out = append(out, h.Hostname)
		}
		slices.Sort(out)
		return out
	}
	if got := names(inventory.TagSelector{Key: "env", Value: "production"}); !slices.Equal(got, []string{"a"}) {
		t.Errorf("production = %v", got)
	}
	if got := names(inventory.TagSelector{Key: "env"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("any env = %v", got)
	}
	if got := names(); len(got) != 3 {
		t.Errorf("no filter = %v", got)
	}
}

func TestINV5_SearchRanksExactThenPrefixThenSubstring(t *testing.T) {
	gone := time.Now()
	hosts := []inventory.Host{
		{ID: "h1", Hostname: "my-web", Status: "online"},
		{ID: "h2", Hostname: "web", Status: "online", Facts: map[string]string{"ips": "10.0.0.7,192.168.1.9"}},
		{ID: "h3", Hostname: "webserver", Status: "online", Tags: map[string]string{"env": "production"}},
		{ID: "h4", Hostname: "retired", Status: "gone", Tags: map[string]string{"x": "web"}},
	}
	containers := []inventory.Container{
		{ID: "c1", HostID: "h2", Name: "Web", State: "running"},
		{ID: "c2", HostID: "h2", Name: "db", State: "running", Tags: map[string]string{"role": "webdb"}},
		{ID: "c3", HostID: "h2", Name: "web-old", State: "exited", GoneAt: &gone},
	}
	ix := inventory.NewIndex(hosts, containers)
	ids := func(q string, limit int) []string {
		var out []string
		for _, h := range ix.Search(q, limit) {
			out = append(out, h.ID)
		}
		return out
	}

	// Exact (c1 "Web", h2 "web", alphabetical by name with case kept: "Web" < "web"), then prefix, then
	// the tag prefix match (webdb), then the name substring (my-web); gone items never appear.
	if got, want := ids("web", 20), []string{"c1", "h2", "h3", "c2", "h1"}; !slices.Equal(got, want) {
		t.Errorf("web = %v, want %v", got, want)
	}
	if got := ids("web", 2); len(got) != 2 {
		t.Errorf("limit not applied: %v", got)
	}
	if got := ids("192.168", 20); !slices.Equal(got, []string{"h2"}) {
		t.Errorf("ip = %v", got)
	}
	if got := ids("ENV:prod", 20); !slices.Equal(got, []string{"h3"}) {
		t.Errorf("tag = %v", got)
	}
	if hit := ix.Search("web", 1)[0]; hit.Type != inventory.ItemContainer || hit.Host != "web" || hit.Match != inventory.FieldName {
		t.Errorf("hit = %+v", hit)
	}
	for _, q := range []string{"", "   ", string(make([]byte, 65))} {
		if got := ix.Search(q, 10); len(got) != 0 {
			t.Errorf("query %q matched %v", q, got)
		}
	}
}

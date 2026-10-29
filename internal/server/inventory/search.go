// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Search limits (INV-5): the query is short by design and the result list is capped.
const (
	MaxSearchQuery   = 64
	DefaultSearchMax = 20
	MaxSearchResults = 50
)

// Match quality, best first.
const (
	matchExact = iota
	matchPrefix
	matchSubstring
)

// What matched, as shown to the user.
const (
	FieldName = "name"
	FieldTag  = "tag"
	FieldIP   = "ip"
)

// Hit is one search result.
type Hit struct {
	Type   string `json:"type"` // host or container
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // host status or container state
	Host   string `json:"host,omitempty"`
	Match  string `json:"match"`  // name, tag or ip
	Detail string `json:"detail"` // the text that matched, for display
	score  int
}

// Search finds hosts and containers whose name, tags or addresses match q, best matches first:
// exact, then prefix, then substring; ties go to name matches over tag matches over address
// matches, then alphabetical. Matching is case-insensitive and runs in memory.
func (ix *Index) Search(q string, limit int) []Hit { return ix.SearchAllowed(q, limit, nil, nil) }

// SearchAllowed is Search limited to the hosts and containers the callers' scope accepts (ACC-5);
// a nil predicate accepts everything. The predicates run under the index lock.
func (ix *Index) SearchAllowed(q string, limit int, allowHost func(Host) bool, allowContainer func(Container, Host) bool) []Hit {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" || len(q) > MaxSearchQuery {
		return []Hit{}
	}
	if limit < 1 || limit > MaxSearchResults {
		limit = DefaultSearchMax
	}
	ix.mu.RLock()
	var hits []Hit
	hostName := make(map[string]string, len(ix.hosts))
	for id, h := range ix.hosts {
		hostName[id] = h.Hostname
		if h.Status == StatusGone || (allowHost != nil && !allowHost(h)) {
			continue
		}
		cands := []cand{{FieldName, h.Hostname}}
		cands = append(cands, tagCands(h.Tags)...)
		cands = append(cands, ipCands(h.Facts["ips"])...)
		if hit, ok := best(q, cands); ok {
			hit.Type, hit.ID, hit.Name, hit.Status = ItemHost, h.ID, h.Hostname, h.Status
			hits = append(hits, hit)
		}
	}
	for _, c := range ix.containers {
		if c.GoneAt != nil || (allowContainer != nil && !allowContainer(c, ix.hosts[c.HostID])) {
			continue
		}
		cands := []cand{{FieldName, c.Name}}
		cands = append(cands, tagCands(c.Tags)...)
		for _, p := range c.Ports {
			if p.HostIP != "" && p.HostIP != "0.0.0.0" && p.HostIP != "::" {
				cands = append(cands, cand{FieldIP, p.HostIP}, cand{FieldIP, p.HostIP + ":" + strconv.Itoa(p.HostPort)})
			}
		}
		if hit, ok := best(q, cands); ok {
			hit.Type, hit.ID, hit.Name, hit.Status, hit.Host = ItemContainer, c.ID, c.Name, c.State, hostName[c.HostID]
			hits = append(hits, hit)
		}
	}
	ix.mu.RUnlock()

	slices.SortFunc(hits, func(a, b Hit) int {
		return cmp.Or(cmp.Compare(a.score, b.score), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	if hits == nil {
		hits = []Hit{}
	}
	return hits
}

type cand struct{ field, text string }

func tagCands(tags map[string]string) []cand {
	out := make([]cand, 0, len(tags)*2)
	for k, v := range tags {
		out = append(out, cand{FieldTag, k + ":" + v}, cand{FieldTag, v})
	}
	return out
}

func ipCands(list string) []cand {
	var out []cand
	for _, ip := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		out = append(out, cand{FieldIP, ip})
	}
	return out
}

// best picks the strongest match among the candidates; the field order name < tag < ip breaks quality ties.
func best(q string, cands []cand) (Hit, bool) {
	var out Hit
	found := false
	for _, c := range cands {
		t := strings.ToLower(c.text)
		var quality int
		switch {
		case t == q:
			quality = matchExact
		case strings.HasPrefix(t, q):
			quality = matchPrefix
		case strings.Contains(t, q):
			quality = matchSubstring
		default:
			continue
		}
		score := quality*10 + fieldRank(c.field)
		if !found || score < out.score {
			out, found = Hit{Match: c.field, Detail: c.text, score: score}, true
		}
	}
	return out, found
}

func fieldRank(f string) int {
	switch f {
	case FieldName:
		return 0
	case FieldTag:
		return 1
	}
	return 2
}

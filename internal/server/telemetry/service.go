// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
)

// DefaultURL is the only endpoint a report goes to. Options.URL exists for tests.
const DefaultURL = "https://telemetry.nuxdeck.com/v1/report"

// previewInstallID stands in until the admin opts in; the real ID is generated at that moment.
const previewInstallID = "00000000-0000-4000-8000-000000000000"

const (
	reportEvery   = 24 * time.Hour
	sampleEvery   = 5 * time.Minute
	maxSamples    = int(reportEvery / sampleEvery)
	startsKey     = "telemetry.starts"
	maxAttempts   = 3
	sendTimeout   = 10 * time.Second
	defaultBackof = 2 * time.Second
)

// ErrDisabled is returned by Send while telemetry is off.
var ErrDisabled = errors.New("telemetry is disabled")

// ErrLocked is returned when NUX_TELEMETRY=off forbids enabling.
var ErrLocked = errors.New("telemetry is switched off by the environment")

// Info holds the static facts about this installation.
type Info struct {
	Version        string
	InstallMethod  string // binary, docker or helm
	StorageBackend string // embedded or clickhouse
}

// Options are the service's dependencies.
type Options struct {
	DB     *store.Store
	Source Source
	Info   Info
	Log    *slog.Logger
	Errors *Counter
	// Locked is true when NUX_TELEMETRY=off: nothing is ever sent and it cannot be enabled.
	Locked bool
	// URL, Client, Now, Poll, Jitter and Backoff are test seams; zero values use production settings.
	URL     string
	Client  *http.Client
	Now     func() time.Time
	Poll    time.Duration
	Jitter  time.Duration
	Backoff time.Duration
}

// Service owns the telemetry state, the payload builder and the daily sender.
type Service struct {
	o       Options
	started time.Time

	mu      sync.Mutex
	samples []int // resident-size samples in MB, newest last
	due     time.Time
}

// New builds a Service.
func New(o Options) *Service {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Errors == nil {
		o.Errors = &Counter{}
	}
	if o.URL == "" {
		o.URL = DefaultURL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Poll <= 0 {
		o.Poll = 15 * time.Minute
	}
	if o.Jitter <= 0 {
		o.Jitter = time.Hour
	}
	if o.Backoff <= 0 {
		o.Backoff = defaultBackof
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: sendTimeout,
			// A report goes to one fixed host; following a redirect would send it somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Service{o: o, started: o.Now()}
}

// Locked reports whether the environment forces telemetry off.
func (s *Service) Locked() bool { return s.o.Locked }

// Enabled reports whether reports are sent.
func (s *Service) Enabled(ctx context.Context) (bool, error) {
	if s.o.Locked {
		return false, nil
	}
	var on int
	if err := s.o.DB.DB().QueryRowContext(ctx, `SELECT enabled FROM telemetry_state WHERE id = 1`).Scan(&on); err != nil {
		return false, fmt.Errorf("read telemetry state: %w", err)
	}
	return on == 1, nil
}

// SetEnabled turns telemetry on or off and records ev in the same transaction. Turning it on
// generates the install ID; turning it off deletes it.
func (s *Service) SetEnabled(ctx context.Context, enabled bool, ev audit.Event) error {
	if enabled && s.o.Locked {
		return ErrLocked
	}
	return s.o.DB.InTx(ctx, func(tx *sql.Tx) error {
		if enabled {
			id, err := newUUID()
			if err != nil {
				return err
			}
			// Keep an existing ID so toggling the UI twice does not double-count an install.
			if _, err := tx.ExecContext(ctx, `UPDATE telemetry_state SET enabled = 1, install_id = CASE WHEN install_id = '' THEN ? ELSE install_id END WHERE id = 1`, id); err != nil {
				return fmt.Errorf("enable telemetry: %w", err)
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE telemetry_state SET enabled = 0, install_id = '', last_sent_at = NULL WHERE id = 1`); err != nil {
			return fmt.Errorf("disable telemetry: %w", err)
		}
		return s.o.DB.AppendAudit(ctx, tx, ev)
	})
}

// Build assembles the report for today. Preview and Send both go through it.
func (s *Service) Build(ctx context.Context) (Payload, error) {
	var id string
	if err := s.o.DB.DB().QueryRowContext(ctx, `SELECT install_id FROM telemetry_state WHERE id = 1`).Scan(&id); err != nil {
		return Payload{}, fmt.Errorf("read install id: %w", err)
	}
	if id == "" {
		id = previewInstallID
	}
	snap, err := s.o.Source.Snapshot(ctx)
	if err != nil {
		return Payload{}, fmt.Errorf("collect snapshot: %w", err)
	}
	now := s.o.Now().UTC()
	versions := map[string]int{}
	agents := 0
	for v, n := range snap.AgentVersions {
		versions[minorVersion(v)] += n
		agents += n
	}
	notifiers := append([]string{}, snap.NotifierTypes...)
	sort.Strings(notifiers)
	features := map[string]bool{}
	for k, v := range snap.Features {
		features[k] = v
	}
	restarts, err := s.restarts(ctx)
	if err != nil {
		return Payload{}, err
	}
	return Payload{
		SchemaVersion:     SchemaVersion,
		InstallID:         id,
		ReportDate:        now.Format(time.DateOnly),
		NuxdVersion:       s.o.Info.Version,
		ReleaseChannel:    channel(s.o.Info.Version),
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		DistroFamily:      distroFamily(),
		InstallMethod:     orDefault(s.o.Info.InstallMethod, "binary"),
		StorageBackend:    orDefault(s.o.Info.StorageBackend, "embedded"),
		AgentsBucket:      Bucket(agents),
		ClustersBucket:    Bucket(snap.Clusters),
		ChecksBucket:      Bucket(snap.Checks),
		AgentVersions:     versions,
		Features:          features,
		NotifierTypes:     notifiers,
		ServerMemoryMBP95: roundTo10(s.memoryP95()),
		ServerUptime:      uptimeBucket(now.Sub(s.started)),
		Restarts24h:       restarts,
		ErrorCodes24h:     s.o.Errors.Top(),
	}, nil
}

// Preview returns the exact bytes the next report would carry.
func (s *Service) Preview(ctx context.Context) ([]byte, error) {
	p, err := s.Build(ctx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

// Send delivers one report. A failure is dropped, never queued, and carries a TEL-SEND code.
func (s *Service) Send(ctx context.Context) error {
	on, err := s.Enabled(ctx)
	if err != nil {
		return err
	}
	if !on {
		return ErrDisabled
	}
	body, err := s.Preview(ctx)
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoff(s.o.Backoff, attempt)); err != nil {
				return errcode.Wrap(errcode.TELSend001, "send cancelled", err)
			}
		}
		retry, err := s.post(ctx, body)
		if err == nil {
			s.o.Errors.Reset()
			_, uerr := s.o.DB.DB().ExecContext(ctx, `UPDATE telemetry_state SET last_sent_at = ? WHERE id = 1 AND enabled = 1`, s.o.Now().Unix())
			return uerr
		}
		last = err
		if !retry {
			break
		}
	}
	return last
}

func (s *Service) post(ctx context.Context, body []byte) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.o.URL, bytes.NewReader(body))
	if err != nil {
		return false, errcode.New(errcode.TELSend001, "build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nuxd/"+s.o.Info.Version)
	resp, err := s.o.Client.Do(req)
	if err != nil {
		// err can embed the URL; the code alone is enough for the log.
		return true, errcode.New(errcode.TELSend001, "request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode/100 == 2 {
		return false, nil
	}
	return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests,
		errcode.New(errcode.TELSend002, "endpoint answered %d", resp.StatusCode)
}

// Run samples memory, records this start and sends the daily report until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if err := s.recordStart(ctx); err != nil {
		s.o.Log.Warn("record telemetry start", "error", err)
	}
	s.sample()
	poll := time.NewTicker(s.o.Poll)
	defer poll.Stop()
	sampler := time.NewTicker(sampleEvery)
	defer sampler.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sampler.C:
			s.sample()
		case <-poll.C:
			s.tick(ctx)
		}
	}
}

// tick sends when a report is due. The schedule lives in memory: after a restart the next report
// is a fresh jittered delay away, which keeps installs from reporting in lockstep.
func (s *Service) tick(ctx context.Context) {
	on, err := s.Enabled(ctx)
	if err != nil || !on {
		s.mu.Lock()
		s.due = time.Time{}
		s.mu.Unlock()
		return
	}
	now := s.o.Now()
	s.mu.Lock()
	if s.due.IsZero() {
		s.due = now.Add(s.jitter())
	}
	due := s.due
	s.mu.Unlock()
	if now.Before(due) {
		return
	}
	err = s.Send(ctx)
	s.mu.Lock()
	s.due = now.Add(reportEvery).Add(s.jitter())
	s.mu.Unlock()
	if err != nil && !errors.Is(err, ErrDisabled) {
		s.o.Log.Warn("telemetry report dropped", "code", string(errcode.CodeOf(err)))
	}
}

func (s *Service) jitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(s.o.Jitter)))
	if err != nil {
		return s.o.Jitter
	}
	return time.Duration(n.Int64())
}

func (s *Service) sample() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mb := int(m.Sys >> 20)
	s.mu.Lock()
	s.samples = append(s.samples, mb)
	if len(s.samples) > maxSamples {
		s.samples = s.samples[len(s.samples)-maxSamples:]
	}
	s.mu.Unlock()
}

func (s *Service) memoryP95() int {
	s.mu.Lock()
	cp := append([]int(nil), s.samples...)
	s.mu.Unlock()
	if len(cp) == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int(m.Sys >> 20)
	}
	sort.Ints(cp)
	return cp[int(math.Ceil(0.95*float64(len(cp))))-1]
}

// recordStart appends this process start to a local, pruned list used for restarts_24h.
func (s *Service) recordStart(ctx context.Context) error {
	starts, err := s.loadStarts(ctx)
	if err != nil {
		return err
	}
	now := s.o.Now().Unix()
	starts = append(prune(starts, now), now)
	raw, _ := json.Marshal(starts)
	_, err = s.o.DB.DB().ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_by, updated_at) VALUES (?, ?, NULL, ?)
		ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`, startsKey, string(raw), now)
	return err
}

func (s *Service) loadStarts(ctx context.Context) ([]int64, error) {
	var raw string
	err := s.o.DB.DB().QueryRowContext(ctx, `SELECT value_json FROM settings WHERE key = ?`, startsKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read starts: %w", err)
	}
	var out []int64
	_ = json.Unmarshal([]byte(raw), &out) // a damaged list only costs this day's restart count
	return out, nil
}

// restarts counts starts in the last 24 hours, excluding the current process's own.
func (s *Service) restarts(ctx context.Context) (int, error) {
	starts, err := s.loadStarts(ctx)
	if err != nil {
		return 0, err
	}
	n := len(prune(starts, s.o.Now().Unix()))
	if n > 0 && s.started.After(s.o.Now().Add(-reportEvery)) {
		n--
	}
	return n, nil
}

func prune(starts []int64, now int64) []int64 {
	cut := now - int64(reportEvery/time.Second)
	out := starts[:0:0]
	for _, t := range starts {
		if t > cut {
			out = append(out, t)
		}
	}
	if len(out) > 100 {
		out = out[len(out)-100:]
	}
	return out
}

func backoff(base time.Duration, attempt int) time.Duration {
	d := base << (attempt - 1)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/2)+1))
	if err != nil {
		return d
	}
	return d + time.Duration(n.Int64())
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate install id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func channel(version string) string {
	switch {
	case version == "" || version == "dev" || strings.Contains(version, "dev"):
		return "dev"
	case strings.Contains(version, "-"):
		return "beta"
	default:
		return "stable"
	}
}

func distroFamily() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "other"
	}
	var ids []string
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && (k == "ID" || k == "ID_LIKE") {
			ids = append(ids, strings.Fields(strings.Trim(v, `"'`))...)
		}
	}
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos":
			return "rhel"
		case "alpine":
			return "alpine"
		case "suse", "opensuse", "sles":
			return "suse"
		case "arch":
			return "arch"
		}
	}
	return "other"
}

func uptimeBucket(d time.Duration) string {
	switch {
	case d < 24*time.Hour:
		return "under 1d"
	case d < 7*24*time.Hour:
		return "1-7d"
	case d < 30*24*time.Hour:
		return "7-30d"
	default:
		return "over 30d"
	}
}

func roundTo10(n int) int { return (n + 5) / 10 * 10 }

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// SPDX-License-Identifier: AGPL-3.0-only

package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/alerting/notify"
	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

// TestGap is the least time between test messages to one channel.
const TestGap = 10 * time.Second

// ErrDisabled is returned when sending through a disabled channel.
var ErrDisabled = errors.New("channel is disabled")

// Channel is a notification channel as the API reads and writes it. Credentials inside Config
// are write-only: a string sets one, and it reads back as {"set":true}.
type Channel struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Enabled       bool            `json:"enabled"`
	AllowPrivate  bool            `json:"allow_private"`
	Config        json.RawMessage `json:"config"`
	LastStatus    string          `json:"last_status"`
	LastErrorCode string          `json:"last_error_code"`
	LastSentAt    *time.Time      `json:"last_sent_at"`
	CreatedBy     string          `json:"created_by"`
	UpdatedBy     string          `json:"updated_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Rev           int64           `json:"-"`
}

// ETag identifies the stored version of a channel.
func (c Channel) ETag() string { return `"n` + itoa(c.Rev) + `"` }

// ChannelOptions are the channel service's dependencies.
type ChannelOptions struct {
	DB      *store.Store
	Secrets *secrets.Box
	Sender  *notify.Sender
	Log     *slog.Logger
	Now     func() time.Time
}

// Channels stores notification channels and delivers through them.
type Channels struct {
	ChannelOptions
	mu       sync.Mutex
	lastTest map[string]time.Time
}

// NewChannels builds the channel service.
func NewChannels(o ChannelOptions) *Channels {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Channels{ChannelOptions: o, lastTest: map[string]time.Time{}}
}

const channelColumns = `id, type, name, config_json, secret_refs_json, enabled, allow_private, rev, last_status, last_error_code, last_sent_at, created_by, updated_by, created_at, updated_at`

func scanChannel(r scanner) (Channel, map[string]string, error) {
	var (
		c                Channel
		cfg, refs        string
		enabled, private int
		sent             sql.NullInt64
		created, updated int64
	)
	if err := r.Scan(&c.ID, &c.Type, &c.Name, &cfg, &refs, &enabled, &private, &c.Rev, &c.LastStatus, &c.LastErrorCode, &sent, &c.CreatedBy, &c.UpdatedBy, &created, &updated); err != nil {
		return Channel{}, nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(refs), &m); err != nil {
		return Channel{}, nil, fmt.Errorf("decode secret references: %w", err)
	}
	c.Config, c.Enabled, c.AllowPrivate, c.LastSentAt = json.RawMessage(cfg), enabled == 1, private == 1, fromNullMS(sent)
	c.CreatedAt, c.UpdatedAt = fromMS(created), fromMS(updated)
	return c, m, nil
}

func asValidation(err error) error {
	var fe *notify.FieldError
	if errors.As(err, &fe) {
		return &ValidationError{Field: fe.Field, Msg: fe.Msg}
	}
	return err
}

func validChannelName(n string) (string, error) {
	n = clean(n)
	if n == "" || len([]rune(n)) > MaxNameLength {
		return n, bad("name", "Use 1 to 100 characters.")
	}
	return n, nil
}

// applySecrets stores, replaces, keeps or removes the credentials of cfg inside tx and returns
// the new reference map. Plaintext is dropped from cfg afterwards.
func (c *Channels) applySecrets(ctx context.Context, tx *sql.Tx, cfg notify.Config, old map[string]string) (map[string]string, error) {
	refs := map[string]string{}
	for _, sl := range cfg.Slots() {
		prev, had := old[sl.Key]
		switch {
		case sl.Secret.Plain == nil: // keep
			if had {
				refs[sl.Key], sl.Secret.IsSet = prev, true
			}
		case *sl.Secret.Plain == "": // clear
			sl.Secret.IsSet = false
		case had:
			if err := c.Secrets.Replace(ctx, tx, prev, []byte(*sl.Secret.Plain)); err != nil {
				return nil, fmt.Errorf("replace secret: %w", err)
			}
			refs[sl.Key], sl.Secret.IsSet = prev, true
		default:
			id, err := c.Secrets.Put(ctx, tx, []byte(*sl.Secret.Plain))
			if err != nil {
				return nil, fmt.Errorf("store secret: %w", err)
			}
			refs[sl.Key], sl.Secret.IsSet = id, true
		}
		sl.Secret.Plain = nil
		if sl.Required && !sl.Secret.IsSet {
			return nil, bad("config."+strings.TrimPrefix(sl.Key, "header:"), "A value is required.")
		}
	}
	for key, id := range old {
		if _, kept := refs[key]; kept {
			continue
		}
		if err := c.Secrets.Delete(ctx, tx, id); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return nil, fmt.Errorf("delete secret: %w", err)
		}
	}
	return refs, nil
}

func channelDetails(ch Channel) map[string]any {
	return map[string]any{"name": ch.Name, "type": ch.Type, "enabled": ch.Enabled, "allow_private": ch.AllowPrivate}
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// Create stores a channel; credentials go to the encrypted store.
func (c *Channels) Create(ctx context.Context, in Channel, who Actor) (Channel, error) {
	name, err := validChannelName(in.Name)
	if err != nil {
		return Channel{}, err
	}
	cfg, err := notify.Decode(in.Type, in.Config)
	if err != nil {
		return Channel{}, asValidation(err)
	}
	if err := cfg.Validate(); err != nil {
		return Channel{}, asValidation(err)
	}
	id, err := ids.New()
	if err != nil {
		return Channel{}, err
	}
	now := c.Now().UTC()
	out := Channel{
		ID: id, Name: name, Type: in.Type, Enabled: in.Enabled, AllowPrivate: in.AllowPrivate, Rev: 1, LastStatus: "never",
		CreatedBy: who.UserID, UpdatedBy: who.UserID, CreatedAt: now, UpdatedAt: now,
	}
	err = c.DB.InTx(ctx, func(tx *sql.Tx) error {
		refs, err := c.applySecrets(ctx, tx, cfg, nil)
		if err != nil {
			return err
		}
		rendered, _ := json.Marshal(cfg)
		out.Config = rendered
		refJSON, _ := json.Marshal(refs)
		if _, err := tx.ExecContext(ctx, `INSERT INTO channels (id, type, name, config_json, secret_refs_json, enabled, allow_private, rev, last_status, last_error_code, last_sent_at, created_by, updated_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'never', '', NULL, ?, ?, ?, ?)`,
			id, out.Type, name, string(rendered), string(refJSON), b2i(out.Enabled), b2i(out.AllowPrivate), who.UserID, who.UserID, ms(now), ms(now)); err != nil {
			if isUnique(err) {
				return bad("name", "That name is already used.")
			}
			return fmt.Errorf("insert channel: %w", err)
		}
		return c.DB.AppendAudit(ctx, tx, who.event("channel.create", "channel", id, channelDetails(out)))
	})
	if err != nil {
		return Channel{}, err
	}
	return out, nil
}

// Update replaces a channel if ifMatch is its current ETag. Credentials omitted or sent as
// {"set":true} are kept.
func (c *Channels) Update(ctx context.Context, id, ifMatch string, in Channel, who Actor) (Channel, error) {
	name, err := validChannelName(in.Name)
	if err != nil {
		return Channel{}, err
	}
	var out Channel
	err = c.DB.InTx(ctx, func(tx *sql.Tx) error {
		old, oldRefs, err := scanChannel(tx.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM channels WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if old.ETag() != ifMatch {
			return ErrStale
		}
		if in.Type != old.Type {
			return bad("type", "The type of a channel cannot change; create a new channel.")
		}
		cfg, err := notify.Decode(old.Type, in.Config)
		if err != nil {
			return asValidation(err)
		}
		if err := cfg.Validate(); err != nil {
			return asValidation(err)
		}
		refs, err := c.applySecrets(ctx, tx, cfg, oldRefs)
		if err != nil {
			return err
		}
		out = old
		out.Name, out.Enabled, out.AllowPrivate, out.Rev, out.UpdatedBy, out.UpdatedAt = name, in.Enabled, in.AllowPrivate, old.Rev+1, who.UserID, c.Now().UTC()
		out.Config, _ = json.Marshal(cfg)
		refJSON, _ := json.Marshal(refs)
		if _, err := tx.ExecContext(ctx, `UPDATE channels SET name=?, config_json=?, secret_refs_json=?, enabled=?, allow_private=?, rev=?, updated_by=?, updated_at=? WHERE id=?`,
			name, string(out.Config), string(refJSON), b2i(out.Enabled), b2i(out.AllowPrivate), out.Rev, out.UpdatedBy, ms(out.UpdatedAt), id); err != nil {
			if isUnique(err) {
				return bad("name", "That name is already used.")
			}
			return fmt.Errorf("update channel: %w", err)
		}
		return c.DB.AppendAudit(ctx, tx, who.event("channel.update", "channel", id, channelDetails(out)))
	})
	if err != nil {
		return Channel{}, err
	}
	return out, nil
}

// Delete removes a channel, its credentials and the routes that point at it.
func (c *Channels) Delete(ctx context.Context, id string, who Actor) error {
	err := c.DB.InTx(ctx, func(tx *sql.Tx) error {
		ch, refs, err := scanChannel(tx.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM channels WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var routed int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM routes WHERE channel_id = ?`, id).Scan(&routed); err != nil {
			return err
		}
		for _, sid := range refs {
			if err := c.Secrets.Delete(ctx, tx, sid); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return fmt.Errorf("delete secret: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM channels WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete channel: %w", err)
		}
		if routed > 0 { // the route list changed, so its ETag must too
			if _, err := tx.ExecContext(ctx, `INSERT INTO alerting_state (key, value) VALUES ('routes_rev', '1')
				ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)`); err != nil {
				return fmt.Errorf("bump route version: %w", err)
			}
		}
		d := channelDetails(ch)
		d["routes_removed"] = routed
		return c.DB.AppendAudit(ctx, tx, who.event("channel.delete", "channel", id, d))
	})
	if err == nil {
		c.Sender.Forget(id)
		c.mu.Lock()
		delete(c.lastTest, id)
		c.mu.Unlock()
	}
	return err
}

// Get returns one channel.
func (c *Channels) Get(ctx context.Context, id string) (Channel, error) {
	ch, _, err := scanChannel(c.DB.DB().QueryRowContext(ctx, `SELECT `+channelColumns+` FROM channels WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return ch, err
}

// List returns channels ordered by ID after the cursor.
func (c *Channels) List(ctx context.Context, after string, limit int) (items []Channel, next string, err error) {
	rows, err := c.DB.DB().QueryContext(ctx, `SELECT `+channelColumns+` FROM channels WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("list channels: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		ch, _, err := scanChannel(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].ID
	}
	return items, next, nil
}

// load reads a channel with its credentials decrypted, for sending only.
func (c *Channels) load(ctx context.Context, id string) (Channel, notify.Config, error) {
	ch, refs, err := scanChannel(c.DB.DB().QueryRowContext(ctx, `SELECT `+channelColumns+` FROM channels WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, nil, ErrNotFound
	}
	if err != nil {
		return Channel{}, nil, err
	}
	cfg, err := notify.Decode(ch.Type, ch.Config)
	if err != nil {
		return Channel{}, nil, err
	}
	for _, sl := range cfg.Slots() {
		ref, ok := refs[sl.Key]
		if !ok {
			if sl.Required {
				return Channel{}, nil, errcode.New(errcode.ALRSend001, "channel credentials are missing")
			}
			continue
		}
		plain, err := c.Secrets.Get(ctx, c.DB.DB(), ref)
		if err != nil {
			return Channel{}, nil, errcode.New(errcode.ALRSend001, "channel credentials are unreadable")
		}
		s := string(plain)
		clear(plain)
		sl.Secret.Plain = &s
	}
	return ch, cfg, nil
}

func (c *Channels) record(ctx context.Context, id string, err error) {
	status, code := "ok", ""
	if err != nil {
		status, code = "failed", string(sendCode(err))
	}
	if _, e := c.DB.DB().ExecContext(ctx, `UPDATE channels SET last_status = ?, last_error_code = ?, last_sent_at = ? WHERE id = ?`, status, code, ms(c.Now().UTC()), id); e != nil && ctx.Err() == nil {
		c.Log.Error("record delivery result", "channel_id", id, "error", e)
	}
}

func sendCode(err error) errcode.Code {
	var se *notify.SendError
	if errors.As(err, &se) {
		return se.Code
	}
	if code := errcode.CodeOf(err); code != "" {
		return code
	}
	return errcode.ALRSend002
}

// Deliver sends m through channel id and records the outcome on the channel.
func (c *Channels) Deliver(ctx context.Context, id string, m notify.Message) error {
	ch, cfg, err := c.load(ctx, id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			c.record(ctx, id, err)
		}
		return err
	}
	if !ch.Enabled {
		return ErrDisabled
	}
	err = c.Sender.Send(ctx, id, cfg, ch.AllowPrivate, m, false)
	c.record(ctx, id, err)
	return err
}

// Test sends a clearly labelled test message through the channel, ignoring an open breaker. The
// attempt is audited with its outcome (never the destination). A delivery failure is returned as
// a *notify.SendError. Test messages to one channel are spaced TestGap apart.
func (c *Channels) Test(ctx context.Context, id, link string, who Actor) error {
	ch, cfg, err := c.load(ctx, id)
	if err != nil {
		return err
	}
	now := c.Now().UTC()
	c.mu.Lock()
	if last, ok := c.lastTest[id]; ok && now.Sub(last) < TestGap {
		c.mu.Unlock()
		return ErrRateLimited
	}
	c.lastTest[id] = now
	c.mu.Unlock()

	m := notify.Message{
		Kind: notify.KindTest, AlertID: "test", Severity: SeverityInfo, RuleID: "test", RuleName: "Test notification", RuleKind: "test",
		ItemType: "test", ItemID: "test", ItemName: ch.Name, Summary: "Test message from Nux Deck. No alert is firing.", Link: link, Since: now, At: now,
	}
	sendErr := c.Sender.Send(ctx, id, cfg, ch.AllowPrivate, m, true)
	c.record(ctx, id, sendErr)
	ev := who.event("channel.test", "channel", id, map[string]any{"name": ch.Name, "type": ch.Type})
	ev.Result = audit.ResultSuccess
	if sendErr != nil {
		ev.Result, ev.Details["error_code"] = audit.ResultFailure, string(sendCode(sendErr))
	}
	if err := c.DB.InTx(ctx, func(tx *sql.Tx) error { return c.DB.AppendAudit(ctx, tx, ev) }); err != nil {
		return err
	}
	return sendErr
}

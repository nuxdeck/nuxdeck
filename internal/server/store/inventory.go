// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/server/audit"
	"github.com/nuxdeck/nuxdeck/internal/server/ids"
	"github.com/nuxdeck/nuxdeck/internal/server/inventory"
)

var _ inventory.Repository = (*Store)(nil)

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func nullableTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func nullMS(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: ms(*t), Valid: true}
}

const hostColumns = `id, agent_id, hostname, os, distro, kernel, arch, cpu_count, memory_bytes, facts_json, owner, status, first_seen_at, last_seen_at, gone_at`

func scanHost(r rowScanner) (inventory.Host, error) {
	var h inventory.Host
	var facts string
	var first, last int64
	var gone sql.NullInt64
	if err := r.Scan(&h.ID, &h.AgentID, &h.Hostname, &h.OS, &h.Distro, &h.Kernel, &h.Arch, &h.CPUCount, &h.MemoryBytes, &facts, &h.Owner, &h.Status, &first, &last, &gone); err != nil {
		return h, err
	}
	h.Facts, h.Tags = map[string]string{}, map[string]string{}
	if err := json.Unmarshal([]byte(facts), &h.Facts); err != nil {
		return h, fmt.Errorf("decode facts of host %s: %w", h.ID, err)
	}
	h.FirstSeenAt, h.LastSeenAt, h.GoneAt = fromMS(first), fromMS(last), nullableTime(gone)
	return h, nil
}

const containerColumns = `id, host_id, runtime, runtime_id, name, image, state, ports_json, labels_json, restart_count, created_at, gone_at, owner`

func scanContainer(r rowScanner) (inventory.Container, error) {
	var c inventory.Container
	var ports, labels string
	var created, gone sql.NullInt64
	if err := r.Scan(&c.ID, &c.HostID, &c.Runtime, &c.RuntimeID, &c.Name, &c.Image, &c.State, &ports, &labels, &c.RestartCount, &created, &gone, &c.Owner); err != nil {
		return c, err
	}
	c.Ports, c.Labels, c.Tags = []inventory.Port{}, map[string]string{}, map[string]string{}
	if err := json.Unmarshal([]byte(ports), &c.Ports); err != nil {
		return c, fmt.Errorf("decode ports of container %s: %w", c.ID, err)
	}
	if err := json.Unmarshal([]byte(labels), &c.Labels); err != nil {
		return c, fmt.Errorf("decode labels of container %s: %w", c.ID, err)
	}
	c.CreatedAt, c.GoneAt = nullableTime(created), nullableTime(gone)
	return c, nil
}

// LoadInventory returns every stored host and container.
func (s *Store) LoadInventory() ([]inventory.Host, []inventory.Container, error) {
	ctx := context.Background()
	hrows, err := s.db.QueryContext(ctx, `SELECT `+hostColumns+` FROM hosts`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = hrows.Close() }()
	var hosts []inventory.Host
	for hrows.Next() {
		h, err := scanHost(hrows)
		if err != nil {
			return nil, nil, err
		}
		hosts = append(hosts, h)
	}
	if err := hrows.Err(); err != nil {
		return nil, nil, err
	}

	crows, err := s.db.QueryContext(ctx, `SELECT `+containerColumns+` FROM containers`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = crows.Close() }()
	var containers []inventory.Container
	for crows.Next() {
		c, err := scanContainer(crows)
		if err != nil {
			return nil, nil, err
		}
		containers = append(containers, c)
	}
	if err := crows.Err(); err != nil {
		return nil, nil, err
	}

	hostTags, err := loadTags(ctx, s.db, inventory.ItemHost, "")
	if err != nil {
		return nil, nil, err
	}
	for i := range hosts {
		if t := hostTags[hosts[i].ID]; t != nil {
			hosts[i].Tags = t
		}
	}
	containerTags, err := loadTags(ctx, s.db, inventory.ItemContainer, "")
	if err != nil {
		return nil, nil, err
	}
	for i := range containers {
		if t := containerTags[containers[i].ID]; t != nil {
			containers[i].Tags = t
		}
	}
	return hosts, containers, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// loadTags returns tags by item ID. A non-empty hostID limits containers to that host.
func loadTags(ctx context.Context, q queryer, itemType, hostID string) (map[string]map[string]string, error) {
	query, args := `SELECT item_id, key, value FROM item_tags WHERE item_type = ?`, []any{itemType}
	if hostID != "" {
		query = `SELECT t.item_id, t.key, t.value FROM item_tags t JOIN containers c ON c.id = t.item_id WHERE t.item_type = ? AND c.host_id = ?`
		args = append(args, hostID)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load %s tags: %w", itemType, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]string{}
	for rows.Next() {
		var id, k, v string
		if err := rows.Scan(&id, &k, &v); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]string{}
		}
		out[id][k] = v
	}
	return out, rows.Err()
}

// copyLabelsToTags makes the enrolment-token labels of the host's agent its first tags (docs/08, enrollment_tokens).
func copyLabelsToTags(ctx context.Context, tx *sql.Tx, hostID, agentID string) (map[string]string, error) {
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT labels_json FROM agents WHERE id = ?`, agentID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("read agent labels: %w", err)
	}
	labels := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &labels); err != nil {
		return nil, fmt.Errorf("decode agent labels: %w", err)
	}
	tags := map[string]string{}
	for k, v := range labels {
		// Labels were validated only for length at token creation; tags have a stricter allowlist.
		if len(tags) >= inventory.MaxTags || !inventory.ValidTag(k, v) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO item_tags (item_type, item_id, key, value) VALUES ('host', ?, ?, ?)`, hostID, k, v); err != nil {
			return nil, fmt.Errorf("insert host tag: %w", err)
		}
		tags[k] = v
	}
	return tags, nil
}

// UpdateMeta implements inventory.Repository.
func (s *Store) UpdateMeta(itemType, itemID, ifMatch string, change inventory.MetaChange, ev audit.Event) (owner string, tags map[string]string, err error) {
	ctx := context.Background()
	var table string
	switch itemType {
	case inventory.ItemHost:
		table = "hosts"
	case inventory.ItemContainer:
		table = "containers"
	default:
		return "", nil, inventory.ErrNotFound
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		// table is one of the two constants above, never input.
		switch err := tx.QueryRowContext(ctx, `SELECT owner FROM `+table+` WHERE id = ?`, itemID).Scan(&owner); { //nolint:gosec // constant table name
		case errors.Is(err, sql.ErrNoRows):
			return inventory.ErrNotFound
		case err != nil:
			return fmt.Errorf("read owner: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT key, value FROM item_tags WHERE item_type = ? AND item_id = ?`, itemType, itemID)
		if err != nil {
			return fmt.Errorf("read tags: %w", err)
		}
		tags = map[string]string{}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				_ = rows.Close()
				return err
			}
			tags[k] = v
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()

		if inventory.MetaETag(owner, tags) != ifMatch {
			return inventory.ErrStale
		}
		if change.Owner != nil {
			owner = *change.Owner
			if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET owner = ? WHERE id = ?`, owner, itemID); err != nil { //nolint:gosec // constant table name
				return fmt.Errorf("update owner: %w", err)
			}
		}
		if change.Tags != nil {
			tags = change.Tags
			if _, err := tx.ExecContext(ctx, `DELETE FROM item_tags WHERE item_type = ? AND item_id = ?`, itemType, itemID); err != nil {
				return fmt.Errorf("clear tags: %w", err)
			}
			for k, v := range tags {
				if _, err := tx.ExecContext(ctx, `INSERT INTO item_tags (item_type, item_id, key, value) VALUES (?, ?, ?, ?)`, itemType, itemID, k, v); err != nil {
					return fmt.Errorf("insert tag: %w", err)
				}
			}
		}
		return s.appendAudit(ctx, tx, ev)
	})
	if err != nil {
		return "", nil, err
	}
	return owner, tags, nil
}

// UpsertHost creates or updates the host of an agent and links the agent to it.
func (s *Store) UpsertHost(h inventory.Host) (stored inventory.Host, created bool, err error) {
	ctx := context.Background()
	facts, err := json.Marshal(h.Facts)
	if err != nil {
		return h, false, err
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var existing string
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE agent_id = ?`, h.AgentID).Scan(&existing); {
		case errors.Is(err, sql.ErrNoRows):
			id, err := ids.New()
			if err != nil {
				return err
			}
			h.ID, h.FirstSeenAt, created = id, h.LastSeenAt, true
			if _, err := tx.ExecContext(ctx, `INSERT INTO hosts (`+hostColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
				h.ID, h.AgentID, h.Hostname, h.OS, h.Distro, h.Kernel, h.Arch, h.CPUCount, h.MemoryBytes, string(facts), h.Owner, h.Status, ms(h.FirstSeenAt), ms(h.LastSeenAt)); err != nil {
				return fmt.Errorf("insert host: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE agents SET host_id = ? WHERE id = ?`, h.ID, h.AgentID); err != nil {
				return fmt.Errorf("link agent to host: %w", err)
			}
			if h.Tags, err = copyLabelsToTags(ctx, tx, h.ID, h.AgentID); err != nil {
				return err
			}
		case err != nil:
			return fmt.Errorf("find host: %w", err)
		default:
			h.ID = existing
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET hostname=?, os=?, distro=?, kernel=?, arch=?, cpu_count=?, memory_bytes=?, facts_json=?, status=?, last_seen_at=?, gone_at=NULL WHERE id=?`,
				h.Hostname, h.OS, h.Distro, h.Kernel, h.Arch, h.CPUCount, h.MemoryBytes, string(facts), h.Status, ms(h.LastSeenAt), h.ID); err != nil {
				return fmt.Errorf("update host: %w", err)
			}
		}
		return nil
	})
	h.GoneAt = nil
	return h, created, err
}

// SetHostStatus changes a host's status.
func (s *Store) SetHostStatus(hostID, status string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(context.Background(), `UPDATE hosts SET status = ?, last_seen_at = ? WHERE id = ? AND status <> ?`, status, ms(at), hostID, status)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReplaceContainers makes list the host's live containers; the rest are marked gone.
func (s *Store) ReplaceContainers(hostID string, list []inventory.Container, at time.Time) ([]inventory.ContainerChange, error) {
	ctx := context.Background()
	var changes []inventory.ContainerChange
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := containersOf(ctx, tx, hostID)
		if err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, c := range list {
			keep[c.RuntimeID] = true
			ch, err := upsertContainer(ctx, tx, existing[c.RuntimeID], c)
			if err != nil {
				return err
			}
			if ch != nil {
				changes = append(changes, *ch)
			}
		}
		for rid, old := range existing {
			if keep[rid] || old.GoneAt != nil {
				continue
			}
			ch, err := markGone(ctx, tx, old, at)
			if err != nil {
				return err
			}
			changes = append(changes, *ch)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

// ApplyContainer upserts one container.
func (s *Store) ApplyContainer(c inventory.Container) (*inventory.ContainerChange, error) {
	ctx := context.Background()
	var ch *inventory.ContainerChange
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := containersOf(ctx, tx, c.HostID)
		if err != nil {
			return err
		}
		ch, err = upsertContainer(ctx, tx, existing[c.RuntimeID], c)
		return err
	})
	return ch, err
}

// RemoveContainer marks a container gone.
func (s *Store) RemoveContainer(hostID, runtimeID string, at time.Time) (*inventory.ContainerChange, error) {
	ctx := context.Background()
	var ch *inventory.ContainerChange
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := containersOf(ctx, tx, hostID)
		if err != nil {
			return err
		}
		old, ok := existing[runtimeID]
		if !ok || old.GoneAt != nil {
			return nil
		}
		ch, err = markGone(ctx, tx, old, at)
		return err
	})
	return ch, err
}

func containersOf(ctx context.Context, tx *sql.Tx, hostID string) (map[string]inventory.Container, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+containerColumns+` FROM containers WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]inventory.Container{}
	for rows.Next() {
		c, err := scanContainer(rows)
		if err != nil {
			return nil, err
		}
		out[c.RuntimeID] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tags, err := loadTags(ctx, tx, inventory.ItemContainer, hostID)
	if err != nil {
		return nil, err
	}
	for rid, c := range out {
		if t := tags[c.ID]; t != nil {
			c.Tags = t
			out[rid] = c
		}
	}
	return out, nil
}

// upsertContainer writes c if it is new, changed or was gone, and reports the change.
func upsertContainer(ctx context.Context, tx *sql.Tx, old inventory.Container, c inventory.Container) (*inventory.ContainerChange, error) {
	ports, err := json.Marshal(c.Ports)
	if err != nil {
		return nil, err
	}
	labels, err := json.Marshal(c.Labels)
	if err != nil {
		return nil, err
	}
	created := sql.NullInt64{}
	if c.CreatedAt != nil {
		created = sql.NullInt64{Int64: ms(*c.CreatedAt), Valid: true}
	}
	if old.ID == "" {
		id, err := ids.New()
		if err != nil {
			return nil, err
		}
		c.ID, c.GoneAt = id, nil
		if _, err := tx.ExecContext(ctx, `INSERT INTO containers (`+containerColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
			c.ID, c.HostID, c.Runtime, c.RuntimeID, c.Name, c.Image, c.State, string(ports), string(labels), c.RestartCount, created); err != nil {
			return nil, fmt.Errorf("insert container: %w", err)
		}
		c.Tags = map[string]string{}
		return &inventory.ContainerChange{Created: true, Container: c}, nil
	}

	// Owner and tags belong to the operator, not the agent: they survive every snapshot.
	c.ID, c.GoneAt, c.Owner, c.Tags = old.ID, nil, old.Owner, old.Tags
	if reflect.DeepEqual(old, c) {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE containers SET runtime=?, name=?, image=?, state=?, ports_json=?, labels_json=?, restart_count=?, created_at=?, gone_at=NULL WHERE id=?`,
		c.Runtime, c.Name, c.Image, c.State, string(ports), string(labels), c.RestartCount, created, c.ID); err != nil {
		return nil, fmt.Errorf("update container: %w", err)
	}
	// A container that was gone and is back is announced as created.
	return &inventory.ContainerChange{Created: old.GoneAt != nil, Container: c}, nil
}

func markGone(ctx context.Context, tx *sql.Tx, old inventory.Container, at time.Time) (*inventory.ContainerChange, error) {
	if _, err := tx.ExecContext(ctx, `UPDATE containers SET gone_at = ? WHERE id = ?`, ms(at), old.ID); err != nil {
		return nil, fmt.Errorf("mark container gone: %w", err)
	}
	t := at.UTC()
	old.GoneAt = &t
	return &inventory.ContainerChange{Removed: true, Container: old}, nil
}

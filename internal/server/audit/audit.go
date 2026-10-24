// SPDX-License-Identifier: AGPL-3.0-only

// Package audit defines the append-only, hash-chained audit log entries. Each
// entry's hash covers the previous entry's hash, so any edit or deletion
// breaks the chain from that point on. Persistence lives in the store package.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Result values for Event.Result.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Event is what a caller reports; the store assigns the ID, time and hashes.
type Event struct {
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	IP         string
	Result     string
	// Details must never hold secrets, tokens or request bodies.
	Details map[string]any
}

// Entry is a stored event.
type Entry struct {
	ID          int64
	TS          int64 // Unix milliseconds
	Event       Event
	DetailsJSON string
	PrevHash    string
	Hash        string
}

// CanonicalDetails renders details as compact JSON with sorted keys, the form that is stored and hashed.
func CanonicalDetails(details map[string]any) (string, error) {
	if len(details) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(details) // map keys are sorted by encoding/json
	if err != nil {
		return "", fmt.Errorf("encode audit details: %w", err)
	}
	return string(b), nil
}

// row fixes the field order of the canonical form: hash = SHA-256(prev_hash || canonical JSON of the row without hash).
type row struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	IP         string `json:"ip"`
	Result     string `json:"result"`
	Details    string `json:"details_json"`
}

// Hash computes the entry's hash from its fields and PrevHash.
func Hash(e Entry) (string, error) {
	body, err := json.Marshal(row{
		ID: e.ID, TS: e.TS, ActorType: e.Event.ActorType, ActorID: e.Event.ActorID, Action: e.Event.Action,
		TargetType: e.Event.TargetType, TargetID: e.Event.TargetID, IP: e.Event.IP, Result: e.Event.Result,
		Details: e.DetailsJSON,
	})
	if err != nil {
		return "", fmt.Errorf("encode audit entry: %w", err)
	}
	sum := sha256.Sum256(append([]byte(e.PrevHash), body...))
	return hex.EncodeToString(sum[:]), nil
}

// Verifier checks entries fed to it in ID order.
type Verifier struct {
	prevID   int64
	prevHash string
}

// Add verifies the next entry: IDs must be consecutive, PrevHash must match the previous entry and Hash must be right.
func (v *Verifier) Add(e Entry) error {
	if e.ID != v.prevID+1 {
		return fmt.Errorf("audit entry %d follows %d: an entry is missing", e.ID, v.prevID)
	}
	if e.PrevHash != v.prevHash {
		return fmt.Errorf("audit entry %d does not chain to entry %d", e.ID, v.prevID)
	}
	want, err := Hash(e)
	if err != nil {
		return err
	}
	if e.Hash != want {
		return fmt.Errorf("audit entry %d was modified", e.ID)
	}
	v.prevID, v.prevHash = e.ID, e.Hash
	return nil
}

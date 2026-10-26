// SPDX-License-Identifier: AGPL-3.0-only

package logs

import "encoding/json"

// Event types and end reasons of the browser protocol.
const (
	TypeLine   = "line"
	TypeNotice = "notice"
	TypeEnd    = "end"

	ReasonSourceEnded    = "source_ended"
	ReasonSourceError    = "source_error"
	ReasonAgentOffline   = "agent_offline"
	ReasonServerShutdown = "server_shutdown"
	ReasonSessionExpired = "session_expired"
)

// Event is one message to a browser. It marshals to the WebSocket protocol:
//
//	{"type":"line","ts":1761472800123,"stream":"stdout","text":"..."}
//	{"type":"notice","code":"LOG-STR-003","message":"...","dropped":12}
//	{"type":"end","reason":"source_ended"}
type Event struct {
	Type    string
	TS      int64  // line: Unix milliseconds
	Stream  string // line: stdout, stderr or journal
	Text    string // line
	Code    string // notice, end: stable error code, may be empty
	Message string // notice
	Dropped int    // notice: lines lost
	Reason  string // end
}

// MarshalJSON renders the per-type shape; empty line text is kept.
func (e Event) MarshalJSON() ([]byte, error) {
	switch e.Type {
	case TypeLine:
		return json.Marshal(struct {
			Type   string `json:"type"`
			TS     int64  `json:"ts"`
			Stream string `json:"stream"`
			Text   string `json:"text"`
		}{e.Type, e.TS, e.Stream, e.Text})
	case TypeNotice:
		return json.Marshal(struct {
			Type    string `json:"type"`
			Code    string `json:"code,omitempty"`
			Message string `json:"message"`
			Dropped int    `json:"dropped,omitempty"`
		}{e.Type, e.Code, e.Message, e.Dropped})
	default:
		return json.Marshal(struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
			Code   string `json:"code,omitempty"`
		}{e.Type, e.Reason, e.Code})
	}
}

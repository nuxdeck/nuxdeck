// SPDX-License-Identifier: AGPL-3.0-only

// Package telemetry builds and sends the opt-in diagnostic report of ADR-007. The payload is
// schema v1 of docs/01-vision.md and nothing else; adding a field needs a new ADR.
package telemetry

// SchemaVersion is the version of the payload below.
const SchemaVersion = 1

// Payload is schema v1. Field order and names follow docs/01-vision.md; TestPayloadMatchesSchemaV1
// fails if either drifts.
type Payload struct {
	SchemaVersion     int             `json:"schema_version"`
	InstallID         string          `json:"install_id"`
	ReportDate        string          `json:"report_date"`
	NuxdVersion       string          `json:"nuxd_version"`
	ReleaseChannel    string          `json:"release_channel"`
	OS                string          `json:"os"`
	Arch              string          `json:"arch"`
	DistroFamily      string          `json:"distro_family"`
	InstallMethod     string          `json:"install_method"`
	StorageBackend    string          `json:"storage_backend"`
	AgentsBucket      string          `json:"agents_bucket"`
	ClustersBucket    string          `json:"clusters_bucket"`
	ChecksBucket      string          `json:"checks_bucket"`
	AgentVersions     map[string]int  `json:"agent_versions"`
	Features          map[string]bool `json:"features"`
	NotifierTypes     []string        `json:"notifier_types"`
	ServerMemoryMBP95 int             `json:"server_memory_mb_p95"`
	ServerUptime      string          `json:"server_uptime_bucket"`
	Restarts24h       int             `json:"restarts_24h"`
	ErrorCodes24h     map[string]int  `json:"error_codes_24h"`
}

// Bucket maps a count to the scale buckets of the spec.
func Bucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n <= 5:
		return "1-5"
	case n <= 20:
		return "6-20"
	case n <= 100:
		return "21-100"
	case n <= 500:
		return "101-500"
	default:
		return "500+"
	}
}

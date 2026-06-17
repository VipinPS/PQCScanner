// Package model holds the data types shared between the collector and the
// reporter, and the wire format posted to the backend's
// /api/runtime/ingest endpoint.
package model

import "time"

// RawEvent is one ring-buffer record decoded from the eBPF program. It
// mirrors `struct event` in agent/bpf/probes.c byte-for-byte.
type RawEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	ProbeID     uint64
	Comm        string
}

// Finding is one aggregated crypto-call observation reported to the
// backend. The agent aggregates RawEvents in memory (per process+algorithm)
// before sending, so a hot loop calling MD5_Init thousands of times per
// second produces one Finding with an occurrence count, not a flood.
type Finding struct {
	Algorithm   string    `json:"algorithm"`    // ALGORITHM_REGISTRY key, e.g. "MD5"
	Symbol      string    `json:"symbol"`       // e.g. "MD5_Init"
	Library     string    `json:"library"`      // "libcrypto" | "libssl" | "liboqs"
	ProcessName string    `json:"process_name"` // comm, e.g. "python3"
	PID         uint32    `json:"pid"`
	Occurrences uint64    `json:"occurrences"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// IngestRequest is the JSON body POSTed to /api/runtime/ingest.
type IngestRequest struct {
	Hostname     string    `json:"hostname"`
	AgentVersion string    `json:"agent_version"`
	KernelInfo   string    `json:"kernel_info,omitempty"`
	Findings     []Finding `json:"findings"`
}

package reporter

import (
	"sync"
	"time"

	"github.com/VipinPS/pqc-platform/agent/internal/mapper"
	"github.com/VipinPS/pqc-platform/agent/internal/model"
)

// aggKey groups raw events into one reported Finding per
// (probe, process) pair, so a hot crypto loop produces a single finding
// with an occurrence count rather than one event per call.
type aggKey struct {
	probeID uint64
	pid     uint32
}

type aggValue struct {
	comm        string
	occurrences uint64
	firstSeen   time.Time
	lastSeen    time.Time
}

// Aggregator accumulates RawEvents in memory until Drain is called. Safe
// for concurrent use: Add is called from the collector's read loop, Drain
// from the flush timer.
type Aggregator struct {
	mu   sync.Mutex
	data map[aggKey]*aggValue
}

func NewAggregator() *Aggregator {
	return &Aggregator{data: map[aggKey]*aggValue{}}
}

// Add records one observed crypto call.
func (a *Aggregator) Add(ev model.RawEvent) {
	now := time.Unix(0, int64(ev.TimestampNS))
	if ev.TimestampNS == 0 {
		now = time.Now()
	}

	key := aggKey{probeID: ev.ProbeID, pid: ev.PID}

	a.mu.Lock()
	defer a.mu.Unlock()

	v, ok := a.data[key]
	if !ok {
		a.data[key] = &aggValue{
			comm:        ev.Comm,
			occurrences: 1,
			firstSeen:   now,
			lastSeen:    now,
		}
		return
	}
	v.occurrences++
	v.lastSeen = now
}

// Drain returns all accumulated findings and resets the aggregator.
// Probes with unrecognized IDs (e.g. from a future agent version's BPF
// object running against an older mapper table) are silently dropped.
func (a *Aggregator) Drain() []model.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.data) == 0 {
		return nil
	}

	findings := make([]model.Finding, 0, len(a.data))
	for key, v := range a.data {
		probe, ok := mapper.ByID(key.probeID)
		if !ok {
			continue
		}
		findings = append(findings, model.Finding{
			Algorithm:   probe.Algorithm,
			Symbol:      probe.Symbol,
			Library:     probe.Library,
			ProcessName: v.comm,
			PID:         key.pid,
			Occurrences: v.occurrences,
			FirstSeen:   v.firstSeen,
			LastSeen:    v.lastSeen,
		})
	}
	a.data = map[aggKey]*aggValue{}
	return findings
}

// merge re-inserts a previously drained Finding. Used by the reporter to
// re-queue findings after a failed delivery so they're retried on the next
// flush instead of being lost.
func (a *Aggregator) merge(f model.Finding) {
	probe, ok := mapper.BySymbol(f.Symbol)
	if !ok {
		return
	}

	key := aggKey{probeID: probe.ID, pid: f.PID}

	a.mu.Lock()
	defer a.mu.Unlock()

	v, ok := a.data[key]
	if !ok {
		a.data[key] = &aggValue{
			comm:        f.ProcessName,
			occurrences: f.Occurrences,
			firstSeen:   f.FirstSeen,
			lastSeen:    f.LastSeen,
		}
		return
	}
	v.occurrences += f.Occurrences
	if f.FirstSeen.Before(v.firstSeen) {
		v.firstSeen = f.FirstSeen
	}
	if f.LastSeen.After(v.lastSeen) {
		v.lastSeen = f.LastSeen
	}
}

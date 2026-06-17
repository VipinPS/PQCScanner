package reporter

import (
	"testing"

	"github.com/VipinPS/pqc-platform/agent/internal/model"
)

func TestAggregatorDedupesByProbeAndPID(t *testing.T) {
	agg := NewAggregator()

	// Three MD5_Init calls (probe ID 0) from pid 100, plus one SHA1_Init
	// (probe ID 1) from the same pid.
	agg.Add(model.RawEvent{ProbeID: 0, PID: 100, Comm: "python3", TimestampNS: 1})
	agg.Add(model.RawEvent{ProbeID: 0, PID: 100, Comm: "python3", TimestampNS: 2})
	agg.Add(model.RawEvent{ProbeID: 0, PID: 100, Comm: "python3", TimestampNS: 3})
	agg.Add(model.RawEvent{ProbeID: 1, PID: 100, Comm: "python3", TimestampNS: 4})

	findings := agg.Drain()
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	byAlgo := map[string]model.Finding{}
	for _, f := range findings {
		byAlgo[f.Algorithm] = f
	}

	md5 := byAlgo["MD5"]
	if md5.Occurrences != 3 {
		t.Errorf("MD5 occurrences = %d, want 3", md5.Occurrences)
	}
	if md5.Symbol != "MD5_Init" || md5.ProcessName != "python3" || md5.PID != 100 {
		t.Errorf("MD5 finding = %+v", md5)
	}

	sha1 := byAlgo["SHA-1"]
	if sha1.Occurrences != 1 {
		t.Errorf("SHA-1 occurrences = %d, want 1", sha1.Occurrences)
	}
}

func TestAggregatorDrainResets(t *testing.T) {
	agg := NewAggregator()
	agg.Add(model.RawEvent{ProbeID: 0, PID: 1, Comm: "a"})

	if got := agg.Drain(); len(got) != 1 {
		t.Fatalf("first Drain() returned %d findings, want 1", len(got))
	}
	if got := agg.Drain(); got != nil {
		t.Fatalf("second Drain() returned %d findings, want nil/empty", len(got))
	}
}

func TestAggregatorUnknownProbeIDDropped(t *testing.T) {
	agg := NewAggregator()
	agg.Add(model.RawEvent{ProbeID: 9999, PID: 1, Comm: "a"})

	if got := agg.Drain(); len(got) != 0 {
		t.Fatalf("Drain() with unknown probe ID = %d findings, want 0", len(got))
	}
}

func TestAggregatorMergeRequeuesFailedDelivery(t *testing.T) {
	agg := NewAggregator()
	agg.Add(model.RawEvent{ProbeID: 0, PID: 1, Comm: "python3"})

	findings := agg.Drain()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	// Simulate a failed send: re-queue the drained finding.
	agg.merge(findings[0])
	agg.Add(model.RawEvent{ProbeID: 0, PID: 1, Comm: "python3"})

	again := agg.Drain()
	if len(again) != 1 {
		t.Fatalf("got %d findings after merge+add, want 1", len(again))
	}
	if again[0].Occurrences != 2 {
		t.Errorf("occurrences after merge+add = %d, want 2", again[0].Occurrences)
	}
}

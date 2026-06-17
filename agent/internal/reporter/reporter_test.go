package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VipinPS/pqc-platform/agent/internal/model"
)

func TestSendPostsIngestRequest(t *testing.T) {
	var gotReq model.IngestRequest
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/runtime/ingest" {
			t.Errorf("path = %s, want /api/runtime/ingest", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	r := New(srv.URL, "secret-token", "host-a", "0.1.0", "linux/amd64")
	err := r.send([]model.Finding{{
		Algorithm:   "MD5",
		Symbol:      "MD5_Init",
		Library:     "libcrypto",
		ProcessName: "python3",
		PID:         123,
		Occurrences: 5,
	}})
	if err != nil {
		t.Fatalf("send returned error: %v", err)
	}

	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer secret-token")
	}
	if gotReq.Hostname != "host-a" {
		t.Errorf("Hostname = %q, want host-a", gotReq.Hostname)
	}
	if len(gotReq.Findings) != 1 || gotReq.Findings[0].Algorithm != "MD5" {
		t.Errorf("Findings = %+v", gotReq.Findings)
	}
}

func TestFlushRequeuesOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := New(srv.URL, "tok", "host-a", "0.1.0", "linux/amd64")
	agg := NewAggregator()
	agg.Add(model.RawEvent{ProbeID: 0, PID: 1, Comm: "python3", TimestampNS: uint64(time.Now().UnixNano())})

	r.flush(agg)

	// Failed delivery should re-queue the finding for the next flush.
	findings := agg.Drain()
	if len(findings) != 1 {
		t.Fatalf("after failed flush, Drain() = %d findings, want 1", len(findings))
	}
	if findings[0].Algorithm != "MD5" {
		t.Errorf("requeued finding algorithm = %q, want MD5", findings[0].Algorithm)
	}
}

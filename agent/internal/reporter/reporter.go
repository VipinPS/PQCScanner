package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/VipinPS/pqc-platform/agent/internal/model"
)

// Reporter periodically drains an Aggregator and POSTs the result to the
// backend's /api/runtime/ingest endpoint.
type Reporter struct {
	BackendURL   string
	Token        string
	Hostname     string
	AgentVersion string
	KernelInfo   string

	client *http.Client
}

func New(backendURL, token, hostname, agentVersion, kernelInfo string) *Reporter {
	return &Reporter{
		BackendURL:   backendURL,
		Token:        token,
		Hostname:     hostname,
		AgentVersion: agentVersion,
		KernelInfo:   kernelInfo,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Run flushes agg every interval until ctx is canceled, logging (but not
// failing on) delivery errors so a transient backend outage doesn't crash
// the agent — findings simply re-accumulate until the next successful
// flush.
func (r *Reporter) Run(ctx context.Context, agg *Aggregator, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.flush(agg) // best-effort final flush
			return
		case <-ticker.C:
			r.flush(agg)
		}
	}
}

func (r *Reporter) flush(agg *Aggregator) {
	findings := agg.Drain()
	if len(findings) == 0 {
		return
	}
	if err := r.send(findings); err != nil {
		log.Printf("reporter: send failed (%d findings will be re-aggregated): %v", len(findings), err)
		// Re-queue: best effort, avoids losing data on a single failed POST.
		for _, f := range findings {
			agg.merge(f)
		}
	}
}

func (r *Reporter) send(findings []model.Finding) error {
	body := model.IngestRequest{
		Hostname:     r.Hostname,
		AgentVersion: r.AgentVersion,
		KernelInfo:   r.KernelInfo,
		Findings:     findings,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := r.BackendURL + "/api/runtime/ingest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("backend returned %s", resp.Status)
	}
	return nil
}

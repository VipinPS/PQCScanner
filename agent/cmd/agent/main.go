// Command agent is the PQCScanner runtime crypto-usage agent (Stage 12).
//
// It attaches eBPF uprobes to OpenSSL/libcrypto, libssl and (optionally)
// liboqs functions on the host, observes which cryptographic primitives
// running processes actually call at runtime, and periodically reports
// aggregated findings back to the PQCScanner backend so they can be
// correlated with the static source-code scan results.
//
// Requires Linux 5.15+ (uprobe attach cookies), CAP_BPF + CAP_PERFMON (or
// root), and at least one of libcrypto/libssl present on the host.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/VipinPS/pqc-platform/agent/internal/collector"
	"github.com/VipinPS/pqc-platform/agent/internal/reporter"
)

const version = "0.1.0"

func main() {
	var (
		backendURL   = flag.String("backend-url", "http://localhost:8000", "PQCScanner backend base URL")
		token        = flag.String("token", os.Getenv("PQC_AGENT_TOKEN"), "Agent ingest token (or set PQC_AGENT_TOKEN)")
		hostnameFlag = flag.String("hostname", "", "Override reported hostname (default: os.Hostname())")
		interval     = flag.Duration("interval", 30*time.Second, "How often to report aggregated findings")
		libcrypto    = flag.String("libcrypto", "", "Path to libcrypto.so (default: auto-discover)")
		libssl       = flag.String("libssl", "", "Path to libssl.so (default: auto-discover)")
		liboqs       = flag.String("liboqs", "", "Path to liboqs.so (default: auto-discover)")
		printOnly    = flag.Bool("print-only", false, "Print findings to stdout instead of (or in addition to printing while) reporting")
	)
	flag.Parse()

	if *token == "" && !*printOnly {
		log.Fatal("missing -token / PQC_AGENT_TOKEN (or pass -print-only for local testing without a backend)")
	}

	hostname := *hostnameFlag
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		} else {
			hostname = h
		}
	}

	libPaths := collector.DiscoverLibraries()
	for lib, override := range map[string]string{"libcrypto": *libcrypto, "libssl": *libssl, "liboqs": *liboqs} {
		if override != "" {
			libPaths[lib] = override
		}
	}
	if len(libPaths) == 0 {
		log.Fatal("no crypto libraries found (libcrypto/libssl/liboqs) — nothing to instrument")
	}
	for lib, path := range libPaths {
		log.Printf("agent: using %s -> %s", lib, path)
	}

	col, err := collector.New(libPaths)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	defer col.Close()

	log.Printf("agent: attached %d/%d probes", len(col.Attached()), len(libPaths))

	agg := reporter.NewAggregator()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("agent: shutting down")
		cancel()
	}()

	// Read loop: decode ring-buffer records into the aggregator.
	go func() {
		for {
			ev, err := col.Read()
			if err != nil {
				if ctx.Err() != nil {
					return // expected: Close() called during shutdown
				}
				log.Printf("agent: read error: %v", err)
				continue
			}
			agg.Add(ev)
		}
	}()

	kernelInfo := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	if *printOnly {
		printLoop(ctx, agg, *interval)
		return
	}

	rep := reporter.New(*backendURL, *token, hostname, version, kernelInfo)
	rep.Run(ctx, agg, *interval)
}

// printLoop drains the aggregator and logs findings to stdout instead of
// reporting to a backend — useful for local testing of probe attachment
// without a running PQCScanner instance.
func printLoop(ctx context.Context, agg *reporter.Aggregator, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, f := range agg.Drain() {
				log.Printf("finding: algo=%s symbol=%s pid=%d comm=%s occurrences=%d",
					f.Algorithm, f.Symbol, f.PID, f.ProcessName, f.Occurrences)
			}
			return
		case <-ticker.C:
			for _, f := range agg.Drain() {
				log.Printf("finding: algo=%s symbol=%s pid=%d comm=%s occurrences=%d",
					f.Algorithm, f.Symbol, f.PID, f.ProcessName, f.Occurrences)
			}
		}
	}
}

// Package collector loads the compiled eBPF program, attaches a uprobe for
// every entry in mapper.Probes whose target library is present on the host,
// and decodes ring-buffer records into model.RawEvent.
package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/VipinPS/pqc-platform/agent/internal/mapper"
	"github.com/VipinPS/pqc-platform/agent/internal/model"
)

// bpfEvent mirrors `struct event` in agent/bpf/probes.c byte-for-byte.
type bpfEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	ProbeID     uint64
	Comm        [16]byte
}

// Collector owns the loaded BPF objects, attached uprobe links and the
// ring-buffer reader. Call Close when done.
type Collector struct {
	objs     probesObjects
	links    []link.Link
	reader   *ringbuf.Reader
	attached []mapper.Probe
}

// New loads the BPF program and attaches a uprobe for every probe whose
// library is present in libPaths (keyed by mapper.Probe.Library, e.g.
// "libcrypto" -> "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"). Probes for
// libraries that aren't present, or whose symbol isn't exported by the
// resolved library, are skipped (logged, not fatal) — that's expected on
// hosts without liboqs, or with stripped/minimal libssl builds.
func New(libPaths map[string]string) (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	var objs probesObjects
	if err := loadProbesObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	c := &Collector{objs: objs}

	executables := map[string]*link.Executable{}
	for _, probe := range mapper.Probes {
		libPath, ok := libPaths[probe.Library]
		if !ok || libPath == "" {
			continue
		}

		ex, ok := executables[libPath]
		if !ok {
			var err error
			opened, err := link.OpenExecutable(libPath)
			if err != nil {
				log.Printf("collector: open %s (%s): %v — skipping its probes", probe.Library, libPath, err)
				executables[libPath] = nil
				continue
			}
			ex = opened
			executables[libPath] = ex
		}
		if ex == nil {
			continue // library failed to open earlier
		}

		up, err := ex.Uprobe(probe.Symbol, objs.ProbeCryptoCall, &link.UprobeOptions{Cookie: probe.ID})
		if err != nil {
			log.Printf("collector: attach uprobe %s@%s: %v — skipping (symbol not present in this build)", probe.Symbol, probe.Library, err)
			continue
		}
		c.links = append(c.links, up)
		c.attached = append(c.attached, probe)
	}

	if len(c.links) == 0 {
		objs.Close()
		return nil, fmt.Errorf("no uprobes attached — no supported crypto libraries found on this host")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	c.reader = rd

	return c, nil
}

// Attached returns the probes that were successfully attached.
func (c *Collector) Attached() []mapper.Probe {
	return c.attached
}

// Read blocks until the next ring-buffer record is available and returns
// the decoded event. Returns ringbuf.ErrClosed once Close has been called.
func (c *Collector) Read() (model.RawEvent, error) {
	record, err := c.reader.Read()
	if err != nil {
		return model.RawEvent{}, err
	}

	var ev bpfEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
		return model.RawEvent{}, fmt.Errorf("decode ring buffer record: %w", err)
	}

	return model.RawEvent{
		TimestampNS: ev.TimestampNS,
		PID:         ev.PID,
		TID:         ev.TID,
		ProbeID:     ev.ProbeID,
		Comm:        cString(ev.Comm[:]),
	}, nil
}

// Close detaches all uprobes, closes the ring buffer and unloads the BPF
// program.
func (c *Collector) Close() error {
	var firstErr error
	if c.reader != nil {
		if err := c.reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, l := range c.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// cString trims a NUL-terminated fixed-size byte array down to its string
// content (TASK_COMM_LEN fields from the kernel are NUL-padded).
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

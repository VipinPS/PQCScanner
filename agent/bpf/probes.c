//go:build ignore

// Single uprobe handler attached (with a per-attachment "cookie") to every
// crypto symbol of interest in libcrypto/libssl/liboqs. The cookie lets one
// compiled program serve every probe in internal/mapper.Probes, so adding a
// new symbol on the Go side never requires touching this file.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 probe_id;
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16); // 64KB ring buffer
} events SEC(".maps");

SEC("uprobe")
int probe_crypto_call(struct pt_regs *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;

	// Cookie is set per-attachment in the Go collector, identifying which
	// entry in mapper.Probes triggered this event.
	e->probe_id = bpf_get_attach_cookie(ctx);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";

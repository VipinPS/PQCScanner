# PQCScanner Runtime Agent (Stage 12)

A small Go/eBPF agent that observes which cryptographic primitives a host's
processes actually *call at runtime* — via uprobes on `libcrypto`, `libssl`
and (optionally) `liboqs` — and reports aggregated findings back to the PQCScanner
backend, where they're correlated with the static source-code scan
results.

This complements (does not replace) the static `CryptoScanner` in
`backend/app/scanner/engine.py`: the static scanner tells you what crypto a
codebase *could* use, this agent tells you what's *actually being executed*
in production, including in dependencies, dynamically loaded code, and
binaries that were never source-scanned.

## How it works

1. **Discovery** — `internal/collector.DiscoverLibraries()` searches common
   library directories for `libcrypto.so*`, `libssl.so*` and `liboqs.so*`.
2. **Attach** — for each symbol in `internal/mapper.Probes` (e.g.
   `MD5_Init`, `ECDH_compute_key`, `RSA_generate_key_ex`,
   `OQS_KEM_ml_kem_768_keypair`), the agent attaches a uprobe — backed by a
   single compiled eBPF program (`bpf/probes.c`) — to the resolved library
   file. Uprobes are attached at the file/inode level, so they fire for
   *every* process on the host that loads that library, not just one PID.
3. **Collect** — each call increments a per-`(symbol, pid)` counter in
   `internal/reporter.Aggregator` via a ring buffer.
4. **Report** — every `-interval` (default 30s), aggregated findings are
   POSTed as JSON to `POST {backend-url}/api/runtime/ingest`, mapped to the
   same `ALGORITHM_REGISTRY` taxonomy (algorithm name, risk level, quantum
   status, NIST replacement) used by the static scanner.

Symbols whose library isn't present, or whose symbol isn't exported by the
resolved build (e.g. a libcrypto built without `RC4`), are skipped with a
log line — this is expected and not fatal.

## Requirements

- Linux kernel **5.15+** (uprobe attach cookies, `BPF_FUNC_get_attach_cookie`)
- `CAP_BPF` + `CAP_PERFMON` (or root)
- At least one of `libcrypto`/`libssl`/`liboqs` present on the host
- Go 1.22+ and `clang`/`libbpf-dev` to build from source (pre-built binaries
  have no build-time dependencies — eBPF bytecode is embedded via
  `//go:embed`)

## Build

```sh
cd agent
go build -o pqc-agent ./cmd/agent
```

To regenerate the embedded eBPF bytecode after editing `bpf/probes.c`:

```sh
cd agent/internal/collector
go generate ./...
```

## Run

```sh
sudo ./pqc-agent \
  -backend-url https://pqc-platform.example.com \
  -token "$PQC_AGENT_TOKEN" \
  -interval 30s
```

Local testing without a backend (logs findings to stdout instead of
reporting):

```sh
sudo ./pqc-agent -print-only -interval 5s
```

Flags:

| Flag           | Default                 | Description                                  |
|----------------|-------------------------|-----------------------------------------------|
| `-backend-url` | `http://localhost:8000` | PQCScanner backend base URL                |
| `-token`       | `$PQC_AGENT_TOKEN`       | Bearer token for `/api/runtime/ingest`       |
| `-hostname`    | `os.Hostname()`          | Override reported hostname                   |
| `-interval`    | `30s`                    | Reporting interval                           |
| `-libcrypto`   | auto-discovered          | Override path to `libcrypto.so`              |
| `-libssl`      | auto-discovered          | Override path to `libssl.so`                 |
| `-liboqs`      | auto-discovered          | Override path to `liboqs.so`                 |
| `-print-only`  | `false`                  | Print findings to stdout, skip the backend   |

## Getting an ingest token

Register the host via the backend (see
`backend/app/api/runtime.py`):

```sh
curl -s -X POST https://pqc-platform.example.com/api/runtime/hosts \
  -H 'Content-Type: application/json' \
  -d '{"hostname": "web-01", "label": "prod web tier"}'
# => {"id": "...", "token": "..."}
```

Use the returned `token` as `-token`/`PQC_AGENT_TOKEN`.

## Probe coverage

See `internal/mapper/mapper.go` for the full, append-only list. Currently
covers: MD5, SHA-1, DES, RC4, AES-128, ECDSA, ECDH, PBKDF2, Blowfish, RSA key
generation, TLS 1.0/1.1/1.2 method selection, and (where `liboqs` is
present) ML-KEM-768 / ML-DSA-65 as an early signal of PQC adoption.

Each entry maps to a key in `backend/app/scanner/engine.py`'s
`ALGORITHM_REGISTRY`, so risk level, quantum status and NIST replacement
guidance stay consistent between static and runtime findings.

## Project layout

```
agent/
├── cmd/agent/main.go         # CLI entrypoint
├── bpf/probes.c               # eBPF C source (single uprobe handler)
├── internal/
│   ├── collector/              # loads BPF program, attaches uprobes, reads ring buffer
│   │   ├── probes_bpfel.go/.o  # generated (go generate) — committed
│   │   └── probes_bpfeb.go/.o  # generated (go generate) — committed
│   ├── mapper/                 # symbol -> ALGORITHM_REGISTRY mapping (the probe list)
│   ├── model/                  # shared event/finding/wire types
│   └── reporter/               # in-memory aggregation + HTTP delivery to the backend
└── README.md
```

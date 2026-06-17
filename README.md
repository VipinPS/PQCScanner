# PQCScanner

A comprehensive, production-grade platform for discovering quantum-vulnerable cryptography across your codebases, scoring crypto agility, tracking migration progress, and generating Cryptographic Bill of Materials (CBOM) for compliance.

---

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Access URLs](#access-urls)
- [Features](#features)
- [Crypto Agility Scoring](#crypto-agility-scoring)
- [Scanning Engine](#scanning-engine)
- [File Secrets Scanning](#file-secrets-scanning)
- [CBOM](#cbom---cryptographic-bill-of-materials)
- [Remediation Playbooks](#remediation-playbooks)
- [API Reference](#api-reference)
- [Authentication & Roles](#authentication--roles)
- [Database Schema](#database-schema)
- [CLI Tool](#cli-tool)
- [CI/CD Integration](#cicd-integration)
- [NIST PQC Standards](#nist-pqc-standards-2024)
- [Configuration](#configuration)

---

## Overview

**PQCScanner** solves the challenge of finding WHERE quantum-vulnerable cryptography is used across hundreds of repositories. It provides:

- **Automated discovery** of 54+ cryptographic algorithms across 12+ languages
- **Crypto agility scoring** (L1–L5 maturity scale)
- **Migration lifecycle tracking** with regression detection
- **CBOM export** in CycloneDX 1.5 and CSV formats
- **Language-specific remediation playbooks** with before/after code examples
- **CI/CD gating** to prevent new vulnerable crypto from being merged

---

## Tech Stack

### Frontend
| Tool | Purpose |
|---|---|
| React | Component-based SPA |
| Vite | Build tool and dev server |
| IBM Carbon Design System | UI components (dark theme) |
| Native `fetch` API | HTTP client (`src/api/client.js`) |
| React Hooks | State management (`useState`, `useEffect`) |

### Backend
| Tool | Version | Purpose |
|---|---|---|
| FastAPI | 0.111.0 | REST API framework |
| Uvicorn | 0.29.0 | ASGI server |
| SQLAlchemy | 2.0.30 | ORM |
| Pydantic | 2.7.1 | Data validation |
| pydantic-settings | 2.2.1 | Settings management |
| psycopg2-binary | 2.9.9 | PostgreSQL driver |
| Alembic | 1.13.1 | Database migrations |
| Celery | 5.4.0 | Async task queue |
| Redis (Python) | 5.0.4 | Cache and message broker |
| GitPython | 3.1.43 | Remote repo cloning |
| httpx | 0.27.0 | HTTP client |
| bcrypt | 4.1.3 | Password hashing |
| Paramiko | 3.5.1 | SSH key parsing |
| cryptography | latest | X.509 cert and PKCS#12 parsing |
| Python | 3.12 | Runtime |

### Infrastructure
| Tool | Version | Purpose |
|---|---|---|
| PostgreSQL | 16-alpine | Primary database |
| Redis | 7-alpine | Cache and Celery broker |
| Docker + Docker Compose | latest | Container orchestration |

---

## Architecture

```
Browser
  └── React + Vite + IBM Carbon (port 5173)
        │
        ▼ HTTP/JSON (fetch API)
FastAPI (port 8000)
  ├── 8 Routers (auth, repos, scans, findings, cbom, secrets, reports, playbooks)
  ├── SQLAlchemy ORM  ──► PostgreSQL 16 (port 5432)
  ├── Celery Workers  ──► Redis 7 (port 6379)
  └── Scanner Engine
        ├── engine.py        (54+ regex patterns, agility scoring)
        └── file_secrets.py  (SSH/TLS/GPG/config parsing)
```

### Directory Structure

```
pqc-platform/
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI app entry point (8 routers)
│   │   ├── api/
│   │   │   ├── auth.py         # Login, logout, session
│   │   │   ├── repos.py        # Repo CRUD
│   │   │   ├── scans.py        # Scan trigger & status polling
│   │   │   ├── findings.py     # Finding query, resolve, archive
│   │   │   ├── cbom.py         # CBOM + CycloneDX/CSV export
│   │   │   ├── reports.py      # Dashboard summary stats
│   │   │   ├── playbooks.py    # Remediation playbooks
│   │   │   └── secrets.py      # SSH/TLS/GPG secret findings
│   │   ├── models/             # SQLAlchemy ORM models (5 entities)
│   │   ├── scanner/
│   │   │   ├── engine.py       # Core crypto detection + agility scoring
│   │   │   └── file_secrets.py # SSH key, TLS cert, GPG, SSH config scanner
│   │   ├── db/                 # PostgreSQL connection
│   │   ├── core/               # Config and settings
│   │   └── schemas/            # Pydantic request/response schemas
│   ├── cli_scan.py             # Standalone CLI scanner
│   ├── migrations/             # SQL migration files
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main app (5 views, dark theme)
│   │   ├── api/client.js       # Fetch-based API client
│   │   └── hooks/useApi.js
│   ├── package.json
│   └── Dockerfile
├── .github/workflows/
│   └── pqc-scan.yml            # GitHub Actions CI/CD
└── docker-compose.yml          # Full stack orchestration
```

---

## Quick Start

### Option A — Docker Compose (Recommended)

```bash
git clone https://github.com/VipinPS/PQCScanner.git
cd PQCScanner
docker compose up
```

### Option B — Manual Setup

```bash
# 1. Start PostgreSQL and Redis
docker run -e POSTGRES_USER=pqc_user -e POSTGRES_PASSWORD=pqc_pass \
  -e POSTGRES_DB=pqc_platform -p 5432:5432 postgres:16-alpine

docker run -p 6379:6379 redis:7-alpine

# 2. Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# 3. Frontend
cd frontend
npm install && npm run dev
```

---

## Access URLs

| Service | URL |
|---|---|
| Frontend UI | `http://localhost:5173` |
| Backend API | `http://localhost:8000` |
| Swagger UI (interactive docs) | `http://localhost:8000/docs` |
| ReDoc (clean docs) | `http://localhost:8000/redoc` |
| OpenAPI JSON schema | `http://localhost:8000/openapi.json` |
| Health check | `http://localhost:8000/api/health` |

---

## Features

### 1. Dashboard
Executive-level overview showing:
- Total repositories monitored
- Critical findings count
- BROKEN / VULNERABLE / SAFE breakdown
- Last scan timestamp
- CBOM entry count

### 2. Repository Management
- Add repositories by Git URL (GitHub, GitLab, Bitbucket, Gitea, self-hosted)
- Trigger on-demand scans
- View per-repo crypto agility level (L1–L5)
- Delete repos (cascades all findings and scan history)

### 3. Findings Explorer
Tab-based investigation interface:
- **Open** — Active findings needing remediation
- **Auto-Resolved** — Scanner no longer detects the finding (2 consecutive scans)
- **Manually Resolved** — Developer marked as fixed with `migrated_to` evidence
- **Re-Opened** — Previously resolved findings that reappeared (regression)

Filtering: by repo, risk level, quantum status, algorithm, migration status, file path search

Actions: resolve with migration target, archive (soft-delete), bulk archive, restore

### 4. CBOM — Cryptographic Bill of Materials
Complete crypto asset inventory aggregated across all repos:
- Priority ordered (BROKEN first)
- Merged code findings + secret findings per algorithm
- Export as **CycloneDX 1.5 JSON** or **CSV**

### 5. Remediation Playbooks
20 algorithms × 6 languages with:
- Severity and quantum risk explanation
- NIST standard replacement
- Step-by-step migration guide
- Before/after code diffs

**Languages:** Python, Java, Go, TypeScript/Node.js, C#, Shell

### 6. Secrets View
Dedicated view for cryptographic material found in repositories:
- SSH private/public keys
- TLS certificates (with expiry tracking)
- PKCS#12 keystores
- GPG/PGP keys
- SSH configuration weaknesses

---

## Crypto Agility Scoring

Crypto agility is the ability to **swap cryptographic algorithms without redesigning the application**. The platform scores each repository on a 5-level maturity scale:

| Level | Label | Description |
|---|---|---|
| **L1** | Hardcoded | Algorithm baked into code — e.g., `RSA.generate(1024)` or private key in source |
| **L2** | Configurable | Algorithm set via config/env at deploy time — e.g., `CRYPTO_ALGO="RSA-2048"` |
| **L3** | Hot-Swap | Registry/factory pattern — swappable at runtime without restart |
| **L4** | Hybrid | Classical + PQC running simultaneously — e.g., `X25519 + ML-KEM-768` |
| **L5** | Fully Agile | Per-request algorithm negotiation, zero hardcoding, fully PQC-ready |

### Agility Signal Patterns

| Pattern | Score | Level Signal |
|---|---|---|
| `alg_negotiat` / `negotiateAlgorithm` | +4 | → L5 |
| `HybridKEM` / `X25519MLKEM` / `hybrid.*pqc` | +3 | → L4 |
| `ML-KEM` / `kyber` / `dilithium` / `ML-DSA` | +3 | → L4+ |
| `fips-203` / `fips-204` | +3 | → L4+ |
| `CryptoRegistry` / `AlgorithmProvider` | +2 | → L3 |
| `registerAlgorithm` / `registry.get(` | +2 | → L3 |
| `algorithm.*config` / `CRYPTO_ALGO` | +1 | → L2 |
| `alg_fallback` / `algorithm_fallback` | +1 | → L2 |
| `-----BEGIN RSA PRIVATE KEY-----` | -3 | → L1 anchor |
| `RSA.generate(1024` / `RSA.generate(512` | -2 | → L1/L2 anchor |

### Correctness Rules

```
Rule 1 — Test/vendor files are ignored entirely
Rule 2 — Hardcoded private key → score anchored at L1 max
          Weak RSA (512/1024) → score capped at L2 max
Rule 3 — Hybrid PQC detected → minimum score bumped to L3
Rule 4 — ≥10 CRITICAL findings → max capped at L2
          1–9 CRITICAL findings → max capped at L3
```

### Score → Level Mapping

```
score ≤ 0   →  L1  Hardcoded
score 1–2   →  L2  Configurable
score 3–4   →  L3  Hot-Swap
score 5–7   →  L4  Hybrid
score ≥ 8   →  L5  Fully Agile
```

---

## Scanning Engine

The scanner detects **54+ cryptographic algorithms** across **12+ languages** using compiled regex patterns.

### Supported Languages

Python, Java, Go, TypeScript/JavaScript, Kotlin, Rust, C, C++, C#, Dart, Ruby, Swift, YAML, Shell scripts

### Algorithms Detected

| Algorithm | Type | Quantum Status | Risk | NIST Replacement |
|---|---|---|---|---|
| MD5 | Hash | BROKEN | CRITICAL | SHA-3-256 |
| SHA-1 | Hash | WEAK | HIGH | SHA-3-256 |
| DES / 3DES | Symmetric | BROKEN | CRITICAL | AES-256-GCM |
| RC4 | Symmetric | BROKEN | CRITICAL | AES-256-GCM |
| Blowfish | Symmetric | BROKEN | CRITICAL | AES-256-GCM |
| AES-128 | Symmetric | VULNERABLE | MEDIUM | AES-256-GCM |
| RSA-1024 | Asymmetric | BROKEN | CRITICAL | ML-KEM-768 (FIPS 203) |
| RSA-2048 | Asymmetric | VULNERABLE | CRITICAL | ML-KEM-768 / ML-DSA-65 |
| RSA-4096 | Asymmetric | VULNERABLE | HIGH | ML-KEM-1024 / ML-DSA-87 |
| ECDSA | Signature | VULNERABLE | HIGH | ML-DSA-65 (FIPS 204) |
| ECDH | KEM | VULNERABLE | HIGH | ML-KEM-768 (FIPS 203) |
| X25519 | KEM | VULNERABLE | MEDIUM | ML-KEM-768 hybrid (FIPS 203) |
| TLS 1.0 | Protocol | BROKEN | CRITICAL | TLS 1.3 + ML-KEM hybrid |
| TLS 1.1 | Protocol | WEAK | HIGH | TLS 1.3 + ML-KEM hybrid |
| TLS 1.2 | Protocol | MONITOR | MEDIUM | TLS 1.3 + ML-KEM hybrid |
| JWT-RS256 | Signature | VULNERABLE | HIGH | ML-DSA-65 (FIPS 204) |
| PBKDF2 | KDF | VULNERABLE | MEDIUM | Argon2id |
| Hardcoded Keys | KeyMgmt | BROKEN | CRITICAL | HSM / KMS |
| SSH-WEAK-KEX | Protocol | VULNERABLE | HIGH | OpenSSH with ML-KEM |
| ML-KEM-512/768/1024 | KEM | SAFE | LOW | — (already PQC) |
| ML-DSA-44/65/87 | Signature | SAFE | LOW | — (already PQC) |
| SLH-DSA | Signature | SAFE | LOW | — (already PQC) |

### Scan Process

1. Walk directory tree — skip `.git`, `node_modules`, `__pycache__`, `vendor`, `dist`, `build`
2. Filter by file extension (language-specific) or special filenames (`sshd_config`, `ssh_config`)
3. Apply 54+ compiled regex patterns per file (case-insensitive, multiline)
4. De-duplicate by `(file, algorithm, line)` triplet
5. Capture ±3 lines of code context around each match
6. Run agility scoring pass on production files only

---

## File Secrets Scanning

Detects actual cryptographic material embedded in repositories — not just API usage patterns.

| Finding Type | Detection | Key Data Extracted |
|---|---|---|
| **SSH_PRIVATE_KEY** | PEM headers | Algorithm, key size, curve |
| **SSH_PUBLIC_KEY** | `.pub` / `authorized_keys` | Key type (rsa, ecdsa, ed25519) |
| **TLS_CERT** | PEM cert blocks → X.509 parse | Subject, issuer, expiry, serial, sig hash |
| **PKCS#12** | Binary header / `.p12` / `.pfx` | Algorithm from leaf cert |
| **GPG_KEY** | `BEGIN PGP` armored text | Conservative RSA-2048/ECDSA assumption |
| **SSH_CONFIG** | `sshd_config` / `ssh_config` files | KexAlgorithms, Ciphers, MACs values |

### Risk Assessment

| Key Type | Risk |
|---|---|
| RSA ≤ 1024 bits | BROKEN / CRITICAL |
| RSA 2048+ bits | VULNERABLE / CRITICAL |
| ECDSA P-256/384 | VULNERABLE / HIGH |
| Ed25519 | VULNERABLE / MEDIUM |
| DSA (any size) | BROKEN / CRITICAL |
| Expired TLS cert | Escalated to CRITICAL |
| SHA-1 signed cert | WEAK / HIGH |
| SSH config with RC4/DES | BROKEN / CRITICAL |

---

## CBOM — Cryptographic Bill of Materials

### Generation Process

1. Takes the most recent completed scan for each repository
2. Groups all active (open/re-opened, non-archived) findings by algorithm
3. Merges code findings + secret findings into unified entries
4. Calculates `total_usages`, `code_usages`, `secret_usages`, `affected_repos`, `risk_score`, `priority`

### Priority Ordering

| Priority | Quantum Status | Risk Score |
|---|---|---|
| 1 (highest) | BROKEN | 10.0 |
| 2 | VULNERABLE | 8.5 |
| 3 | WEAK | 6.0 |
| 4 | MONITOR | 4.0 |
| 5 (lowest) | SAFE | 1.0 |

### Export Formats

**CycloneDX 1.5 JSON** — Industry standard BOM format:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [{
    "type": "cryptographic-asset",
    "name": "RSA-2048",
    "cryptoProperties": {
      "assetType": "Asymmetric",
      "algorithmProperties": { "nistQuantumSecurityLevel": 0 }
    },
    "x-pqc-status": "VULNERABLE",
    "x-nist-replacement": "ML-KEM-768 / ML-DSA-65",
    "x-total-usages": 42,
    "x-affected-repos": 5
  }]
}
```

**CSV** — One row per finding location for spreadsheet analysis and ticketing imports.

---

## Remediation Playbooks

Available for **20 algorithms** across **6 languages** with step-by-step migration guides.

**Algorithms:** RSA-2048, RSA-1024, RSA-4096, ECDSA, ECDH, X25519, SHA-1, MD5, DES, RC4, Blowfish, AES-128, TLS-1.0, TLS-1.1, TLS-1.2, JWT-RS256, HARDCODED-KEY, PBKDF2, SSH-WEAK-KEX, CRYPTSETUP-WEAK-KDF

**Languages:** Python, Java, Go, TypeScript/Node.js, C#, Shell

Each playbook includes severity rating, quantum risk explanation, NIST replacement, migration effort estimate, library recommendations, and before/after code diffs.

---

## API Reference

Interactive docs available at `http://localhost:8000/docs`

### Authentication

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api/auth/login` | Login (returns httpOnly session cookie) | None |
| POST | `/api/auth/logout` | Clear session | Session |
| GET | `/api/auth/me` | Current user and role | Session |

### Repositories

| Method | Endpoint | Description | Role |
|---|---|---|---|
| GET | `/api/repos/` | List all repositories | Public |
| POST | `/api/repos/` | Add repository (Git URL) | Admin |
| GET | `/api/repos/{repo_id}` | Get repo details + agility scores | Public |
| DELETE | `/api/repos/{repo_id}` | Delete repository | Admin |

### Scans

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scans/{repo_id}/trigger` | Trigger async scan |
| GET | `/api/scans/{repo_id}/runs` | Scan history |
| GET | `/api/scans/runs/{scan_run_id}` | Poll scan status (`pending/running/complete/failed`) |

### Findings

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/findings/` | Query findings (filter: repo, risk, algorithm, status) |
| GET | `/api/findings/summary` | Aggregated counts by risk and status |
| PATCH | `/api/findings/{id}/status` | Resolve finding, set `migrated_to` |
| PATCH | `/api/findings/{id}/archive` | Soft-delete finding |
| PATCH | `/api/findings/{id}/restore` | Restore archived finding |
| POST | `/api/findings/archive-resolved` | Bulk archive all resolved findings |
| GET | `/api/findings/archived` | Audit trail |
| GET | `/api/findings/migration-stats` | Per-algorithm migration progress % |

### CBOM & Reports

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/cbom/` | CBOM entries (priority ordered) |
| GET | `/api/cbom/export/cyclonedx` | Export as CycloneDX 1.5 JSON |
| GET | `/api/cbom/export/csv` | Export as CSV |
| GET | `/api/secrets/` | Secret findings (SSH, TLS, GPG, SSH config) |
| GET | `/api/secrets/summary` | Secrets aggregation + expiry counts |
| GET | `/api/reports/dashboard` | Dashboard summary stats |
| GET | `/api/health` | Liveness probe |

### Playbooks

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/playbooks/` | List all available playbooks |
| GET | `/api/playbooks/{algorithm}` | Full playbook for an algorithm |
| GET | `/api/playbooks/{algorithm}/{language}` | Language-specific code example |

---

## Authentication & Roles

Session-based auth via httpOnly cookie (`pqc_session`, 8-hour TTL).

| Role | Capabilities |
|---|---|
| **admin** | Full access — add/delete repos, trigger scans, manage all data |
| **dev** | Trigger scans, resolve findings, view everything |
| **reader** | Read-only — view findings, CBOM, playbooks, reports |

**Default credentials (development only):**

| Username | Password | Role |
|---|---|---|
| `admin` | `pqcadmin` | Admin |
| `dev` | `pqcdev` | Dev |
| `reader` | `pqcreader` | Reader |

> **Note:** Change these credentials before any production deployment.

---

## Database Schema

### Core Tables

| Table | Purpose |
|---|---|
| `repos` | Repository registry + agility scores (level, label, score, hybrid flag, signals) |
| `scan_runs` | Scan execution history (status, file counts, finding counts, errors) |
| `findings` | Code-level crypto detections with full migration lifecycle |
| `secret_findings` | SSH/TLS/GPG/config detections with certificate metadata |
| `cbom_entries` | Aggregated crypto asset inventory (total usages, affected repos, risk score) |

### Finding Migration Lifecycle

```
open
 ├──► manually_resolved  (developer resolves with migrated_to evidence)
 ├──► auto_resolved      (not detected in 2 consecutive scans)
 └──► re_opened          (regression — finding reappears after resolution)

any state ──► archived   (soft-delete, kept for audit trail)
```

### SQL Migrations

Located in `backend/migrations/`:
- `add_agility_and_migration_tracking.sql` — Agility fields on Repo, migration tracking on Finding
- `add_resolution_fields.sql` — Archive fields on Finding and SecretFinding
- `deduplicate_findings.sql` — Removes duplicate `(scan_run_id, algo, line)` entries

---

## CLI Tool

Standalone scanner — no server required. Useful for local development and CI pipelines.

```bash
# Scan a local directory
python cli_scan.py /path/to/repo

# Scan a remote GitHub repo
python cli_scan.py https://github.com/org/repo --branch main

# Output formats
python cli_scan.py /path/to/repo --format table      # Colored table (default)
python cli_scan.py /path/to/repo --format json
python cli_scan.py /path/to/repo --format csv
python cli_scan.py /path/to/repo --format cyclonedx

# Filter and CI gating
python cli_scan.py /path/to/repo --min-risk HIGH
python cli_scan.py /path/to/repo --fail-on CRITICAL  # Exits with code 1 if threshold met

# Skip secrets scanning
python cli_scan.py /path/to/repo --no-secrets
```

**Environment variables:**
```bash
GITHUB_TOKEN=ghp_xxx        # For private GitHub repos
GITLAB_TOKEN=glpat_xxx      # For GitLab repos
BITBUCKET_TOKEN=user:pass   # For Bitbucket repos
```

---

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/pqc-scan.yml`) runs on every push, PR, and weekly schedule.

**What it does:**
1. Scans the repository for vulnerable crypto
2. Posts a findings table as a PR comment (🔴 CRITICAL, 🟡 HIGH)
3. Fails the PR check if CRITICAL findings are found
4. On merge to main — pushes findings to the PQCScanner API and rebuilds CBOM

**Setup — add these GitHub Secrets:**

```
PQC_API_URL    = https://your-pqc-platform.com
PQC_API_TOKEN  = your-api-token
GITHUB_TOKEN   = (auto-provided by GitHub Actions)
```

---

## NIST PQC Standards (2024)

| Standard | Algorithm | Replaces |
|---|---|---|
| **FIPS 203** | ML-KEM (Kyber) | RSA/ECDH key exchange |
| **FIPS 204** | ML-DSA (Dilithium) | RSA-sign/ECDSA signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Stateless hash-based signatures |

---

## Configuration

### Environment Variables (`.env`)

```env
DATABASE_URL=postgresql://pqc_user:pqc_pass@localhost:5432/pqc_platform
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=change-me-in-production

# Git provider tokens (set as needed)
GITHUB_TOKEN=ghp_xxx
GITHUB_ENTERPRISE_TOKEN=
GITLAB_TOKEN=glpat_xxx
BITBUCKET_TOKEN=user:app_password
GITEA_TOKEN=

# Optional SSH key auth alternative
SSH_KEY_PATH=/run/secrets/id_rsa

# Scan worker concurrency
SCAN_WORKERS=4
```

### Docker Compose Services

| Service | Image | Port |
|---|---|---|
| PostgreSQL | postgres:16-alpine | 5432 |
| Redis | redis:7-alpine | 6379 |
| Backend (FastAPI) | python:3.12 | 8000 |
| Frontend (Vite) | node:latest | 5173 |

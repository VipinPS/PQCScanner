---
sidebar_position: 1
title: Introduction
slug: /intro
---

# Getting Started with PQCScanner

PQCScanner is an open-source tool that scans codebases for quantum-vulnerable cryptography and helps engineering teams migrate to post-quantum-safe algorithms. It identifies weak crypto usage across source code, dependencies, secrets, and binary artifacts -- then generates actionable migration plans.

## What It Does

- **Scans 15+ languages** for 26+ cryptographic patterns (RSA, ECDSA, AES-CBC, SHA-1, and more)
- **Exports CBOM** (Cryptography Bill of Materials) in CycloneDX 1.5 format
- **Scores crypto agility** on a five-level scale (L1 through L5)
- **Reduces false positives** via path exclusions, call-graph reachability analysis, and AI-powered validation
- **Integrates with CI/CD** pipelines for automated quality gates
- **Monitors at runtime** using eBPF probes and TLS network scanning

## Tech Stack

### Frontend

| Tool | Purpose |
| ---- | ------- |
| React | Component-based SPA |
| Vite | Build tool and dev server |
| Carbon Design System | UI components (dark theme) |
| Native `fetch` API | HTTP client |
| React Hooks | State management |

### Backend

| Tool | Version | Purpose |
| ---- | ------- | ------- |
| FastAPI | 0.111.0 | REST API framework |
| Uvicorn | 0.29.0 | ASGI server |
| SQLAlchemy | 2.0.30 | ORM |
| Pydantic | 2.7.1 | Data validation |
| Celery | 5.4.0 | Async task queue |
| Redis (Python) | 5.0.4 | Cache and message broker |
| GitPython | 3.1.43 | Remote repo cloning |
| Paramiko | 3.5.1 | SSH key parsing |
| cryptography | latest | X.509 cert and PKCS#12 parsing |
| Python | 3.12 | Runtime |

### Infrastructure

| Tool | Version | Purpose |
| ---- | ------- | ------- |
| PostgreSQL | 16-alpine | Primary database |
| Redis | 7-alpine | Cache and Celery broker |
| Ollama | latest | Local LLM for AI validation |
| Docker + Docker Compose | latest | Container orchestration |

## Prerequisites

- Docker and Docker Compose v2
- 8 GB RAM minimum (16 GB recommended for AI validation)
- Git

## Quick Start

Clone the repository and start all services:

```bash
git clone https://github.com/VipinPS/PQCScanner.git
cd PQCScanner
docker compose up -d
```

This brings up eight containers: the FastAPI backend, the React/Vite frontend, PostgreSQL, Redis, an Ollama instance for AI validation, and supporting services.

Once everything is running, open **http://localhost:5173** for the dashboard.

### Run Your First Scan

1. Navigate to **Scans** in the sidebar.
2. Click **New Scan** and provide a repository URL or upload a project archive.
3. Select scan targets (source, dependencies, secrets, artifacts).
4. Review results on the findings page. Export a CBOM from the **Export** menu.

## Next Steps

- [Scanning capabilities](/docs/features/scanning) -- learn about supported languages and scan types
- [CBOM export](/docs/features/cbom) -- understand the Cryptography Bill of Materials output
- [Architecture](/docs/architecture) -- explore how the platform components fit together

---
sidebar_position: 4
title: Architecture
---

# Architecture

PQCScanner is a containerized application composed of eight services orchestrated by Docker Compose. This page describes the high-level architecture and the role of each component.

## System Diagram

```
                          +------------------+
                          |   React / Vite   |
                          |    Frontend      |
                          |   (port 5173)    |
                          +--------+---------+
                                   |
                                   | REST API
                                   v
                          +--------+---------+
                          |   FastAPI         |
                          |   Backend         |
                          |   (port 8000)     |
                          +--+-----+------+--+
                             |     |      |
                +------------+     |      +-------------+
                |                  |                     |
                v                  v                     v
        +-------+------+  +-------+------+  +-----------+----+
        |  PostgreSQL   |  |    Redis     |  |    Ollama       |
        |  (port 5432)  |  |  (port 6379) |  |  AI Validation  |
        +--------------+   +--------------+  +----------------+
                |                  |
                v                  v
        +-------+------+  +-------+------+
        |  Scan Worker  |  |  eBPF Agent  |
        |  (Celery)     |  |  (runtime)   |
        +--------------+   +--------------+
                |
                v
        +-------+------+
        |  TLS Scanner  |
        |  (network)    |
        +--------------+
```

## Component Overview

### Frontend (React / Vite)

Single-page application providing the dashboard, scan management, findings explorer, and CBOM export UI. Communicates exclusively through the REST API.

### Backend (FastAPI)

Core application server exposing 68 REST API endpoints. Handles authentication, scan orchestration, finding aggregation, CBOM generation, and CI/CD webhook integrations. Runs with Uvicorn on port 8000.

### PostgreSQL

Primary data store for scan metadata, findings, user accounts, project configuration, and CBOM records. Schema migrations are managed with Alembic.

### Redis

Used for two purposes: as a Celery message broker for asynchronous task dispatch, and as a caching layer for frequently accessed scan summaries and configuration.

### Scan Worker (Celery)

Background workers that execute the actual scanning logic. Each worker pulls tasks from Redis, runs the appropriate scan mode (source, dependency, secrets, artifact), and writes results back to PostgreSQL. Workers scale horizontally.

### Ollama (AI Validation)

Runs a local LLM for false-positive classification. The backend sends code context snippets to Ollama and receives confidence-scored classifications. No data leaves the deployment.

### eBPF Agent

Optional component that attaches eBPF probes to monitored processes for runtime crypto observation. Requires Linux kernel 5.8+ and `CAP_BPF` capability. Reports findings back to the backend via internal API.

### TLS Scanner

Connects to configured network endpoints, performs TLS handshakes, and reports negotiated parameters (protocol version, cipher suite, certificate key type). Results are stored as network-type findings.

## Data Flow

1. A user or CI/CD pipeline triggers a scan via the REST API or dashboard.
2. The backend validates the request and enqueues scan tasks in Redis.
3. Celery workers pick up tasks, execute scans, and persist raw findings to PostgreSQL.
4. The backend runs the false-positive reduction pipeline (path exclusion, reachability, AI validation).
5. Final findings are available via the API. CBOM export aggregates findings into CycloneDX format.
6. Optional runtime and network scans run continuously and feed findings into the same pipeline.

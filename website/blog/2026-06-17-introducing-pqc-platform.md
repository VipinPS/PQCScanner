---
slug: introducing-pqc-platform
title: Introducing PQCScanner
authors:
  - name: PQCScanner Team
tags: [announcement, post-quantum, cryptography]
date: 2026-06-17
---

# Introducing PQCScanner

Quantum computers capable of breaking RSA and elliptic-curve cryptography are no longer a distant possibility. NIST has finalized its first post-quantum standards, and organizations worldwide are beginning the long process of migrating their cryptographic infrastructure. The first step in any migration is knowing what you have -- and that is exactly what PQCScanner does.

<!-- truncate -->

## The Problem

Most codebases contain cryptographic dependencies scattered across application code, configuration files, third-party libraries, and runtime environments. Manually inventorying these assets is slow, error-prone, and incomplete. Teams need automated tooling that can scan broadly, report precisely, and integrate into existing development workflows.

## What PQCScanner Provides

PQCScanner is an open-source tool that scans your codebase for quantum-vulnerable cryptography and helps you plan the migration to post-quantum-safe algorithms.

Key capabilities:

- **Multi-language scanning** across 15+ languages, detecting 26+ cryptographic patterns in source code, dependency manifests, secrets, and binary artifacts
- **CBOM generation** in CycloneDX 1.5 format, giving you a machine-readable inventory of every cryptographic asset
- **Crypto agility scoring** on a five-level scale (L1 through L5), measuring how easily your codebase can adopt new algorithms
- **False positive reduction** through path-based exclusions, call-graph reachability analysis, and AI-powered validation using a local Ollama instance
- **CI/CD integration** with configurable quality gates that fail builds when new quantum-vulnerable crypto is introduced
- **Runtime monitoring** via eBPF probes and TLS network scanning for visibility into what algorithms are actually negotiated in production

## Built for Real Workflows

The platform deploys as a set of Docker containers (FastAPI backend, React frontend, PostgreSQL, Redis, Celery workers, Ollama, and optional eBPF and TLS scanners). A single `docker compose up` gets you running. The 68-endpoint REST API makes it straightforward to integrate with existing toolchains.

## Get Started

Visit the [documentation](/docs/intro) to set up PQCScanner, or browse the source on [GitHub](https://github.com/VipinPS/PQCScanner).

We welcome contributions -- whether that means adding detection patterns for new languages, improving the reachability analysis engine, or writing documentation.

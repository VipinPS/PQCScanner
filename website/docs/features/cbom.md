---
sidebar_position: 2
title: CBOM Export
---

# Cryptography Bill of Materials (CBOM)

PQCScanner generates a Cryptography Bill of Materials (CBOM) conforming to the **CycloneDX 1.5** specification. A CBOM provides a complete inventory of every cryptographic asset discovered in your codebase, giving security teams and auditors a clear picture of quantum readiness.

## What Is a CBOM?

A CBOM is a machine-readable document that catalogs:

- **Algorithms** in use (e.g., RSA-2048, AES-256-GCM, SHA-256)
- **Key sizes and parameters** for each cryptographic operation
- **Locations** where each algorithm appears (file, line, dependency)
- **Quantum-vulnerability classification** per finding
- **Crypto agility score** for the overall project

## Crypto Agility Scoring

Each scanned project receives an agility score on a five-level scale:

| Level | Description |
|---|---|
| L1 | Hard-coded algorithms with no abstraction; migration requires rewriting |
| L2 | Algorithm names are configurable but tightly coupled to specific libraries |
| L3 | Crypto operations use an abstraction layer; swapping algorithms requires moderate effort |
| L4 | Algorithm selection is policy-driven and externally configurable |
| L5 | Fully agile -- algorithms can be rotated at runtime without code changes |

## Export Formats

The primary export format is CycloneDX 1.5 JSON. Additional formats are available:

- **CycloneDX XML** -- for toolchains that require XML input
- **CSV summary** -- lightweight tabular export for spreadsheet workflows
- **PDF report** -- formatted report suitable for management review

## Generating a CBOM

From the dashboard, navigate to a completed scan and click **Export CBOM**. Via the API:

```bash
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/export \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "cyclonedx-json"}'
```

The response contains the full CBOM document. For large projects, use the asynchronous export endpoint, which returns a task ID for polling.

## Integration with Compliance Workflows

CBOM exports can be fed into existing software composition analysis (SCA) pipelines, governance platforms, or submitted directly to auditors. The CycloneDX format is supported by OWASP Dependency-Track, Grype, and other tools in the software supply chain ecosystem.

---
sidebar_position: 1
title: Scanning Capabilities
---

# Scanning Capabilities

PQCScanner provides five distinct scan modes, each targeting a different layer of your technology stack. All modes feed into the same findings pipeline and contribute to CBOM generation.

## Source Code Scanning

The source scanner uses pattern-based detection enhanced with AST-level analysis to locate cryptographic API calls, algorithm constants, and key-size declarations. It supports **15+ languages** including Python, Java, Go, Rust, C/C++, JavaScript/TypeScript, C#, Ruby, PHP, Kotlin, Swift, and Scala.

Detection covers **26+ cryptographic patterns**:

| Category | Examples |
|---|---|
| Asymmetric ciphers | RSA, DSA, ECDSA, ECDH, DH |
| Symmetric ciphers | AES-CBC, DES, 3DES, RC4, Blowfish |
| Hash functions | MD5, SHA-1, SHA-224 |
| Key exchange | Static DH, non-ephemeral ECDH |
| Signatures | RSA-PKCS1v15, DSA |
| Key sizes | RSA < 3072, ECC < 256 |

## Dependency Scanning

Parses lock files and manifests (requirements.txt, go.sum, package-lock.json, Cargo.lock, pom.xml, and more) to identify libraries that bundle or expose quantum-vulnerable cryptographic primitives.

## Secrets Scanning

Detects hard-coded keys, certificates, and PEM-encoded material embedded in source files and configuration. Flags quantum-vulnerable key types (RSA, ECDSA) with their bit strengths.

## Binary Artifact Scanning

Inspects compiled binaries, JARs, and container images for linked crypto libraries and embedded algorithm identifiers. Useful for auditing third-party components where source is unavailable.

## Runtime Monitoring

Deploys eBPF probes to observe cryptographic operations at runtime. Captures live TLS handshakes, cipher suite negotiation, and certificate chains. This mode requires a Linux host with kernel 5.8 or later.

## Network TLS Scanning

Connects to specified endpoints and inspects negotiated TLS parameters: protocol version, cipher suite, certificate key type, and signature algorithm. Results are mapped to quantum-vulnerability classifications.

## Scan Configuration

Scans are configured through the REST API or the dashboard UI. Key options:

- **Target selection** -- choose which scan modes to enable per run
- **Path exclusions** -- skip vendor directories, test fixtures, or generated code
- **Severity thresholds** -- set minimum severity for CI/CD gate failures
- **Concurrency** -- control parallel scanning workers (default: 4)

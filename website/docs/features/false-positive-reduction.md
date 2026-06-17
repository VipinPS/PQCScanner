---
sidebar_position: 3
title: False Positive Reduction
---

# False Positive Reduction

Crypto scanners are notoriously noisy. PQCScanner combines three complementary techniques to suppress false positives and keep findings actionable.

## Path-Based Exclusions

Not every match matters. Test fixtures, vendored dependencies, documentation snippets, and generated code frequently trigger crypto pattern detectors without representing real risk. PQCScanner applies configurable path exclusion rules to filter these out:

- Default exclusions: `**/test/**`, `**/vendor/**`, `**/node_modules/**`, `**/*.md`
- Custom exclusions can be added per project or per scan run
- Exclusions are logged and auditable -- they appear in the scan report with a "suppressed" status

## Call-Graph Reachability Analysis

A pattern match in source code does not mean the code is executed. PQCScanner builds a call graph from scan targets and traces whether flagged crypto calls are reachable from application entry points.

How it works:

1. **Entry point detection** -- identifies main functions, HTTP handlers, CLI entry points, and event listeners
2. **Graph construction** -- builds a static call graph across the scanned module
3. **Reachability check** -- marks each finding as reachable or unreachable from any entry point
4. **Confidence scoring** -- assigns a confidence level based on graph completeness and language support

Unreachable findings are demoted to informational severity by default. You can configure the behavior to suppress them entirely or keep them at their original severity.

## AI-Powered Validation

For findings that survive path exclusion and reachability checks, PQCScanner offers an optional AI validation step powered by Ollama. The validator examines the surrounding code context and classifies whether the flagged pattern is:

- **True positive** -- a real cryptographic operation using a quantum-vulnerable algorithm
- **False positive** -- a benign match (e.g., a variable name, a comment, a test constant)
- **Uncertain** -- insufficient context for a confident classification

AI validation runs locally via Ollama -- no data leaves your infrastructure. The model evaluates:

- Whether the matched token is part of an actual crypto API call
- Whether the enclosing function performs cryptographic work
- Whether the algorithm is used in a security-relevant context

### Configuration

Enable AI validation in the scan configuration:

```json
{
  "ai_validation": {
    "enabled": true,
    "model": "llama3",
    "confidence_threshold": 0.8
  }
}
```

Findings below the confidence threshold are flagged for manual review rather than auto-suppressed.

## Combined Pipeline

The three techniques run in sequence:

1. Path exclusions (fast, rule-based)
2. Reachability analysis (medium cost, static analysis)
3. AI validation (higher cost, applied only to surviving findings)

This layered approach typically reduces false positive rates by 60-80% compared to pattern matching alone, while preserving true positive recall.

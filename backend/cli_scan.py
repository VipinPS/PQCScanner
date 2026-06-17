#!/usr/bin/env python3
"""
pqc-scan — standalone CLI for the PQCScanner scanner.

Usage:
  # Scan a local directory
  python cli_scan.py /path/to/repo

  # Clone and scan a remote repo (requires token in env or --token flag)
  python cli_scan.py https://github.com/org/repo --branch main

  # Output formats
  python cli_scan.py /path/to/repo --format table      # default
  python cli_scan.py /path/to/repo --format json
  python cli_scan.py /path/to/repo --format csv
  python cli_scan.py /path/to/repo --format cyclonedx

  # Filter by risk level
  python cli_scan.py /path/to/repo --min-risk HIGH

  # Exit with non-zero code if CRITICAL findings found (for CI gating)
  python cli_scan.py /path/to/repo --fail-on CRITICAL
"""
import argparse
import csv
import json
import os
import sys
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root or backend/
sys.path.insert(0, str(Path(__file__).parent))

from app.scanner.engine import CryptoScanner, clone_repo
from app.scanner.file_secrets import FileSecretsScanner

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def _filter(findings, min_risk):
    if not min_risk:
        return findings
    threshold = RISK_ORDER.get(min_risk.upper(), 99)
    return [f for f in findings if RISK_ORDER.get(f.risk_level, 99) <= threshold]


def _print_table(findings, secret_findings):
    if not findings and not secret_findings:
        print("No findings.")
        return

    RISK_COLOURS = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM":   "\033[33m", "LOW":  "\033[92m",
        "SAFE":     "\033[92m",
    }
    RESET = "\033[0m"

    def colour(risk, text):
        return f"{RISK_COLOURS.get(risk, '')}{text}{RESET}" if sys.stdout.isatty() else text

    fmt = "{:<40} {:>6}  {:<20}  {:<10}  {:<12}  {}"
    header = fmt.format("File", "Line", "Algorithm", "Risk", "Status", "Replacement")
    print(header)
    print("-" * len(header))

    for f in sorted(findings, key=lambda x: (RISK_ORDER.get(x.risk_level, 99), x.file_path)):
        path = f.file_path if len(f.file_path) <= 40 else "…" + f.file_path[-38:]
        print(fmt.format(
            path, f.line_number,
            colour(f.risk_level, f.algorithm[:20]),
            colour(f.risk_level, f.risk_level),
            f.quantum_status[:12],
            (f.nist_replacement or "")[:40],
        ))

    for s in sorted(secret_findings, key=lambda x: RISK_ORDER.get(x.risk_level, 99)):
        path = s.file_path if len(s.file_path) <= 40 else "…" + s.file_path[-38:]
        print(fmt.format(
            path, "[secret]",
            colour(s.risk_level, s.algorithm[:20]),
            colour(s.risk_level, s.risk_level or ""),
            s.quantum_status[:12] if s.quantum_status else "",
            (s.nist_replacement or "")[:40],
        ))

    counts = {}
    for f in findings:
        counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
    print()
    summary = "  ".join(
        f"{colour(r, r)}: {counts[r]}"
        for r in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if r in counts
    )
    print(f"Total: {len(findings) + len(secret_findings)} findings  |  {summary}")


def _print_json(findings, secret_findings):
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(findings) + len(secret_findings),
        "code_findings": [
            {
                "file": f.file_path, "line": f.line_number,
                "algorithm": f.algorithm, "type": f.algo_type,
                "risk": f.risk_level, "quantum_status": f.quantum_status,
                "nist_replacement": f.nist_replacement,
                "context": f.context,
            }
            for f in findings
        ],
        "secret_findings": [
            {
                "file": s.file_path,
                "algorithm": s.algorithm, "type": s.finding_type,
                "risk": s.risk_level, "quantum_status": s.quantum_status,
                "nist_replacement": s.nist_replacement,
            }
            for s in secret_findings
        ],
    }
    print(json.dumps(out, indent=2))


def _print_csv(findings, secret_findings):
    writer = csv.writer(sys.stdout)
    writer.writerow(["source", "file", "line", "algorithm", "type",
                     "risk_level", "quantum_status", "nist_replacement"])
    for f in findings:
        writer.writerow(["code", f.file_path, f.line_number, f.algorithm,
                         f.algo_type, f.risk_level, f.quantum_status,
                         f.nist_replacement or ""])
    for s in secret_findings:
        writer.writerow(["secret", s.file_path, "", s.algorithm,
                         s.finding_type, s.risk_level or "", s.quantum_status or "",
                         s.nist_replacement or ""])


def _print_cyclonedx(findings, secret_findings, repo_name):
    from collections import defaultdict
    occ = defaultdict(list)
    algo_meta = {}
    for f in findings:
        occ[f.algorithm].append(f"{f.file_path}#{f.line_number}")
        algo_meta[f.algorithm] = {"type": f.algo_type, "quantum_status": f.quantum_status,
                                  "nist_replacement": f.nist_replacement}
    for s in secret_findings:
        occ[s.algorithm].append(s.file_path)
        if s.algorithm not in algo_meta:
            algo_meta[s.algorithm] = {"type": s.finding_type,
                                      "quantum_status": s.quantum_status,
                                      "nist_replacement": s.nist_replacement}
    _QSL = {"SAFE": 3, "MONITOR": 2, "WEAK": 1, "VULNERABLE": 0, "BROKEN": 0}
    components = []
    for algo, meta in algo_meta.items():
        comp = {
            "type": "cryptographic-asset", "bom-ref": str(uuid.uuid4()),
            "name": algo,
            "cryptoProperties": {
                "assetType": meta["type"],
                "algorithmProperties": {
                    "nistQuantumSecurityLevel": _QSL.get(meta["quantum_status"], 0)
                },
            },
            "x-pqc-status": meta["quantum_status"],
            "x-nist-replacement": meta["nist_replacement"],
        }
        if occ[algo]:
            comp["evidence"] = {"occurrences": [{"location": l} for l in occ[algo]]}
        components.append(comp)

    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": repo_name},
        },
        "components": components,
    }
    print(json.dumps(bom, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="pqc-scan",
        description="Scan a repository for quantum-vulnerable cryptography.",
    )
    parser.add_argument("target", help="Local directory path or remote Git URL")
    parser.add_argument("--branch", default="main", help="Branch to clone (default: main)")
    parser.add_argument("--token", default="", help="Git token (or set GITHUB_TOKEN env var)")
    parser.add_argument(
        "--format", choices=["table", "json", "csv", "cyclonedx"],
        default="table", help="Output format (default: table)",
    )
    parser.add_argument(
        "--min-risk", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None, help="Only show findings at or above this risk level",
    )
    parser.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Exit with code 1 if any findings at or above this risk level exist",
    )
    parser.add_argument("--no-secrets", action="store_true",
                        help="Skip SSH key / TLS cert secret scanning")
    args = parser.parse_args()

    tmp_dir = None
    target = args.target

    try:
        # ── Clone if remote URL ────────────────────────────────────────────────
        if target.startswith("http://") or target.startswith("https://"):
            token = args.token or os.environ.get("GITHUB_TOKEN", "")
            print(f"Cloning {target} (branch: {args.branch}) …", file=sys.stderr)
            tmp_dir = clone_repo(target, token=token, branch=args.branch)
            scan_path = tmp_dir
            repo_name = target.rstrip("/").split("/")[-1]
        else:
            scan_path = os.path.abspath(target)
            repo_name = Path(scan_path).name
            if not os.path.isdir(scan_path):
                print(f"Error: '{scan_path}' is not a directory.", file=sys.stderr)
                sys.exit(2)

        # ── Source code scan ──────────────────────────────────────────────────
        def progress(done, total):
            print(f"\rScanning files: {done}/{total}", end="", file=sys.stderr)

        scanner = CryptoScanner(progress_callback=progress)
        result = scanner.scan_directory(scan_path)
        print(file=sys.stderr)  # newline after progress

        findings = _filter(result.findings, args.min_risk)

        # ── Secret scan ───────────────────────────────────────────────────────
        secret_findings = []
        if not args.no_secrets:
            try:
                raw_secrets = FileSecretsScanner().scan_directory(scan_path)
                for s in raw_secrets:
                    s.file_path = os.path.relpath(s.file_path, scan_path)
                secret_findings = _filter(raw_secrets, args.min_risk)
            except Exception as e:
                print(f"Warning: secret scan failed: {e}", file=sys.stderr)

        # ── Output ────────────────────────────────────────────────────────────
        if args.format == "table":
            _print_table(findings, secret_findings)
        elif args.format == "json":
            _print_json(findings, secret_findings)
        elif args.format == "csv":
            _print_csv(findings, secret_findings)
        elif args.format == "cyclonedx":
            _print_cyclonedx(findings, secret_findings, repo_name)

        # ── Agility summary ───────────────────────────────────────────────────
        if result.agility and args.format == "table":
            ag = result.agility
            print(f"\nCrypto Agility: L{ag.level} — {ag.label}", file=sys.stderr)

        # ── CI gating ─────────────────────────────────────────────────────────
        if args.fail_on:
            threshold = RISK_ORDER[args.fail_on.upper()]
            gate_hits = [
                f for f in findings + secret_findings
                if RISK_ORDER.get(f.risk_level, 99) <= threshold
            ]
            if gate_hits:
                print(
                    f"\n✖ {len(gate_hits)} finding(s) at or above {args.fail_on} — failing.",
                    file=sys.stderr,
                )
                sys.exit(1)

    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

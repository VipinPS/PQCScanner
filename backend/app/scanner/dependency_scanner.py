"""
Dependency Scanner — Phase 1.1
Parses package manifests, cross-references against a curated crypto-vulnerable
package list, and queries OSV.dev for additional CVE coverage.

Supported manifests:
  Python  : requirements.txt, pyproject.toml, poetry.lock, Pipfile
  Node.js : package.json
  Go      : go.mod
  Rust    : Cargo.toml
  Java    : pom.xml
  Ruby    : Gemfile.lock
"""

import os
import re
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OSV_API_URL  = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT  = 30   # seconds

# ── Curated crypto-vulnerable package map ─────────────────────────────────────
# Key: (ecosystem_lower, package_name_lower)
# vulnerable_below=None means ALL versions are flagged (e.g. abandoned libs)
CRYPTO_PACKAGE_MAP = {
    ("pypi", "cryptography"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Widely-used crypto library — provides RSA/ECDSA/AES/TLS primitives, all quantum-vulnerable; no PQC support yet",
    },
    ("pypi", "pyopenssl"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "PyOpenSSL wraps OpenSSL RSA/ECDSA/TLS — all quantum-vulnerable algorithms exposed",
    },
    ("pypi", "python-jose"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "3.3.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 3.3.0 had algorithm confusion (CVE-2022-29217); RS256/RS512 JWT signing is quantum-vulnerable",
    },
    ("pypi", "authlib"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "1.2.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "OAuth2/OIDC library using RSA-based JWT — quantum-vulnerable; versions < 1.2.0 had validation issues",
    },
    ("pypi", "jwcrypto"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "1.5.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "JWE/JWS/JWT library using RSA/ECDSA — quantum-vulnerable",
    },
    ("pypi", "pycrypto"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Abandoned library (last release 2014); implements RSA/DES/MD5 — quantum-vulnerable with known CVEs",
    },
    ("pypi", "pycryptodome"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Provides RSA/ECDSA/DES/MD5 — all quantum-vulnerable; migrate to post-quantum primitives",
    },
    ("pypi", "pyjwt"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "2.4.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 2.4.0 default to RS256 (RSA-based JWT signing) — quantum-vulnerable",
    },
    ("pypi", "paramiko"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "3.0.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 hybrid (FIPS 203)",
        "reason": "Versions < 3.0.0 use RSA/DSA host key algorithms by default in SSH connections",
    },
    ("pypi", "pydes"): {
        "algorithm": "DES", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "BROKEN",
        "nist_replacement": "AES-256-GCM",
        "reason": "Implements DES/3DES — classically broken cipher, quantum-vulnerable",
    },
    ("pypi", "m2crypto"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "OpenSSL wrapper — exposes RSA/ECDSA which are quantum-vulnerable",
    },
    ("pypi", "rsa"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Pure-Python RSA implementation — quantum-vulnerable; no PQC support",
    },
    ("pypi", "ecdsa"): {
        "algorithm": "ECDSA", "algo_type": "Signature",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Pure-Python ECDSA implementation — quantum-vulnerable elliptic curve signatures",
    },
    ("pypi", "pyotp"): {
        "algorithm": "SHA-1", "algo_type": "Hash",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "WEAK",
        "nist_replacement": "TOTP with SHA-256 (RFC 6238)",
        "reason": "Uses HMAC-SHA1 by default for TOTP generation — SHA-1 is quantum-weak",
    },
    # ── Node.js (npm) ─────────────────────────────────────────────────────────
    ("npm", "jsonwebtoken"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "9.0.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 9.0.0 defaulted to RS256 and had CVE-2022-23529; RS256 is quantum-vulnerable",
    },
    ("npm", "node-forge"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "1.3.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203)",
        "reason": "Versions < 1.3.0 had RSA verification bypass (CVE-2022-0122); all versions use quantum-vulnerable RSA",
    },
    ("npm", "md5"): {
        "algorithm": "MD5", "algo_type": "Hash",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "BROKEN",
        "nist_replacement": "SHA-3-256",
        "reason": "MD5 hash — classically broken (collision attacks) and quantum-vulnerable",
    },
    ("npm", "sha1"): {
        "algorithm": "SHA-1", "algo_type": "Hash",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "WEAK",
        "nist_replacement": "SHA-3-256",
        "reason": "SHA-1 hash — weakened by SHAttered attack; quantum-weak",
    },
    ("npm", "crypto-js"): {
        "algorithm": "MD5", "algo_type": "Hash",
        "vulnerable_below": "4.2.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "SHA-3-256 / AES-256-GCM",
        "reason": "Versions < 4.2.0 include MD5/SHA1/DES implementations and weak PRNG",
    },
    ("npm", "des.js"): {
        "algorithm": "DES", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "BROKEN",
        "nist_replacement": "AES-256-GCM",
        "reason": "Implements DES/3DES — classically broken cipher",
    },
    ("npm", "jsrsasign"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "10.5.25",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 10.5.25 had signature verification bypass; all versions use quantum-vulnerable RSA/ECDSA",
    },
    # ── Java (Maven) ──────────────────────────────────────────────────────────
    ("maven", "bcprov-jdk15on"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "1.70",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Bouncy Castle < 1.70 has known CVEs; all versions provide quantum-vulnerable RSA/ECDSA",
    },
    ("maven", "bcprov-jdk18on"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Bouncy Castle provides quantum-vulnerable RSA/ECDSA — use PQC extensions",
    },
    ("maven", "nimbus-jose-jwt"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "9.37.2",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 9.37.2 had parsing vulnerabilities; RS256 default is quantum-vulnerable",
    },
    ("maven", "jose4j"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "0.9.4",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "JWT library using RSA-based signing — quantum-vulnerable",
    },
    ("maven", "jasypt"): {
        "algorithm": "MD5", "algo_type": "Hash",
        "vulnerable_below": "1.9.3",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "Argon2id / AES-256-GCM",
        "reason": "Versions < 1.9.3 default to MD5-based encryption; weak key derivation",
    },
    # ── Go ────────────────────────────────────────────────────────────────────
    ("go", "github.com/dgrijalva/jwt-go"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Abandoned (CVE-2020-26160); uses RSA-based JWT signing — quantum-vulnerable. Migrate to github.com/golang-jwt/jwt/v5",
    },
    ("go", "github.com/golang-jwt/jwt"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "4.5.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 4.5.0 had algorithm confusion vulnerability; RS256 is quantum-vulnerable",
    },
    # ── Rust (crates.io) ──────────────────────────────────────────────────────
    ("crates.io", "md5"): {
        "algorithm": "MD5", "algo_type": "Hash",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "BROKEN",
        "nist_replacement": "SHA-3-256",
        "reason": "MD5 hash implementation — classically broken and quantum-vulnerable",
    },
    ("crates.io", "sha1"): {
        "algorithm": "SHA-1", "algo_type": "Hash",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "WEAK",
        "nist_replacement": "SHA-3-256",
        "reason": "SHA-1 hash implementation — weakened by SHAttered attack",
    },
    ("crates.io", "rsa"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "0.9.6",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203)",
        "reason": "Versions < 0.9.6 had timing side-channel (RUSTSEC-2023-0071); all versions quantum-vulnerable",
    },
    ("crates.io", "des"): {
        "algorithm": "DES", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "CRITICAL", "quantum_status": "BROKEN",
        "nist_replacement": "AES-256-GCM",
        "reason": "DES cipher implementation — classically broken",
    },
    # ── Python OpenSSL / TLS bindings ────────────────────────────────────────
    ("pypi", "m2crypto"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "M2Crypto wraps OpenSSL RSA/DSA/ECDSA/TLS — all quantum-vulnerable algorithms exposed",
    },
    ("pypi", "twisted"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Twisted TLS/SSL uses OpenSSL RSA/ECDSA under the hood — quantum-vulnerable; no PQC support",
    },
    # ── Python SSH / remote execution ─────────────────────────────────────────
    ("pypi", "fabric"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Fabric uses Paramiko for SSH — RSA/ECDSA key exchange is quantum-vulnerable",
    },
    ("pypi", "invoke"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": None,
        "risk_level": "MEDIUM", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "reason": "Invoke (Fabric dependency) may invoke SSH via Paramiko — quantum-vulnerable key exchange",
    },
    # ── Python HTTP / network clients ─────────────────────────────────────────
    ("pypi", "httplib2"): {
        "algorithm": "RSA-2048", "algo_type": "Asymmetric",
        "vulnerable_below": "0.22.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "httpx with TLS 1.3 / ML-KEM post-quantum TLS",
        "reason": "httplib2 < 0.22.0 had SSRF and cert validation issues; TLS transport uses RSA/ECDSA — quantum-vulnerable",
    },
    # ── Python password hashing ───────────────────────────────────────────────
    ("pypi", "bcrypt"): {
        "algorithm": "Blowfish", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "Argon2id (quantum-safe KDF)",
        "reason": "bcrypt uses Blowfish cipher — Grover's algorithm halves effective key strength; migrate to Argon2id for password hashing",
    },
    ("pypi", "passlib"): {
        "algorithm": "Blowfish", "algo_type": "Symmetric",
        "vulnerable_below": "1.7.4",
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "Argon2id (quantum-safe KDF)",
        "reason": "passlib bcrypt backend uses Blowfish — quantum-weak; upgrade to Argon2id handler",
    },
    ("pypi", "itsdangerous"): {
        "algorithm": "HMAC-SHA1", "algo_type": "Signature",
        "vulnerable_below": "2.0.0",
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "HMAC-SHA256 / ML-DSA-65 (FIPS 204)",
        "reason": "Versions < 2.0.0 default to HMAC-SHA1 for token signing — SHA-1 is quantum-weak",
    },
    ("pypi", "django"): {
        "algorithm": "PBKDF2-SHA256", "algo_type": "Symmetric",
        "vulnerable_below": "4.2.0",
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "Argon2id (quantum-safe KDF) — enable django.contrib.auth.hashers.Argon2PasswordHasher",
        "reason": "Django < 4.2 defaults to PBKDF2-SHA256 for password hashing; Argon2id is the quantum-safe alternative",
    },
    ("pypi", "flask"): {
        "algorithm": "HMAC-SHA1", "algo_type": "Signature",
        "vulnerable_below": "2.3.0",
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "HMAC-SHA256 / ML-DSA-65 (FIPS 204)",
        "reason": "Flask < 2.3 session cookies signed with HMAC-SHA1 via Werkzeug — quantum-weak",
    },
    # ── Node.js additional ────────────────────────────────────────────────────
    ("npm", "bcrypt"): {
        "algorithm": "Blowfish", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "Argon2id (quantum-safe KDF)",
        "reason": "bcrypt uses Blowfish cipher — Grover's algorithm halves effective key strength; migrate to Argon2id",
    },
    ("npm", "bcryptjs"): {
        "algorithm": "Blowfish", "algo_type": "Symmetric",
        "vulnerable_below": None,
        "risk_level": "MEDIUM", "quantum_status": "WEAK",
        "nist_replacement": "Argon2id (quantum-safe KDF)",
        "reason": "bcryptjs uses Blowfish cipher — quantum-weak symmetric; migrate to Argon2id",
    },
    ("npm", "passport"): {
        "algorithm": "JWT-RS256", "algo_type": "Signature",
        "vulnerable_below": "0.6.0",
        "risk_level": "HIGH", "quantum_status": "VULNERABLE",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "reason": "Passport.js < 0.6.0 had session fixation; JWT strategy uses RSA-based RS256 — quantum-vulnerable",
    },
}

# Keywords that indicate a CVE is crypto-relevant
CRYPTO_CVE_KEYWORDS = [
    "cryptograph", "cipher", "encrypt", "decrypt", "hash", "digest",
    "tls", "ssl", "rsa", "ecdsa", "ecdh", "aes", "des", "md5", "sha-1",
    "sha1", "key exchange", "certificate", "jwt", "signature", "pkcs",
    "quantum", "post-quantum", "hmac", "pbkdf", "kdf", "diffie",
]

# Matches CVE identifiers embedded in curated package "reason" strings
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")

# Map OSV.dev ecosystem names to our internal names
ECOSYSTEM_MAP = {
    "PyPI":      "pypi",
    "npm":       "npm",
    "Go":        "go",
    "crates.io": "crates.io",
    "Maven":     "maven",
    "RubyGems":  "rubygems",
}


@dataclass
class DependencyFinding:
    file_path:          str          # manifest file (e.g. "requirements.txt")
    line_number:        int          # 0 — no specific line for dependencies
    algorithm:          str
    algo_type:          str
    risk_level:         str
    quantum_status:     str
    quantum_safe:       bool
    nist_replacement:   str
    context:            str          # human-readable description shown in Explorer
    source_type:        str = "dependency"
    dependency_name:    str = ""
    dependency_version: str = ""
    ecosystem:          str = ""     # "pypi" | "npm" | "go" | "crates.io" | "maven" | "rubygems"
    cves:               list = field(default_factory=list)   # [{cve_id, summary, cvss_score, cvss_severity, source}]


@dataclass
class ParsedPackage:
    name:      str
    version:   str          # "" if not pinned
    ecosystem: str          # "pypi" | "npm" | "go" | "crates.io" | "maven" | "rubygems"
    manifest:  str          # relative file path


# ── Version comparison helper ─────────────────────────────────────────────────

def _parse_ver(v: str) -> tuple:
    """Convert a version string to a comparable integer tuple."""
    cleaned = re.sub(r"[^0-9.]", "", v.split("+")[0].split("-")[0])
    parts = [p for p in cleaned.split(".") if p.isdigit()]
    return tuple(int(p) for p in parts) if parts else (0,)


def _is_vulnerable(installed: str, vulnerable_below: Optional[str]) -> bool:
    """Return True if installed version is below the vulnerable_below threshold."""
    if not vulnerable_below:
        return True   # ALL versions flagged
    if not installed:
        return True   # unpinned — flag conservatively
    return _parse_ver(installed) < _parse_ver(vulnerable_below)


# ── Manifest parsers ──────────────────────────────────────────────────────────

def _parse_requirements_txt(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse requirements.txt style files.
    Handles: pkg==1.0, pkg>=1.0, pkg[extras]==1.0, bare pkg names.
    """
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", "-r", "-c", "git+", "http")):
                    continue
                # Strip [extras] before matching: uvicorn[standard]==0.29.0 → uvicorn==0.29.0
                normalized = re.sub(r"\[[^\]]*\]", "", line)
                # Extract name and version: pyjwt==1.7.0, pyjwt>=1.7.0, pyjwt~=1.7
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=><~!]+\s*([^\s,;#]+)", normalized)
                if m:
                    pkgs.append(ParsedPackage(
                        name=m.group(1).lower(), version=m.group(2),
                        ecosystem="pypi", manifest=rel_path,
                    ))
                else:
                    bare = re.match(r"^([A-Za-z0-9_.\-]+)", normalized)
                    if bare:
                        pkgs.append(ParsedPackage(
                            name=bare.group(1).lower(), version="",
                            ecosystem="pypi", manifest=rel_path,
                        ))
    except Exception as e:
        logger.debug("requirements parse error %s: %s", path, e)
    return pkgs


def _parse_pyproject_toml(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse pyproject.toml [tool.poetry.dependencies] or [project.dependencies]."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        # Match lines like: pyjwt = "^1.7.0" or pyjwt = {version = "1.7.0"}
        for m in re.finditer(
            r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']([^"\']*)["\']',
            content, re.MULTILINE
        ):
            name, ver = m.group(1).lower(), m.group(2)
            cleaned = re.sub(r"[^0-9.]", "", ver.split(",")[0])
            pkgs.append(ParsedPackage(
                name=name, version=cleaned,
                ecosystem="pypi", manifest=rel_path,
            ))
    except Exception as e:
        logger.debug("pyproject.toml parse error %s: %s", path, e)
    return pkgs


def _parse_package_json(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse package.json dependencies and devDependencies."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver in data.get(section, {}).items():
                cleaned = re.sub(r"[^0-9.]", "", ver.split(" ")[0]) if isinstance(ver, str) else ""
                pkgs.append(ParsedPackage(
                    name=name.lower(), version=cleaned,
                    ecosystem="npm", manifest=rel_path,
                ))
    except Exception as e:
        logger.debug("package.json parse error %s: %s", path, e)
    return pkgs


def _parse_go_mod(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse go.mod require blocks."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        for m in re.finditer(
            r"^\s+([a-zA-Z0-9./_\-]+)\s+v([^\s]+)",
            content, re.MULTILINE
        ):
            pkgs.append(ParsedPackage(
                name=m.group(1).lower(), version=m.group(2),
                ecosystem="go", manifest=rel_path,
            ))
    except Exception as e:
        logger.debug("go.mod parse error %s: %s", path, e)
    return pkgs


def _parse_cargo_toml(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse Cargo.toml [dependencies] section."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and stripped != "[dependencies]":
                in_deps = False
            if not in_deps:
                continue
            # name = "version"  or  name = { version = "x.y.z", ... }
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*["\']([^"\']+)["\']', stripped)
            if m:
                pkgs.append(ParsedPackage(
                    name=m.group(1).lower(), version=m.group(2),
                    ecosystem="crates.io", manifest=rel_path,
                ))
            else:
                m2 = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{.*version\s*=\s*["\']([^"\']+)["\']', stripped)
                if m2:
                    pkgs.append(ParsedPackage(
                        name=m2.group(1).lower(), version=m2.group(2),
                        ecosystem="crates.io", manifest=rel_path,
                    ))
    except Exception as e:
        logger.debug("Cargo.toml parse error %s: %s", path, e)
    return pkgs


def _parse_pom_xml(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse Maven pom.xml dependencies."""
    pkgs = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        ns = re.match(r"\{[^}]+\}", root.tag)
        prefix = ns.group(0) if ns else ""
        for dep in root.iter(f"{prefix}dependency"):
            artifact = dep.findtext(f"{prefix}artifactId") or ""
            version  = dep.findtext(f"{prefix}version")    or ""
            version  = re.sub(r"[^0-9.]", "", version)
            if artifact:
                pkgs.append(ParsedPackage(
                    name=artifact.lower(), version=version,
                    ecosystem="maven", manifest=rel_path,
                ))
    except Exception as e:
        logger.debug("pom.xml parse error %s: %s", path, e)
    return pkgs


def _parse_gemfile_lock(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse Gemfile.lock specs section."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        for m in re.finditer(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)", content, re.MULTILINE):
            pkgs.append(ParsedPackage(
                name=m.group(1).lower(), version=m.group(2),
                ecosystem="rubygems", manifest=rel_path,
            ))
    except Exception as e:
        logger.debug("Gemfile.lock parse error %s: %s", path, e)
    return pkgs


# ── Manifest file detection ───────────────────────────────────────────────────

MANIFEST_PARSERS = {
    "requirements.txt":  _parse_requirements_txt,
    "pyproject.toml":    _parse_pyproject_toml,
    "Pipfile":           _parse_requirements_txt,   # same format for [packages]
    "package.json":      _parse_package_json,
    "go.mod":            _parse_go_mod,
    "Cargo.toml":        _parse_cargo_toml,
    "pom.xml":           _parse_pom_xml,
    "Gemfile.lock":      _parse_gemfile_lock,
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", ".tox", "venv", ".venv"}


def _collect_manifests(root: str) -> list[tuple[str, str]]:
    """Walk the repo and return (abs_path, rel_path) for every manifest file."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname in MANIFEST_PARSERS:
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root)
                found.append((abs_path, rel_path))
            # Also match requirements*.txt patterns (e.g. requirements-dev.txt)
            elif re.match(r"requirements.*\.txt$", fname, re.IGNORECASE):
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root)
                found.append((abs_path, rel_path))
    return found


# ── OSV.dev integration ───────────────────────────────────────────────────────

def _osv_ecosystem(ecosystem: str) -> str:
    """Map internal ecosystem name to OSV.dev ecosystem name."""
    return {
        "pypi":      "PyPI",
        "npm":       "npm",
        "go":        "Go",
        "crates.io": "crates.io",
        "maven":     "Maven",
        "rubygems":  "RubyGems",
    }.get(ecosystem, "")


def _is_crypto_cve(vuln: dict) -> bool:
    """Return True if the OSV.dev vulnerability is crypto-relevant."""
    text = " ".join([
        vuln.get("summary", ""),
        vuln.get("details", ""),
        " ".join(a.get("value", "") for a in vuln.get("aliases", [])),
    ]).lower()
    return any(kw in text for kw in CRYPTO_CVE_KEYWORDS)


def _cvss_score(vuln: dict) -> Optional[float]:
    """Extract the numeric CVSS score from an OSV.dev vuln, if present."""
    for severity in vuln.get("severity", []):
        score_str = severity.get("score", "")
        # CVSS v3 vectors: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        m = re.search(r"(\d+\.\d+)$", score_str)
        if m:
            return float(m.group(1))
    return None


def _cvss_to_risk(vuln: dict) -> str:
    """Map an OSV.dev vuln's CVSS score to our risk levels."""
    score = _cvss_score(vuln)
    if score is None:
        return "HIGH"   # default if no CVSS available
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _query_osv(packages: list[ParsedPackage]) -> dict[tuple, list]:
    """
    Batch query OSV.dev for all packages.
    Returns dict: (ecosystem, name) → list of crypto-relevant vulns
    """
    if not packages:
        return {}

    # Build batch queries — OSV.dev accepts up to 1000 per request
    queries = []
    index_map = []   # (ecosystem, name) per query index
    for pkg in packages:
        eco = _osv_ecosystem(pkg.ecosystem)
        if not eco:
            continue
        query = {"package": {"name": pkg.name, "ecosystem": eco}}
        if pkg.version:
            query["version"] = pkg.version
        queries.append(query)
        index_map.append((pkg.ecosystem, pkg.name))

    if not queries:
        return {}

    results: dict[tuple, list] = {}
    # Split into batches of 1000
    batch_size = 1000
    for batch_start in range(0, len(queries), batch_size):
        batch_queries  = queries[batch_start: batch_start + batch_size]
        batch_index    = index_map[batch_start: batch_start + batch_size]
        try:
            resp = httpx.post(
                OSV_API_URL,
                json={"queries": batch_queries},
                timeout=OSV_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning("OSV.dev query failed: %s", e)
            continue

        for i, result_entry in enumerate(data.get("results", [])):
            vulns = result_entry.get("vulns", [])
            crypto_vulns = [v for v in vulns if _is_crypto_cve(v)]
            if crypto_vulns:
                key = batch_index[i]
                results.setdefault(key, []).extend(crypto_vulns)

    return results


# ── Main scanner class ────────────────────────────────────────────────────────

class DependencyScanner:
    """
    Scans a repository's dependency manifests for quantum-vulnerable
    cryptographic packages. Combines a curated package map with live
    OSV.dev CVE data.
    """

    def scan_directory(self, root_path: str) -> list[DependencyFinding]:
        manifests = _collect_manifests(root_path)
        if not manifests:
            logger.info("Dependency scan: no manifest files found in %s", root_path)
            return []

        logger.info("Dependency scan: found %d manifest(s): %s",
                    len(manifests), [r for _, r in manifests])

        # Parse all manifests → flat list of packages
        all_packages: list[ParsedPackage] = []
        for abs_path, rel_path in manifests:
            fname  = os.path.basename(abs_path)
            # Primary lookup — exact filename match
            parser = MANIFEST_PARSERS.get(fname)
            # Fallback — any requirements*.txt uses the requirements parser
            if parser is None and re.match(r"requirements.*\.txt$", fname, re.IGNORECASE):
                parser = _parse_requirements_txt
            if parser:
                pkgs = parser(abs_path, rel_path)
                logger.info("  %s → %d package(s) parsed", rel_path, len(pkgs))
                all_packages.extend(pkgs)
            else:
                logger.debug("  %s → no parser available", rel_path)

        if not all_packages:
            logger.info("Dependency scan: 0 packages parsed from manifests")
            return []

        logger.info("Dependency scan: %d total packages parsed", len(all_packages))
        # Log every parsed package so the user can see exactly what was checked
        for p in all_packages:
            logger.info("    checked: [%s] %s%s",
                        p.ecosystem, p.name,
                        f"=={p.version}" if p.version else " (unpinned)")

        # Deduplicate packages for OSV.dev query (same name+ecosystem may appear in multiple manifests)
        unique_pkgs = list({(p.ecosystem, p.name): p for p in all_packages}.values())

        # Query OSV.dev for additional CVE coverage
        osv_results = {}
        try:
            osv_results = _query_osv(unique_pkgs)
        except Exception as e:
            logger.warning("OSV.dev integration skipped: %s", e)

        # Build findings
        findings: list[DependencyFinding] = []
        seen: set[tuple] = set()   # (manifest, package_name) — one finding per package per manifest

        for pkg in all_packages:
            key_tuple = (pkg.ecosystem, pkg.name.lower())

            # ── Check curated crypto package map first ────────────────────────
            entry = CRYPTO_PACKAGE_MAP.get(key_tuple)
            if entry and _is_vulnerable(pkg.version, entry["vulnerable_below"]):
                dedup_key = (pkg.manifest, pkg.name.lower())
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    ver_str  = f"=={pkg.version}" if pkg.version else " (unpinned)"
                    cves = [
                        {
                            "cve_id":        cve_id,
                            "summary":       entry["reason"],
                            "cvss_score":    None,
                            "cvss_severity": entry["risk_level"],
                            "source":        "curated",
                        }
                        for cve_id in CVE_ID_RE.findall(entry["reason"])
                    ]
                    findings.append(DependencyFinding(
                        file_path          = pkg.manifest,
                        line_number        = 0,
                        algorithm          = entry["algorithm"],
                        algo_type          = entry["algo_type"],
                        risk_level         = entry["risk_level"],
                        quantum_status     = entry["quantum_status"],
                        quantum_safe       = entry["quantum_status"] in ("SAFE", "MONITOR"),
                        nist_replacement   = entry["nist_replacement"],
                        context            = (
                            f"Dependency: {pkg.name}{ver_str}\n"
                            f"Manifest:   {pkg.manifest}\n"
                            f"Issue:      {entry['reason']}\n"
                            f"Replace with: {entry['nist_replacement']}"
                        ),
                        dependency_name    = pkg.name,
                        dependency_version = pkg.version,
                        ecosystem          = pkg.ecosystem,
                        cves               = cves,
                    ))

            # ── OSV.dev crypto CVEs (packages not in curated map) ─────────────
            osv_vulns = osv_results.get(key_tuple, [])
            for vuln in osv_vulns:
                vuln_algo = _infer_algorithm(vuln)
                dedup_key = (pkg.manifest, pkg.name.lower(), vuln_algo)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                risk = _cvss_to_risk(vuln)
                ver_str = f"=={pkg.version}" if pkg.version else " (unpinned)"
                findings.append(DependencyFinding(
                    file_path          = pkg.manifest,
                    line_number        = 0,
                    algorithm          = vuln_algo,
                    algo_type          = "Asymmetric",
                    risk_level         = risk,
                    quantum_status     = "VULNERABLE",
                    quantum_safe       = False,
                    nist_replacement   = "See NIST PQC standards (FIPS 203/204/205)",
                    context            = (
                        f"Dependency: {pkg.name}{ver_str}\n"
                        f"Manifest:   {pkg.manifest}\n"
                        f"CVE:        {vuln.get('id', 'Unknown')}\n"
                        f"Issue:      {vuln.get('summary', 'Crypto vulnerability detected')}"
                    ),
                    dependency_name    = pkg.name,
                    dependency_version = pkg.version,
                    ecosystem          = pkg.ecosystem,
                    cves               = [{
                        "cve_id":        vuln.get("id", "Unknown"),
                        "summary":       vuln.get("summary", "Crypto vulnerability detected"),
                        "cvss_score":    _cvss_score(vuln),
                        "cvss_severity": risk,
                        "source":        "osv",
                    }],
                ))

        logger.info("Dependency scan: %d manifests, %d packages, %d findings",
                    len(manifests), len(all_packages), len(findings))
        return findings


def _infer_algorithm(vuln: dict) -> str:
    """Best-effort map of OSV.dev vuln text to a known algorithm name."""
    text = (vuln.get("summary", "") + " " + vuln.get("details", "")).lower()
    if "rsa" in text:      return "RSA-2048"
    if "ecdsa" in text:    return "ECDSA"
    if "md5" in text:      return "MD5"
    if "sha-1" in text or "sha1" in text: return "SHA-1"
    if "des" in text:      return "DES"
    if "rc4" in text:      return "RC4"
    if "tls" in text:      return "TLS-1.2"
    if "jwt" in text:      return "JWT-RS256"
    return "RSA-2048"   # conservative default

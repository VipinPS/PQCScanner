"""
TLS / network endpoint scanner.

Connects to host:port, performs a TLS handshake, extracts certificate and
cipher-suite details, then classifies the quantum risk of the public key.

Dependencies: ssl, socket (stdlib) + cryptography (available via paramiko).
"""
from __future__ import annotations

import json
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# cryptography is a transitive dep of paramiko
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dh, dsa


# ── Quantum risk tables ───────────────────────────────────────────────────────

_RSA_STATUS = {
    # key_size → (quantum_status, risk_level, nist_replacement)
    512:  ("BROKEN",     "CRITICAL", "ML-KEM-768"),
    1024: ("BROKEN",     "CRITICAL", "ML-KEM-768"),
    2048: ("VULNERABLE", "HIGH",     "ML-KEM-768"),
    3072: ("VULNERABLE", "HIGH",     "ML-KEM-768"),
    4096: ("VULNERABLE", "MEDIUM",   "ML-KEM-768"),
}
_RSA_DEFAULT = ("VULNERABLE", "HIGH", "ML-KEM-768")

_EC_CURVE_STATUS = {
    # OID short name / common name → (quantum_status, risk_level, nist_replacement)
    "secp256r1":  ("VULNERABLE", "HIGH",   "ML-KEM-768"),
    "prime256v1": ("VULNERABLE", "HIGH",   "ML-KEM-768"),
    "secp384r1":  ("VULNERABLE", "MEDIUM", "ML-KEM-768"),
    "secp521r1":  ("VULNERABLE", "MEDIUM", "ML-KEM-1024"),
    "secp256k1":  ("VULNERABLE", "HIGH",   "ML-KEM-768"),
    "brainpoolP256r1": ("VULNERABLE", "HIGH", "ML-KEM-768"),
    "brainpoolP384r1": ("VULNERABLE", "MEDIUM", "ML-KEM-768"),
}
_EC_DEFAULT = ("VULNERABLE", "HIGH", "ML-KEM-768")

_TLS_STATUS = {
    "SSLv2":   ("BROKEN",     "CRITICAL"),
    "SSLv3":   ("BROKEN",     "CRITICAL"),
    "TLSv1":   ("BROKEN",     "HIGH"),
    "TLSv1.1": ("BROKEN",     "HIGH"),
    "TLSv1.2": ("WEAK",       "MEDIUM"),
    "TLSv1.3": ("MONITOR",    "LOW"),
}


@dataclass
class TLSScanResult:
    endpoint:       str
    scan_status:    str = "complete"        # complete | failed
    error_message:  Optional[str] = None

    # TLS handshake
    tls_version:    Optional[str] = None
    cipher_name:    Optional[str] = None
    cipher_bits:    Optional[int] = None

    # Certificate
    cert_subject:   Optional[str] = None
    cert_issuer:    Optional[str] = None
    cert_not_before: Optional[datetime] = None
    cert_not_after:  Optional[datetime] = None
    cert_serial:    Optional[str] = None

    # Public key
    key_type:       Optional[str] = None    # RSA | EC | Ed25519 | Ed448 | DSA
    key_size:       Optional[int] = None
    key_curve:      Optional[str] = None
    sig_algorithm:  Optional[str] = None

    # Quantum risk (aggregated worst)
    algorithm:        Optional[str] = None  # display name, e.g. "RSA-2048"
    quantum_status:   Optional[str] = None  # BROKEN / VULNERABLE / WEAK / MONITOR / SAFE
    risk_level:       Optional[str] = None  # CRITICAL / HIGH / MEDIUM / LOW
    nist_replacement: Optional[str] = None
    issues:           list = field(default_factory=list)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _classify_rsa(key_size: int) -> tuple:
    return _RSA_STATUS.get(key_size, _RSA_DEFAULT)


def _classify_ec(curve_name: str) -> tuple:
    return _EC_CURVE_STATUS.get(curve_name, _EC_DEFAULT)


_STATUS_RANK = {"BROKEN": 0, "VULNERABLE": 1, "WEAK": 2, "MONITOR": 3, "SAFE": 4}


def _worst(a: str | None, b: str | None) -> str:
    """Return whichever status is worse (lower rank)."""
    if a is None:
        return b or "MONITOR"
    if b is None:
        return a
    return a if _STATUS_RANK.get(a, 99) <= _STATUS_RANK.get(b, 99) else b


def _dn_str(name) -> str:
    """Convert an x509.Name to a readable string."""
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_endpoint(host: str, port: int = 443, timeout: int = 10) -> TLSScanResult:
    endpoint = f"{host}:{port}"
    result = TLSScanResult(endpoint=endpoint)

    try:
        # Build a permissive SSL context — we want to scan even self-signed /
        # expired certs, so disable verification.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                # ── TLS version & cipher ─────────────────────────────────────
                result.tls_version = tls_sock.version()          # e.g. "TLSv1.3"
                cipher = tls_sock.cipher()                        # (name, proto, bits)
                if cipher:
                    result.cipher_name = cipher[0]
                    result.cipher_bits = cipher[2]

                # ── DER certificate ──────────────────────────────────────────
                der = tls_sock.getpeercert(binary_form=True)

        if der:
            _parse_cert(der, result)

        # ── TLS-version risk ─────────────────────────────────────────────────
        tls_qs, tls_rl = _TLS_STATUS.get(result.tls_version or "", ("MONITOR", "LOW"))
        if result.tls_version and result.tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            result.issues.append(f"Deprecated TLS version: {result.tls_version}")

        # ── Aggregate worst status ───────────────────────────────────────────
        key_qs = result.quantum_status  # set by _parse_cert
        result.quantum_status = _worst(key_qs, tls_qs)

        # Keep key risk_level if key is worse, else use TLS risk
        if key_qs and _STATUS_RANK.get(key_qs, 99) <= _STATUS_RANK.get(tls_qs, 99):
            pass  # already set
        else:
            result.risk_level = tls_rl

        # ── Check cert expiry ────────────────────────────────────────────────
        if result.cert_not_after:
            now = datetime.now(tz=timezone.utc)
            expiry = result.cert_not_after
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < now:
                result.issues.append("Certificate is expired")
            elif (expiry - now).days < 30:
                result.issues.append(f"Certificate expires in {(expiry - now).days} days")

    except socket.timeout:
        result.scan_status = "failed"
        result.error_message = f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        result.scan_status = "failed"
        result.error_message = "Connection refused"
    except ssl.SSLError as exc:
        result.scan_status = "failed"
        result.error_message = f"SSL error: {exc.reason or str(exc)}"
    except OSError as exc:
        result.scan_status = "failed"
        result.error_message = str(exc)
    except Exception as exc:
        result.scan_status = "failed"
        result.error_message = f"Unexpected error: {exc}"

    return result


def _parse_cert(der: bytes, result: TLSScanResult) -> None:
    """Parse DER cert and populate result fields in-place."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        result.issues.append(f"Could not parse certificate: {exc}")
        return

    # Subject / issuer
    result.cert_subject = _dn_str(cert.subject)
    result.cert_issuer  = _dn_str(cert.issuer)
    result.cert_serial  = str(cert.serial_number)

    # Validity window
    try:
        result.cert_not_before = cert.not_valid_before_utc
        result.cert_not_after  = cert.not_valid_after_utc
    except AttributeError:
        # older cryptography versions
        nb = cert.not_valid_before
        na = cert.not_valid_after
        result.cert_not_before = nb.replace(tzinfo=timezone.utc) if nb else None
        result.cert_not_after  = na.replace(tzinfo=timezone.utc) if na else None

    # Signature algorithm
    try:
        result.sig_algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        result.sig_algorithm = None

    # Public key
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        result.key_type = "RSA"
        result.key_size = pub.key_size
        result.algorithm = f"RSA-{pub.key_size}"
        qs, rl, repl = _classify_rsa(pub.key_size)
        result.quantum_status   = qs
        result.risk_level       = rl
        result.nist_replacement = repl
        result.issues.append(f"RSA-{pub.key_size} is quantum-vulnerable (Shor's algorithm)")

    elif isinstance(pub, ec.EllipticCurvePublicKey):
        result.key_type  = "EC"
        result.key_size  = pub.key_size
        curve_name       = pub.curve.name
        result.key_curve = curve_name
        result.algorithm = f"EC-{curve_name}"
        qs, rl, repl = _classify_ec(curve_name)
        result.quantum_status   = qs
        result.risk_level       = rl
        result.nist_replacement = repl
        result.issues.append(f"Elliptic curve {curve_name} is quantum-vulnerable (Shor's algorithm)")

    elif isinstance(pub, ed25519.Ed25519PublicKey):
        result.key_type       = "Ed25519"
        result.key_size       = 256
        result.algorithm      = "Ed25519"
        result.quantum_status = "VULNERABLE"
        result.risk_level     = "HIGH"
        result.nist_replacement = "ML-DSA-44"
        result.issues.append("Ed25519 is quantum-vulnerable")

    elif isinstance(pub, ed448.Ed448PublicKey):
        result.key_type       = "Ed448"
        result.key_size       = 448
        result.algorithm      = "Ed448"
        result.quantum_status = "VULNERABLE"
        result.risk_level     = "HIGH"
        result.nist_replacement = "ML-DSA-65"
        result.issues.append("Ed448 is quantum-vulnerable")

    elif isinstance(pub, dsa.DSAPublicKey):
        result.key_type       = "DSA"
        result.key_size       = pub.key_size
        result.algorithm      = f"DSA-{pub.key_size}"
        result.quantum_status = "BROKEN"
        result.risk_level     = "CRITICAL"
        result.nist_replacement = "ML-DSA-44"
        result.issues.append(f"DSA is broken and quantum-vulnerable")

    else:
        result.key_type       = type(pub).__name__
        result.algorithm      = type(pub).__name__
        result.quantum_status = "MONITOR"
        result.risk_level     = "LOW"

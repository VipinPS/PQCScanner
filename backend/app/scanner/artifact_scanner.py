"""
Artifact Scanner — Phase 4+
Scans uploaded binary artifacts for quantum-vulnerable cryptography.

Supported artifact types:
  python_wheel   — .whl / .egg (zip) → parse METADATA + requirements → dep check
  python_sdist   — .tar.gz containing setup.py/PKG-INFO → dep check
  java_jar       — .jar (zip) → pom.xml deps + .class bytecode strings
  java_war       — .war / .ear (zip) → same as jar
  android_aar    — .aar (zip) → classes.jar + jni/*.so
  android_apk    — .apk (zip) → classes.dex strings + lib/*.so
  nuget          — .nupkg (zip) → .nuspec dependency list
  ruby_gem       — .gem (tar) → metadata.gz deps + data.tar.gz contents
  container_image — .tar (docker save) → extract layers → dep manifests
  native_elf     — Linux ELF (.so, .ko, executables) → nm + strings
  native_macho   — macOS Mach-O (.dylib, frameworks) → strings + otool
  static_archive — .a static library (ar archive) → extract .o → nm + strings
  deb            — Debian .deb → control Depends + data ELF binaries
  rpm            — RPM package → header deps + rpm2cpio extraction
  zip_generic    — .zip fallback → walk manifests + ELF binaries
"""

import gzip
import os
import re
import json
import shlex
import shutil
import tarfile
import zipfile
import tempfile
import subprocess
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from app.scanner.dependency_scanner import (
    CRYPTO_PACKAGE_MAP,
    DependencyFinding,
    ParsedPackage,
    _is_vulnerable,
    _parse_requirements_txt,
    _parse_pom_xml,
    _parse_package_json,
    _parse_pyproject_toml,
)

logger = logging.getLogger(__name__)

UPLOAD_DIR = "/app/uploads"

# ── Crypto symbols to look for in native binaries ────────────────────────────
# Each entry: (regex_pattern, algorithm, algo_type, risk, quantum_status, replacement)
NATIVE_CRYPTO_PATTERNS = [
    # OpenSSL RSA
    (r"\bRSA_(generate_key|private_encrypt|public_decrypt|sign|verify)\b",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"),
    # OpenSSL EC
    (r"\bEC_KEY_(generate_key|new_by_curve_name)\b|ECDSA_(sign|verify)\b",
     "ECDSA-P256", "Asymmetric", "HIGH", "VULNERABLE", "ML-DSA-65 (FIPS 204)"),
    # OpenSSL DH
    (r"\bDH_(generate_parameters|generate_key|compute_key)\b",
     "DH-2048", "KeyExchange", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
    # OpenSSL DSA
    (r"\bDSA_(generate_parameters|generate_key|sign|verify)\b",
     "DSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-DSA-65 (FIPS 204)"),
    # MD5
    (r"\bMD5(_Init|_Update|_Final|_Transform)?\b",
     "MD5", "Hash", "CRITICAL", "BROKEN", "SHA-3-256"),
    # SHA-1
    (r"\bSHA1(_Init|_Update|_Final)?\b",
     "SHA-1", "Hash", "HIGH", "WEAK", "SHA-3-256"),
    # DES / 3DES
    (r"\b(DES|DES3|DES_ecb_encrypt|des_ecb_encrypt|EVP_des|EVP_des3)\b",
     "DES", "Symmetric", "CRITICAL", "BROKEN", "AES-256-GCM"),
    # RC4
    (r"\b(RC4_set_key|RC4|EVP_rc4)\b",
     "RC4", "Stream", "CRITICAL", "BROKEN", "AES-256-GCM"),
    # mbedTLS RSA
    (r"\bmbedtls_rsa_(gen_key|pkcs1_encrypt|pkcs1_decrypt|rsassa_pkcs1|rsaes_pkcs1)\b",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
    # mbedTLS ECDH / ECDSA
    (r"\bmbedtls_(ecdh|ecdsa)_",
     "ECDSA-P256", "Asymmetric", "HIGH", "VULNERABLE", "ML-DSA-65 (FIPS 204)"),
    # WolfSSL
    (r"\b(wolfSSL_RSA|wc_RsaPublicEncrypt|wc_RsaPrivateDecrypt)\b",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
    # libgcrypt
    (r"\bgcry_(pk_encrypt|pk_decrypt|pk_sign|pk_verify)\b",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
    # Java crypto class names appearing in .class bytecode strings
    (r"javax/crypto/(KeyAgreement|KeyPairGenerator|Cipher)",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
    (r"java/security/(MessageDigest|Signature|KeyPairGenerator)",
     "RSA-2048", "Asymmetric", "HIGH", "VULNERABLE", "ML-KEM-768 (FIPS 203)"),
]

# ── Compiled regex for performance ───────────────────────────────────────────
_COMPILED = [(re.compile(p), alg, at, risk, qs, rep)
             for p, alg, at, risk, qs, rep in NATIVE_CRYPTO_PATTERNS]


# ── Type detection ────────────────────────────────────────────────────────────

_MACHO_MAGIC = (
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit BE
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit BE
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit LE
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit LE
    b"\xca\xfe\xba\xbe",  # Mach-O fat/universal binary
)


def detect_artifact_type(filename: str, file_path: str) -> str:
    """Determine artifact type from filename + magic bytes."""
    name_lower = filename.lower()

    # ── Extension-based detection (most specific first) ───────────────────────
    if name_lower.endswith(".whl") or name_lower.endswith(".egg"):
        return "python_wheel"
    if name_lower.endswith(".jar"):
        return "java_jar"
    if name_lower.endswith((".war", ".ear")):
        return "java_war"
    if name_lower.endswith(".aar"):
        return "android_aar"
    if name_lower.endswith(".apk"):
        return "android_apk"
    if name_lower.endswith(".nupkg"):
        return "nuget"
    if name_lower.endswith(".gem"):
        return "ruby_gem"
    if name_lower.endswith((".rpm", ".srpm", ".src.rpm")):
        return "rpm"
    if name_lower.endswith((".deb", ".udeb")):
        return "deb"
    if name_lower.endswith(".dylib"):
        return "native_macho"
    if name_lower.endswith(".a"):
        return "static_archive"
    if name_lower.endswith(".ko") or re.search(r"\.ko\.gz$", name_lower):
        return "native_elf"
    # Versioned .so names: libfoo.so / libfoo.so.1 / libfoo.so.1.2.3
    if re.search(r"\.so(\.\d+)*$", name_lower):
        return "native_elf"

    # ── Magic bytes ───────────────────────────────────────────────────────────
    try:
        with open(file_path, "rb") as fh:
            magic = fh.read(8)
    except OSError:
        return "unknown"

    if magic[:4] == b"\x7fELF":
        return "native_elf"
    if magic[:4] in _MACHO_MAGIC:
        return "native_macho"
    # PE / MZ — keep detection for strings-based fallback but don't actively promote
    if magic[:2] == b"MZ":
        return "native_pe"
    # ar archive → static lib or deb
    if magic[:8] == b"!<arch>\n":
        return "deb" if name_lower.endswith((".deb", ".udeb")) else "static_archive"
    # Zip-based
    if magic[:2] == b"PK":
        return _sniff_zip_type(file_path, name_lower)
    # Tar / gzip
    if magic[:2] == b"\x1f\x8b" or magic[:5] == b"ustar":
        return _sniff_tar_type(file_path, name_lower)
    # RPM magic: 0xED 0xAB 0xEE 0xDB
    if magic[:4] == b"\xed\xab\xee\xdb":
        return "rpm"

    # RPM magic: 0xED 0xAB 0xEE 0xDB
    if magic[:4] == b"\xed\xab\xee\xdb":
        return "rpm"

    # RPM by extension (magic check may fail on unusual containers)
    if name_lower.endswith((".rpm", ".srpm", ".src.rpm")):
        return "rpm"

    return "unknown"


def _sniff_zip_type(path: str, name_lower: str = "") -> str:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        if any(n.endswith("/METADATA") or n == "METADATA" for n in names):
            return "python_wheel"
        if any(n == "classes.jar" or n.endswith("/classes.jar") for n in names):
            return "android_aar"
        if any(n == "classes.dex" or n.endswith("/classes.dex") for n in names):
            return "android_apk"
        if any(n.endswith(".nuspec") for n in names):
            return "nuget"
        if any(n.endswith("pom.xml") for n in names):
            return "java_jar"
        return "zip_generic"
    except Exception:
        return "unknown"


def _sniff_tar_type(path: str, name_lower: str) -> str:
    try:
        with tarfile.open(path) as t:
            members = t.getnames()
        # Docker save tarballs always have manifest.json at root
        if "manifest.json" in members:
            return "container_image"
        # Python sdist has PKG-INFO or setup.py at top level
        if any(m.endswith("PKG-INFO") or m.endswith("setup.py") for m in members):
            return "python_sdist"
    except Exception:
        pass
    if name_lower.endswith((".tar.gz", ".tgz")):
        return "python_sdist"  # best guess
    return "unknown"


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan_artifact(artifact_type: str, file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan the artifact and return a list of DependencyFinding objects.
    artifact_name is used as the file_path in findings for display.
    """
    logger.info("Scanning artifact: %s (type=%s)", artifact_name, artifact_type)

    try:
        if artifact_type in ("python_wheel", "python_sdist"):
            return _scan_python_artifact(file_path, artifact_name)
        elif artifact_type in ("java_jar", "java_war"):
            return _scan_java_artifact(file_path, artifact_name)
        elif artifact_type == "container_image":
            return _scan_container_artifact(file_path, artifact_name)
        elif artifact_type in ("native_elf", "native_pe"):
            return _scan_native_binary(file_path, artifact_name)
        elif artifact_type == "native_macho":
            return _scan_macho_binary(file_path, artifact_name)
        elif artifact_type == "static_archive":
            return _scan_static_archive(file_path, artifact_name)
        elif artifact_type == "deb":
            return _scan_deb_artifact(file_path, artifact_name)
        elif artifact_type == "android_aar":
            return _scan_aar_artifact(file_path, artifact_name)
        elif artifact_type == "android_apk":
            return _scan_apk_artifact(file_path, artifact_name)
        elif artifact_type == "ruby_gem":
            return _scan_gem_artifact(file_path, artifact_name)
        elif artifact_type == "nuget":
            return _scan_nupkg_artifact(file_path, artifact_name)
        elif artifact_type == "zip_generic":
            return _scan_zip_generic(file_path, artifact_name)
        elif artifact_type == "rpm":
            return _scan_rpm_artifact(file_path, artifact_name)
        else:
            return _scan_unknown(file_path, artifact_name)
    except Exception as exc:
        logger.exception("Artifact scan failed for %s: %s", artifact_name, exc)
        raise


# ── Python wheel / sdist ──────────────────────────────────────────────────────

def _scan_python_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    findings = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_art_")
    try:
        # Wheels are zip files; sdists are tarballs
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as z:
                z.extractall(tmpdir)
        else:
            with tarfile.open(file_path) as t:
                t.extractall(tmpdir, filter="data")

        # Walk extracted tree and parse manifests
        packages: list[ParsedPackage] = []
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                full = os.path.join(root, fname)
                rel  = os.path.relpath(full, tmpdir)
                fl   = fname.lower()
                if fl == "requirements.txt" or re.match(r"requirements[._-].+\.txt$", fl):
                    packages.extend(_parse_requirements_txt(full, f"{artifact_name}/{rel}"))
                elif fl in ("pyproject.toml",):
                    packages.extend(_parse_pyproject_toml(full, f"{artifact_name}/{rel}"))
                elif fl == "metadata":
                    # dist-info/METADATA — parse Requires-Dist lines
                    packages.extend(_parse_wheel_metadata(full, f"{artifact_name}/{rel}"))

        findings.extend(_check_packages(packages))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return findings


def _parse_wheel_metadata(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse Requires-Dist lines from wheel METADATA."""
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = re.match(r"Requires-Dist:\s*([A-Za-z0-9_.\-]+)\s*(?:\(([^)]+)\))?", line, re.I)
                if m:
                    name    = m.group(1).lower().strip()
                    ver_str = m.group(2) or ""
                    # Extract version number from spec like ">=1.0,<2.0"
                    ver_match = re.search(r"([\d.]+)", ver_str)
                    version = ver_match.group(1) if ver_match else ""
                    pkgs.append(ParsedPackage(name=name, version=version,
                                              ecosystem="pypi", manifest=rel_path))
    except Exception as e:
        logger.debug("wheel METADATA parse error: %s", e)
    return pkgs


# ── Java JAR / WAR ────────────────────────────────────────────────────────────

def _scan_java_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    findings = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_art_")
    try:
        with zipfile.ZipFile(file_path) as z:
            z.extractall(tmpdir)

        # 1. Parse pom.xml for declared dependencies
        packages: list[ParsedPackage] = []
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if fname.lower() == "pom.xml":
                    full = os.path.join(root, fname)
                    rel  = os.path.relpath(full, tmpdir)
                    packages.extend(_parse_pom_xml(full, f"{artifact_name}/{rel}"))

        findings.extend(_check_packages(packages))

        # 2. Scan .class bytecode strings for crypto API calls
        class_hits: dict[str, DependencyFinding] = {}  # deduplicate by algorithm
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if not fname.endswith(".class"):
                    continue
                full = os.path.join(root, fname)
                rel  = os.path.relpath(full, tmpdir)
                try:
                    with open(full, "rb") as fh:
                        raw = fh.read()
                    # Extract printable strings from .class bytecode
                    text = _extract_class_strings(raw)
                    for cre, alg, at, risk, qs, rep in _COMPILED:
                        if cre.search(text) and alg not in class_hits:
                            class_hits[alg] = DependencyFinding(
                                file_path=f"{artifact_name}/{rel}",
                                line_number=0,
                                algorithm=alg,
                                algo_type=at,
                                risk_level=risk,
                                quantum_status=qs,
                                quantum_safe=False,
                                nist_replacement=rep,
                                context=f"Crypto API reference found in bytecode: {rel}",
                                source_type="artifact",
                                dependency_name="",
                                dependency_version="",
                            )
                except Exception:
                    pass

        findings.extend(class_hits.values())

        # 3. Scan nested JARs (fat/uber jars)
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if fname.lower().endswith(".jar"):
                    inner = os.path.join(root, fname)
                    rel   = os.path.relpath(inner, tmpdir)
                    inner_findings = _scan_java_artifact(inner, f"{artifact_name}/{rel}")
                    findings.extend(inner_findings)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return findings


def _extract_class_strings(data: bytes) -> str:
    """Pull printable ASCII strings (length ≥6) from raw bytecode."""
    result = []
    current = []
    for b in data:
        if 0x20 <= b < 0x7f:
            current.append(chr(b))
        else:
            if len(current) >= 6:
                result.append("".join(current))
            current = []
    if len(current) >= 6:
        result.append("".join(current))
    return "\n".join(result)


# ── Container image tarball ───────────────────────────────────────────────────

def _scan_container_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """Parse a docker-save tarball: extract layers and scan package manifests."""
    findings = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_art_")
    try:
        with tarfile.open(file_path) as t:
            t.extractall(tmpdir, filter="data")

        # Read manifest.json to get layer ordering
        manifest_path = os.path.join(tmpdir, "manifest.json")
        if not os.path.exists(manifest_path):
            logger.warning("container tarball has no manifest.json")
            return findings

        with open(manifest_path) as fh:
            manifest = json.load(fh)

        # Collect all package manifest files across layers
        packages: list[ParsedPackage] = []
        for image_entry in manifest:
            for layer_path in image_entry.get("Layers", []):
                layer_tar = os.path.join(tmpdir, layer_path)
                if not os.path.exists(layer_tar):
                    continue
                layer_dir = tempfile.mkdtemp(prefix="pqc_layer_")
                try:
                    with tarfile.open(layer_tar) as lt:
                        lt.extractall(layer_dir, filter="data")
                    packages.extend(_collect_container_packages(layer_dir, artifact_name))
                finally:
                    shutil.rmtree(layer_dir, ignore_errors=True)

        # Deduplicate packages by (ecosystem, name)
        seen = set()
        unique_packages = []
        for p in packages:
            key = (p.ecosystem, p.name)
            if key not in seen:
                seen.add(key)
                unique_packages.append(p)

        findings.extend(_check_packages(unique_packages))

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return findings


def _collect_container_packages(layer_dir: str, artifact_name: str) -> list[ParsedPackage]:
    """Walk a layer directory and extract package manager manifests."""
    packages = []
    for root, _, files in os.walk(layer_dir):
        for fname in files:
            full = os.path.join(root, fname)
            rel  = os.path.relpath(full, layer_dir)
            fl   = fname.lower()

            # dpkg installed packages
            if rel in ("var/lib/dpkg/status",):
                packages.extend(_parse_dpkg_status(full, f"{artifact_name}/layer/{rel}"))

            # Python site-packages .dist-info or egg-info METADATA/PKG-INFO
            elif fl in ("metadata", "pkg-info") and (".dist-info" in rel or ".egg-info" in rel):
                packages.extend(_parse_wheel_metadata(full, f"{artifact_name}/layer/{rel}"))

            # requirements.txt anywhere in the image
            elif fl == "requirements.txt":
                packages.extend(_parse_requirements_txt(full, f"{artifact_name}/layer/{rel}"))

            # npm package.json
            elif fl == "package.json" and "node_modules" not in rel:
                packages.extend(_parse_package_json(full, f"{artifact_name}/layer/{rel}"))

            # pom.xml
            elif fl == "pom.xml":
                packages.extend(_parse_pom_xml(full, f"{artifact_name}/layer/{rel}"))

    return packages


def _parse_dpkg_status(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse /var/lib/dpkg/status for installed Debian packages."""
    packages = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()

        blocks = content.split("\n\n")
        for block in blocks:
            name_m    = re.search(r"^Package:\s*(.+)$", block, re.M)
            version_m = re.search(r"^Version:\s*(.+)$", block, re.M)
            if name_m:
                packages.append(ParsedPackage(
                    name=name_m.group(1).strip().lower(),
                    version=version_m.group(1).strip() if version_m else "",
                    ecosystem="deb",
                    manifest=rel_path,
                ))
    except Exception as e:
        logger.debug("dpkg status parse error: %s", e)
    return packages


# ── Native binary (ELF / PE) ──────────────────────────────────────────────────

def _scan_native_binary(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    findings: dict[str, DependencyFinding] = {}  # deduplicate by algorithm

    # 1. nm — exported/imported symbols
    sym_text = _run_nm(file_path)
    # 2. strings — printable strings
    str_text = _run_strings(file_path)

    combined = sym_text + "\n" + str_text

    for cre, alg, at, risk, qs, rep in _COMPILED:
        m = cre.search(combined)
        if m and alg not in findings:
            findings[alg] = DependencyFinding(
                file_path=artifact_name,
                line_number=0,
                algorithm=alg,
                algo_type=at,
                risk_level=risk,
                quantum_status=qs,
                quantum_safe=False,
                nist_replacement=rep,
                context=f"Crypto symbol/string found in binary: {m.group(0)!r}",
                source_type="artifact",
                dependency_name="",
                dependency_version="",
            )

    return list(findings.values())


def _run_nm(file_path: str) -> str:
    for flag in ["-D", ""]:
        try:
            args = ["nm"] + ([flag] if flag else []) + [file_path]
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
    return ""


def _run_strings(file_path: str) -> str:
    try:
        result = subprocess.run(["strings", file_path],
                                capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


# ── Unknown / generic ─────────────────────────────────────────────────────────

def _scan_unknown(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """Fallback: run strings and look for crypto hints."""
    return _scan_native_binary(file_path, artifact_name)


# ── Shared helper: walk an extracted tree ─────────────────────────────────────

def _scan_extracted_tree(root_dir: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Walk an extracted directory tree.
    Scans package manifests (requirements.txt, pom.xml, etc.) and
    any ELF / Mach-O binaries found inside.
    """
    findings_map: dict[tuple, DependencyFinding] = {}
    packages: list[ParsedPackage] = []

    for root, _, files in os.walk(root_dir):
        for fname in files:
            full = os.path.join(root, fname)
            rel  = os.path.relpath(full, root_dir)
            fl   = fname.lower()

            try:
                file_size = os.path.getsize(full)
            except OSError:
                continue

            # Package manifests
            if fl == "requirements.txt" or re.match(r"requirements[._-].+\.txt$", fl):
                packages.extend(_parse_requirements_txt(full, f"{artifact_name}/{rel}"))
            elif fl == "pyproject.toml":
                packages.extend(_parse_pyproject_toml(full, f"{artifact_name}/{rel}"))
            elif fl == "pom.xml":
                packages.extend(_parse_pom_xml(full, f"{artifact_name}/{rel}"))
            elif fl == "package.json" and "node_modules" not in rel:
                packages.extend(_parse_package_json(full, f"{artifact_name}/{rel}"))
            elif fl in ("metadata", "pkg-info") and (".dist-info" in rel or ".egg-info" in rel):
                packages.extend(_parse_wheel_metadata(full, f"{artifact_name}/{rel}"))
            # Native binaries
            elif file_size > 4:
                try:
                    with open(full, "rb") as fh:
                        magic = fh.read(4)
                    if magic[:4] == b"\x7fELF":
                        for df in _scan_native_binary(full, f"{artifact_name}/{rel}"):
                            key = (f"{artifact_name}/{rel}", df.algorithm)
                            if key not in findings_map:
                                findings_map[key] = df
                    elif magic[:4] in _MACHO_MAGIC:
                        for df in _scan_macho_binary(full, f"{artifact_name}/{rel}"):
                            key = (f"{artifact_name}/{rel}", df.algorithm)
                            if key not in findings_map:
                                findings_map[key] = df
                except OSError:
                    pass

    result = list(findings_map.values())
    result.extend(_check_packages(packages))
    return result


# ── Mach-O binary (macOS .dylib, .framework, universal binaries) ──────────────

def _scan_macho_binary(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """Scan a Mach-O binary using strings (+ otool -L if available)."""
    findings: dict[str, DependencyFinding] = {}

    # strings works on any binary format
    str_text = _run_strings(file_path)
    # nm may work on Mach-O with cross-tools; gracefully skips if not
    sym_text = _run_nm(file_path)
    # otool -L lists linked dylibs (macOS/cross-tool)
    otool_text = ""
    if shutil.which("otool"):
        try:
            r = subprocess.run(["otool", "-L", file_path],
                               capture_output=True, text=True, timeout=15)
            otool_text = r.stdout
        except Exception:
            pass

    combined = sym_text + "\n" + str_text + "\n" + otool_text
    for cre, alg, at, risk, qs, rep in _COMPILED:
        m = cre.search(combined)
        if m and alg not in findings:
            findings[alg] = DependencyFinding(
                file_path=artifact_name,
                line_number=0,
                algorithm=alg,
                algo_type=at,
                risk_level=risk,
                quantum_status=qs,
                quantum_safe=False,
                nist_replacement=rep,
                context=f"Crypto symbol found in Mach-O binary: {m.group(0)!r}",
                source_type="artifact",
                dependency_name="",
                dependency_version="",
            )
    return list(findings.values())


# ── Static archive (.a) ────────────────────────────────────────────────────────

def _scan_static_archive(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan a static library (.a) — ar archive of .o object files.
    Uses `ar x` (binutils) to extract members, then nm+strings on each ELF.
    Falls back to strings on the whole archive if ar is unavailable.
    """
    findings: dict[str, DependencyFinding] = {}
    tmpdir = tempfile.mkdtemp(prefix="pqc_ar_")
    try:
        if shutil.which("ar"):
            result = subprocess.run(["ar", "x", file_path],
                                    cwd=tmpdir, capture_output=True, timeout=60)
            if result.returncode == 0:
                for fname in os.listdir(tmpdir):
                    full = os.path.join(tmpdir, fname)
                    try:
                        with open(full, "rb") as fh:
                            magic = fh.read(4)
                        scanner = None
                        if magic[:4] == b"\x7fELF":
                            scanner = _scan_native_binary
                        elif magic[:4] in _MACHO_MAGIC:
                            scanner = _scan_macho_binary
                        if scanner:
                            for df in scanner(full, f"{artifact_name}/{fname}"):
                                if df.algorithm not in findings:
                                    findings[df.algorithm] = df
                    except OSError:
                        pass
                return list(findings.values())
        # fallback: strings on the whole archive
        return _scan_native_binary(file_path, artifact_name)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Debian .deb package ────────────────────────────────────────────────────────

def _parse_deb_control(path: str, artifact_name: str) -> list[ParsedPackage]:
    """Parse Debian control file Depends/Pre-Depends/Recommends into ParsedPackage list."""
    packages = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        for field_name in ("Depends", "Pre-Depends", "Recommends"):
            m = re.search(rf"^{field_name}:\s*(.+?)(?=\n\S|\Z)", content, re.M | re.S)
            if not m:
                continue
            deps_str = re.sub(r"\s+", " ", m.group(1))
            for dep in deps_str.split(","):
                dep = dep.strip()
                dm = re.match(r"([a-z0-9][a-z0-9.+\-]+)\s*(?:\(([>=<! ]+)\s*([\d.~:+\-]+)\))?", dep)
                if dm:
                    packages.append(ParsedPackage(
                        name=dm.group(1).strip().lower(),
                        version=dm.group(3) or "",
                        ecosystem="deb",
                        manifest=artifact_name,
                    ))
    except Exception as e:
        logger.debug("deb control parse error: %s", e)
    return packages


def _scan_deb_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan a Debian .deb package:
    1. ar x → extract control.tar.* + data.tar.*
    2. Parse control Depends for crypto library deps
    3. Walk data.tar for ELF binaries and package manifests
    """
    findings: list[DependencyFinding] = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_deb_")
    try:
        # Extract the ar archive
        if shutil.which("ar"):
            subprocess.run(["ar", "x", file_path], cwd=tmpdir,
                           capture_output=True, timeout=60)
        else:
            logger.warning("ar not found; cannot extract .deb %s", artifact_name)
            return _scan_native_binary(file_path, artifact_name)

        # Find data.tar.* and control.tar.*
        data_tar_path = ctrl_tar_path = None
        for fname in os.listdir(tmpdir):
            if fname.startswith("data.tar"):
                data_tar_path = os.path.join(tmpdir, fname)
            elif fname.startswith("control.tar"):
                ctrl_tar_path = os.path.join(tmpdir, fname)

        # Parse control for Depends
        if ctrl_tar_path and os.path.exists(ctrl_tar_path):
            ctrl_dir = tempfile.mkdtemp(prefix="pqc_deb_ctrl_")
            try:
                with tarfile.open(ctrl_tar_path) as t:
                    t.extractall(ctrl_dir, filter="data")
                for candidate in ("control", "./control"):
                    ctrl_file = os.path.join(ctrl_dir, candidate)
                    if os.path.exists(ctrl_file):
                        findings.extend(_check_packages(
                            _parse_deb_control(ctrl_file, artifact_name)))
                        break
            except Exception as e:
                logger.debug("deb control extraction error: %s", e)
            finally:
                shutil.rmtree(ctrl_dir, ignore_errors=True)

        # Walk data tarball for ELF + manifests
        if data_tar_path and os.path.exists(data_tar_path):
            data_dir = tempfile.mkdtemp(prefix="pqc_deb_data_")
            try:
                with tarfile.open(data_tar_path) as t:
                    t.extractall(data_dir, filter="data")
                findings.extend(_scan_extracted_tree(data_dir, artifact_name))
            except Exception as e:
                logger.debug("deb data extraction error: %s", e)
            finally:
                shutil.rmtree(data_dir, ignore_errors=True)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Deduplicate
    seen: set[tuple] = set()
    unique: list[DependencyFinding] = []
    for f in findings:
        key = (f.file_path, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Android ARchive (.aar) ─────────────────────────────────────────────────────

def _scan_aar_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan an Android ARchive (.aar):
    - classes.jar  → Java bytecode scan
    - jni/<abi>/*.so → native ELF scan
    - libs/*.jar   → nested JAR scan
    """
    findings: list[DependencyFinding] = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_aar_")
    try:
        with zipfile.ZipFile(file_path) as z:
            z.extractall(tmpdir)

        classes_jar = os.path.join(tmpdir, "classes.jar")
        if os.path.exists(classes_jar):
            findings.extend(_scan_java_artifact(classes_jar, f"{artifact_name}/classes.jar"))

        for subdir in ("jni", "libs"):
            sub = os.path.join(tmpdir, subdir)
            if os.path.exists(sub):
                findings.extend(_scan_extracted_tree(sub, f"{artifact_name}/{subdir}"))
                # scan nested JARs in libs/
                if subdir == "libs":
                    for fname in os.listdir(sub):
                        if fname.lower().endswith(".jar"):
                            findings.extend(
                                _scan_java_artifact(os.path.join(sub, fname),
                                                    f"{artifact_name}/libs/{fname}"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return findings


# ── Android APK ────────────────────────────────────────────────────────────────

def _scan_apk_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan an Android APK:
    - classes.dex  → strings-based scan (Dalvik bytecode)
    - lib/<abi>/*.so → native ELF scan
    """
    findings: dict[str, DependencyFinding] = {}
    tmpdir = tempfile.mkdtemp(prefix="pqc_apk_")
    try:
        with zipfile.ZipFile(file_path) as z:
            z.extractall(tmpdir)

        # Scan .dex files via strings (Dalvik bytecode has readable class refs)
        for fname in os.listdir(tmpdir):
            if fname.endswith(".dex"):
                for df in _scan_native_binary(os.path.join(tmpdir, fname),
                                              f"{artifact_name}/{fname}"):
                    if df.algorithm not in findings:
                        findings[df.algorithm] = df

        # Native libraries
        lib_dir = os.path.join(tmpdir, "lib")
        if os.path.exists(lib_dir):
            for df in _scan_extracted_tree(lib_dir, f"{artifact_name}/lib"):
                if df.algorithm not in findings:
                    findings[df.algorithm] = df
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return list(findings.values())


# ── Ruby Gem (.gem) ────────────────────────────────────────────────────────────

def _parse_gem_metadata(metadata_gz: str, artifact_name: str) -> list[ParsedPackage]:
    """Parse a gem's metadata.gz (YAML) for runtime_dependencies."""
    packages = []
    try:
        with gzip.open(metadata_gz, "rt", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        # YAML structure has "name: <gem>" lines under dependencies.
        # We extract all dependency names conservatively.
        in_deps = False
        for line in content.splitlines():
            if re.match(r"^(runtime_)?dependencies\s*:", line):
                in_deps = True
            elif in_deps and line and not line.startswith(" "):
                in_deps = False
            if in_deps:
                m = re.match(r"\s+name\s*:\s*(.+)", line)
                if m:
                    packages.append(ParsedPackage(
                        name=m.group(1).strip().strip("'\"").lower(),
                        version="",
                        ecosystem="gem",
                        manifest=artifact_name,
                    ))
    except Exception as e:
        logger.debug("gem metadata parse error: %s", e)
    return packages


def _scan_gem_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan a Ruby gem (.gem):
    1. Outer tarball → metadata.gz (YAML deps) + data.tar.gz (contents)
    2. Parse runtime dependencies
    3. Scan data.tar.gz for ELF binaries + package manifests
    """
    findings: list[DependencyFinding] = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_gem_")
    try:
        with tarfile.open(file_path) as t:
            t.extractall(tmpdir, filter="data")

        metadata_gz = os.path.join(tmpdir, "metadata.gz")
        if os.path.exists(metadata_gz):
            findings.extend(_check_packages(
                _parse_gem_metadata(metadata_gz, artifact_name)))

        data_tar = os.path.join(tmpdir, "data.tar.gz")
        if os.path.exists(data_tar):
            data_dir = tempfile.mkdtemp(prefix="pqc_gem_data_")
            try:
                with tarfile.open(data_tar) as t:
                    t.extractall(data_dir, filter="data")
                findings.extend(_scan_extracted_tree(data_dir, artifact_name))
            finally:
                shutil.rmtree(data_dir, ignore_errors=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return findings


# ── NuGet package (.nupkg) ─────────────────────────────────────────────────────

def _parse_nuspec(path: str, rel_path: str) -> list[ParsedPackage]:
    """Parse .nuspec XML for <dependency id=... version=...> entries."""
    packages = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        for m in re.finditer(r'<dependency[^>]+id="([^"]+)"[^>]*(?:version="([^"]*)")?', content, re.I):
            packages.append(ParsedPackage(
                name=m.group(1).strip().lower(),
                version=m.group(2) or "",
                ecosystem="nuget",
                manifest=rel_path,
            ))
    except Exception as e:
        logger.debug("nuspec parse error: %s", e)
    return packages


def _scan_nupkg_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan a NuGet package (.nupkg):
    1. Unzip → parse .nuspec for dependency names
    2. Scan runtimes/ directory for native ELF/Mach-O binaries
    """
    findings: list[DependencyFinding] = []
    tmpdir = tempfile.mkdtemp(prefix="pqc_nuget_")
    try:
        with zipfile.ZipFile(file_path) as z:
            z.extractall(tmpdir)

        packages: list[ParsedPackage] = []
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if fname.lower().endswith(".nuspec"):
                    full = os.path.join(root, fname)
                    rel  = os.path.relpath(full, tmpdir)
                    packages.extend(_parse_nuspec(full, f"{artifact_name}/{rel}"))
        findings.extend(_check_packages(packages))

        runtimes = os.path.join(tmpdir, "runtimes")
        if os.path.exists(runtimes):
            findings.extend(_scan_extracted_tree(runtimes, f"{artifact_name}/runtimes"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return findings


# ── Generic ZIP ────────────────────────────────────────────────────────────────

def _scan_zip_generic(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """Walk a generic ZIP archive for manifests and ELF/Mach-O binaries."""
    tmpdir = tempfile.mkdtemp(prefix="pqc_zip_")
    try:
        with zipfile.ZipFile(file_path) as z:
            z.extractall(tmpdir)
        return _scan_extracted_tree(tmpdir, artifact_name)
    except Exception as e:
        logger.debug("ZIP extraction failed for %s: %s", artifact_name, e)
        return _scan_native_binary(file_path, artifact_name)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── RPM package ───────────────────────────────────────────────────────────────

# RPM header tag IDs we care about
_RPM_TAG_NAME         = 1000
_RPM_TAG_VERSION      = 1001
_RPM_TAG_RELEASE      = 1002
_RPM_TAG_REQUIRENAME  = 1049
_RPM_TAG_REQUIREVER   = 1050

# RPM tag types
_RPM_TYPE_STRING      = 6
_RPM_TYPE_STRING_ARRAY= 8
_RPM_TYPE_I18NSTRING  = 9


def _parse_rpm_header(file_path: str) -> tuple[str, str, list[ParsedPackage]]:
    """
    Pure-Python RPM header parser.
    Returns (pkg_name, pkg_version, list[ParsedPackage] of Requires).
    Works without any external tools — reads the binary header directly.
    """
    pkg_name    = ""
    pkg_version = ""
    requires: list[ParsedPackage] = []

    try:
        with open(file_path, "rb") as fh:
            # ── Lead (96 bytes) ────────────────────────────────────────────
            lead = fh.read(96)
            if lead[:4] != b"\xed\xab\xee\xdb":
                return pkg_name, pkg_version, requires

            # ── Skip Signature header ──────────────────────────────────────
            # Each header starts with magic 0x8EADE801, then 4 reserved bytes,
            # then nindex (4 bytes BE), then hsize (4 bytes BE).
            def _skip_header(fh):
                magic = fh.read(8)          # 8-byte magic + reserved
                if len(magic) < 8:
                    return False
                nindex = int.from_bytes(fh.read(4), "big")
                hsize  = int.from_bytes(fh.read(4), "big")
                fh.read(nindex * 16 + hsize)   # skip index + store
                # Headers are aligned to 8-byte boundaries
                pos = fh.tell()
                pad = (8 - pos % 8) % 8
                fh.read(pad)
                return True

            if not _skip_header(fh):
                return pkg_name, pkg_version, requires

            # ── Main header ────────────────────────────────────────────────
            magic = fh.read(8)
            if len(magic) < 8:
                return pkg_name, pkg_version, requires

            nindex = int.from_bytes(fh.read(4), "big")
            hsize  = int.from_bytes(fh.read(4), "big")

            # Read all index entries
            index_data = fh.read(nindex * 16)
            store_data = fh.read(hsize)

            def _read_string(store: bytes, offset: int) -> str:
                end = store.index(b"\x00", offset)
                return store[offset:end].decode("utf-8", errors="ignore")

            def _read_string_array(store: bytes, offset: int, count: int) -> list[str]:
                results, pos = [], offset
                for _ in range(count):
                    end = store.index(b"\x00", pos)
                    results.append(store[pos:end].decode("utf-8", errors="ignore"))
                    pos = end + 1
                return results

            for i in range(nindex):
                base   = i * 16
                tag    = int.from_bytes(index_data[base:base+4],   "big")
                t_type = int.from_bytes(index_data[base+4:base+8], "big")
                offset = int.from_bytes(index_data[base+8:base+12], "big")
                count  = int.from_bytes(index_data[base+12:base+16], "big")

                if tag == _RPM_TAG_NAME and t_type in (_RPM_TYPE_STRING, _RPM_TYPE_I18NSTRING):
                    pkg_name = _read_string(store_data, offset)

                elif tag == _RPM_TAG_VERSION and t_type in (_RPM_TYPE_STRING, _RPM_TYPE_I18NSTRING):
                    pkg_version = _read_string(store_data, offset)

                elif tag == _RPM_TAG_REQUIRENAME and t_type == _RPM_TYPE_STRING_ARRAY:
                    req_names = _read_string_array(store_data, offset, count)
                    # Try to pair with versions (tag 1050 follows 1049 in practice)
                    for rname in req_names:
                        # Skip internal RPM deps (rpmlib, config, /bin/sh etc.)
                        if rname.startswith(("rpmlib(", "/", "config(", "rtld(")):
                            continue
                        requires.append(ParsedPackage(
                            name=rname.lower().split("(")[0].strip(),
                            version="",
                            ecosystem="rpm",
                            manifest=file_path,
                        ))

    except Exception as e:
        logger.debug("RPM header parse error: %s", e)

    return pkg_name, pkg_version, requires


def _scan_rpm_artifact(file_path: str, artifact_name: str) -> list[DependencyFinding]:
    """
    Scan an RPM package for quantum-vulnerable cryptography.

    Strategy:
    1. Parse RPM header (pure Python) → check declared Requires against CRYPTO_PACKAGE_MAP
    2. If rpm2cpio + cpio are available → extract payload → scan ELF/PE binaries
       and any package manifests (requirements.txt, pom.xml, etc.) inside the RPM
    3. Otherwise fall back to strings-based scan on the raw RPM file
    """
    findings: list[DependencyFinding] = []
    tmpdir   = tempfile.mkdtemp(prefix="pqc_rpm_")

    try:
        # ── 1. Parse RPM header for declared dependencies ─────────────────
        pkg_name, pkg_version, requires = _parse_rpm_header(file_path)
        logger.info("RPM: %s-%s  requires %d packages", pkg_name, pkg_version, len(requires))

        # Annotate each require with the RPM name as manifest path
        for r in requires:
            r.manifest = artifact_name

        findings.extend(_check_packages(requires))

        # ── 2. Try extraction with rpm2cpio + cpio ────────────────────────
        rpm2cpio_ok = shutil.which("rpm2cpio") and shutil.which("cpio")
        if rpm2cpio_ok:
            findings.extend(_extract_and_scan_rpm(file_path, artifact_name, tmpdir))
        else:
            # ── 3. Strings fallback on raw RPM binary ─────────────────────
            logger.info("rpm2cpio not found — falling back to strings scan for %s", artifact_name)
            findings.extend(_scan_native_binary(file_path, artifact_name))

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Deduplicate by (file_path, algorithm)
    seen: set[tuple] = set()
    unique: list[DependencyFinding] = []
    for f in findings:
        key = (f.file_path, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def _extract_and_scan_rpm(file_path: str, artifact_name: str, tmpdir: str) -> list[DependencyFinding]:
    """Extract RPM payload with rpm2cpio | cpio and scan the contents."""
    try:
        extract_cmd = f"rpm2cpio {shlex.quote(file_path)} | cpio -idm --quiet"
        result = subprocess.run(
            extract_cmd, shell=True, cwd=tmpdir,
            capture_output=True, timeout=120,
        )
        if result.returncode != 0:
            logger.warning("rpm2cpio extraction failed: %s", result.stderr[:200])
            return []
    except Exception as e:
        logger.warning("RPM extraction error: %s", e)
        return []

    return _scan_extracted_tree(tmpdir, artifact_name)


# ── Package → finding check ───────────────────────────────────────────────────

def _check_packages(packages: list[ParsedPackage]) -> list[DependencyFinding]:
    """Cross-check parsed packages against CRYPTO_PACKAGE_MAP."""
    findings = []
    seen: set[tuple] = set()

    for pkg in packages:
        key = (pkg.ecosystem.lower(), pkg.name.lower())
        info = CRYPTO_PACKAGE_MAP.get(key)
        if not info:
            continue
        if not _is_vulnerable(pkg.version, info.get("vulnerable_below")):
            continue

        dedup_key = (pkg.manifest, info["algorithm"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        ver_str = f" {pkg.version}" if pkg.version else ""
        findings.append(DependencyFinding(
            file_path=pkg.manifest,
            line_number=0,
            algorithm=info["algorithm"],
            algo_type=info.get("algo_type", "Unknown"),
            risk_level=info["risk_level"],
            quantum_status=info["quantum_status"],
            quantum_safe=False,
            nist_replacement=info.get("nist_replacement", ""),
            context=f"{pkg.name}{ver_str} — {info.get('reason', '')}",
            source_type="artifact",
            dependency_name=pkg.name,
            dependency_version=pkg.version,
        ))

    return findings

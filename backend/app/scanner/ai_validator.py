"""
AI Validator — Phase 3.2
Uses a locally-running Ollama instance (IBM Granite) to confirm whether a
scanner finding is a genuine cryptographic usage or a false positive.

The validator is intentionally fault-tolerant:
  - If Ollama is not running, raises OllamaUnavailable (caller decides action)
  - If the model returns unparseable JSON, falls back to keyword heuristics
  - Timeout: 60 s per request (CPU inference of granite-code:3b ≈ 10–40 s)
"""

import json
import logging
import os
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_URL",   "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "granite-code:3b")
OLLAMA_TIMEOUT  = 90   # seconds — CPU inference can be slow

PROMPT_TEMPLATE = """\
You are a post-quantum cryptography security expert reviewing code scanner results.

A scanner flagged the following source code for using the cryptographic algorithm "{algorithm}".
Your task: decide if the flag is a TRUE POSITIVE (actual crypto usage) or FALSE POSITIVE (non-crypto context).

File: {file_path}  |  Line: {line_number}  |  Algorithm: {algorithm} ({algo_type})

Code context (line {line_number} is the flagged line):
```
{context}
```

Respond with ONLY valid JSON — no markdown, no extra text:
{{"is_crypto_usage": true, "confidence": 0.95, "label": "true_positive", "explanation": "one or two sentences"}}

Rules for label:
  "true_positive"  — code actively uses {algorithm} for cryptographic operations
  "false_positive" — algorithm name appears only in comments, strings, variable names,
                     or non-cryptographic logic (e.g. scheduling, routing)
  "uncertain"      — context is ambiguous or insufficient to determine

confidence: float 0.0–1.0 reflecting certainty of your judgment
"""


class OllamaUnavailable(RuntimeError):
    """Raised when the Ollama service cannot be reached."""


@dataclass
class AIValidationResult:
    is_crypto_usage: bool
    confidence:      float    # 0.0 – 1.0
    label:           str      # true_positive | false_positive | uncertain
    explanation:     str
    model:           str


def _extract_json(text: str) -> dict:
    """
    Extract the first JSON object from a model response.
    Handles cases where the model wraps JSON in markdown code fences.
    """
    # Strip markdown fences if present
    text = re.sub(r"```[a-z]*\n?", "", text).strip()
    # Find first { ... }
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError("No JSON object found in model response")


def _fallback_result(raw: str, model: str) -> AIValidationResult:
    """
    When the model returns non-JSON, use keyword heuristics to guess.
    """
    lower = raw.lower()
    is_fp = any(kw in lower for kw in [
        "false positive", "not a crypto", "not cryptograph",
        "comment", "string literal", "variable name",
        "no cryptograph", "non-cryptograph",
    ])
    label = "false_positive" if is_fp else "uncertain"
    return AIValidationResult(
        is_crypto_usage = not is_fp,
        confidence      = 0.4,
        label           = label,
        explanation     = raw[:300].strip(),
        model           = model,
    )


def validate_finding(finding: dict) -> AIValidationResult:
    """
    Send a finding to Ollama/Granite for AI validation.

    Args:
        finding: dict with keys algorithm, algo_type, file_path,
                 line_number, context

    Returns:
        AIValidationResult

    Raises:
        OllamaUnavailable: if the Ollama server is not reachable
    """
    model = OLLAMA_MODEL
    prompt = PROMPT_TEMPLATE.format(
        algorithm   = finding.get("algorithm", "Unknown"),
        algo_type   = finding.get("algo_type",  "Unknown"),
        file_path   = finding.get("file_path",  "unknown"),
        line_number = finding.get("line_number", 0),
        context     = finding.get("context",    "(no context available)"),
    )

    try:
        resp = httpx.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
    except httpx.ConnectError as exc:
        raise OllamaUnavailable(f"Cannot connect to Ollama at {OLLAMA_BASE_URL}") from exc
    except httpx.HTTPStatusError as exc:
        raise OllamaUnavailable(f"Ollama returned {exc.response.status_code}") from exc

    raw = resp.json().get("response", "")
    logger.debug("Granite raw response for %s:%s — %s",
                 finding.get("file_path"), finding.get("line_number"), raw[:200])

    try:
        data = _extract_json(raw)
        return AIValidationResult(
            is_crypto_usage = bool(data.get("is_crypto_usage", True)),
            confidence      = max(0.0, min(1.0, float(data.get("confidence", 0.5)))),
            label           = data.get("label", "uncertain"),
            explanation     = str(data.get("explanation", ""))[:500],
            model           = model,
        )
    except (json.JSONDecodeError, ValueError, KeyError) as exc:
        logger.warning("Could not parse Granite JSON (%s) — using heuristic fallback", exc)
        return _fallback_result(raw, model)

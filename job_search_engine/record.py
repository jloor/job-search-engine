"""The submit record and its fingerprint: what a person approves, and what a live run must match.

⭐ ONE IMPLEMENTATION, TWO CALLERS. The runner computes the fingerprint from what the page read
back; the relay recomputes it from the record the runner posted, and again when the passkey
assertion arrives. If the two sides normalised differently, an honest run could never match its
own approval, so both import this file. Standard library only.

What is bound: the application, the posting URL, every field (id, label, value), and the SHA-256
of each attached file. What is NOT bound: screenshots. Pixels change between runs of the same
form, and the field values are what an employer receives.
"""
from __future__ import annotations

import hashlib
import json
import re


def canonical_fields(fields: list) -> list:
    """[{id, label, value}] sorted by id, whitespace collapsed. Order and spacing never matter."""
    out = []
    for f in fields or []:
        out.append({"id": str(f.get("id") or ""),
                    "label": " ".join(str(f.get("label") or "").split()),
                    "value": " ".join(str(f.get("value") if f.get("value") is not None else "").split())})
    return sorted(out, key=lambda x: x["id"])


def _sha_ok(s: str | None) -> str:
    s = (s or "").strip().lower()
    if s and not re.fullmatch(r"[0-9a-f]{64}", s):
        raise ValueError("a file hash must be 64 lowercase hex characters")
    return s


def fingerprint(application_id: int, url: str, fields: list, files: dict) -> str:
    """64 hex characters. Each part is hashed separately, so text moved between parts changes it.

    `files` maps a filename (resume.pdf, cover-letter.pdf) to its SHA-256; missing means none."""
    parts = [str(int(application_id)), (url or "").strip(),
             json.dumps(canonical_fields(fields), sort_keys=True, separators=(",", ":"), ensure_ascii=False)]
    for name in sorted((files or {}).keys()):
        parts.append(f"{name}:{_sha_ok(files[name])}")
    h = hashlib.sha256()
    for p in parts:
        h.update(hashlib.sha256(p.encode("utf-8")).digest())
    return h.hexdigest()


def file_sha(path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

"""Ashby's public job-board API, for the submitter: whether a posting is still open and what it
says. Standard library only. The Greenhouse twin is greenhouse.py.

⭐ ASHBY HAS NO QUESTIONS API. Greenhouse describes every form field over its API; Ashby's
public posting API describes the job only. So the page decides everything about the form, and
this module answers liveness and the gates.

⚠️ ONE FAILED CALL IS NOT A CLOSED REQUISITION. Same rule as greenhouse.py: a posting only counts
as gone when the board itself answers and does not list it.

⚠️ THE FORM LIVES AT <posting>/application. The posting page has no fields at all (the private
harvester learned this the hard way). The record fingerprint keeps the CANONICAL posting URL,
because the relay recomputes it from posting.canonical_url.
"""
from __future__ import annotations

import html
import re

import greenhouse as GH                                        # the shared retrying HTTP helpers

API = "https://api.ashbyhq.com/posting-api/job-board"
RE_POSTING = re.compile(r"jobs\.ashbyhq\.com/([A-Za-z0-9._-]+)/([0-9a-fA-F-]{36})")

NotFound = GH.NotFound


def is_ashby(url: str | None) -> bool:
    return bool(RE_POSTING.search(url or ""))


def parse(url: str) -> tuple[str, str]:
    """(board token, posting id). Raises ValueError for anything else."""
    m = RE_POSTING.search(url or "")
    if not m:
        raise ValueError(f"not an Ashby posting URL: {url}")
    return m.group(1), m.group(2).lower()


def hosted_url(token: str, pid: str) -> str:
    return f"https://jobs.ashbyhq.com/{token}/{pid}/application"


def _board(token: str, opener=None) -> dict:
    return GH._get_json(f"{API}/{token}?includeCompensation=true", opener)


def board_exists(token: str, opener=None) -> bool:
    try:
        _board(token, opener)
        return True
    except NotFound:
        return False


def job(token: str, pid: str, opener=None) -> dict:
    """The posting from the board's own listing. Raises NotFound when the board answers and does
    not list it (a removed posting), or when the board itself is gone."""
    for j in _board(token, opener).get("jobs") or []:
        if str(j.get("id") or "").lower() == pid.lower():
            return j
    raise NotFound(f"posting {pid} is not on board {token}")


def description(job_doc: dict) -> str:
    plain = job_doc.get("descriptionPlain")
    if plain:
        return plain
    raw = html.unescape(job_doc.get("descriptionHtml") or "")
    raw = re.sub(r"<(br|/p|/li|/h\d)[^>]*>", "\n", raw, flags=re.I)
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))


def location(job_doc: dict) -> str:
    return str(job_doc.get("location") or "").strip()

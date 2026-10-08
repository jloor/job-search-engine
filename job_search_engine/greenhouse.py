"""Greenhouse's public job-board API, for the submitter: where a form lives, whether it is still
open, and what it asks. Standard library only.

⭐ WHY THE API AND THE PAGE BOTH. The API gives each question's exact label, its field names and
the options of every select, which the rendered page hides until a menu is opened. The page has
fields the API does not list (a country picker beside the phone number is one). So the API
describes the questions and the page decides what exists; submit.py uses both.

⚠️ ONE FAILED CALL IS NOT A CLOSED REQUISITION. A throttled host and a closed job look the same
on a single failure, so every call is retried, and a 404 for a job only counts as "gone" when the
board itself still answers.
"""
from __future__ import annotations

import html
import json
import re
import time
import urllib.error
import urllib.request

API = "https://boards-api.greenhouse.io/v1/boards"
UA = {"User-Agent": "Mozilla/5.0 (job-search-engine submitter)", "Accept": "application/json"}

RE_HOSTED = re.compile(r"(?:job-boards|boards)(?:\.eu)?\.greenhouse\.io/(?:embed/job_app\?for=)?"
                       r"([A-Za-z0-9_-]+)/jobs/(\d+)")
RE_EMBED_APP = re.compile(r"greenhouse\.io/embed/job_app\?[^\"' ]*?for=([A-Za-z0-9_-]+)[^\"' ]*?token=(\d+)")
RE_GH_JID = re.compile(r"[?&]gh_jid=(\d+)")
# The token an employer's careers page loads its embedded board with.
RE_BOARD_SCRIPT = re.compile(r"greenhouse\.io/embed/job_board/js\?for=([A-Za-z0-9_-]+)")
RE_FOR = re.compile(r"greenhouse\.io/embed/job_(?:board|app)[^\"' ]*?[?&]for=([A-Za-z0-9_-]+)")


class NotFound(Exception):
    """A 404 or 410 from the API."""


def _retry(fn, tries: int = 3):
    for i in range(tries):
        try:
            return fn()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                raise NotFound(str(e)) from e
            if i == tries - 1:
                raise
        except Exception:                                         # noqa: BLE001
            if i == tries - 1:
                raise
        time.sleep(1.5 * (i + 1))


def _get_json(url: str, opener=None) -> dict:
    op = opener or urllib.request.urlopen

    def go():
        with op(urllib.request.Request(url, headers=UA), timeout=25) as r:
            return json.loads(r.read().decode())
    return _retry(go)


def _get_text(url: str, opener=None) -> str:
    op = opener or urllib.request.urlopen

    def go():
        with op(urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]}), timeout=25) as r:
            return r.read().decode("utf-8", "replace")
    return _retry(go)


def is_greenhouse(url: str | None) -> bool:
    u = url or ""
    return bool(RE_HOSTED.search(u) or RE_EMBED_APP.search(u) or RE_GH_JID.search(u))


def parse(url: str) -> tuple[str | None, str | None]:
    """(board token, job id) from a URL. The token is None for an employer-site embed."""
    m = RE_HOSTED.search(url) or RE_EMBED_APP.search(url)
    if m:
        return m.group(1), m.group(2)
    j = RE_GH_JID.search(url)
    return (None, j.group(1)) if j else (None, None)


def resolve(url: str, opener=None) -> tuple[str, str]:
    """(token, job id) for any Greenhouse URL, reading the employer's page for an embed.

    Raises ValueError when no token can be found. ⚠️ Never guess the token from the company
    name: a guessed token can belong to a different employer whose board happens to answer.
    """
    tok, jid = parse(url)
    if not jid:
        raise ValueError(f"not a Greenhouse job URL: {url}")
    if tok:
        return tok, jid
    page = _get_text(url, opener)
    m = RE_BOARD_SCRIPT.search(page) or RE_FOR.search(page)
    if not m:
        raise ValueError("the page embeds a Greenhouse job but names no board token")
    return m.group(1), jid


def hosted_url(token: str, jid: str) -> str:
    """The form on Greenhouse's own host. An embed renders the same form inside an iframe, and
    filling the hosted page directly avoids driving a frame."""
    return f"https://job-boards.greenhouse.io/{token}/jobs/{jid}"


def board_exists(token: str, opener=None) -> bool:
    try:
        _get_json(f"{API}/{token}", opener)
        return True
    except NotFound:
        return False


def job(token: str, jid: str, opener=None) -> dict:
    """The job with its questions. Raises NotFound."""
    return _get_json(f"{API}/{token}/jobs/{jid}?questions=true", opener)


def questions(job_doc: dict) -> dict:
    """Every field the API describes, keyed by field name:
    {name: {"label", "required", "type", "options": [labels], "group"}}.
    "group" is questions | location | compliance | demographic."""
    out: dict = {}

    def add(q: dict, group: str):
        for f in q.get("fields") or []:
            name = f.get("name")
            if not name or name in out:
                continue
            out[name] = {"label": html.unescape(q.get("label") or ""),
                         "required": bool(q.get("required")),
                         "type": f.get("type") or "",
                         "options": [html.unescape(v.get("label") or "") for v in f.get("values") or []],
                         "group": group}

    for q in job_doc.get("questions") or []:
        add(q, "questions")
    for q in job_doc.get("location_questions") or []:
        add(q, "location")
    for block in job_doc.get("compliance") or []:
        for q in block.get("questions") or []:
            add(q, "compliance")
    demo = job_doc.get("demographic_questions") or {}
    for q in (demo.get("questions") if isinstance(demo, dict) else demo) or []:
        name = f"demographic_{q.get('id')}"
        if name not in out:
            out[name] = {"label": html.unescape(q.get("label") or ""),
                         "required": bool(q.get("required")), "type": q.get("type") or "",
                         "options": [html.unescape(o.get("label") or "")
                                     for o in q.get("answer_options") or []],
                         "group": "demographic"}
    return out


def description(job_doc: dict) -> str:
    """The posting text as plain text. The API returns it HTML-escaped AND as HTML."""
    raw = html.unescape(job_doc.get("content") or "")
    raw = re.sub(r"<(br|/p|/li|/h\d)[^>]*>", "\n", raw, flags=re.I)
    return html.unescape(re.sub(r"<[^>]+>", " ", raw))

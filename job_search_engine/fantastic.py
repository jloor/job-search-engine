"""The Fantastic Jobs API as a discovery source. Client and field map, nothing else.

⭐ WHY THIS MODULE IS DELIBERATELY THIN. The board sweep finds postings on six ATS
platforms. This API reads 55. That is the ONLY thing it is here to do. Every judgement the
pipeline makes stays where it is: the gates read the candidate profile, `job_triage` scores
fit, `remote_check` reaches the remote verdict, `place` measures the commute. A discovery
source that started deciding things would be a second pipeline with no tests.

🚨 THEIR DERIVED FIELDS ARE NEVER OUR VERDICTS. Measured 2026-09-14 on one posting:
`ai_work_arrangement` reported "On-site" while the employer's own SmartRecruiters record
said `remote: true, hybrid: false`. Remote is a hard filter in some profiles, so a wrong
value there deletes a viable role in silence. `to_posting` therefore returns is_remote=None
always, and it maps their salary with a source of its own so it can never be mistaken for a
number the employer published.

🚨 JOB RECORDS ARE THE METERED UNIT, NOT REQUESTS. One credit per job RETURNED. So a filter
that runs after the response has already been paid for saves nothing: narrowing must happen
in the QUERY. `params()` pushes the title, location and organization exclusions into the
request for that reason, not for tidiness.

📌 Complimentary endpoints (expired, modified, organizations) cost no job credits at all.
They still cost one API request each.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://data.fantastic.jobs/v1"
TIMEOUT = 60
# Their maximum is 1000 and their minimum useful page is 100. This is a page size, not a
# budget: every row returned is billed either way, so a small limit does not save money,
# it only costs more requests to collect the same rows.
PAGE = 200
# ⚠️ A BACKSTOP AGAINST A QUERY THAT MATCHES THE WHOLE FEED, not a budget. A filter typo
# ("location=United" instead of a real place) turns a 40-row pull into a 100,000-row one
# and the bill is the first place it shows. Refuse rather than spend.
MAX_PAGES = 25

USER_AGENT = "job-search-engine (discovery; one poll per interval)"


class Denied(RuntimeError):
    """The plan does not include this endpoint. Not a failure, a tier boundary.

    ⚠️ Kept separate from a network error on purpose. `modified-ats` needs a Pro plan and a
    caller on a lower tier must be able to skip it quietly forever, while a 500 from the
    same endpoint is worth reporting every time it happens.
    """


def call(endpoint: str, params: dict, key: str, timeout: int = TIMEOUT) -> tuple:
    """(payload, quota). Raises on anything that is not a usable answer.

    `quota` is read off the response headers because THE PRICING PAGE RENDERS IN
    JAVASCRIPT AND SHOWS NOTHING TO A SCRIPT. These headers are the only machine-readable
    record of what a pull cost, which is why every caller stores them rather than logging
    them. `jobs_this_request` is exact for the current response; the `remaining` values are
    cached for a few seconds and can lag a burst of calls.
    """
    q = {k: v for k, v in params.items() if v not in (None, "")}
    url = f"{BASE}/{endpoint}?" + urllib.parse.urlencode(q, doseq=True)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {key}", "Accept": "application/json",
        "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            head = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:                        # noqa: PERF203
        # 402/403 is "your plan does not cover this". 429 is the rate limit and is a
        # different problem with a different fix, so it is not swallowed here.
        if e.code in (401, 402, 403):
            raise Denied(f"{endpoint}: HTTP {e.code}, the plan does not cover this call")
        raise
    return json.loads(body or b"null"), quota(head)


def quota(head: dict) -> dict:
    """The cost ledger for one call, from the x-api-* headers."""
    def num(name):
        try:
            return int(head.get(name))
        except (TypeError, ValueError):
            return None
    return {"jobs_spent": num("x-api-jobs-this-request"),
            "jobs_remaining": num("x-api-jobs-remaining"),
            "jobs_limit": num("x-api-jobs-limit"),
            "requests_remaining": num("x-api-requests-remaining"),
            "requests_limit": num("x-api-requests-limit"),
            "next_billing": head.get("x-api-next-billing-date")}


def params(query: dict, shared: dict | None = None, since: str = "") -> dict:
    """Build one request's parameters from a profile query plus the shared filters.

    ⭐ THE EXCLUSIONS BELONG IN THE REQUEST. A company the operator will not work for and a
    seniority band they cannot reach both cost a job credit if they come back in the
    response. `exclude_organization` and `ai_experience_level` are free to send.

    ⚠️ `since` SWITCHES THE WINDOW, and that is the documented outage-recovery path rather
    than a second mode we invented. `1h` is a rolling hour and cannot reach back further, so
    replaying a gap means asking the 7-day window for everything indexed after a watermark.
    """
    p = dict(shared or {})
    p.update(query)
    if since:
        p["time_frame"] = "7d"
        p["date_created_gte"] = since
    p.setdefault("time_frame", "1h")
    p.setdefault("limit", PAGE)
    # Descriptions are omitted by default and the triage step cannot read a posting without
    # one. `text` rather than `html`: their html is unsanitised scraped markup and every tag
    # in it would be billed again as triage tokens.
    p.setdefault("description_format", "text")
    return p


def pages(endpoint: str, p: dict, key: str, max_pages: int = MAX_PAGES, budget: int = 0):
    """Yield (rows, quota) per page, offset-paginated, until a short page ends it.

    🚨 `budget` BOUNDS WHAT IS ASKED FOR, NOT ONLY WHEN TO STOP. Credits are spent when a
    row is RETURNED, so a caller that fetches a full page and then decides it has enough has
    already paid for the overshoot. Measured 2026-09-14: a `--cap 40` run spent 100 credits
    for exactly this reason, because the cap was tested after the page came back.

    So the limit sent is clamped to what remains of the budget on every request. A caller
    that passes no budget keeps the old behaviour.

    📌 `offset` counts ROWS ALREADY FETCHED rather than pages, because the clamp makes pages
    different sizes and `page_number * limit` would then skip rows.
    """
    limit = int(p.get("limit") or PAGE)
    seen = 0
    for _ in range(max_pages):
        ask = min(limit, budget - seen) if budget else limit
        if ask <= 0:
            return
        got, q = call(endpoint, {**p, "limit": ask, "offset": seen}, key)
        rows = got if isinstance(got, list) else []
        seen += len(rows)
        yield rows, q
        # A short page means the window is exhausted. Asking again costs a request and
        # returns nothing.
        if len(rows) < ask:
            return
        if budget and seen >= budget:
            return
    raise RuntimeError(
        f"{endpoint}: more than {max_pages} pages for one query. Refusing to keep "
        f"spending: narrow the filter rather than raising this cap.")


# ───────────────────────────────────────────────────────────────────── the field map

def norm_url(u: str) -> str:
    """One spelling of a URL, for comparison only. Never stored in place of the original.

    ⚠️ The SAME requisition arrives from the board sweep and from this API with different
    query strings and a different trailing slash, and a dedupe that misses it writes the
    posting twice. The original is what gets stored: this is only ever a join key.
    """
    u = (u or "").strip().split("#")[0]
    u = re.sub(r"[?&](utm_[^=]+|gh_src|source|ref)=[^&]*", "", u)
    return u.split("?")[0].rstrip("/").lower()


def their_id(req_id: str) -> str:
    """Their `id` back out of our req_id. 'fantastic|greenhouse:4711345006' -> '4711345006'.

    📌 Safe because the prefix contains no colon: 'fantastic|<source>' is a fixed shape this
    module writes itself. It is the join for the expired feed, which returns ids and nothing
    else, so it has to survive a round trip through the database.
    """
    return (req_id or "").rpartition(":")[2]


def contains(a: str, b: str, floor: int = 5) -> bool:
    """Containment with a length floor, the rule the rest of the pipeline already uses.

    🚨 NOT EQUALITY AND NOT A BARE SUBSTRING. Equality misses "Invisibletech" against
    "Invisible Technologies"; a bare substring once matched a company named "H" inside five
    unrelated ones. The floor is what makes containment safe.
    """
    a = re.sub(r"[^a-z0-9]", "", (a or "").lower())
    b = re.sub(r"[^a-z0-9]", "", (b or "").lower())
    if len(a) < floor or len(b) < floor:
        return a == b and bool(a)
    return a in b or b in a


def salary_text(row: dict) -> str | None:
    """The EMPLOYER'S OWN pay field, rendered as text for the existing comp reader.

    🚨 THIS IS THE HIGHEST-PROVENANCE NUMBER THE FEED CARRIES AND IT WAS BEING DISCARDED.
    `salary` is the schema.org MonetaryAmount the employer published, distinct from the
    `ai_salary_*` fields, which are somebody's extraction. Measured over 183 sample rows it
    is present on only 18 (9%), but on those 18 it outranks everything else: `comp.extract`
    labels it `board`, meaning the employer said it, and that is the number a negotiation
    later stands on.

    ⚠️ THREE REAL SHAPES IN THE SAMPLE, EACH OF WHICH BREAKS THE OBVIOUS PARSE:
        {"minValue": 0, "maxValue": 0, "unitText": "YEAR"}        a zero band
        {"minValue": "86,502", "maxValue": "104,400"}             STRINGS, with commas
        {"minValue": "70", "maxValue": "78", "unitText": "hour"}  lowercase unit
    So this renders text and hands it to the reader that already survives all three:
    `_plausible` rejects the zero band, `_to_number` handles the commas, and the period is
    matched case-insensitively. Parsing the numbers here would be a second implementation
    of a rule that already exists, and the two would drift.
    """
    sal = row.get("salary")
    if not isinstance(sal, dict):
        return None
    v = sal.get("value")
    v = v if isinstance(v, dict) else sal
    lo, hi = v.get("minValue"), v.get("maxValue")
    if lo is None and hi is None:
        lo = hi = v.get("value")
    if lo is None and hi is None:
        return None
    unit = str(v.get("unitText") or sal.get("unitText") or "YEAR").lower()
    per = {"year": "per year", "month": "per month", "week": "per week",
           "day": "per day", "hour": "per hour"}.get(unit, "per year")
    cur = "$" if str(sal.get("currency") or "USD").upper() == "USD" else ""
    lo_s, hi_s = str(lo if lo is not None else hi), str(hi if hi is not None else lo)
    return f"{cur}{lo_s} - {cur}{hi_s} {per}"


_UNIT = {"YEAR": "base", "MONTH": "base/month", "WEEK": "base/week",
         "DAY": "base/day", "HOUR": "base/hour"}


def to_posting(row: dict) -> dict:
    """One API record as the posting dict the rest of the engine already understands.

    🚨 is_remote IS ALWAYS None. NULL means "the source did not say". Writing 0 for an
    unknown reads downstream as "confirmed not remote", which is the exact absence-is-not-a-
    verdict mistake the remote gate is built to avoid, and their arrangement field has
    already been measured wrong on a real posting.
    """
    src = (row.get("source") or "unknown").strip().lower()
    rid = str(row.get("id") or "").strip()
    locs = row.get("locations_derived") or []
    return {
        "id": rid,
        "req_id": f"fantastic|{src}:{rid}",
        "board": f"fantastic|{src}",
        "title": (row.get("title") or "").strip(),
        "company": (row.get("organization") or "").strip() or None,
        # ⭐ Their organization field is the EMPLOYER'S NAME, not a board token, so it is a
        # verified name rather than a slug opened out. That distinction is what
        # company_source exists to record.
        "company_source": "fantastic",
        "location": (locs[0] if locs else None),
        "url": (row.get("url") or "").strip() or None,
        # 🚨 THE FIELD IS `description_text`, NOT `description`. Measured against a live
        # response 2026-09-14, and reading the obvious name would have stored an EMPTY
        # description on every row while nothing failed: triage would have scored every
        # posting on its title alone and no check anywhere would have noticed. `html` mode
        # names it differently again, so all three spellings are tried.
        # ⚠️ It is absent entirely unless `description_format` is sent. See params().
        "description": (row.get("description_text") or row.get("description_html")
                        or row.get("description") or ""),
        "is_remote": None,
        # ⭐ THE EMPLOYER'S OWN FIELD, when they published one. It goes in `comp` exactly as
        # a board scanner's does, so the existing reader gives it `board` provenance for
        # free. Their ai_salary_* extraction is the FALLBACK and carries its own source.
        "comp": salary_text(row),
        "posted_at": row.get("date_posted"),
        "updated_at": row.get("date_modified"),
        "posted_source": "fantastic:date_posted",
        "deadline": row.get("date_valid_through"),
        # ⭐ THE GATE THAT DID NOT EXIST. A derived years-of-experience band is still the
        # only machine-readable answer to "is this role beneath or above the seat I hold",
        # and down-levelling is a documented, repeated cost.
        "stated_level": row.get("ai_experience_level"),
        "discovery_url": (row.get("url") or "").strip() or None,
        "discovery_source": "fantastic",
        "work_arrangement": row.get("ai_work_arrangement"),   # recorded, never gated on
    }


def comp_band(row: dict) -> tuple | None:
    """(min, max, basis, evidence, source) from THEIR salary fields, or None.

    🚨 THE SOURCE IS 'fantastic_ai' AND IT IS A NEW VALUE ON PURPOSE. The existing three are
    `board` (the employer's own pay field), `body_regex` (read out of the posting text here,
    free) and `model` (the paid reader). This number is none of those: it is somebody else's
    extraction, arriving with no evidence span attached. Presenting it as `board` would make
    a derived figure indistinguishable from a published one, and a band is the thing a
    negotiation later stands on.

    ⚠️ Callers try the free local reader FIRST. This is the fallback, not the default.
    """
    lo, hi = row.get("ai_salary_min_value"), row.get("ai_salary_max_value")
    if lo is None and hi is None:
        lo = hi = row.get("ai_salary_value")
    if lo is None and hi is None:
        return None
    try:
        lo = int(float(lo)) if lo is not None else None
        hi = int(float(hi)) if hi is not None else None
    except (TypeError, ValueError):
        return None
    cur = (row.get("ai_salary_currency") or "USD").upper()
    if cur != "USD":
        # 📌 Not converted. A rate applied here would be invisible to every later reader and
        # would age. Record nothing rather than a number nobody can check.
        return None
    basis = _UNIT.get((row.get("ai_salary_unit_text") or "YEAR").upper(), "unclear")
    return lo, hi, basis, f"ai_salary ({row.get('ai_salary_unit_text') or 'YEAR'})", "fantastic_ai"

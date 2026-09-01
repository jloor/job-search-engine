"""The candidate profile, as the SERVICE sees it. One definition, two callers.

⭐ WHY THIS LIVES IN platform/relay/ AND NOT IN tools/. Every parameter here decides what
the scanner keeps: which job titles count, which locations are reachable, what the salary
floor is. Those rules ran as CLI tools during a backfill and the deployed service knew
nothing about them, so the nightly sweep kept applying an older, looser set. Two copies of
a filter is two answers to "is this job worth showing him". `tools/` now imports this.

📌 THE CONFIG IS READ FROM THE SYNCED REPO, NOT BAKED INTO THE IMAGE. gitsync keeps a
working copy at /data/repo, so changing a salary floor or adding a job title is a commit
and a sync, not a rebuild and a redeploy. A baked copy is kept only as a fallback for the
first boot before the clone lands.

Resolution order:
  1. CANDIDATE_CONFIG           explicit override, used by tests and by one-off runs
  2. <synced repo>/config/      normal operation
  3. next to this file          bootstrap only, may be stale
"""
import os
import pathlib
import re
import tomllib

HERE = pathlib.Path(__file__).resolve().parent
_cache: dict = {}


def _repo_dir() -> pathlib.Path | None:
    try:
        import gitsync
        return gitsync.REPO_DIR
    except Exception:                                         # noqa: BLE001
        return None


def config_path() -> pathlib.Path | None:
    env = os.environ.get("CANDIDATE_CONFIG", "").strip()
    if env:
        return pathlib.Path(env)
    repo = _repo_dir()
    if repo and (repo / "config" / "candidate.toml").exists():
        return repo / "config" / "candidate.toml"
    # 📌 Running from a SOURCE CHECKOUT rather than the container. gitsync's path only
    # exists inside the deployment, so without this the operator tools silently found no
    # config and fell back to generic defaults, which looks like working software.
    checkout = HERE.parent.parent / "config" / "candidate.toml"
    if checkout.exists():
        return checkout
    baked = HERE / "candidate.toml"
    return baked if baked.exists() else None


def load() -> dict:
    """Return the profile, or {} if none is available.

    ⚠️ Returns {} rather than raising. A missing config must not take the whole service
    down: mail classification, backups and tracking do not depend on it. Callers that DO
    depend on it check for emptiness and decline, the same way the AI jobs decline without
    a key. A scanner that silently runs with no filters would be worse than one that stops.
    """
    p = config_path()
    if p is None:
        return {}
    key = str(p)
    if key not in _cache or _cache[key].get("_mtime") != p.stat().st_mtime:
        cfg = tomllib.loads(p.read_text())
        cfg["_path"], cfg["_mtime"] = str(p), p.stat().st_mtime
        env_origin = os.environ.get("COMMUTE_ORIGIN", "").strip()
        if env_origin:
            cfg.setdefault("commute", {})["origin"] = env_origin
        _cache[key] = cfg
    return _cache[key]


def _alt(words) -> str:
    """Longest first, so 'customer success engineer' is not pre-empted by 'support'."""
    return "|".join(sorted(words, key=len, reverse=True))


def title_re(cfg: dict | None = None):
    cfg = load() if cfg is None else cfg
    pats = (cfg.get("targeting") or {}).get("title_patterns") or []
    return re.compile(rf"\b({_alt(pats)})\b", re.I) if pats else None


def metro_re(cfg: dict | None = None):
    """Places reachable from the origin, plus the near-state suffixes.

    ⚠️ This is the rule that decides whether a HYBRID role survives. Treating hybrid as a
    rejection instead of a question about WHERE deleted two roles at the candidate's
    top-choice employer once already.
    """
    cfg = load() if cfg is None else cfg
    c = cfg.get("commute") or {}
    places, states = c.get("metro_places") or [], c.get("near_states") or []
    if not places and not states:
        return None
    parts = []
    if places:
        parts.append(rf"\b({_alt(places)})\b")
    if states:
        parts.append(rf",\s*({'|'.join(states)})\b")
    return re.compile("|".join(parts), re.I)


def metro_place_re(cfg: dict | None = None):
    r"""The CURATED place names only. Never the near-state suffix.

    🚨 THIS EXISTS BECAUSE metro_re DECIDES TOO MUCH. metro_re ORs the place list with
    `,\s*(NY|NJ|CT|PA)`, so ANY city followed by a near-state abbreviation reads as "in the
    metro". That is right for the recall pre-filter in gate(), whose job is to avoid deleting
    a posting nobody has ruled on. It is wrong anywhere a verdict is ASSERTED.

    ⚠️ Measured 2026-08-25. A posting located "Phoenix, AZ; Boston, MA;
    Philadelphia, PA" was written into scan_candidate as `hybrid_commutable` with the evidence
    "its location is in the metro. No model was asked." It matched on ", PA". The real
    measurement from the configured origin is 145 minutes by car and 131 by transit, against a
    90 minute ceiling. `travel_notes` says outright that Philadelphia is not commutable.
    "Albany, NY" and "Pittsburgh, PA" fail the same way.

    ⭐ near_states is a GEOGRAPHIC PRE-FILTER, not a commutability test. Its own comment says
    "Only these states CAN CONTAIN a place inside max_minutes" - can contain, not does. The two
    meanings were collapsed into one regex and the permissive one won.

    📌 The cost of this fix is recall, in the safe direction. A genuinely commutable town that
    is not on the curated list (Fort Lee, Nyack) no longer gets a free verdict. It keeps no
    verdict instead of a wrong one, which leaves it for a measurement or a model read. Add the
    town to metro_places to settle it: that list is a human ruling and outranks both.
    """
    cfg = load() if cfg is None else cfg
    places = (cfg.get("commute") or {}).get("metro_places") or []
    return re.compile(rf"\b({_alt(places)})\b", re.I) if places else None


_US_STATES = {
    "AL": "alabama", "AK": "alaska", "AZ": "arizona", "AR": "arkansas", "CA": "california",
    "CO": "colorado", "CT": "connecticut", "DE": "delaware", "FL": "florida", "GA": "georgia",
    "HI": "hawaii", "ID": "idaho", "IL": "illinois", "IN": "indiana", "IA": "iowa",
    "KS": "kansas", "KY": "kentucky", "LA": "louisiana", "ME": "maine", "MD": "maryland",
    "MA": "massachusetts", "MI": "michigan", "MN": "minnesota", "MS": "mississippi",
    "MO": "missouri", "MT": "montana", "NE": "nebraska", "NV": "nevada",
    "NH": "new hampshire", "NJ": "new jersey", "NM": "new mexico", "NY": "new york",
    "NC": "north carolina", "ND": "north dakota", "OH": "ohio", "OK": "oklahoma",
    "OR": "oregon", "PA": "pennsylvania", "RI": "rhode island", "SC": "south carolina",
    "SD": "south dakota", "TN": "tennessee", "TX": "texas", "UT": "utah", "VT": "vermont",
    "VA": "virginia", "WA": "washington", "WV": "west virginia", "WI": "wisconsin",
    "WY": "wyoming", "DC": "district of columbia"}


# 🚨 LONGEST FIRST, AND MATCHED AGAINST REAL STATE NAMES. The first version of the check
# below used a generic word pattern, and it read "New York, Rhode Island" as the state "rhode",
# concluded that was not a state at all, and accepted the match. Every two-word state failed the
# same way: West Virginia, New Mexico, North Carolina. That is how a posting whose own
# text says it will NOT hire in New Jersey or New York stayed marked commutable even after the
# first fix. Sorting longest-first is what makes "rhode island" win over nothing.
_STATE_AFTER = re.compile(
    r"[\s,]*(" + "|".join(sorted(
        list(_US_STATES) + list(_US_STATES.values()), key=len, reverse=True)) + r")\b", re.I)


def metro_match(location: str | None, cfg: dict | None = None) -> bool:
    """Does this location name a curated metro place IN A NEAR STATE?

    🚨 A PLACE NAME IS NOT A PLACE. The curated list holds bare tokens, and American city
    names repeat across states. Measured 2026-08-25, every one of these read as commutable:
    "Newark, CA" (the Bay Area one), "Newark, DE", "Princeton, WV". Only the UK case was
    caught, and only because eligibility() rejects it for being foreign, not because anything
    noticed the city was wrong.

    ⭐ THE RULE: a matched token counts only if the state written beside it is one of
    near_states, or if no state is written at all. "Holmdel, New Jersey" counts. "Newark, CA"
    does not. An unqualified "Remote" or a bare "New York" still counts, because there is
    nothing to contradict.

    📌 It scans EVERY match, not just the first. A posting that lists several offices is the
    normal case, and the reachable one is often not first: the row that exposed this reads
    "Fort Lauderdale, Florida, United States, Holmdel, New Jersey, United States".
    """
    cfg = load() if cfg is None else cfg
    place = metro_place_re(cfg)
    if not place or not location:
        return False
    near = {s.upper() for s in ((cfg.get("commute") or {}).get("near_states") or [])}
    ok = {s.lower() for s in near} | {_US_STATES[s] for s in near if s in _US_STATES}
    for m in place.finditer(location):
        st = _STATE_AFTER.match(location[m.end():m.end() + 40])
        # Nothing recognisable beside it: nothing contradicts the match, so it counts.
        if not st or st.group(1).lower() in ok:
            return True
    return False


def excluded_company(name: str | None, cfg: dict | None = None) -> bool:
    """True when this employer is on the never-apply list.

    🚫 TWO DIFFERENT REASONS SHARE ONE LIST, and a later reader needs to know that. Some
    entries are a VALUES decision about employers that would otherwise be good roles. Others
    are there because the postings are not employment at all: one "employer" gated every
    posting on the phrase "to qualify for this business opportunity" and produced nineteen
    near-duplicate rows in a single sweep. The config file carries the per-entry reason.

    ⚠️ COMPARE ON LETTERS AND DIGITS ONLY. A plain lowercase substring test matched
    "AcmeTravel" and missed "Acme Travel", so an employer could defeat the list by
    rendering its own name with a space. Board tokens, markdown and punctuation vary across
    the same employer constantly and the exclusion has to survive all of it.
    ⚠️ Deliberately NOT a word-boundary match: a board token like "palantirtech" is the same
    employer and must still be caught.
    """
    cfg = cfg or load()

    def flat(s):
        return re.sub(r"[^a-z0-9]", "", (s or "").lower())

    names = [flat(n) for n in ((cfg.get("targeting", {}) or {}).get("exclude_companies") or [])]
    low = flat(name)
    return any(n and n in low for n in names)


def near_state_re(cfg: dict | None = None):
    cfg = load() if cfg is None else cfg
    st = (cfg.get("commute") or {}).get("near_states") or []
    if not st:
        return None
    names = {"NY": "new york", "NJ": "new jersey", "CT": "connecticut",
             "PA": "pennsylvania", "MA": "massachusetts", "CA": "california",
             "TX": "texas", "WA": "washington", "IL": "illinois", "FL": "florida",
             "GA": "georgia", "CO": "colorado", "AZ": "arizona", "MD": "maryland"}
    full = "|".join(names[s] for s in st if s in names)
    return re.compile(rf",\s*({'|'.join(st)})\b" + (rf"|\b({full})\b" if full else ""),
                      re.I)


def workable_remote(cfg: dict | None = None) -> set:
    """Remote verdicts that count as workable.

    🚨 Under remote_only a hybrid role must NOT cascade to the commute rules. Under
    prefer_remote it must. Getting this backwards is silent: the roles simply stop
    appearing, with no error anywhere.
    """
    cfg = load() if cfg is None else cfg
    r = cfg.get("remote") or {}
    ok = set(r.get("accept") or ["fully_remote", "remote_in_metro"])
    if r.get("keep_unclear", True):
        ok.add("unclear")
    if r.get("policy") == "remote_only":
        ok -= {"hybrid_commutable"}
    return ok


def band(cfg: dict | None = None) -> tuple:
    """(apply_min, gap_min, gap_max). Env still wins so a deploy can tune without a sync."""
    cfg = load() if cfg is None else cfg
    s = cfg.get("scoring") or {}
    return (int(os.environ.get("TRIAGE_BAND_MIN", s.get("apply_band_min", 70))),
            int(os.environ.get("TRIAGE_GAP_MIN", s.get("gap_band_min", 50))),
            int(os.environ.get("TRIAGE_GAP_MAX", s.get("gap_band_max", 69))))


def describe(cfg: dict | None = None) -> str:
    cfg = load() if cfg is None else cfg
    if not cfg:
        return "no candidate config"
    c = cfg.get("commute") or {}
    return (f"{(cfg.get('candidate') or {}).get('name', '?')} · "
            f"origin {c.get('origin', '?')} · {c.get('max_minutes', '?')} min · "
            f"remote {(cfg.get('remote') or {}).get('policy', '?')} · "
            f"floor ${(cfg.get('compensation') or {}).get('floor', 0):,}")

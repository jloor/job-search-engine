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

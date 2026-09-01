#!/usr/bin/env python3
"""Posting age: every board says it differently, and one of them does not say it at all.

🚨 WHY THIS EXISTS. `scan_candidate` recorded `at`, which is when WE first saw a posting,
and nothing else. A requisition rotting on a board for six weeks ranked identically to one
published that morning. A posting went out five weeks stale and that only
surfaced because a human opened the archived copy by hand.

⭐ THE MEASUREMENT THAT SHAPED THE SCHEMA. On a live Greenhouse board, 2026-09-01:

    updated_at       2026-09-01T17:11:29-04:00     (that day)
    first_published  2026-02-10T17:53:20-05:00     (February)

Nearly seven months apart on ONE posting. Age and liveness are different questions, so they
are different columns. Collapsing them makes a stale req look new every time an employer
fixes a typo in it.

⚠️ Workable measured 2026-08-13 published_on against 2026-05-05 created_at, three months
apart in the other direction: created is when the req opened internally, published is when a
candidate could first see it. Age means the latter.

🚨 AND WORKDAY PUBLISHES NO DATE AT ALL in its list, only relative prose ("Posted 30+ Days
Ago"). Converting that to a timestamp would invent precision that is wrong by up to weeks
and that nothing downstream could distinguish from a real one. It must stay NULL.

Every fixture below is the SHAPE of a real board response with synthetic ids and titles.

Run:  python3 tests/test_posting_age.py
"""
import importlib.util, json, os, pathlib, sys, types

HERE = pathlib.Path(__file__).resolve().parent
for _v in ("BUNNY_DATABASE_URL", "BUNNY_DATABASE_AUTH_TOKEN"):
    os.environ.pop(_v, None)


def load_app():
    """Import app.py without needing fastapi installed.

    ⚠️ app.py imports candidate.py and gates.py as ordinary modules. Loading app by an
    explicit spec does NOT put its directory on sys.path, so without this those imports
    fail silently inside try/except and every config-driven rule degrades to "not
    configured" — which looks exactly like a passing decline instead of a broken test.
    """
    _relay = str(pathlib.Path(__file__).resolve().parent.parent / "job_search_engine")
    if _relay not in sys.path:
        sys.path.insert(0, _relay)
    fa = types.ModuleType("fastapi")

    class FastAPI:
        def __init__(self, **k): pass
        def _d(self, *a, **k):
            def w(f): return f
            return w
        get = post = on_event = _d

    class HTTPException(Exception):
        def __init__(self, c, d=""): self.code, self.detail = c, d; super().__init__(f"{c}: {d}")

    def Header(default=None, **k): return default

    class Request: pass

    fa.FastAPI, fa.HTTPException, fa.Header, fa.Request = FastAPI, HTTPException, Header, Request
    resp = types.ModuleType("fastapi.responses")

    class JSONResponse:
        def __init__(self, c, status_code=200): self.content, self.status_code = c, status_code

    resp.JSONResponse = JSONResponse
    fa.responses = resp
    sys.modules["fastapi"], sys.modules["fastapi.responses"] = fa, resp
    # 📌 The engine is a package now, so app.py sits one level in. The suite still loads
    # it by path rather than importing it, because it must run from a clean clone with
    # nothing installed.
    spec = importlib.util.spec_from_file_location(
        "relayapp", HERE.parent / "job_search_engine" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── fixtures: the shape of each board's list response, synthetic values ────────────────
FIXTURES = {
    "greenhouse": ({"jobs": [{
        "id": 111, "title": "Support Engineer", "absolute_url": "https://x/1",
        "company_name": "Acme", "location": {"name": "Remote"},
        "first_published": "2026-02-10T17:53:20-05:00",
        "updated_at": "2026-09-01T17:11:29-04:00",
        "application_deadline": "2026-10-15", "content": "hello"}]},
        {"posted_at": "2026-02-10", "updated_at": "2026-09-01",
         "posted_source": "first_published", "deadline": "2026-10-15"}),
    "ashby": ({"jobs": [{
        "title": "Support Engineer", "jobUrl": "https://jobs.ashbyhq.com/acme/abc-123",
        "isRemote": True, "location": "Remote",
        "publishedAt": "2026-07-23T09:01:29.429+00:00", "descriptionPlain": "hi"}]},
        {"posted_at": "2026-07-23", "posted_source": "publishedAt"}),
    "lever": ([{
        "id": "lv1", "text": "Support Engineer", "hostedUrl": "https://jobs.lever.co/acme/lv1",
        "categories": {"location": "Remote"},
        "createdAt": 1783363485942, "descriptionPlain": "hi"}],
        {"posted_at": "2026-07-06", "posted_source": "createdAt"}),
    "breezy": ([{
        "id": "bz1", "name": "Support Engineer", "url": "https://acme.breezy.hr/p/bz1",
        "location": {"city": "NY", "state": {"name": "NY"}, "country": {"name": "US"}},
        "published_date": "2026-07-07T17:38:08.486Z"}],
        {"posted_at": "2026-07-07", "posted_source": "published_date"}),
    "workable": ({"jobs": [{
        "shortcode": "WK1", "title": "Support Engineer", "location": "Remote",
        "url": "https://apply.workable.com/acme/j/WK1", "telecommuting": True,
        "published_on": "2026-08-13", "created_at": "2026-05-05", "description": "hi"}]},
        {"posted_at": "2026-08-13", "posted_source": "published_on"}),
    "teamtailor": ({"items": [{
        "id": "tt1", "title": "Support Engineer", "url": "https://careers.acme.com/j/tt1",
        "date_published": "2026-07-23T11:44:25+03:00", "content_html": "hi",
        "_jobposting": {"hiringOrganization": {"name": "Acme"}, "jobLocation": [],
                        "validThrough": "2026-12-01"}}]},
        {"posted_at": "2026-07-23", "posted_source": "date_published",
         "deadline": "2026-12-01"}),
    # 🚨 The one that must REFUSE.
    "workday": ({"jobPostings": [{
        "title": "Support Engineer", "externalPath": "/job/Remote/Support_JR1",
        "locationsText": "Remote", "postedOn": "Posted 30+ Days Ago"}]},
        {"posted_at": None, "posted_source": "relative_only"}),
}


def main() -> int:
    app = load_app()
    fails = []
    print("── per-platform date capture")
    for platform, (data, want) in FIXTURES.items():
        api = ("https://acme.wd12.myworkdayjobs.com/wday/cxs/acme/Ext/jobs"
               if platform == "workday" else "https://example.invalid/x")
        rows = app._normalise_board(platform, data, api)
        assert rows, f"{platform}: normaliser returned nothing"
        got = rows[0]
        for k, v in want.items():
            if got.get(k) != v:
                fails.append(f"{platform}.{k}: got {got.get(k)!r}, want {v!r}")
                print(f"  🚨 {platform:<14} {k}: {got.get(k)!r} != {v!r}")
            else:
                print(f"  ✅ {platform:<14} {k} = {v!r}")

    print("\n── the schema carries all four columns")
    src = "\n".join(app.MIGRATIONS)
    for col in ("posted_at", "updated_at", "posted_source", "deadline"):
        ok = f"ADD COLUMN {col} " in src
        print(f"  {'✅' if ok else '🚨'} scan_candidate.{col}")
        if not ok:
            fails.append(f"migration missing for {col}")

    print("\n── every INSERT binds as many values as it names columns")
    import re
    apath = HERE.parent / "job_search_engine" / "app.py"
    body = apath.read_text()
    for m in re.finditer(r"INSERT INTO scan_candidate \((.*?)\) VALUES \((.*?)\)", body, re.S):
        cols = [c for c in re.sub(r'["\n ]', "", m.group(1)).split(",") if c]
        ph = [c for c in m.group(2).split(",")]
        ok = len(cols) == len(ph)
        print(f"  {'✅' if ok else '🚨'} {len(cols)} columns / {len(ph)} placeholders")
        if not ok:
            fails.append(f"INSERT arity {len(cols)} != {len(ph)}")

    print()
    if fails:
        print(f"🚨 {len(fails)} failure(s):")
        for f in fails:
            print("   ", f)
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

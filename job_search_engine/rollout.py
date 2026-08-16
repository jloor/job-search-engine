#!/usr/bin/env python3
"""
rollout.py — drive the platform build-out one verifiable step at a time.

Every step is IDEMPOTENT and states what it found before it changes anything. Re-running
after a failure is always safe, which matters because a 1Password read or a Bunny API call
fails often enough that a fragile script would be worse than doing it by hand.

Nothing here deletes. Not a volume, not a database, not a record. Removing something that
holds recruiter correspondence is a deliberate act in a dashboard, not a script flag.

    python3 rollout.py status              what exists right now
    python3 rollout.py schema              apply the SPEC 3.4 tables to Bunny Database
    python3 rollout.py import-tracker      load the markdown tracker into the schema (dry-run default)
    python3 rollout.py volume              attach /data to the Magic Containers app
    python3 rollout.py all                 status, schema, volume, then re-status

Credentials are read at call time, with retries, because the 1Password desktop
integration intermittently declines and a bare failure looks like a real error.
"""
from __future__ import annotations

import argparse, json, os, pathlib, re, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
APP_ID = os.environ.get("RELAY_APP_ID", "EAtkS3wXFyk5v8B")
ENV_FILE = pathlib.Path.home() / ".config/job-search/relay.env"

OP_ITEMS = {
    "bunny": ("ecbqg7ah5trsh7qm3mh7vfbh4a", "API Key"),
}


def op_read(item: str, tries: int = 4) -> str:
    """1Password reads flake. Retry, and say so rather than returning an empty string
    that later looks like an authentication failure."""
    uuid, field = OP_ITEMS[item]
    for i in range(tries):
        try:
            v = subprocess.run(
                ["op", "item", "get", uuid, "--account", "my.1password.com",
                 "--fields", f"label={field}", "--reveal"],
                capture_output=True, text=True, timeout=25).stdout.strip()
            if v:
                return v
        except subprocess.TimeoutExpired:
            pass
        if i < tries - 1:
            print(f"    1Password did not answer (attempt {i+1}), retrying", file=sys.stderr)
            time.sleep(3)
    sys.exit("1Password is not authorizing reads. Unlock it and re-run; this script is idempotent.")


def env() -> dict:
    if not ENV_FILE.exists():
        sys.exit(f"missing {ENV_FILE}")
    return dict(l.split("=", 1) for l in ENV_FILE.read_text().splitlines()
                if "=" in l and not l.startswith("#"))


def bunny():
    import importlib.util
    spec = importlib.util.spec_from_file_location("b", HERE / "bunny.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sql(statements: list[str]) -> list:
    e = env()
    return bunny().pipeline(e["BUNNY_DATABASE_URL"], e["BUNNY_DATABASE_AUTH_TOKEN"], statements)


def tables() -> list[str]:
    r = sql(["SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"])
    return [row[0]["value"] for row in r[0].get("rows", [])]


def objects() -> set[str]:
    """Tables AND indexes. Tracking only tables made every index report as 'to create'
    on every run, which is harmless but hides what is actually changing."""
    r = sql(["SELECT name FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'"])
    return {row[0]["value"] for row in r[0].get("rows", [])}


# ---------------------------------------------------------------- steps
def step_status(a) -> None:
    print("== database ==")
    try:
        t = tables()
        print(f"   tables ({len(t)}): {', '.join(t)}")
        want = {"company", "posting", "application", "contact", "interaction",
                "backlog_item", "content_item", "scan_observation"}
        missing = sorted(want - set(t))
        print(f"   SPEC 3.4 tables missing: {', '.join(missing) if missing else 'none'}")
        if not missing:
            counts = sql([f"SELECT count(*) FROM {x}" for x in sorted(want)])
            for name, c in zip(sorted(want), counts):
                print(f"     {name:<18} {c['rows'][0][0]['value']:>5} rows")
    except Exception as ex:
        print(f"   unreachable: {type(ex).__name__}: {ex}")

    print("== magic containers app ==")
    os.environ["BUNNY_API_KEY"] = op_read("bunny")
    m = bunny()
    st, app = m.req(m.MC_API + f"/apps/{APP_ID}")
    if st != 200:
        print(f"   GET failed: {st}")
        return
    ct = app["containerTemplates"][0]
    print(f"   status:     {app.get('status')}")
    print(f"   image tag:  {ct.get('imageTag')}")
    print(f"   region:     {app.get('regionSettings', {}).get('requiredRegionIds')}")
    print(f"   autoscaling:{app.get('autoScaling')}")
    inst = app.get("containerInstances") or []
    print(f"   instances:  {len(inst)}")
    if len(inst) > 1:
        print("   🚨 MORE THAN ONE INSTANCE. Volumes are per-instance (SPEC 5.0b);")
        print("      a git working copy here would diverge. Scale to 1 before adding the volume.")
    vols = app.get("volumes") or []
    print(f"   volumes:    {vols if vols else 'none'}")
    mounts = ct.get("volumeMounts") or []
    print(f"   mounts:     {mounts if mounts else 'none'}")


def step_schema(a) -> None:
    ddl = extract_ddl()
    have = objects()
    todo = [(name, stmt) for name, stmt in ddl if name not in have]

    # Detect tables that exist but no longer match the spec. This happens whenever the DDL
    # in SPEC.md is edited after a first apply, and CREATE TABLE IF NOT EXISTS silently
    # does nothing about it. A schema that quietly disagrees with its spec is worse than
    # one that was never applied, because everything downstream assumes it matches.
    drift = []
    for name, stmt in ddl:
        if name in have and stmt.upper().lstrip().startswith("CREATE TABLE"):
            # Compare column names AND their NOT NULL flags. Names alone missed the posting
            # table, whose columns were unchanged but whose NOT NULL constraints were
            # relaxed. That difference is exactly what would have blocked the import.
            want = {c: bool(re.search(r"NOT\s+NULL", rest, re.I))
                    for c, rest in re.findall(r"^\s*(\w+)\s+(?:INTEGER|TEXT|REAL|BLOB)([^,\n]*)",
                                              stmt, re.M | re.I)}
            info = sql([f"PRAGMA table_info({name})"])[0]["rows"]
            got = {row[1]["value"]: row[3]["value"] in ("1", 1) for row in info}
            diffs = [c for c in want if c not in got]
            diffs += [f"{c} NOT NULL differs" for c in want if c in got and want[c] != got[c]]
            if diffs:
                n = int(sql([f"SELECT count(*) FROM {name}"])[0]["rows"][0][0]["value"])
                drift.append((name, sorted(diffs), n, stmt))

    print(f"== schema: {len(ddl)} objects in SPEC 3.4, {len(todo)} to create, {len(drift)} drifted ==")
    for name, _ in todo:
        print(f"   will create: {name}")
    for name, missing, n, _ in drift:
        mark = "EMPTY, safe to rebuild" if n == 0 else f"🚨 HAS {n} ROWS"
        print(f"   drift: {name} missing {', '.join(missing)}  ({mark})")

    if not todo and not drift:
        print("   nothing to do")
        return
    if a.dry_run:
        print("   dry run, nothing applied. Re-run with --apply")
        return

    stmts = [stmt for _, stmt in todo]
    # 🚨 EMPTIED 2026-08-12, deliberately. These tables WERE re-derivable from the markdown
    # tracker, so rebuilding them cost nothing. That stopped being true the moment
    # tools/render-tracker.py started GENERATING the markdown from them: the database is
    # now the only copy, and a rebuild would destroy the pipeline rather than reload it.
    # Leave this empty. Schema changes to these tables need an explicit ALTER migration.
    DERIVED: set[str] = set()
    for name, _, n, stmt in drift:
        if n and (name not in DERIVED or not a.force):
            print(f"   ⛔ skipping {name}: it holds {n} rows. Rebuilding would lose them. "
                  + ("Re-run with --force; it is re-importable from the tracker."
                     if name in DERIVED else "Write an explicit ALTER migration instead."))
            continue
        if n:
            print(f"   rebuilding {name} ({n} rows, re-derivable from the tracker)")
        # Empty and drifted: rebuilding is not destructive, and it is the only way to change
        # a column's NOT NULL in SQLite.
        stmts += [f"DROP TABLE {name}", stmt]
        print(f"   rebuilding empty table {name}")
    sql(stmts)
    print(f"   applied. tables now: {', '.join(tables())}")


def extract_ddl() -> list[tuple[str, str]]:
    """Pull the CREATE statements straight out of SPEC.md 3.4 so the spec stays the
    single definition. A schema that drifts from its spec is worse than no spec."""
    text = (REPO / "platform/SPEC.md").read_text()
    block = re.search(r"#### DDL\s*```sql\n(.*?)```", text, re.S)
    if not block:
        sys.exit("could not find the DDL block in SPEC.md 3.4")
    body = "\n".join(re.sub(r"--.*$", "", ln) for ln in block.group(1).splitlines())
    out = []
    for stmt in (s.strip() for s in body.split(";")):
        if not stmt:
            continue
        m = re.match(r"CREATE\s+(?:UNIQUE\s+)?(TABLE|INDEX)\s+(?:IF NOT EXISTS\s+)?(\w+)", stmt, re.I)
        name = m.group(2) if m else stmt[:24]
        # every statement gets IF NOT EXISTS so re-running is a no-op
        stmt = re.sub(r"^CREATE\s+TABLE\s+(?!IF NOT EXISTS)", "CREATE TABLE IF NOT EXISTS ", stmt, flags=re.I)
        stmt = re.sub(r"^CREATE\s+INDEX\s+(?!IF NOT EXISTS)", "CREATE INDEX IF NOT EXISTS ", stmt, flags=re.I)
        out.append((name, stmt))
    return out


def step_volume(a) -> None:
    os.environ["BUNNY_API_KEY"] = op_read("bunny")
    m = bunny()
    st, app = m.req(m.MC_API + f"/apps/{APP_ID}")
    if st != 200:
        sys.exit(f"GET app failed: {st}")
    inst = app.get("containerInstances") or []
    scale = app.get("autoScaling") or {}
    if scale.get("max", 1) > 1 or len(inst) > 1:
        sys.exit("refusing: app runs more than one instance. Volumes are per-instance and the "
                 "git working copies would diverge (SPEC 5.0b). Scale to min=max=1 first.")

    ct = app["containerTemplates"][0]
    if any(v.get("name") == a.name for v in (app.get("volumes") or [])):
        print(f"   volume {a.name!r} already exists, nothing to do")
        return

    ct.pop("image", None); ct.pop("imageDigest", None)
    for ep in ct.get("endpoints", []):
        if "cdn" not in ep and ep.get("portMappings"):
            ep["cdn"] = {"isSslEnabled": ep.get("isSslEnabled", True),
                         "portMappings": ep.pop("portMappings")}
    body = {k: app[k] for k in ("name", "runtimeType", "regionSettings", "autoScaling",
                                "containerTemplates") if k in app}
    body["volumes"] = (app.get("volumes") or []) + [{"name": a.name, "size": a.size}]
    ct["volumeMounts"] = (ct.get("volumeMounts") or []) + [{"name": a.name, "mountPath": a.path}]
    print(f"== attaching volume {a.name!r} {a.size}GB at {a.path} ==")
    if a.dry_run:
        print("   dry run. Re-run with --apply")
        return
    st, _ = m.req(m.MC_API + f"/apps/{APP_ID}", "PATCH", body)
    print(f"   PATCH -> {st}")
    if st not in (200, 201, 204):
        sys.exit("attach failed")
    for i in range(30):
        time.sleep(10)
        try:
            st, app = m.req(m.MC_API + f"/apps/{APP_ID}")
        except Exception:
            continue
        if app.get("status") == "active" and (app.get("volumes") or []):
            print(f"   active. volumes: {app.get('volumes')}")
            return
    print("   still progressing. Re-run 'status' in a minute; this is safe to repeat.")


def step_import_tracker(a) -> None:
    """Parse the markdown tracker into company/posting/application rows.

    Dry run by default and LOUD about anything it cannot parse. The point of moving to a
    schema is that malformed rows stop being invisible, so this must not paper over them.
    """
    # 🚨 CONFIG, NOT A LITERAL. Naming the operator's own file here is what made this
    # module unpublishable, and it also silently fails for anyone who names theirs
    # differently. TRACKER_PATH still wins so a one-off import can point anywhere.
    import os as _os
    _rel = _os.environ.get("TRACKER_PATH")
    if not _rel:
        try:
            import candidate as _C
            _rel = (_C.load().get("candidate") or {}).get("tracker_doc")
        except Exception:                                     # noqa: BLE001
            _rel = None
    if not _rel:
        raise SystemExit("no tracker configured: set TRACKER_PATH or "
                         "candidate.tracker_doc in config/candidate.toml")
    path = pathlib.Path(_rel)
    if not path.is_absolute():
        path = REPO / _rel
    lines = path.read_text().splitlines()

    # The file holds FIVE different tables (applications, tier-1 leads, tier-2, flagged,
    # closed) with different column counts. Scope to the applications table only: find its
    # exact header, then stop at the next heading or blank line. Treating every pipe row in
    # the document as an application row reports 47 "malformed" rows that are simply other
    # tables, which would send someone editing perfectly good data.
    HEADER = ["company", "role", "remote?", "applied", "status", "next action", "contact", "link", "notes"]
    start = None
    for n, line in enumerate(lines):
        if line.startswith("|"):
            cells = [c.strip().lower() for c in line.strip().strip("|").split("|")]
            if cells == HEADER:
                start = n
                break
    if start is None:
        sys.exit("could not find the applications table header in the tracker")

    rows, bad = [], []
    for n in range(start + 1, len(lines)):
        line = lines[n]
        if line.startswith("#") or not line.strip():
            break
        if not line.startswith("|") or re.match(r"^\|[\s\-:|]+\|$", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 9:
            bad.append((n + 1, len(cells), line[:70]))
            continue
        rec = dict(zip(
            ["company", "role", "remote", "applied", "status", "next", "contact", "link", "notes"], cells))
        rec["source_row"] = line            # P4: keep the original bytes, always
        rows.append(rec)
    print(f"== applications table (lines {start+1}..{n}) ==")
    print(f"   {len(rows)} parsed, {len(bad)} malformed")
    for ln, c, text in bad:
        print(f"   ⚠️ line {ln}: {c} cells (want 9): {text}")
    if bad:
        sys.exit("refusing to import while rows are malformed. Fix them first; that is the "
                 "whole reason for moving to a schema.")

    for r in rows:
        r["company_clean"] = clean(r["company"])
        r["role_clean"] = clean(r["role"])
        r["applied_date"] = first_date(r["applied"])
        r["status_norm"] = normalise_status(r["status"], r["applied_date"])
        r["url"] = first_url(r["link"])

    companies = sorted({r["company_clean"] for r in rows if r["company_clean"]})
    print(f"   distinct companies: {len(companies)}")
    no_url = [r for r in rows if not r["url"]]
    no_date = [r for r in rows if not r["applied_date"]]
    unknown = [r for r in rows if r["status_norm"] == "unknown"]
    print(f"   rows with no link:        {len(no_url)}")
    print(f"   rows with no applied date:{len(no_date)}")
    print(f"   status could not be normalised: {len(unknown)}")
    for r in unknown:
        print(f"      ? {r['company_clean'][:22]:<22} {r['status'][:56]}")
    print("   status distribution:")
    dist: dict = {}
    for r in rows:
        dist[r["status_norm"]] = dist.get(r["status_norm"], 0) + 1
    for k in sorted(dist, key=lambda x: -dist[x]):
        print(f"      {k:<12} {dist[k]}")

    if a.dry_run:
        print("\n   dry run. Nothing written. Re-run with --apply.")
        return

    have = set(tables())
    if not {"company", "posting", "application"} <= have:
        sys.exit("schema is not applied yet. Run: rollout.py schema --apply")
    counts = sql(["SELECT count(*) FROM company", "SELECT count(*) FROM application"])
    existing = [int(c["rows"][0][0]["value"]) for c in counts]
    if any(existing) and not a.force:
        sys.exit(f"refusing: company has {existing[0]} rows and application has {existing[1]}. "
                 "This importer is for the initial load only. Re-importing would duplicate "
                 "rather than reconcile, and reconciliation is a different tool. "
                 "Use --force to clear and reload while the tracker is still the source of truth.")
    if any(existing):
        print("   --force: clearing company/posting/application and reloading from the tracker")
        sql(["DELETE FROM application", "DELETE FROM posting", "DELETE FROM company"])

    stmts = []
    for c in companies:
        stmts.append(f"INSERT INTO company(name) VALUES ({q(c)})")
    sql(stmts)
    ids = {row[1]["value"]: row[0]["value"]
           for row in sql(["SELECT id,name FROM company"])[0]["rows"]}
    print(f"   inserted {len(companies)} companies")

    stmts = []
    for r in rows:
        cid = ids[r["company_clean"]]
        stmts.append(
            "INSERT INTO posting(company_id,title,canonical_url,captured_at,status,work_model_raw) "
            f"VALUES ({cid},{q(r['role_clean'])},{q(r['url'])},{q(TODAY)},'unknown',{qraw(r['remote'])})")
    sql(stmts)
    print(f"   inserted {len(rows)} postings")

    pid = {}
    for row in sql(["SELECT id,company_id,title FROM posting"])[0]["rows"]:
        pid[(row[1]["value"], row[2]["value"])] = row[0]["value"]
    stmts = []
    for r in rows:
        key = (ids[r["company_clean"]], r["role_clean"])
        stmts.append(
            "INSERT INTO application(posting_id,submitted_at,status,status_raw,notes,next_action,"
            "company_raw,role_raw,link_raw,contact_raw,applied_raw,source_row,channel) "
            f"VALUES ({pid[key]},{q(r['applied_date'])},{q(r['status_norm'])},{qraw(r['status'])},"
            f"{qraw(r['notes'])},{qraw(r['next'])},{qraw(r['company'])},{qraw(r['role'])},{qraw(r['link'])},"
            f"{qraw(r['contact'])},{qraw(r['applied'])},{qraw(r['source_row'])},NULL)")
    sql(stmts)
    print(f"   inserted {len(rows)} applications")
    print("\n   ⚠️ The markdown tracker is now a DUPLICATE of this data, not the source.")
    print("      Next step is to generate it from the database (SPEC 3.4), or the two will drift.")


TODAY = time.strftime("%Y-%m-%d")


def q(v) -> str:
    """SQL literal for a STRUCTURED field, where an em-dash placeholder means absent.
    Only use this for dates, URLs and enums."""
    if v is None or v == "" or v.strip("—- ") == "":
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def qraw(v) -> str:
    """SQL literal for a RAW cell, preserved exactly.

    ⚠️ Do NOT collapse an em-dash to NULL here. The tracker uses "—" as its
    empty-cell marker, so treating it as absent means the cell renders back as
    blank and the table quietly loses its formatting. Caught by the round-trip
    check on 26 of 38 rows, which is what that check is for.
    """
    if v is None or v == "":
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def clean(s: str) -> str:
    """Strip markdown decoration so 'Fusion Health' and '**Fusion Health**' are one company."""
    s = re.sub(r"~~(.*?)~~", r"\1", s)
    s = re.sub(r"\*\*(.*?)\*\*", r"\1", s)
    s = re.sub(r"\*(.*?)\*", r"\1", s)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[⭐🔴🟡🟢✅❌👻📞🎯⚡📌⚠️]", "", s)
    s = re.sub(r"\s*·\s*$", "", s)
    return re.sub(r"\s{2,}", " ", s).strip()


def first_date(s: str) -> str | None:
    m = re.search(r"(20\d\d-\d\d-\d\d)", s or "")
    return m.group(1) if m else None


def first_url(s: str) -> str | None:
    m = re.search(r"https?://[^\s)\]|]+", s or "")
    return m.group(0).rstrip(".,") if m else None


def _markers(key: str, default: tuple) -> tuple:
    """Tracker phrases for one status, from the candidate config, plus the generic defaults.

    ⚠️ ADDITIVE, never replacing. An operator listing their own wording should not silently
    lose "withdrawn", and a status parser that stops recognising a common word is a parser
    that mislabels history without saying so.
    """
    try:
        import candidate as _C
        extra = (_C.load().get("tracker") or {}).get(key) or []
    except Exception:                                     # noqa: BLE001
        extra = []
    return tuple(default) + tuple(x.lower() for x in extra)


def normalise_status(raw: str, applied: str | None) -> str:
    """
    Map the tracker's freeform status to the schema enum.

    ⚠️ Conservative on purpose. `status_raw` keeps the original words, so guessing here buys
    nothing and costs accuracy. Anything unrecognised becomes 'unknown' and gets printed for
    a human, per P6.
    """
    t = (raw or "").lower()
    if "ghost" in t:                                    return "ghosted"
    if "superseded" in t:                               return "superseded"
    if "offer" in t:                                    return "offer"

    # 🚨 Who decided matters more than the word used. "declined by R1" is a rejection;
    # A tracker cell like "DECLINED (<operator>'s call)" is the CANDIDATE passing, not an
    # employer rejecting. Collapsing the two would make the
    # pipeline look worse than it is and quietly rewrite his own history, which is the
    # same reason CLAUDE.md refuses to file a ghosting as a rejection.
    # 🚨 His own decisions split in two, and collapsing them hides live pipeline.
    # SUSPENDED means he stopped or held it and it can resume: the package may be
    # complete and it is waiting on a conversation, a warm channel, or his own timing.
    # PASSED means he decided against it and is not going back without a new reason.
    # Both are his call, so the old his_call test could not tell them apart and filed
    # two live opportunities under a terminal-sounding label, which made pipeline_status
    # under-report what he actually had.
    # ⚠️ "package ready" is NOT a hold signal on its own and was removed after it
    # matched "📦 Package ready — submit", which is the exact opposite: a finished
    # package waiting to go out. Every keyword here has to carry the hold by itself.
    held = any(k in t for k in ("suspended", "on hold", "parked", "do not submit",
                                "hold for", "paused", "awaiting a warm"))
    if held:                                            return "suspended"

    # ⭐ THE CANDIDATE PASSING IS NOT THE EMPLOYER REJECTING, and collapsing the two
    # quietly rewrites the operator's own history: it makes a pipeline look worse than it
    # was and turns a deliberate decision into a defeat.
    #
    # 📌 The markers are CONFIGURABLE because they are one person's phrasing. This list used
    # to contain a specific first name, which is the sort of thing that makes an engine
    # unpublishable and silently fails for everyone else. An operator adds their own wording
    # under [tracker].passed_markers; the defaults below are the generic ones.
    if any(k in t for k in _markers("passed_markers",
                                    ("their call", "candidate's call", "recommended pass",
                                     "never applied", "do not re-evaluate",
                                     "withdrew", "withdrawn", "excluded", "moved on"))):
        return "passed"
    if any(k in t for k in ("rejected", "declined by", "not moving forward", "warm no",
                            "closed —", "closed -")):
        return "rejected"
    if "declined" in t:                                 return "rejected"
    if "parked" in t or "held" in t:                    return "draft"

    # ⚠️ "ROUND 1 PASSED" means he advanced, not that he passed ON the role. The two
    # senses of "passed" are opposite outcomes, so the advancement patterns are checked
    # after the his_call block above and matched explicitly rather than on the bare word.
    if re.search(r"\bround\s*\d", t) or "(final)" in t or "next round" in t:
        return "interview"
    if any(k in t for k in ("interview", "final round", "onsite", "screen", "talent talk")):
        return "interview"
    if any(k in t for k in ("applied", "submitted", "awaiting", "in review", "under review")):
        return "submitted"
    if any(k in t for k in ("ready", "draft", "to apply", "not applied")):
        return "draft"
    return "submitted" if applied else "unknown"


def main() -> int:
    # --apply is accepted both before and after the subcommand. Requiring a global flag to
    # come first is the kind of papercut that gets worked around with a shell alias.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--apply", dest="dry_run", action="store_false", default=True,
                        help="actually make changes (default is a dry run)")
    common.add_argument("--force", action="store_true", default=False,
                        help="rebuild/reload tables that are re-derivable from the tracker")
    ap = argparse.ArgumentParser(description=__doc__, parents=[common],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", parents=[common]).set_defaults(fn=step_status)
    sub.add_parser("schema", parents=[common]).set_defaults(fn=step_schema)
    sub.add_parser("import-tracker", parents=[common]).set_defaults(fn=step_import_tracker)
    v = sub.add_parser("volume", parents=[common]); v.set_defaults(fn=step_volume)
    v.add_argument("--name", default="job-search-data")
    v.add_argument("--size", type=int, default=5, help="GB, can grow but never shrink")
    v.add_argument("--path", default="/data")
    allp = sub.add_parser("all", parents=[common]); allp.set_defaults(fn=None)
    allp.add_argument("--name", default="job-search-data")
    allp.add_argument("--size", type=int, default=5)
    allp.add_argument("--path", default="/data")

    a = ap.parse_args()
    if a.cmd == "all":
        for fn in (step_status, step_schema, step_volume, step_status):
            print()
            fn(a)
    else:
        a.fn(a)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

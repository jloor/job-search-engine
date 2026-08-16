#!/usr/bin/env python3
"""
bunny.py — provision the Bunny Database and inspect Magic Containers for the relay.

Everything here is idempotent and prints what it did. Nothing is created twice, and
nothing is deleted, ever: this script has no delete path on purpose. Removing a database
that holds recruiter correspondence should be a deliberate act in the dashboard, not a
flag someone passes to a script at 1am.

Credentials come from the environment. Pull them at call time:

    export BUNNY_API_KEY=$(op read "op://Private/bunny.net/API Key" --account my.1password.com)

Commands
--------
  db-list                     list existing databases
  db-create   --name NAME     create a database (idempotent by name)
  db-token    --name NAME     mint a full-access token and print the two env vars
  db-schema   --name NAME     apply schema.sql to it (CREATE TABLE IF NOT EXISTS, safe to repeat)
  db-verify   --name NAME     list tables and row counts, proving the thing works
  mc-apps                     list Magic Containers apps (also used to discover the API shape)

Regions default to a single primary with no replicas. This is one person's mailbox, not
a global edge workload, and replicas cost money for latency nobody will perceive.
"""
from __future__ import annotations

import argparse, json, os, sys, urllib.error, urllib.request

API_KEY  = os.environ.get("BUNNY_API_KEY", "")
DB_API   = os.environ.get("BUNNY_DB_API", "https://api.bunny.net/database")
MC_API   = os.environ.get("BUNNY_MC_API", "https://api.bunny.net/mc")
DEFAULT_NAME = os.environ.get("RELAY_DB_NAME", "job-search-relay")


def req(url: str, method: str = "GET", body: dict | None = None,
        token: str | None = None, accesskey: bool = True) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif accesskey:
        if not API_KEY:
            sys.exit("BUNNY_API_KEY is not set. Pull it from 1Password first.")
        headers["AccessKey"] = API_KEY
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=45) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def die(what: str, status: int, payload) -> None:
    # P3: fail loudly and print the server's own words. Guessing why a 4xx happened
    # has cost this project more time than reading the response ever would.
    print(f"\n{what} failed: HTTP {status}", file=sys.stderr)
    print(json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else payload, file=sys.stderr)
    sys.exit(1)


def list_databases() -> list:
    for path in ("/v2/databases", "/v1/databases"):
        st, body = req(DB_API + path)
        if st == 200:
            if isinstance(body, dict):
                for k in ("items", "data", "databases", "results"):
                    if isinstance(body.get(k), list):
                        return body[k]
                return [body]
            return body if isinstance(body, list) else []
    die("list databases", st, body)
    return []


def find_db(name: str):
    return next((d for d in list_databases() if str(d.get("name") or d.get("Name")) == name), None)


def db_id(d: dict):
    for k in ("id", "Id", "database_id", "uuid"):
        if d.get(k):
            return d[k]
    return None


def db_url(d: dict):
    """Normalise to the https:// form the SQL API is served on. Bunny reports the
    endpoint as libsql://<id>-<name>.lite.bunnydb.net; naively prefixing https:// to
    that produces https://libsql://… , which fails in a confusing way later."""
    for k in ("hostname", "host", "url", "endpoint", "Hostname"):
        v = str(d.get(k) or "").strip()
        if not v:
            continue
        for scheme in ("libsql://", "wss://", "ws://", "https://", "http://"):
            if v.startswith(scheme):
                v = v[len(scheme):]
                break
        return "https://" + v.rstrip("/")
    return None


def cmd_db_list(a):
    for d in list_databases():
        print(f"  {db_id(d)}  {d.get('name')}  {db_url(d) or ''}")


def cmd_db_create(a):
    existing = find_db(a.name)
    if existing:
        print(f"already exists: {a.name} (id {db_id(existing)}) — nothing to do")
        print(json.dumps(existing, indent=2))
        return
    # These use two different vocabularies: storage_region is an AWS-style code
    # (us-east-1) while primary/replica regions are Bunny PoP codes (NY). Confirmed
    # against the existing group via GET /v1/groups.
    payload = {"name": a.name, "storage_region": a.storage_region,
               "primary_regions": [a.region], "replicas_regions": [a.region]}
    st, body = req(DB_API + "/v2/databases", "POST", payload)
    if st not in (200, 201):
        die("create database", st, body)
    print(f"created {a.name}")
    print(json.dumps(body, indent=2))


def cmd_db_token(a):
    d = find_db(a.name) or sys.exit(f"no database named {a.name}. Run db-create first.")
    st, body = req(f"{DB_API}/v1/databases/{db_id(d)}/auth/tokens", "POST",
                   {"authorization": "full-access"})
    if st not in (200, 201):
        die("mint token", st, body)
    tok = body.get("token") or body.get("jwt") or body.get("access_token") if isinstance(body, dict) else None
    url = db_url(d)
    print("# Add these to the Magic Containers app as SECRETS, not plain variables.")
    print(f"BUNNY_DATABASE_URL={url}")
    print(f"BUNNY_DATABASE_AUTH_TOKEN={tok or json.dumps(body)}")
    print("\n# Never commit these. The token is full-access to every message in the mailbox.")


def pipeline(url: str, token: str, statements: list[str]) -> list:
    """Bunny's documented HTTP SQL API (libSQL Hrana v2), same shape app.py speaks."""
    base = url.rstrip("/")
    if not base.endswith("/v2/pipeline"):
        base += "/v2/pipeline"
    st, body = req(base, "POST",
                   {"requests": [{"type": "execute", "stmt": {"sql": s}} for s in statements]
                                + [{"type": "close"}]}, token=token)
    if st != 200:
        die("sql pipeline", st, body)
    results = []
    for r in (body or {}).get("results", []):
        if r.get("type") == "error":
            die("sql statement", 200, r.get("error"))
        resp = r.get("response") or {}
        # Only collect execute responses. The trailing "close" also returns a result, and
        # counting it meant callers got N+1 results for N statements, so zipping statements
        # against results silently misaligned by one.
        if resp.get("type") == "execute":
            results.append(resp.get("result") or {})
    return results


def statements_from_schema() -> list[str]:
    import re
    raw = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")).read()
    clean = "\n".join(re.sub(r"--.*$", "", ln) for ln in raw.splitlines())
    return [s.strip() for s in clean.split(";")
            if s.strip() and not s.strip().upper().startswith("PRAGMA")]


def cmd_db_schema(a):
    url, tok = a.url or os.environ.get("BUNNY_DATABASE_URL"), a.token or os.environ.get("BUNNY_DATABASE_AUTH_TOKEN")
    if not (url and tok):
        sys.exit("need --url/--token or BUNNY_DATABASE_URL/BUNNY_DATABASE_AUTH_TOKEN in the environment")
    stmts = statements_from_schema()
    pipeline(url, tok, stmts)
    print(f"applied {len(stmts)} statements from schema.sql")


def cmd_db_verify(a):
    url, tok = a.url or os.environ.get("BUNNY_DATABASE_URL"), a.token or os.environ.get("BUNNY_DATABASE_AUTH_TOKEN")
    if not (url and tok):
        sys.exit("need --url/--token or BUNNY_DATABASE_URL/BUNNY_DATABASE_AUTH_TOKEN in the environment")
    res = pipeline(url, tok, ["SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"])
    tables = [row[0]["value"] for row in res[0].get("rows", [])]
    if not tables:
        sys.exit("no tables. Run db-schema first.")
    counts = pipeline(url, tok, [f"SELECT count(*) FROM {t}" for t in tables])
    for t, c in zip(tables, counts):
        print(f"  {t:<18} {c['rows'][0][0]['value']:>6} rows")


def cmd_mc_apps(a):
    st, body = req(MC_API + "/apps")
    if st != 200:
        die("list magic containers apps", st, body)
    print(json.dumps(body, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("db-list").set_defaults(fn=cmd_db_list)
    sub.add_parser("mc-apps").set_defaults(fn=cmd_mc_apps)

    c = sub.add_parser("db-create"); c.set_defaults(fn=cmd_db_create)
    c.add_argument("--name", default=DEFAULT_NAME)
    c.add_argument("--region", default="NY", help="Bunny PoP code for primary/replica")
    c.add_argument("--storage-region", default="us-east-1", help="AWS-style storage region")

    t = sub.add_parser("db-token"); t.set_defaults(fn=cmd_db_token)
    t.add_argument("--name", default=DEFAULT_NAME)

    for nm, fn in (("db-schema", cmd_db_schema), ("db-verify", cmd_db_verify)):
        s = sub.add_parser(nm); s.set_defaults(fn=fn)
        s.add_argument("--name", default=DEFAULT_NAME)
        s.add_argument("--url"); s.add_argument("--token")

    a = ap.parse_args()
    a.fn(a)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

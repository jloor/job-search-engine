#!/usr/bin/env python3
"""The VA's queue notice: POST /va/notify, the one narrow exception to the approval gate.

⭐ WHY THESE GUARDS. The VM asks the relay to email a virtual assistant "N new tasks are
ready" because the VM must never hold RESEND_API_KEY, and that key can send as any alias on
the domain. Every other outbound mail needs the operator's approval, so this route is built
to send ONE fixed notice and nothing else.

🚨 WHAT MUST NEVER HAPPEN:
  - a read token, a submit token, or no token sending the notice;
  - any text from the caller reaching the mail (a subject, a recipient, a URL, a body);
  - an unconfigured relay sending anything, or inventing a recipient or a domain;
  - two notices inside VA_NOTIFY_MIN_GAP_S;
  - a recipient address landing in va_notice or in the audit log.

Run:  python3 tests/test_va_notify.py
"""
import asyncio
import io
import json
import os
import pathlib
import sys
import tempfile
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402  (strips BUNNY_*)

os.environ["DB_PATH"] = tempfile.mkdtemp() + "/va.db"
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
app.init_db()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


class Req:
    """Enough of a Starlette request for this route."""
    def __init__(self, body=None, bad_json=False):
        self._body = body
        self._bad = bad_json
        self.client = type("C", (), {"host": "10.0.0.9"})()
        self.headers = {}

    async def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._body


def call(body=None, auth="Bearer admin-tok", bad_json=False):
    """(status, payload) for one call."""
    try:
        r = asyncio.run(app.va_notify(Req(body, bad_json), authorization=auth))
    except Exception as e:                                    # noqa: BLE001
        return (getattr(e, "status_code", None) or getattr(e, "code", None) or repr(e),
                getattr(e, "detail", None))
    if hasattr(r, "status_code"):                             # a JSONResponse, real or stubbed
        return r.status_code, (json.loads(r.body) if hasattr(r, "body") else r.content)
    return 200, r


# Every Resend call is captured here. Nothing reaches the network.
sent = []


class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_urlopen(req, timeout=0):
    sent.append({"url": req.full_url, "payload": json.loads(req.data)})
    return Resp(json.dumps({"id": f"re{len(sent)}"}).encode())


urllib.request.urlopen = fake_urlopen


def rows():
    with app.db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM va_notice ORDER BY id")]


def reset_rows():
    with app.db() as con:
        con.execute("DELETE FROM va_notice")


app.READ_TOKEN, app.ADMIN_TOKEN = "read-tok", "admin-tok"
app.SUBMIT_TOKEN = "submit-tok"
app.MAIL_DOMAIN = "jobs.example.com"
app.RESEND_API_KEY = "re_test"
app.VA_NOTIFY_TO = "va@example.org"
app.VA_NOTIFY_FROM = ""
app.VA_NOTIFY_URL = "https://queue.example.net/signin"
app.VA_NOTIFY_MIN_GAP_S = 10800

print("schema:")
sql = (HERE.parent / "job_search_engine" / "schema.sql").read_text()
check("schema.sql declares va_notice", "CREATE TABLE IF NOT EXISTS va_notice (" in sql)
check("MIGRATIONS declares va_notice",
      any("CREATE TABLE IF NOT EXISTS va_notice (" in m for m in app.MIGRATIONS))

print("\nthe token:")
check("no token is 401", call({"count": 1}, auth=None)[0] == 401)
check("a wrong token is 401", call({"count": 1}, auth="Bearer nope")[0] == 401)
check("the READ token is refused (403)", call({"count": 1}, auth="Bearer read-tok")[0] == 403)
check("the SUBMIT token is refused", call({"count": 1}, auth="Bearer submit-tok")[0] in (401, 403))
check("…and nothing was sent", not sent)
check("…and an unauthenticated call writes no va_notice row", not rows())

print("\nthe body:")
for body, why in (({"count": 1, "subject": "hi"}, "an unknown key beside count"),
                  ({"count": 1, "to": "x@evil.example"}, "a recipient"),
                  ({"count": 1, "url": "https://evil.example"}, "a URL"),
                  ({"count": 1, "body": "free text"}, "a body"),
                  ({}, "an empty object"),
                  ([1], "a list"),
                  ("3", "a string")):
    check(f"400 for {why}", call(body)[0] == 400)
check("400 for a body that is not JSON", call(bad_json=True)[0] == 400)
for c, why in ((0, "zero"), (51, "51"), (-1, "a negative"), (2.0, "a float"),
               ("2", "a numeric string"), (True, "a boolean (True is an int in Python)"),
               (None, "null")):
    check(f"400 for count {why}", call({"count": c})[0] == 400)
check("…and nothing was sent", not sent)
r = rows()
check("each refusal is recorded as 'refused'", r and all(x["status"] == "refused" for x in r))
check("…and no refusal stored the caller's text",
      not any("evil" in json.dumps(x) or "free text" in json.dumps(x) for x in r))
reset_rows()

print("\nnot configured:")
for attr, val, why in (("VA_NOTIFY_TO", "", "VA_NOTIFY_TO unset"),
                       ("VA_NOTIFY_TO", " , ", "VA_NOTIFY_TO only commas"),
                       ("VA_NOTIFY_URL", "", "VA_NOTIFY_URL unset"),
                       ("MAIL_DOMAIN", "", "MAIL_DOMAIN unset, so no default sender")):
    old = getattr(app, attr)
    setattr(app, attr, val)
    st, detail = call({"count": 2})
    check(f"503 when {why}", st == 503)
    setattr(app, attr, old)
app.VA_NOTIFY_TO = ""
st, detail = call({"count": 2})
check("the unset message says 'VA notice not configured'",
      st == 503 and "VA notice not configured" in str(detail))
app.VA_NOTIFY_TO = "va@example.org"
for attr, val, why in (
        ("VA_NOTIFY_FROM", "notify@other.example", "a sender off the verified domain"),
        ("VA_NOTIFY_FROM", "Notify <notify@jobs.example.com>", "a sender with a display name"),
        ("VA_NOTIFY_TO", "Bob <va@example.org>", "a recipient with a display name"),
        ("VA_NOTIFY_TO", "va@example.org\r\nBcc: x@evil.example", "a recipient with a newline"),
        ("VA_NOTIFY_TO", ",".join(f"v{i}@example.org" for i in range(6)), "six recipients"),
        ("VA_NOTIFY_URL", "http://queue.example.net/signin", "a plain-http URL"),
        ("VA_NOTIFY_URL", "https://queue.example.net/x\nInjected", "a URL with a newline"),
        ("RESEND_API_KEY", "", "RESEND_API_KEY unset")):
    old = getattr(app, attr)
    setattr(app, attr, val)
    check(f"503 for {why}", call({"count": 2})[0] == 503)
    setattr(app, attr, old)
check("…and nothing was sent while unconfigured", not sent)
r = rows()
check("each one is recorded as 'refused'", r and all(x["status"] == "refused" for x in r))
check("…with no address in the record",
      not any("@" in (x["detail"] or "") for x in r if "VA_NOTIFY_FROM" not in (x["detail"] or "")))
reset_rows()

print("\nthe text:")
check("count 1 is singular",
      app.va_notice_body(1, "https://q.example/s") ==
      "1 new task is ready in your queue.\n\nSign in here: https://q.example/s\n\n"
      "This is an automatic notice. Please do not reply.")
check("count 3 is plural",
      app.va_notice_body(3, "https://q.example/s") ==
      "3 new tasks are ready in your queue.\n\nSign in here: https://q.example/s\n\n"
      "This is an automatic notice. Please do not reply.")

print("\nthe send:")
app.VA_NOTIFY_TO = "va@example.org, backup@example.org"
st, out = call({"count": 3})
check("200 on success", st == 200)
check("the response says sent, with Resend's ids and the recipient count",
      out == {"sent": True, "resend_id": "<re1@resend> <re2@resend>", "to_count": 2})
check("one Resend call per recipient, so no VA sees another's address", len(sent) == 2)
want_body = ("3 new tasks are ready in your queue.\n\n"
             "Sign in here: https://queue.example.net/signin\n\n"
             "This is an automatic notice. Please do not reply.")
for s, addr in zip(sent, ("va@example.org", "backup@example.org")):
    pl = s["payload"]
    check(f"to {addr}: the payload has exactly from, to, subject, text",
          set(pl) == {"from", "to", "subject", "text"})
    check(f"to {addr}: the sender defaults to notify@ on MAIL_DOMAIN",
          pl["from"] == "notify@jobs.example.com")
    check(f"to {addr}: the recipient is the configured one, alone", pl["to"] == [addr])
    check(f"to {addr}: the subject is fixed", pl["subject"] == "New tasks in your queue")
    check(f"to {addr}: the body is the fixed template", pl["text"] == want_body)
    check(f"to {addr}: no bcc, no reply headers", "bcc" not in pl and "headers" not in pl)
    check(f"to {addr}: it went to Resend", s["url"] == "https://api.resend.com/emails")
r = rows()
check("one row, at 'sent'", len(r) == 1 and r[0]["status"] == "sent")
check("the row holds count and to_count", r and r[0]["count"] == 3 and r[0]["to_count"] == 2)
check("the row holds the Resend ids", r and r[0]["resend_id"] == "<re1@resend> <re2@resend>")
check("the row holds no address",
      r and "example.org" not in json.dumps(r[0]) and "@example" not in json.dumps(r[0]))

print("\nthe rate limit:")
n_before = len(sent)
st, out = call({"count": 1})
check("a second notice inside the gap is 429", st == 429)
check("…with retry_after_s, close to the full gap",
      isinstance(out, dict) and set(out) == {"retry_after_s"}
      and 10800 - 60 <= out["retry_after_s"] <= 10800)
check("…and nothing was sent", len(sent) == n_before)
r429 = asyncio.run(app.va_notify(Req({"count": 1}), authorization="Bearer admin-tok"))
check("…and it carries a Retry-After header",
      str(getattr(r429, "headers", {}).get("Retry-After", "")).isdigit())
check("…and the refusal is recorded",
      rows()[-1]["status"] == "refused" and "rate limit" in rows()[-1]["detail"])
app.VA_NOTIFY_MIN_GAP_S = 0
st, out = call({"count": 1})
check("with the gap past, the next notice goes", st == 200 and out["sent"] is True)
check("…and its body is singular", sent[-1]["payload"]["text"].startswith("1 new task is ready"))
app.VA_NOTIFY_MIN_GAP_S = 10800
reset_rows()

print("\na failed send:")
app.VA_NOTIFY_TO = "va@example.org"


def failing_urlopen(req, timeout=0):
    import urllib.error
    raise urllib.error.HTTPError(req.full_url, 422, "bad", {},
                                 io.BytesIO(b'{"message":"Invalid `to`: va@example.org"}'))


urllib.request.urlopen = failing_urlopen
st, _ = call({"count": 2})
check("every recipient failing is 502", st == 502)
r = rows()
check("…recorded as 'error'", len(r) == 1 and r[0]["status"] == "error")
check("…with the address Resend echoed scrubbed out", r and "va@example.org" not in r[0]["detail"])
urllib.request.urlopen = fake_urlopen
st, _ = call({"count": 2})
check("an 'error' does not hold the gap: the retry goes at once", st == 200)

print("\nthe audit log:")
with app.db() as con:
    ev = json.dumps([dict(x) for x in con.execute("SELECT * FROM event")])
check("no recipient address in the event table", "va@example.org" not in ev
      and "backup@example.org" not in ev)

print("\n/send is untouched:")
src = (HERE.parent / "job_search_engine" / "app.py").read_text()
va = src[src.index("async def va_notify("):src.index("# ======", src.index("async def va_notify("))]
check("the route reads exactly one caller field", va.count('p["count"]') == 1
      and "p.get(" not in va)
check("the route never calls _deliver_approved or the SMTP path",
      "_deliver_approved" not in va and "_send_via_smtp" not in va)

print()
if fails:
    print(f"{len(fails)} FAILED")
    sys.exit(1)
print("all passed")

#!/usr/bin/env python3
"""The phone alert: which mail rings, that it rings once, and what leaves the box.

⭐ WHY, 2026-10-01. Mail reached the relay in seconds and nothing told a person. A rejection on
a row at INTERVIEW is held for a human by design, and the hold had no prompt: the LeanTaaS
rejection sat on a live interview row for a day unseen. The first block below is that case.

🚨 WHAT MUST NEVER HAPPEN, and each has a check:
  * a double alert, from the webhook thread and the sweep reaching one row together
  * the email BODY leaving the box through the alert
  * an alert path that fails silently

Run:  python3 tests/test_notify.py
"""
import http.server
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402  (strips BUNNY_*)

_db = tempfile.mkdtemp() + "/notify.db"
os.environ["DB_PATH"] = _db
app = test_parse.load_app()
if getattr(app, "BUNNY_DB_URL", ""):
    sys.exit("refusing to run: the app is bound to a remote database")
import notify as N                                            # noqa: E402  same module app uses

SRC = (HERE.parent / "job_search_engine" / "app.py").read_text()
fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


print("the rule:")
check("a rejection on a submitted row is quiet", N.decide("rejection", False, "submitted") is None)
check("a confirmation is quiet", N.decide("confirmation", False, None) is None)
check("⭐ a rejection on an INTERVIEW row rings (the LeanTaaS case)",
      N.decide("rejection", False, "interview") == "live_interview")
check("any mail on an offer row rings", N.decide("noise", False, "offer") == "live_offer")
check("a security code rings", N.decide("otp", False, None) == "label_otp")
check("a spoof warning rings whatever the label", N.decide("confirmation", True, None) == "spoof_warning")
check("no label at all rings as unknown", N.decide(None, False, None) == "label_unknown")

print("\nthe alert:")
msg = {"id": 7, "from_name": "Grace", "from_addr": "g@x.com", "subject": "An update",
       "classification": "rejection", "to_alias": "leantaas@jobs.example.com",
       "body_text": "SECRET BODY TEXT"}
p = N.build(msg, "live_interview", "LeanTaaS")
check("the title names the company and the live row",
      "LeanTaaS" in p["title"] and "INTERVIEW ROW" in p["title"])
check("a live row is high priority", p["priority"] == 4)
check("🚨 the body never leaves the box", "SECRET" not in json.dumps(p))
check("an unmatched message falls back to the alias",
      N.build({**msg, "classification": "otp"}, "label_otp")["title"].startswith("leantaas:"))
check("the topic splits off the URL", N.split_url("https://ntfy.sh/js-abc") == ("https://ntfy.sh", "js-abc"))
try:
    N.split_url("ntfy.sh")
    check("a malformed NTFY_URL is refused", False)
except ValueError:
    check("a malformed NTFY_URL is refused", True)

print("\nthe wire format, against a real local HTTP server:")
seen = {}


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        seen["path"] = self.path
        seen["auth"] = self.headers.get("Authorization")
        seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        out = b'{"id":"abc123"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.handle_request, daemon=True).start()
ok, detail = N.send(f"http://127.0.0.1:{srv.server_port}/js-topic", "tk_1", p)
check("a 200 reports ok, with ntfy's message id as evidence", ok and "abc123" in detail)
check("it posts to the server root", seen.get("path") == "/")
check("the topic travels in the JSON body", seen.get("body", {}).get("topic") == "js-topic")
check("the token travels as a bearer header", seen.get("auth") == "Bearer tk_1")
ok, detail = N.send("http://127.0.0.1:9/js-topic", "", p, timeout=2)
check("an unreachable server reports failure and does not raise", not ok and detail)

print("\nend to end through the database:")
con = sqlite3.connect(_db)
con.executescript((HERE.parent / "job_search_engine" / "schema.sql").read_text())
for s in app.MIGRATIONS:
    try:
        con.execute(s)
    except Exception:
        pass
con.execute("INSERT INTO application(id,posting_id,status,company_raw,alias_used) "
            "VALUES (1,1,'interview','**LeanTaaS** ⭐⭐ *(x)*','leantaas@jobs.example.com')")
con.execute("INSERT INTO application(id,posting_id,status,company_raw,alias_used) "
            "VALUES (2,1,'submitted','Acme','acme@jobs.example.com')")
old = app._ago(minutes=5)


def add(mid, label, ref, auth=0):
    con.execute("INSERT INTO message(id,received_at,to_alias,raw_payload,from_addr,subject,"
                "classification,application_ref,auth_warn,body_text) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (mid, old, f"{ref}@jobs.example.com", "{}", "a@b.c", f"s{mid}", label, ref, auth,
                 "SECRET"))
    con.commit()


def row(mid):
    return dict(zip(("state", "attempts", "reason"), con.execute(
        "SELECT notify_state, notify_attempts, notify_reason FROM message WHERE id=?",
        (mid,)).fetchone()))


sent = []
N.send = lambda url, tok, payload, timeout=8.0: (sent.append(payload) or (True, "http 200 id=t"))

app.NTFY_URL = ""
add(1, "rejection", "leantaas")
check("with NTFY_URL unset the feature is off", app.notify_message(1) == "disabled" and not sent)
check("…and writes nothing", row(1)["state"] is None)

app.NTFY_URL = "https://ntfy.example/js-topic"
check("the interview-row rejection is sent", app.notify_message(1) == "sent" and len(sent) == 1)
check("the company is cleaned of markdown and stars", sent[0]["title"].startswith("INTERVIEW ROW · LeanTaaS:"))
check("🚨 a second attempt does not alert twice", app.notify_message(1) != "sent" and len(sent) == 1)
check("the sweep does not pick a sent row up again", app.job_notify() == "nothing to notify")

add(2, "rejection", "acme")
check("a plain rejection is skipped", app.notify_message(2) == "skipped" and row(2)["state"] == "skipped")
check("a skipped row is not swept again while its label holds", app.job_notify() == "nothing to notify")
con.execute("UPDATE message SET classification='interview_invite', classification_source='model' "
            " WHERE id=2")
con.commit()
before = len(sent)
check("⭐ when the model relabels it, the sweep sends it", "sent 1" in app.job_notify()
      and len(sent) == before + 1)

add(3, "otp", "nobody")
N.send = lambda url, tok, payload, timeout=8.0: (False, "http 503")
r = app.notify_message(3)
check("a failed send says so", r.startswith("failed") and row(3)["state"] == "failed")
check("…and counts the attempt", row(3)["attempts"] == 1)
check("the sweep reports the failure where /diag/jobs shows it", "failed" in app.job_notify())
for _ in range(10):
    app.job_notify()
check("retries stop at NOTIFY_MAX_TRIES", row(3)["attempts"] == app.NOTIFY_MAX_TRIES)

con.execute("UPDATE message SET notify_state='sending', notify_at=? WHERE id=3",
            (app._ago(minutes=30),))
con.execute("UPDATE message SET notify_attempts=0 WHERE id=3")
con.commit()
N.send = lambda url, tok, payload, timeout=8.0: (True, "http 200")
check("a claim abandoned by a dead thread is reclaimed", "sent 1" in app.job_notify())

con.execute("INSERT INTO message(id,received_at,to_alias,raw_payload) VALUES (9,?, '', '{}')",
            (app._ago(seconds=5),))
con.commit()
check("a row still mid-ingest is left to its webhook thread", app.job_notify() == "nothing to notify")

print("\nthe wiring:")
check("the webhook starts the alert on a thread, off the request path",
      "threading.Thread(target=notify_message, args=(mid,), daemon=True).start()" in SRC)
check("the sweep is registered with the scheduler", '("notify", NOTIFY_EVERY_MIN * 60, job_notify)' in SRC)
check("🚨 the secret topic URL is never interpolated into a log line",
      "{NTFY_URL" not in SRC and "{NTFY_TOKEN" not in SRC)

print("\nthe Bunny result shape:")
# 🚨 The suite runs on sqlite, whose cursor has rowcount. The Bunny result object did not, so
# the claim passed every test above and raised AttributeError in production on 2026-10-01.
rs = app._RS({"cols": [], "rows": [], "affected_row_count": 1, "last_insert_rowid": None},
             lambda v: v)
check("a Bunny result reports rows changed, like sqlite3.Cursor", rs.rowcount == 1)
check("…and zero when the claim lost the race",
      app._RS({"cols": [], "rows": []}, lambda v: v).rowcount == 0)

print(f"\n{'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
sys.exit(1 if fails else 0)

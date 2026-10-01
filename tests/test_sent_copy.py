#!/usr/bin/env python3
"""The operator's copy of every approved send, by BCC.

⭐ WHY, 2026-10-01. Resend keeps no copy in his mailbox, so a reply sent through the relay
existed nowhere he reads mail, and it was not in the employer's conversation on his side
either. The BCC copy carries the same In-Reply-To and References, so it files there.

🚨 WHAT MUST NEVER HAPPEN: the BCC address showing in a header the employer receives, and a
bad SENT_COPY_BCC value failing the send itself rather than just the copy.

Run:  python3 tests/test_sent_copy.py
"""
import io
import json
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_parse                                             # noqa: E402  (strips BUNNY_*)

os.environ["DB_PATH"] = tempfile.mkdtemp() + "/copy.db"
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


print("the setting:")
app.SENT_COPY_BCC = ""
check("unset means no copy", app._sent_copy_bcc() is None)
app.SENT_COPY_BCC = "copy@example.com"
check("one address is used", app._sent_copy_bcc() == "copy@example.com")
for bad in ("a@b.com, c@d.com", "Name <a@b.com>", "nobody", "a@b"):
    app.SENT_COPY_BCC = bad
    check(f"a malformed value is refused, not passed on: {bad!r}", app._sent_copy_bcc() is None)

print("\nResend:")
seen = {}


class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_urlopen(req, timeout=0):
    seen["payload"] = json.loads(req.data)
    return Resp(b'{"id":"abc"}')


import urllib.request                                          # noqa: E402
_real = urllib.request.urlopen
urllib.request.urlopen = fake_urlopen
app.RESEND_API_KEY = "re_test"
parent = {"message_id": "<orig@employer.com>", "references_hdr": "<a@employer.com>"}
try:
    app._send_via_resend("acme@jobs.example.com", "dana@acme.com", "Re: hi", "Thanks.", parent,
                         bcc="copy@example.com")
    pl = seen.get("payload", {})
    check("the copy goes as bcc", pl.get("bcc") == ["copy@example.com"])
    check("…and never as to or cc", pl.get("to") == ["dana@acme.com"] and "cc" not in pl)
    check("the thread headers ride on the same message, so the copy files in the conversation",
          pl.get("headers", {}).get("In-Reply-To") == "<orig@employer.com>")
    app._send_via_resend("acme@jobs.example.com", "dana@acme.com", "Re: hi", "Thanks.", parent)
    check("no bcc argument, no bcc field", "bcc" not in seen["payload"])
except Exception as e:
    check(f"the Resend path runs ({type(e).__name__}: {e})", False)
finally:
    urllib.request.urlopen = _real

print("\nSMTP:")
from email.message import EmailMessage                         # noqa: E402
sent = {}


class FakeSMTP:
    def __init__(self, *a, **k): pass
    def ehlo(self, *a): pass
    def starttls(self, **k): pass
    def login(self, *a): pass
    def quit(self): pass

    def send_message(self, msg, to_addrs=None):
        sent["to_addrs"], sent["wire"] = to_addrs, msg.as_string()


app.smtplib.SMTP = FakeSMTP
app.SMTP_USER, app.SMTP_PASS = "u", "p"
m = EmailMessage()
m["From"], m["To"], m["Subject"], m["Message-ID"] = "x@jobs.example.com", "Dana <dana@acme.com>", "s", "<m@x>"
m.set_content("body")
app._send_via_smtp(m, bcc="copy@example.com")
check("the copy is an envelope recipient", sent["to_addrs"] == ["dana@acme.com", "copy@example.com"])
check("🚨 the copy address appears in no header the employer receives",
      "copy@example.com" not in sent["wire"])
app._send_via_smtp(m)
check("no bcc argument, one recipient", sent["to_addrs"] == ["dana@acme.com"])

print(f"\n{'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
sys.exit(1 if fails else 0)

"""The browser submitter's runner, SHADOW MODE: fill one application form, prove what it holds,
and stop before submit. Runs on the submitter's own host user, never in the container.

    python -m job_search_engine.submit once [--app N] [--live]

One run, start to finish (each step is recorded through the relay, with its screenshot):
   1 claim      the next eligible draft from /submit/next (or the one named by --app)
   2 liveness   the Greenhouse job still exists on a board that still answers
   3 gates      remote, no excluded time zones, a pay range stated, no office obligation
   4 package    the archived posting, the résumé, the letter when the form takes one, and the
                application's alias inside each PDF
   5 open       the form, headed on the submitter's virtual screen
   6 answers    every field decided from the package and the candidate config, or the run stops
   7 fill       files, then choices, then free text
   8 readback   every field read back off the page and compared with the decision
   9 review     a full-page screenshot of the filled form. THE RUN ENDS HERE.
  10 record     fields.json for the submission record, the run closed, one phone alert

🚨 A SHADOW RUN CANNOT SUBMIT: the page blocks every submission, and step 10 posts the record to
the relay, which turns it into a passkey approval link for a person.
⭐ A LIVE RUN (--live, 2026-10-08) submits ONE application, once, and only when:
  - a person approved this exact record with a passkey (/submit/approve/{token});
  - the package files hash exactly as approved;
  - the page, filled again, reads back exactly the approved record (same fingerprint);
  - the relay consumed the approval and returned a nonce (arm), before the single click.
After arming, any failure closes the run 'unknown' and it is never retried: a click with no proof
is resolved from the confirmation mail, not by clicking again.

Environment (from the submitter host's env file, never from the repository):
  SUBMIT_RELAY_URL      the relay, e.g. https://relay.example.com
  SUBMIT_TOKEN          the submit-scope token
  SUBMIT_REPO_DIR       the checkout holding the application packages and candidate config
  SUBMIT_EVIDENCE_DIR   where screenshots go (default ~/evidence)
  SUBMIT_NODE           node binary (default: node)
  SUBMIT_HEADED         1 to draw on $DISPLAY (default 1 when DISPLAY is set)
  SUBMIT_DISABLED       1 stops every run before it starts (the kill switch)
  SUBMIT_KILL_FILE      a file whose existence is the same kill switch
  SUBMIT_HOLD_SECONDS   keep the filled form on screen this long after the run ends (max 600)
  NTFY_URL, NTFY_TOKEN  the phone alert (optional)
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import answers as A                                             # noqa: E402
import ashby as ASH                                             # noqa: E402
import greenhouse as GH                                         # noqa: E402
import record as R                                              # noqa: E402

FORM_JS = HERE / "browser" / "form.js"


class Stop(Exception):
    """The run must stop at this step for a person. Not an error: the reason is the output."""


# ── the relay ─────────────────────────────────────────────────────────────────────────────
class Relay:
    def __init__(self, url: str, token: str, opener=None):
        if not (url and token):
            raise SystemExit("SUBMIT_RELAY_URL and SUBMIT_TOKEN must be set")
        self.url, self.token = url.rstrip("/"), token
        self.op = opener or urllib.request.urlopen

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            self.url + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                     "User-Agent": "job-search-engine submitter"})
        try:
            with self.op(req, timeout=30) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"relay {method} {path}: {e.code} {e.read()[:300]!r}") from e

    def next(self, app_id: int | None = None, mode: str = "shadow") -> dict | None:
        q = f"?mode={mode}" + (f"&app_id={int(app_id)}" if app_id is not None else "")
        return self._call("GET", "/submit/next" + q).get("next")

    def next_all(self, ats: str) -> list:
        """Every approved live item for one board, oldest approval first (a batch)."""
        return self._call("GET", f"/submit/next?mode=live&ats={ats}&all=1").get("items") or []

    def open(self, **kw) -> int:
        return self._call("POST", "/submit/run", kw)["run_id"]

    def step(self, run_id: int, **kw) -> None:
        self._call("POST", f"/submit/run/{run_id}/step", kw)

    def close(self, run_id: int, **kw) -> dict:
        return self._call("POST", f"/submit/run/{run_id}/close", kw)

    def arm(self, run_id: int, record_fp: str) -> str:
        return self._call("POST", f"/submit/run/{run_id}/arm", {"record_fp": record_fp})["nonce"]

    def submitted(self, run_id: int, **kw) -> None:
        self._call("POST", f"/submit/run/{run_id}/submitted", kw)

    def confirmation(self, run_id: int) -> dict | None:
        """The employer's confirmation email for this run, or None while none has arrived (404)."""
        try:
            return self._call("GET", f"/submit/run/{run_id}/confirmation")
        except RuntimeError as e:
            if f"/submit/run/{run_id}/confirmation: 404" in str(e):
                return None
            raise

    def code(self, run_id: int) -> dict | None:
        """The run's ONE security code, or None while no qualifying mail has arrived (404)."""
        try:
            return self._call("GET", f"/submit/run/{run_id}/code")
        except RuntimeError as e:
            if f"/submit/run/{run_id}/code: 404" in str(e):
                return None
            raise


# ── the browser ───────────────────────────────────────────────────────────────────────────
class Browser:
    """form.js as a child process: one JSON line out, one JSON line back."""

    def __init__(self, node: str = "node", env: dict | None = None):
        self.p = subprocess.Popen([node, str(FORM_JS)], cwd=str(FORM_JS.parent), text=True,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)

    def __call__(self, cmd: str, **kw) -> dict:
        self.p.stdin.write(json.dumps({"cmd": cmd, **kw}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"form.js exited during {cmd!r}")
        r = json.loads(line)
        if not r.get("ok"):
            raise RuntimeError(f"form.js {cmd}: {r.get('error')}")
        return r

    def quit(self):
        try:
            self("close")
            self.p.stdin.close()
            self.p.wait(timeout=20)
        except Exception:                                           # noqa: BLE001
            self.p.kill()


# ── checks with no browser ────────────────────────────────────────────────────────────────
# A location that names the whole eligible country and nothing smaller.
COUNTRY_WIDE = re.compile(r"^(united states( of america)?|u\.?s\.?a?\.?)$", re.I)


def check_gates(job_doc: dict, cfg: dict, ats: str = "greenhouse") -> None:
    import comp as COMP
    import gates as G
    if ats == "ashby":
        desc, loc = ASH.description(job_doc), ASH.location(job_doc)
    else:
        desc = GH.description(job_doc)
        loc = ((job_doc.get("location") or {}).get("name") or "").strip()
    keep, why = G.gate({"location": loc, "title": job_doc.get("title") or "", "description": desc}, cfg)
    # ⚠️ THE RUNNER MUST NOT BE STRICTER THAN THE DECISION IT CARRIES OUT. gate() is the cheap
    # first filter: it keeps on evidence and leaves the rest to the remote reader, which an
    # approved posting has already passed. A posting located only "United States" reads as
    # "out on geography" there, while it names no city at all. Found 2026-10-08 on an
    # approved role whose body said "our remote implementation model". A country-wide
    # location passes here; the office-obligation check below still runs on its text.
    if not keep and why == "out on geography" and COUNTRY_WIDE.match(loc):
        keep = True
    if not keep:
        raise Stop(f"the remote gate fails: {why} (location {loc!r})")
    ob = G.office_obligation(desc)
    if ob:
        raise Stop(f"the posting states an office obligation: {ob!r}")
    tz = G._tz_re(cfg)
    m = tz.search(desc) if tz else None
    if m:
        raise Stop(f"the posting names an excluded time zone: {m.group(0)!r}")
    if not COMP.extract(None, desc):
        raise Stop("the posting states no pay range")


def pdf_text(path: Path) -> str:
    """The text of a PDF (poppler's pdftotext). A module function so a test can replace it."""
    try:
        return subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True,
                              timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"pdftotext failed on {path.name}: {e}") from e


def check_package(pkg: Path, alias: str, needs_letter: bool) -> list:
    """The package files this run will attach. Raises Stop on anything missing."""
    jd = pkg / "job-description.md"
    if not jd.exists() or "verbatim" not in jd.read_text(errors="replace").lower():
        raise Stop("job-description.md is missing or has no verbatim posting text")
    # A letter that exists is always checked, because the fill attaches it wherever the form
    # offers a slot; a letter the form requires must exist.
    letter = pkg / "cover-letter.pdf"
    files = [pkg / "resume.pdf"] + ([letter] if needs_letter or letter.exists() else [])
    for f in files:
        if not f.exists() or f.stat().st_size == 0:
            raise Stop(f"{f.name} is missing or empty")
        text = pdf_text(f)
        if alias.lower() not in re.sub(r"\s+", "", text).lower():
            raise Stop(f"{f.name} does not carry the application's alias {alias}")
    return files


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def compare(decisions: list, fill_results: list, page: list, uploads: dict | None = None) -> list:
    """What the page holds against what was decided. Returns the mismatches as sentences."""
    got = {f["id"]: f for f in page}
    uploads = uploads or {}
    chosen = {r["id"]: r for r in fill_results}
    bad = []
    for d in decisions:
        if not d.answered:
            continue
        r, f = chosen.get(d.id, {}), got.get(d.id)
        if r.get("status") not in ("set",):
            extra = f" (options: {r.get('options')})" if r.get("options") else ""
            bad.append(f"{d.label or d.id}: fill reported {r.get('status', 'nothing')}{extra}")
            continue
        if d.kind == "file":
            # The input itself when it still exists; otherwise the filename the page shows in its
            # place (a board that swaps the input for a chip after the upload).
            name = Path(d.value).name
            up = uploads.get(d.id) or {}
            held = (f or {}).get("files") or up.get("held") or []
            if not (any(x["name"] == name and x["size"] > 0 for x in held)
                    or (f is None and up.get("shown"))):
                bad.append(f"{d.label or d.id}: the page does not hold {name}")
        elif f is None:
            bad.append(f"{d.label or d.id}: the field is gone from the page after the fill")
        elif d.kind == "yesno":
            if (f.get("value") or "") != d.value:
                bad.append(f"{d.label or d.id}: reads {f.get('value') or 'nothing'!r}, wanted {d.value!r}")
        elif d.kind == "checkgroup":
            got_set = {x.strip().lower() for x in (f.get("value") or "").split("|") if x.strip()}
            if got_set != {x.strip().lower() for x in d.spellings}:
                bad.append(f"{d.label or d.id}: reads {f.get('value')!r}, wanted {' | '.join(d.spellings)!r}")
        elif d.kind in ("select", "native_select", "radiogroup"):
            # Compared without whitespace: a board's two renderings of one option differ only in
            # spacing ("United States +1" / "United States+1"), the same rule form.js chooses by.
            if re.sub(r"\s+", "", (f.get("value") or "").lower()) != re.sub(r"\s+", "", (r.get("chosen") or "").lower()):
                bad.append(f"{d.label or d.id}: reads {f.get('value')!r}, chose {r.get('chosen')!r}")
        elif d.kind == "tel":
            if not _digits(f.get("value")).endswith(_digits(d.value)[-10:]):
                bad.append(f"{d.label or d.id}: reads {f.get('value')!r}, wanted {d.value!r}")
        elif " ".join((f.get("value") or "").split()) != " ".join(d.value.split()):
            bad.append(f"{d.label or d.id}: reads {(f.get('value') or '')[:80]!r}, "
                       f"wanted {d.value[:80]!r}")
    return bad


def required_empty(page: list, fields: list) -> list:
    req = {f["id"]: f for f in fields if f.get("required")}
    out = []
    for f in page:
        if f["id"] not in req:
            continue
        # A yes/no or a checkbox group reads back as a value ("yes", "A | B"), so the value rule applies.
        empty = (not f.get("files")) if f.get("kind") == "file" else (
            not f.get("checked") if f.get("kind") in ("checkbox", "radio") else not (f.get("value") or "").strip())
        if empty:
            out.append(req[f["id"]].get("label") or f["id"])
    return out


# ── one run ───────────────────────────────────────────────────────────────────────────────
CODE_WAIT_S = 90                       # each wait for the emailed security code
CODE_POLL_S = 5
CODE_RESENDS = 2                       # resend requests after a wait with no code (3 waits in all)
CONFIRM_WAIT_S = 600                   # with no page proof, how long to watch for the confirmation email
CONFIRM_POLL_S = 15
HANDOFF_CLICKS = 3                     # a person's clicks the hand-off lets through (after a spam refusal)
HANDOFF_ROUNDS = 2                     # further waits after a spam refusal or a CAPTCHA
HANDOFF_AGAIN_S = 240                  # each of those waits


def _handoff_seconds() -> int:
    """SUBMIT_HANDOFF_SECONDS: how long a handed-off form waits for the person's click (30-600)."""
    try:
        return max(30, min(600, int(os.environ.get("SUBMIT_HANDOFF_SECONDS", "600") or 600)))
    except ValueError:
        return 600


def VIEWER_URL() -> str:                                            # noqa: N802
    """Where the person opens the virtual screen. Configuration of the host, never the engine's."""
    return os.environ.get("SUBMIT_VIEWER_URL", "").strip()


def ready_alert(items: list) -> dict:
    n = len(items)
    names = ", ".join(str(i.get("company") or f"APP {i['application_id']}") for i in items[:6])
    return {"title": (f"Ready for your click: {n} application{'s' if n != 1 else ''}")[:200],
            "message": (f"{names}. Each is filled and checked against the record you approved. "
                        "Open the viewer and click Submit Application, once per form. Nothing is "
                        "sent without your click.")[:400],
            "priority": 5, "tags": ["robot", "point_right"],
            **({"click": VIEWER_URL()} if VIEWER_URL() else {})}


class Run:
    def __init__(self, relay, browser_factory, cfg: dict, repo: Path, evidence: Path,
                 headed: bool, opener=None, version: str = "", notify=None, sleep=time.sleep,
                 batch: bool = False):
        self.relay, self.browser_factory, self.cfg = relay, browser_factory, cfg
        self.repo, self.evidence, self.headed = repo, evidence, headed
        self.opener, self.version, self.notify = opener, version, notify
        self.sleep = sleep
        self.batch = batch                   # a batch sends one "ready" alert for all its forms
        self.handed_off = False
        self.spam_seen = False               # Ashby showed its spam refusal during the hand-off
        self.n = 0

    def _step(self, name: str, outcome: str, detail: str = "", shot: Path | None = None):
        self.n += 1
        sha = hashlib.sha256(shot.read_bytes()).hexdigest() if shot and shot.exists() else None
        self.relay.step(self.run_id, n=self.n, name=name, outcome=outcome, detail=detail[:4000],
                        screenshot_path=str(shot) if sha else None, sha256=sha)

    def _shot(self, br, name: str) -> Path:
        p = self.dir / f"{self.n + 1:02d}-{name}.png"
        br("shot", path=str(p))
        return p

    def go(self, item: dict) -> dict:
        app_id = item["application_id"]
        alias = item["alias_used"]
        pkg = self.repo / item["package_path"]
        self.mode = item.get("mode") or "shadow"
        live = self.mode == "live"
        ats = "ashby" if ASH.is_ashby(item["url"]) else "greenhouse"
        self.handed_off = False
        self.run_id = self.relay.open(application_id=app_id, ats=ats, mode=self.mode,
                                      record_fp=item.get("record_fp"),
                                      engine_version=self.version, host=socket.gethostname(),
                                      evidence_dir="")
        self.dir = self.evidence / str(app_id) / str(self.run_id)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._step("claim", "ok", f"application {app_id} {item['url']} evidence {self.dir}")
        br, step, armed = None, "liveness", False
        try:
            M = ASH if ats == "ashby" else GH
            if ats == "ashby":
                token, jid = ASH.parse(item["url"])
            else:
                token, jid = GH.resolve(item["url"], self.opener)
            try:
                job_doc = M.job(token, jid, self.opener)
            except M.NotFound:
                if M.board_exists(token, self.opener):
                    raise Stop(f"the job is gone from board {token!r} (the board answers)")
                raise RuntimeError(f"board {token!r} does not answer; cannot judge liveness")
            self._step(step, "ok", f"{token}/{jid}: {job_doc.get('title')}")

            step = "gates"
            check_gates(job_doc, self.cfg, ats)
            self._step(step, "ok")

            step = "package"
            # Ashby publishes no question API: the page alone describes the form.
            api_q = GH.questions(job_doc) if ats == "greenhouse" else {}
            # The letter is checked when the form takes one: required, or offered and written.
            letter_slot = "cover_letter" in api_q
            needs_letter = letter_slot and api_q["cover_letter"]["required"]
            files = check_package(pkg, alias, needs_letter=needs_letter)
            hashes = {f.name: R.file_sha(f) for f in files}
            if live and hashes != (item.get("files") or {}):
                raise Stop(f"the package files differ from the approved record: {sorted(hashes)} "
                           f"vs {sorted(item.get('files') or {})} (a file was edited after approval)")
            self._step(step, "ok", ", ".join(f"{n} {h[:12]}" for n, h in sorted(hashes.items())))

            step = "open"
            br = self.browser_factory()
            o = br("open", url=M.hosted_url(token, jid), headed=self.headed, settle=4500)
            h = br("harvest")
            if h.get("captcha"):
                raise Stop("a CAPTCHA is on the page before any input; a person must solve it")
            shot = self._shot(br, "loaded")
            self._step(step, "ok", f"{o['url']} · {len(h['fields'])} fields", shot)

            step = "answers"
            decisions, stops = A.plan(h["fields"], api_q, self.cfg, pkg, alias)
            unanswered = [d.label or d.id for d in decisions if not d.answered and not d.required]
            if stops:
                raise Stop("; ".join(stops))
            self._step(step, "ok", f"{sum(d.answered for d in decisions)} answered; "
                       f"optional left blank: {unanswered}")

            step = "fill"
            fr = br(**A.fill_command(decisions))
            shot = self._shot(br, "filled")
            self._step(step, "ok", json.dumps(fr["results"])[:3900], shot)

            step = "readback"
            fc = A.fill_command(decisions)
            rb = br("readback", files=[{"id": x["id"], "name": Path(x["path"]).name} for x in fc["files"]])
            if any(rb["blocked_submits"].values()):
                raise RuntimeError(f"a submit was attempted and blocked: {rb['blocked_submits']}")
            bad = compare(decisions, fr["results"], rb["fields"], rb.get("uploads")) + [
                f"{x}: required and still empty" for x in required_empty(rb["fields"], h["fields"])]
            if bad:
                raise Stop("; ".join(bad))
            self._step(step, "ok", f"{len(rb['fields'])} fields read back, all as decided")

            step = "review"
            shot = self._shot(br, "review")
            self._step(step, "ok", "the filled form, as it would be submitted."
                       + ("" if live else " NOT submitted."), shot)

            step = "record"
            by_id = {f["id"]: f for f in rb["fields"]}
            record = [{"id": d.id, "label": d.label or d.id,
                       "value": Path(d.value).name if d.kind == "file" else (
                           by_id.get(d.id, {}).get("value") or ""),
                       "verified_len": len(by_id.get(d.id, {}).get("value") or "")
                       if d.kind != "file" else None,
                       "source": d.source}
                      for d in decisions if d.answered]
            (self.dir / "fields.json").write_text(json.dumps(record, indent=1))
            rec = {"fields": [{"id": r["id"], "label": r["label"], "value": r["value"]} for r in record],
                   "files": hashes}
            record_fp = R.fingerprint(app_id, item["url"], rec["fields"], rec["files"])
            self._step(step, "ok", f"fields.json with {len(record)} fields; record {record_fp[:16]}")

            if not live:
                try:
                    out = self.relay.close(self.run_id, outcome="shadow_complete", record=rec,
                                           record_fp=record_fp) or {}
                except RuntimeError as e:
                    # The relay refused the record: close the run, so the draft is not left busy.
                    raise RuntimeError(f"the relay refused the record: {e}") from e
                return self._done(app_id, "shadow_complete", out.get("approval_url") or "")

            # ── LIVE: the approved record, exactly, or nothing ─────────────────────────────
            step = "match"
            if record_fp != item.get("record_fp"):
                raise Stop(f"the form now reads differently from the approved record "
                           f"({record_fp[:16]} vs {str(item.get('record_fp'))[:16]}); nothing was sent. "
                           f"Compare fields.json with the approved record.")
            self._step(step, "ok", f"the page holds the approved record {record_fp[:16]}")

            step = "submit"
            nonce = self.relay.arm(self.run_id, record_fp)
            armed = True                       # from here on, a failure is 'unknown', never retried
            br("arm", nonce=nonce)
            if ats == "ashby":
                # ⭐ ASHBY: A PERSON CLICKS. Ashby refuses a scripted Submit as possible spam, and
                # imitating a person to pass that check is evasion. The form is filled, proved to be
                # the approved record, and handed to the operator for ONE real click in the viewer.
                r = self._handoff(br, app_id, item, nonce, step)
                if r.get("status") == "not_clicked":
                    return r["done"]
            else:
                r = br("final_submit", nonce=nonce, wait_s=60)
            if r.get("status") == "code_step":
                r = self._code(br, r, step)
            if r.get("status") == "human_step":
                shot = self._shot(br, "human-step")
                self._step(step, "ok", "a CAPTCHA appeared after the click; waiting for a person", shot)
                if self.notify:
                    self.notify({"title": f"Submitter: APP {app_id} needs you (CAPTCHA)"[:200],
                                 "message": "Solve it in the viewer. The run waits 10 minutes and "
                                            "never clicks Submit again.", "priority": 5,
                                 "tags": ["robot", "warning"]})
                r = br("await_proof", wait_s=600)
            shot = self._shot(br, "after-submit")
            # 📌 RECORD THE STATE: nobody watches the console. What the page said is the record.
            state = r.get("status") or "unknown"
            said = (r.get("excerpt") or "")[:400]
            self._step(step, "ok" if state == "proof" else "error",
                       f"after submit: {state} | {r.get('url') or ''} | the page: {said}", shot)
            if state == "proof":
                self.relay.submitted(self.run_id, url=r.get("url"), excerpt=r.get("excerpt"))
                return self._done(app_id, "submitted", f"confirmed on the page: {said[:200]}")

            # No proof on the page: the employer's confirmation email is the other proof. Watch for
            # it, so the outcome is established by the run and not by a person's memory.
            step = "confirm"
            mail = None
            for _ in range(int(CONFIRM_WAIT_S / CONFIRM_POLL_S)):
                mail = self.relay.confirmation(self.run_id)
                if mail:
                    break
                self.sleep(CONFIRM_POLL_S)
            if mail:
                self._step(step, "ok", f"confirmed by mail: message {mail['message_id']} "
                                       f"'{mail['subject']}' at {mail['received_at']}")
                self.relay.submitted(self.run_id, url=f"mail:{mail['message_id']}",
                                     excerpt=f"confirmation email: {mail['subject']}")
                return self._done(app_id, "submitted", f"confirmed by email: {mail['subject']}")
            self._step(step, "error", f"no confirmation email within {CONFIRM_WAIT_S} s")
            if ats == "ashby" and self.spam_seen and (r.get("spam_page") or state == "spam_refused"):
                return self._spam_close(app_id, said)
            self.relay.close(self.run_id, outcome="unknown", stop_step="submit",
                             stop_reason=f"{state}: no thank-you page and no confirmation email within "
                                         f"{CONFIRM_WAIT_S} s. The page said: {said[:300]}")
            return self._done(app_id, "unknown", f"{state}; no page proof, no confirmation email. "
                              f"The page said: {said[:200]}. NOT retried.")
        except Stop as e:
            self._safe_step(step, "stop", str(e), br)
            self.relay.close(self.run_id, outcome="stopped", stop_step=step, stop_reason=str(e))
            return self._done(app_id, "stopped", f"{step}: {e}")
        except Exception as e:                                        # noqa: BLE001
            self._safe_step(step, "error", repr(e), br)
            # 🚨 After arming, the click may have happened. 'unknown' is never retried; 'error' is.
            outcome = "unknown" if armed else "error"
            try:
                self.relay.close(self.run_id, outcome=outcome, stop_step=step, stop_reason=repr(e)[:2000])
            except Exception as e2:                                   # noqa: BLE001
                print(f"could not close run {self.run_id}: {e2}", file=sys.stderr)
            return self._done(app_id, outcome, f"{step}: {e!r}")
        finally:
            if br is not None:
                # 📌 Keep the filled form on the virtual screen for a person to inspect in the
                # viewer. The run is already recorded and closed, and the page still cannot submit.
                # A hand-off already held the form for the person, so it is not held twice.
                hold = 0 if self.handed_off else _hold_seconds()
                if hold:
                    time.sleep(hold)
                br.quit()

    def _code(self, br, r: dict, step: str) -> dict:
        """The emailed security code (authorized explicitly by the operator, 2026-10-08, and for
        Ashby the same day): the relay releases this run's ONE code; it is never written to a
        step or an alert."""
        shot = self._shot(br, "code-step")
        self._step(step, "ok", "the board asked for its emailed security code. The page: "
                   f"{(r.get('excerpt') or '')[-400:]}", shot)
        # Wait; if no code came, ask the board to resend it (a board may send none for a second
        # attempt at one application, and a code sent before this run armed is never accepted),
        # then wait again. At most CODE_RESENDS times.
        got = None
        for attempt in range(CODE_RESENDS + 1):
            for _ in range(int(CODE_WAIT_S / CODE_POLL_S)):
                got = self.relay.code(self.run_id)
                if got:
                    break
                self.sleep(CODE_POLL_S)
            if got or attempt == CODE_RESENDS:
                break
            try:
                br("resend_code")
                self._step(step, "ok", f"no code after {CODE_WAIT_S} s; asked the board to "
                                       f"resend it ({attempt + 1}/{CODE_RESENDS})")
            except RuntimeError as e:
                self._step(step, "ok", f"no code after {CODE_WAIT_S} s, and no resend: {e}")
                break
        if not got:
            return {"status": "no_code"}
        self._step(step, "ok", f"entering the code from message {got['message_id']}")
        return br("enter_code", code=got["code"], wait_s=60)

    def _handoff(self, br, app_id: int, item: dict, nonce: str, step: str) -> dict:
        """Hand the filled, verified form to a person for ONE Submit click, and watch.

        Returns the page state for the shared tail (proof, code_step, no_proof...), or
        {"status": "not_clicked", "done": ...} when no click came and the page proves nothing
        was attempted: then the relay keeps the approval for the next batch."""
        hold = _handoff_seconds()
        br("handoff", nonce=nonce, hold_s=hold, clicks=HANDOFF_CLICKS)
        self.handed_off = True
        shot = self._shot(br, "handed-off")
        self._step(step, "ok", "filled, verified against the approved record, and handed to a "
                               f"person for the Submit click; holding {hold} s", shot)
        if self.notify and not self.batch:
            self.notify(ready_alert([item]))
        r = br("await_proof", wait_s=hold)
        for _ in range(HANDOFF_ROUNDS):
            st = r.get("status")
            if st == "spam_refused":
                self.spam_seen = True
                shot = self._shot(br, "spam-refused")
                self._step(step, "error", "Ashby refused the click as possible spam; NOTHING was sent. "
                           "The form stays held for the person. The page: "
                           f"{(r.get('excerpt') or '')[:300]}", shot)
                if self.notify:
                    self.notify({"title": f"Submitter: APP {app_id}: Ashby refused that click"[:200],
                                 "message": "Ashby flagged the click as possible spam; nothing was sent. "
                                            "You may click Submit Application once more in the viewer. "
                                            "The runner never clicks.",
                                 "priority": 5, "tags": ["robot", "warning"],
                                 **({"click": VIEWER_URL()} if VIEWER_URL() else {})})
            elif st == "human_step":
                shot = self._shot(br, "human-step")
                self._step(step, "ok", "a CAPTCHA appeared after the click; waiting for the person", shot)
                if self.notify:
                    self.notify({"title": f"Submitter: APP {app_id} needs you (CAPTCHA)"[:200],
                                 "message": "Solve it in the viewer. The runner never clicks.",
                                 "priority": 5, "tags": ["robot", "warning"],
                                 **({"click": VIEWER_URL()} if VIEWER_URL() else {})})
            else:
                break
            r = br("await_proof", wait_s=HANDOFF_AGAIN_S)
        if r.get("status") == "no_proof":
            c = br("readback").get("blocked_submits") or {}
            if not any(c.get(k) for k in ("human_clicks", "sanctioned", "submit_events",
                                          "submit_requests", "post_navigations", "submit_calls")):
                shot = self._shot(br, "not-clicked")
                self._step(step, "ok", f"no click within {hold} s; nothing was sent", shot)
                out = self.relay.close(self.run_id, outcome="not_clicked", stop_step=step,
                                       stop_reason=f"no click within {hold} s; nothing was sent",
                                       counters=c) or {}
                kept = bool(out.get("released"))
                try:
                    br("status", title="Not sent",
                       text="No click came in time. Nothing was sent. "
                            + ("Your approval is kept for the next batch." if kept else
                               "The approval was NOT kept; approve the record again."))
                except Exception:                                    # noqa: BLE001
                    pass
                return {"status": "not_clicked",
                        "done": self._done(app_id, "not_clicked",
                                           "no click; nothing sent; approval "
                                           + ("kept for the next batch" if kept else "NOT kept"))}
        return r

    def _spam_close(self, app_id: int, said: str) -> dict:
        """Ashby refused the click as possible spam and its refusal is still the last thing on the
        page: no proof, no confirmation email. Ashby's own page says nothing was sent, so the run
        closes 'spam_refused' and not 'unknown'. The relay applies the operator's rule (2026-10-08):
        the first refusal waits SUBMIT_SPAM_WAIT_S and keeps the approval; the second sets the
        application aside for manual entry."""
        out = self.relay.close(self.run_id, outcome="spam_refused", stop_step="submit",
                               stop_reason=f"Ashby refused the click as possible spam; nothing was "
                                           f"sent. The page said: {said[:300]}") or {}
        if out.get("manual"):
            why = (f"Ashby refused it as possible spam {out.get('refusals')} times; set aside for "
                   "manual entry. Submit it by hand with the paste-ready sheet.")
        elif out.get("released"):
            at = datetime.fromtimestamp(int(out["retry_at"]), timezone.utc).strftime("%H:%M UTC")
            why = f"Ashby refused it as possible spam; nothing was sent. The approval is kept; retry after {at}."
        else:
            why = "Ashby refused it as possible spam; nothing was sent. The approval was NOT kept (expired?)."
        return self._done(app_id, "spam_refused", why)

    def _safe_step(self, name, outcome, detail, br):
        shot = None
        try:
            if br is not None:
                shot = self._shot(br, f"{name}-{outcome}")
        except Exception:                                             # noqa: BLE001
            shot = None
        try:
            self._step(name, outcome, detail, shot)
        except Exception as e:                                        # noqa: BLE001
            print(f"could not record the {name} step: {e}", file=sys.stderr)

    def _done(self, app_id, outcome, why) -> dict:
        if self.notify:
            self.notify({"title": f"Submitter ({getattr(self, 'mode', 'shadow')}): APP {app_id} {outcome}"[:200],
                         "message": (why or "filled to review, not submitted")[:400],
                         "priority": 5 if outcome == "unknown" else
                                     3 if outcome in ("shadow_complete", "submitted") else 4,
                         "tags": ["robot"]})
        return {"application_id": app_id, "run_id": self.run_id, "outcome": outcome, "why": why}


# ── the command line ──────────────────────────────────────────────────────────────────────
def _hold_seconds() -> int:
    """SUBMIT_HOLD_SECONDS, capped at 600 so a held window cannot outlive the unit's timeout."""
    try:
        return max(0, min(600, int(os.environ.get("SUBMIT_HOLD_SECONDS", "0") or 0)))
    except ValueError:
        return 0


def killed() -> str | None:
    if os.environ.get("SUBMIT_DISABLED", "").strip() not in ("", "0"):
        return "SUBMIT_DISABLED is set"
    kf = os.environ.get("SUBMIT_KILL_FILE", "/etc/jobsubmit/disabled")
    return f"{kf} exists" if kf and os.path.exists(kf) else None


def cmd_once(a) -> int:
    why = killed()
    if why:
        print(f"kill switch: {why}; no run")
        return 0
    repo = Path(os.environ.get("SUBMIT_REPO_DIR", "")).expanduser()
    if not (repo / "config" / "candidate.toml").exists():
        raise SystemExit("SUBMIT_REPO_DIR must be the checkout holding config/candidate.toml")
    os.environ.setdefault("CANDIDATE_CONFIG", str(repo / "config" / "candidate.toml"))
    import candidate as C
    cfg = C.load()
    evidence = Path(os.environ.get("SUBMIT_EVIDENCE_DIR", "~/evidence")).expanduser()
    evidence.mkdir(parents=True, exist_ok=True)
    lock = open(evidence / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)            # one run at a time
    except BlockingIOError:
        print("another run holds the lock; no run")
        return 0
    relay = Relay(os.environ.get("SUBMIT_RELAY_URL", ""), os.environ.get("SUBMIT_TOKEN", ""))
    headed = os.environ.get("SUBMIT_HEADED", "1" if os.environ.get("DISPLAY") else "0") == "1"
    node = os.environ.get("SUBMIT_NODE", "node")
    notify = None
    if os.environ.get("NTFY_URL"):
        import notify as N
        notify = lambda payload: N.send(os.environ["NTFY_URL"], os.environ.get("NTFY_TOKEN", ""), payload)  # noqa: E731
    m = re.search(r'__version__\s*=\s*"([^"]+)"', (HERE / "__init__.py").read_text())
    version = m.group(1) if m else ""
    if getattr(a, "batch", None):
        return run_batch(relay, a.batch, lambda: Browser(node), cfg, repo, evidence, headed,
                         version, notify)
    item = relay.next(a.app, "live" if a.live else "shadow")
    if not item:
        print("nothing eligible")
        return 0
    r = Run(relay, lambda: Browser(node), cfg, repo, evidence, headed,
            version=version, notify=notify).go(item)
    print(json.dumps(r))
    return 0 if r["outcome"] in ("shadow_complete", "submitted") else 3


def run_batch(relay, ats: str, browser_factory, cfg, repo, evidence, headed, version, notify,
              sleep=time.sleep) -> int:
    """Every approved live item for one board, one after another, with ONE alert up front.

    ⭐ WHY (2026-10-08). An Ashby form needs the operator's click. One alert and one viewer session
    for several forms costs him seconds per application instead of a session each. The batch ends
    at the first form nobody clicked: he has left, and the forms after it stay approved and
    untouched (never armed)."""
    if ats != "ashby":
        raise SystemExit("a batch is for a board that needs a person's click: --batch ashby")
    items = relay.next_all(ats)
    if not items:
        print("nothing approved for a batch")
        return 0
    if notify:
        notify(ready_alert(items))
    results = []
    for item in items:
        if killed():
            print("kill switch: stopping the batch")
            break
        r = Run(relay, browser_factory, cfg, repo, evidence, headed, version=version,
                notify=notify, sleep=sleep, batch=True).go(item)
        results.append(r)
        print(json.dumps(r))
        if r["outcome"] == "not_clicked":
            break
    return 0 if all(r["outcome"] == "submitted" for r in results) else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m job_search_engine.submit",
                                 description="The browser submitter, shadow mode.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("once", help="take one eligible draft and run it to the review screenshot")
    o.add_argument("--app", type=int, help="this application only (it must still be eligible)")
    o.add_argument("--live", action="store_true",
                   help="a LIVE run: only a draft whose exact record a person approved by passkey; "
                        "it fills, proves the page holds that record, and clicks Submit once")
    o.add_argument("--batch", choices=["ashby"],
                   help="every approved live application on this board, in turn; each form is "
                        "handed to the operator for his own Submit click (one alert for all)")
    o.set_defaults(fn=cmd_once)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())

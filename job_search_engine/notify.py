"""
notify — a phone alert for inbound mail that a person must see, sent as an ntfy message.

⭐ WHY THIS EXISTS, 2026-10-01. Mail reached the relay within seconds and was labelled on a
schedule, but nothing told a person it had arrived. A rejection on a row at INTERVIEW is held
for a human by design (job_track never closes one), and the hold had no prompt: the LeanTaaS
rejection sat on a live interview row for a day with nobody aware of it.

🚨 IT ALERTS ONLY. It cannot change a label, clear needs_human, move an application, or send
mail. A sender writes the subject and the sender name, so everything in the alert is
sender-controlled text, and an alert is a hint to go and read, never an instruction.

⚠️ THE BODY NEVER LEAVES THE BOX THROUGH THIS PATH. The alert carries the sender, the subject,
the label, and the message id. ntfy.sh caches a message for about 12 hours and relays it to
Android phones through Firebase, so whatever is put here is held by two third parties.

⚠️ NO DEPENDENCY. urllib only, so the suite runs from a clean clone with nothing installed,
the same constraint the rest of the engine keeps.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

# Labels that a person must see when they arrive, whatever application they belong to.
# ⚠️ Named as a positive list on purpose. A new classifier label is silent until somebody
# decides it deserves an alert, which is the right failure: a noisy alert gets ignored, and
# an ignored alert is worse than none.
ALERT_LABELS = {
    "interview_invite", "interview_followup", "interview_feedback", "scheduling",
    "assessment_invite", "assessment_result", "incomplete_application", "otp",
    "hired", "lead", "recruiter_outreach", "unknown",
}

# Labels that are time-boxed. A security code expires in minutes and an assessment
# invitation in days, so these ring at high priority.
URGENT_LABELS = {"otp", "interview_invite", "assessment_invite", "scheduling", "hired"}

# ⭐ ANY mail on a row in one of these statuses alerts, rejections included. This is the
# LeanTaaS case: job_track holds a rejection on an interview row for a human, so the human
# has to be told.
LIVE_STATUSES = {"interview", "offer"}


def decide(label: str | None, auth_warn: bool, app_status: str | None) -> str | None:
    """The reason to alert, or None. Pure, so the rule is testable without a network."""
    label = (label or "unknown").strip() or "unknown"
    if auth_warn:
        return "spoof_warning"
    if (app_status or "") in LIVE_STATUSES:
        return f"live_{app_status}"
    if label in ALERT_LABELS:
        return f"label_{label}"
    return None


def priority(label: str | None, reason: str) -> int:
    """ntfy priority: 5 max, 4 high, 3 default."""
    if reason.startswith("live_") or (label or "") in URGENT_LABELS:
        return 4
    return 3


def build(msg: dict, reason: str, company: str | None = None) -> dict:
    """The ntfy JSON publish body, minus the topic. msg needs id, from_name, from_addr,
    subject, classification, to_alias."""
    label = msg.get("classification") or "unknown"
    who = (msg.get("from_name") or "").strip()
    addr = (msg.get("from_addr") or "").strip()
    sender = f"{who} <{addr}>" if who and addr else (who or addr or "unknown sender")
    where = company or (msg.get("to_alias") or "").split("@")[0] or "unmatched"
    tags = ["email"]
    if reason == "spoof_warning":
        tags = ["warning", "email"]
    elif reason.startswith("live_"):
        tags = ["rotating_light", "email"]
    title = f"{where}: {label.replace('_', ' ')}"
    if reason == "spoof_warning":
        title = f"POSSIBLE SPOOF · {title}"
    elif reason.startswith("live_"):
        title = f"{reason[5:].upper()} ROW · {title}"
    body = (f"From: {sender}\n"
            f"Subject: {(msg.get('subject') or '(no subject)')[:200]}\n"
            f"msg {msg.get('id')} · to {msg.get('to_alias') or '?'}")
    return {"title": title[:200], "message": body, "priority": priority(label, reason),
            "tags": tags}


def split_url(url: str) -> tuple[str, str]:
    """NTFY_URL is the full topic URL, e.g. https://ntfy.sh/<secret-topic>. The JSON publish
    endpoint is the server root, with the topic in the body."""
    url = url.strip().rstrip("/")
    base, _, topic = url.rpartition("/")
    if not base.startswith(("http://", "https://")) or not topic:
        raise ValueError("NTFY_URL must look like https://<server>/<topic>")
    return base, topic


def send(url: str, token: str, payload: dict, timeout: float = 8.0) -> tuple[bool, str]:
    """POST one alert. Returns (ok, detail). Never raises."""
    try:
        base, topic = split_url(url)
        data = json.dumps({"topic": topic, **payload}).encode("utf-8")
        req = urllib.request.Request(base, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            # ⚠️ A 200 says ntfy accepted it, not that a phone showed it. The end-to-end
            # proof is a real email to a test alias and a real alert on the phone.
            body = r.read(400).decode("utf-8", "replace")
            ok = 200 <= r.status < 300
            # ntfy answers with the stored message, which carries an id. Keep it as evidence.
            try:
                detail = f"http {r.status} id={json.loads(body).get('id')}"
            except Exception:
                detail = f"http {r.status}"
            return ok, detail
    except urllib.error.HTTPError as e:
        return False, f"http {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:300]

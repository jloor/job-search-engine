#!/usr/bin/env python3
"""
approve.py — mint a single-use approval for one outgoing reply, then optionally send it.

This runs on THE OPERATOR'S machine, never in the container, and it is the only thing that
holds APPROVAL_SECRET. That separation is what makes the human gate real:

    READ_TOKEN     agents have it. Lets them read mail and the pipeline.
    ADMIN_TOKEN    reaches /send, but /send still demands an approval.
    APPROVAL_KEY   Ed25519 PRIVATE key. Only he has it. Signs one message.

The relay holds only the matching PUBLIC key, so it can verify an approval and cannot
create one. Neither an agent, nor a stolen admin token, nor someone who has compromised
the container can mint an approval; signing requires a key that is not there.

The approval is bound to a sha256 over (from_alias, to, subject, body). Change one
character of the draft after approving and the signature stops matching, which is the
behaviour you want: he approves a message, not a permission.

Usage
-----
  # show the draft, then approve and send it
  python3 approve.py --from acme@jobs.example.com \
                     --to "Dana Reed <dana@acme.com>" \
                     --subject "Re: Support Engineer" \
                     --body-file reply.txt \
                     --reply-to 42 \
                     --send

  # print the token only (paste into your own curl)
  python3 approve.py ... --print-token

Secrets come from the environment. Pull them from 1Password at call time rather than
exporting them into a long-lived shell:

  export APPROVAL_SECRET=$(op read "op://Private/relay/approval secret" --account my.1password.com)
  export RELAY_API_TOKEN=$(op read "op://Private/job-search relay/admin token" --account my.1password.com)
  export RELAY_URL=https://relay.example.net
"""
from __future__ import annotations

import argparse, base64, hashlib, json, os, secrets, sys, time, urllib.error, urllib.request

DEFAULT_TTL = 900


def fingerprint(from_alias: str, to: str, subject: str, body: str) -> str:
    """Must stay byte-identical to fingerprint() in app.py."""
    h = hashlib.sha256()
    for part in (from_alias, to, subject, body):
        h.update(hashlib.sha256(part.encode("utf-8")).digest())
    return h.hexdigest()


def mint(fp: str, key_hex: str, ttl: int) -> str:
    """Sign with the Ed25519 PRIVATE key. It never leaves this machine.

    The relay holds only the matching public key, so it can check this signature and
    cannot produce one. That is what makes the human gate survive a compromise of the
    container: an attacker there gets the mailbox, not the ability to send as him.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    nonce = secrets.token_urlsafe(12)
    expires = int(time.time()) + ttl
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    sig = sk.sign(f"{nonce}.{expires}.{fp}".encode())
    return f"{nonce}.{expires}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


SK_NAMESPACE = "job-search-send"     # must equal APPROVAL_SK_NAMESPACE in app.py
# ⭐ 240s, 2026-10-01: four minutes to read a full email before deciding, at his request.
# ⚠️ The YubiKey itself stops waiting for a touch after about 30 seconds, so a long window
# alone made a slow read fail. touch_sign re-arms the key while the window stays open.
TOUCH_WINDOW_S = 240
REARM_LIMIT = 40          # re-arms per window: a key that fails instantly must not spin forever


def touch_sign(key: str, message: bytes, header: list[str], body: str,
               namespace: str = SK_NAMESPACE) -> tuple[str | None, str]:
    """Show the exact email in a window, then ask the security key to sign. (armored, why).

    ⭐ THE WINDOW IS THE GATE, NOT THE TOUCH. A touch proves someone was there, not what they
    read. So the window opens FIRST, the key is only asked to sign a moment later, and closing
    the window or letting it time out kills the request before anything is signed.

    🚨 WHAT IT SHOWS IS WHAT IS SIGNED. `header` and `body` are the same strings the
    fingerprint was computed from, and the relay re-computes the fingerprint from the bytes it
    sends. A window that showed different text would produce a signature the relay refuses.

    ⚠️ The agent that runs this can still call ssh-keygen directly, and then the key blinks
    with no window. The rule for the human is simple: no window, no touch.
    """
    import subprocess, threading
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk

    st = {"sig": None, "why": "cancelled: window closed", "proc": None, "over": False,
          "left": TOUCH_WINDOW_S, "arms": 0}

    def finish(why=None):
        if st["over"]:
            return False
        st["over"] = True
        if why:
            st["why"] = why
        p = st["proc"]
        if p and p.poll() is None:
            p.kill()
        Gtk.main_quit()
        return False

    win = Gtk.Window(title="Approve this email (job-search)")
    win.set_default_size(780, 640)
    win.set_keep_above(True)
    win.set_urgency_hint(True)
    win.connect("delete-event", lambda *a: finish("cancelled: window closed") or False)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    for side in ("top", "bottom", "start", "end"):
        getattr(box, f"set_margin_{side}")(16)
    win.add(box)

    head = Gtk.Label(xalign=0)
    head.set_selectable(True)
    head.set_markup("\n".join(f"<b>{GLib.markup_escape_text(h.split(':', 1)[0])}:</b>"
                              f"{GLib.markup_escape_text(h.split(':', 1)[1])}" for h in header))
    box.pack_start(head, False, False, 0)

    view = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD)
    view.get_buffer().set_text(body)
    scroll = Gtk.ScrolledWindow(vexpand=True)
    scroll.add(view)
    box.pack_start(scroll, True, True, 0)

    status = Gtk.Label(xalign=0)
    box.pack_start(status, False, False, 0)
    cancel = Gtk.Button(label="Cancel, do not send")
    cancel.connect("clicked", lambda *a: finish("cancelled: button"))
    box.pack_start(cancel, False, False, 0)

    def tick():
        if st["over"]:
            return False
        st["left"] -= 1
        m, s = divmod(st["left"], 60)
        status.set_markup(f"<big><b>Read it. Then touch your YubiKey to send this exact email.</b></big>\n"
                          f"Touch any time while this window is open. Close it to cancel. "
                          f"{m}:{s:02d} left.")
        if st["left"] <= 0:
            return finish("cancelled: no touch within the time limit")
        return True

    def start():
        if st["over"]:
            return False
        st["arms"] += 1
        # ⚠️ SSH_ASKPASS_REQUIRE=never: there is no askpass here, and a PIN prompt it cannot
        # show would be sent EMPTY and burn a PIN attempt. A key that wants a PIN fails instead.
        env = {**os.environ, "SSH_ASKPASS_REQUIRE": "never"}
        p = subprocess.Popen(["ssh-keygen", "-Y", "sign", "-f", key, "-n", namespace],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
        st["proc"] = p

        def run():
            out, err = p.communicate(message)
            def done():
                if st["over"]:
                    return False
                if p.returncode == 0 and out.startswith(b"-----BEGIN SSH SIGNATURE-----"):
                    st["sig"] = out.decode()
                    return finish("signed")
                # The key timed out waiting for a touch (about 30s) while he was still
                # reading. Ask it again, unless the window is nearly done or the key keeps
                # failing at once, which means something other than a timeout is wrong.
                if st["left"] > 3 and st["arms"] < REARM_LIMIT:
                    GLib.timeout_add(500, start)
                    return False
                lines = [l for l in err.decode(errors="replace").splitlines()
                         if l.strip() and "Signing data on standard input" not in l]
                return finish("refused by the key: " + (" | ".join(lines)[-300:] or
                                                        f"exit {p.returncode}"))
            GLib.idle_add(done)
        threading.Thread(target=run, daemon=True).start()
        return False

    tick()
    win.show_all()
    win.present()
    GLib.timeout_add(1000, tick)
    GLib.timeout_add(1200, start)      # the window is on screen before the key ever blinks
    Gtk.main()
    win.destroy()
    while Gtk.events_pending():
        Gtk.main_iteration()
    return st["sig"], st["why"]


def mint_sk(fp: str, key: str, ttl: int, header: list[str], body: str) -> str | None:
    """`sk1.<nonce>.<expires>.<base64url SSHSIG>`, or None when nothing was signed."""
    import sshsig
    nonce = secrets.token_urlsafe(12)
    expires = int(time.time()) + ttl
    msg = f"{nonce}.{expires}.{fp}".encode()
    armored, why = touch_sign(key, msg, header, body)
    if not armored:
        print(f"nothing approved: {why}", file=sys.stderr)
        return None
    blob = sshsig.unarmor(armored)
    # Check it here first, against the key's own public half. A refusal now names the reason;
    # the relay deliberately answers every failure with the same words.
    try:
        allowed = [sshsig.parse_pubkey_line(open(key + ".pub").read())]
        sshsig.verify(blob, msg, SK_NAMESPACE, allowed)
    except Exception as e:
        print(f"the signature does not verify locally: {e}", file=sys.stderr)
        return None
    return f"sk1.{nonce}.{expires}.{base64.urlsafe_b64encode(blob).decode().rstrip('=')}"


def passkey_activate_main(argv: list[str]) -> int:
    """`approve.py passkey-activate --sk-key KEY [--credential-id ID]`

    Turn a PENDING passkey ACTIVE on the relay. The window shows the credential's label and
    code; the YubiKey signs only after the window is up, in the ENROLLMENT namespace, so this
    signature can never be replayed as a send approval (or the other way round).

    ⭐ COMPARE THE CODE. The phone showed one when it registered. If this window shows a
    different code, or a credential you did not just register, close it: something else
    registered that credential.
    """
    import passkey, sshsig
    ap = argparse.ArgumentParser(prog="approve.py passkey-activate")
    ap.add_argument("--sk-key", required=True, help="the YubiKey-SSH handle, as for sends")
    ap.add_argument("--credential-id", default=None, help="needed only if several are pending")
    a = ap.parse_args(argv)
    url = os.environ.get("RELAY_URL", "").rstrip("/")
    api = os.environ.get("RELAY_API_TOKEN", "")
    if not url or not api:
        print("RELAY_URL and RELAY_API_TOKEN must be set", file=sys.stderr)
        return 2

    def call(path, payload=None):
        req = urllib.request.Request(url + path, method="POST" if payload is not None else "GET",
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers={"Authorization": f"Bearer {api}",
                                              "Content-Type": "application/json",
                                              "User-Agent": "approve.py"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    pending = [c for c in call("/passkey/credentials")["credentials"] if c["status"] == "pending"]
    if a.credential_id:
        pending = [c for c in pending if c["credential_id"] == a.credential_id]
    if len(pending) != 1:
        print(f"{len(pending)} pending credential(s) match; name one with --credential-id:", file=sys.stderr)
        for c in pending:
            print(f"  {c['credential_id']}  code {c['code']}  {c['label'] or '-'}  {c['created_at']}",
                  file=sys.stderr)
        return 1
    c = pending[0]
    msg = passkey.enroll_message(c["credential_id"], passkey.unb64u(c["public_key"]))
    header = ["ACTIVATE A PASSKEY FOR MAIL APPROVAL", f"Code: {c['code']}",
              f"Name: {c['label'] or '-'}", f"Registered: {c['created_at']}"]
    body = ("Touch the key ONLY if this code matches the code your phone showed.\n\n"
            "Once active, this credential can approve sending mail as you, from any browser "
            "that holds it.")
    print(f"waiting for approval in the window: code {c['code']}", file=sys.stderr)
    armored, why = touch_sign(a.sk_key, msg, header, body, namespace=passkey.ENROLL_NAMESPACE)
    if not armored:
        print(f"nothing activated: {why}", file=sys.stderr)
        return 1
    blob = sshsig.unarmor(armored)
    try:
        sshsig.verify(blob, msg, passkey.ENROLL_NAMESPACE,
                      [sshsig.parse_pubkey_line(open(a.sk_key + ".pub").read())])
    except Exception as e:
        print(f"the signature does not verify locally: {e}", file=sys.stderr)
        return 1
    try:
        out = call("/passkey/activate", {"credential_id": c["credential_id"],
                                         "signature": passkey.b64u(blob)})
    except urllib.error.HTTPError as e:
        print(f"relay refused: HTTP {e.code} {e.read().decode(errors='replace')[:200]}", file=sys.stderr)
        return 1
    print(f"ACTIVE: {out['credential_id'][:16]}… code {out['code']}")
    return 0


def main() -> int:
    if sys.argv[1:2] == ["passkey-activate"]:
        return passkey_activate_main(sys.argv[2:])
    ap = argparse.ArgumentParser(description="Approve one outgoing relay message.")
    ap.add_argument("--from", dest="from_alias", required=True)
    ap.add_argument("--to", required=True)
    ap.add_argument("--subject", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--body-file")
    src.add_argument("--body")
    ap.add_argument("--reply-to", type=int, default=None, help="message id being replied to")
    ap.add_argument("--intent", default=None)
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    ap.add_argument("--send", action="store_true", help="POST to the relay after confirming")
    ap.add_argument("--print-token", action="store_true", help="print the token and exit")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--sk-key", default=None,
                    help="security-key handle (~/.ssh/id_ed25519_sk_...). Approve with a touch, "
                         "shown in a window; APPROVAL_KEY is not used")
    a = ap.parse_args()

    if a.sk_key:
        if a.yes:
            # The window is the gate. There is nothing to skip.
            print("--yes does not apply to a security-key approval", file=sys.stderr)
            return 2
        body = open(a.body_file, encoding="utf-8").read() if a.body_file else a.body
        fp = fingerprint(a.from_alias, a.to, a.subject, body)
        header = [f"From: {a.from_alias}", f"To: {a.to}", f"Subject: {a.subject}"]
        if a.reply_to:
            header.append(f"In reply to: message {a.reply_to}")
        print(f"waiting for approval in the window: fingerprint {fp[:16]}…, {TOUCH_WINDOW_S}s",
              file=sys.stderr)
        token = mint_sk(fp, a.sk_key, a.ttl, header, body)
        if not token:
            return 1
        return _deliver(a, body, token)

    secret = os.environ.get("APPROVAL_KEY", "")
    if not secret:
        print("APPROVAL_KEY is not set (Ed25519 private key, hex). Nothing can be approved\n"
              "without it. Pull it from 1Password:\n"
              '  export APPROVAL_KEY=$(op read "op://Private/job-search relay approval key/private key" '
              "--account my.1password.com)", file=sys.stderr)
        return 2

    body = open(a.body_file, encoding="utf-8").read() if a.body_file else a.body
    fp = fingerprint(a.from_alias, a.to, a.subject, body)

    if not a.print_token and not a.yes:
        # Read it before you sign it. This is the human gate, not the flag below it.
        print("=" * 72)
        print(f"From:    {a.from_alias}")
        print(f"To:      {a.to}")
        print(f"Subject: {a.subject}")
        if a.reply_to:
            print(f"In reply to message id: {a.reply_to}")
        print("-" * 72)
        print(body)
        print("=" * 72)
        print(f"fingerprint {fp[:16]}…   approval valid {a.ttl}s   ONE use")
        if input("Send this exact message? type 'send' to confirm: ").strip() != "send":
            print("aborted, nothing approved")
            return 1

    token = mint(fp, secret, a.ttl)
    return _deliver(a, body, token)


def _deliver(a, body: str, token: str) -> int:
    """Print the token, or POST the approved message to the relay."""
    if a.print_token or not a.send:
        print(token)
        return 0

    url = os.environ.get("RELAY_URL", "").rstrip("/")
    api = os.environ.get("RELAY_API_TOKEN", "")
    if not url or not api:
        print("RELAY_URL and RELAY_API_TOKEN must be set to use --send", file=sys.stderr)
        return 2

    payload = {"from_alias": a.from_alias, "to": a.to, "subject": a.subject,
               "body": body, "approved": True, "approved_by": os.environ.get("USER", "operator")}
    if a.reply_to:
        payload["in_reply_to_id"] = a.reply_to
    if a.intent:
        payload["intent"] = a.intent

    req = urllib.request.Request(
        f"{url}/send", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api}",
                 "X-Approval": token},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            print(json.dumps(json.loads(r.read()), indent=2))
        return 0
    except urllib.error.HTTPError as e:
        print(f"relay refused: HTTP {e.code}\n{e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"relay unreachable: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

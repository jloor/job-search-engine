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


def main() -> int:
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
    a = ap.parse_args()

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

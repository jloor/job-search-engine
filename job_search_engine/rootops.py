"""Root operations a person approves by passkey, carried by the relay to a root broker on the host.

⭐ THE PROPERTY: the relay carries a root request and the passkey assertion over it, and decides
NOTHING. The root broker on the host verifies the assertion itself, against a public key in a
root-owned file, and recomputes the hash below from the operation it is about to run. Whoever can
change the relay (the harness can) can therefore delay or drop a request, but cannot approve one.

🚨 THIS FILE IS NOT THE AUTHORITY. The broker keeps its own copy of the list and of the canonical
form, in root-owned code, because the relay's copy is code the harness can change. This copy only
stops a typo early and shows the operator what he is approving. The two copies agree on one test
vector (CANONICAL_VECTOR), which both test suites check.

The canonical form is JSON with sorted keys and no spaces. It carries a domain string, so a
signature over a mail or a submit record can never be read as a signature over a root operation,
the host name, so an approval for one machine cannot run on another, and an expiry in Unix seconds.
"""
import hashlib
import json
import re

DOMAIN = "job-search-root-op.v1"
TTL_S = 900                     # a request the operator does not approve in 15 minutes expires
MAX_TTL_S = 3600                # the broker refuses an expiry further out than this

_TAG = r"v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
# 🚨 ONLY THE DIRECTIONS THAT INSTALL OR STOP (the operator's decision, 2026-10-08). The passkey
# signs an opaque challenge, and the page that shows it is relay code the agent can change, so a
# tap must never lift a brake or grant a right. At worst it installs an engine tag. Turning the
# timer ON, the kill switch OFF, or a sudo level ON stays with the admin login. The argument
# names stay, so the canonical form does not change; only the allowed values narrow.
OPS = {
    "submitter-install": {"tag": _TAG},
    "submitter-timer":   {"state": r"off"},
    "submitter-kill":    {"state": r"on"},
    "sudoers-level":     {"level": r"INSTALL|RELEASE|LIVE", "state": r"off"},
}
_HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def validate(op: str, args: dict, host: str) -> None:
    """Raise ValueError unless op is on the list and args match its patterns EXACTLY."""
    spec = OPS.get(op)
    if spec is None:
        raise ValueError(f"not a root operation: {op!r}")
    if not isinstance(args, dict) or set(args) != set(spec):
        raise ValueError(f"{op} takes exactly {sorted(spec)}")
    for k, pat in spec.items():
        if not (isinstance(args[k], str) and re.fullmatch(pat, args[k])):
            raise ValueError(f"{op}: bad {k}")
    if not (isinstance(host, str) and _HOST.fullmatch(host)):
        raise ValueError("bad host")


def canonical(op: str, args: dict, host: str, expires: int) -> bytes:
    return json.dumps({"d": DOMAIN, "op": op, "args": args, "host": host, "exp": int(expires)},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def op_hash(op: str, args: dict, host: str, expires: int) -> str:
    return hashlib.sha256(canonical(op, args, host, expires)).hexdigest()


def describe(op: str, args: dict) -> str:
    """Plain words for the approval page and the alert."""
    if op == "submitter-install":
        return f"Install engine {args['tag']} into the submitter (pip, npm, Playwright, as the submitter user)"
    if op == "submitter-timer":
        return "Turn the submitter's 15-minute timer OFF"
    if op == "submitter-kill":
        return "Turn the submitter kill switch ON (stops all runs)"
    if op == "sudoers-level":
        return f"Revoke the harness sudo level JOBSUBMIT_{args['level']}"
    return op


# Both copies must produce this hash for these inputs. Change it only together with the broker.
CANONICAL_VECTOR = ({"op": "submitter-install", "args": {"tag": "v0.93.2"}, "host": "host01",
                     "expires": 1791000000},
                    "2f9de188c1627d959a818df7eb22bc23beffb06edf525e574a220c19de296a26")

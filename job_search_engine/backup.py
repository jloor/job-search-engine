"""
backup — encrypted snapshots of Bunny Database.

Bunny Database has no automatic backups, and since tools/render-tracker.py started
generating the markdown tracker FROM the database, the database is the only copy of the
pipeline. That is a single point of failure holding 38 applications and every recruiter
message.

## Why the encryption is asymmetric

The container holds only a PUBLIC key. It can seal a snapshot and cannot open one, so a
compromise of the container does not hand over the history of every backup ever taken.

That distinction matters because of where snapshots end up: pulled to a laptop, committed
to a private repo, replicated to GitHub, cloned again. Each hop is a copy of salary floors,
comp intelligence, recruiter phone numbers and mail bodies. A symmetric key sitting in the
container environment would protect none of that from anyone who read the environment.

X25519 for key agreement, HKDF-SHA256 to derive, AES-256-GCM to seal. An ephemeral keypair
per snapshot means two dumps of identical data share no key material.

## Format

    magic  b"JSBK1\\n"
    32     ephemeral X25519 public key
    12     nonce
    rest   AES-256-GCM ciphertext (tag appended)
"""
from __future__ import annotations

import json, os, time

MAGIC = b"JSBK1\n"


def _derive(shared: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"job-search backup v1").derive(shared)


def seal(plaintext: bytes, recipient_pub_hex: str) -> bytes:
    """Encrypt to the recipient's public key. Requires no secret, by design."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization as ser
    recipient = X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_pub_hex))
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    key = _derive(eph.exchange(recipient), eph_pub)
    nonce = os.urandom(12)
    return MAGIC + eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC)


def unseal(blob: bytes, recipient_priv_hex: str) -> bytes:
    """Decrypt. Only ever runs on the operator's machine."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC):
        raise ValueError("not a job-search backup (bad magic)")
    body = blob[len(MAGIC):]
    eph_pub, nonce, ct = body[:32], body[32:44], body[44:]
    sk = X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_priv_hex))
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    key = _derive(sk.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub)
    return AESGCM(key).decrypt(nonce, ct, MAGIC)


# 🚨 SKIPPED TOGETHER OR NOT AT ALL. board_state is 86% of the database and a sweep
# rebuilds it, so it does not belong in a backup. But dropping it while KEEPING
# board_seeded is the worst of both: on restore the seed guard does not fire (the board is
# seeded by its own reckoning) and the diff computes new = now_ids - {} = every requisition
# on every board. ~158,000 phantom discoveries, all of them handed to a paid model.
#
# Dropped as a pair, every board simply re-seeds silently on the next sweep, which is
# exactly what board_seeded exists to do.
#
# ⚠️ NOTHING ELSE BELONGS HERE, and the tempting additions are the dangerous ones.
# scan_change is the appeared/vanished audit trail: once a requisition vanishes no future
# sweep can prove it existed. scan_candidate holds descriptions that die with the posting
# (this has happened: a requisition was pulled mid-process and only the archived copy
# survived) and scores that cost money. Both are irreplaceable.
REGENERABLE = ("board_state", "board_seeded")

# Rows per read. The dump used to SELECT every row of every table in one response, which
# worked until the scanner's data outgrew Bunny's response limit and the backup began
# failing silently-ish at 13:50 on 2026-08-14. Paging is what stops that recurring for the
# tables that are KEPT, which still grow: scan_change tracks churn and message bodies are
# unbounded.
PAGE = int(os.environ.get("BACKUP_PAGE", "2000"))


def dump_sql(con) -> str:
    """
    Serialise the irreplaceable tables to SQL that restores into plain SQLite.

    Deliberately SQL rather than a proprietary export: libSQL is a SQLite fork, so this
    restores with `sqlite3 restored.db < dump.sql` on any machine, with no Bunny account
    and no network. A backup you can only restore through the vendor that lost your data
    is not a backup.

    📌 NO SILENT DEFAULT. Every table is either dumped or named in REGENERABLE, and the
    header records the disposition of each one. A table nobody classified is still dumped
    rather than skipped, because backing up something unnecessary costs bytes while
    skipping something irreplaceable costs the data.
    """
    tables = [r["name"] for r in _rows(con,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    kept = [t for t in tables if t not in REGENERABLE]
    out = ["-- job-search relay snapshot",
           f"-- taken {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
           "-- SKIPPED as regenerable (a sweep rebuilds them, and they restore as a pair): "
           + ", ".join(REGENERABLE),
           "PRAGMA foreign_keys=OFF;", "BEGIN TRANSACTION;"]
    counts = {}
    for t in kept:
        ddl = _rows(con, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,))
        if ddl and ddl[0]["sql"]:
            out.append(ddl[0]["sql"].strip() + ";")
        n, off = 0, 0
        while True:
            rows = _rows(con, f"SELECT * FROM {t} LIMIT {PAGE} OFFSET {off}")
            if not rows:
                break
            for r in rows:
                cols = ", ".join(r.keys())
                vals = ", ".join(_lit(v) for v in r.values())
                out.append(f"INSERT INTO {t} ({cols}) VALUES ({vals});")
            n += len(rows)
            off += PAGE
            if len(rows) < PAGE:
                break
        counts[t] = n
        out.append(f"-- {t}: {n} rows")
    for idx in _rows(con, "SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
        out.append(idx["sql"].strip() + ";")
    out.append("COMMIT;")
    out.insert(3, "-- kept: " + ", ".join(f"{t}={counts[t]}" for t in kept))
    return "\n".join(out) + "\n"


def _rows(con, q, params=()):
    cur = con.execute(q, params)
    return [dict(r) for r in cur.fetchall()]


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return "X'" + v.hex() + "'"
    return "'" + str(v).replace("'", "''") + "'"

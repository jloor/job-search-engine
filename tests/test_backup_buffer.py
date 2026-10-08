#!/usr/bin/env python3
"""The backup retry buffer (_backup_buffer in app.py).

⭐ WHY, 2026-10-08. The 5 GB volume filled: the buffer kept 14 snapshots of about 300 MB each.
A write that failed part way then left a truncated snapshot under its final name, and a later
run uploaded it. Storage received one file of 182 MB (of 301 MB) and two of 0 bytes. Every
run also uploaded every kept file again.

🚨 WHAT MUST NEVER HAPPEN:
  - a file under a final snapshot name that is not complete;
  - an empty or headerless file uploaded as a snapshot;
  - an unshipped snapshot deleted (it is the only copy);
  - a shipped snapshot uploaded again on every run.

Run:  python3 tests/test_backup_buffer.py
"""
import os
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "job_search_engine"))
sys.path.insert(0, str(HERE))
import backup as B                                            # noqa: E402

fails = []


def check(label, got, want=True):
    ok = bool(got) == bool(want)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)


os.environ["DB_PATH"] = tempfile.mkdtemp() + "/bb.db"
import test_parse                                             # noqa: E402  (strips BUNNY_*)
app = test_parse.load_app()

SNAP = B.MAGIC + b"\x01" * 32 + b"\x02" * 12 + b"\x03" * 64     # shaped like a sealed snapshot


class Store:
    def __init__(self, fail=()):
        self.got, self.fail = [], set(fail)

    def __call__(self, name, data):
        if name in self.fail:
            raise OSError("storage unreachable")
        self.got.append((name, len(data)))


def names(d):
    return sorted(p.name for p in d.iterdir())


print("a snapshot is written whole, uploaded once, and pruned only after upload:")
d = pathlib.Path(tempfile.mkdtemp())
st = Store()
shipped, failed, dropped = app._backup_buffer("relay-20261008T000001Z.sql.age", SNAP, put=st, keep=2, d=d)
check("it is uploaded", shipped == ["relay-20261008T000001Z.sql.age"] and not failed and not dropped)
check("…and marked shipped, with no .part left", names(d) == ["relay-20261008T000001Z.sql.age",
                                                              "relay-20261008T000001Z.sql.age.shipped"])
st = Store()
app._backup_buffer("relay-20261008T000002Z.sql.age", SNAP, put=st, keep=2, d=d)
check("🚨 the next run uploads only the new snapshot, never the shipped one again",
      st.got == [("relay-20261008T000002Z.sql.age", len(SNAP))])
app._backup_buffer("relay-20261008T000003Z.sql.age", SNAP, put=Store(), keep=2, d=d)
check("keep=2: the oldest shipped snapshot and its marker are pruned",
      [n for n in names(d) if n.endswith(".age")] == ["relay-20261008T000002Z.sql.age",
                                                      "relay-20261008T000003Z.sql.age"]
      and "relay-20261008T000001Z.sql.age.shipped" not in names(d))

print("\nan upload that fails keeps the only copy, and the next run retries it:")
d = pathlib.Path(tempfile.mkdtemp())
for i in range(1, 4):
    app._backup_buffer(f"relay-2026100{i}T000000Z.sql.age", SNAP, keep=1, d=d,
                       put=Store(fail={f"relay-2026100{k}T000000Z.sql.age" for k in range(1, 4)}))
check("🚨 three unshipped snapshots with keep=1: none is deleted",
      len([n for n in names(d) if n.endswith(".age")]) == 3)
st = Store()
shipped, failed, _ = app._backup_buffer("relay-20261004T000000Z.sql.age", SNAP, put=st, keep=1, d=d)
check("the next good run ships all four", len(shipped) == 4 and not failed)
check("…and then keeps only the newest", [n for n in names(d) if n.endswith(".age")] ==
      ["relay-20261004T000000Z.sql.age"])

print("\na bad file is never uploaded:")
d = pathlib.Path(tempfile.mkdtemp())
(d / "relay-20261008T134816Z.sql.age").write_bytes(b"")
(d / "relay-20261008T135011Z.sql.age").write_bytes(b"not a snapshot at all, but long enough to pass a size check")
(d / "relay-20261008T135500Z.sql.age.part").write_bytes(SNAP[:20])
st = Store()
shipped, _, dropped = app._backup_buffer("relay-20261008T140000Z.sql.age", SNAP, put=st, keep=5, d=d)
check("🚨 an empty file and a headerless file are dropped, not uploaded",
      len(dropped) == 2 and [n for n, _ in st.got] == ["relay-20261008T140000Z.sql.age"])
check("a stale .part from a write that died is removed", not list(d.glob("*.part")))

print("\na write that fails part way leaves nothing under the final name:")
d = pathlib.Path(tempfile.mkdtemp())
real = os.fsync


def no_space(fd):
    raise OSError(28, "No space left on device")


os.fsync = no_space
try:
    app._backup_buffer("relay-20261008T150000Z.sql.age", SNAP, put=Store(), keep=5, d=d)
    check("the failure is raised", False)
except OSError:
    check("the failure is raised (the job reports an error)", True)
finally:
    os.fsync = real
check("🚨 no file under the final name, and no .part left", names(d) == [])

# A process that DIES mid-write runs no cleanup. Imitate it: the write fails and unlink does nothing.
d = pathlib.Path(tempfile.mkdtemp())
real_unlink = pathlib.Path.unlink
os.fsync, pathlib.Path.unlink = no_space, lambda self, missing_ok=False: None
try:
    app._backup_buffer("relay-20261008T160000Z.sql.age", SNAP, put=Store(), keep=5, d=d)
except OSError:
    pass
finally:
    os.fsync, pathlib.Path.unlink = real, real_unlink
check("🚨 a process killed mid-write leaves only a .part, never a file under the final name",
      not (d / "relay-20261008T160000Z.sql.age").exists())
st = Store()
app._backup_buffer("relay-20261008T170000Z.sql.age", SNAP, put=st, keep=5, d=d)
check("…and the next run removes the .part and uploads only the complete snapshot",
      not list(d.glob("*.part")) and [n for n, _ in st.got] == ["relay-20261008T170000Z.sql.age"])

print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'all passed'}")
sys.exit(1 if fails else 0)

"""
gitsync — keep the /data volume as a working copy of the private repo.

The volume is a CACHE, never the source of truth. Git is authoritative, for one concrete
reason: `git diff` is the only thing that shows a comp range that moved after a posting
went up, which is why 24 job descriptions are archived verbatim in the first place. A
volume holds the current bytes and cannot say what they used to be.

That also makes the volume's awkward properties harmless. Bunny volumes are per-instance,
a new pod gets a blank one, and there are no backups. A blank volume is simply a cache
miss: clone and carry on.

Rules, each of which exists because breaking it is expensive:

  ONE INSTANCE ONLY.  Volumes are per-instance, so two pods are two working copies
                      pushing to one repo. rollout.py refuses to attach a volume while
                      the app runs more than one.
  PULL BEFORE PUSH.   His laptop writes to this repo too. Diverging is how you get
                      conflicts in files that matter.
  FENCED WRITES.      This process writes only under applications/ and platform/state/.
                      Never vault/: the Career Inventory, Answer Bank, Contacts and
                      trackers are hand-edited, and two writers on one file is misery.
  NO SIGNING.         The container has no access to his 1Password SSH signer, and the
                      global config turns signing on. Left alone, every commit fails with
                      "failed to write commit object".
"""
from __future__ import annotations

import base64, os, pathlib, subprocess, sys, time

DATA = pathlib.Path(os.environ.get("DATA_DIR", "/data"))
REPO_DIR = DATA / "repo"
REPO_SSH = os.environ.get("GIT_REPO_SSH", "")
KEY_B64 = os.environ.get("GIT_DEPLOY_KEY_B64", "")
KEY_PATH = pathlib.Path("/tmp/deploy_key")
WRITE_PATHS = ("applications", "platform/state")


def _ssh_env() -> dict:
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = (f"ssh -i {KEY_PATH} -o IdentitiesOnly=yes "
                              "-o StrictHostKeyChecking=accept-new -o BatchMode=yes")
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run(args: list[str], cwd: pathlib.Path | None = None, check: bool = True):
    p = subprocess.run(args, cwd=cwd, env=_ssh_env(), capture_output=True, text=True, timeout=180)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p


def install_key() -> None:
    if not KEY_B64:
        raise RuntimeError("GIT_DEPLOY_KEY_B64 is not set")
    KEY_PATH.write_bytes(base64.b64decode(KEY_B64))
    KEY_PATH.chmod(0o600)


def ensure_repo() -> pathlib.Path:
    """Clone if the volume is blank, otherwise fetch and hard-reset onto origin/main.

    Hard reset rather than merge on purpose: this working copy holds nothing that is not
    either pushed already or freshly generated. Preserving a divergent local state here
    would only produce conflicts nobody is present to resolve.
    """
    install_key()
    DATA.mkdir(parents=True, exist_ok=True)
    if not (REPO_DIR / ".git").is_dir():
        print(f"gitsync: {REPO_DIR} is blank, cloning", flush=True)
        _run(["git", "clone", "--quiet", REPO_SSH, str(REPO_DIR)])
    # The committer identity is the OPERATOR's, not a name baked into the engine.
    _run(["git", "config", "user.email",
          os.environ.get("GIT_AUTHOR_EMAIL", "relay@localhost")], REPO_DIR)
    _run(["git", "config", "user.name", "job-search relay"], REPO_DIR)
    _run(["git", "config", "commit.gpgsign", "false"], REPO_DIR)   # no signer in here
    _run(["git", "fetch", "--quiet", "origin", "main"], REPO_DIR)
    _run(["git", "reset", "--hard", "--quiet", "origin/main"], REPO_DIR)
    return REPO_DIR


def commit_and_push(message: str) -> str:
    """
    Commit whatever changed under the fenced paths and push. Returns a status string.

    🚨 **The deployed key is READ-ONLY as of 2026-08-12, so this will fail.** That is
    deliberate. Nothing in the service called this function, and carrying write access for
    weeks against a hypothetical future writer is the definition of over-privilege. GitHub's
    own warning on the deploy keys page is the reason: the key has no passphrase and lives
    unencrypted in the container environment.

    When a real writer arrives (the Phase 1 scanner archiving job descriptions), issue a
    write key then, deliberately, and swap GIT_DEPLOY_KEY_B64. The push will refuse with
    "The key you are authenticating with has been marked as read only" until you do, which
    is a clear message rather than a mystery.
    """
    if not (REPO_DIR / ".git").is_dir():
        return "no working copy"
    _run(["git", "fetch", "--quiet", "origin", "main"], REPO_DIR)

    # Refuse to carry changes outside the fence. If they exist, something wrote where it
    # should not have, and quietly committing it is how the vault gets clobbered.
    dirty = _run(["git", "status", "--porcelain"], REPO_DIR).stdout.splitlines()
    stray = [l[3:] for l in dirty if not l[3:].startswith(WRITE_PATHS)]
    if stray:
        _run(["git", "checkout", "--", "."], REPO_DIR, check=False)
        return f"refused: changes outside the write fence: {stray[:5]}"
    if not dirty:
        return "nothing to commit"

    for p in WRITE_PATHS:
        _run(["git", "add", "--", p], REPO_DIR, check=False)
    _run(["git", "commit", "--quiet", "-m", message], REPO_DIR)

    # Rebase onto whatever landed while we worked, then push. One retry: if it still
    # conflicts, a human should look rather than a loop guessing.
    for attempt in (1, 2):
        r = _run(["git", "pull", "--rebase", "--quiet", "origin", "main"], REPO_DIR, check=False)
        if r.returncode:
            _run(["git", "rebase", "--abort"], REPO_DIR, check=False)
            return f"refused: rebase conflict, needs a human: {(r.stderr or '')[:200]}"
        p = _run(["git", "push", "--quiet", "origin", "HEAD:main"], REPO_DIR, check=False)
        if not p.returncode:
            return "pushed"
        if attempt == 1:
            time.sleep(3)
    return f"push failed: {(p.stderr or p.stdout)[:200]}"


if __name__ == "__main__":                                  # smoke test from a shell
    d = ensure_repo()
    n = sum(1 for _ in d.rglob("*") if _.is_file())
    print(f"working copy at {d}: {n} files")
    print("head:", _run(["git", "log", "--oneline", "-1"], d).stdout.strip())

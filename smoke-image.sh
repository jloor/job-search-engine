#!/usr/bin/env bash
# smoke-image.sh IMAGE [WANT_VERSION] — start an image and assert what it ANSWERS.
#
# ⭐ ONE COPY, RUN TWICE. The release workflow runs this against the image it just built,
# before it pushes. The operator's deploy runs it again against the image it pulled BY
# DIGEST, before it points production at it. The second run is not redundant: it tests the
# bytes that will actually run, not the bytes a CI runner had on its disk.
#
# ⚠️ THE ASSERTIONS CHECK CONTENT, NOT STATUS CODES. Two diagnostics once shipped subtly wrong
# and both returned 200 while they said something false: database_host was empty on the
# sqlite backend, and /diag/ai named a field AI_SCHEMA does not define. A check that they
# answered would have passed both. A check of what they answered catches both.
#
# Works with podman or docker. Set CONTAINER_ENGINE to choose; podman wins when both exist.
# Exit 0 only when every assertion passed. No network, no credentials, no real data.
set -uo pipefail

IMG="${1:?usage: smoke-image.sh IMAGE [WANT_VERSION]}"
WANT="${2:-}"
ENGINE="${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}"
[ -n "$ENGINE" ] || { echo "no podman or docker"; exit 2; }

PASS=0; FAIL=0
ok()  { printf "  ok   %-48s %s\n" "$1" "${2:-}"; PASS=$((PASS+1)); }
bad() { printf "  FAIL %-48s %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }

CID=$("$ENGINE" run -d -P -e ADMIN_TOKEN=smokeadmin -e READ_TOKEN=smokeread \
      -e INBOUND_TOKEN='alpha,beta' -e APPROVAL_SECRET=smoke -e DB_PATH=/tmp/smoke.db "$IMG") \
  || { echo "could not start $IMG"; exit 1; }
trap '"$ENGINE" rm -f "$CID" >/dev/null 2>&1 || true' EXIT
PORT=$("$ENGINE" port "$CID" 8080/tcp | head -1 | sed 's/.*://')
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.5
done
sq() { curl -s --max-time 20 -H "Authorization: Bearer smokeadmin" "http://127.0.0.1:$PORT$1"; }

# 🚨 The import that broke every scheduled job while /health stayed green.
"$ENGINE" exec "$CID" python -c "import job_search_engine, gitsync, candidate, gates" 2>/dev/null \
  && ok "intra-package imports resolve" || bad "intra-package imports resolve"
# 🚨 The dependencies pyproject once failed to declare, which killed backups for a day.
"$ENGINE" exec "$CID" python -c "
import importlib
for m in ('cryptography.hazmat.primitives.asymmetric.x25519','email_reply_parser','anthropic','multipart','webauthn','cbor2'):
    importlib.import_module(m)" 2>/dev/null \
  && ok "every runtime dependency imports" || bad "every runtime dependency imports"
# The backup path specifically: its failure is invisible until the day it is needed.
"$ENGINE" exec "$CID" python -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
import job_search_engine.backup as b
k=X25519PrivateKey.generate()
pub=k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
prv=k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()).hex()
assert b.unseal(b.seal(b'x'*64, pub), prv)==b'x'*64" 2>/dev/null \
  && ok "backup seal/unseal round-trips" || bad "backup seal/unseal round-trips"

V=$(sq /health | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('version','?'))
except Exception: print('?')")
if [ -n "$WANT" ]; then
  [ "$V" = "$WANT" ] && ok "image reports the wanted version" "$V" \
                     || bad "image reports the wanted version" "got $V want $WANT"
else
  [ "$V" != "?" ] && ok "image reports a version" "$V" || bad "image reports a version" "none"
fi

# ⚠️ A LITERAL ON PURPOSE. Reading the count from the image would assert the image against
# itself and could never notice a job that silently disappeared. Adding a job means changing
# this number deliberately. History of the number: the operator's tools/deploy.sh, where this
# check lived until 2026-10-07 (26 since notify, v0.85.0).
JOBS=26
DC=$(sq /diag/config | JOBS=$JOBS python3 -c "
import json,os,sys
d=json.load(sys.stdin); n=int(os.environ['JOBS'])
errs=[]
if not d.get('database_host'): errs.append('database_host is EMPTY')
if len(d.get('secrets') or {}) < 10: errs.append('secrets dict looks empty')
if len(d.get('jobs_registered') or []) != n: errs.append(f\"{len(d.get('jobs_registered') or [])} jobs, want {n}\")
if d.get('inbound_tokens_configured') != 2: errs.append('inbound token count wrong')
print('; '.join(errs) or 'ok')" 2>/dev/null)
[ "$DC" = "ok" ] && ok "/diag/config reports real values" || bad "/diag/config reports real values" "${DC:-no answer}"

DA=$(sq /diag/ai | python3 -c "
import json,sys
d=json.load(sys.stdin)
errs=[]
if d.get('key_present') is not False: errs.append('claims a key with none configured')
if d.get('live_called') is not False: errs.append('claims a live call it did not make')
if not d.get('result'): errs.append('no result string')
print('; '.join(errs) or 'ok')" 2>/dev/null)
[ "$DA" = "ok" ] && ok "/diag/ai is honest with no key" || bad "/diag/ai is honest with no key" "${DA:-no answer}"

DJ=$(sq /diag/jobs | JOBS=$JOBS python3 -c "
import json,os,sys
d=json.load(sys.stdin); n=int(os.environ['JOBS'])
errs=[]
for k in ('stale','stuck','jobs','ok'):
    if k not in d: errs.append(f'missing {k}')
if len(d.get('jobs') or []) != n: errs.append(f'not {n} jobs')
if any('running_for_s' not in j for j in d.get('jobs') or []): errs.append('no running_for_s')
print('; '.join(errs) or 'ok')" 2>/dev/null)
[ "$DJ" = "ok" ] && ok "/diag/jobs distinguishes stale from stuck" || bad "/diag/jobs distinguishes stale from stuck" "${DJ:-no answer}"

C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST \
    -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$PORT/inbound/not-a-token")
[ "$C" = "404" ] && ok "an unknown webhook token is refused" "404" \
                 || bad "an unknown webhook token is refused" "got $C"

# The container runs as the unprivileged user, never root.
U=$("$ENGINE" exec "$CID" id -u 2>/dev/null)
[ "$U" = "10001" ] && ok "runs as the relay user, not root" "uid $U" \
                   || bad "runs as the relay user, not root" "uid ${U:-?}"

printf "\n  smoke: %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

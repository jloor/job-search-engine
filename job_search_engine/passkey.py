"""Mail approval by passkey (WebAuthn). The relay's third approval path, beside Ed25519 and
YubiKey-SSH.

⭐ THE PROPERTY: no agent can send mail as the operator. An agent may QUEUE an email. Only a
WebAuthn assertion with user verification, from a credential the operator ACTIVATED, sends it.

🚨 ENROLLMENT HAS TWO HALVES, AND THE SECOND IS THE POINT. A WebAuthn credential is only a
key pair, and software can make one. If the admin token alone could register a credential,
any agent holding that token could enroll a software "passkey" and approve its own sends.
So a newly registered credential is PENDING. It becomes active only with an SSHSIG from a key
in APPROVAL_SK_KEYS (a hardware security key, touch required), in its own namespace, over a
message that names the credential's id and public key.

⚠️ Imports of `webauthn` are lazy. The bare test job installs nothing, and this module must
import there so the pure helpers below can be tested.
"""
import base64
import hashlib
import html
import json
import secrets

ENROLL_NAMESPACE = "job-search-enroll"
CHALLENGE_TTL_S = 300
QUEUE_TTL_S = 24 * 3600
ENROLL_TTL_S = 900


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ------------------------------------------------------------------ pure helpers --

def challenge_for(fp_hex: str) -> bytes:
    """16 random bytes, then the 32-byte content fingerprint. The signature therefore covers
    the exact email, and the random half makes every challenge single-use."""
    fp = bytes.fromhex(fp_hex)
    if len(fp) != 32:
        raise ValueError("fingerprint must be 32 bytes")
    return secrets.token_bytes(16) + fp


def fp_in_challenge(challenge: bytes) -> str:
    if len(challenge) != 48:
        raise ValueError("challenge must be 48 bytes")
    return challenge[16:].hex()


def enroll_message(credential_id_b64u: str, public_key: bytes) -> bytes:
    """What the operator's security key signs to activate a credential. It names both the id
    and the key, so an activation cannot be moved onto a different credential."""
    return f"enroll.{credential_id_b64u}.{hashlib.sha256(public_key).hexdigest()}".encode()


def short_code(public_key: bytes) -> str:
    """A code the phone page and the laptop both show, for a human to compare. It is a check
    that he is activating the credential he just made, not a secret."""
    h = hashlib.sha256(public_key).hexdigest()[:12].upper()
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}"


def sign_count_ok(stored: int, new: int) -> bool:
    """WebAuthn clone detection. Many passkeys always report 0, which is allowed. Otherwise
    the counter must grow."""
    if stored == 0 and new == 0:
        return True
    return new > stored


# ---------------------------------------------------------------- webauthn wrappers --

def registration_options(rp_id: str, rp_name: str, exclude_ids: list[bytes]) -> tuple[str, bytes]:
    """Options JSON for navigator.credentials.create, and the challenge to store."""
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (AttestationConveyancePreference,
                                          AuthenticatorSelectionCriteria,
                                          PublicKeyCredentialDescriptor,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    opts = generate_registration_options(
        rp_id=rp_id, rp_name=rp_name,
        user_id=b"operator", user_name="operator", user_display_name="Mail approver",
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=i) for i in exclude_ids],
        timeout=120000)
    return options_to_json(opts), opts.challenge


def verify_registration(body: dict, challenge: bytes, rp_id: str, origin: str) -> dict:
    from webauthn import verify_registration_response
    v = verify_registration_response(credential=body, expected_challenge=challenge,
                                     expected_rp_id=rp_id, expected_origin=origin,
                                     require_user_verification=True)
    return {"credential_id": v.credential_id, "public_key": v.credential_public_key,
            "sign_count": v.sign_count}


def authentication_options(rp_id: str, challenge: bytes, allow_ids: list[bytes]) -> str:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor,
                                          UserVerificationRequirement)
    opts = generate_authentication_options(
        rp_id=rp_id, challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=i) for i in allow_ids],
        user_verification=UserVerificationRequirement.REQUIRED, timeout=120000)
    return options_to_json(opts)


def verify_authentication(body: dict, challenge: bytes, rp_id: str, origin: str,
                          public_key: bytes, sign_count: int) -> int:
    """Return the new sign count. Raises on any failure, including a missing UV flag."""
    from webauthn import verify_authentication_response
    v = verify_authentication_response(credential=body, expected_challenge=challenge,
                                       expected_rp_id=rp_id, expected_origin=origin,
                                       credential_public_key=public_key,
                                       credential_current_sign_count=sign_count,
                                       require_user_verification=True)
    return v.new_sign_count


# ------------------------------------------------------------------------- pages --

_STYLE = """
:root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1b1b1b;--mut:#666;--card:#fff;--line:#ddd;--ok:#0b6e4f;--bad:#a4161a}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--mut:#aaa;--card:#1e1e1e;--line:#333;--ok:#4fd1a5;--bad:#ff7b7b}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
main{max-width:640px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:20px;margin:0 0 4px} p.mut{color:var(--mut);margin:0 0 16px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:12px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0} dt{color:var(--mut)} dd{margin:0;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font:15px/1.5 ui-monospace,monospace}
button{width:100%;padding:16px;font-size:18px;border-radius:10px;border:0;background:var(--ok);color:#fff;margin-top:8px}
button:disabled{opacity:.5} input{width:100%;box-sizing:border-box;padding:12px;font-size:16px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
#msg{margin-top:14px;font-weight:600} .bad{color:var(--bad)} .ok{color:var(--ok)} .code{font:600 28px ui-monospace,monospace;letter-spacing:2px}
"""


def _page(title: str, inner: str) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="referrer" content="no-referrer"><title>{html.escape(title)}</title>'
            f'<style>{_STYLE}</style></head><body><main>{inner}</main>'
            f'<script src="/passkey.js"></script></body></html>')


def approve_page(token: str, item: dict) -> str:
    e = html.escape
    status = item.get("status")
    head = (f"<h1>Approve this email?</h1><p class='mut'>It is sent exactly as shown, "
            f"after you verify with your passkey or YubiKey. Queued {e(item.get('created_at') or '')}.</p>")
    card = (f"<div class='card'><dl><dt>From</dt><dd>{e(item['from_alias'])}</dd>"
            f"<dt>To</dt><dd>{e(item['to_addr'])}</dd><dt>Subject</dt><dd>{e(item['subject'])}</dd></dl></div>"
            f"<div class='card'><pre>{e(item['body'])}</pre></div>")
    if status != "queued":
        tail = f"<p id='msg' class='bad'>This email is {e(status or 'unknown')}. Nothing more can be done here.</p>"
    else:
        tail = (f"<button id='go' data-mode='approve' data-token='{e(token)}'>Approve and send</button>"
                f"<p id='msg'></p>")
    return _page("Approve email", head + card + tail)


def submit_approve_page(token: str, item: dict) -> str:
    """One exact submit record: every field value as the page read it back, the files by hash.
    Approving it lets ONE live run submit exactly this, once. Nothing is submitted here."""
    e = html.escape
    rec = json.loads(item.get("record_json") or "{}")
    status = item.get("status")
    head = (f"<h1>Approve this application?</h1><p class='mut'>{e(item.get('company_raw') or '')} · "
            f"{e(item.get('role_raw') or '')}. A shadow run filled the form and read every field back. "
            f"If you approve, one live run fills it again and submits only if every value below matches. "
            f"Recorded {e(item.get('created_at') or '')}.</p>")
    rows = "".join(f"<dt>{e(f.get('label') or f.get('id') or '')}</dt><dd>{e(str(f.get('value') or ''))}</dd>"
                   for f in rec.get("fields") or [])
    files = "".join(f"<dt>{e(n)}</dt><dd><code>{e(h[:16])}…</code></dd>"
                    for n, h in sorted((rec.get("files") or {}).items()))
    card = (f"<div class='card'><dl><dt>Posting</dt><dd>{e(rec.get('url') or '')}</dd>{rows}</dl></div>"
            f"<div class='card'><dl>{files}<dt>Record</dt><dd><code>{e(item['record_fp'][:16])}…</code>"
            f"</dd></dl></div>")
    if status != "pending":
        tail = f"<p id='msg' class='bad'>This record is {e(status or 'unknown')}. Nothing more can be done here.</p>"
    else:
        tail = (f"<button id='go' data-mode='approve' data-base='/submit/approve/' "
                f"data-done='Approved. One live run may now submit exactly this.' "
                f"data-token='{e(token)}'>Approve this submission</button><p id='msg'></p>")
    return _page("Approve application", head + card + tail)


def enroll_page(token: str) -> str:
    e = html.escape
    inner = ("<h1>Register a passkey for mail approval</h1>"
             "<p class='mut'>Step 1 of 2. After this, activate it from the laptop with your "
             "YubiKey. Until then it cannot approve anything.</p>"
             "<div class='card'><label for='label'>Name for this credential</label>"
             "<input id='label' maxlength='40' placeholder='YubiKey 5C NFC, or Pixel passkey'></div>"
             f"<button id='go' data-mode='enroll' data-token='{e(token)}'>Register</button>"
             "<p id='msg'></p>")
    return _page("Register passkey", inner)


# One static script, served from the relay's own origin, so the pages carry no inline script
# and the CSP can say script-src 'self'.
SCRIPT = r"""
(function(){
const b=document.getElementById('go'); if(!b) return;
const msg=document.getElementById('msg'), mode=b.dataset.mode, tok=b.dataset.token;
// The URL prefix of the approval being made: '/approve/' for mail, '/submit/approve/' for a
// submit record. Same ceremony, same credentials; only the endpoint and the final words differ.
const base=b.dataset.base||'/approve/', done=b.dataset.done||'Sent.';
const d=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0));
const e=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const say=(t,c)=>{msg.textContent=t;msg.className=c||'';};
async function post(u,body){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  const j=await r.json().catch(()=>({detail:'HTTP '+r.status})); if(!r.ok) throw new Error(j.detail||('HTTP '+r.status)); return j;}
b.onclick=async()=>{b.disabled=true; say('Waiting for your passkey or YubiKey...');
 try{
  if(mode==='approve'){
   const o=await post(base+tok+'/options'); o.challenge=d(o.challenge);
   (o.allowCredentials||[]).forEach(c=>c.id=d(c.id));
   const a=await navigator.credentials.get({publicKey:o});
   const r=await post(base+tok+'/verify',{id:a.id,rawId:e(a.rawId),type:a.type,
     response:{clientDataJSON:e(a.response.clientDataJSON),authenticatorData:e(a.response.authenticatorData),
     signature:e(a.response.signature),userHandle:a.response.userHandle?e(a.response.userHandle):null},clientExtensionResults:{}});
   say(done+' '+(r.transport?('via '+r.transport):''),'ok'); b.remove();
  } else {
   const label=(document.getElementById('label').value||'').trim();
   const o=await post('/passkey/enroll/'+tok+'/options'); o.challenge=d(o.challenge); o.user.id=d(o.user.id);
   (o.excludeCredentials||[]).forEach(c=>c.id=d(c.id));
   const c=await navigator.credentials.create({publicKey:o});
   const r=await post('/passkey/enroll/'+tok+'/verify',{label:label,credential:{id:c.id,rawId:e(c.rawId),type:c.type,
     response:{clientDataJSON:e(c.response.clientDataJSON),attestationObject:e(c.response.attestationObject),
     transports:c.response.getTransports?c.response.getTransports():[]},clientExtensionResults:{}}});
   say('Registered, PENDING. Code '+r.code+'. Activate it from the laptop and check the code matches.','ok'); b.remove();
  }
 }catch(x){say('Not done: '+x.message,'bad'); b.disabled=false;}
};
})();
"""

# Headers for every passkey page. no-store matters: the relay sits behind a CDN, and an
# approval page cached at the edge would show a stale status to the next viewer.
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                               "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


def options_json_to_dict(s: str) -> dict:
    return json.loads(s)

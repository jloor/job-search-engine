// The browser half of the submitter: open an application form, describe it, fill it, read it
// back, and take screenshots. It holds the MECHANICS only. Every decision (which answer, which
// file, whether a value is right) is made by submit.py, which drives this process.
//
// Protocol: one JSON command per line on stdin, one JSON reply per line on stdout.
//   {"cmd":"open","url":...,"headed":bool,"settle":ms}   -> {ok,url,title}
//   {"cmd":"harvest"}                                    -> {ok,fields:[...],captcha,password_inputs}
//   {"cmd":"fill","files":[],"selects":[],"checks":[],"texts":[]} -> {ok,results:[...]}
//   {"cmd":"readback"}                                   -> {ok,fields:[...],blocked_submits}
//   {"cmd":"shot","path":...}                            -> {ok,path}
//   {"cmd":"close"}                                      -> {ok}
// A failure is {ok:false,error}. The process never exits on a bad command.
//
// 🚨 SUBMISSION IS BLOCKED ON THE PAGE. Three guards, each counted and reported by `readback`, so
// a submit attempt is visible rather than silent: a capture-phase listener cancels every submit
// event; form.submit(), which fires no event, is replaced; and any non-GET request that would
// navigate the top document is aborted at the network layer.
//
// ⭐ ONE SANCTIONED CLICK (2026-10-08). `final_submit` is the only way through, and only after
// `arm` with the nonce the relay returned when it CONSUMED a person's passkey approval of this
// exact record. It tags the real submit button with a per-browser secret and clicks it; the
// listener lets through exactly one submit event from that button, once, and the network guard
// opens for 15 seconds. form.submit() stays replaced. Every pass-through is counted.
//
// The rules below are each a way a filler reports success and does the wrong thing:
//   - Address fields by attribute ([id="..."]), never '#id': ids can start with a digit.
//   - Files first: an upload re-renders the form and can wipe values set before it.
//   - Choices before free text: selecting an option re-renders and can wipe typed text.
//   - Never commit an autocomplete or dropdown by pressing Down then Enter. Read the options,
//     match one, click it. The first suggestion is often a different place with the same name.
//   - Set values with real input events (fill, click, setInputFiles). A value written to the
//     DOM can display while the page's own state stays empty.
//   - Read state, not styling: the FileList, the input's value, the rendered single value.
'use strict';
const readline = require('readline');
const { chromium } = require('playwright');

const crypto = require('crypto');
const fresh = () => ({ submit_events: 0, submit_calls: 0, post_navigations: 0, sanctioned: 0 });
let browser = null, page = null, blocked = fresh();
let secret = '', armed = null, openUntil = 0;              // the one sanctioned click
let stage = 'idle';                                        // idle -> clicked -> code_done

const attr = (id) => `[id=${JSON.stringify(id)}]`;
const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();

async function open(c) {
  if (browser) await browser.close();
  // Headed draws on the DISPLAY in the environment (a virtual screen on the submitter host), so
  // a person can watch or take over. Headless is for tests.
  browser = await chromium.launch({ headless: !c.headed });
  page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  blocked = fresh(); armed = null; openUntil = 0; stage = 'idle';
  secret = crypto.randomBytes(16).toString('hex');
  await page.exposeFunction('__submitBlocked', (kind) => { blocked[kind] += 1; });
  await page.addInitScript((SECRET) => {
    const used = new Set();
    // A submit event (button click, Enter, requestSubmit) is cancelled before the page sees it,
    // EXCEPT the events whose submitter carries a tag only Node can write: SECRET:1 for the
    // approved click (final_submit) and SECRET:2 for the emailed security code (enter_code). Each
    // tag passes ONCE; a page cannot mint a third.
    document.addEventListener('submit', (e) => {
      const s = e.submitter;
      const tag = s && s.getAttribute ? s.getAttribute('data-sanctioned') : null;
      if (tag && (tag === SECRET + ':1' || tag === SECRET + ':2') && !used.has(tag)) {
        used.add(tag);
        try { window.__submitBlocked('sanctioned'); } catch (_) { /* page closing */ }
        return;
      }
      e.preventDefault(); e.stopImmediatePropagation();
      try { window.__submitBlocked('submit_events'); } catch (_) { /* page closing */ }
    }, true);
    // form.submit() fires no event, so it is replaced. The page stays on the form.
    HTMLFormElement.prototype.submit = function () {
      try { window.__submitBlocked('submit_calls'); } catch (_) { /* page closing */ }
    };
  }, secret);
  await page.route('**/*', (route) => {
    const r = route.request();
    if (r.method() !== 'GET' && r.isNavigationRequest() && r.frame() === page.mainFrame()) {
      if (Date.now() < openUntil) { blocked.sanctioned += 1; return route.continue(); }
      blocked.post_navigations += 1;
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  await page.goto(c.url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(c.settle || 4000);
  return { url: page.url(), title: await page.title() };
}

async function harvest() {
  return page.evaluate(() => {
    const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
    const labelOf = (el) => {
      if (el.labels && el.labels[0]) return clean(el.labels[0].innerText);
      const by = el.getAttribute('aria-labelledby');
      if (by) { const l = document.getElementById(by); if (l) return clean(l.innerText); }
      return clean(el.getAttribute('aria-label') || '');
    };
    const fields = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      const type = (el.type || el.tagName).toLowerCase();
      if (['hidden', 'submit', 'button', 'search', 'password'].includes(type)) return;
      if (!el.id) return;                                   // nothing to address it by
      if (/^iti-/.test(el.id) || /recaptcha/i.test(el.id + ' ' + el.name)) return;
      let kind = type;
      if (el.tagName === 'TEXTAREA') kind = 'textarea';
      else if (el.tagName === 'SELECT') kind = 'native_select';
      else if ((el.className || '').toString().includes('select__input')) kind = 'select';
      const label = labelOf(el);
      const required = !!el.required || el.getAttribute('aria-required') === 'true'
                       || /\*\s*$/.test(label);
      const r = el.getBoundingClientRect();
      fields.push({ id: el.id, name: el.name || '', kind, label: label.replace(/\s*\*\s*$/, ''),
                    required, visible: r.width > 0 && r.height > 0 || type === 'file' });
    });
    return {
      fields,
      captcha: !!document.querySelector('iframe[src*="recaptcha"][src*="bframe"], iframe[src*="hcaptcha"], .cf-turnstile'),
      password_inputs: document.querySelectorAll('input[type=password]').length,
    };
  });
}

// The one option a wording names, or null. Tiers: exact, starts-with, whole word. A tier with
// two hits is ambiguous and is no match. ⚠️ Whole words only: a substring test lets "No" match
// "I am not a veteran". answers.py applies the same tiers before the browser opens.
// ⚠️ OPTIONS ARE COMPARED ON A KEY WITHOUT WHITESPACE. Greenhouse renders each option twice (a
// wrapper and an inner role="option" node) and the two copies differ in spacing: "United States +1"
// and "United States+1" (2026-10-08). Removing exact duplicates left both, and the ambiguity rule
// refused the country it should have chosen. Two options with the same key are one option.
const optKey = (s) => String(s).toLowerCase().replace(/\s+/g, '');
function pickOption(opts, want) {
  const seen = new Map();
  for (const o of opts) if (!seen.has(optKey(o))) seen.set(optKey(o), o);
  opts = [...seen.values()];
  const w = String(want).trim().toLowerCase(), wk = optKey(want);
  const esc = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const word = new RegExp('(?<![\\w])' + esc + '(?![\\w])');
  const tiers = [opts.filter((o) => optKey(o) === wk),
                 opts.filter((o) => optKey(o).startsWith(wk) && word.test(o.trim().toLowerCase().slice(0, w.length + 1))),
                 opts.filter((o) => word.test(o.toLowerCase()))];
  for (const t of tiers) { if (t.length === 1) return t[0]; if (t.length > 1) return null; }
  return null;
}

// One react-select style control: open it, type each wanted spelling in turn, click the
// option the page itself offers. Returns the option text chosen, or null with the options seen.
async function chooseOption(id, wants) {
  const input = page.locator(attr(id)).first();
  if (await input.count() === 0) return { status: 'not_found' };
  if (await input.evaluate((n) => n.tagName === 'SELECT')) {   // a native <select>
    const opts = (await input.locator('option').allInnerTexts()).map(clean).filter(Boolean);
    for (const want of wants) {
      const hit = pickOption(opts, want);
      if (hit) { await input.selectOption({ label: hit }); return { status: 'set', chosen: hit }; }
    }
    return { status: 'no_option', options: opts.slice(0, 40) };
  }
  const control = page.locator('.select__control').filter({ has: input }).first();
  const opener = (await control.count()) ? control : input;
  const optSel = '[class*="select__option"], [role="option"]';
  let seen = [];
  for (const want of wants) {
    await opener.click();
    await input.fill('');
    await input.pressSequentially(String(want).slice(0, 40), { delay: 15 });
    await page.waitForTimeout(500);
    const opts = (await page.locator(optSel).allInnerTexts()).map(clean).filter(Boolean);
    seen = opts.length ? opts : seen;
    const hit = pickOption(opts, want);
    if (hit) {
      const exact = new RegExp('^' + hit.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
      await page.locator(optSel).filter({ hasText: exact }).first().click();
      await page.waitForTimeout(300);
      return { status: 'set', chosen: hit };
    }
    await page.keyboard.press('Escape');
  }
  // Show what the control offers with no filter, so a person can add the right spelling.
  await opener.click(); await input.fill(''); await page.waitForTimeout(400);
  const all = (await page.locator(optSel).allInnerTexts()).map(clean).filter(Boolean);
  await page.keyboard.press('Escape');
  return { status: 'no_option', options: (all.length ? all : seen).slice(0, 40) };
}

async function fill(c) {
  const results = [];
  for (const f of c.files || []) {                          // 1. files first
    const el = page.locator(attr(f.id)).first();
    if (await el.count() === 0) { results.push({ id: f.id, kind: 'file', status: 'not_found' }); continue; }
    await el.setInputFiles(f.path);
    const name = f.path.split('/').pop();
    // ⚠️ THE INPUT MAY BE GONE AFTER THE UPLOAD. Greenhouse replaces it with a filename chip once
    // the file is accepted (found on the first real shadow run, 2026-10-08: the next read of the
    // input waited 30 s for an element that no longer existed). Read the input only while it
    // exists; after that, the filename on the page is the proof.
    let ok = false, via = '';
    for (let i = 0; i < 40 && !ok; i++) {                   // wait for the name, not a clock
      if (await el.count()) {
        const held = await el.evaluate((n) => [...(n.files || [])].map((x) => x.name), null, { timeout: 2000 }).catch(() => []);
        if (held.includes(name)) { ok = true; via = 'input'; break; }
      }
      if ((await page.evaluate(() => document.body.innerText)).includes(name)) { ok = true; via = 'shown'; break; }
      await page.waitForTimeout(500);
    }
    results.push({ id: f.id, kind: 'file', status: ok ? 'set' : 'not_registered', file: name, via });
  }
  for (const s of c.selects || []) {                        // 2. choices
    const r = await chooseOption(s.id, s.values || []);
    results.push({ id: s.id, kind: 'select', ...r });
  }
  for (const k of c.checks || []) {                         // 3. checkboxes and radios, by id
    const el = page.locator(attr(k.id)).first();
    if (await el.count() === 0) { results.push({ id: k.id, kind: 'check', status: 'not_found' }); continue; }
    // The label beside the control must contain the text submit.py expects, so an id that has
    // moved to a different question is refused rather than clicked.
    const lab = clean(await el.evaluate((n) => (n.labels && n.labels[0] ? n.labels[0].innerText : '')));
    if (k.expect && !lab.toLowerCase().includes(String(k.expect).toLowerCase())) {
      results.push({ id: k.id, kind: 'check', status: 'label_mismatch', label: lab }); continue;
    }
    if (!(await el.isChecked())) await el.check({ force: true });
    results.push({ id: k.id, kind: 'check', status: (await el.isChecked()) ? 'set' : 'not_set' });
  }
  for (const t of c.texts || []) {                          // 4. free text last
    const el = page.locator(attr(t.id)).first();
    if (await el.count() === 0) { results.push({ id: t.id, kind: 'text', status: 'not_found' }); continue; }
    await el.fill(String(t.value));
    results.push({ id: t.id, kind: 'text', status: 'set' });
  }
  await page.waitForTimeout(800);
  return { results };
}

async function readback(c) {
  const fields = await page.evaluate(() => {
    const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
    const out = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      const type = (el.type || el.tagName).toLowerCase();
      if (!el.id || ['hidden', 'submit', 'button', 'search', 'password'].includes(type)) return;
      if (/^iti-/.test(el.id) || /recaptcha/i.test(el.id + ' ' + el.name)) return;
      const label = clean(el.labels && el.labels[0] ? el.labels[0].innerText : '').replace(/\s*\*\s*$/, '');
      const f = { id: el.id, label };
      if (type === 'file') {
        f.kind = 'file'; f.files = [...(el.files || [])].map((x) => ({ name: x.name, size: x.size }));
      } else if ((el.className || '').toString().includes('select__input')) {
        f.kind = 'select';
        const ctl = el.closest('.select__control') || el.parentElement;
        const single = ctl && ctl.querySelector('[class*="single-value"], [class*="singleValue"]');
        const multi = ctl ? [...ctl.querySelectorAll('[class*="multi-value__label"]')].map((x) => clean(x.innerText)) : [];
        f.value = multi.length ? multi.join(' + ') : (single ? clean(single.innerText) : '');
        // A country picker shows only a flag and a dial code ("+1" is the US AND Canada). The
        // flag's class carries the ISO code (iti__us), so name the country from it.
        const flag = single && single.querySelector('[class*="iti__flag"]');
        const iso = flag && ((flag.className.match(/\biti__([a-z]{2})\b/) || [])[1]);
        if (iso) {
          try { f.value = clean(new Intl.DisplayNames(['en'], { type: 'region' }).of(iso.toUpperCase()) + ' ' + f.value); }
          catch (_) { f.value = clean(iso.toUpperCase() + ' ' + f.value); }
        }
      } else if (type === 'checkbox' || type === 'radio') {
        f.kind = type; f.checked = el.checked;
      } else if (el.tagName === 'SELECT') {
        f.kind = 'native_select';
        f.value = el.selectedIndex >= 0 ? clean(el.options[el.selectedIndex].text) : '';
      } else {
        f.kind = el.tagName === 'TEXTAREA' ? 'textarea' : type;
        f.value = el.value || '';                           // the whole value, never truncated
      }
      out.push(f);
    });
    return out;
  });
  // For each uploaded file: what its input still holds, or, when the page replaced the input,
  // whether the page shows the filename. submit.py accepts either as proof of the upload.
  const uploads = {};
  for (const f of (c && c.files) || []) {
    const st = await page.evaluate(({ id, name }) => {
      const el = document.getElementById(id);
      const held = el && el.files ? [...el.files].map((x) => ({ name: x.name, size: x.size })) : null;
      return { held, shown: document.body.innerText.includes(name) };
    }, f);
    uploads[f.id] = st;
  }
  return { fields, uploads, blocked_submits: blocked };
}

async function shot(c) {
  // A password is never captured: cover every password input before the screenshot.
  await page.evaluate(() => document.querySelectorAll('input[type=password]').forEach((el) => {
    el.style.setProperty('-webkit-text-security', 'disc'); el.value && (el.dataset.masked = '1');
    el.style.setProperty('color', 'transparent'); el.style.setProperty('background', '#000');
  }));
  await page.screenshot({ path: c.path, fullPage: c.full !== false });
  return { path: c.path };
}

// ── the last mile ────────────────────────────────────────────────────────────────────────
const PROOF = /thank you for (applying|your application|your interest)|application (has been |was )?(submitted|received)|we(?:'|’)ve received your application/i;

async function arm(c) {
  if (!/^[0-9a-f]{32}$/.test(String(c.nonce || ''))) throw new Error('arm needs the relay nonce');
  armed = { nonce: c.nonce, until: Date.now() + 5000 };
  return { armed: true };
}

// Greenhouse's emailed security code: the prompt text, and one single-character box per character.
const CODE_PROMPT = /verification code was sent|enter the \d+-character code|security code/i;
const codeBoxes = () => page.locator('input[maxlength="1"]:visible');
async function codePrompt() {
  const text = await page.evaluate(() => document.body ? document.body.innerText : '').catch(() => '');
  return CODE_PROMPT.test(text) && (await codeBoxes().count()) >= 6;
}

async function watchProof(waitS, allowCode = true) {
  const until = Date.now() + Math.min(600, Math.max(1, waitS || 60)) * 1000;
  let excerpt = '';
  while (Date.now() < until) {
    const url = page.url();
    const text = await page.evaluate(() => document.body ? document.body.innerText : '').catch(() => '');
    const m = text.match(PROOF);
    if (/\/confirmation\b/.test(url) || m) {
      excerpt = m ? text.slice(Math.max(0, m.index - 80), m.index + 160).replace(/\s+/g, ' ').trim() : '';
      return { status: 'proof', url, excerpt };
    }
    if (allowCode && stage === 'clicked' && await codePrompt()) return { status: 'code_step', url };
    // A CAPTCHA challenge a person must solve: the reCAPTCHA or hCaptcha challenge frame, visible.
    const challenge = await page.evaluate(() => [...document.querySelectorAll(
      'iframe[src*="recaptcha"][src*="bframe"], iframe[src*="hcaptcha"][src*="challenge"]')]
      .some((f) => { const r = f.getBoundingClientRect(); return r.width > 50 && r.height > 50; })).catch(() => false);
    if (challenge) return { status: 'human_step', url };
    await page.waitForTimeout(1000);
  }
  return { status: 'no_proof', url: page.url(),
           excerpt: (await page.evaluate(() => document.body ? document.body.innerText : '').catch(() => '')).replace(/\s+/g, ' ').slice(0, 300) };
}

async function finalSubmit(c) {
  // One shot: the arm is spent whether the click succeeds or not.
  const a = armed; armed = null;
  if (!a || a.nonce !== c.nonce || Date.now() > a.until) throw new Error('not armed for this nonce');
  const btn = page.locator(c.selector || 'button[type="submit"]').filter({ hasText: c.text ? new RegExp(c.text, 'i') : /submit/i }).first();
  if (await btn.count() === 0) throw new Error('no submit button matched');
  await btn.evaluate((el, s) => el.setAttribute('data-sanctioned', s + ':1'), secret);
  openUntil = Date.now() + 15000;
  stage = 'clicked';
  await btn.click();
  return { clicked: true, ...(await watchProof(c.wait_s || 60)) };
}

// The emailed security code (2026-10-08, authorized explicitly by the operator). Allowed only after the
// approved click, only while the code prompt shows, once. The code comes from the relay (the run's
// one released code); it is typed with real key events, read back, and only then is the ONE second
// submit allowed. The code is never echoed in a reply.
async function enterCode(c) {
  if (stage !== 'clicked') throw new Error('enter_code is allowed only once, after the approved click');
  const code = String(c.code || '');
  if (!/^[A-Za-z0-9]{6,10}$/.test(code)) throw new Error('a code must be 6-10 letters or digits');
  if (!(await codePrompt())) throw new Error('no security-code prompt on the page');
  const boxes = codeBoxes();
  const n = await boxes.count();
  if (n !== code.length) throw new Error(`the page has ${n} code boxes for a ${code.length}-character code`);
  stage = 'code_done';                                     // one attempt, whatever happens next
  for (let i = 0; i < n; i++) {
    await boxes.nth(i).click();
    await boxes.nth(i).pressSequentially(code[i], { delay: 40 });
  }
  const held = (await boxes.evaluateAll((els) => els.map((e) => e.value))).join('');
  if (held !== code) throw new Error('the code boxes do not read back the code; nothing submitted');
  const btn = page.locator(c.selector || 'button[type="submit"]').filter({ hasText: /submit/i }).first();
  if (await btn.count() === 0) throw new Error('no submit button matched');
  await btn.evaluate((el, s) => el.setAttribute('data-sanctioned', s + ':2'), secret);
  openUntil = Date.now() + 15000;
  await btn.click();
  const r = await watchProof(c.wait_s || 60, false);
  // The reply becomes the run's proof record: a page or URL that repeats the code must not carry
  // it into the relay's steps or the alerts.
  const mask = (s) => (s || '').split(code).join(code.slice(0, 2) + '*'.repeat(code.length - 2));
  return { entered: true, ...r, url: mask(r.url), excerpt: mask(r.excerpt) };
}

const handlers = { open, harvest, fill, readback, shot, arm,
                   final_submit: finalSubmit,
                   enter_code: enterCode,
                   await_proof: async (c) => watchProof(c.wait_s || 600),
                   close: async () => { if (browser) await browser.close(); browser = null; return {}; } };

const rl = readline.createInterface({ input: process.stdin });
let chain = Promise.resolve();
rl.on('line', (line) => {
  chain = chain.then(async () => {
    let c;
    try { c = JSON.parse(line); } catch (e) { return out({ ok: false, error: 'bad json' }); }
    const h = handlers[c.cmd];
    if (!h) return out({ ok: false, error: `unknown command ${JSON.stringify(c.cmd)}` });
    if (c.cmd !== 'open' && c.cmd !== 'close' && !page) return out({ ok: false, error: 'no page open' });
    try { out({ ok: true, ...(await h(c)) }); } catch (e) { out({ ok: false, error: String(e && e.message || e) }); }
  });
});
rl.on('close', () => { chain.then(async () => { if (browser) await browser.close(); process.exit(0); }); });
function out(o) { process.stdout.write(JSON.stringify(o) + '\n'); }

/**
 * Privacy First Security Toolkit
 * Tool: Breach Checker — tools/breach-checker.js
 *
 * Checks whether a password has appeared in known data breaches,
 * using the k-anonymity method: the password is hashed locally with SHA-1
 * and only the FIRST 5 characters of the hash are sent to
 * HaveIBeenPwned (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).
 * The full password and full hash never leave your device.
 */

import { Utils } from '../core/utils.js';

async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkPassword(password) {
  const fullHash = (await sha1Hex(password)).toUpperCase();
  const prefix = fullHash.slice(0, 5);
  const suffix = fullHash.slice(5);

  let res;
  try {
    res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Accept': 'text/plain' }
    });
  } catch (e) {
    return { error: 'Could not reach the HaveIBeenPwned API. Check your internet connection.' };
  }
  if (!res.ok) {
    return { error: `Breach API error (${res.status}). Try again in a moment.` };
  }

  const body = await res.text();
  let count = 0;
  for (const line of body.split(/\r?\n/)) {
    const [suf, c] = line.split(':');
    if (suf === suffix) { count = parseInt(c, 10) || 1; break; }
  }

  return { count, prefix };
}

export function renderBreachChecker(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Breach Checker</h1>
      <p class="tool-subtitle">KNOWN BREACHES &middot; SHA-1 K-ANONYMITY &middot; HAVEIBEENPWNED</p>
      <span class="tool-privacy-badge">🔒 Full password never leaves your device</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="bc-input">Enter a password to check</label>
        <input class="input-field" id="bc-input" type="password"
          placeholder="Type or paste a password…" autocomplete="off" spellcheck="false" />
      </div>
      <button class="btn btn-primary btn-full" id="bc-btn">🔍 Check breach status</button>
      <p style="font-size:11px;color:var(--text-muted);margin-top:var(--space-sm);line-height:1.6;">
        How it works: your password is hashed locally (SHA-1). Only the first 5 characters of that hash
        are sent to HaveIBeenPwned — the industry-standard <em>k-anonymity</em> method. Neither your password
        nor its full hash ever leaves this page.
      </p>
    </div>

    <div id="bc-result"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Good password habits</div>
      <div style="display:flex;flex-direction:column;gap:8px;font-size:13px;color:var(--text-secondary);line-height:1.7;">
        <div>• Never reuse passwords across sites — one breach then unlocks everything.</div>
        <div>• Use a unique random password per site (try the <strong>Password Generator</strong> here).</div>
        <div>• Enable two-factor authentication wherever it is offered.</div>
        <div>• A password manager makes unique passwords practical.</div>
      </div>
    </div>
  `;

  const input = container.querySelector('#bc-input');
  const btn = container.querySelector('#bc-btn');
  const result = container.querySelector('#bc-result');

  async function check() {
    const password = input.value;
    if (!password) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Checking…';

    const res = await checkPassword(password);
    renderResult(result, res, password.length);

    result.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '🔍 Check breach status';
  }

  btn.addEventListener('click', check);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') check(); });
}

function renderResult(container, res, len) {
  if (res.error) {
    container.innerHTML = `
      <div class="card" style="margin-top:var(--space-md);">
        <div class="warning-item warn"><span class="warning-icon">⚠️</span><span>${Utils.escapeHTML(res.error)}</span></div>
      </div>`;
    return;
  }

  if (res.count > 0) {
    container.innerHTML = `
      <div class="card" style="margin-top:var(--space-md);">
        <div class="result-panel">
          <div class="result-panel-header">
            <span class="result-panel-title">Result</span>
            <span class="risk-badge risk-high">⚠️ BREACHED</span>
          </div>
          <div class="result-panel-body">
            <div class="warning-item warn">
              <span class="warning-icon">🚨</span>
              <div>
                <strong style="font-size:18px;color:var(--text-primary);">${res.count.toLocaleString()}</strong>
                <span> times in known breach data.</span>
                <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                  Stop using this password immediately — it is already exposed and will be tried first in
                  credential-stuffing attacks. Replace it with a unique password you have never used before.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  } else {
    container.innerHTML = `
      <div class="card" style="margin-top:var(--space-md);">
        <div class="result-panel">
          <div class="result-panel-header">
            <span class="result-panel-title">Result</span>
            <span class="risk-badge risk-safe">✅ NOT FOUND</span>
          </div>
          <div class="result-panel-body">
            <div class="warning-item safe">
              <span class="warning-icon">✅</span>
              <div>
                <strong>Not found</strong> in any known breach — good.
                <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                  This only means the exact password hasn't shown up in a public breach (yet). Length, uniqueness
                  and 2FA still matter. A ${len < 12 ? 'short password like this is still weak — make it 12+ characters and unique.' : 'strong, unique password like this is exactly what to keep using.'}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }
}

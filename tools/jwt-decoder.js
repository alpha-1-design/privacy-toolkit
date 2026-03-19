/**
 * Privacy First Security Toolkit
 * Tool: JWT Decoder — tools/jwt-decoder.js
 *
 * Decodes and inspects JSON Web Tokens.
 * Shows header, payload, expiry status, algorithm.
 * Does NOT verify signature (requires secret key).
 * 100% client-side — token never leaves browser.
 */

import { Utils } from '../core/utils.js';
import { icon } from '../core/icons.js';

function decodeBase64URL(str) {
  // Pad base64 string
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try {
    return JSON.parse(atob(str));
  } catch {
    return null;
  }
}

export function decodeJWT(token) {
  token = token.trim();
  const parts = token.split('.');

  if (parts.length !== 3) {
    return { error: 'Invalid JWT format. A valid JWT has exactly 3 parts separated by dots.' };
  }

  const header  = decodeBase64URL(parts[0]);
  const payload = decodeBase64URL(parts[1]);
  const sig     = parts[2];

  if (!header || !payload) {
    return { error: 'Could not decode JWT. The token may be malformed or corrupted.' };
  }

  const now = Math.floor(Date.now() / 1000);

  // Expiry analysis
  let expiryStatus = null;
  let expiryDate   = null;
  let issuedDate   = null;
  let nbfDate      = null;
  let timeRemaining = null;

  if (payload.exp) {
    expiryDate = new Date(payload.exp * 1000);
    const diff = payload.exp - now;

    if (diff < 0) {
      expiryStatus = {
        status: 'expired',
        label: 'Expired',
        detail: `Expired ${formatDuration(Math.abs(diff))} ago — ${expiryDate.toLocaleString()}`
      };
    } else if (diff < 300) {
      expiryStatus = {
        status: 'expiring',
        label: 'Expiring Soon',
        detail: `Expires in ${formatDuration(diff)} — ${expiryDate.toLocaleString()}`
      };
      timeRemaining = diff;
    } else {
      expiryStatus = {
        status: 'valid',
        label: 'Valid',
        detail: `Expires in ${formatDuration(diff)} — ${expiryDate.toLocaleString()}`
      };
      timeRemaining = diff;
    }
  }

  if (payload.iat) issuedDate  = new Date(payload.iat * 1000);
  if (payload.nbf) nbfDate     = new Date(payload.nbf * 1000);

  // Not before check
  let nbfStatus = null;
  if (payload.nbf && now < payload.nbf) {
    nbfStatus = {
      status: 'not-yet-valid',
      label: 'Not Yet Valid',
      detail: `Token is not valid until ${nbfDate.toLocaleString()}`
    };
  }

  // Algorithm warnings
  const algoWarnings = [];
  const algo = header.alg?.toUpperCase();
  if (algo === 'NONE' || algo === 'none') {
    algoWarnings.push({ level: 'danger', text: 'Algorithm "none" — this token has NO signature. Never accept this in production.' });
  }
  if (algo === 'HS256' || algo === 'HS384' || algo === 'HS512') {
    algoWarnings.push({ level: 'info', text: `HMAC algorithm (${algo}) — uses a shared secret. Ensure the secret is strong and kept private.` });
  }
  if (algo === 'RS256' || algo === 'RS384' || algo === 'RS512') {
    algoWarnings.push({ level: 'safe', text: `RSA algorithm (${algo}) — uses public/private key pair. Good for distributed systems.` });
  }
  if (algo === 'ES256' || algo === 'ES384' || algo === 'ES512') {
    algoWarnings.push({ level: 'safe', text: `ECDSA algorithm (${algo}) — strong and compact. Good choice.` });
  }

  // Sensitive fields detection
  const sensitiveKeys = ['password', 'secret', 'token', 'api_key', 'apikey', 'credit_card',
    'ssn', 'cvv', 'private_key', 'access_token', 'refresh_token'];
  const foundSensitive = Object.keys(payload)
    .filter(k => sensitiveKeys.some(s => k.toLowerCase().includes(s)));

  if (foundSensitive.length > 0) {
    algoWarnings.push({
      level: 'danger',
      text: `Sensitive data in payload: "${foundSensitive.join('", "')}". JWT payload is base64 encoded, NOT encrypted. Anyone with the token can read this.`
    });
  }

  return {
    raw: token,
    header,
    payload,
    signature: sig,
    expiryStatus,
    nbfStatus,
    issuedDate,
    expiryDate,
    nbfDate,
    timeRemaining,
    algoWarnings,
    foundSensitive,
    parts: { header: parts[0], payload: parts[1], signature: parts[2] }
  };
}

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

export function renderJWTDecoder(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">JWT Decoder</h1>
      <p class="tool-subtitle">DECODE · INSPECT · EXPIRY CHECK · ALGORITHM AUDIT</p>
      <span class="tool-privacy-badge">${icon('lock-closed', 12)} Token never leaves your device</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="jwt-input">Paste JWT token</label>
        <textarea class="input-field" id="jwt-input" rows="4"
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
          autocomplete="off" spellcheck="false"></textarea>
      </div>
      <div style="display:flex; gap:var(--space-sm);">
        <button class="btn btn-primary" style="flex:1;" id="jwt-decode-btn">
          ${icon('beaker', 16)} Decode Token
        </button>
        <button class="btn btn-secondary" id="jwt-sample-btn" title="Load sample JWT">
          Sample
        </button>
        <button class="btn btn-secondary" id="jwt-clear-btn" title="Clear">
          ${icon('x-mark', 16)}
        </button>
      </div>
    </div>

    <div id="jwt-result" style="display:none;"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Important Security Notes</div>
      <ul class="warning-list">
        <li class="warning-item warn">
          ${icon('exclamation-triangle', 14)}
          <span><strong>JWTs are not encrypted by default.</strong> Anyone who gets the token can decode the payload. Never store passwords or secrets inside a JWT.</span>
        </li>
        <li class="warning-item info">
          ${icon('information-circle', 14)}
          <span><strong>Signature is not verified here.</strong> This tool decodes only. Verification requires the secret or public key on your server.</span>
        </li>
        <li class="warning-item info">
          ${icon('information-circle', 14)}
          <span><strong>Algorithm matters.</strong> Always use RS256 or ES256 in production. Never accept "alg: none".</span>
        </li>
      </ul>
    </div>
  `;

  const input  = container.querySelector('#jwt-input');
  const btn    = container.querySelector('#jwt-decode-btn');
  const result = container.querySelector('#jwt-result');

  const SAMPLE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMzQ1IiwibmFtZSI6IkphbmUgRG9lIiwiZW1haWwiOiJqYW5lQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.placeholder';

  container.querySelector('#jwt-sample-btn').addEventListener('click', () => {
    input.value = SAMPLE;
    decode();
  });

  container.querySelector('#jwt-clear-btn').addEventListener('click', () => {
    input.value = '';
    result.style.display = 'none';
  });

  function decode() {
    const token = input.value.trim();
    if (!token) return;
    const decoded = decodeJWT(token);
    renderResult(result, decoded);
    result.style.display = 'block';
  }

  btn.addEventListener('click', decode);
  input.addEventListener('keydown', e => { if (e.key === 'Enter' && e.ctrlKey) decode(); });

  // Auto-decode on paste
  input.addEventListener('paste', () => setTimeout(decode, 50));
}

function renderResult(container, jwt) {
  if (jwt.error) {
    container.innerHTML = `
      <div class="card">
        <div class="warning-item danger">
          ${icon('x-mark', 16)}
          <span>${Utils.escapeHTML(jwt.error)}</span>
        </div>
      </div>`;
    return;
  }

  const expiry = jwt.expiryStatus;
  const expiryColor = !expiry ? 'info'
    : expiry.status === 'expired'  ? 'danger'
    : expiry.status === 'expiring' ? 'warn'
    : 'safe';

  const expiryRisk = !expiry ? 'medium'
    : expiry.status === 'expired'  ? 'high'
    : expiry.status === 'expiring' ? 'medium'
    : 'safe';

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Decoded JWT</span>
        <span class="risk-badge risk-${expiryRisk}">
          ${expiry ? expiry.label.toUpperCase() : 'NO EXPIRY SET'}
        </span>
      </div>
      <div class="result-panel-body">

        <!-- Token parts visual -->
        <div style="font-family:var(--font-mono); font-size:11px; word-break:break-all; line-height:2; margin-bottom:var(--space-md); background:var(--black); border:1px solid var(--border); border-radius:var(--radius-md); padding:var(--space-md);">
          <span style="color:#e06c75;">${Utils.escapeHTML(jwt.parts.header)}</span>.<span style="color:#98c379;">${Utils.escapeHTML(jwt.parts.payload)}</span>.<span style="color:#61afef;">${Utils.escapeHTML(jwt.parts.signature)}</span>
        </div>
        <div style="display:flex; gap:var(--space-sm); font-family:var(--font-mono); font-size:10px; margin-bottom:var(--space-lg);">
          <span style="color:#e06c75;">■ Header</span>
          <span style="color:#98c379;">■ Payload</span>
          <span style="color:#61afef;">■ Signature</span>
        </div>

        <!-- Expiry status -->
        ${expiry ? `
          <div class="warning-item ${expiryColor}" style="margin-bottom:var(--space-md);">
            ${icon(expiry.status === 'valid' ? 'check' : 'exclamation-triangle', 16)}
            <div>
              <strong>${expiry.label}</strong>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">${Utils.escapeHTML(expiry.detail)}</div>
            </div>
          </div>
        ` : `
          <div class="warning-item warn" style="margin-bottom:var(--space-md);">
            ${icon('exclamation-triangle', 16)}
            <span>No expiry (exp) claim set. This token never expires — consider adding one.</span>
          </div>
        `}

        <!-- Algorithm warnings -->
        ${jwt.algoWarnings.map(w => `
          <div class="warning-item ${w.level}" style="margin-bottom:var(--space-sm);">
            ${icon(w.level === 'safe' ? 'check' : w.level === 'danger' ? 'exclamation-triangle' : 'information-circle', 16)}
            <span style="font-size:13px;">${Utils.escapeHTML(w.text)}</span>
          </div>
        `).join('')}

        <hr class="separator" />

        <div class="grid-2" style="gap:var(--space-md); margin-bottom:var(--space-md);">

          <!-- Header -->
          <div>
            <div class="card-title" style="color:#e06c75;">Header</div>
            <div style="background:var(--black); border:1px solid var(--border); border-radius:var(--radius-md); padding:var(--space-md); font-family:var(--font-mono); font-size:12px; line-height:1.8;">
              ${renderJSON(jwt.header)}
            </div>
          </div>

          <!-- Dates summary -->
          <div>
            <div class="card-title">Timeline</div>
            <div style="display:flex; flex-direction:column; gap:var(--space-sm);">
              ${jwt.issuedDate ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Issued At (iat)</div>
                  <div class="fingerprint-val">${jwt.issuedDate.toLocaleString()}</div>
                </div>
              ` : ''}
              ${jwt.expiryDate ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Expires At (exp)</div>
                  <div class="fingerprint-val" style="color:var(--${expiryColor});">${jwt.expiryDate.toLocaleString()}</div>
                </div>
              ` : ''}
              ${jwt.nbfDate ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Not Before (nbf)</div>
                  <div class="fingerprint-val">${jwt.nbfDate.toLocaleString()}</div>
                </div>
              ` : ''}
              ${jwt.payload.iss ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Issuer (iss)</div>
                  <div class="fingerprint-val">${Utils.escapeHTML(String(jwt.payload.iss))}</div>
                </div>
              ` : ''}
              ${jwt.payload.sub ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Subject (sub)</div>
                  <div class="fingerprint-val">${Utils.escapeHTML(String(jwt.payload.sub))}</div>
                </div>
              ` : ''}
              ${jwt.payload.aud ? `
                <div class="fingerprint-item">
                  <div class="fingerprint-key">Audience (aud)</div>
                  <div class="fingerprint-val">${Utils.escapeHTML(String(jwt.payload.aud))}</div>
                </div>
              ` : ''}
            </div>
          </div>
        </div>

        <!-- Payload -->
        <div class="card-title" style="color:#98c379;">Full Payload</div>
        <div style="background:var(--black); border:1px solid var(--border); border-radius:var(--radius-md); padding:var(--space-md); font-family:var(--font-mono); font-size:12px; line-height:1.8; margin-bottom:var(--space-md); max-height:300px; overflow-y:auto;">
          ${renderJSON(jwt.payload)}
        </div>

        <div style="display:flex; gap:var(--space-sm);">
          <button class="btn btn-secondary" id="copy-payload-btn" style="flex:1;">
            ${icon('clipboard', 14)} Copy Payload
          </button>
          <button class="btn btn-secondary" id="copy-header-btn" style="flex:1;">
            ${icon('clipboard', 14)} Copy Header
          </button>
        </div>

      </div>
    </div>
  `;

  container.querySelector('#copy-payload-btn').addEventListener('click', async (e) => {
    await Utils.copyToClipboard(JSON.stringify(jwt.payload, null, 2));
    Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Payload`);
  });

  container.querySelector('#copy-header-btn').addEventListener('click', async (e) => {
    await Utils.copyToClipboard(JSON.stringify(jwt.header, null, 2));
    Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Header`);
  });
}

function renderJSON(obj) {
  return JSON.stringify(obj, null, 2)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"([^"]+)":/g, '<span style="color:#e06c75;">"$1"</span>:')
    .replace(/: "([^"]*)"/g, ': <span style="color:#98c379;">"$1"</span>')
    .replace(/: (\d+)/g, ': <span style="color:#d19a66;">$1</span>')
    .replace(/: (true|false|null)/g, ': <span style="color:#56b6c2;">$1</span>');
}

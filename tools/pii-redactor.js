/**
 * Privacy First Security Toolkit
 * Tool: PII Redactor — tools/pii-redactor.js
 *
 * Finds and masks personal / sensitive data in pasted text:
 * emails, phone numbers, credit cards (Luhn-validated), SSNs, API keys
 * and IP addresses. 100% local — nothing leaves the browser.
 */

import { Utils } from '../core/utils.js';

const CATEGORIES = [
  {
    key: 'api', label: 'API Key', token: '[API_KEY]', color: '#ef4444',
    regex: /\b(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|ya29\.[0-9A-Za-z_-]{20,}|rk_live_[0-9A-Za-z]{20,}|qqt_[0-9A-Za-z]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/g
  },
  {
    key: 'card', label: 'Credit Card', token: '[CARD]', color: '#ef4444',
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    validate: (raw) => {
      const digits = raw.replace(/[^\d]/g, '');
      if (digits.length < 13 || digits.length > 19) return false;
      let sum = 0;
      let alt = false;
      for (let i = digits.length - 1; i >= 0; i--) {
        let d = parseInt(digits[i], 10);
        if (alt) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        alt = !alt;
      }
      return sum % 10 === 0;
    }
  },
  { key: 'ssn', label: 'US SSN', token: '[SSN]', color: '#f59e0b', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { key: 'email', label: 'Email', token: '[EMAIL]', color: '#f59e0b', regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { key: 'phone', label: 'Phone', token: '[PHONE]', color: '#f59e0b',    regex: /(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?(?:\d[\s.-]?){6,12}\d(?!\d)/g },
  { key: 'ip', label: 'IP Address', token: '[IP]', color: '#3b82f6', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g }
];

function isValidIP(ip) {
  const parts = ip.split('.');
  return parts.every(p => {
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255 && String(n) === p;
  });
}

function luhnMatch(raw) {
  // card candidates also match plain numbers — require a valid Luhn checksum
  return CATEGORIES[1].validate(raw);
}

export function redactText(text) {
  const stats = {};
  CATEGORIES.forEach(c => { stats[c.key] = { count: 0, samples: [] }; });

  let working = text;

  // Pass 1 — non-numeric categories (emails, API keys, SSNs) so they are masked before
  // the broad phone/number pass can swallow parts of them.
  const numberFirst = ['card', 'ssn', 'ip'];
  const ordered = ['api', 'email', ...numberFirst, 'phone'];

  for (const key of ordered) {
    const cat = CATEGORIES.find(c => c.key === key);      const rx = new RegExp(cat.regex.source, cat.regex.flags.replace('g', '') + 'g');
      working = working.replace(rx, (match) => {
      let valid = true;
      if (key === 'card') valid = luhnMatch(match);
      if (key === 'ip') valid = isValidIP(match);
      if (!valid) return match;
      stats[key].count++;
      if (stats[key].samples.length < 3) {
        const s = match.length > 18 ? match.slice(0, 8) + '…' + match.slice(-4) : match.slice(0, 3) + '…' + (match.length > 6 ? match.slice(-3) : '');
        stats[key].samples.push(s);
      }
      return cat.token;
    });
  }

  return { redacted: working, stats, total: Object.values(stats).reduce((s, v) => s + v.count, 0) };
}

export function renderPIIRedactor(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">PII Redactor</h1>
      <p class="tool-subtitle">MASK EMAILS &middot; PHONES &middot; CARDS &middot; SSNs &middot; API KEYS</p>
      <span class="tool-privacy-badge">🔒 Everything happens in your browser</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="pr-input">Paste text containing personal data</label>
        <textarea class="input-field" id="pr-input" rows="10" spellcheck="false"
          placeholder="Paste logs, messages, documents, screenshots text…&#10;e.g. Contact me at jane@example.com or +233 55 000 0000.&#10;Card: 4242 4242 4242 4242 — API: sk_live_AbC123…"></textarea>
      </div>
      <button class="btn btn-primary btn-full" id="pr-btn">🕶 Redact</button>
    </div>

    <div id="pr-result"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">What gets detected</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;">
        ${CATEGORIES.map(c => `
          <span style="background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;font-size:11px;color:var(--text-secondary);">
            <span style="font-weight:600;color:${c.color};">${c.label}</span>
            <span style="font-family:var(--font-mono);margin-left:6px;">${c.token}</span>
          </span>`).join('')}
      </div>
      <p style="font-size:12px;color:var(--text-muted);line-height:1.7;margin-top:var(--space-sm);">
        Credit-card detection validates the Luhn checksum to avoid false positives.
        Detection is heuristic — always double-check anything you share.
      </p>
    </div>
  `;

  const input = container.querySelector('#pr-input');
  const btn = container.querySelector('#pr-btn');
  const result = container.querySelector('#pr-result');

  function run() {
    const text = input.value;
    if (!text.trim()) return;
    const res = redactText(text);
    renderResult(result, res);
    result.style.display = 'block';
  }

  btn.addEventListener('click', run);
  input.addEventListener('paste', () => setTimeout(run, 150));
}

function renderResult(container, res) {
  const active = CATEGORIES.filter(c => res.stats[c.key].count > 0);

  container.innerHTML = `
    <div class="card" style="margin-top:var(--space-md);">
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">Redacted</span>
          ${res.total
            ? `<span class="risk-badge ${res.total > 0 ? 'risk-medium' : 'risk-safe'}">${res.total} ITEM${res.total === 1 ? '' : 'S'} MASKED</span>`
            : '<span class="risk-badge risk-safe">NO PII FOUND</span>'}
        </div>
        <div class="result-panel-body">

          ${res.total
            ? `
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:var(--space-md);">
              ${active.map(c => `
                <span style="background:var(--surface-2);border:1px solid var(--border);border-radius:100px;padding:3px 10px;font-size:11px;">
                  <span style="font-weight:700;color:${c.color};">${res.stats[c.key].count} × ${c.label}</span>
                  ${res.stats[c.key].samples.length ? `<span style="font-family:var(--font-mono);color:var(--text-muted);margin-left:4px;">${Utils.escapeHTML(res.stats[c.key].samples.join(', '))}</span>` : ''}
                </span>`).join('')}
            </div>

            <textarea class="input-field" id="pr-output" rows="10" readonly spellcheck="false">${Utils.escapeHTML(res.redacted)}</textarea>
            <div style="display:flex;gap:8px;margin-top:var(--space-sm);flex-wrap:wrap;">
              <button class="btn btn-primary" id="pr-copy">📋 Copy redacted text</button>
              <button class="btn btn-secondary" id="pr-download">⬇ Download .txt</button>
            </div>
            <p style="font-size:11px;color:var(--text-muted);margin-top:var(--space-sm);">The original input was never stored or sent — it only lives in this page's memory until you leave.</p>
            `
            : '<div class="warning-item safe"><span class="warning-icon">✅</span><span>No emails, phones, cards, SSNs, API keys or IP addresses were detected.</span></div>'}

        </div>
      </div>
    </div>`;

  if (res.total) {
    container.querySelector('#pr-copy').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(res.redacted);
      Utils.showCopyFeedback(e.target, '📋 Copy redacted text');
    });
    container.querySelector('#pr-download').addEventListener('click', () => {
      const blob = new Blob([res.redacted], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'redacted.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      window.showToast('Redacted file saved to your device', 'success');
    });
  }
}

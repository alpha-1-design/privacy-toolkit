/**
 * Privacy First Security Toolkit
 * Tool: Email Header Analyzer — tools/email-analyzer.js
 *
 * Paste raw email headers (in Gmail: ⋮ → Show original; in Outlook:
 * View → View message source) and analyze the routing + authentication
 * locally. SPF/DKIM/DMARC results are read from the Authentication-Results
 * header that the receiving server already computed — nothing is sent
 * anywhere and no DNS lookups are made.
 */

import { Utils } from '../core/utils.js';

function parseHeaders(raw) {
  const map = {};
  const order = [];
  const lines = raw.replace(/\r\n/g, '\n').split('\n');
  let current = null;

  for (const line of lines) {
    if (/^[\t ]/.test(line) && current) {
      map[current][map[current].length - 1] += '\n' + line.trim();
    } else if (/^([\w-]+):\s?(.*)$/.test(line)) {
      const m = line.match(/^([\w-]+):\s?(.*)$/);
      const key = m[1].toLowerCase();
      const val = m[2];
      if (!map[key]) { map[key] = []; order.push(key); }
      map[key].push(val);
      current = key;
    }
  }
  return { map, order };
}

function extractAuth(headers) {
  const res = { spf: null, dkim: null, dmarc: null };
  const authResults = headers.map['authentication-results'] || [];
  const text = authResults.join('\n');

  const spf = text.match(/spf=(\w+)/i);
  if (spf) res.spf = spf[1].toLowerCase();

  const dkim = text.match(/dkim=(\w+)/i);
  if (dkim) res.dkim = dkim[1].toLowerCase();

  const dmarc = text.match(/dmarc=(\w+)/i);
  if (dmarc) res.dmarc = dmarc[1].toLowerCase();

  return res;
}

function domainOfEmail(addr) {
  const m = String(addr || '').match(/@([\w.-]+)\s*>?/);
  return m ? m[1].toLowerCase() : null;
}

function extractReceived(headers) {
  const out = [];
  (headers.map.received || []).forEach((raw, i) => {
    const ipMatch = raw.match(/\[([0-9a-fA-F.:]+)\]/);
    const fromMatch = raw.match(/from\s+([^\s(]+)/i);
    const byMatch = raw.match(/by\s+([^\s(]+)/i);
    const dateMatch = raw.match(/(?:for|;\s*)(.{0,4}\d{1,2}\s\w{3}\s\d{4}\s[\d:]+)/i) ||
      raw.match(/\d{1,2}\s\w{3}\s\d{4}\s\d{2}:\d{2}:\d{2}/);
    const withMatch = raw.match(/with\s+(\w+)/i);
    out.push({
      index: out.length + 1,
      raw,
      ip: ipMatch ? ipMatch[1] : null,
      from: fromMatch ? fromMatch[1] : null,
      by: byMatch ? byMatch[1] : null,
      via: withMatch ? withMatch[1] : null,
      date: dateMatch ? dateMatch[0].replace(/^;\s*/, '').trim() : null
    });
  });
  return out;
}

export function analyze(raw) {
  const { map } = parseHeaders(raw);
  const auth = extractAuth({ map });
  const received = extractReceived({ map });
  const findings = [];

  const fromAddr = (map.from || [''])[0];
  const returnPath = (map['return-path'] || [''])[0];
  const replyTo = (map['reply-to'] || [''])[0];

  const fromDomain = domainOfEmail(fromAddr);
  const returnDomain = domainOfEmail(returnPath === '<>' ? '' : returnPath);
  const replyDomain = domainOfEmail(replyTo);

  if (auth.spf && auth.spf !== 'pass') findings.push({ level: 'warn', text: `SPF failed (${auth.spf}) — the sending server was not authorized for this domain.` });
  if (auth.dkim && auth.dkim !== 'pass') findings.push({ level: 'warn', text: `DKIM failed (${auth.dkim}) — the message signature could not be verified.` });
  if (auth.dmarc && auth.dmarc !== 'pass') findings.push({ level: 'warn', text: `DMARC failed (${auth.dmarc}) — treat with extra caution.` });

  if (returnDomain && fromDomain && returnDomain !== fromDomain) {
    findings.push({ level: 'high', text: `Return-Path domain (${returnDomain}) does not match the From domain (${fromDomain}) — common in phishing/spoofing.` });
  }
  if (replyDomain && fromDomain && replyDomain !== fromDomain) {
    findings.push({ level: 'warn', text: `Reply-To domain (${replyDomain}) differs from From (${fromDomain}) — replies may be hijacked.` });
  }
  if (!auth.spf && !auth.dkim && !auth.dmarc) {
    findings.push({ level: 'info', text: 'No Authentication-Results header found — this header may have been stripped or the mail server does not publish it.' });
  }
  if (received.length === 0) {
    findings.push({ level: 'high', text: 'No Received headers — this is not a full raw header block (in Gmail use ⋮ → Show original).' });
  }
  if (fromAddr && /[\u0400-\u04FF\u0370-\u03FF]/.test(fromAddr)) {
    findings.push({ level: 'high', text: 'Non-Latin characters in the From address — possible homograph/spoofing attempt.' });
  }

  return { map, auth, received, findings, fromAddr, fromDomain, returnDomain };
}

export function renderEmailAnalyzer(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Email Header Analyzer</h1>
      <p class="tool-subtitle">RAW HEADERS &middot; SPF &middot; DKIM &middot; DMARC &middot; ROUTING</p>
      <span class="tool-privacy-badge">🔒 100% local — nothing is sent, no DNS lookups</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="ea-input">Paste raw email headers</label>
        <textarea class="input-field" id="ea-input" rows="12" spellcheck="false"
          placeholder="In Gmail: open the message → ⋮ → Show original → copy the top block.&#10;In Outlook: open the message → ⋮ → View → View message source."></textarea>
      </div>
      <button class="btn btn-primary btn-full" id="ea-btn">📨 Analyze headers</button>
    </div>

    <div id="ea-result"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">What this checks</div>
      <p style="font-size:13px;color:var(--text-secondary);line-height:1.8;">
        Every email travels through several mail servers, and each one stamps a <strong>Received</strong> line.
        The <strong>Authentication-Results</strong> header records whether the receiving server's SPF, DKIM and
        DMARC checks passed. This tool reads those stamps locally and flags mismatches between the claimed
        sender (<em>From</em>), the envelope sender (<em>Return-Path</em>) and where replies go (<em>Reply-To</em>)
        — the classic anatomy of a spoofed or phishing email.
      </p>
    </div>
  `;

  const input = container.querySelector('#ea-input');
  const btn = container.querySelector('#ea-btn');
  const result = container.querySelector('#ea-result');

  function run() {
    const raw = input.value;
    if (!raw.trim()) return;
    const analysis = analyze(raw);
    renderResult(result, analysis);
    result.style.display = 'block';
  }

  btn.addEventListener('click', run);
}

function renderResult(container, a) {
  const allPass = a.auth.spf === 'pass' && a.auth.dkim === 'pass' && a.auth.dmarc === 'pass' &&
    a.findings.every(f => f.level === 'info');
  const anyHigh = a.findings.some(f => f.level === 'high');

  const badge = anyHigh
    ? '<span class="risk-badge risk-high">⚠️ SUSPICIOUS</span>'
    : allPass
      ? '<span class="risk-badge risk-safe">✅ VERIFIED SENDER</span>'
      : '<span class="risk-badge risk-medium">🔶 REVIEW CAREFULLY</span>';

  const authRow = (label, val) => `
    <div style="display:flex;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);">
      <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);text-transform:uppercase;">${label}</span>
      <span style="font-family:var(--font-mono);font-size:12px;color:${val === 'pass' ? 'var(--safe)' : !val ? 'var(--text-muted)' : '#ef4444'};font-weight:700;">${val ? val.toUpperCase() : '— not reported'}</span>
    </div>`;

  container.innerHTML = `
    <div class="card" style="margin-top:var(--space-md);">
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">Analysis</span>
          ${badge}
        </div>
        <div class="result-panel-body">

          <div class="card-title">Authentication</div>
          ${authRow('SPF', a.auth.spf)}
          ${authRow('DKIM', a.auth.dkim)}
          ${authRow('DMARC', a.auth.dmarc)}

          <div style="margin-top:var(--space-md);">
            <div class="card-title">Findings</div>
            ${a.findings.length
              ? a.findings.map(f => `
                  <div class="warning-item ${f.level === 'high' ? 'warn' : f.level === 'warn' ? 'warn' : 'safe'}">
                    <span class="warning-icon">${f.level === 'high' ? '🚨' : f.level === 'warn' ? '⚠️' : 'ℹ️'}</span>
                    <span>${Utils.escapeHTML(f.text)}</span>
                  </div>`).join('')
              : '<div class="warning-item safe"><span class="warning-icon">✅</span><span>No red flags detected.</span></div>'}
          </div>

          <div style="margin-top:var(--space-md);">
            <div class="card-title">Routing trail (${a.received.length} hop${a.received.length === 1 ? '' : 's'} — newest first)</div>
            ${a.received.length
              ? a.received.map(h => `
                  <div style="border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;margin-bottom:8px;font-size:12px;line-height:1.7;">
                    <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-bottom:4px;">HOP ${h.index}</div>
                    ${h.from ? `<div><span style="color:var(--text-muted);">from</span> <strong style="color:var(--text);">${Utils.escapeHTML(h.from)}</strong></div>` : ''}
                    ${h.by ? `<div><span style="color:var(--text-muted);">by</span> <strong style="color:var(--text);">${Utils.escapeHTML(h.by)}</strong></div>` : ''}
                    ${h.ip ? `<div><span style="color:var(--text-muted);">ip</span> <span style="font-family:var(--font-mono);color:var(--accent);">${Utils.escapeHTML(h.ip)}</span></div>` : ''}
                    ${h.via ? `<div><span style="color:var(--text-muted);">via</span> ${Utils.escapeHTML(h.via)}</div>` : ''}
                    ${h.date ? `<div><span style="color:var(--text-muted);">at</span> ${Utils.escapeHTML(h.date)}</div>` : ''}
                  </div>`).join('')
              : '<p style="font-size:12px;color:var(--text-muted);">No Received headers found.</p>'}
          </div>

          <div style="margin-top:var(--space-md);">
            <div class="card-title">Key addresses</div>
            <div class="code-block" style="font-size:11px;line-height:2;">${['from', 'return-path', 'reply-to', 'message-id', 'date', 'subject'].map(k => {
              const v = (a.map[k] || [''])[0];
              return `<span style="color:var(--text-muted);">${k}:</span> ${Utils.escapeHTML(v || '—')}`;
            }).join('<br>')}</div>
          </div>

        </div>
      </div>
    </div>`;
}

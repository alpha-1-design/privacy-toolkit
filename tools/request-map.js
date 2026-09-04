/**
 * Privacy First Security Toolkit
 * Tool: Request Map — tools/request-map.js
 *
 * Shows every network request leaving this page, in real time:
 * destination domain, method, payload size, status and timing.
 * It only measures SIZES and DESTINATIONS — request contents are never read
 * or logged. Nothing captured here is ever sent anywhere.
 */

import { Utils } from '../core/utils.js';

let installed = false;
const MAX_LOG = 200;

const state = {
  running: true,
  log: [],
  byDomain: new Map(), // domain -> { count, bytes, thirdParty }
  totalBytes: 0,
  thirdPartyCount: 0,
  container: null
};

/* ---------- capture ---------- */

function bodySize(body) {
  try {
    if (typeof body === 'string') return new Blob([body]).size;
    if (body instanceof Blob) return body.size;
    if (body instanceof URLSearchParams) return new Blob([body.toString()]).size;
    if (body instanceof ArrayBuffer) return body.byteLength;
    if (ArrayBuffer.isView(body)) return body.byteLength;
    if (body instanceof FormData) {
      let s = 0;
      for (const v of body.values()) s += String(v).length;
      return s;
    }
  } catch (e) { /* ignore */ }
  return 0;
}

function hostOf(urlStr) {
  try { return new URL(urlStr).hostname; } catch (e) { return null; }
}

function push(entry) {
  if (!state.running) return;
  const host = hostOf(entry.url);
  if (!host) return; // data:, blob:, about: etc. never leave the device
  const scheme = entry.url.slice(0, 6);
  if (scheme === 'data:' || scheme === 'blob:') return;

  const thirdParty = host !== location.hostname;
  entry.host = host;
  entry.thirdParty = thirdParty;
  entry.time = new Date().toLocaleTimeString();

  state.log.push(entry);
  if (state.log.length > MAX_LOG) state.log.shift();

  state.totalBytes += entry.size || 0;
  if (thirdParty) state.thirdPartyCount++;

  const agg = state.byDomain.get(host) || { count: 0, bytes: 0, thirdParty };
  agg.count++;
  agg.bytes += entry.size || 0;
  agg.thirdParty = agg.thirdParty || thirdParty;
  state.byDomain.set(host, agg);

  renderLog();
}

function install() {
  if (installed) return;
  installed = true;

  // fetch()
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    let url = '';
    try { url = typeof input === 'string' ? input : (input instanceof URL ? input.href : input.url); } catch (e) {}
    const method = (init && init.method) || 'GET';
    const size = bodySize(init && init.body);
    const t0 = performance.now();
    const p = origFetch.apply(this, arguments);
    p.then(r => push({ type: 'fetch', method, url, size, status: r.status, ms: Math.round(performance.now() - t0) }))
      .catch(() => push({ type: 'fetch', method, url, size, status: 'failed', ms: Math.round(performance.now() - t0) }));
    return p;
  };

  // XMLHttpRequest
  const proto = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (proto) {
    const origOpen = proto.open;
    const origSend = proto.send;
    let xUrl = '';
    let xMethod = '';
    proto.open = function (m, u) { xMethod = m; xUrl = u; return origOpen.apply(this, arguments); };
    proto.send = function (body) {
      const t0 = performance.now();
      const size = bodySize(body);
      this.addEventListener('loadend', () => {
        push({ type: 'xhr', method: xMethod || 'GET', url: xUrl, size, status: this.status, ms: Math.round(performance.now() - t0) });
      });
      return origSend.apply(this, arguments);
    };
  }

  // navigator.sendBeacon
  if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      const size = bodySize(data);
      const ok = origBeacon(url, data);
      push({ type: 'beacon', method: 'POST', url, size, status: ok ? 200 : 'queued', ms: 0 });
      return ok;
    };
  }

  // Other page resources (styles, scripts, images, fonts) via Resource Timing
  if ('PerformanceObserver' in window) {
    try {
      const po = new PerformanceObserver(list => {
        for (const e of list.getEntries()) {
          const t = e.initiatorType;
          if (t === 'fetch' || t === 'xmlhttprequest' || t === 'beacon' || t === 'navigator') continue; // already tracked
          push({ type: 'resource', method: 'GET', url: e.name, size: e.transferSize || 0, status: 'loaded', ms: Math.round(e.duration) });
        }
      });
      po.observe({ type: 'resource', buffered: false });
    } catch (e) { /* observer unsupported */ }
  }
}

/* ---------- rendering ---------- */

function methodColor(m) {
  const c = {
    GET: 'var(--safe)',
    POST: 'var(--accent)',
    PUT: '#f59e0b',
    PATCH: '#f59e0b',
    DELETE: '#ef4444'
  };
  return c[m] || 'var(--text-muted)';
}

function renderLog() {
  const logEl = document.getElementById('rm-log');
  const statReqs = document.getElementById('rm-stat-reqs');
  const statBytes = document.getElementById('rm-stat-bytes');
  const statThird = document.getElementById('rm-stat-third');
  const statDomains = document.getElementById('rm-stat-domains');
  const domEl = document.getElementById('rm-domains');

  if (statReqs) statReqs.textContent = state.log.length;
  if (statBytes) statBytes.textContent = Utils.formatBytes(state.totalBytes);
  if (statThird) statThird.textContent = state.thirdPartyCount;
  if (statDomains) statDomains.textContent = state.byDomain.size;

  if (domEl) {
    const sorted = [...state.byDomain.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 12);
    domEl.innerHTML = sorted.length
      ? sorted.map(([host, a]) => `
          <div style="display:flex;align-items:center;gap:6px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:5px 9px;font-family:var(--font-mono);font-size:10.5px;">
            <span style="${a.thirdParty ? 'color:var(--accent);' : 'color:var(--safe);'}">${a.thirdParty ? '⇢' : '●'}</span>
            <span style="color:var(--text);">${Utils.escapeHTML(host)}</span>
            <span style="color:var(--text-muted);">×${a.count}</span>
            <span style="color:var(--text-muted);margin-left:auto;">${Utils.formatBytes(a.bytes)}</span>
          </div>`).join('')
      : '<span style="color:var(--text-muted);font-size:12px;">No outbound requests observed yet.</span>';
  }

  if (logEl) {
    if (!state.log.length) {
      logEl.innerHTML = '<span style="color:var(--text-muted);">Nothing yet. Run analyses, open tools, or toggle the sidebar <strong>Usage Stats</strong> switch — and watch what happens here in real time.</span>';
      return;
    }
    logEl.innerHTML = [...state.log].reverse().map(e => `
      <div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;border-bottom:1px dashed var(--border);font-family:var(--font-mono);font-size:10.5px;white-space:nowrap;overflow:hidden;">
        <span style="color:var(--text-muted);flex-shrink:0;">${e.time}</span>
        <span style="color:${methodColor(e.method)};font-weight:700;flex-shrink:0;width:42px;">${e.method}</span>
        <span style="flex-shrink:0;width:34px;text-align:right;color:${e.status === 200 || e.status === 'loaded' ? 'var(--safe)' : e.status === 'failed' ? '#ef4444' : 'var(--text-muted)'};">${e.status}</span>
        <span style="${e.thirdParty ? 'color:var(--accent);' : 'color:var(--safe);'}">${e.thirdParty ? '3rd' : 'self'}</span>
        <span style="color:var(--text);overflow:hidden;text-overflow:ellipsis;" title="${Utils.escapeHTML(e.url)}">${Utils.escapeHTML(Utils.truncate(e.url, 95))}</span>
        <span style="color:var(--text-muted);flex-shrink:0;margin-left:auto;">${e.size ? Utils.formatBytes(e.size) : ''}${e.ms ? ' · ' + e.ms + 'ms' : ''}</span>
      </div>`).join('');
  }
}

export function renderRequestMap(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  state.container = container;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Request Map</h1>
      <p class="tool-subtitle">LIVE OUTBOUND TRAFFIC &middot; FETCH &middot; XHR &middot; BEACON &middot; RESOURCES</p>
      <span class="tool-privacy-badge">🔒 Sizes &amp; destinations only — contents are never read or logged</span>
    </div>

    <div class="card">
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:var(--space-md);">
        <span class="status-dot" style="background:${state.running ? 'var(--safe)' : 'var(--text-muted)'};"></span>
        <span id="rm-state-label" style="font-size:12px;color:var(--text-secondary);">${state.running ? 'Capturing — watch what leaves this page' : 'Paused'}</span>
        <span style="margin-left:auto;display:flex;gap:6px;">
          <button class="btn btn-secondary" id="rm-toggle">${state.running ? '⏸ Pause' : '▶ Resume'}</button>
          <button class="btn btn-secondary" id="rm-clear">🗑 Clear</button>
          <button class="btn btn-secondary" id="rm-export">⬇ Export JSON</button>
        </span>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:var(--space-md);">
        <div class="stat-card"><span class="stat-value" id="rm-stat-reqs">0</span><span class="stat-label">Requests</span></div>
        <div class="stat-card"><span class="stat-value" id="rm-stat-bytes">0 B</span><span class="stat-label">Sent</span></div>
        <div class="stat-card"><span class="stat-value" id="rm-stat-third">0</span><span class="stat-label">3rd-party reqs</span></div>
        <div class="stat-card"><span class="stat-value" id="rm-stat-domains">0</span><span class="stat-label">Domains</span></div>
      </div>

      <div class="card-title">Destinations</div>
      <div id="rm-domains" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:var(--space-md);">
        <span style="color:var(--text-muted);font-size:12px;">Loading…</span>
      </div>
      <div style="display:flex;gap:14px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-bottom:var(--space-sm);">
        <span><span style="color:var(--safe);">●</span> this site (self)</span>
        <span><span style="color:var(--accent);">⇢</span> third-party domain</span>
      </div>

      <div class="card-title">Live log</div>
      <div id="rm-log" class="code-block" style="max-height:320px;overflow:auto;"></div>
    </div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Why this matters</div>
      <p style="font-size:13px;color:var(--text-secondary);line-height:1.8;margin-bottom:12px;">
        Most sites quietly talk to dozens of companies you never see. This toolkit promises that nothing leaves your browser —
        and here is the <em>proof</em>: every request this page makes is listed above with its destination and size.
        Try it: toggle the sidebar <strong>Usage Stats</strong> switch and watch the analytics request appear —
        <strong>only after you opt in</strong>.
      </p>
      <p style="font-size:13px;color:var(--text-muted);line-height:1.7;">
        Your request <em>contents</em> are never inspected, stored or shown — only sizes, methods and destinations,
        so you can verify data flow without exposing it. The export stays on your device as a downloaded file.
      </p>
    </div>
  `;

  const toggle = container.querySelector('#rm-toggle');
  const clear = container.querySelector('#rm-clear');
  const exportBtn = container.querySelector('#rm-export');
  const stateLabel = container.querySelector('#rm-state-label');

  toggle.addEventListener('click', () => {
    state.running = !state.running;
    toggle.textContent = state.running ? '⏸ Pause' : '▶ Resume';
    if (stateLabel) stateLabel.textContent = state.running ? 'Capturing — watch what leaves this page' : 'Paused';
    renderLog();
  });

  clear.addEventListener('click', () => {
    state.log = [];
    state.byDomain.clear();
    state.totalBytes = 0;
    state.thirdPartyCount = 0;
    renderLog();
  });

  exportBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), log: state.log }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'request-map.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    window.showToast('Export saved to your device', 'success');
  });

  install();
  renderLog();
}

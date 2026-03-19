/**
 * Privacy First Security Toolkit
 * Tool: Tracking Link Cleaner — tools/tracking-cleaner.js
 *
 * Strips tracking parameters from URLs.
 * Shows which companies were tracking you.
 * 100% client-side.
 */

import { Utils } from '../core/utils.js';

let trackingData = null;

async function loadData() {
  if (!trackingData) {
    const res = await fetch('./data/tracking-params.json');
    trackingData = await res.json();
  }
}

export async function cleanURL(rawURL) {
  await loadData();

  const url = Utils.parseURL(rawURL);
  if (!url) {
    return { error: 'Please enter a valid URL.' };
  }

  const params = new URLSearchParams(url.search);
  const removed = [];
  const kept = [];
  const cleanParams = new URLSearchParams();

  for (const [key, value] of params) {
    const lk = key.toLowerCase();
    if (trackingData.params.includes(lk)) {
      // Find which tracker this belongs to
      let tracker = 'Other';
      for (const [company, companyParams] of Object.entries(trackingData.categories)) {
        if (companyParams.includes(lk)) {
          tracker = company.charAt(0).toUpperCase() + company.slice(1);
          break;
        }
      }
      removed.push({ param: key, tracker });
    } else {
      kept.push(key);
      cleanParams.append(key, value);
    }
  }

  const clean = cleanParams.toString();
  url.search = clean ? '?' + clean : '';

  // Remove trailing ?
  const cleanURL = url.toString().replace(/\?$/, '');

  // Group by tracker
  const byTracker = {};
  for (const { param, tracker } of removed) {
    if (!byTracker[tracker]) byTracker[tracker] = [];
    byTracker[tracker].push(param);
  }

  return {
    original: rawURL,
    clean: cleanURL,
    removed,
    kept,
    byTracker,
    wasClean: removed.length === 0
  };
}

export function renderTrackingCleaner(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Tracking Link Cleaner</h1>
      <p class="tool-subtitle">REMOVE · UTM · FACEBOOK · GOOGLE · MICROSOFT · 60+ TRACKERS</p>
      <span class="tool-privacy-badge">🔒 Cleaned locally — original URL never sent anywhere</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="track-input">Paste URL with tracking parameters</label>
        <input class="input-field" id="track-input" type="text"
          placeholder="https://example.com/page?utm_source=facebook&fbclid=abc123&gclid=xyz..."
          autocomplete="off" spellcheck="false" />
      </div>
      <button class="btn btn-primary btn-full" id="track-clean-btn">🧹 Clean URL</button>
    </div>

    <div id="track-result" style="display:none;"></div>

    <!-- Explainer -->
    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">What is a tracking parameter?</div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.7;">
        When you click a link from social media, emails, or ads, companies append hidden tags to the URL
        to track <em>exactly where you came from, which ad you clicked, and which campaign you saw.</em>
        This tool strips those tags so you can share clean links and reduce your digital footprint.
      </p>
    </div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Common Trackers Removed</div>
      <div style="display:flex; flex-wrap:wrap; gap:4px;">
        ${[
          ['Google Analytics', 'utm_*'],
          ['Google Ads', 'gclid'],
          ['Facebook', 'fbclid'],
          ['Microsoft', 'msclkid'],
          ['TikTok', 'ttclid'],
          ['Twitter/X', 'twclid'],
          ['LinkedIn', 'li_fat_id'],
          ['Mailchimp', 'mc_cid'],
          ['HubSpot', '_hsenc'],
          ['60+ more', '…']
        ].map(([name, param]) => `
          <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:4px 8px; font-family:var(--font-mono); font-size:10px;">
            <span style="color:var(--text-muted);">${name}</span>
            <span style="color:var(--accent); margin-left:4px;">${param}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  const input = container.querySelector('#track-input');
  const btn = container.querySelector('#track-clean-btn');
  const result = container.querySelector('#track-result');

  async function clean() {
    const url = input.value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Cleaning…';

    const res = await cleanURL(url);
    renderResult(result, res);

    result.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '🧹 Clean URL';
  }

  btn.addEventListener('click', clean);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') clean(); });

  // Auto-clean on paste
  input.addEventListener('paste', () => {
    setTimeout(clean, 100);
  });
}

function renderResult(container, res) {
  if (res.error) {
    container.innerHTML = `
      <div class="card">
        <div class="warning-item warn">
          <span class="warning-icon">⚠️</span>
          <span>${Utils.escapeHTML(res.error)}</span>
        </div>
      </div>`;
    return;
  }

  if (res.wasClean) {
    container.innerHTML = `
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">Result</span>
          <span class="risk-badge risk-safe">✅ NO TRACKERS FOUND</span>
        </div>
        <div class="result-panel-body">
          <div class="warning-item safe">
            <span class="warning-icon">✅</span>
            <span>This URL has no known tracking parameters. It's already clean!</span>
          </div>
          <div class="code-block" style="margin-top:var(--space-md);">${Utils.escapeHTML(res.original)}</div>
        </div>
      </div>`;
    return;
  }

  const trackerNames = Object.keys(res.byTracker);

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Cleaned URL</span>
        <span class="risk-badge risk-medium">${res.removed.length} TRACKER${res.removed.length > 1 ? 'S' : ''} REMOVED</span>
      </div>
      <div class="result-panel-body">

        <div class="card-title">Clean URL</div>
        <div class="code-block" style="margin-bottom:var(--space-md); color:var(--safe);">
          ${Utils.escapeHTML(res.clean)}
        </div>
        <button class="btn btn-primary" id="copy-clean-btn" style="margin-bottom:var(--space-md);">📋 Copy Clean URL</button>

        <hr class="separator" />

        <div class="card-title">Trackers Removed</div>
        <div style="display:flex; flex-direction:column; gap:var(--space-sm); margin-bottom:var(--space-md);">
          ${trackerNames.map(tracker => `
            <div class="warning-item warn">
              <span class="warning-icon">📡</span>
              <div>
                <strong>${Utils.escapeHTML(tracker)}</strong>
                <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); margin-top:3px;">
                  ${res.byTracker[tracker].map(p => `<span class="tag-chip tracking">${Utils.escapeHTML(p)}</span>`).join('')}
                </div>
              </div>
            </div>
          `).join('')}
        </div>

        ${res.kept.length > 0 ? `
          <div class="card-title">Parameters Kept (non-tracking)</div>
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">
            ${res.kept.map(p => `<span class="tag-chip safe">${Utils.escapeHTML(p)}</span>`).join('')}
          </div>
        ` : ''}

        <hr class="separator" />
        <div class="card-title">Original URL</div>
        <div class="code-block" style="color:var(--text-muted); text-decoration:line-through; opacity:0.5;">
          ${Utils.escapeHTML(res.original)}
        </div>

      </div>
    </div>
  `;

  container.querySelector('#copy-clean-btn').addEventListener('click', async (e) => {
    await Utils.copyToClipboard(res.clean);
    Utils.showCopyFeedback(e.target, '📋 Copy Clean URL');
  });
}

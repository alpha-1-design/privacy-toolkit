/**
 * Privacy First Security Toolkit
 * Tool: Fake Domain Detector — tools/fake-domain-detector.js
 *
 * Detects brand impersonation and lookalike domains.
 * 100% client-side.
 */

import { Utils } from '../core/utils.js';

let knownBrands = null;

async function loadBrands() {
  if (!knownBrands) {
    const res = await fetch('./data/known-brands.json');
    knownBrands = await res.json();
  }
}

// Levenshtein distance (edit distance)
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

export async function analyzeDomain(rawInput) {
  await loadBrands();

  const domain = rawInput.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];

  if (!domain || domain.length < 3) {
    return { error: 'Please enter a valid domain name.' };
  }

  const results = [];
  const domainBase = domain.split('.')[0]; // part before TLD

  for (const brand of knownBrands.brands) {
    const realBase = brand.domain.split('.')[0];

    // Exact match = legit, skip
    if (domain === brand.domain) {
      return {
        domain,
        isLegit: true,
        brand: brand.name,
        realDomain: brand.domain,
        results: []
      };
    }

    // Check keyword list
    let keywordMatch = false;
    for (const keyword of brand.keywords) {
      if (domain.includes(keyword) || keyword.includes(domainBase)) {
        keywordMatch = true;
        break;
      }
    }

    // Levenshtein similarity
    const distance = levenshtein(domainBase, realBase);
    const similarity = 1 - (distance / Math.max(domainBase.length, realBase.length));

    const homographChars = Utils.hasHomographChars(domain);

    if (keywordMatch || similarity > 0.7 || homographChars.length > 0) {
      const score = Math.round(
        (keywordMatch ? 0.4 : 0) +
        (similarity > 0.7 ? similarity * 0.5 : 0) +
        (homographChars.length > 0 ? 0.3 : 0)
      * 100);

      results.push({
        brand: brand.name,
        realDomain: brand.domain,
        similarity: Math.round(similarity * 100),
        keywordMatch,
        homographChars,
        score: Math.min(score, 100),
        techniques: buildTechniqueList(domain, brand, domainBase, realBase, distance, homographChars)
      });
    }
  }

  // Sort by score
  results.sort((a, b) => b.score - a.score);

  return {
    domain,
    isLegit: false,
    results,
    homographChars: Utils.hasHomographChars(domain)
  };
}

function buildTechniqueList(domain, brand, domainBase, realBase, distance, homographChars) {
  const techniques = [];

  if (domain.includes(realBase) && domain !== brand.domain) {
    techniques.push(`Contains the word "${realBase}" — brand name embedded in fake domain`);
  }

  if (distance <= 2 && distance > 0) {
    techniques.push(`Only ${distance} character${distance > 1 ? 's' : ''} different from "${brand.domain}"`);
  }

  if (domain.includes('-') && (domain.includes(realBase) || domain.includes(brand.name.toLowerCase()))) {
    techniques.push(`Hyphen injection: "${domain}" uses dashes to impersonate "${brand.domain}"`);
  }

  if (homographChars.length > 0) {
    techniques.push(`Homograph attack: uses lookalike characters (${homographChars.map(h => `"${h.original}"→"${h.looksLike}"`).join(', ')})`);
  }

  const tld = '.' + domain.split('.').pop();
  if (brand.domain.endsWith('.com') && tld !== '.com') {
    techniques.push(`TLD substitution: uses "${tld}" instead of ".com"`);
  }

  return techniques;
}

export function renderFakeDomainDetector(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Fake Domain Detector</h1>
      <p class="tool-subtitle">BRAND IMPERSONATION · LOOKALIKE DOMAINS · HOMOGRAPH ATTACKS</p>
      <span class="tool-privacy-badge">🔒 Analyzed locally — no data sent anywhere</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="domain-input">Enter suspicious domain</label>
        <input class="input-field" id="domain-input" type="text"
          placeholder="paypaI-login-secure.com"
          autocomplete="off" spellcheck="false" />
      </div>
      <button class="btn btn-primary btn-full" id="domain-scan-btn">🔍 Check Domain</button>
    </div>

    <div id="domain-result" style="display:none;"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Common Impersonation Techniques</div>
      <ul class="warning-list">
        <li class="warning-item info"><span class="warning-icon">🔤</span><span><strong>Homograph attacks</strong> — Cyrillic "а" looks identical to Latin "a". аpple.com ≠ apple.com</span></li>
        <li class="warning-item info"><span class="warning-icon">➕</span><span><strong>Keyword injection</strong> — paypal-secure-login.com contains "paypal" but isn't PayPal</span></li>
        <li class="warning-item info"><span class="warning-icon">🌐</span><span><strong>TLD substitution</strong> — amazon.co instead of amazon.com</span></li>
        <li class="warning-item info"><span class="warning-icon">✏️</span><span><strong>Typosquatting</strong> — gooogle.com (extra "o") or gogle.com (missing "o")</span></li>
      </ul>
    </div>
  `;

  const input = container.querySelector('#domain-input');
  const btn = container.querySelector('#domain-scan-btn');
  const result = container.querySelector('#domain-result');

  async function scan() {
    const domain = input.value.trim();
    if (!domain) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Checking…';

    const analysis = await analyzeDomain(domain);
    renderResult(result, analysis);

    result.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '🔍 Check Domain';
  }

  btn.addEventListener('click', scan);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') scan(); });
}

function renderResult(container, analysis) {
  if (analysis.error) {
    container.innerHTML = `<div class="card"><div class="warning-item warn"><span>⚠️</span><span>${Utils.escapeHTML(analysis.error)}</span></div></div>`;
    return;
  }

  if (analysis.isLegit) {
    container.innerHTML = `
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">Domain Check</span>
          <span class="risk-badge risk-safe">✅ LEGITIMATE</span>
        </div>
        <div class="result-panel-body">
          <div class="warning-item safe">
            <span class="warning-icon">✅</span>
            <span>This is the verified domain for <strong>${Utils.escapeHTML(analysis.brand)}</strong>.</span>
          </div>
        </div>
      </div>`;
    return;
  }

  const topResult = analysis.results[0];

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Domain Analysis</span>
        <span class="risk-badge risk-${topResult ? (topResult.score >= 60 ? 'high' : 'medium') : 'safe'}">
          ${topResult ? `${topResult.score}% IMPERSONATION RISK` : '✅ NO IMPERSONATION DETECTED'}
        </span>
      </div>
      <div class="result-panel-body">

        <div class="code-block" style="margin-bottom:var(--space-md);">${Utils.escapeHTML(analysis.domain)}</div>

        ${analysis.homographChars.length > 0 ? `
          <div class="warning-item danger" style="margin-bottom:var(--space-md);">
            <span class="warning-icon">👁️</span>
            <div>
              <strong>Homograph characters detected!</strong>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
                ${analysis.homographChars.map(h => `"${h.original}" looks like "${h.looksLike}"`).join(' · ')}
              </div>
            </div>
          </div>
        ` : ''}

        ${analysis.results.length === 0 ? `
          <div class="warning-item safe">
            <span class="warning-icon">✅</span>
            <span>No known brand impersonation detected. Always verify independently.</span>
          </div>
        ` : analysis.results.map(r => `
          <div class="card" style="background:var(--surface-2); border-left:3px solid var(--danger); margin-bottom:var(--space-sm);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:var(--space-sm);">
              <strong>⚠️ Possible impersonation of ${Utils.escapeHTML(r.brand)}</strong>
              <span class="risk-badge risk-high">${r.score}% risk</span>
            </div>
            <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); margin-bottom:var(--space-sm);">
              Real domain: <span style="color:var(--safe);">${Utils.escapeHTML(r.realDomain)}</span>
            </div>
            ${r.techniques.length > 0 ? `
              <ul style="list-style:none; display:flex; flex-direction:column; gap:4px;">
                ${r.techniques.map(t => `
                  <li style="font-size:12px; color:var(--text-secondary); display:flex; gap:6px;">
                    <span style="color:var(--danger);">→</span> ${Utils.escapeHTML(t)}
                  </li>
                `).join('')}
              </ul>
            ` : ''}
          </div>
        `).join('')}

      </div>
    </div>
  `;
}

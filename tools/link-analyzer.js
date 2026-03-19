/**
 * Privacy First Security Toolkit
 * Tool: Link Analyzer — tools/link-analyzer.js
 *
 * Detects suspicious, phishing, and malicious URLs.
 * All processing is 100% client-side.
 */

import { Utils } from '../core/utils.js';
import { VirusTotal } from '../core/virustotal.js';
import { icon } from '../core/icons.js';

let suspiciousTLDs = null;
let knownBrands = null;

async function loadData() {
  if (!suspiciousTLDs) {
    const r1 = await fetch('./data/suspicious-tlds.json');
    suspiciousTLDs = await r1.json();
  }
  if (!knownBrands) {
    const r2 = await fetch('./data/known-brands.json');
    knownBrands = await r2.json();
  }
}

export async function analyzeURL(rawURL) {
  await loadData();

  const url = Utils.parseURL(rawURL);
  if (!url) {
    return { error: 'Invalid URL. Please enter a valid web address.' };
  }

  const domain = url.hostname.replace(/^www\./, '');
  const tld = Utils.getTLD(domain);
  const warnings = [];
  const info = [];
  let riskScore = 0;

  // ── Check 1: HTTPS ──
  if (url.protocol === 'http:') {
    warnings.push({
      level: 'danger',
      icon: '🔓',
      title: 'No HTTPS encryption',
      detail: 'This site uses HTTP, not HTTPS. Your data can be intercepted by anyone on the same network.'
    });
    riskScore += 20;
  } else {
    info.push({
      level: 'safe',
      icon: '🔒',
      title: 'HTTPS encryption active',
      detail: 'The connection to this site is encrypted.'
    });
  }

  // ── Check 2: Suspicious TLD ──
  if (suspiciousTLDs.high_risk.includes(tld)) {
    warnings.push({
      level: 'danger',
      icon: '🌐',
      title: `High-risk domain extension: ${tld}`,
      detail: `The "${tld}" extension is frequently used for free phishing and malware domains. Treat with extreme caution.`
    });
    riskScore += 30;
  } else if (suspiciousTLDs.suspicious.includes(tld)) {
    warnings.push({
      level: 'warn',
      icon: '🌐',
      title: `Suspicious domain extension: ${tld}`,
      detail: `The "${tld}" extension is commonly abused in phishing campaigns. This does not mean the site is malicious, but extra caution is advised.`
    });
    riskScore += 15;
  }

  // ── Check 3: Brand impersonation ──
  const impersonated = detectBrandImpersonation(domain);
  if (impersonated) {
    warnings.push({
      level: 'danger',
      icon: '🎭',
      title: `Possible impersonation of ${impersonated.brand}`,
      detail: `This domain appears to impersonate "${impersonated.brand}" (${impersonated.realDomain}). Never enter passwords or payment details here.`
    });
    riskScore += 40;
  }

  // ── Check 4: Homograph attack ──
  const homographs = Utils.hasHomographChars(domain);
  if (homographs.length > 0) {
    warnings.push({
      level: 'danger',
      icon: '👁️',
      title: 'Homograph attack detected',
      detail: `This domain uses lookalike characters (e.g. Cyrillic "а" instead of Latin "a") to appear as a trusted site. Detected: ${homographs.map(h => `"${h.original}" looks like "${h.looksLike}"`).join(', ')}`
    });
    riskScore += 45;
  }

  // ── Check 5: Punycode ──
  if (Utils.hasPunycode(domain)) {
    warnings.push({
      level: 'warn',
      icon: '🔤',
      title: 'International/punycode domain',
      detail: 'This domain uses encoded international characters (xn--). This can be used to disguise lookalike domains.'
    });
    riskScore += 15;
  }

  // ── Check 6: IP address used as domain ──
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(url.hostname)) {
    warnings.push({
      level: 'danger',
      icon: '🔢',
      title: 'IP address used instead of domain name',
      detail: 'Legitimate websites use domain names, not raw IP addresses. This is a common phishing technique.'
    });
    riskScore += 35;
  }

  // ── Check 7: Phishing keywords in domain ──
  const phishingKeywords = detectPhishingKeywords(domain);
  if (phishingKeywords.length > 0) {
    warnings.push({
      level: 'warn',
      icon: '🎣',
      title: 'Phishing keywords in domain',
      detail: `The domain contains suspicious keywords commonly used in phishing: ${phishingKeywords.join(', ')}`
    });
    riskScore += 20;
  }

  // ── Check 8: Excessive subdomains ──
  const parts = url.hostname.split('.');
  if (parts.length > 4) {
    warnings.push({
      level: 'warn',
      icon: '📂',
      title: 'Unusually long subdomain chain',
      detail: `This URL has ${parts.length - 2} subdomain levels. Phishing sites often use many subdomains to hide the real domain.`
    });
    riskScore += 10;
  }

  // ── Check 9: Long URL ──
  if (rawURL.length > 200) {
    warnings.push({
      level: 'warn',
      icon: '📏',
      title: 'Abnormally long URL',
      detail: 'Very long URLs can be used to hide malicious destinations or overwhelm detection systems.'
    });
    riskScore += 10;
  }

  // ── Check 10: Tracking parameters ──
  const { cleanURL, removed } = await Utils.cleanTrackingParams(rawURL);
  if (removed && removed.length > 0) {
    info.push({
      level: 'info',
      icon: '📡',
      title: `${removed.length} tracking parameter${removed.length > 1 ? 's' : ''} detected`,
      detail: `Tracking parameters found: ${removed.join(', ')}. These are used to monitor your activity across websites.`
    });
  }

  // ── Check 11: URL shortener detection ──
  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
    'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'];
  if (shorteners.includes(domain)) {
    warnings.push({
      level: 'warn',
      icon: '🔗',
      title: 'Shortened URL detected',
      detail: 'This is a link shortener. The real destination is hidden. Use a link expander to see where it leads before clicking.'
    });
    riskScore += 10;
  }

  // ── Check 12: Multiple redirects in URL path ──
  if (url.pathname.includes('redirect') || url.searchParams.has('url') ||
      url.searchParams.has('redirect') || url.searchParams.has('goto') ||
      url.searchParams.has('return')) {
    warnings.push({
      level: 'warn',
      icon: '↪️',
      title: 'Redirect parameter detected',
      detail: 'This URL contains a redirect parameter. It may forward you to a different destination than expected.'
    });
    riskScore += 15;
  }

  // ── Clamp risk score ──
  riskScore = Math.min(riskScore, 100);

  // ── Risk level label ──
  const riskLevel = riskScore >= 70 ? 'critical'
                  : riskScore >= 40 ? 'high'
                  : riskScore >= 20 ? 'medium'
                  : riskScore > 0   ? 'low'
                  : 'safe';

  // ── Simple explanation ──
  const explanation = generateExplanation(warnings, riskLevel, domain);

  return {
    url: rawURL,
    domain,
    protocol: url.protocol,
    riskScore,
    riskLevel,
    warnings,
    info,
    explanation,
    cleanURL: removed && removed.length > 0 ? cleanURL : null,
    removedParams: removed || []
  };
}

function detectBrandImpersonation(domain) {
  if (!knownBrands) return null;

  for (const brand of knownBrands.brands) {
    // Exact match = not impersonation
    if (domain === brand.domain || domain === `www.${brand.domain}`) continue;

    for (const keyword of brand.keywords) {
      if (domain.includes(keyword) && domain !== brand.domain) {
        return { brand: brand.name, realDomain: brand.domain };
      }
    }

    // Check if domain contains brand name but is not the real domain
    const brandName = brand.name.toLowerCase().replace(/\s+/g, '');
    if (domain.includes(brandName) && !domain.endsWith(brand.domain)) {
      return { brand: brand.name, realDomain: brand.domain };
    }
  }

  return null;
}

function detectPhishingKeywords(domain) {
  const keywords = [
    'login', 'signin', 'secure', 'account', 'verify', 'update',
    'confirm', 'banking', 'password', 'credential', 'wallet',
    'support', 'help-center', 'security', 'alert', 'suspended',
    'suspended', 'unlock', 'validate', 'authenticate'
  ];

  return keywords.filter(k => domain.includes(k));
}

function generateExplanation(warnings, riskLevel, domain) {
  if (riskLevel === 'safe' || riskLevel === 'low') {
    return `This link to "${domain}" appears to be safe. No major red flags were detected. Always stay alert, especially if you weren't expecting this link.`;
  }

  if (riskLevel === 'medium') {
    return `This link has some suspicious characteristics. Be careful — do not enter passwords or payment information unless you are absolutely certain this is a legitimate website.`;
  }

  if (riskLevel === 'high') {
    const topWarning = warnings[0];
    return `⚠️ This link looks dangerous. ${topWarning ? topWarning.detail : ''} Do NOT enter any personal information, passwords, or payment details. Close this tab immediately.`;
  }

  if (riskLevel === 'critical') {
    return `🚨 This link is very likely malicious. It may be attempting to steal your password, credit card details, or personal information. Do NOT visit this website.`;
  }
}

// ── Render function ──
export function renderLinkAnalyzer(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Link Analyzer</h1>
      <p class="tool-subtitle">PHISHING · IMPERSONATION · TRACKERS · VIRUSTOTAL · 90+ VENDORS</p>
      <span class="tool-privacy-badge">${icon('lock-closed', 12)} Local analysis + optional VirusTotal check</span>
    </div>

    <!-- Scan input -->
    <div class="card">
      <div class="input-group">
        <label class="input-label" for="link-input">Paste suspicious URL or link</label>
        <input class="input-field" id="link-input" type="text"
          placeholder="https://example.com/login?redirect=..." autocomplete="off" spellcheck="false" />
      </div>
      <button class="btn btn-primary btn-full" id="link-scan-btn">
        ${icon('magnifying-glass', 16)} Analyze Link
      </button>
    </div>

    <!-- VirusTotal API key panel -->
    <div class="card" id="vt-panel" style="border-color: var(--accent); border-style: dashed;">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:var(--space-sm);">
        <div class="card-title" style="margin:0; display:flex; align-items:center; gap:6px;">
          ${icon('shield', 16)}
          VirusTotal Integration
          <span id="vt-status-badge" class="risk-badge" style="font-size:9px; padding:2px 7px;">NOT CONNECTED</span>
        </div>
        <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer"
          style="font-size:11px; color:var(--accent); text-decoration:none;">
          Get free API key →
        </a>
      </div>

      <p style="font-size:12px; color:var(--text-muted); margin-bottom:var(--space-md); line-height:1.6;">
        Add your free VirusTotal key to check every URL against 90+ security vendors.
        Key is <strong style="color:var(--text-primary);">never stored</strong> — cleared when you close this tab.
      </p>

      <div id="vt-key-section">
        <div style="display:flex; gap:var(--space-sm);">
          <input class="input-field" id="vt-key-input" type="password"
            placeholder="Paste your VirusTotal API key here"
            autocomplete="off" spellcheck="false" style="flex:1; font-family:var(--font-mono); font-size:12px;" />
          <button class="btn btn-primary" id="vt-connect-btn">Connect</button>
        </div>
        <p style="font-size:10px; color:var(--text-muted); margin-top:6px;">
          Free tier: 500 checks/day · 4/min · No credit card required
        </p>
      </div>

      <div id="vt-connected-section" style="display:none;">
        <div style="display:flex; align-items:center; gap:var(--space-sm);">
          <span style="color:var(--safe); display:flex; align-items:center; gap:4px; font-size:13px;">
            ${icon('check', 14)} VirusTotal connected for this session
          </span>
          <button class="btn btn-secondary" id="vt-disconnect-btn" style="margin-left:auto; font-size:11px; padding:4px 10px;">
            Disconnect
          </button>
        </div>
      </div>
    </div>

    <div id="link-result" style="display:none;"></div>
  `;

  const input  = container.querySelector('#link-input');
  const btn    = container.querySelector('#link-scan-btn');
  const result = container.querySelector('#link-result');

  // ── VT key management ──
  const vtKeyInput        = container.querySelector('#vt-key-input');
  const vtConnectBtn      = container.querySelector('#vt-connect-btn');
  const vtDisconnectBtn   = container.querySelector('#vt-disconnect-btn');
  const vtKeySection      = container.querySelector('#vt-key-section');
  const vtConnectedSection = container.querySelector('#vt-connected-section');
  const vtStatusBadge     = container.querySelector('#vt-status-badge');

  function setVTConnected(connected) {
    vtKeySection.style.display      = connected ? 'none' : 'block';
    vtConnectedSection.style.display = connected ? 'block' : 'none';
    vtStatusBadge.textContent = connected ? 'CONNECTED' : 'NOT CONNECTED';
    vtStatusBadge.className = `risk-badge ${connected ? 'risk-safe' : ''}`;
    vtStatusBadge.style.cssText = `font-size:9px; padding:2px 7px; ${connected ? 'background:var(--safe);' : ''}`;
  }

  vtConnectBtn.addEventListener('click', () => {
    const key = vtKeyInput.value.trim();
    if (!key) return;
    VirusTotal.setKey(key);
    vtKeyInput.value = '';
    setVTConnected(true);
  });

  vtKeyInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') vtConnectBtn.click();
  });

  vtDisconnectBtn.addEventListener('click', () => {
    VirusTotal.clearKey();
    setVTConnected(false);
  });

  // ── Scan logic ──
  async function scan() {
    const url = input.value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Analyzing…`;
    result.style.display = 'none';

    // Run local analysis always
    const analysis = await analyzeURL(url);

    // Run VirusTotal if connected
    let vtResult = null;
    if (VirusTotal.hasKey()) {
      btn.innerHTML = `<span class="spinner"></span> Checking VirusTotal (90+ vendors)…`;
      vtResult = await VirusTotal.checkURL(url);
    }

    renderResult(result, analysis, vtResult);
    result.style.display = 'block';
    btn.disabled = false;
    btn.innerHTML = `${icon('magnifying-glass', 16)} Analyze Link`;
  }

  btn.addEventListener('click', scan);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') scan(); });
}

function renderResult(container, analysis, vtResult = null) {
  if (analysis.error) {
    container.innerHTML = `
      <div class="card">
        <div class="warning-item danger">
          ${icon('x-mark', 16)}
          <span>${Utils.escapeHTML(analysis.error)}</span>
        </div>
      </div>`;
    return;
  }

  const { riskScore, riskLevel, warnings, info, explanation, domain, cleanURL, removedParams } = analysis;

  // Merge VT score into overall risk if VT is available
  let finalScore = riskScore;
  let finalLevel = riskLevel;

  if (vtResult?.ok) {
    finalScore = Math.min(100, Math.max(riskScore, vtResult.vtScore));
    finalLevel = finalScore >= 70 ? 'critical'
               : finalScore >= 40 ? 'high'
               : finalScore >= 20 ? 'medium'
               : finalScore > 0   ? 'low'
               : 'safe';
  }

  const riskColor = finalLevel === 'safe' || finalLevel === 'low' ? 'safe'
                  : finalLevel === 'medium' ? 'warn' : 'danger';

  const allItems = [...warnings, ...info];

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Analysis Result</span>
        <span class="risk-badge risk-${finalLevel}">${finalLevel.toUpperCase()} RISK — ${finalScore}%</span>
      </div>
      <div class="result-panel-body">

        <!-- Risk bar -->
        <div style="margin-bottom:var(--space-md);">
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill ${riskColor}" style="width:${finalScore}%"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-top:4px;">
            <span>SAFE</span><span>MEDIUM</span><span>CRITICAL</span>
          </div>
        </div>

        <!-- URL -->
        <div class="code-block" style="margin-bottom:var(--space-md);">${Utils.escapeHTML(analysis.url)}</div>

        <!-- Explanation -->
        <div class="card" style="background:var(--surface-2); border-left:3px solid var(--${riskColor}); margin-bottom:var(--space-md);">
          <p style="font-size:14px; line-height:1.6;">${Utils.escapeHTML(explanation)}</p>
        </div>

        <!-- Local checks -->
        ${allItems.length > 0 ? `
          <div class="card-title">Local Analysis</div>
          <ul class="warning-list" style="margin-bottom:var(--space-md);">
            ${allItems.map(w => `
              <li class="warning-item ${w.level}">
                ${icon(w.level === 'safe' ? 'check' : w.level === 'danger' ? 'exclamation-triangle' : w.level === 'info' ? 'information-circle' : 'exclamation-triangle', 16)}
                <div>
                  <strong>${Utils.escapeHTML(w.title)}</strong>
                  <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">${Utils.escapeHTML(w.detail)}</div>
                </div>
              </li>
            `).join('')}
          </ul>
        ` : ''}

        <!-- VirusTotal results -->
        ${vtResult ? renderVTResult(vtResult) : `
          <div class="card" style="background:var(--surface-2); border-style:dashed;">
            <div style="display:flex; align-items:center; gap:var(--space-sm); color:var(--text-muted); font-size:13px;">
              ${icon('shield', 16)}
              <span>VirusTotal not connected — add your free API key above to check against 90+ security vendors</span>
            </div>
          </div>
        `}

        <!-- Clean URL -->
        ${cleanURL ? `
          <div class="card" style="background:var(--surface-2); margin-top:var(--space-md);">
            <div class="card-title">Clean URL (tracking removed)</div>
            <div class="code-block" style="margin-bottom:var(--space-sm);">${Utils.escapeHTML(cleanURL)}</div>
            <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); margin-bottom:var(--space-sm);">
              Removed: ${removedParams.map(p => `<span class="tag-chip tracking">${Utils.escapeHTML(p)}</span>`).join('')}
            </div>
            <button class="btn btn-secondary" id="copy-clean-url">
              ${icon('clipboard', 14)} Copy Clean URL
            </button>
          </div>
        ` : ''}

      </div>
    </div>
  `;

  if (cleanURL) {
    container.querySelector('#copy-clean-url').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(cleanURL);
      Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Clean URL`);
    });
  }
}

function renderVTResult(vt) {
  if (vt.error) {
    const isRateLimit = vt.code === 'RATE_LIMIT';
    const isNoKey     = vt.code === 'NO_KEY';
    const isInvalid   = vt.code === 'INVALID_KEY';
    return `
      <div class="card" style="background:var(--surface-2);">
        <div class="card-title" style="display:flex; align-items:center; gap:6px;">
          ${icon('shield-exclamation', 14)} VirusTotal
        </div>
        <div class="warning-item ${isRateLimit ? 'warn' : 'danger'}">
          ${icon('exclamation-triangle', 14)}
          <span style="font-size:13px;">${Utils.escapeHTML(vt.error)}
            ${isInvalid ? `<a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener"
              style="color:var(--accent); margin-left:4px;">Get a free key</a>` : ''}
          </span>
        </div>
      </div>`;
  }

  const vtColor = vt.vtRisk === 'malicious'  ? 'danger'
                : vt.vtRisk === 'suspicious' ? 'warn'
                : 'safe';

  const vtLabel = vt.vtRisk === 'malicious'  ? 'MALICIOUS'
                : vt.vtRisk === 'suspicious' ? 'SUSPICIOUS'
                : vt.vtRisk === 'low_risk'   ? 'LOW RISK'
                : 'CLEAN';

  return `
    <div class="card" style="background:var(--surface-2);">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:var(--space-md);">
        <div class="card-title" style="margin:0; display:flex; align-items:center; gap:6px;">
          ${icon('shield', 14)} VirusTotal — 90+ Vendors
        </div>
        <span class="risk-badge risk-${vtColor}" style="font-size:10px;">${vtLabel}</span>
      </div>

      <!-- Vendor stats grid -->
      <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:var(--space-sm); margin-bottom:var(--space-md);">
        <div style="text-align:center; background:var(--surface); border-radius:var(--radius-md); padding:10px; border:1px solid var(--border);">
          <div style="font-family:var(--font-mono); font-size:22px; font-weight:700; color:var(--danger); line-height:1;">${vt.malicious}</div>
          <div style="font-size:10px; color:var(--text-muted); margin-top:3px;">Malicious</div>
        </div>
        <div style="text-align:center; background:var(--surface); border-radius:var(--radius-md); padding:10px; border:1px solid var(--border);">
          <div style="font-family:var(--font-mono); font-size:22px; font-weight:700; color:var(--warn); line-height:1;">${vt.suspicious}</div>
          <div style="font-size:10px; color:var(--text-muted); margin-top:3px;">Suspicious</div>
        </div>
        <div style="text-align:center; background:var(--surface); border-radius:var(--radius-md); padding:10px; border:1px solid var(--border);">
          <div style="font-family:var(--font-mono); font-size:22px; font-weight:700; color:var(--safe); line-height:1;">${vt.harmless}</div>
          <div style="font-size:10px; color:var(--text-muted); margin-top:3px;">Clean</div>
        </div>
        <div style="text-align:center; background:var(--surface); border-radius:var(--radius-md); padding:10px; border:1px solid var(--border);">
          <div style="font-family:var(--font-mono); font-size:22px; font-weight:700; color:var(--text-muted); line-height:1;">${vt.undetected}</div>
          <div style="font-size:10px; color:var(--text-muted); margin-top:3px;">Undetected</div>
        </div>
      </div>

      <!-- Vendor detections -->
      ${vt.detections.length > 0 ? `
        <div class="card-title" style="margin-bottom:var(--space-sm);">Flagged by</div>
        <div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:var(--space-sm);">
          ${vt.detections.map(d => `
            <span style="font-family:var(--font-mono); font-size:10px; padding:3px 8px;
              background:var(--${d.category === 'malicious' ? 'danger' : 'warn'});
              color:#fff; border-radius:4px; opacity:0.85;"
              title="${Utils.escapeHTML(d.result)}">
              ${Utils.escapeHTML(d.vendor)}
            </span>
          `).join('')}
        </div>
      ` : `
        <div class="warning-item safe">
          ${icon('check', 14)}
          <span>No vendors flagged this URL as malicious or suspicious.</span>
        </div>
      `}

      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:var(--space-sm);">
        <span style="font-size:10px; color:var(--text-muted);">
          Last scanned: ${Utils.escapeHTML(vt.lastAnalysis)} &middot;
          ${vt.total} vendors checked
        </span>
        ${vt.permalink ? `
          <a href="${Utils.escapeHTML(vt.permalink)}" target="_blank" rel="noopener noreferrer"
            class="btn btn-secondary" style="font-size:11px; padding:4px 10px; text-decoration:none;">
            ${icon('globe', 12)} Full report
          </a>
        ` : ''}
      </div>
    </div>
  `;
}


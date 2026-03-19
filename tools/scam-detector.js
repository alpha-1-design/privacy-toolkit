/**
 * Privacy First Security Toolkit
 * Tool: Scam Message Detector — tools/scam-detector.js
 *
 * Analyzes messages for phishing, scam, and social engineering patterns.
 * 100% local — text never sent anywhere.
 */

import { Utils } from '../core/utils.js';

let patterns = null;

async function loadPatterns() {
  if (!patterns) {
    const res = await fetch('./data/scam-patterns.json');
    patterns = await res.json();
  }
}

export async function analyzeMessage(text) {
  await loadPatterns();

  if (!text || text.trim().length < 10) {
    return { error: 'Please enter a message of at least 10 characters.' };
  }

  const lower = text.toLowerCase();
  const signals = [];
  let score = 0;

  // ── Urgency language ──
  const urgencyHits = patterns.urgency_phrases.filter(p => lower.includes(p));
  if (urgencyHits.length > 0) {
    const pts = Math.min(urgencyHits.length * 8, 30);
    score += pts;
    signals.push({
      category: 'Urgency Language',
      icon: '⚡',
      level: urgencyHits.length >= 3 ? 'danger' : 'warn',
      detail: `Pressure tactics detected: "${urgencyHits.slice(0, 3).join('", "')}"`,
      explanation: 'Scammers create urgency to stop you from thinking clearly. Legitimate organizations don\'t pressure you to act "immediately."'
    });
  }

  // ── Authority impersonation ──
  const authorityHits = patterns.authority_impersonation.filter(p => lower.includes(p));
  if (authorityHits.length > 0) {
    score += Math.min(authorityHits.length * 10, 25);
    signals.push({
      category: 'Authority Impersonation',
      icon: '🏛️',
      level: 'danger',
      detail: `Impersonating: ${authorityHits.slice(0, 4).join(', ')}`,
      explanation: 'Scammers pretend to be banks, government agencies, or companies to seem trustworthy. Real organizations contact you through official channels.'
    });
  }

  // ── Payment requests ──
  const paymentHits = patterns.payment_keywords.filter(p => lower.includes(p));
  if (paymentHits.length > 0) {
    score += Math.min(paymentHits.length * 12, 35);
    signals.push({
      category: 'Payment / Credential Request',
      icon: '💳',
      level: 'danger',
      detail: `Suspicious terms: "${paymentHits.slice(0, 3).join('", "')}"`,
      explanation: 'Legitimate organizations never ask for gift cards, OTPs, or wire transfers via text or email. This is almost always fraud.'
    });
  }

  // ── Phishing phrases ──
  const phishingHits = patterns.phishing_phrases.filter(p => lower.includes(p));
  if (phishingHits.length > 0) {
    score += Math.min(phishingHits.length * 7, 25);
    signals.push({
      category: 'Phishing Language',
      icon: '🎣',
      level: phishingHits.length >= 2 ? 'danger' : 'warn',
      detail: `Phishing phrases: "${phishingHits.slice(0, 3).join('", "')}"`,
      explanation: 'These phrases are extremely common in phishing emails designed to steal your login credentials.'
    });
  }

  // ── Category detection ──
  const detectedCategories = [];
  for (const [cat, keywords] of Object.entries(patterns.categories)) {
    const hits = keywords.filter(k => lower.includes(k));
    if (hits.length >= 2) {
      detectedCategories.push({
        name: cat.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()),
        hits
      });
    }
  }

  if (detectedCategories.length > 0) {
    score += 10;
  }

  // ── URL in message ──
  const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+)/gi;
  const urls = text.match(urlRegex) || [];
  if (urls.length > 0) {
    signals.push({
      category: 'URLs Detected',
      icon: '🔗',
      level: 'warn',
      detail: `${urls.length} link${urls.length > 1 ? 's' : ''} found in message`,
      explanation: 'Links in suspicious messages often lead to phishing sites. Use the Link Analyzer tool to check them before clicking.'
    });
    score += 10;
  }

  // ── Generic salutation ──
  const genericGreetings = ['dear customer', 'dear user', 'dear member', 'dear account holder', 'dear valued'];
  if (genericGreetings.some(g => lower.includes(g))) {
    score += 8;
    signals.push({
      category: 'Generic Greeting',
      icon: '👤',
      level: 'warn',
      detail: 'Message uses a generic salutation instead of your name',
      explanation: 'Legitimate companies that have your account usually address you by name. Generic greetings suggest mass phishing.'
    });
  }

  // ── All caps / excessive punctuation ──
  const uppercaseRatio = (text.match(/[A-Z]/g) || []).length / text.length;
  if (uppercaseRatio > 0.3 && text.length > 20) {
    score += 5;
    signals.push({
      category: 'Aggressive Formatting',
      icon: '📢',
      level: 'info',
      detail: 'Message uses excessive uppercase or punctuation',
      explanation: 'Scammers use aggressive formatting to create panic and urgency.'
    });
  }

  // ── Clamp score ──
  score = Math.min(score, 100);

  const riskLevel = score >= 70 ? 'High'
                  : score >= 40 ? 'Medium'
                  : score >= 15 ? 'Low'
                  : 'Safe';

  const verdict = generateVerdict(score, signals, detectedCategories);

  return {
    score,
    riskLevel,
    signals,
    detectedCategories,
    urls,
    verdict
  };
}

function generateVerdict(score, signals, categories) {
  if (score >= 70) {
    const catNames = categories.map(c => c.name).join(', ');
    return `🚨 This message has very strong scam indicators${catNames ? ` — likely a ${catNames}` : ''}. Do NOT click any links, provide any information, or send any money. Block and report the sender.`;
  }
  if (score >= 40) {
    return `⚠️ This message contains several warning signs of a scam. Be very cautious. If it claims to be from a company, contact that company directly through their official website — not through this message.`;
  }
  if (score >= 15) {
    return `🔔 This message has a few minor scam signals. It could be legitimate, but proceed with caution. Do not share personal information or click links unless you can verify the sender independently.`;
  }
  return `✅ No significant scam indicators detected. This message appears relatively normal, but always stay alert — scammers constantly evolve their tactics.`;
}

export function renderScamDetector(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Scam Message Detector</h1>
      <p class="tool-subtitle">PHISHING · URGENCY TACTICS · IMPERSONATION · PAYMENT FRAUD</p>
      <span class="tool-privacy-badge">🔒 Text analyzed locally — never transmitted</span>
    </div>

    <div class="card">
      <div class="input-group">
        <label class="input-label" for="scam-input">Paste suspicious message, email, or text</label>
        <textarea class="input-field" id="scam-input" rows="6"
          placeholder="Your bank account will be suspended within 24 hours. Click the link below to verify your identity immediately..."></textarea>
      </div>
      <button class="btn btn-primary btn-full" id="scam-scan-btn">🔍 Analyze Message</button>
    </div>

    <div id="scam-result" style="display:none;"></div>
  `;

  const input = container.querySelector('#scam-input');
  const btn = container.querySelector('#scam-scan-btn');
  const result = container.querySelector('#scam-result');

  async function scan() {
    const text = input.value.trim();
    if (!text) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing…';

    const analysis = await analyzeMessage(text);
    renderScamResult(result, analysis);

    result.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '🔍 Analyze Message';
  }

  btn.addEventListener('click', scan);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) scan();
  });
}

function renderScamResult(container, analysis) {
  if (analysis.error) {
    container.innerHTML = `
      <div class="card">
        <div class="warning-item warn">
          <span class="warning-icon">⚠️</span>
          <span>${Utils.escapeHTML(analysis.error)}</span>
        </div>
      </div>`;
    return;
  }

  const { score, riskLevel, signals, detectedCategories, urls, verdict } = analysis;

  const riskColor = score >= 70 ? 'danger' : score >= 40 ? 'warn' : score >= 15 ? 'warn' : 'safe';
  const riskCSSLevel = score >= 70 ? 'high' : score >= 40 ? 'medium' : score >= 15 ? 'low' : 'safe';

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Message Analysis</span>
        <span class="risk-badge risk-${riskCSSLevel}">
          ${riskLevel.toUpperCase()} RISK — ${score}%
        </span>
      </div>
      <div class="result-panel-body">

        <div style="margin-bottom:var(--space-md);">
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill ${riskColor}" style="width:${score}%"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-top:4px;">
            <span>SAFE</span><span>SUSPICIOUS</span><span>SCAM</span>
          </div>
        </div>

        <div class="card" style="background:var(--surface-2); border-left: 3px solid var(--${riskColor}); margin-bottom:var(--space-md);">
          <p style="font-size:14px; line-height:1.7;">${Utils.escapeHTML(verdict)}</p>
        </div>

        ${detectedCategories.length > 0 ? `
          <div style="margin-bottom:var(--space-md);">
            <div class="card-title">Detected Scam Type${detectedCategories.length > 1 ? 's' : ''}</div>
            <div>
              ${detectedCategories.map(c => `<span class="tag-chip phishing">${Utils.escapeHTML(c.name)}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        ${signals.length > 0 ? `
          <div class="card-title">Warning Signals</div>
          <ul class="warning-list" style="margin-bottom:var(--space-md);">
            ${signals.map(s => `
              <li class="warning-item ${s.level}">
                <span class="warning-icon">${s.icon}</span>
                <div>
                  <strong>${Utils.escapeHTML(s.category)}</strong>
                  <div style="font-size:12px; color:var(--text-secondary); margin:3px 0;">${Utils.escapeHTML(s.detail)}</div>
                  <div style="font-size:12px; color:var(--text-muted); font-style:italic;">${Utils.escapeHTML(s.explanation)}</div>
                </div>
              </li>
            `).join('')}
          </ul>
        ` : ''}

        ${urls.length > 0 ? `
          <div class="card" style="background:var(--warn-dim); border:1px solid rgba(255,171,0,0.2);">
            <div class="card-title" style="color:var(--warn);">🔗 Links found in this message</div>
            ${urls.map(u => `
              <div class="code-block" style="margin-bottom:4px; color:var(--warn);">
                ${Utils.escapeHTML(Utils.truncate(u, 80))}
              </div>
            `).join('')}
            <p style="font-size:12px; color:var(--text-secondary); margin-top:var(--space-sm);">
              Use the Link Analyzer tool to check these URLs before clicking.
            </p>
          </div>
        ` : ''}

      </div>
    </div>
  `;
}

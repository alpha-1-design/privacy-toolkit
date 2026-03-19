/**
 * Privacy First Security Toolkit
 * Tool: Support — tools/support.js
 */

import { icon } from '../core/icons.js';

export function renderSupport(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Support</h1>
      <p class="tool-subtitle">GET HELP · REPORT BUGS · CONTRIBUTE</p>
    </div>

    <!-- Contact -->
    <div class="card" style="margin-bottom:var(--space-md);">
      <div class="card-title" style="display:flex; align-items:center; gap:8px;">
        ${icon('bell-alert', 16)} Contact
      </div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.8; margin-bottom:var(--space-md);">
        Have a question, found a bug, or want to suggest a feature? Reach out directly.
      </p>
      <div style="display:flex; flex-direction:column; gap:var(--space-sm);">
        <div class="fingerprint-item">
          <div class="fingerprint-key">Email</div>
          <div class="fingerprint-val">
            <a href="mailto:alphariansamuel@gmail.com" style="color:var(--accent); text-decoration:none;">
              alphariansamuel@gmail.com
            </a>
          </div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-key">GitHub</div>
          <div class="fingerprint-val">
            <a href="https://github.com/alpha-1-design/privacy-toolkit" target="_blank" rel="noopener noreferrer"
              style="color:var(--accent); text-decoration:none;">
              github.com/alpha-1-design/privacy-toolkit
            </a>
          </div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-key">Response time</div>
          <div class="fingerprint-val" style="color:var(--text-secondary);">Usually within 48 hours</div>
        </div>
      </div>
    </div>

    <!-- Report a bug -->
    <div class="card" style="margin-bottom:var(--space-md);">
      <div class="card-title" style="display:flex; align-items:center; gap:8px;">
        ${icon('exclamation-triangle', 16)} Report a Bug
      </div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.8; margin-bottom:var(--space-md);">
        Found something broken? Open an issue on GitHub with as much detail as possible — 
        what tool, what you did, what happened, and what you expected.
      </p>
      <a href="https://github.com/alpha-1-design/privacy-toolkit/issues/new" 
        target="_blank" rel="noopener noreferrer"
        class="btn btn-primary" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
        ${icon('github', 16)} Open an Issue on GitHub
      </a>
    </div>

    <!-- Contribute -->
    <div class="card" style="margin-bottom:var(--space-md);">
      <div class="card-title" style="display:flex; align-items:center; gap:8px;">
        ${icon('code-bracket', 16)} Contribute
      </div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.8; margin-bottom:var(--space-md);">
        This is an open source project and contributions are welcome. You can help by:
      </p>
      <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:var(--space-md);">
        ${[
          ['Writing a security plugin', 'Add your own detection logic without touching core code'],
          ['Improving threat data', 'Add brands, scam patterns, or tracking parameters'],
          ['Fixing bugs', 'Check the Issues tab for open bugs'],
          ['Improving documentation', 'Help make the README and guides clearer'],
        ].map(([title, desc]) => `
          <div style="display:flex; align-items:flex-start; gap:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-md); padding:10px var(--space-md);">
            <span style="color:var(--safe); margin-top:2px; flex-shrink:0;">${icon('check', 14)}</span>
            <div>
              <div style="font-size:12px; font-weight:600; color:var(--text-primary);">${title}</div>
              <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${desc}</div>
            </div>
          </div>
        `).join('')}
      </div>
      <a href="https://github.com/alpha-1-design/privacy-toolkit/blob/main/CONTRIBUTING.md"
        target="_blank" rel="noopener noreferrer"
        class="btn btn-secondary" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
        ${icon('document', 14)} Read Contributing Guide
      </a>
    </div>

    <!-- Version info -->
    <div class="card">
      <div class="card-title" style="display:flex; align-items:center; gap:8px;">
        ${icon('information-circle', 16)} Version Info
      </div>
      <div style="display:flex; flex-direction:column; gap:var(--space-sm);">
        <div class="fingerprint-item">
          <div class="fingerprint-key">Current version</div>
          <div class="fingerprint-val" style="font-family:var(--font-mono); color:var(--safe);">v1.0.0</div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-key">Tools</div>
          <div class="fingerprint-val">13 tools</div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-key">License</div>
          <div class="fingerprint-val">MIT — free to use and modify</div>
        </div>
        <div class="fingerprint-item">
          <div class="fingerprint-key">Live site</div>
          <div class="fingerprint-val">
            <a href="https://privacy-toolkit-ten.vercel.app" target="_blank" rel="noopener noreferrer"
              style="color:var(--accent); text-decoration:none;">
              privacy-toolkit-ten.vercel.app
            </a>
          </div>
        </div>
      </div>
    </div>
  `;
}

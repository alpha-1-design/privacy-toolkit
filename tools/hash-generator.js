/**
 * Privacy First Security Toolkit
 * Tool: Hash Generator — tools/hash-generator.js
 *
 * Generate cryptographic hashes of text and files.
 * Uses the Web Crypto API — 100% client-side.
 * Supports: SHA-1, SHA-256, SHA-384, SHA-512
 * Also includes HMAC generation for developers.
 */

import { Utils } from '../core/utils.js';
import { icon } from '../core/icons.js';

async function hashText(text, algorithm) {
  const enc  = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return bufferToHex(hashBuffer);
}

async function hashBuffer(buffer, algorithm) {
  const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
  return bufferToHex(hashBuffer);
}

async function hmac(text, secret, algorithm) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: algorithm },
    false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', keyMaterial, enc.encode(text));
  return bufferToHex(signature);
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

const ALGORITHMS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

export function renderHashGenerator(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Hash Generator</h1>
      <p class="tool-subtitle">SHA-1 · SHA-256 · SHA-384 · SHA-512 · HMAC · FILE HASHING</p>
      <span class="tool-privacy-badge">${icon('lock-closed', 12)} Computed locally using Web Crypto API</span>
    </div>

    <!-- Mode tabs -->
    <div style="display:flex; gap:var(--space-sm); margin-bottom:var(--space-md);">
      <button class="btn btn-primary mode-tab" data-mode="text">Text Hash</button>
      <button class="btn btn-secondary mode-tab" data-mode="file">File Hash</button>
      <button class="btn btn-secondary mode-tab" data-mode="hmac">HMAC</button>
      <button class="btn btn-secondary mode-tab" data-mode="compare">Compare</button>
    </div>

    <!-- Text hash panel -->
    <div id="panel-text">
      <div class="card">
        <div class="input-group">
          <label class="input-label">Input Text</label>
          <textarea class="input-field" id="hash-text-input" rows="4"
            placeholder="Enter text to hash..."></textarea>
        </div>
        <div style="display:flex; gap:var(--space-sm); align-items:center; margin-bottom:var(--space-sm);">
          <label class="input-label" style="margin:0; white-space:nowrap;">Output format:</label>
          <select class="input-field" id="hash-format" style="padding:6px 10px; width:auto;">
            <option value="hex">Hex (lowercase)</option>
            <option value="HEX">Hex (UPPERCASE)</option>
            <option value="base64">Base64</option>
          </select>
        </div>
        <button class="btn btn-primary btn-full" id="hash-text-btn">
          ${icon('hashtag', 16)} Generate Hashes
        </button>
      </div>
      <div id="text-hash-results" style="display:none;"></div>
    </div>

    <!-- File hash panel -->
    <div id="panel-file" style="display:none;">
      <div class="card">
        <label class="drop-zone" id="hash-drop-zone" for="hash-file-input">
          <span style="display:block; margin-bottom:var(--space-sm);">
            ${icon('document', 32)}
          </span>
          <div class="drop-zone-text">
            <strong style="color:var(--text-primary); font-size:14px;">Drop a file to hash</strong><br/>
            or click to browse<br/>
            <span style="color:var(--text-muted); font-size:11px; margin-top:6px; display:block;">File never uploaded — hashed locally</span>
          </div>
        </label>
        <input type="file" id="hash-file-input" style="display:none;" />
      </div>
      <div id="file-hash-results" style="display:none;"></div>
    </div>

    <!-- HMAC panel -->
    <div id="panel-hmac" style="display:none;">
      <div class="card">
        <div class="input-group">
          <label class="input-label">Message</label>
          <textarea class="input-field" id="hmac-message" rows="3" placeholder="Message to authenticate..."></textarea>
        </div>
        <div class="input-group">
          <label class="input-label">Secret Key</label>
          <input class="input-field" id="hmac-secret" type="password" placeholder="HMAC secret key" />
        </div>
        <div class="input-group">
          <label class="input-label">Algorithm</label>
          <select class="input-field" id="hmac-algo" style="padding:10px 12px;">
            <option value="SHA-256">HMAC-SHA-256 (recommended)</option>
            <option value="SHA-384">HMAC-SHA-384</option>
            <option value="SHA-512">HMAC-SHA-512</option>
          </select>
        </div>
        <button class="btn btn-primary btn-full" id="hmac-btn">
          ${icon('key', 16)} Generate HMAC
        </button>
      </div>
      <div id="hmac-result" style="display:none;"></div>
    </div>

    <!-- Compare panel -->
    <div id="panel-compare" style="display:none;">
      <div class="card">
        <div class="card-title">Hash Comparison — Verify File Integrity</div>
        <div class="input-group">
          <label class="input-label">Hash A</label>
          <input class="input-field" id="compare-a" type="text" placeholder="Expected hash..." spellcheck="false" />
        </div>
        <div class="input-group">
          <label class="input-label">Hash B</label>
          <input class="input-field" id="compare-b" type="text" placeholder="Computed hash..." spellcheck="false" />
        </div>
        <button class="btn btn-primary btn-full" id="compare-btn">
          ${icon('magnifying-glass', 16)} Compare Hashes
        </button>
      </div>
      <div id="compare-result" style="display:none;"></div>
    </div>

    <!-- Reference card -->
    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Algorithm Reference</div>
      <div style="display:grid; grid-template-columns:repeat(2,1fr); gap:var(--space-sm);">
        ${[
          ['SHA-1',   '160-bit', 'Legacy only. Broken for security — do not use for new applications.', 'danger'],
          ['SHA-256', '256-bit', 'Current standard. Use for checksums, HMAC, certificates.', 'safe'],
          ['SHA-384', '384-bit', 'Stronger variant of SHA-256. Good for high-security applications.', 'safe'],
          ['SHA-512', '512-bit', 'Maximum strength. Use when performance is not a constraint.', 'safe'],
        ].map(([name, bits, desc, level]) => `
          <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-md); padding:10px var(--space-md);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
              <span style="font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--text-primary);">${name}</span>
              <span class="risk-badge risk-${level === 'safe' ? 'safe' : 'high'}" style="font-size:9px; padding:2px 6px;">${bits}</span>
            </div>
            <p style="font-size:11px; color:var(--text-muted); line-height:1.5;">${desc}</p>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  // Mode switching
  container.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      container.querySelectorAll('.mode-tab').forEach(t => t.className = 'btn btn-secondary mode-tab');
      tab.className = 'btn btn-primary mode-tab';
      ['text','file','hmac','compare'].forEach(m => {
        container.querySelector(`#panel-${m}`).style.display = m === tab.dataset.mode ? 'block' : 'none';
      });
    });
  });

  // ── Text hashing ──
  container.querySelector('#hash-text-btn').addEventListener('click', async () => {
    const text    = container.querySelector('#hash-text-input').value;
    const format  = container.querySelector('#hash-format').value;
    const results = container.querySelector('#text-hash-results');

    if (!text) return;

    const hashes = {};
    for (const algo of ALGORITHMS) {
      let h = await hashText(text, algo);
      if (format === 'HEX') h = h.toUpperCase();
      if (format === 'base64') {
        const enc = new TextEncoder();
        const buf = await crypto.subtle.digest(algo, enc.encode(text));
        h = bufferToBase64(buf);
      }
      hashes[algo] = h;
    }

    renderHashResults(results, hashes, text.length, format);
    results.style.display = 'block';
  });

  // Auto-hash on input
  let debounceTimer;
  container.querySelector('#hash-text-input').addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      container.querySelector('#hash-text-btn').click();
    }, 400);
  });

  // ── File hashing ──
  const dropZone  = container.querySelector('#hash-drop-zone');
  const fileInput = container.querySelector('#hash-file-input');

  fileInput.addEventListener('change', () => { if (fileInput.files[0]) hashFile(fileInput.files[0]); });
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragging'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    if (e.dataTransfer?.files[0]) hashFile(e.dataTransfer.files[0]);
  });

  async function hashFile(file) {
    const results = container.querySelector('#file-hash-results');
    const buffer  = await Utils.readFileAsBuffer(file);
    const hashes  = {};
    for (const algo of ALGORITHMS) {
      hashes[algo] = await hashBuffer(buffer, algo);
    }
    renderFileHashResults(results, hashes, file);
    results.style.display = 'block';
  }

  // ── HMAC ──
  container.querySelector('#hmac-btn').addEventListener('click', async () => {
    const message = container.querySelector('#hmac-message').value;
    const secret  = container.querySelector('#hmac-secret').value;
    const algo    = container.querySelector('#hmac-algo').value;
    const result  = container.querySelector('#hmac-result');

    if (!message || !secret) return;

    const h = await hmac(message, secret, algo);
    result.innerHTML = `
      <div class="card">
        <div class="card-title">${algo} HMAC Signature</div>
        <div class="code-block" style="margin-bottom:var(--space-sm);">${Utils.escapeHTML(h)}</div>
        <button class="btn btn-secondary copy-hmac-btn">
          ${icon('clipboard', 14)} Copy HMAC
        </button>
      </div>`;
    result.style.display = 'block';
    result.querySelector('.copy-hmac-btn').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(h);
      Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy HMAC`);
    });
  });

  // ── Compare ──
  container.querySelector('#compare-btn').addEventListener('click', () => {
    const a = container.querySelector('#compare-a').value.trim().toLowerCase();
    const b = container.querySelector('#compare-b').value.trim().toLowerCase();
    const result = container.querySelector('#compare-result');

    if (!a || !b) return;

    const match = a === b;
    result.innerHTML = `
      <div class="card">
        <div class="warning-item ${match ? 'safe' : 'danger'}">
          ${icon(match ? 'check' : 'x-mark', 18)}
          <div>
            <strong>${match ? 'Hashes match — content is identical' : 'Hashes do NOT match — content differs'}</strong>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
              ${match
                ? 'The file or data has not been tampered with.'
                : 'The data has been modified, corrupted, or you are comparing the wrong hashes.'}
            </div>
          </div>
        </div>
      </div>`;
    result.style.display = 'block';
  });
}

function renderHashResults(container, hashes, inputLength, format) {
  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">Hash Results</span>
        <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">
          ${inputLength} char input · ${format} output
        </span>
      </div>
      <div class="result-panel-body">
        ${Object.entries(hashes).map(([algo, hash]) => `
          <div style="margin-bottom:var(--space-md);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
              <span class="card-title" style="margin:0;">${algo}</span>
              <span style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${hash.length} chars</span>
            </div>
            <div style="display:flex; gap:var(--space-sm);">
              <div class="code-block" style="flex:1; font-size:11px;">${Utils.escapeHTML(hash)}</div>
              <button class="btn btn-secondary copy-hash-btn" data-hash="${Utils.escapeHTML(hash)}" style="flex-shrink:0; padding:8px 12px;">
                ${icon('clipboard', 14)}
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  container.querySelectorAll('.copy-hash-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      await Utils.copyToClipboard(btn.dataset.hash);
      btn.innerHTML = icon('check', 14);
      btn.style.color = 'var(--safe)';
      setTimeout(() => { btn.innerHTML = icon('clipboard', 14); btn.style.color = ''; }, 2000);
    });
  });
}

function renderFileHashResults(container, hashes, file) {
  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">File Hash Results</span>
        <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">
          ${Utils.escapeHTML(file.name)} · ${Utils.formatBytes(file.size)}
        </span>
      </div>
      <div class="result-panel-body">
        ${Object.entries(hashes).map(([algo, hash]) => `
          <div style="margin-bottom:var(--space-md);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
              <span class="card-title" style="margin:0;">${algo}</span>
            </div>
            <div style="display:flex; gap:var(--space-sm);">
              <div class="code-block" style="flex:1; font-size:11px;">${Utils.escapeHTML(hash)}</div>
              <button class="btn btn-secondary copy-hash-btn" data-hash="${Utils.escapeHTML(hash)}" style="flex-shrink:0; padding:8px 12px;">
                ${icon('clipboard', 14)}
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  container.querySelectorAll('.copy-hash-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      await Utils.copyToClipboard(btn.dataset.hash);
      btn.innerHTML = icon('check', 14);
      btn.style.color = 'var(--safe)';
      setTimeout(() => { btn.innerHTML = icon('clipboard', 14); btn.style.color = ''; }, 2000);
    });
  });
}

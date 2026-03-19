/**
 * Privacy First Security Toolkit
 * Tool: Base64 Tool — tools/base64-tool.js
 *
 * Encode and decode Base64, URL-safe Base64, and files.
 * Detect and decode Base64 strings automatically.
 * 100% client-side.
 */

import { Utils } from '../core/utils.js';
import { icon } from '../core/icons.js';

function toBase64(str) {
  try { return btoa(unescape(encodeURIComponent(str))); }
  catch { return btoa(str); }
}

function fromBase64(str) {
  try { return decodeURIComponent(escape(atob(str.trim()))); }
  catch { throw new Error('Invalid Base64 string'); }
}

function toBase64URL(str) {
  return toBase64(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64URL(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return fromBase64(str);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function isLikelyBase64(str) {
  str = str.trim();
  const base64RE    = /^[A-Za-z0-9+/]+=*$/;
  const base64URLRE = /^[A-Za-z0-9\-_]+=*$/;
  return (base64RE.test(str) || base64URLRE.test(str)) && str.length % 4 === 0 || str.length > 20;
}

export function renderBase64Tool(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Base64 Tool</h1>
      <p class="tool-subtitle">ENCODE · DECODE · URL-SAFE · FILE · AUTO-DETECT</p>
      <span class="tool-privacy-badge">${icon('lock-closed', 12)} Processed entirely in browser</span>
    </div>

    <!-- Mode tabs -->
    <div style="display:flex; gap:var(--space-sm); margin-bottom:var(--space-md); flex-wrap:wrap;">
      <button class="btn btn-primary mode-tab" data-mode="text">Text</button>
      <button class="btn btn-secondary mode-tab" data-mode="file">File</button>
      <button class="btn btn-secondary mode-tab" data-mode="image">Image Preview</button>
    </div>

    <!-- Text panel -->
    <div id="panel-text">
      <div class="card">
        <div class="input-group">
          <label class="input-label">Input</label>
          <textarea class="input-field" id="b64-input" rows="5"
            placeholder="Enter text to encode, or paste Base64 to decode..."></textarea>
        </div>

        <div style="display:flex; gap:var(--space-sm); align-items:center; margin-bottom:var(--space-md); flex-wrap:wrap;">
          <label class="input-label" style="margin:0;">Format:</label>
          <select class="input-field" id="b64-format" style="padding:6px 10px; width:auto; flex-shrink:0;">
            <option value="standard">Standard Base64</option>
            <option value="url">URL-safe Base64 (no padding)</option>
          </select>
        </div>

        <div style="display:flex; gap:var(--space-sm);">
          <button class="btn btn-primary" id="encode-btn" style="flex:1;">
            ${icon('arrow-down-tray', 16)} Encode
          </button>
          <button class="btn btn-secondary" id="decode-btn" style="flex:1;">
            ${icon('code-bracket', 16)} Decode
          </button>
          <button class="btn btn-secondary" id="auto-btn" title="Auto-detect and convert">
            ${icon('arrow-path', 16)} Auto
          </button>
        </div>
      </div>

      <div id="b64-text-result" style="display:none;"></div>
    </div>

    <!-- File panel -->
    <div id="panel-file" style="display:none;">
      <div class="card">
        <label class="drop-zone" id="b64-drop-zone">
          <span style="display:block; margin-bottom:var(--space-sm);">
            ${icon('document', 32)}
          </span>
          <div class="drop-zone-text">
            <strong style="color:var(--text-primary); font-size:14px;">Drop a file to encode</strong><br/>
            or click to browse<br/>
            <span style="color:var(--text-muted); font-size:11px; margin-top:6px; display:block;">
              File is encoded to Base64 string locally
            </span>
          </div>
        </label>
        <input type="file" id="b64-file-input" style="display:none;" />
      </div>
      <div id="b64-file-result" style="display:none;"></div>
    </div>

    <!-- Image preview panel -->
    <div id="panel-image" style="display:none;">
      <div class="card">
        <div class="card-title">Base64 Image Preview</div>
        <p style="font-size:13px; color:var(--text-secondary); margin-bottom:var(--space-md);">
          Paste a Base64-encoded image string (with or without data URI prefix) to preview it.
        </p>
        <div class="input-group">
          <label class="input-label">Base64 Image Data</label>
          <textarea class="input-field" id="img-b64-input" rows="4"
            placeholder="data:image/png;base64,iVBORw0KGgo... or just the raw base64 string"></textarea>
        </div>
        <button class="btn btn-primary btn-full" id="preview-img-btn">
          ${icon('eye-slash', 16)} Preview Image
        </button>
      </div>
      <div id="img-preview-result" style="display:none;"></div>
    </div>

    <!-- Reference -->
    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">Common Use Cases</div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-sm);">
        ${[
          ['Embed images in HTML/CSS',     'data:image/png;base64,...'],
          ['JWT token payload',            'eyJhbGciOiJIUzI1...'],
          ['HTTP Basic Auth headers',      'Authorization: Basic ...'],
          ['API binary data transfer',     'JSON body with file data'],
          ['Email attachments (MIME)',      'Content-Transfer-Encoding'],
          ['URL-safe tokens',              'No +, / or = padding'],
        ].map(([use, example]) => `
          <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-md); padding:10px var(--space-md);">
            <div style="font-size:12px; color:var(--text-primary); font-weight:600; margin-bottom:3px;">${use}</div>
            <div style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${example}</div>
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
      ['text','file','image'].forEach(m => {
        container.querySelector(`#panel-${m}`).style.display = m === tab.dataset.mode ? 'block' : 'none';
      });
    });
  });

  const input  = container.querySelector('#b64-input');
  const result = container.querySelector('#b64-text-result');

  function getFormat() { return container.querySelector('#b64-format').value; }

  function showResult(output, operation, inputVal) {
    result.innerHTML = `
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">${operation} Result</span>
          <span style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">
            ${inputVal.length} → ${output.length} chars
          </span>
        </div>
        <div class="result-panel-body">
          <textarea class="input-field" rows="5" readonly style="font-size:12px; color:var(--accent);">${Utils.escapeHTML(output)}</textarea>
          <div style="display:flex; gap:var(--space-sm); margin-top:var(--space-sm);">
            <button class="btn btn-primary copy-result-btn" data-val="${Utils.escapeHTML(output)}" style="flex:1;">
              ${icon('clipboard', 14)} Copy Result
            </button>
            <button class="btn btn-secondary use-as-input-btn" data-val="${Utils.escapeHTML(output)}">
              ${icon('arrow-path', 14)} Use as Input
            </button>
          </div>
        </div>
      </div>`;
    result.style.display = 'block';

    result.querySelector('.copy-result-btn').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(output);
      Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Result`);
    });

    result.querySelector('.use-as-input-btn').addEventListener('click', () => {
      input.value = output;
    });
  }

  function showError(msg) {
    result.innerHTML = `
      <div class="card">
        <div class="warning-item danger">
          ${icon('x-mark', 16)}
          <span>${Utils.escapeHTML(msg)}</span>
        </div>
      </div>`;
    result.style.display = 'block';
  }

  // Encode
  container.querySelector('#encode-btn').addEventListener('click', () => {
    const val = input.value;
    if (!val) return;
    const fmt = getFormat();
    const out = fmt === 'url' ? toBase64URL(val) : toBase64(val);
    showResult(out, `Encoded (${fmt === 'url' ? 'URL-safe' : 'Standard'})`, val);
  });

  // Decode
  container.querySelector('#decode-btn').addEventListener('click', () => {
    const val = input.value.trim();
    if (!val) return;
    try {
      const fmt = getFormat();
      const out = fmt === 'url' ? fromBase64URL(val) : fromBase64(val);
      showResult(out, 'Decoded', val);
    } catch (e) {
      showError('Invalid Base64 string. Make sure the input is valid Base64.');
    }
  });

  // Auto detect
  container.querySelector('#auto-btn').addEventListener('click', () => {
    const val = input.value.trim();
    if (!val) return;
    if (isLikelyBase64(val)) {
      try {
        const out = fromBase64(val);
        showResult(out, 'Auto-Decoded', val);
        return;
      } catch {}
    }
    const out = toBase64(val);
    showResult(out, 'Auto-Encoded', val);
  });

  // File encoding
  const dropZone  = container.querySelector('#b64-drop-zone');
  const fileInput = container.querySelector('#b64-file-input');

  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => { if (fileInput.files[0]) encodeFile(fileInput.files[0]); });
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragging'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    if (e.dataTransfer?.files[0]) encodeFile(e.dataTransfer.files[0]);
  });

  async function encodeFile(file) {
    const fileResult = container.querySelector('#b64-file-result');
    const dataURL = await fileToBase64(file);
    const b64Only = dataURL.split(',')[1];

    fileResult.innerHTML = `
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">File Encoded</span>
          <span style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">
            ${Utils.escapeHTML(file.name)} · ${Utils.formatBytes(file.size)}
          </span>
        </div>
        <div class="result-panel-body">
          <div class="card-title">Data URI (with MIME type)</div>
          <div class="code-block" style="font-size:10px; max-height:80px; overflow:hidden; margin-bottom:var(--space-sm);">
            ${Utils.escapeHTML(dataURL.substring(0, 200))}…
          </div>
          <div style="display:flex; gap:var(--space-sm); margin-bottom:var(--space-md);">
            <button class="btn btn-primary copy-data-uri-btn" style="flex:1;">
              ${icon('clipboard', 14)} Copy Data URI
            </button>
            <button class="btn btn-secondary copy-b64-only-btn" style="flex:1;">
              ${icon('clipboard', 14)} Copy Base64 Only
            </button>
          </div>
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">
            Size: ${Utils.formatBytes(file.size)} → ${Utils.formatBytes(b64Only.length)} base64
            (${Math.round((b64Only.length / file.size - 1) * 100)}% overhead)
          </div>
        </div>
      </div>`;
    fileResult.style.display = 'block';

    fileResult.querySelector('.copy-data-uri-btn').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(dataURL);
      Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Data URI`);
    });
    fileResult.querySelector('.copy-b64-only-btn').addEventListener('click', async (e) => {
      await Utils.copyToClipboard(b64Only);
      Utils.showCopyFeedback(e.target, `${icon('clipboard', 14)} Copy Base64 Only`);
    });
  }

  // Image preview
  container.querySelector('#preview-img-btn').addEventListener('click', () => {
    const val = container.querySelector('#img-b64-input').value.trim();
    const imgResult = container.querySelector('#img-preview-result');

    const src = val.startsWith('data:') ? val : `data:image/png;base64,${val}`;

    imgResult.innerHTML = `
      <div class="card">
        <div class="card-title">Image Preview</div>
        <div style="text-align:center;">
          <img src="${Utils.escapeHTML(src)}"
            style="max-width:100%; max-height:400px; border-radius:var(--radius-md); border:1px solid var(--border);"
            onerror="this.parentElement.innerHTML='<div class=warning-item danger>${icon('x-mark', 16)} <span>Not a valid Base64 image.</span></div>'" />
        </div>
      </div>`;
    imgResult.style.display = 'block';
  });
}

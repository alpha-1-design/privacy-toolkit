/**
 * Privacy First Security Toolkit
 * Tool: Text Encryption — tools/encryption-tool.js
 *
 * AES-256-GCM encryption using the Web Crypto API.
 * Encryption and decryption are 100% client-side.
 * No keys, passwords, or encrypted data leave the browser.
 */

import { Utils } from '../core/utils.js';

// ── AES-256-GCM encrypt ──
async function encrypt(plaintext, password) {
  const enc = new TextEncoder();
  const salt = Utils.randomBytes(16);
  const iv   = Utils.randomBytes(12);

  // Derive key from password using PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );

  // Pack: salt (16) + iv (12) + ciphertext
  const packed = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(new Uint8Array(ciphertext), 28);

  return btoa(String.fromCharCode(...packed));
}

// ── AES-256-GCM decrypt ──
async function decrypt(b64, password) {
  const packed = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt   = packed.slice(0, 16);
  const iv     = packed.slice(16, 28);
  const data   = packed.slice(28);

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  return new TextDecoder().decode(plaintext);
}

export function renderEncryptionTool(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Text Encryption</h1>
      <p class="tool-subtitle">AES-256-GCM · PBKDF2 KEY DERIVATION · 250,000 ITERATIONS</p>
      <span class="tool-privacy-badge">🔒 Encryption happens locally — nothing sent anywhere</span>
    </div>

    <!-- Mode tabs -->
    <div style="display:flex; gap:var(--space-sm); margin-bottom:var(--space-md);">
      <button class="btn btn-primary mode-tab" data-mode="encrypt">🔐 Encrypt</button>
      <button class="btn btn-secondary mode-tab" data-mode="decrypt">🔓 Decrypt</button>
    </div>

    <!-- Encrypt panel -->
    <div id="panel-encrypt">
      <div class="card">
        <div class="input-group">
          <label class="input-label">Message to encrypt</label>
          <textarea class="input-field" id="enc-input" rows="5" placeholder="Type your secret message here..."></textarea>
        </div>
        <div class="input-group">
          <label class="input-label">Encryption password</label>
          <input class="input-field" id="enc-password" type="password" placeholder="Strong password — keep this safe!" />
        </div>
        <div class="input-group">
          <label class="input-label">Confirm password</label>
          <input class="input-field" id="enc-confirm" type="password" placeholder="Repeat password" />
        </div>
        <button class="btn btn-primary btn-full" id="enc-btn">🔐 Encrypt Message</button>
      </div>

      <div id="enc-result" style="display:none;">
        <div class="card">
          <div class="card-title">Encrypted Output (AES-256-GCM)</div>
          <div class="encrypted-output" id="enc-output"></div>
          <div style="display:flex; gap:var(--space-sm); margin-top:var(--space-md);">
            <button class="btn btn-primary" id="copy-enc-btn" style="flex:1;">📋 Copy Encrypted Text</button>
            <button class="btn btn-secondary" id="clear-enc-btn">🗑️ Clear</button>
          </div>
          <p style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-top:var(--space-sm); line-height:1.6;">
            Share this encrypted text safely. Only someone with the correct password can decrypt it.
            The password is NEVER stored — if you lose it, the message cannot be recovered.
          </p>
        </div>
      </div>
    </div>

    <!-- Decrypt panel -->
    <div id="panel-decrypt" style="display:none;">
      <div class="card">
        <div class="input-group">
          <label class="input-label">Encrypted message</label>
          <textarea class="input-field" id="dec-input" rows="5" placeholder="Paste encrypted text here..."></textarea>
        </div>
        <div class="input-group">
          <label class="input-label">Decryption password</label>
          <input class="input-field" id="dec-password" type="password" placeholder="Enter the password used to encrypt" />
        </div>
        <button class="btn btn-primary btn-full" id="dec-btn">🔓 Decrypt Message</button>
      </div>

      <div id="dec-result" style="display:none;">
        <div class="card">
          <div class="card-title">Decrypted Message</div>
          <div id="dec-error" style="display:none;" class="warning-item danger" style="margin-bottom:var(--space-md);">
            <span class="warning-icon">❌</span>
            <span>Decryption failed. Wrong password or corrupted data.</span>
          </div>
          <textarea class="input-field" id="dec-output" rows="5" readonly style="color:var(--safe);"></textarea>
          <button class="btn btn-secondary" id="copy-dec-btn" style="margin-top:var(--space-sm);">📋 Copy Decrypted Text</button>
        </div>
      </div>
    </div>

    <!-- Info card -->
    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">How it works</div>
      <div class="grid-2" style="gap:var(--space-sm);">
        ${[
          ['AES-256-GCM', 'Military-grade authenticated encryption'],
          ['PBKDF2', '250,000 iterations for key derivation'],
          ['Random Salt', '128-bit salt prevents rainbow tables'],
          ['Random IV', 'Unique per message — prevents pattern analysis'],
        ].map(([tech, desc]) => `
          <div style="padding:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:var(--radius-md);">
            <div style="font-family:var(--font-mono); font-size:11px; color:var(--accent); margin-bottom:3px;">${tech}</div>
            <div style="font-size:12px; color:var(--text-muted);">${desc}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  // Mode switching
  container.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      container.querySelectorAll('.mode-tab').forEach(t => {
        t.className = 'btn btn-secondary mode-tab';
      });
      tab.className = 'btn btn-primary mode-tab';

      const mode = tab.dataset.mode;
      container.querySelector('#panel-encrypt').style.display = mode === 'encrypt' ? 'block' : 'none';
      container.querySelector('#panel-decrypt').style.display = mode === 'decrypt' ? 'block' : 'none';
    });
  });

  // Encrypt
  container.querySelector('#enc-btn').addEventListener('click', async () => {
    const text = container.querySelector('#enc-input').value.trim();
    const pass = container.querySelector('#enc-password').value;
    const conf = container.querySelector('#enc-confirm').value;
    const btn  = container.querySelector('#enc-btn');

    if (!text) return alert('Please enter a message to encrypt.');
    if (!pass) return alert('Please enter a password.');
    if (pass !== conf) return alert('Passwords do not match.');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Encrypting…';

    try {
      const encrypted = await encrypt(text, pass);
      container.querySelector('#enc-output').textContent = encrypted;
      container.querySelector('#enc-result').style.display = 'block';
      container.querySelector('#enc-input').value = '';
      container.querySelector('#enc-password').value = '';
      container.querySelector('#enc-confirm').value = '';
    } catch (err) {
      alert('Encryption failed: ' + err.message);
    }

    btn.disabled = false;
    btn.textContent = '🔐 Encrypt Message';
  });

  // Copy encrypted
  container.querySelector('#copy-enc-btn').addEventListener('click', async (e) => {
    const text = container.querySelector('#enc-output').textContent;
    await Utils.copyToClipboard(text);
    Utils.showCopyFeedback(e.target, '📋 Copy Encrypted Text');
  });

  // Clear
  container.querySelector('#clear-enc-btn').addEventListener('click', () => {
    container.querySelector('#enc-result').style.display = 'none';
    container.querySelector('#enc-output').textContent = '';
  });

  // Decrypt
  container.querySelector('#dec-btn').addEventListener('click', async () => {
    const text = container.querySelector('#dec-input').value.trim();
    const pass = container.querySelector('#dec-password').value;
    const btn  = container.querySelector('#dec-btn');

    if (!text || !pass) return alert('Please enter encrypted text and password.');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Decrypting…';

    try {
      const decrypted = await decrypt(text, pass);
      container.querySelector('#dec-output').value = decrypted;
      container.querySelector('#dec-error').style.display = 'none';
      container.querySelector('#dec-result').style.display = 'block';
    } catch {
      container.querySelector('#dec-error').style.display = 'flex';
      container.querySelector('#dec-result').style.display = 'block';
      container.querySelector('#dec-output').value = '';
    }

    btn.disabled = false;
    btn.textContent = '🔓 Decrypt Message';
  });

  // Copy decrypted
  container.querySelector('#copy-dec-btn').addEventListener('click', async (e) => {
    const text = container.querySelector('#dec-output').value;
    await Utils.copyToClipboard(text);
    Utils.showCopyFeedback(e.target, '📋 Copy Decrypted Text');
  });
}

/**
 * Privacy First Security Toolkit
 * Tool: QR Scanner — tools/qr-scanner.js
 *
 * Decodes QR codes from uploaded images.
 * QR data is analyzed locally.
 *
 * Uses the jsQR library (loaded from CDN, or bundled locally).
 */

import { Utils } from '../core/utils.js';
import { analyzeURL } from './link-analyzer.js';

// jsQR is loaded via script tag in index.html
// Fallback message if not available

export function renderQRScanner(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">QR Code Scanner</h1>
      <p class="tool-subtitle">DECODE · ANALYZE DESTINATION · DETECT PHISHING LINKS</p>
      <span class="tool-privacy-badge">🔒 QR data never leaves your device</span>
    </div>

    <div class="card">
      <label class="drop-zone" id="qr-drop-zone">
        <span class="drop-zone-icon">📷</span>
        <div class="drop-zone-text">
          <strong style="color:var(--text-primary); font-size:14px;">Drop QR code image here</strong><br/>
          or click to upload<br/>
          <span style="color:var(--text-muted); font-size:11px; margin-top:6px; display:block;">
            Supports PNG, JPG, GIF, WebP. Never uploaded.
          </span>
        </div>
      </label>
      <input type="file" id="qr-file-input" accept="image/*" style="display:none;" />

      <!-- Camera capture -->
      <div style="text-align:center; margin-top:var(--space-md);">
        <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">or</span>
      </div>
      <button class="btn btn-secondary btn-full" id="qr-camera-btn" style="margin-top:var(--space-sm);">
        📸 Use Camera to Scan
      </button>
    </div>

    <!-- Camera view -->
    <div id="qr-camera-panel" style="display:none;">
      <div class="card">
        <div class="card-title">📷 Camera Scanner</div>
        <div style="position:relative; background:var(--black); border-radius:var(--radius-md); overflow:hidden; margin-bottom:var(--space-md);">
          <video id="qr-video" style="width:100%; display:block;" playsinline autoplay></video>
          <canvas id="qr-canvas" style="display:none;"></canvas>
          <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
               width:180px;height:180px;border:2px solid var(--accent);border-radius:8px;
               box-shadow:0 0 0 9999px rgba(0,0,0,0.4);pointer-events:none;"></div>
        </div>
        <button class="btn btn-danger btn-full" id="qr-stop-btn">⬛ Stop Camera</button>
      </div>
    </div>

    <!-- Preview and result -->
    <div id="qr-preview-panel" style="display:none;">
      <div class="card">
        <div class="card-title">QR Image</div>
        <img id="qr-preview-img" style="max-width:200px; border-radius:var(--radius-md); border:1px solid var(--border); display:block; margin:0 auto var(--space-md);" />
      </div>
    </div>

    <div id="qr-result" style="display:none;"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">⚠️ QR Code Safety Tips</div>
      <ul class="warning-list">
        <li class="warning-item warn"><span class="warning-icon">🎭</span><span><strong>Sticker overlay attacks</strong> — Criminals place fake QR stickers over legitimate ones in public places.</span></li>
        <li class="warning-item warn"><span class="warning-icon">🔗</span><span><strong>Hidden redirects</strong> — A QR code may redirect through multiple URLs before reaching a malicious destination.</span></li>
        <li class="warning-item info"><span class="warning-icon">✅</span><span><strong>Always check the URL</strong> — Before visiting a QR destination, verify the domain looks legitimate.</span></li>
      </ul>
    </div>
  `;

  const dropZone = container.querySelector('#qr-drop-zone');
  const fileInput = container.querySelector('#qr-file-input');
  const cameraBtn = container.querySelector('#qr-camera-btn');
  const stopBtn = container.querySelector('#qr-stop-btn');
  const cameraPanel = container.querySelector('#qr-camera-panel');
  const previewPanel = container.querySelector('#qr-preview-panel');
  const previewImg = container.querySelector('#qr-preview-img');
  const result = container.querySelector('#qr-result');

  let cameraStream = null;
  let scanInterval = null;

  // File drop/click
  dropZone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) processImage(fileInput.files[0]);
  });

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragging');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    if (e.dataTransfer?.files[0]) processImage(e.dataTransfer.files[0]);
  });

  // Camera
  cameraBtn.addEventListener('click', async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      alert('Camera not supported in this browser or requires HTTPS.');
      return;
    }
    try {
      cameraStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      const video = container.querySelector('#qr-video');
      video.srcObject = cameraStream;
      cameraPanel.style.display = 'block';
      startCameraScan(video, container.querySelector('#qr-canvas'));
    } catch {
      alert('Camera permission denied.');
    }
  });

  stopBtn.addEventListener('click', stopCamera);

  function stopCamera() {
    if (scanInterval) clearInterval(scanInterval);
    if (cameraStream) {
      cameraStream.getTracks().forEach(t => t.stop());
      cameraStream = null;
    }
    cameraPanel.style.display = 'none';
  }

  function startCameraScan(video, canvas) {
    scanInterval = setInterval(() => {
      if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (typeof jsQR === 'undefined') return;

      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        clearInterval(scanInterval);
        stopCamera();
        handleQRData(code.data, null);
      }
    }, 200);
  }

  async function processImage(file) {
    if (!file.type.startsWith('image/')) {
      result.innerHTML = '<div class="card"><div class="warning-item danger"><span>❌</span><span>Please upload an image file.</span></div></div>';
      result.style.display = 'block';
      return;
    }

    const dataURL = await Utils.readFileAsDataURL(file);
    previewImg.src = dataURL;
    previewPanel.style.display = 'block';

    // Decode QR using jsQR
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (typeof jsQR === 'undefined') {
        renderQRResult(result, {
          error: 'QR decoder library not loaded. Please run with the local server (python server.py) to enable this feature.'
        });
        result.style.display = 'block';
        return;
      }

      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (!code) {
        renderQRResult(result, { error: 'No QR code detected in this image. Try a clearer or higher-resolution image.' });
      } else {
        handleQRData(code.data, null);
      }
      result.style.display = 'block';
    };
    img.src = dataURL;
  }

  async function handleQRData(data, canvas) {
    result.style.display = 'block';

    const isURL = data.startsWith('http://') || data.startsWith('https://') ||
                  data.startsWith('www.') || data.includes('://');

    if (isURL) {
      const analysis = await analyzeURL(data);
      renderQRResult(result, { data, isURL: true, analysis });
    } else {
      renderQRResult(result, { data, isURL: false });
    }
  }
}

function renderQRResult(container, res) {
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

  const { data, isURL, analysis } = res;

  if (!isURL) {
    container.innerHTML = `
      <div class="result-panel">
        <div class="result-panel-header">
          <span class="result-panel-title">QR Code Decoded</span>
          <span class="risk-badge risk-safe">TEXT CONTENT</span>
        </div>
        <div class="result-panel-body">
          <div class="card-title">QR Content</div>
          <div class="code-block">${Utils.escapeHTML(data)}</div>
          <p style="font-size:12px; color:var(--text-muted); margin-top:var(--space-sm);">
            This QR code contains text, not a URL. No link risk detected.
          </p>
        </div>
      </div>`;
    return;
  }

  const riskLevel = analysis.riskLevel || 'safe';
  const riskColor = riskLevel === 'safe' || riskLevel === 'low' ? 'safe'
                  : riskLevel === 'medium' ? 'warn' : 'danger';

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">QR Link Analysis</span>
        <span class="risk-badge risk-${riskLevel}">${riskLevel.toUpperCase()} — ${analysis.riskScore}%</span>
      </div>
      <div class="result-panel-body">
        <div class="card-title">QR Destination</div>
        <div class="code-block" style="margin-bottom:var(--space-md);">${Utils.escapeHTML(data)}</div>

        <div class="progress-bar-wrap" style="margin-bottom:var(--space-md);">
          <div class="progress-bar-fill ${riskColor}" style="width:${analysis.riskScore}%"></div>
        </div>

        <div class="card" style="background:var(--surface-2); border-left:3px solid var(--${riskColor});">
          <p style="font-size:14px; line-height:1.6;">${Utils.escapeHTML(analysis.explanation || 'Analysis complete.')}</p>
        </div>

        ${[...(analysis.warnings || []), ...(analysis.info || [])].map(w => `
          <div class="warning-item ${w.level}" style="margin-top:var(--space-sm);">
            <span class="warning-icon">${w.icon}</span>
            <div>
              <strong>${Utils.escapeHTML(w.title)}</strong>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">${Utils.escapeHTML(w.detail)}</div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

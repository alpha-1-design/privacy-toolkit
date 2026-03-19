/**
 * Privacy First Security Toolkit
 * Tool: Digital Fingerprint Viewer — tools/fingerprint-viewer.js
 *
 * Shows what websites can learn about your browser.
 * Educational privacy tool — 100% local.
 */

import { Utils } from '../core/utils.js';

export function gatherFingerprint() {
  const nav = navigator;
  const screen = window.screen;

  const data = {
    // Browser
    userAgent:        nav.userAgent,
    browser:          detectBrowser(),
    browserVersion:   detectBrowserVersion(),
    platform:         nav.platform || 'Unknown',
    vendor:           nav.vendor || 'Unknown',

    // Language
    language:         nav.language,
    languages:        (nav.languages || [nav.language]).join(', '),

    // Screen
    screenWidth:      screen.width,
    screenHeight:     screen.height,
    colorDepth:       screen.colorDepth + '-bit',
    pixelRatio:       window.devicePixelRatio || 1,

    // Window
    windowWidth:      window.innerWidth,
    windowHeight:     window.innerHeight,

    // Timezone
    timezone:         Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset:   new Date().getTimezoneOffset(),

    // Hardware
    cpuCores:         nav.hardwareConcurrency || 'Unknown',
    deviceMemory:     nav.deviceMemory ? nav.deviceMemory + ' GB' : 'Hidden',
    touchPoints:      nav.maxTouchPoints,

    // Connection
    connectionType:   nav.connection?.effectiveType || 'Unknown',
    cookiesEnabled:   nav.cookieEnabled,
    doNotTrack:       nav.doNotTrack === '1' ? 'Yes ✓' : 'No ✗',
    onlineStatus:     nav.onLine ? 'Online' : 'Offline',

    // Capabilities
    webGL:            detectWebGL(),
    canvas:           detectCanvas(),
    webRTC:           typeof RTCPeerConnection !== 'undefined' ? 'Available' : 'Blocked',
    serviceWorker:    'serviceWorker' in nav ? 'Supported' : 'Not supported',
    localStorage:     localStorageAvailable() ? 'Available' : 'Blocked',
    sessionStorage:   sessionStorageAvailable() ? 'Available' : 'Blocked',
    indexedDB:        typeof indexedDB !== 'undefined' ? 'Available' : 'Blocked',

    // Fonts (basic detection)
    installedFonts:   detectFonts(),
  };

  const risk = assessPrivacyRisk(data);
  return { data, risk };
}

function detectBrowser() {
  const ua = navigator.userAgent;
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Edg/')) return 'Microsoft Edge';
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Safari')) return 'Safari';
  if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
  return 'Unknown';
}

function detectBrowserVersion() {
  const ua = navigator.userAgent;
  const matches = ua.match(/(firefox|chrome|safari|edg|opera|opr)\/(\d+)/i);
  if (matches) return matches[2];
  return 'Unknown';
}

function detectWebGL() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const info = gl.getExtension('WEBGL_debug_renderer_info');
      if (info) {
        const renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
        return renderer ? `Available (${renderer.substring(0, 40)})` : 'Available';
      }
      return 'Available';
    }
    return 'Not available';
  } catch {
    return 'Blocked';
  }
}

function detectCanvas() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) return 'Available (can be fingerprinted)';
    return 'Not available';
  } catch {
    return 'Blocked';
  }
}

function localStorageAvailable() {
  try { localStorage.setItem('_test', '1'); localStorage.removeItem('_test'); return true; }
  catch { return false; }
}

function sessionStorageAvailable() {
  try { sessionStorage.setItem('_test', '1'); sessionStorage.removeItem('_test'); return true; }
  catch { return false; }
}

function detectFonts() {
  // Basic font detection without Canvas fingerprinting
  const testFonts = ['Arial', 'Georgia', 'Verdana', 'Times New Roman', 'Courier New', 'Comic Sans MS'];
  const detected = [];
  const span = document.createElement('span');
  span.style.cssText = 'position:absolute;visibility:hidden;font-size:72px;';
  span.textContent = 'mMMmm';
  document.body.appendChild(span);

  const baseWidths = {};
  span.style.fontFamily = 'monospace';
  baseWidths.monospace = span.offsetWidth;
  span.style.fontFamily = 'serif';
  baseWidths.serif = span.offsetWidth;

  for (const font of testFonts) {
    span.style.fontFamily = `'${font}', monospace`;
    if (span.offsetWidth !== baseWidths.monospace) detected.push(font);
  }

  document.body.removeChild(span);
  return detected.length > 0 ? detected.join(', ') : 'Unable to detect';
}

function assessPrivacyRisk(data) {
  const exposures = [];

  if (data.doNotTrack === 'No ✗') {
    exposures.push({ text: 'Do Not Track is disabled — advertisers can track you freely', level: 'warn' });
  }
  if (data.webGL.includes('Available') && !data.webGL.includes('Blocked')) {
    exposures.push({ text: 'WebGL exposes GPU info which can be used to fingerprint you', level: 'warn' });
  }
  if (data.canvas.includes('Available')) {
    exposures.push({ text: 'Canvas API allows unique fingerprinting of your browser', level: 'warn' });
  }
  if (data.webRTC === 'Available') {
    exposures.push({ text: 'WebRTC may leak your real IP address even behind a VPN', level: 'danger' });
  }
  if (data.localStorage === 'Available') {
    exposures.push({ text: 'LocalStorage allows persistent tracking without cookies', level: 'info' });
  }
  if (data.cookiesEnabled) {
    exposures.push({ text: 'Cookies are enabled and can be used for tracking', level: 'info' });
  }

  return exposures;
}

export function renderFingerprintViewer(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const { data, risk } = gatherFingerprint();

  const sections = [
    {
      title: 'Browser Identity',
      icon: '🌐',
      items: [
        ['Browser',          data.browser],
        ['Version',          data.browserVersion],
        ['Platform',         data.platform],
        ['User Agent',       Utils.truncate(data.userAgent, 60)],
      ]
    },
    {
      title: 'Display & Screen',
      icon: '🖥️',
      items: [
        ['Screen Size',      `${data.screenWidth} × ${data.screenHeight}`],
        ['Window Size',      `${data.windowWidth} × ${data.windowHeight}`],
        ['Pixel Ratio',      `${data.pixelRatio}×`],
        ['Color Depth',      data.colorDepth],
      ]
    },
    {
      title: 'Language & Location',
      icon: '🌍',
      items: [
        ['Language',         data.language],
        ['All Languages',    data.languages],
        ['Timezone',         data.timezone],
        ['UTC Offset',       `UTC${data.timezoneOffset > 0 ? '-' : '+'}${Math.abs(data.timezoneOffset / 60)}h`],
      ]
    },
    {
      title: 'Hardware',
      icon: '💻',
      items: [
        ['CPU Cores',        data.cpuCores],
        ['Memory',           data.deviceMemory],
        ['Touch Points',     data.touchPoints],
        ['Connection',       data.connectionType],
      ]
    },
    {
      title: 'Privacy Settings',
      icon: '🔒',
      items: [
        ['Do Not Track',     data.doNotTrack],
        ['Cookies',          data.cookiesEnabled ? 'Enabled' : 'Disabled'],
        ['LocalStorage',     data.localStorage],
        ['SessionStorage',   data.sessionStorage],
      ]
    },
    {
      title: 'Fingerprinting APIs',
      icon: '🕵️',
      items: [
        ['Canvas',           data.canvas],
        ['WebGL',            Utils.truncate(data.webGL, 50)],
        ['WebRTC',           data.webRTC],
        ['IndexedDB',        data.indexedDB],
      ]
    }
  ];

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Digital Fingerprint Viewer</h1>
      <p class="tool-subtitle">SEE WHAT WEBSITES KNOW ABOUT YOU · EDUCATIONAL ONLY</p>
      <span class="tool-privacy-badge">🔒 All info gathered locally — nothing sent anywhere</span>
    </div>

    ${risk.length > 0 ? `
      <div class="card" style="margin-bottom:var(--space-md);">
        <div class="card-title">⚠️ Privacy Risks Detected</div>
        <ul class="warning-list">
          ${risk.map(r => `
            <li class="warning-item ${r.level}">
              <span class="warning-icon">${r.level === 'danger' ? '🚨' : r.level === 'warn' ? '⚠️' : 'ℹ️'}</span>
              <span>${Utils.escapeHTML(r.text)}</span>
            </li>
          `).join('')}
        </ul>
      </div>
    ` : ''}

    <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-md);">
      ${sections.map(section => `
        <div class="card">
          <div class="card-title">${section.icon} ${section.title}</div>
          <div style="display:flex; flex-direction:column; gap:var(--space-sm);">
            ${section.items.map(([key, val]) => `
              <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:var(--space-sm);">
                <span style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted); flex-shrink:0; padding-top:1px;">${Utils.escapeHTML(key)}</span>
                <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-primary); text-align:right; word-break:break-all;">${Utils.escapeHTML(String(val))}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `).join('')}
    </div>

    <div class="card" style="margin-top:var(--space-md); background:var(--surface-2);">
      <div class="card-title">What does this mean?</div>
      <p style="font-size:13px; color:var(--text-secondary); line-height:1.7;">
        Every website you visit can see much of this information without you knowing.
        Combined together, these data points create a unique "fingerprint" that can identify
        you across the internet — even without cookies, accounts, or login. 
        Using a privacy browser like <strong>Firefox</strong> with <strong>uBlock Origin</strong>
        reduces fingerprinting significantly.
      </p>
    </div>
  `;
}

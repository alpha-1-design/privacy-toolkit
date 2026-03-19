/**
 * Privacy First Security Toolkit
 * Core Utilities — core/utils.js
 * 
 * Shared helpers used across all tools.
 * No data is stored or transmitted.
 */

export const Utils = {

  /**
   * Safely parse a URL string
   * Returns URL object or null
   */
  parseURL(str) {
    str = str.trim();
    if (!str.startsWith('http://') && !str.startsWith('https://')) {
      str = 'https://' + str;
    }
    try { return new URL(str); }
    catch { return null; }
  },

  /**
   * Extract domain from URL
   */
  getDomain(urlStr) {
    const url = this.parseURL(urlStr);
    if (!url) return null;
    return url.hostname.replace(/^www\./, '');
  },

  /**
   * Get TLD from domain
   */
  getTLD(domain) {
    const parts = domain.split('.');
    return '.' + parts[parts.length - 1];
  },

  /**
   * Remove tracking parameters from URL
   */
  async cleanTrackingParams(urlStr) {
    const url = this.parseURL(urlStr);
    if (!url) return null;

    let data;
    try {
      const res = await fetch('./data/tracking-params.json');
      data = await res.json();
    } catch {
      return url.toString();
    }

    const removed = [];
    const params = new URLSearchParams(url.search);
    const cleanParams = new URLSearchParams();

    for (const [key, value] of params) {
      if (data.params.includes(key.toLowerCase())) {
        removed.push(key);
      } else {
        cleanParams.append(key, value);
      }
    }

    const clean = cleanParams.toString();
    url.search = clean ? '?' + clean : '';

    return { cleanURL: url.toString(), removed };
  },

  /**
   * Generate cryptographically secure random bytes
   */
  randomBytes(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  },

  /**
   * Generate random integer between min and max inclusive
   */
  randomInt(min, max) {
    const range = max - min + 1;
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return min + (buf[0] % range);
  },

  /**
   * Calculate Shannon entropy of a string (password strength)
   */
  entropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return Object.values(freq).reduce((e, f) => {
      const p = f / len;
      return e - p * Math.log2(p);
    }, 0);
  },

  /**
   * Estimate crack time from password entropy
   */
  crackTime(password) {
    const chars = new Set(password);
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 32;

    const combinations = Math.pow(pool, password.length);
    const guessesPerSec = 1e12; // Modern GPU: 1 trillion/sec

    const seconds = combinations / guessesPerSec;
    return this.formatTime(seconds);
  },

  formatTime(seconds) {
    if (seconds < 1) return 'Instantly';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds/60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds/3600)} hours`;
    if (seconds < 2592000) return `${Math.round(seconds/86400)} days`;
    if (seconds < 31536000) return `${Math.round(seconds/2592000)} months`;
    if (seconds < 3153600000) return `${Math.round(seconds/31536000)} years`;
    if (seconds < 315360000000) return `${Math.round(seconds/3153600000)} centuries`;
    return 'Practically forever';
  },

  /**
   * Detect homograph characters (cyrillic/greek lookalikes)
   */
  hasHomographChars(str) {
    const homographMap = {
      'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
      'х': 'x', 'і': 'i', 'ӏ': 'l', 'ԁ': 'd', 'ԝ': 'w',
      'ʏ': 'y', 'ɡ': 'g', 'ο': 'o', 'ρ': 'p', 'ε': 'e',
      'α': 'a', 'β': 'b', 'ν': 'v', 'μ': 'u', 'κ': 'k',
      'ℓ': 'l', '℮': 'e', '⁰': '0', '¹': '1', '²': '2'
    };

    const found = [];
    for (const char of str) {
      if (homographMap[char]) {
        found.push({ original: char, looksLike: homographMap[char] });
      }
    }
    return found;
  },

  /**
   * Check if string contains punycode (xn--)
   */
  hasPunycode(domain) {
    return domain.includes('xn--');
  },

  /**
   * Copy text to clipboard
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fallback for older browsers
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      return true;
    }
  },

  /**
   * Format bytes to human readable
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  },

  /**
   * Simple HTML escaping to prevent XSS
   */
  escapeHTML(str) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return String(str).replace(/[&<>"']/g, m => map[m]);
  },

  /**
   * Truncate string to max length
   */
  truncate(str, max = 60) {
    if (str.length <= max) return str;
    return str.slice(0, max) + '…';
  },

  /**
   * Read file as ArrayBuffer
   */
  readFileAsBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  },

  /**
   * Read file as text
   */
  readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  },

  /**
   * Read file as data URL (for images)
   */
  readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  },

  /**
   * Debounce function
   */
  debounce(fn, delay) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  },

  /**
   * Show copy feedback on button
   */
  showCopyFeedback(btn, originalText = 'Copy') {
    btn.textContent = '✓ Copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = originalText;
      btn.classList.remove('copied');
    }, 2000);
  }
};

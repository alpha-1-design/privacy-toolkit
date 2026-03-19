/**
 * Privacy First Security Toolkit
 * Developer SDK — sdk/toolkit.js
 *
 * Modular API for integrating toolkit features into other applications.
 *
 * Usage:
 *   import { LinkScanner, PasswordGenerator, ScamDetector } from './sdk/toolkit.js';
 *
 *   const result = await LinkScanner.analyze('https://suspicious-site.com');
 *   const password = PasswordGenerator.generate({ mode: 'strong', length: 20 });
 *   const scamResult = await ScamDetector.analyze('Your account will be suspended...');
 */

// ── LinkScanner ──
export const LinkScanner = {
  /**
   * Analyze a URL for security risks
   * @param {string} url
   * @returns {Promise<Object>} analysis result
   */
  async analyze(url) {
    const { analyzeURL } = await import('../tools/link-analyzer.js');
    return analyzeURL(url);
  },

  /**
   * Clean tracking parameters from a URL
   * @param {string} url
   * @returns {Promise<Object>} { cleanURL, removed }
   */
  async clean(url) {
    const { cleanURL } = await import('../tools/tracking-cleaner.js');
    return cleanURL(url);
  }
};

// ── QRScanner ──
export const QRScanner = {
  /**
   * Decode and analyze a QR code from an image file
   * @param {File} imageFile
   * @returns {Promise<Object>} QR content + URL analysis if applicable
   */
  async scanFile(imageFile) {
    console.info('[SDK] QRScanner.scanFile: Use the QR Scanner tool in the UI for full QR support.');
    return { note: 'Use the QR Scanner UI tool for full QR code analysis.' };
  }
};

// ── PasswordGenerator ──
export const PasswordGenerator = {
  /**
   * Generate a secure password
   * @param {Object} options
   * @param {'strong'|'passphrase'|'memorable'|'devtest'} options.mode
   * @param {number} options.length - For 'strong' mode (default: 20)
   * @param {number} options.wordCount - For 'passphrase' mode (default: 4)
   * @returns {Object} { password, strength, crackTime }
   */
  generate(options = {}) {
    const { mode = 'strong', length = 20, wordCount = 4 } = options;

    // Import inline to keep SDK self-contained
    const pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    const buf = new Uint8Array(length);
    crypto.getRandomValues(buf);
    const password = Array.from(buf).map(b => pool[b % pool.length]).join('');

    return {
      password,
      mode,
      length: password.length,
      note: 'Use the full PasswordGenerator tool for all modes and strength analysis.'
    };
  }
};

// ── ScamDetector ──
export const ScamDetector = {
  /**
   * Analyze a message for scam indicators
   * @param {string} text
   * @returns {Promise<Object>} analysis result
   */
  async analyze(text) {
    const { analyzeMessage } = await import('../tools/scam-detector.js');
    return analyzeMessage(text);
  }
};

// ── DomainAnalyzer ──
export const DomainAnalyzer = {
  /**
   * Check if a domain impersonates a known brand
   * @param {string} domain
   * @returns {Promise<Object>} analysis result
   */
  async checkImpersonation(domain) {
    const { analyzeDomain } = await import('../tools/fake-domain-detector.js');
    return analyzeDomain(domain);
  }
};

// ── FileAnalyzer ──
export const FileAnalyzer = {
  /**
   * Analyze a file for suspicious characteristics
   * @param {File} file
   * @returns {Promise<Object>} analysis result
   */
  async analyze(file) {
    const { analyzeFile } = await import('../tools/file-analyzer.js');
    return analyzeFile(file);
  }
};

// ── Fingerprint ──
export const Fingerprint = {
  /**
   * Gather browser fingerprint data
   * @returns {Object} fingerprint data + privacy risks
   */
  gather() {
    // Basic gather without full render
    return {
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: `${screen.width}x${screen.height}`,
      note: 'Use the full Fingerprint Viewer for complete analysis.'
    };
  }
};

// ── Encryption ──
export const Encryption = {
  /**
   * Encrypt text with AES-256-GCM
   * @param {string} plaintext
   * @param {string} password
   * @returns {Promise<string>} base64 encrypted string
   */
  async encrypt(plaintext, password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));

    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt']
    );

    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    const packed = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    packed.set(salt, 0);
    packed.set(iv, 16);
    packed.set(new Uint8Array(ciphertext), 28);
    return btoa(String.fromCharCode(...packed));
  },

  /**
   * Decrypt text encrypted with this SDK
   * @param {string} encrypted - base64 string
   * @param {string} password
   * @returns {Promise<string>} decrypted text
   */
  async decrypt(encrypted, password) {
    const packed = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const salt = packed.slice(0, 16);
    const iv   = packed.slice(16, 28);
    const data = packed.slice(28);
    const enc  = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, ['decrypt']
    );

    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(plaintext);
  }
};

// Default export — full SDK
export default {
  LinkScanner,
  QRScanner,
  PasswordGenerator,
  ScamDetector,
  DomainAnalyzer,
  FileAnalyzer,
  Fingerprint,
  Encryption,
  version: '1.0.0'
};

/**
 * Phishing Detector Plugin
 * Privacy First Security Toolkit
 *
 * Plugin type: LINK_ANALYSIS
 *
 * To register this plugin:
 * import plugin from './plugins/phishing-detector/main.js';
 * engine.register(plugin);
 */

const PhishingDetectorPlugin = {
  name: 'phishing-detector',
  version: '1.0.0',
  type: 'LINK_ANALYSIS',
  description: 'Detects phishing-style domains using keyword and pattern analysis',

  phishingKeywords: [
    'login', 'signin', 'secure', 'verify', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'wallet',
    'suspended', 'unlock', 'validate', 'authenticate', 'webscr',
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'bank'
  ],

  /**
   * Analyze a URL for phishing indicators
   * @param {string} input - URL to analyze
   * @returns {Object} - Plugin result
   */
  run(input) {
    let url;
    try {
      url = new URL(input.startsWith('http') ? input : 'https://' + input);
    } catch {
      return null;
    }

    const domain = url.hostname.toLowerCase().replace(/^www\./, '');
    const findings = [];
    let score = 0;

    // Keyword check
    const hits = this.phishingKeywords.filter(k => domain.includes(k));
    if (hits.length > 0) {
      score += hits.length * 15;
      findings.push({
        type: 'phishing_keywords',
        detail: `Phishing keywords in domain: ${hits.join(', ')}`,
        severity: hits.length > 2 ? 'high' : 'medium'
      });
    }

    // Multiple hyphens
    const hyphens = (domain.match(/-/g) || []).length;
    if (hyphens >= 2) {
      score += hyphens * 5;
      findings.push({
        type: 'multiple_hyphens',
        detail: `Domain contains ${hyphens} hyphens — common in phishing domains`,
        severity: 'low'
      });
    }

    // Long domain
    if (domain.length > 30) {
      score += 10;
      findings.push({
        type: 'long_domain',
        detail: `Domain is unusually long (${domain.length} chars)`,
        severity: 'low'
      });
    }

    if (findings.length === 0) return null;

    return {
      pluginName: this.name,
      score: Math.min(score, 100),
      findings
    };
  }
};

export default PhishingDetectorPlugin;

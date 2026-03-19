/**
 * Privacy First Security Toolkit
 * Module: VirusTotal Integration — core/virustotal.js
 *
 * Sends requests through the local Python proxy (/api/virustotal)
 * to work around browser CORS restrictions.
 *
 * API key lives in memory only — never stored, never logged.
 */

// Key lives only in module memory
let _apiKey = null;

export const VirusTotal = {

  setKey(key) {
    _apiKey = key?.trim() || null;
  },

  hasKey() {
    return !!_apiKey;
  },

  clearKey() {
    _apiKey = null;
  },

  /**
   * Check a URL against VirusTotal via local proxy.
   */
  async checkURL(rawURL) {
    if (!_apiKey) return { error: 'No API key set', code: 'NO_KEY' };

    try {
      // Step 1: Try cached report first (no quota cost)
      const urlId = btoa(rawURL).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const cached = await this._proxyGet(`/urls/${urlId}`);

      if (cached && !cached.error) {
        return this._parseReport(cached, rawURL);
      }

      // Step 2: Submit URL for fresh scan
      const submitted = await this._proxyPost('/urls', `url=${encodeURIComponent(rawURL)}`);
      if (submitted.error) return submitted;

      const analysisId = submitted.data?.id;
      if (!analysisId) return { error: 'VirusTotal returned no analysis ID', code: 'NO_ID' };

      // Step 3: Poll until complete
      const report = await this._poll(analysisId);
      if (report.error) return report;

      return this._parseReport(report, rawURL);

    } catch (err) {
      return { error: `Unexpected error: ${err.message}`, code: 'UNKNOWN' };
    }
  },

  async _proxyGet(vtPath) {
    const res = await fetch('/api/virustotal', {
      method: 'GET',
      headers: {
        'X-VT-Key':  _apiKey,
        'X-VT-Path': vtPath,
      }
    });
    const data = await res.json();
    if (res.status === 404) return null;
    if (!res.ok) return this._mapError(res.status, data);
    return data;
  },

  async _proxyPost(vtPath, body) {
    const res = await fetch('/api/virustotal', {
      method: 'POST',
      headers: {
        'X-VT-Key':    _apiKey,
        'X-VT-Path':   vtPath,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body
    });
    const data = await res.json();
    if (!res.ok) return this._mapError(res.status, data);
    return data;
  },

  async _poll(analysisId, maxWaitMs = 12000, intervalMs = 2000) {
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      await new Promise(r => setTimeout(r, intervalMs));
      const data = await this._proxyGet(`/analyses/${analysisId}`);
      if (data?.error) return data;
      if (data?.data?.attributes?.status === 'completed') return data;
    }
    return { error: 'Scan timed out. The URL may be new to VirusTotal — try again in a few seconds.', code: 'TIMEOUT' };
  },

  _mapError(status, data) {
    if (status === 401) return { error: 'Invalid API key. Check your VirusTotal API key.', code: 'INVALID_KEY' };
    if (status === 429) return { error: 'Rate limit hit. Free tier allows 4 requests/minute.', code: 'RATE_LIMIT' };
    if (status === 503) return { error: 'Could not reach VirusTotal. Check your internet connection.', code: 'NETWORK' };
    return { error: data?.error || `VirusTotal error (${status})`, code: String(status) };
  },

  _parseReport(data, rawURL) {
    const attrs  = data?.data?.attributes ?? {};
    const stats  = attrs.last_analysis_stats  ?? attrs.stats  ?? {};
    const results = attrs.last_analysis_results ?? attrs.results ?? {};

    const malicious  = stats.malicious  ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless   = stats.harmless   ?? 0;
    const undetected = stats.undetected ?? 0;
    const total      = malicious + suspicious + harmless + undetected;

    const detections = Object.entries(results)
      .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
      .map(([vendor, v]) => ({ vendor, category: v.category, result: v.result ?? v.category }))
      .sort((a, b) => a.category === 'malicious' ? -1 : 1);

    let vtRisk = 'clean', vtScore = 0;
    if      (malicious >= 3)  { vtRisk = 'malicious';  vtScore = 90; }
    else if (malicious >= 1)  { vtRisk = 'suspicious'; vtScore = 60; }
    else if (suspicious >= 2) { vtRisk = 'suspicious'; vtScore = 40; }
    else if (suspicious >= 1) { vtRisk = 'low_risk';   vtScore = 20; }

    const lastAnalysis = attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toLocaleString()
      : 'Just now';

    const urlB64 = attrs.url
      ? btoa(attrs.url).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
      : null;

    return {
      ok: true, url: rawURL, vtRisk, vtScore,
      malicious, suspicious, harmless, undetected, total,
      detections, lastAnalysis,
      permalink: urlB64 ? `https://www.virustotal.com/gui/url/${urlB64}` : null,
    };
  }
};

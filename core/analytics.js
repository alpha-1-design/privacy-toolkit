/**
 * Privacy First Security Toolkit
 * Optional Usage Analytics — core/analytics.js
 *
 * The toolkit ships with analytics DISABLED. Nothing is sent anywhere
 * unless the visitor explicitly opts in via the sidebar toggle.
 *
 * The opt-in is remembered for the current browsing session only
 * (sessionStorage — cleared when the tab closes). No cookies,
 * no localStorage, no cross-session persistence.
 */

const SITE_ID = '5602fd10';
const API_URL = 'https://alpha-analytics-api-production-b795.up.railway.app';
const CONSENT_KEY = 'ptk_usage_stats';

let enabled = false;

function pageview() {
  try {
    fetch(API_URL + '/track/pageview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        site_id: SITE_ID,
        path: location.pathname,
        referrer: document.referrer || null
      }),
      keepalive: true
    }).catch(() => {});
  } catch (e) {
    // Analytics must never break the toolkit.
  }
}

export function isAnalyticsEnabled() {
  return enabled;
}

export function setAnalyticsEnabled(on) {
  enabled = !!on;
  try {
    sessionStorage.setItem(CONSENT_KEY, enabled ? '1' : '0');
  } catch (e) {
    // Storage unavailable — keep in-memory state only.
  }
  if (enabled) pageview();
}

export function initAnalytics() {
  try {
    enabled = sessionStorage.getItem(CONSENT_KEY) === '1';
  } catch (e) {
    enabled = false;
  }
  if (!enabled) return false;

  pageview();
  const original = history.pushState;
  history.pushState = function (...args) {
    const result = original.apply(this, args);
    pageview();
    return result;
  };
  window.addEventListener('popstate', pageview);
  return true;
}

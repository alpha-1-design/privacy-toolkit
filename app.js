/**
 * Privacy First Security Toolkit
 * App Bootstrap — app.js
 */

import { router } from "./core/router.js";
import { initAnalytics, isAnalyticsEnabled, setAnalyticsEnabled } from "./core/analytics.js";
import { renderLinkAnalyzer }        from "./tools/link-analyzer.js";
import { renderPasswordGenerator }   from "./tools/password-generator.js";
import { renderScamDetector }        from "./tools/scam-detector.js";
import { renderTrackingCleaner }     from "./tools/tracking-cleaner.js";
import { renderFingerprintViewer }   from "./tools/fingerprint-viewer.js";
import { renderFileAnalyzer }        from "./tools/file-analyzer.js";
import { renderEncryptionTool }      from "./tools/encryption-tool.js";
import { renderFakeDomainDetector }  from "./tools/fake-domain-detector.js";
import { renderQRScanner }           from "./tools/qr-scanner.js";
import { renderIdentityGenerator }   from "./tools/identity-generator.js";
import { renderJWTDecoder }          from "./tools/jwt-decoder.js";
import { renderHashGenerator }       from "./tools/hash-generator.js";
import { renderBase64Tool }          from "./tools/base64-tool.js";
import { renderRequestMap }          from "./tools/request-map.js";
import { renderBreachChecker }       from "./tools/breach-checker.js";
import { renderEmailAnalyzer }       from "./tools/email-analyzer.js";
import { renderPIIRedactor }         from "./tools/pii-redactor.js";
import { renderFAQ }                from "./tools/faq.js";
import { renderSupport }            from "./tools/support.js";

const TOOLS = {
  "link-analyzer":      () => renderLinkAnalyzer("view-link-analyzer"),
  "qr-scanner":         () => renderQRScanner("view-qr-scanner"),
  "file-analyzer":      () => renderFileAnalyzer("view-file-analyzer"),
  "scam-detector":      () => renderScamDetector("view-scam-detector"),
  "fake-domain":        () => renderFakeDomainDetector("view-fake-domain"),
  "email-analyzer":     () => renderEmailAnalyzer("view-email-analyzer"),
  "breach-checker":     () => renderBreachChecker("view-breach-checker"),
  "tracking-cleaner":   () => renderTrackingCleaner("view-tracking-cleaner"),
  "fingerprint-viewer": () => renderFingerprintViewer("view-fingerprint-viewer"),
  "encryption-tool":    () => renderEncryptionTool("view-encryption-tool"),
  "request-map":        () => renderRequestMap("view-request-map"),
  "pii-redactor":       () => renderPIIRedactor("view-pii-redactor"),
  "password-generator": () => renderPasswordGenerator("view-password-generator"),
  "identity-generator": () => renderIdentityGenerator("view-identity-generator"),
  "jwt-decoder":        () => renderJWTDecoder("view-jwt-decoder"),
  "hash-generator":     () => renderHashGenerator("view-hash-generator"),
  "base64-tool":        () => renderBase64Tool("view-base64-tool"),
  "faq":                () => renderFAQ("view-faq"),
  "support":            () => renderSupport("view-support"),
};

const initialized = new Set();

for (const [route, renderer] of Object.entries(TOOLS)) {
  router.register(route, () => {
    if (!initialized.has(route)) { renderer(); initialized.add(route); }
  });
}

router.register("dashboard", () => {});

document.getElementById("hamburger")?.addEventListener("click", () => {
  document.getElementById("sidebar").classList.toggle("open");
});

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    document.getElementById("sidebar").classList.remove("open");
  });
});

document.querySelectorAll(".dashboard-tool-card[data-route]").forEach(card => {
  card.addEventListener("click", () => router.navigate(card.dataset.route));
});

router.init();

// ── Home button ──
document.getElementById("home-btn")?.addEventListener("click", () => {
  router.navigate("dashboard");
});

// ── Toast system ──
window.showToast = function(message, type = "info", durationMs = 3000) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 300);
  }, durationMs);
};

// ── Optional usage analytics — opt-in, off by default ──
initAnalytics();

function updateAnalyticsUI() {
  const on = isAnalyticsEnabled();
  const toggle = document.getElementById("analyticsToggle");
  const claim = document.getElementById("analyticsClaim");
  if (toggle) {
    toggle.textContent = on ? "On" : "Off";
    toggle.classList.toggle("active", on);
    toggle.setAttribute("aria-checked", on ? "true" : "false");
  }
  if (claim) {
    claim.textContent = on ? "\u2713 Analytics: on (you opted in)" : "\u2713 No analytics";
  }
}

document.getElementById("analyticsToggle")?.addEventListener("click", () => {
  const on = !isAnalyticsEnabled();
  setAnalyticsEnabled(on);
  updateAnalyticsUI();
  window.showToast(
    on
      ? "Anonymous usage stats enabled for this session \u2014 thanks!"
      : "Usage stats disabled. Nothing will be sent.",
    "info"
  );
});

updateAnalyticsUI();

// ── Update notification — the service worker broadcasts the deployed version ──
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', event => {
    if (event.data && event.data.type === 'APP_VERSION') {
      try {
        const seen = sessionStorage.getItem('ptk_version');
        if (seen && seen !== event.data.version) {
          window.showToast(`Toolkit updated to v${event.data.version} \u2014 refresh for the latest`, 'info', 6000);
        }
        sessionStorage.setItem('ptk_version', event.data.version);
      } catch (err) { /* ignore */ }
    }
  });
}

console.log("%c Privacy First Security Toolkit v1.2.0", "color:#00d4ff;font-size:14px;font-weight:bold;");
console.log("%c Verify everything. Store nothing. Track nothing.", "color:#7a95ab;font-size:11px;");

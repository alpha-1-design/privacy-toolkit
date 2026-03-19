/**
 * Privacy First Security Toolkit
 * App Bootstrap — app.js
 */

import { router } from "./core/router.js";
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
import { renderFAQ }                from "./tools/faq.js";
import { renderSupport }            from "./tools/support.js";

const TOOLS = {
  "link-analyzer":      () => renderLinkAnalyzer("view-link-analyzer"),
  "qr-scanner":         () => renderQRScanner("view-qr-scanner"),
  "file-analyzer":      () => renderFileAnalyzer("view-file-analyzer"),
  "scam-detector":      () => renderScamDetector("view-scam-detector"),
  "fake-domain":        () => renderFakeDomainDetector("view-fake-domain"),
  "tracking-cleaner":   () => renderTrackingCleaner("view-tracking-cleaner"),
  "fingerprint-viewer": () => renderFingerprintViewer("view-fingerprint-viewer"),
  "encryption-tool":    () => renderEncryptionTool("view-encryption-tool"),
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

// ── Version toast on load ──
setTimeout(() => {
  window.showToast(
    \`<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>
    You are on the latest version &mdash; v1.0.0\`,
    "success",
    3000
  );
}, 1000);

console.log("%c Privacy First Security Toolkit v1.0.0", "color:#00d4ff;font-size:14px;font-weight:bold;");
console.log("%c Verify everything. Store nothing. Track nothing.", "color:#7a95ab;font-size:11px;");

/**
 * Privacy First Security Toolkit
 * Service Worker — sw.js
 *
 * Strategy:
 * - HTML: Network first (always get latest version)
 * - JS/CSS/JSON: Cache first, update in background
 * - API calls: Never cached (VirusTotal proxy)
 */

const CACHE_NAME = 'privacy-toolkit-v1.0.0';

const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/app.js',
  '/core/engine.js',
  '/core/icons.js',
  '/core/router.js',
  '/core/utils.js',
  '/core/virustotal.js',
  '/tools/link-analyzer.js',
  '/tools/password-generator.js',
  '/tools/scam-detector.js',
  '/tools/tracking-cleaner.js',
  '/tools/fingerprint-viewer.js',
  '/tools/file-analyzer.js',
  '/tools/encryption-tool.js',
  '/tools/fake-domain-detector.js',
  '/tools/qr-scanner.js',
  '/tools/identity-generator.js',
  '/tools/jwt-decoder.js',
  '/tools/hash-generator.js',
  '/tools/base64-tool.js',
  '/tools/faq.js',
  '/tools/support.js',
  '/data/known-brands.json',
  '/data/scam-patterns.json',
  '/data/suspicious-tlds.json',
  '/data/tracking-params.json',
  '/sdk/toolkit.js',
];

// Install — cache all static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Activate — delete old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

// Fetch — smart routing
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Never cache API calls
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Never cache external requests
  if (url.origin !== location.origin) {
    event.respondWith(fetch(event.request));
    return;
  }

  // HTML — network first so updates show immediately
  if (event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // JS/CSS/JSON — cache first, update in background
  event.respondWith(
    caches.match(event.request).then(cached => {
      const networkFetch = fetch(event.request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
      return cached || networkFetch;
    })
  );
});

// ── Auto-update: notify page when new version is available ──
self.addEventListener('message', event => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

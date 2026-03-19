/**
 * Privacy First Security Toolkit
 * Tool: FAQ — tools/faq.js
 */

import { icon } from '../core/icons.js';
import { router } from '../core/router.js';

const FAQS = [
  {
    category: 'Privacy & Security',
    items: [
      {
        q: 'Does this toolkit store any of my data?',
        a: 'No. Nothing you enter is ever stored. No cookies, no localStorage, no database. Everything is processed in your browser memory and cleared when you close the tab.'
      },
      {
        q: 'Does it send my data to any server?',
        a: 'The toolkit works entirely offline. The only exception is the optional VirusTotal integration — if you provide your own API key, the URL you scan is sent to VirusTotal. This is opt-in and clearly shown in the UI.'
      },
      {
        q: 'Is the source code open source?',
        a: 'Yes. The full source code is available on GitHub under the MIT license. You can inspect every line, fork it, or contribute to it.'
      },
      {
        q: 'Can I use this on mobile?',
        a: 'Yes. The toolkit is fully responsive and works on Android and iOS browsers. Some features like file upload may behave slightly differently depending on your browser.'
      },
    ]
  },
  {
    category: 'VirusTotal Integration',
    items: [
      {
        q: 'Why do I need my own VirusTotal API key?',
        a: 'VirusTotal requires authentication for API access. A shared key embedded in the code would be publicly visible on GitHub and immediately revoked. Your own free key gives you 500 checks per day with no restrictions.'
      },
      {
        q: 'How do I get a free VirusTotal API key?',
        a: 'Go to virustotal.com, create a free account, then go to your profile and click API Key. No credit card required. The free tier gives you 500 URL checks per day and 4 per minute.'
      },
      {
        q: 'Is my API key stored anywhere?',
        a: 'No. Your API key is held in browser memory only for the current session. It is cleared the moment you close or refresh the tab. It is never written to disk, localStorage, or any server.'
      },
      {
        q: 'VirusTotal scan is taking too long — what should I do?',
        a: 'If a URL has never been scanned before, VirusTotal needs to submit it to 90+ vendors which can take up to 12 seconds. If it times out, wait a few seconds and try again — the result will be cached on VirusTotal\'s end.'
      },
    ]
  },
  {
    category: 'Tools',
    items: [
      {
        q: 'What is the difference between Link Analyzer and Fake Domain Detector?',
        a: 'Link Analyzer checks a full URL for phishing signals, tracking parameters, suspicious TLDs, and VirusTotal results. Fake Domain Detector specifically checks if a domain is impersonating a known brand using typosquatting or lookalike techniques.'
      },
      {
        q: 'Can the encryption tool decrypt files encrypted elsewhere?',
        a: 'No — the encryption tool uses AES-256-GCM with PBKDF2 key derivation. It can only decrypt text that was encrypted using this same tool with the same password. It is not compatible with other encryption implementations.'
      },
      {
        q: 'Is the Identity Generator data real?',
        a: 'No. All generated identities are completely synthetic and fictional. They are intended for developers who need realistic-looking test data. Do not use generated identities for any fraudulent purpose.'
      },
      {
        q: 'Does the File Analyzer upload my file anywhere?',
        a: 'No. File analysis is done entirely in your browser using the File API. Your file bytes never leave your device.'
      },
    ]
  },
  {
    category: 'Running Locally',
    items: [
      {
        q: 'How do I run this locally?',
        a: 'Download the project from GitHub, then run: python server.py — and open http://localhost:8080 in your browser. Requires Python 3. Works on Windows, Mac, Linux, and Android (Termux).'
      },
      {
        q: 'Why does VirusTotal only work locally, not on the live site?',
        a: 'Browsers block direct API requests to third-party services due to CORS restrictions. The local Python server includes a proxy that forwards requests to VirusTotal on your behalf. The live Vercel deployment uses a serverless function for the same purpose.'
      },
      {
        q: 'Can I use this completely offline?',
        a: 'Yes — all tools except VirusTotal work fully offline. Once the page is loaded, you can disconnect from the internet and everything continues to function.'
      },
    ]
  },
];

export function renderFAQ(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">FAQ</h1>
      <p class="tool-subtitle">FREQUENTLY ASKED QUESTIONS</p>
    </div>

    ${FAQS.map(section => `
      <div style="margin-bottom: var(--space-xl);">
        <div class="card-title" style="font-size:13px; margin-bottom:var(--space-md); color:var(--accent); letter-spacing:.08em;">
          ${section.category.toUpperCase()}
        </div>
        <div style="display:flex; flex-direction:column; gap:var(--space-sm);">
          ${section.items.map((item, i) => `
            <div class="faq-item card" style="cursor:pointer;" data-faq="${section.category}-${i}">
              <div class="faq-question" style="display:flex; align-items:center; justify-content:space-between; gap:var(--space-md);">
                <span style="font-size:13px; font-weight:600; color:var(--text-primary); line-height:1.5;">${item.q}</span>
                <span class="faq-chevron" style="flex-shrink:0; color:var(--text-muted); transition:transform 0.2s;">
                  ${icon('information-circle', 16)}
                </span>
              </div>
              <div class="faq-answer" style="display:none; margin-top:var(--space-md); font-size:13px; color:var(--text-secondary); line-height:1.8; border-top:1px solid var(--border); padding-top:var(--space-md);">
                ${item.a}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `).join('')}

    <div class="card" style="text-align:center; margin-top:var(--space-xl);">
      <p style="font-size:13px; color:var(--text-secondary); margin-bottom:var(--space-md);">
        Can't find what you're looking for?
      </p>
      <a href="#support" class="btn btn-primary" data-route="support" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
        ${icon('bell-alert', 16)} Contact Support
      </a>
    </div>
  `;

  // Accordion toggle
  container.querySelectorAll('.faq-item').forEach(item => {
    item.addEventListener('click', () => {
      const answer  = item.querySelector('.faq-answer');
      const chevron = item.querySelector('.faq-chevron');
      const isOpen  = answer.style.display === 'block';

      // Close all others
      container.querySelectorAll('.faq-answer').forEach(a => a.style.display = 'none');
      container.querySelectorAll('.faq-chevron').forEach(c => c.style.transform = '');

      if (!isOpen) {
        answer.style.display = 'block';
        chevron.style.transform = 'rotate(180deg)';
      }
    });
  });

  // Support link
  container.querySelector('[data-route="support"]')?.addEventListener('click', (e) => {
    e.preventDefault();
    router.navigate('support');
  });
}

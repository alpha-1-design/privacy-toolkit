/**
 * Privacy First Security Toolkit
 * Tool: File Analyzer — tools/file-analyzer.js
 *
 * Analyzes files for suspicious characteristics locally.
 * File contents never leave the browser.
 */

import { Utils } from '../core/utils.js';

const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'msi', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe',
  'js', 'jse', 'wsh', 'wsf', 'hta', 'scr', 'pif', 'reg', 'inf', 'msc',
  'dll', 'sys', 'drv', 'cpl', 'ocx', 'lnk', 'jar', 'app', 'deb', 'rpm',
  'sh', 'bash', 'zsh', 'fish', 'run', 'bin', 'elf', 'apk', 'ipa'
]);

const DOCUMENT_EXTENSIONS = new Set([
  'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
  'pdf', 'rtf'
]);

const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img', 'cab'
]);

// Magic bytes for file type identification
const MAGIC_BYTES = {
  'PE Executable (Windows EXE/DLL)': [0x4D, 0x5A],
  'ELF Binary (Linux)':              [0x7F, 0x45, 0x4C, 0x46],
  'PDF Document':                    [0x25, 0x50, 0x44, 0x46],
  'ZIP Archive':                     [0x50, 0x4B, 0x03, 0x04],
  'RAR Archive':                     [0x52, 0x61, 0x72, 0x21],
  'Java Archive (JAR)':              [0x50, 0x4B, 0x03, 0x04],
  'Mach-O Binary (macOS)':           [0xCF, 0xFA, 0xED, 0xFE],
  'Mach-O 32-bit':                   [0xCE, 0xFA, 0xED, 0xFE],
  'Script (shebang)':                [0x23, 0x21],
  'MS Office Document':              [0xD0, 0xCF, 0x11, 0xE0],
  'PNG Image':                       [0x89, 0x50, 0x4E, 0x47],
  'JPEG Image':                      [0xFF, 0xD8, 0xFF],
  'GIF Image':                       [0x47, 0x49, 0x46, 0x38],
  'Windows Shortcut (LNK)':         [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00],
};

export async function analyzeFile(file) {
  const warnings = [];
  const info = [];
  let riskScore = 0;

  // ── Basic info ──
  const name = file.name;
  const size = file.size;
  const parts = name.split('.');
  const extension = parts[parts.length - 1].toLowerCase();
  const hasDoubleExtension = parts.length > 2;

  // ── Check 1: Extension ──
  if (DANGEROUS_EXTENSIONS.has(extension)) {
    warnings.push({
      level: 'danger',
      icon: '⚠️',
      title: `Dangerous file type: .${extension}`,
      detail: 'This file extension can execute code on your computer. Never open files like this from untrusted sources.'
    });
    riskScore += 50;
  } else if (DOCUMENT_EXTENSIONS.has(extension)) {
    info.push({
      level: 'warn',
      icon: '📄',
      title: `Office document: .${extension}`,
      detail: 'Office documents can contain macros or embedded scripts. Be cautious with files from unknown senders.'
    });
    riskScore += 10;
  } else if (ARCHIVE_EXTENSIONS.has(extension)) {
    info.push({
      level: 'info',
      icon: '📦',
      title: `Archive file: .${extension}`,
      detail: 'Archives can contain malicious files. Always scan extracted contents before opening.'
    });
    riskScore += 5;
  }

  // ── Check 2: Double extension ──
  if (hasDoubleExtension) {
    const secondExt = parts[parts.length - 2].toLowerCase();
    const isDisguise = DANGEROUS_EXTENSIONS.has(extension) || DANGEROUS_EXTENSIONS.has(secondExt);

    warnings.push({
      level: isDisguise ? 'danger' : 'warn',
      icon: '🎭',
      title: `Double extension detected: .${secondExt}.${extension}`,
      detail: isDisguise
        ? `This is a classic malware disguise! The file appears to be a .${secondExt} but is actually an executable .${extension}.`
        : `File has multiple extensions. Make sure this is intentional.`
    });
    if (isDisguise) riskScore += 40;
    else riskScore += 10;
  }

  // ── Check 3: Magic bytes (read first 16 bytes) ──
  try {
    const buffer = await Utils.readFileAsBuffer(file.slice(0, 16));
    const bytes = new Uint8Array(buffer);
    const detectedType = detectMagicBytes(bytes);

    if (detectedType) {
      // Check if magic bytes match claimed extension
      const mismatch = checkMagicMismatch(detectedType, extension);
      if (mismatch) {
        warnings.push({
          level: 'danger',
          icon: '🔬',
          title: 'File type mismatch detected',
          detail: `The file claims to be .${extension} but its contents indicate it is a "${detectedType}". This is a common malware disguise technique.`
        });
        riskScore += 45;
      } else {
        info.push({
          level: 'info',
          icon: '🔬',
          title: `File signature: ${detectedType}`,
          detail: 'File type confirmed by magic bytes.'
        });
      }
    }
  } catch {
    info.push({ level: 'info', icon: '⚠️', title: 'Could not read file signature', detail: 'File too small or unreadable.' });
  }

  // ── Check 4: Suspicious filename patterns ──
  const suspiciousPatterns = [
    { pattern: /invoice/i,      msg: 'Invoice-themed files are frequently used in malware campaigns.' },
    { pattern: /receipt/i,      msg: 'Receipt-themed files are a common social engineering tactic.' },
    { pattern: /payment/i,      msg: 'Payment-themed files are frequently used in phishing attacks.' },
    { pattern: /urgent/i,       msg: 'Urgency in filename is a social engineering red flag.' },
    { pattern: /update/i,       msg: '"Update" filenames are used to trick users into running fake installers.' },
    { pattern: /free/i,         msg: '"Free" filenames often accompany cracked software containing malware.' },
    { pattern: /crack|keygen/i, msg: 'Cracked software and keygens are primary malware distribution vectors.' },
  ];

  for (const { pattern, msg } of suspiciousPatterns) {
    if (pattern.test(name)) {
      warnings.push({
        level: 'warn',
        icon: '🎣',
        title: 'Suspicious filename pattern',
        detail: msg
      });
      riskScore += 15;
      break; // Only flag once
    }
  }

  // ── Check 5: Hidden file (starts with dot) ──
  if (name.startsWith('.')) {
    warnings.push({
      level: 'warn',
      icon: '👻',
      title: 'Hidden file',
      detail: 'Files starting with "." are hidden on Unix systems. This could be a concealment technique.'
    });
    riskScore += 10;
  }

  riskScore = Math.min(riskScore, 100);
  const riskLevel = riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 15 ? 'medium' : 'low';

  return {
    name,
    size: Utils.formatBytes(size),
    extension,
    riskScore,
    riskLevel,
    warnings,
    info,
    allItems: [...warnings, ...info]
  };
}

function detectMagicBytes(bytes) {
  for (const [type, magic] of Object.entries(MAGIC_BYTES)) {
    if (magic.every((b, i) => bytes[i] === b)) return type;
  }
  return null;
}

function checkMagicMismatch(detectedType, extension) {
  const safeMatches = {
    'PDF Document': ['pdf'],
    'PNG Image': ['png'],
    'JPEG Image': ['jpg', 'jpeg'],
    'GIF Image': ['gif'],
    'ZIP Archive': ['zip', 'jar', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'apk'],
    'MS Office Document': ['doc', 'xls', 'ppt'],
    'Script (shebang)': ['sh', 'bash', 'py', 'rb', 'pl'],
  };

  for (const [type, exts] of Object.entries(safeMatches)) {
    if (detectedType === type) {
      return !exts.includes(extension);
    }
  }

  // If detected as executable but extension is not
  if (detectedType.includes('Executable') || detectedType.includes('Binary')) {
    return !DANGEROUS_EXTENSIONS.has(extension);
  }

  return false;
}

export function renderFileAnalyzer(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">File Analyzer</h1>
      <p class="tool-subtitle">EXTENSION · MAGIC BYTES · DOUBLE EXTENSION · MALWARE PATTERNS</p>
      <span class="tool-privacy-badge">🔒 File never leaves your device — analyzed in browser</span>
    </div>

    <div class="card">
      <label class="drop-zone" id="file-drop-zone" for="file-input">
        <span class="drop-zone-icon">📂</span>
        <div class="drop-zone-text">
          <strong style="color:var(--text-primary); font-size:14px;">Drop a file here</strong><br/>
          or click to browse<br/>
          <span style="color:var(--text-muted); font-size:11px; margin-top:6px; display:block;">
            Supports any file type. Nothing is uploaded.
          </span>
        </div>
      </label>
      <input type="file" id="file-input" style="display:none;" />
    </div>

    <div id="file-result" style="display:none;"></div>

    <div class="card" style="margin-top:var(--space-md);">
      <div class="card-title">What this tool checks</div>
      <ul class="warning-list">
        <li class="warning-item info"><span class="warning-icon">🔬</span><span><strong>File signature (magic bytes)</strong> — The first bytes of a file reveal its true type, even if the extension is faked.</span></li>
        <li class="warning-item info"><span class="warning-icon">🎭</span><span><strong>Double extensions</strong> — A file named "document.pdf.exe" is an executable disguised as a PDF.</span></li>
        <li class="warning-item info"><span class="warning-icon">⚡</span><span><strong>Dangerous extensions</strong> — .exe, .bat, .ps1, .vbs and others can run malicious code.</span></li>
        <li class="warning-item info"><span class="warning-icon">🎣</span><span><strong>Suspicious naming</strong> — Invoice, receipt, and update filenames are common social engineering tactics.</span></li>
      </ul>
    </div>
  `;

  const dropZone = container.querySelector('#file-drop-zone');
  const fileInput = container.querySelector('#file-input');
  const result = container.querySelector('#file-result');

  fileInput.addEventListener('change', async () => {
    if (fileInput.files[0]) {
      const analysis = await analyzeFile(fileInput.files[0]);
      renderFileResult(result, analysis);
      result.style.display = 'block';
    }
  });

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragging');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragging');
  });

  dropZone.addEventListener('drop', async e => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    const file = e.dataTransfer?.files[0];
    if (file) {
      const analysis = await analyzeFile(file);
      renderFileResult(result, analysis);
      result.style.display = 'block';
    }
  });
}

function renderFileResult(container, analysis) {
  const { name, size, extension, riskScore, riskLevel, allItems } = analysis;
  const riskColor = riskLevel === 'critical' || riskLevel === 'high' ? 'danger'
                  : riskLevel === 'medium' ? 'warn' : 'safe';

  container.innerHTML = `
    <div class="result-panel">
      <div class="result-panel-header">
        <span class="result-panel-title">File Analysis</span>
        <span class="risk-badge risk-${riskLevel === 'critical' ? 'critical' : riskLevel === 'high' ? 'high' : riskLevel === 'medium' ? 'medium' : 'safe'}">
          ${riskLevel.toUpperCase()} RISK — ${riskScore}%
        </span>
      </div>
      <div class="result-panel-body">

        <div class="grid-2" style="margin-bottom:var(--space-md);">
          <div class="stat-card">
            <span class="stat-value" style="font-size:18px; word-break:break-all;">${Utils.escapeHTML(name)}</span>
            <span class="stat-label">Filename</span>
          </div>
          <div class="stat-card">
            <span class="stat-value">${Utils.escapeHTML(size)}</span>
            <span class="stat-label">File Size</span>
          </div>
        </div>

        <div class="progress-bar-wrap" style="margin-bottom:var(--space-md);">
          <div class="progress-bar-fill ${riskColor}" style="width:${riskScore}%"></div>
        </div>

        ${allItems.length > 0 ? `
          <ul class="warning-list">
            ${allItems.map(w => `
              <li class="warning-item ${w.level}">
                <span class="warning-icon">${w.icon}</span>
                <div>
                  <strong>${Utils.escapeHTML(w.title)}</strong>
                  <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">${Utils.escapeHTML(w.detail)}</div>
                </div>
              </li>
            `).join('')}
          </ul>
        ` : `
          <div class="warning-item safe">
            <span class="warning-icon">✅</span>
            <span>No obvious threats detected. Always be cautious with unexpected files.</span>
          </div>
        `}

      </div>
    </div>
  `;
}

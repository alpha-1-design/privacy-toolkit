/**
 * Privacy First Security Toolkit
 * Tool: Password Generator — tools/password-generator.js
 *
 * 100% client-side. Uses Web Crypto API.
 * No passwords are stored or transmitted.
 */

import { Utils } from '../core/utils.js';

// EFF Large Wordlist (subset — first 256 for offline use)
// Full wordlist: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
const WORDLIST = [
  'abacus','abbey','ability','ablaze','aboard','absorb','abstract','absurd',
  'abuse','accent','accept','access','aching','acorn','acoustic','acquire',
  'action','active','actual','added','adjust','admire','advent','advice',
  'aerial','afford','afraid','agenda','agile','agony','ahead','aircraft',
  'airport','airtight','alarm','album','alchemy','almond','almost','alone',
  'amber','amble','amend','ample','anchor','anger','angle','ankle',
  'answer','antler','anvil','apart','apple','arctic','arena','arise',
  'armor','aroma','arrow','atlas','attempt','attic','attract','audio',
  'autumn','avocado','avoid','awake','awful','awkward','badge','bakery',
  'balance','bamboo','banana','banish','banner','barely','barrel','basket',
  'battle','beacon','beauty','become','before','behave','belief','belong',
  'bench','berry','better','beyond','biscuit','bison','bitter','blanket',
  'blossom','blue','blunt','board','bonus','border','bottle','bounce',
  'branch','breach','breezy','bright','brine','bristle','bronze','brother',
  'browse','bruise','bubble','budget','burden','buzzing','cabin','cadence',
  'candle','captain','carbon','castle','cattle','cavern','cedar','cellar',
  'census','chain','chance','change','chaos','charm','chasm','cherry',
  'chest','cinder','circle','citrus','clamor','clarity','clever','climate',
  'clover','coast','coffee','comet','commit','common','compact','complex',
  'concert','condor','copper','corner','cosmos','cotton','council','cougar',
  'coyote','crater','credit','crimson','crystal','curious','current','custom',
  'cycle','dagger','damage','danger','daring','daytime','debris','decent',
  'delay','desert','desire','detail','devote','diamond','diffuse','dinner',
  'direct','distant','divide','domain','doorway','draft','dragon','drastic',
  'drifted','driver','driven','droplet','durable','dust','eagle','early',
  'earth','eclipse','effort','either','elbow','empire','enable','energy',
  'engine','enough','enter','entire','entry','epoch','escape','essence',
  'evolve','exact','exceed','factor','falcon','fancy','faultless','feast',
  'fervent','fiesta','filter','finish','fjord','flame','flannel','flair',
  'flatten','flavor','flexible','forest','forge','formal','forward','fossil',
  'fracture','fragile','fresh','frugal','future','galaxy','gamble','garden',
  'gather','gentle','genuine','glacier','global','golden','gorge','graceful',
  'granite','gravity','guardian','habitat','harbor','harvest','hazard','helpful',
  'heroic','hidden','highest','hiking','hollow','horizon','humble','hungry',
  'hunter','icicle','ignore','impact','income','increase','inner','insight',
  'inspire','instant','intense','island','journal','jungle','justice','kernel',
  'kindness','kingdom','lantern','launch','layer','legend','liberty','liquid',
  'listen','lively','logic','lunar','magnet','marble','market','meadow',
  'memory','mentor','mighty','mirror','mission','modest','moment','mountain',
  'mystery','nature','network','neutral','noble','notion','nourish','object',
  'ocean','offer','orange','orbit','origin','outdoor','oyster','palace',
  'panda','pattern','peaceful','perfect','persist','petal','pine','planet',
  'plastic','pledge','polar','precise','protect','prove','puzzle','quartz',
  'quiet','radiant','ranger','rapids','reason','recall','record','reform',
  'remote','rescue','resolve','reveal','ribbon','rising','river','robust',
  'rocket','rogue','rolling','rough','route','sacred','safety','salmon',
  'savage','scenic','secure','select','settle','shadow','shelter','signal',
  'simple','sincere','sketch','skill','skyline','sleek','slender','smooth',
  'solar','solid','solution','source','sparkle','spirit','spoken','spring',
  'stable','static','steadfast','steel','stellar','sterling','stone','storm',
  'strategy','stream','stride','strong','summit','sunlight','supply','surplus',
  'survive','swift','symbol','system','talent','target','temple','theory',
  'thunder','timber','topaz','torch','total','trail','transit','triumph',
  'tropical','trouble','trusted','tunnel','unique','urgent','useful','valley',
  'venture','vibrant','village','violet','vision','visitor','vital','vivid',
  'voyage','walnut','warden','watchful','wealth','weave','welcome','wheat',
  'wilderness','wisdom','wonder','worthy','xeric','yarrow','zealous','zenith'
];

const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  digits:    '0123456789',
  symbols:   '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

function securePickChar(charset) {
  const buf = new Uint8Array(1);
  let pick;
  do {
    crypto.getRandomValues(buf);
    pick = buf[0];
  } while (pick >= Math.floor(256 / charset.length) * charset.length);
  return charset[pick % charset.length];
}

function generateStrong(length = 20, options = {}) {
  const { useUpper = true, useLower = true, useDigits = true, useSymbols = true } = options;

  let pool = '';
  const required = [];

  if (useUpper)   { pool += CHARSETS.uppercase; required.push(securePickChar(CHARSETS.uppercase)); }
  if (useLower)   { pool += CHARSETS.lowercase; required.push(securePickChar(CHARSETS.lowercase)); }
  if (useDigits)  { pool += CHARSETS.digits;    required.push(securePickChar(CHARSETS.digits)); }
  if (useSymbols) { pool += CHARSETS.symbols;   required.push(securePickChar(CHARSETS.symbols)); }

  if (!pool) pool = CHARSETS.lowercase + CHARSETS.digits;

  const remaining = [];
  for (let i = required.length; i < length; i++) {
    remaining.push(securePickChar(pool));
  }

  // Shuffle required + remaining together
  const all = [...required, ...remaining];
  for (let i = all.length - 1; i > 0; i--) {
    const j = Utils.randomInt(0, i);
    [all[i], all[j]] = [all[j], all[i]];
  }

  return all.join('');
}

function generatePassphrase(wordCount = 4, separator = '-') {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(WORDLIST[Utils.randomInt(0, WORDLIST.length - 1)]);
  }
  return words.join(separator);
}

function generateMemorable(length = 12) {
  // Consonant-Vowel-Consonant pattern + digits
  const consonants = 'bcdfghjklmnpqrstvwxyz';
  const vowels = 'aeiou';

  let word = '';
  for (let i = 0; i < Math.floor(length * 0.7); i++) {
    word += i % 2 === 0
      ? securePickChar(consonants)
      : securePickChar(vowels);
  }
  // Add some digits at the end
  const digits = Utils.randomInt(10, 9999).toString();
  return word + digits;
}

function generateDevTest() {
  const prefixes = ['test', 'dev', 'demo', 'sample', 'temp', 'local'];
  const prefix = prefixes[Utils.randomInt(0, prefixes.length - 1)];
  return `${prefix}_${Utils.randomInt(1000, 9999)}_${generateStrong(8, { useSymbols: false })}`;
}

function getStrengthLevel(password) {
  const score = evaluateStrength(password);
  if (score >= 90) return { level: 4, label: 'Very Strong', color: 'var(--safe)' };
  if (score >= 70) return { level: 3, label: 'Strong',      color: 'var(--safe)' };
  if (score >= 50) return { level: 2, label: 'Medium',      color: 'var(--warn)' };
  if (score >= 30) return { level: 1, label: 'Weak',        color: 'var(--danger)' };
  return              { level: 0, label: 'Very Weak',   color: 'var(--danger)' };
}

function evaluateStrength(password) {
  let score = 0;
  if (password.length >= 12) score += 20;
  if (password.length >= 16) score += 10;
  if (password.length >= 20) score += 10;
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 20;

  // Entropy bonus
  const entropy = Utils.entropy(password);
  if (entropy > 3) score += 10;
  if (entropy > 4) score += 10;

  return Math.min(score, 100);
}

export function renderPasswordGenerator(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = `
    <div class="tool-header">
      <h1 class="tool-title">Password Generator</h1>
      <p class="tool-subtitle">CRYPTOGRAPHICALLY SECURE · CLIENT-SIDE · NEVER STORED</p>
      <span class="tool-privacy-badge">🔒 Passwords never leave your device</span>
    </div>

    <div class="card">
      <div class="card-title">Generator Mode</div>
      <div style="display:flex; gap:var(--space-sm); flex-wrap:wrap; margin-bottom:var(--space-md);">
        ${[
          { id: 'strong',     label: '🔐 Strong',     desc: 'Random secure password' },
          { id: 'passphrase', label: '📖 Passphrase',  desc: 'Word-based, easier to remember' },
          { id: 'memorable',  label: '🧠 Memorable',   desc: 'Pronounceable pattern' },
          { id: 'devtest',    label: '💻 Dev/Test',    desc: 'For development use only' }
        ].map(m => `
          <button class="btn ${m.id === 'strong' ? 'btn-primary' : 'btn-secondary'} mode-btn" data-mode="${m.id}" title="${m.desc}">
            ${m.label}
          </button>
        `).join('')}
      </div>

      <!-- Strong options -->
      <div id="options-strong">
        <div class="grid-2" style="margin-bottom:var(--space-md);">
          <div>
            <label class="input-label">Length: <span id="length-val">20</span></label>
            <input type="range" id="pw-length" min="8" max="64" value="20" style="width:100%;accent-color:var(--accent);">
          </div>
          <div style="display:flex; flex-direction:column; gap:6px; padding-top: 20px;">
            ${[
              ['useUpper',   'Uppercase (A–Z)'],
              ['useLower',   'Lowercase (a–z)'],
              ['useDigits',  'Numbers (0–9)'],
              ['useSymbols', 'Symbols (!@#)']
            ].map(([id, label]) => `
              <label class="toggle-group">
                <input class="toggle-input" type="checkbox" id="${id}" checked>
                <span class="toggle-track"></span>
                <span class="toggle-label">${label}</span>
              </label>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Passphrase options -->
      <div id="options-passphrase" style="display:none;">
        <div class="grid-2" style="margin-bottom:var(--space-md);">
          <div>
            <label class="input-label">Word count: <span id="word-count-val">4</span></label>
            <input type="range" id="word-count" min="3" max="8" value="4" style="width:100%;accent-color:var(--accent);">
          </div>
          <div>
            <label class="input-label">Separator</label>
            <select class="input-field" id="separator" style="padding:8px 12px;">
              <option value="-">Hyphen (word-word)</option>
              <option value=".">Dot (word.word)</option>
              <option value="_">Underscore (word_word)</option>
              <option value=" ">Space (word word)</option>
            </select>
          </div>
        </div>
      </div>

      <button class="btn btn-primary btn-full" id="generate-btn" style="margin-top:4px;">
        ⚡ Generate Password
      </button>
    </div>

    <!-- Output -->
    <div id="pw-output" style="display:none;">
      <div class="card">
        <div class="card-title">Generated Password</div>
        <div class="code-block" id="pw-display" style="font-size:18px; letter-spacing:0.05em; cursor:pointer; text-align:center; padding:var(--space-lg);">
          —
        </div>

        <div style="margin:var(--space-md) 0;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span class="input-label" style="margin:0;">Strength</span>
            <span id="strength-label" style="font-family:var(--font-mono); font-size:11px;"></span>
          </div>
          <div class="strength-meter" id="strength-meter">
            ${[0,1,2,3,4].map(i => `<div class="strength-bar" id="sbar-${i}"></div>`).join('')}
          </div>
          <div style="display:flex; justify-content:space-between; font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-top:4px;">
            <span>⏱️ Crack time: <span id="crack-time">—</span></span>
            <span>Entropy: <span id="entropy-val">—</span> bits</span>
          </div>
        </div>

        <div style="display:flex; gap:var(--space-sm);">
          <button class="btn btn-primary" id="copy-pw-btn" style="flex:1;">📋 Copy Password</button>
          <button class="btn btn-secondary" id="regen-btn">🔄 Regenerate</button>
        </div>
      </div>
    </div>
  `;

  let currentMode = 'strong';

  // Mode switching
  container.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.mode-btn').forEach(b => {
        b.className = 'btn btn-secondary mode-btn';
      });
      btn.className = 'btn btn-primary mode-btn';
      currentMode = btn.dataset.mode;

      ['strong', 'passphrase'].forEach(m => {
        const el = container.querySelector(`#options-${m}`);
        if (el) el.style.display = m === currentMode ? 'block' : 'none';
      });

      generate();
    });
  });

  // Length slider
  const lengthSlider = container.querySelector('#pw-length');
  const lengthVal = container.querySelector('#length-val');
  lengthSlider.addEventListener('input', () => {
    lengthVal.textContent = lengthSlider.value;
    generate();
  });

  // Word count slider
  const wordCountSlider = container.querySelector('#word-count');
  const wordCountVal = container.querySelector('#word-count-val');
  wordCountSlider.addEventListener('input', () => {
    wordCountVal.textContent = wordCountSlider.value;
    generate();
  });

  // Checkbox toggles
  container.querySelectorAll('.toggle-input').forEach(cb => {
    cb.addEventListener('change', generate);
  });

  container.querySelector('#separator').addEventListener('change', generate);

  function generate() {
    let password = '';

    if (currentMode === 'strong') {
      const length = parseInt(container.querySelector('#pw-length').value);
      const options = {
        useUpper:   container.querySelector('#useUpper').checked,
        useLower:   container.querySelector('#useLower').checked,
        useDigits:  container.querySelector('#useDigits').checked,
        useSymbols: container.querySelector('#useSymbols').checked
      };
      password = generateStrong(length, options);
    } else if (currentMode === 'passphrase') {
      const count = parseInt(container.querySelector('#word-count').value);
      const sep = container.querySelector('#separator').value;
      password = generatePassphrase(count, sep);
    } else if (currentMode === 'memorable') {
      password = generateMemorable(12);
    } else if (currentMode === 'devtest') {
      password = generateDevTest();
    }

    const output = container.querySelector('#pw-output');
    const display = container.querySelector('#pw-display');

    output.style.display = 'block';
    display.textContent = password;

    // Update strength
    const strength = getStrengthLevel(password);
    container.querySelector('#strength-label').textContent = strength.label;
    container.querySelector('#strength-label').style.color = strength.color;

    for (let i = 0; i <= 4; i++) {
      const bar = container.querySelector(`#sbar-${i}`);
      bar.style.background = i <= strength.level ? strength.color : 'var(--border)';
    }

    container.querySelector('#crack-time').textContent = Utils.crackTime(password);
    container.querySelector('#entropy-val').textContent =
      (Utils.entropy(password) * password.length).toFixed(1);

    // Copy on display click
    display.onclick = async () => {
      await Utils.copyToClipboard(password);
      display.style.color = 'var(--safe)';
      setTimeout(() => { display.style.color = ''; }, 1500);
    };
  }

  container.querySelector('#generate-btn').addEventListener('click', generate);
  container.querySelector('#regen-btn')?.addEventListener('click', generate);

  container.querySelector('#copy-pw-btn').addEventListener('click', async () => {
    const pw = container.querySelector('#pw-display').textContent;
    await Utils.copyToClipboard(pw);
    Utils.showCopyFeedback(container.querySelector('#copy-pw-btn'), '📋 Copy Password');
  });

  // Generate on load
  generate();
}

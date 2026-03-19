/**
 * Privacy First Security Toolkit
 * Tool: Random Identity Generator — tools/identity-generator.js
 *
 * Generates fake identities for testing and development.
 * No real data. All synthetic.
 */

import { Utils } from '../core/utils.js';

const FIRST_NAMES = [
  'James','Mary','Robert','Patricia','John','Jennifer','Michael','Linda',
  'William','Barbara','David','Elizabeth','Richard','Susan','Joseph','Jessica',
  'Thomas','Sarah','Charles','Karen','Alex','Jordan','Taylor','Morgan',
  'Avery','Riley','Cameron','Quinn','Sage','Hayden','Blake','Parker',
  'Luca','Aria','Noah','Olivia','Ethan','Ava','Mason','Emma'
];

const LAST_NAMES = [
  'Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis',
  'Rodriguez','Martinez','Hernandez','Lopez','Gonzalez','Wilson','Anderson',
  'Thomas','Taylor','Moore','Jackson','Martin','Lee','Perez','Thompson',
  'White','Harris','Sanchez','Clark','Ramirez','Lewis','Robinson',
  'Walker','Young','Allen','King','Wright','Scott','Torres','Nguyen'
];

const STREET_TYPES = ['Street','Avenue','Boulevard','Drive','Road','Lane','Way','Court','Place'];
const STREET_NAMES = ['Oak','Maple','Pine','Cedar','Elm','Willow','River','Lake','Hill','Park',
  'Main','First','Second','Third','Market','Church','School','Forest','Valley'];
const CITIES = [
  { city: 'Austin', state: 'TX', zip: '78701' },
  { city: 'Denver', state: 'CO', zip: '80201' },
  { city: 'Portland', state: 'OR', zip: '97201' },
  { city: 'Nashville', state: 'TN', zip: '37201' },
  { city: 'Chicago', state: 'IL', zip: '60601' },
  { city: 'Phoenix', state: 'AZ', zip: '85001' },
  { city: 'Atlanta', state: 'GA', zip: '30301' },
  { city: 'Seattle', state: 'WA', zip: '98101' },
  { city: 'Miami', state: 'FL', zip: '33101' },
  { city: 'Boston', state: 'MA', zip: '02101' },
];

const DOMAINS = ['gmail.com', 'yahoo.com', 'outlook.com', 'protonmail.com', 'icloud.com', 'example.com'];
const COMPANIES = ['Acme Corp', 'Globex', 'Initech', 'Umbrella Inc', 'Dunder Mifflin', 'Stark Industries',
  'Wayne Enterprises', 'Soylent Corp', 'Weyland Corp', 'OCP', 'Cyberdyne Systems'];
const JOBS = ['Software Engineer', 'Product Manager', 'Designer', 'Data Analyst', 'Marketing Manager',
  'Sales Representative', 'Customer Support', 'Operations Manager', 'QA Engineer', 'DevOps Engineer'];

function pick(arr) {
  return arr[Utils.randomInt(0, arr.length - 1)];
}

function randomDigits(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += Utils.randomInt(0, 9);
  return s;
}

function generateIdentity() {
  const firstName = pick(FIRST_NAMES);
  const lastName  = pick(LAST_NAMES);
  const location  = pick(CITIES);

  const emailUser = `${firstName.toLowerCase()}.${lastName.toLowerCase()}${Utils.randomInt(1, 999)}`;
  const emailDomain = pick(DOMAINS);

  const dob = new Date(
    Utils.randomInt(1970, 2000),
    Utils.randomInt(0, 11),
    Utils.randomInt(1, 28)
  );

  const street = `${Utils.randomInt(10, 9999)} ${pick(STREET_NAMES)} ${pick(STREET_TYPES)}`;
  const zip    = location.zip.slice(0, 3) + randomDigits(2);

  const phone = `(${randomDigits(3)}) ${randomDigits(3)}-${randomDigits(4)}`;

  const company = pick(COMPANIES);
  const job     = pick(JOBS);

  const username = `${firstName.toLowerCase()}_${lastName.toLowerCase().slice(0,4)}${Utils.randomInt(10,99)}`;

  return {
    name:      { first: firstName, last: lastName, full: `${firstName} ${lastName}` },
    dob:       dob.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
    age: (() => {
    const today = new Date();
    let age = today.getFullYear() - dob.getFullYear();
    const m = today.getMonth() - dob.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
    return age;
  })(),
    email:     `${emailUser}@${emailDomain}`,
    phone,
    username,
    password:  generateTestPassword(),
    address: {
      street,
      city: location.city,
      state: location.state,
      zip
    },
    company,
    job,
    website:   `https://www.example.com/users/${username}`,
    avatar:    generateAvatarSVG(firstName[0] + lastName[0]),
    uuid:      generateUUID(),
    ipv4:      generateIPv4(),
    userAgent: generateUserAgent(),
  };
}

function generateTestPassword() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$';
  let pw = '';
  for (let i = 0; i < 16; i++) pw += chars[Utils.randomInt(0, chars.length - 1)];
  return pw;
}

function generateUUID() {
  const bytes = Utils.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

function generateIPv4() {
  return `${Utils.randomInt(1,254)}.${Utils.randomInt(0,255)}.${Utils.randomInt(0,255)}.${Utils.randomInt(1,254)}`;
}

function generateUserAgent() {
  const browsers = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
  ];
  return pick(browsers);
}

function generateAvatarSVG(initials) {
  const colors = ['#00d4ff', '#00e676', '#ffab00', '#ff3d71', '#7c4dff'];
  const color = pick(colors);
  return `data:image/svg+xml,${encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 60 60">
      <circle cx="30" cy="30" r="30" fill="${color}22"/>
      <circle cx="30" cy="30" r="29" fill="none" stroke="${color}" stroke-width="1"/>
      <text x="50%" y="55%" text-anchor="middle" fill="${color}" font-family="monospace" font-size="20" font-weight="bold">${initials}</text>
    </svg>
  `)}`;
}

export function renderIdentityGenerator(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  let current = generateIdentity();

  function render() {
    container.innerHTML = `
      <div class="tool-header">
        <h1 class="tool-title">Random Identity Generator</h1>
        <p class="tool-subtitle">FOR DEVELOPERS & TESTING ONLY · NOT REAL DATA</p>
        <span class="tool-privacy-badge">⚠️ Test data only — do not use for fraud</span>
      </div>

      <div style="display:flex; gap:var(--space-sm); margin-bottom:var(--space-md); flex-wrap:wrap;">
        <button class="btn btn-primary" id="regen-id-btn">🔄 Generate New Identity</button>
        <button class="btn btn-secondary" id="copy-text-btn">📋 Copy as Text</button>
        <button class="btn btn-secondary" id="copy-json-btn">{ } Copy as JSON</button>
      </div>

      <div class="grid-2">
        <!-- Left column -->
        <div>
          <div class="card">
            <div style="text-align:center; margin-bottom:var(--space-md);">
              <img src="${current.avatar}" style="width:60px;height:60px;border-radius:50%;" />
              <div style="font-size:18px;font-weight:700;margin-top:var(--space-sm);">${Utils.escapeHTML(current.name.full)}</div>
              <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">@${Utils.escapeHTML(current.username)}</div>
            </div>

            ${[
              ['📅 Date of Birth',  `${current.dob} (age ${current.age})`],
              ['📧 Email',          current.email],
              ['📞 Phone',          current.phone],
              ['🏢 Company',        current.company],
              ['💼 Job Title',      current.job],
            ].map(([label, val]) => `
              <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border);">
                <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${label}</span>
                <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-primary);">${Utils.escapeHTML(String(val))}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Right column -->
        <div>
          <div class="card">
            <div class="card-title">📍 Address</div>
            <div class="code-block" style="line-height:2;">
              ${Utils.escapeHTML(current.address.street)}<br/>
              ${Utils.escapeHTML(current.address.city)}, ${Utils.escapeHTML(current.address.state)} ${Utils.escapeHTML(current.address.zip)}
            </div>
          </div>

          <div class="card" style="margin-top:var(--space-md);">
            <div class="card-title">🔐 Test Credentials</div>
            ${[
              ['Username', current.username],
              ['Password', current.password],
              ['UUID', current.uuid],
            ].map(([label, val]) => `
              <div style="margin-bottom:var(--space-sm);">
                <div style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-bottom:3px;">${label}</div>
                <div class="code-block" style="font-size:11px; padding:6px 10px;">${Utils.escapeHTML(val)}</div>
              </div>
            `).join('')}
          </div>

          <div class="card" style="margin-top:var(--space-md);">
            <div class="card-title">🌐 Network</div>
            ${[
              ['IPv4', current.ipv4],
              ['User Agent', Utils.truncate(current.userAgent, 50)],
            ].map(([label, val]) => `
              <div style="margin-bottom:var(--space-sm);">
                <div style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted); margin-bottom:3px;">${label}</div>
                <div class="code-block" style="font-size:10px; padding:6px 10px;">${Utils.escapeHTML(val)}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <div class="card" style="margin-top:var(--space-md); background:var(--warn-dim); border:1px solid rgba(255,171,0,0.2);">
        <p style="font-size:12px; color:var(--warn); font-family:var(--font-mono);">
          ⚠️ This data is entirely synthetic and randomly generated. It is intended for software testing and development only. Using fake identities for fraud or deception is illegal.
        </p>
      </div>
    `;

    container.querySelector('#regen-id-btn').addEventListener('click', () => {
      current = generateIdentity();
      render();
    });

    container.querySelector('#copy-text-btn').addEventListener('click', async (e) => {
      const text = [
        `Name:       ${current.name.full}`,
        `Birthday:   ${current.dob} (age ${current.age})`,
        `Email:      ${current.email}`,
        `Phone:      ${current.phone}`,
        `Username:   ${current.username}`,
        `Password:   ${current.password}`,
        ``,
        `Address:    ${current.address.street}`,
        `            ${current.address.city}, ${current.address.state} ${current.address.zip}`,
        ``,
        `Company:    ${current.company}`,
        `Job:        ${current.job}`,
        `Website:    ${current.website}`,
        ``,
        `UUID:       ${current.uuid}`,
        `IPv4:       ${current.ipv4}`,
        `User Agent: ${current.userAgent}`,
      ].join('\n');
      await Utils.copyToClipboard(text);
      Utils.showCopyFeedback(e.target, 'Copy as Text');
    });

    container.querySelector('#copy-json-btn').addEventListener('click', async (e) => {
      const { avatar, ...clean } = current;
      const json = JSON.stringify(clean, null, 2);
      await Utils.copyToClipboard(json);
      Utils.showCopyFeedback(e.target, 'Copy as JSON');
    });
  }

  render();
}

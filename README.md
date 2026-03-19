# Privacy First Security Toolkit

> **Verify everything. Store nothing. Track nothing.**

A free, open source cybersecurity toolkit that runs entirely in your browser.
No accounts. No analytics. No cloud. No tracking. 100% local processing.

---

## Tools

### Security Analysis
| Tool | Description | Processing |
|------|-------------|------------|
| **Link Analyzer** | Phishing detection, homograph attacks, brand impersonation, redirect chains, tracking parameters | Local |
| **QR Scanner** | Decode QR codes and analyze destinations for threats | Local |
| **File Analyzer** | Magic byte detection, double extension attacks, malware file signatures | Local |
| **Scam Detector** | Pattern matching for urgency language, authority impersonation, payment fraud | Local |
| **Fake Domain Detector** | Brand impersonation, typosquatting, TLD substitution, homograph domains | Local |

### Privacy Tools
| Tool | Description | Processing |
|------|-------------|------------|
| **Tracking Cleaner** | Strips UTM, fbclid, gclid, msclkid and 60+ tracking parameters | Local |
| **Fingerprint Viewer** | Shows what websites can learn about your browser | Local |
| **Encryption Tool** | AES-256-GCM text encryption with PBKDF2 key derivation (250k iterations) | Local |

### Developer Tools
| Tool | Description | Processing |
|------|-------------|------------|
| **JWT Decoder** | Decode, inspect, expiry check, algorithm audit | Local |
| **Hash Generator** | SHA-1, SHA-256, SHA-384, SHA-512, HMAC, file hashing | Local |
| **Base64 Tool** | Encode/decode, URL-safe, file encoding, image preview, auto-detect | Local |
| **Password Generator** | Strong, passphrase, memorable, dev/test modes with crack time estimation | Local |
| **Identity Generator** | Synthetic test data for developers (not for fraud) | Local |

---

## Quick Start

### Run locally (Termux / any Python)
```bash
git clone https://github.com/your-username/privacy-toolkit.git
cd privacy-toolkit
python server.py
# Open http://localhost:8080
```

### Use offline
```bash
# Download once, use forever
git clone https://github.com/your-username/privacy-toolkit.git
cd privacy-toolkit
python server.py
# Works completely offline after first clone
```

---

## Developer Integration

Import individual tools directly in your ES Module project:

```javascript
import { analyzeURL }    from './tools/link-analyzer.js';
import { analyzeMessage } from './tools/scam-detector.js';
import { decodeJWT }     from './tools/jwt-decoder.js';

// Analyze a suspicious URL
const result = await analyzeURL('https://paypaI-login-secure.xyz');
console.log(result.riskLevel);   // 'critical'
console.log(result.riskScore);   // 95
console.log(result.warnings);    // Array of warning objects
console.log(result.explanation); // Human readable explanation

// Analyze a suspicious message
const scam = await analyzeMessage('Your account will be suspended. Send OTP immediately.');
console.log(scam.score);         // 0-100
console.log(scam.riskLevel);     // 'High'
console.log(scam.signals);       // Detected scam signals

// Decode a JWT
const jwt = decodeJWT('eyJhbGci...');
console.log(jwt.header);         // { alg: 'HS256', typ: 'JWT' }
console.log(jwt.payload);        // Decoded claims
console.log(jwt.expiryStatus);   // { status: 'valid', label: 'Valid', detail: '...' }
```

Or use the full SDK:

```javascript
import toolkit from './sdk/toolkit.js';

const { LinkScanner, ScamDetector, Encryption, HashGenerator } = toolkit;

// Clean tracking params
const { cleanURL, removed } = await LinkScanner.clean(
  'https://example.com?utm_source=facebook&fbclid=abc123'
);

// Encrypt text with AES-256-GCM
const encrypted = await Encryption.encrypt('secret message', 'strong-password');
const decrypted = await Encryption.decrypt(encrypted, 'strong-password');
```

---

## Plugin System

Extend the toolkit with custom security plugins:

```javascript
// plugins/my-detector/main.js
const MyPlugin = {
  name: 'my-detector',
  version: '1.0.0',
  type: 'LINK_ANALYSIS',
  description: 'Custom threat detection',

  run(input) {
    // Analyze input, return null or findings object
    return {
      pluginName: this.name,
      score: 80,
      findings: [{ type: 'custom_threat', detail: 'Detected X', severity: 'high' }]
    };
  }
};

export default MyPlugin;
```

Register in your app:
```javascript
import { engine } from './core/engine.js';
import MyPlugin from './plugins/my-detector/main.js';

engine.register(MyPlugin);
const results = await engine.runPlugins('LINK_ANALYSIS', 'https://suspicious.com');
```

---

## Privacy Architecture

```
User Input
    │
    ▼
Browser Memory Only
    │
    ├── Local Analysis (pattern matching, heuristics)
    │
    ├── Web Crypto API (hashing, encryption, key derivation)
    │
    └── Result Displayed
            │
            ▼
    Nothing stored. Nothing sent.
```

**Privacy guarantees:**
- No cookies set
- No localStorage used
- No sessionStorage used
- No analytics or tracking scripts
- No user accounts or sessions
- All processing in browser memory only
- Data cleared when tab closes

---

## Security Standards Used

| Feature | Standard |
|---------|----------|
| Encryption | AES-256-GCM (NIST FIPS 197) |
| Key Derivation | PBKDF2-SHA256, 250,000 iterations |
| Password Generation | Web Crypto API (CSPRNG) |
| Hashing | SHA-256, SHA-512 (NIST FIPS 180-4) |
| HMAC | HMAC-SHA256, HMAC-SHA512 (RFC 2104) |

---

## Project Structure

```
privacy-toolkit/
├── index.html              Main application shell
├── style.css               Design system (CSS variables)
├── app.js                  App bootstrap and router
├── server.py               Local development server
├── package.json            Package metadata
├── LICENSE                 MIT License
│
├── core/
│   ├── engine.js           Plugin engine
│   ├── icons.js            SVG icon system (Heroicons)
│   ├── router.js           Hash-based client router
│   └── utils.js            Shared utilities
│
├── tools/                  13 security tools
├── plugins/                Community plugin directory
├── data/                   Threat intelligence (JSON)
└── sdk/                    Developer integration SDK
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Ways to contribute:**
- Add a security plugin
- Submit threat intelligence data (phishing domains, scam patterns)
- Fix bugs or improve detection accuracy
- Improve documentation
- Translate the UI

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

## Acknowledgments

- Icons by [Heroicons](https://heroicons.com) (MIT)
- QR decoding by [jsQR](https://github.com/cozmo/jsQR) (Apache 2.0)
- Wordlist from [EFF Diceware](https://www.eff.org/dice) (CC BY 3.0)

# Contributing to Privacy First Security Toolkit

Thank you for your interest in contributing. This project is built on one principle:
**privacy first, always.** Every contribution must respect that.

---

## Core Rules for Contributors

Before writing any code, understand these non-negotiable rules:

1. **No data collection** — no analytics, no telemetry, no logging of user input
2. **No external requests** — tools must not send data to third-party servers without explicit user opt-in
3. **Client-side first** — every feature must work locally without internet if at all possible
4. **No cookies, no session storage, no IndexedDB** for user input
5. **No new dependencies** without discussion — the project stays lightweight on purpose

---

## Ways to Contribute

### Add a Plugin
The easiest way to contribute. See `/plugins/phishing-detector/` for an example.

Each plugin needs:
- `plugin.json` — metadata
- `main.js` — your analysis logic
- `README.md` — what your plugin does and how

Plugin types available:
- `LINK_ANALYSIS` — analyze URLs
- `QR_ANALYSIS` — analyze QR code destinations
- `SCAM_PATTERN` — detect scam message patterns
- `FILE_ANALYSIS` — analyze files
- `DOMAIN_ANALYSIS` — analyze domain reputation
- `TRACKING_CLEANER` — remove tracking parameters

### Add Threat Intelligence Data
Submit additions to the `/data/` directory:
- `known-brands.json` — brands commonly impersonated
- `scam-patterns.json` — scam message patterns
- `suspicious-tlds.json` — abused domain extensions
- `tracking-params.json` — tracking parameters to strip

### Fix Bugs
Check the Issues tab for open bugs. Look for the `good first issue` label.

### Improve Documentation
Documentation PRs are always welcome.

---

## Getting Started

```bash
# Fork the repository on GitHub
# Then clone your fork:
git clone https://github.com/YOUR-USERNAME/privacy-toolkit.git
cd privacy-toolkit

# Run locally
python server.py

# Open http://localhost:8080
```

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test everything works locally
5. Commit with a clear message: `git commit -m "feat: add X detection to link analyzer"`
6. Push: `git push origin feature/your-feature-name`
7. Open a Pull Request and describe what you changed and why

---

## Commit Message Format

Use conventional commits:

```
feat: add new tool or feature
fix: fix a bug
data: update threat intelligence data
docs: documentation only changes
plugin: add or update a plugin
refactor: code change that doesn't add features or fix bugs
style: formatting, CSS changes
```

---

## Writing a Plugin

```javascript
// plugins/my-detector/main.js

const MyDetectorPlugin = {
  name: 'my-detector',
  version: '1.0.0',
  type: 'LINK_ANALYSIS',      // or SCAM_PATTERN, FILE_ANALYSIS, etc.
  description: 'Detects XYZ',

  run(input) {
    // Analyze input
    // Return null if nothing found
    // Return an object with findings if something detected

    const findings = [];

    // Your detection logic here

    if (findings.length === 0) return null;

    return {
      pluginName: this.name,
      score: 75,          // 0-100 risk score
      findings
    };
  }
};

export default MyDetectorPlugin;
```

---

## Questions?

Open a GitHub Discussion or an Issue. We respond to all questions.

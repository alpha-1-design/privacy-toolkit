/**
 * Privacy First Security Toolkit
 * Vercel Serverless Function — api/virustotal.js
 *
 * Proxies requests to VirusTotal API to work around browser CORS restrictions.
 * API key is passed in the X-VT-Key header and never logged or stored.
 */

const VT_API_BASE = 'https://www.virustotal.com/api/v3';

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-VT-Key, X-VT-Path');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const apiKey = req.headers['x-vt-key'];
  const vtPath = req.headers['x-vt-path'];

  if (!apiKey) return res.status(401).json({ error: 'No API key provided', code: 'NO_KEY' });
  if (!vtPath) return res.status(400).json({ error: 'No VT path specified', code: 'NO_PATH' });

  const vtURL = VT_API_BASE + vtPath;

  try {
    const options = {
      method: req.method,
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    };

    if (req.method === 'POST' && req.body) {
      options.body = new URLSearchParams(req.body).toString();
    }

    const vtRes = await fetch(vtURL, options);
    const data  = await vtRes.json();

    return res.status(vtRes.status).json(data);

  } catch (err) {
    return res.status(503).json({
      error: 'Could not reach VirusTotal. Check your internet connection.',
      code: 'NETWORK'
    });
  }
}

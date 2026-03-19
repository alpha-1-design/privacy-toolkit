#!/usr/bin/env python3
"""
Privacy First Security Toolkit - Local Server
Run: python server.py
Then open: http://localhost:8080

Includes a /api/virustotal proxy to work around browser CORS restrictions.
The proxy forwards requests to VirusTotal on behalf of the browser.
API keys are never logged.
"""

import http.server
import socketserver
import os
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

PORT = 8080
VT_API_BASE = 'https://www.virustotal.com/api/v3'

class PrivacyFirstHandler(http.server.SimpleHTTPRequestHandler):

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:8080')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:8080')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-VT-Key, X-VT-Path')
        self.end_headers()

    def do_POST(self):
        if self.path.startswith('/api/virustotal'):
            self._handle_vt_proxy()
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path.startswith('/api/virustotal'):
            self._handle_vt_proxy()
        else:
            super().do_GET()

    def _handle_vt_proxy(self):
        try:
            # API key comes from request header - never logged
            api_key = self.headers.get('X-VT-Key', '')
            if not api_key:
                self._json_response(401, {'error': 'No API key provided', 'code': 'NO_KEY'})
                return

            # VT path comes from header e.g. /urls/abc123 or /analyses/abc123
            vt_path = self.headers.get('X-VT-Path', '')
            if not vt_path:
                self._json_response(400, {'error': 'No VT path specified', 'code': 'NO_PATH'})
                return

            vt_url = VT_API_BASE + vt_path
            method  = self.command  # GET or POST

            # Read request body if POST
            body = None
            if method == 'POST':
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length) if length else None

            # Forward request to VirusTotal
            req = urllib.request.Request(
                vt_url,
                data=body,
                headers={
                    'x-apikey': api_key,
                    'Content-Type': self.headers.get('Content-Type', 'application/x-www-form-urlencoded'),
                },
                method=method
            )

            with urllib.request.urlopen(req, timeout=15) as res:
                data = res.read()
                self._json_response(res.status, json.loads(data))

        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                self._json_response(e.code, json.loads(body))
            except Exception:
                self._json_response(e.code, {'error': str(e), 'code': str(e.code)})
        except urllib.error.URLError as e:
            self._json_response(503, {'error': 'Could not reach VirusTotal. Check your internet connection.', 'code': 'NETWORK'})
        except Exception as e:
            self._json_response(500, {'error': f'Proxy error: {str(e)}', 'code': 'PROXY_ERROR'})

    def _json_response(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Only log path type, never log URLs or API keys
        if self.path.startswith('/api/virustotal'):
            print('[Server] VirusTotal proxy request')
        else:
            print('[Server] Static file request')


os.chdir(os.path.dirname(os.path.abspath(__file__)))

with socketserver.TCPServer(('', PORT), PrivacyFirstHandler) as httpd:
    httpd.allow_reuse_address = True
    print(f"""
╔══════════════════════════════════════════╗
║   Privacy First Security Toolkit         ║
║   Running at http://localhost:{PORT}        ║
║   Press Ctrl+C to stop                   ║
║                                          ║
║   VirusTotal proxy: /api/virustotal      ║
║   Verify everything. Store nothing.      ║
╚══════════════════════════════════════════╝
    """)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n[Server] Stopped. Your privacy remains intact.')
        sys.exit(0)

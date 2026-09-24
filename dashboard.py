import html
import io
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
REPORT_FILE = ROOT / "scan_report.json"
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"


class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            return self.serve_file(FRONTEND / 'index.html', 'text/html; charset=utf-8')
        if self.path.startswith('/static/'):
            path = FRONTEND / self.path[len('/static/'):]
            if path.suffix == '.css':
                return self.serve_file(path, 'text/css; charset=utf-8')
            if path.suffix == '.js':
                return self.serve_file(path, 'application/javascript; charset=utf-8')
            return self.serve_file(path, 'application/octet-stream')
        if self.path == '/report':
            return self.serve_report()
        self.send_error(404)

    def do_POST(self):
        if self.path == '/scan':
            # Run scanner safely
            try:
                run = subprocess.run([sys.executable, str(SCANNER_FILE)], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                out = {'returncode': run.returncode}
                self.wfile.write(json.dumps(out).encode('utf-8'))
            except subprocess.TimeoutExpired:
                self.send_error(504, 'Scanner timed out')
            return
        self.send_error(404)

    def serve_file(self, path: Path, content_type: str):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_report(self):
        try:
            raw = REPORT_FILE.read_text(encoding='utf-8')
            report = json.loads(raw)
        except FileNotFoundError:
            report = {
                'checked_at_utc': '—',
                'overall_result': 'INCONCLUSIVE',
                'checks': [],
                'error': 'No scan report available. Run scan to generate one.'
            }
        except json.JSONDecodeError:
            report = {
                'checked_at_utc': '—',
                'overall_result': 'INCONCLUSIVE',
                'checks': [],
                'error': 'Report is invalid JSON.'
            }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        body = json.dumps(report).encode('utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    print('Dashboard: http://127.0.0.1:8501')
    HTTPServer(('127.0.0.1', 8501), Dashboard).serve_forever()

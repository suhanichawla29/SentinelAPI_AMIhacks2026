import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="SentinelAPI Scalable Scanner")

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"
DEFAULT_REPORT = ROOT / "scan_report.json"

# Serve static frontend files
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

class ScanRequest(BaseModel):
    target_url: Optional[str] = "http://127.0.0.1:8000"

def run_scanner_job(scan_id: str, target_url: str):
    out_file = REPORTS_DIR / f"{scan_id}.json"
    try:
        # Run Scanner (Scan.py handles default scan and writes scan_report.json)
        run = subprocess.run(
            [sys.executable, str(SCANNER_FILE)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # If Scan.py wrote scan_report.json, copy it to the unique report file
        if DEFAULT_REPORT.exists():
            data = json.loads(DEFAULT_REPORT.read_text(encoding="utf-8"))
            data["scan_id"] = scan_id
            data["target_url"] = target_url
            out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            fallback = {
                "scan_id": scan_id,
                "target_url": target_url,
                "overall_result": "PASS" if run.returncode == 0 else "FAIL",
                "checks": [],
                "output": run.stdout or run.stderr
            }
            out_file.write_text(json.dumps(fallback, indent=2), encoding="utf-8")
    except Exception as e:
        err_report = {
            "scan_id": scan_id,
            "target_url": target_url,
            "overall_result": "FAIL",
            "checks": [],
            "error": str(e)
        }
        out_file.write_text(json.dumps(err_report, indent=2), encoding="utf-8")

@app.get("/")
def serve_dashboard():
    return FileResponse(FRONTEND / "index.html")

@app.get("/style.css")
def serve_css():
    return FileResponse(FRONTEND / "style.css")

@app.get("/script.js")
def serve_js():
    return FileResponse(FRONTEND / "script.js")

@app.post("/scan")
async def trigger_scan(bg: BackgroundTasks, request: Request):
    target_url = "http://127.0.0.1:8000"
    try:
        body = await request.json()
        if body and "target_url" in body:
            target_url = body["target_url"]
    except Exception:
        pass  # Keep default if body is empty

    scan_id = str(uuid.uuid4())[:8]
    bg.add_task(run_scanner_job, scan_id, target_url)
    return {"status": "queued", "scan_id": scan_id}

@app.get("/report")
def get_latest_report():
    if DEFAULT_REPORT.exists():
        try:
            return json.loads(DEFAULT_REPORT.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "checked_at_utc": "—",
        "overall_result": "INCONCLUSIVE",
        "checks": [],
        "error": "No scan report available yet. Click Run Security Scan to generate one."
    }

@app.get("/report/{scan_id}")
def get_specific_report(scan_id: str):
    target_path = REPORTS_DIR / f"{scan_id}.json"
    if not target_path.exists():
        return {"status": "running", "scan_id": scan_id}
    return json.loads(target_path.read_text(encoding="utf-8"))
    
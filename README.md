# SentinelAPI_AMIhacks2026
Zero-Trust API Vulnerability Scanner

This project tests a local sandbox API that simulates order access control. The scanner checks whether a valid user can read their own order, whether the API rejects a missing token, and whether a user can access another user's order.

## Install requirements

```powershell
python -m pip install "fastapi[standard]" httpx
```

## Vulnerable mode demo

Start the API in vulnerable mode from the repository root in one terminal:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026.worktrees\pasted-text-processing"
$env:SANDBOX_MODE = "vulnerable"
python -m uvicorn Sandbox_api.main:app --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026.worktrees\pasted-text-processing"
python dashboard.py
```

Open http://127.0.0.1:8501 and click Run scan. The dashboard should show the red VULNERABLE result for the missing token and other user's order checks.

## Secure mode demo

Stop the API with Ctrl+C, then restart it without the vulnerable mode flag:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026.worktrees\pasted-text-processing"
Remove-Item Env:SANDBOX_MODE -ErrorAction SilentlyContinue
python -m uvicorn Sandbox_api.main:app --host 127.0.0.1 --port 8000
```

Run the dashboard again, then click Run scan. The dashboard should show PASS for all three checks.

## Scanner and report

You can also run the scanner directly from the repository root:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026.worktrees\pasted-text-processing"
python Scanner/Scan.py
```

The scanner reads the API configuration from `Scanner/config.json` and writes a report to `scan_report.json` in the same format the dashboard reads.

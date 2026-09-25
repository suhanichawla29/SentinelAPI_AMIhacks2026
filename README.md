# SentinelAPI

Zero-trust API security testing console for the SentinelAPI hackathon track. The project includes a FastAPI sandbox, an OpenAPI-aware OWASP API scanner, and a browser dashboard.

## Requirements

- Python 3.10+
- A local API target, such as the included sandbox

Install dependencies:

```powershell
python -m pip install "fastapi[standard]" httpx
```

## Run the demo

Open two PowerShell terminals from the repository root:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026"
python -m uvicorn Sandbox_api.main:app --host 127.0.0.1 --port 8000
```

In the second terminal, start the dashboard:

```powershell
cd "C:\xampp\htdocs\SentinelAPI_AMIhacks2026"
python -m uvicorn server:app --host 127.0.0.1 --port 8501
```

Open [http://127.0.0.1:8501](http://127.0.0.1:8501). Enter a target URL and OpenAPI URL, choose a priority, and run the audit.

## Sandbox modes

The sandbox starts in secure mode. To demonstrate a vulnerable BOLA or authentication result, stop it and restart with a mode:

```powershell
$env:SANDBOX_MODE = "vulnerable"
python -m uvicorn Sandbox_api.main:app --host 127.0.0.1 --port 8000
```

Available modes:

- `secure`: ownership and authentication are enforced
- `vulnerable`: cross-user order access is allowed
- `no_auth`: authentication is disabled
- `broken_auth`: token validation rejects requests

## Run the scanner directly

```powershell
python Scanner/Scan.py
```

CLI options:

```text
--target   Base API URL (default: http://127.0.0.1:8000)
--spec     OpenAPI JSON URL (default: http://127.0.0.1:8000/openapi.json)
--out      Report destination (default: scan_report.json)
--priority all or high (default: all)
```

Example:

```powershell
python Scanner/Scan.py --target http://127.0.0.1:8000 --spec http://127.0.0.1:8000/openapi.json --priority all --out scan_report.json
```

The scanner checks API1 BOLA, API2 broken authentication, API3 sensitive data exposure, and API4 rate limiting. It ingests parameterized OpenAPI paths and falls back to the included order routes when the spec is unavailable.

## Server API

- `POST /scan`: queue a scan with `target_url`, optional `spec_url`, and `priority`
- `GET /report/{scan_id}`: retrieve a scan report
- `GET /scans`: list in-memory scan history
- `GET /report`: retrieve the latest canonical report
- `GET /`: serve the dashboard

Example request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8501/scan `
  -ContentType "application/json" `
  -Body '{"target_url":"http://127.0.0.1:8000","spec_url":"http://127.0.0.1:8000/openapi.json","priority":"all"}'
```

## Reports

- `scan_report.json`: latest direct scanner report
- `reports/<scan_id>.json`: reports created by the web server

Reports contain the overall result, timestamp, status, severity, OWASP category, explanation, suggested fix, status code, and reproducible cURL command for every check.

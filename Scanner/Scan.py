import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
FALLBACK_PATHS = ("/orders/101", "/orders/202", "/orders/ord-101", "/orders/ord-202")
SENSITIVE_KEYS = {"token", "secret", "password_hash", "ssn", "internal_id"}


def utc_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_args():
    parser = argparse.ArgumentParser(description="Run non-destructive OWASP API security checks")
    parser.add_argument("--target", default="http://127.0.0.1:8000", help="Base URL")
    parser.add_argument("--spec", default="http://127.0.0.1:8000/openapi.json", help="OpenAPI JSON URL")
    parser.add_argument("--out", default="scan_report.json", help="Destination JSON report path")
    parser.add_argument("--priority", choices=("all", "high"), default="all")
    return parser.parse_args()


def make_check(name, category, severity, priority, status, status_code, explanation, fix, command):
    return {
        "name": name,
        "category": category,
        "severity": severity,
        "priority": priority,
        "status": status,
        "status_code": status_code,
        "explanation": explanation,
        "suggested_fix": fix,
        "poc_curl": command,
    }


def absolute_url(base_url, path):
    return path if path.startswith(("http://", "https://")) else f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def path_candidates(spec):
    candidates = []
    spec_paths = spec.get("paths", {}) if isinstance(spec, dict) else {}
    if not any("{" in path and "}" in path for path in spec_paths):
        return []
    for path, operations in spec_paths.items():
        if not isinstance(operations, dict) or not any(method in operations for method in ("get", "post", "put", "patch", "delete")):
            continue
        if "{" in path and "}" in path:
            candidates.append(re.sub(r"\{[^}]+\}", "101", path))
        else:
            candidates.append(path)
    return list(dict.fromkeys(candidates))


def load_paths(client, spec_url):
    try:
        response = client.get(spec_url)
        response.raise_for_status()
        paths = path_candidates(response.json())
        return paths or list(FALLBACK_PATHS), None
    except (httpx.HTTPError, ValueError) as error:
        return list(FALLBACK_PATHS), f"OpenAPI spec unavailable; using fallback routes: {error}"


def json_payload(response):
    try:
        return response.json()
    except (ValueError, AttributeError):
        return None


def contains_sensitive_key(value):
    if isinstance(value, dict):
        return any(key.lower() in SENSITIVE_KEYS or contains_sensitive_key(item) for key, item in value.items())
    return any(contains_sensitive_key(item) for item in value) if isinstance(value, list) else False


def curl_command(url, token=None):
    auth = f" -H 'Authorization: Bearer {token}'" if token else ""
    return f"curl -i{auth} '{url}'"


def run_scan(args):
    base_url = args.target.rstrip("/")
    token = "asha-demo-token"
    checks = []
    with httpx.Client(timeout=5, follow_redirects=True) as client:
        paths, spec_note = load_paths(client, args.spec)
        order_paths = [path for path in paths if "/orders/" in path.lower()]
        own_path = next((path for path in order_paths if any(value in path for value in ("101", "ord-101"))), paths[0])
        ravi_path = next((path for path in order_paths if any(value in path for value in ("202", "ord-202", "102", "ord-102"))), "/orders/202")
        own_url = absolute_url(base_url, own_path)
        ravi_url = absolute_url(base_url, ravi_path)
        auth_headers = {"Authorization": f"Bearer {token}"}

        def request(path, headers=None):
            try:
                return client.get(path, headers=headers)
            except httpx.RequestError as error:
                return error

        missing = request(own_url)
        missing_code = missing.status_code if isinstance(missing, httpx.Response) else None
        missing_pass = missing_code in (401, 403)
        checks.append(make_check(
            "Missing Token", "API2:2023 Broken Authentication", "HIGH", "HIGH",
            "PASS" if missing_pass else "VULNERABLE", missing_code,
            "The API rejected a request without Authorization." if missing_pass else "The API returned the resource without an Authorization header.",
            "Require a valid Authorization header and return 401 or 403 when it is absent.", curl_command(own_url)))

        forged = request(own_url, {"Authorization": "Bearer forged-invalid-token"})
        forged_code = forged.status_code if isinstance(forged, httpx.Response) else None
        forged_pass = forged_code in (401, 403)
        checks.append(make_check(
            "Invalid Token", "API2:2023 Broken Authentication", "HIGH", "HIGH",
            "PASS" if forged_pass else "VULNERABLE", forged_code,
            "The API rejected a forged token." if forged_pass else "The API accepted a forged or invalid token.",
            "Validate token signatures, issuer, audience, expiry, and revocation state.", curl_command(own_url, "forged-invalid-token")))

        bola = request(ravi_url, auth_headers)
        bola_code = bola.status_code if isinstance(bola, httpx.Response) else None
        bola_pass = bola_code in (401, 403, 404)
        checks.append(make_check(
            "Cross-user Object Access (BOLA/IDOR)", "API1:2023 Broken Object Level Authorization", "CRITICAL", "HIGH",
            "PASS" if bola_pass else "VULNERABLE", bola_code,
            "Asha could not access Ravi's resource." if bola_pass else "Asha's token returned Ravi's resource.",
            "Authorize every object access against the authenticated user and deny cross-user reads.", curl_command(ravi_url, token)))

        if args.priority == "all":
            authorized = request(own_url, auth_headers)
            authorized_code = authorized.status_code if isinstance(authorized, httpx.Response) else None
            payload = json_payload(authorized) if isinstance(authorized, httpx.Response) else None
            data_leak = authorized_code == 200 and contains_sensitive_key(payload)
            checks.append(make_check(
                "Sensitive Field Exposure", "API3:2023 Broken Object Property Level Authorization", "MEDIUM", "STANDARD",
                "VULNERABLE" if data_leak else "PASS", authorized_code,
                "The JSON payload contains sensitive internal fields." if data_leak else "No configured sensitive fields were found in the valid JSON response.",
                "Return an allowlisted response schema containing only fields required by the client.", curl_command(own_url, token)))

            rate_limit_headers = {key.lower() for key in (authorized.headers.keys() if isinstance(authorized, httpx.Response) else ())}
            has_rate_limit = bool(rate_limit_headers & {"x-ratelimit-limit", "ratelimit-limit", "retry-after"})
            checks.append(make_check(
                "Rate Limiting", "API4:2023 Unrestricted Resource Consumption", "LOW", "STANDARD",
                "PASS" if has_rate_limit else "VULNERABLE", authorized_code,
                "Rate-limiting headers were returned." if has_rate_limit else "No rate-limiting response headers were returned.",
                "Apply authenticated, per-client rate limits and return limit or retry metadata.", curl_command(own_url, token)))

    return checks, spec_note


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def main():
    args = parse_args()
    try:
        checks, spec_note = run_scan(args)
    except httpx.RequestError as error:
        checks = []
        spec_note = f"Could not complete scan: {error}"
    report = {
        "checked_at_utc": utc_timestamp(),
        "overall_result": "VULNERABLE" if any(check["status"] == "VULNERABLE" for check in checks) else "PASS",
        "checks": checks,
    }
    if spec_note:
        report["spec_note"] = spec_note
    output_path = Path(args.out)
    write_report(output_path, report)
    canonical_path = ROOT / "scan_report.json"
    if output_path.resolve() != canonical_path.resolve():
        write_report(canonical_path, report)
    print(f"Overall: {report['overall_result']}")
    print(f"Report saved to {output_path}")


if __name__ == "__main__":
    main()
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

scanner_dir = Path(__file__).resolve().parent
config = json.loads((scanner_dir / "config.json").read_text(encoding="utf-8"))
report_file = scanner_dir.parent / "scan_report.json"

# Support the structured multi-endpoint configuration format.
if "target" in config:
    target = config["target"]
    checks_config = config.get("checks", [])
    config["base_url"] = target["base_url"]
    config["token"] = config.get("token", "")
    config["own_user"] = config.get("own_user", "")
    config["other_user"] = config.get("other_user", "")
    for check in checks_config:
        endpoint = check.get("endpoint", "")
        if check.get("test_type") == "VALID_USER" and "own_order_id" not in config:
            config["own_order_id"] = endpoint.rsplit("/", 1)[-1]
        elif check.get("test_type") == "CROSS_TENANT_IDOR" and "other_order_id" not in config:
            config["other_order_id"] = endpoint.rsplit("/", 1)[-1]


def utc_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_check(name, status, status_code, explanation, suggested_fix=None):
    return {
        "name": name,
        "status": status,
        "status_code": status_code,
        "explanation": explanation,
        "suggested_fix": suggested_fix,
    }


def safe_json(response):
    if response is None or not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {"_json_error": True}


try:
    base_url = config["base_url"].rstrip("/")
    own_url = f"{base_url}/orders/{config['own_order_id']}"
    other_url = f"{base_url}/orders/{config['other_order_id']}"
    own_headers = {"Authorization": f"Bearer {config['token']}"}

    def fetch(url, headers=None):
        return httpx.get(url, headers=headers, timeout=5)

    own_response = fetch(own_url, own_headers)
    own_payload = safe_json(own_response)

    if own_response.status_code == 200 and own_payload.get("owner") == config["own_user"]:
        own_check = make_check(
            "Own order",
            "PASS",
            own_response.status_code,
            "The authenticated user successfully retrieved their own order.",
        )
    else:
        own_check = make_check(
            "Own order",
            "INCONCLUSIVE",
            own_response.status_code if own_response is not None else "—",
            "The API did not confirm that the authenticated user can read their own order.",
        )

    no_token_response = fetch(own_url)
    no_token_payload = safe_json(no_token_response)

    if no_token_response.status_code == 401:
        no_token_check = make_check(
            "Missing token",
            "PASS",
            no_token_response.status_code,
            "The API rejected the request without an Authorization header.",
        )
    elif no_token_response.status_code == 200 and not no_token_payload.get("_json_error"):
        no_token_check = make_check(
            "Missing token",
            "VULNERABLE",
            no_token_response.status_code,
            "The API returned an order even though no Authorization header was sent.",
            "Require a valid Authorization header before returning order data.",
        )
    else:
        no_token_check = make_check(
            "Missing token",
            "INCONCLUSIVE",
            no_token_response.status_code,
            "The API did not clearly reject the request without authentication.",
        )

    other_response = fetch(other_url, own_headers)
    other_payload = safe_json(other_response)

    if other_response.status_code == 403:
        other_check = make_check(
            "Other user's order",
            "PASS",
            other_response.status_code,
            "The API blocked Asha from reading Ravi's order.",
        )
    elif other_response.status_code == 200 and other_payload.get("owner") == config["other_user"]:
        other_check = make_check(
            "Other user's order",
            "VULNERABLE",
            other_response.status_code,
            "Asha's token successfully returned Ravi's order.",
            "Check the order owner against the authenticated user before returning any order record.",
        )
    else:
        other_check = make_check(
            "Other user's order",
            "INCONCLUSIVE",
            other_response.status_code,
            "The API response did not match the expected secure access behavior.",
        )

    checks = [own_check, no_token_check, other_check]
    overall_result = "VULNERABLE" if any(check["status"] == "VULNERABLE" for check in checks) else (
        "PASS" if all(check["status"] == "PASS" for check in checks) else "INCONCLUSIVE"
    )

    report = {
        "checked_at_utc": utc_timestamp(),
        "overall_result": overall_result,
        "checks": checks,
    }

    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Overall: {overall_result}")
    for check in checks:
        print(f"{check['name']}: {check['status']} ({check['status_code']})")
    print("Report saved to scan_report.json")

except httpx.RequestError as error:
    report = {
        "checked_at_utc": utc_timestamp(),
        "overall_result": "INCONCLUSIVE",
        "checks": [
            make_check(
                "Own order",
                "INCONCLUSIVE",
                "—",
                f"Could not connect to the API: {error}",
            ),
            make_check(
                "Missing token",
                "INCONCLUSIVE",
                "—",
                f"Could not connect to the API: {error}",
            ),
            make_check(
                "Other user's order",
                "INCONCLUSIVE",
                "—",
                f"Could not connect to the API: {error}",
            ),
        ],
        "error": str(error),
    }
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"INCONCLUSIVE: {error}")
    print("Report saved to scan_report.json")

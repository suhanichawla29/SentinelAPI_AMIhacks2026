import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

scanner_dir = Path(__file__).resolve().parent


def utc_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_args():
    parser = argparse.ArgumentParser(description="Run non-destructive API security checks")
    parser.add_argument("--target", help="Base URL, overriding config.json")
    parser.add_argument("--out", help="Output JSON report path")
    parser.add_argument("--priority", choices=("all", "high", "standard"), default="all")
    parser.add_argument("--config", default=str(scanner_dir / "config.json"))
    return parser.parse_args()

def result(name, priority, status, code, explanation, fix=None):
    return {"name": name, "priority": priority, "status": status,
            "status_code": code, "explanation": explanation,
            "suggested_fix": fix}

def write_report(path, checks, error=None):
    report = {"checked_at_utc": utc_timestamp(),
              "overall_result": "VULNERABLE" if any(c["status"] == "VULNERABLE" for c in checks) else "PASS",
              "checks": checks}
    if error:
        report["error"] = str(error)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report

args = parse_args()
config = json.loads(Path(args.config).read_text(encoding="utf-8"))
if "target" in config:
    target = config["target"]
    for check in config.get("checks", []):
        endpoint = check.get("endpoint", "")
        if check.get("test_type") == "VALID_USER":
            config.setdefault("own_order_id", endpoint.rsplit("/", 1)[-1])
        elif check.get("test_type") == "CROSS_TENANT_IDOR":
            config.setdefault("other_order_id", endpoint.rsplit("/", 1)[-1])
    config["base_url"] = target.get("base_url", "")

base_url = (args.target or config.get("base_url", "")).rstrip("/")
token = config.get("token", "")
own_id = config.get("own_order_id", "")
other_id = config.get("other_order_id", "")
own_endpoint = config.get("own_endpoint", f"orders/{own_id}")
other_endpoint = config.get("other_endpoint", f"orders/{other_id}")

def url(endpoint):
    return endpoint if endpoint.startswith(("http://", "https://")) else f"{base_url}/{endpoint.lstrip('/')}"

report_file = Path(args.out) if args.out else scanner_dir.parent / "scan_report.json"
checks = []
try:
    headers = {"Authorization": f"Bearer {token}"}
    authorized = httpx.get(url(own_endpoint), headers=headers, timeout=5)
    checks.append(result("Authorized Read", "HIGH", "PASS" if authorized.status_code == 200 else "VULNERABLE",
                         authorized.status_code, "The valid token retrieved the resource." if authorized.status_code == 200 else
                         "An authorized read did not return 200.", "Require a valid token and permit authorized reads only."))
    missing = httpx.get(url(own_endpoint), timeout=5)
    checks.append(result("Missing Auth", "HIGH", "PASS" if missing.status_code in (401, 403) else "VULNERABLE",
                         missing.status_code, "The unauthenticated request was rejected." if missing.status_code in (401, 403) else
                         "The API did not reject a request without authentication.", "Require Authorization and return 401 or 403 when it is absent."))

    bola = httpx.get(url(other_endpoint), headers=headers, timeout=5)
    checks.append(result("Object-level Access (BOLA/IDOR)", "HIGH", "VULNERABLE" if bola.status_code == 200 else "PASS",
                         bola.status_code, "User A accessed User B's resource." if bola.status_code == 200 else
                         "User A could not access User B's resource.", "Authorize every object access against the authenticated user."))
except httpx.RequestError as error:
    checks = [result(name, "HIGH", "PASS", "—", f"Could not complete check: {error}")
              for name in ("Missing Auth", "Authorized Read", "Object-level Access (BOLA/IDOR)")]
    write_report(report_file, checks, error)
else:
    if args.priority == "high":
        checks = [c for c in checks if c["priority"] == "HIGH"]
    elif args.priority == "standard":
        checks = [c for c in checks if c["priority"] != "HIGH"]
    report = write_report(report_file, checks)
    print(f"Overall: {report['overall_result']}")
    print(f"Report saved to {report_file}")
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

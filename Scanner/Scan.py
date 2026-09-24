import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

scanner_dir = Path(__file__).resolve().parent
config = json.loads((scanner_dir / "config.json").read_text(encoding="utf-8"))
report_file = scanner_dir.parent / "scan_report.json"


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

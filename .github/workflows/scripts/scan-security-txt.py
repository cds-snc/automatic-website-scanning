#!/usr/bin/env python3
"""Scan configured domains for /.well-known/security.txt compliance."""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 1024 * 1024
REQUIRED_FIELD_COUNTS = {
    "contact": 2,
    "policy": 1,
    "canonical": 2,
    "preferred-languages": 1,
    "expires": 1,
}
USER_AGENT = "cds-snc-security-txt-monitor/1.0"


def security_txt_url(target):
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Unsupported target URL: {target}")

    return urlunsplit((parsed.scheme, parsed.netloc, "/.well-known/security.txt", "", ""))


def parse_security_txt(body):
    fields = defaultdict(list)

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue

        name, value = line.split(":", 1)
        fields[name.strip().lower()].append(value.strip())

    return fields


def field_values(fields, name):
    return [value for value in fields.get(name, []) if value]


def field_count(fields, name):
    return len(field_values(fields, name))


def parse_expires(value):
    normalized = value.strip()
    if normalized.upper().endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        parsed = parsedate_to_datetime(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def decode_body(body_bytes, charset):
    try:
        return body_bytes.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return body_bytes.decode("utf-8", errors="replace")


def error_message(error):
    if isinstance(error, URLError):
        return str(error.reason)

    return str(error)


def fetch_security_txt(url, timeout):
    request = Request(url, headers={"Accept": "text/plain, */*", "User-Agent": USER_AGENT})

    try:
        with urlopen(request, timeout=timeout) as response:
            body_bytes = response.read(MAX_RESPONSE_BYTES + 1)
            charset = response.headers.get_content_charset() or "utf-8"
            return {
                "body": decode_body(body_bytes[:MAX_RESPONSE_BYTES], charset),
                "error": None,
                "final_url": response.geturl(),
                "http_status": response.status,
                "response_truncated": len(body_bytes) > MAX_RESPONSE_BYTES,
            }
    except HTTPError as error:
        return {
            "body": "",
            "error": error.reason,
            "final_url": error.geturl(),
            "http_status": error.code,
            "response_truncated": False,
        }
    except (TimeoutError, URLError, OSError) as error:
        return {
            "body": "",
            "error": error_message(error),
            "final_url": url,
            "http_status": None,
            "response_truncated": False,
        }


def result_for_target(target, scanned_at, timeout):
    url = security_txt_url(target)
    parsed_target = urlsplit(target)
    fetched = fetch_security_txt(url, timeout)
    present = fetched["http_status"] is not None and 200 <= fetched["http_status"] < 300 and bool(fetched["body"].strip())

    fields = parse_security_txt(fetched["body"]) if present else {}
    required_field_counts = dict(REQUIRED_FIELD_COUNTS)
    actual_field_counts = {field: field_count(fields, field) for field in required_field_counts}
    present_fields = sorted(field for field, count in actual_field_counts.items() if count > 0)
    missing_fields = sorted(
        field for field, required_count in required_field_counts.items() if actual_field_counts[field] < required_count
    )

    expires_values = field_values(fields, "expires")
    expires_value = expires_values[0] if expires_values else None
    expires_valid = False
    expires_expired = None
    expires_days_until = None
    expires_at = None

    if expires_value:
        try:
            expires_at_datetime = parse_expires(expires_value)
            expires_at = expires_at_datetime.isoformat()
            expires_valid = True
            expires_expired = expires_at_datetime <= scanned_at
            expires_days_until = int((expires_at_datetime - scanned_at).total_seconds() // 86400)
        except (TypeError, ValueError, IndexError, OverflowError):
            expires_valid = False

    failure_reason = None
    if not present:
        failure_reason = "request_error" if fetched["http_status"] is None else f"http_{fetched['http_status']}"
    elif not expires_value:
        failure_reason = "missing_expires"
    elif missing_fields:
        failure_reason = "missing_required_fields"
    elif not expires_valid:
        failure_reason = "invalid_expires"
    elif expires_expired:
        failure_reason = "expired"

    return {
        "scan_type": "security_txt",
        "target_url": target,
        "domain": parsed_target.netloc,
        "security_txt_url": url,
        "final_url": fetched["final_url"],
        "scanned_at": scanned_at.isoformat(),
        "http_status": fetched["http_status"],
        "security_txt_present": present,
        "response_truncated": fetched["response_truncated"],
        "required_fields": list(required_field_counts),
        "required_field_counts": required_field_counts,
        "present_fields": present_fields,
        "missing_fields": missing_fields,
        "required_fields_present": not missing_fields,
        "contact_present": "contact" in present_fields,
        "policy_present": "policy" in present_fields,
        "canonical_present": "canonical" in present_fields,
        "preferred_languages_present": "preferred-languages" in present_fields,
        "expires_value": expires_value,
        "expires_at": expires_at,
        "expires_present": bool(expires_value),
        "expires_valid": expires_valid,
        "expires_expired": expires_expired,
        "expires_days_until": expires_days_until,
        "contact_count": actual_field_counts["contact"],
        "canonical_count": actual_field_counts["canonical"],
        "policy_count": actual_field_counts["policy"],
        "preferred_languages_count": actual_field_counts["preferred-languages"],
        "compliant": present and not missing_fields and expires_valid and not expires_expired,
        "failure_reason": failure_reason,
        "error": fetched["error"],
        "metadata_source": "github_action_matrix",
    }


def main():
    parser = argparse.ArgumentParser(description="Scan configured domains for security.txt compliance.")
    parser.add_argument("--target", action="append", required=True, help="Target URL to scan. May be provided more than once.")
    parser.add_argument("--output", default="security-txt-results.jsonl", help="JSON Lines output file.")
    parser.add_argument("--timeout", default=20, type=int, help="HTTP timeout in seconds.")
    args = parser.parse_args()

    scanned_at = datetime.now(timezone.utc)
    results = [result_for_target(target, scanned_at, args.timeout) for target in args.target]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output:
        for result in results:
            output.write(json.dumps(result, sort_keys=True) + "\n")

    compliant_count = sum(1 for result in results if result["compliant"])
    print(f"Wrote {len(results)} security.txt records to {output_path}")
    print(f"{compliant_count}/{len(results)} targets passed required field and Expires checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())

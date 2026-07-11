"""Publish an approved Hacker Bob AWS report into Bob-site's sealed report ingest.

This Lambda is deliberately downstream of verifier approval, Security Hub export,
and the REPORT-stage AgentCore invocation. It is a bridge, not a second verdict
path: it takes already-approved AWS output, shapes the Bob-site render model, and
POSTs to Bob-site's existing /api/reports endpoint.

The AgentCore runtime/model never receives the Bob-site ingest token or the report
access password. Those secrets are only read here by this Lambda role.
"""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


LIBHEIF_PROFILE = "libheif-cve-2026-49271"
LIBHEIF_DOMAIN = "libheif CVE-2026-49271 replay"
LIBHEIF_FINDING_ID = "F-22"


def _now_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _payload(value: Any) -> Any:
    """Step Functions Lambda integrations wrap function output under Payload."""
    if isinstance(value, dict) and "Payload" in value:
        return value["Payload"]
    return value


def _safe(value: Any, fallback: str = "") -> str:
    return value if isinstance(value, str) and value else fallback


def _configured(value: str | None) -> bool:
    return bool(value and value.strip() and value.strip().lower() not in {"disabled", "none", "null"})


def _validate_https_base_url(raw: str) -> str:
    base = raw.strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("BOB_SITE_BASE_URL must be an HTTPS origin without userinfo")
    host = parsed.hostname or ""
    lowered = host.lower().strip(".")
    if lowered in {"localhost"} or lowered.endswith(".localhost"):
        raise ValueError("BOB_SITE_BASE_URL must not point at localhost")
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return base
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise ValueError("BOB_SITE_BASE_URL must not point at a private/link-local IP")
    return base


def _secret_string(secrets_client: Any, secret_id: str) -> str:
    value = secrets_client.get_secret_value(SecretId=secret_id)
    secret = value.get("SecretString", "")
    return secret if isinstance(secret, str) else ""


def _section(heading: str, section_id: str, kind: str, prose: str, provenance: str) -> dict[str, Any]:
    return {
        "heading": heading,
        "section_id": section_id,
        "kind": kind,
        "provenance": provenance,
        "prose": prose,
        "evidence": [],
    }


def _build_libheif_model(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    approval = event.get("approval") if isinstance(event.get("approval"), dict) else {}
    report = event.get("reportResult") if isinstance(event.get("reportResult"), dict) else {}
    grade = event.get("gradeResult") if isinstance(event.get("gradeResult"), dict) else {}
    export_result = _payload(event.get("exportResult"))
    export_result = export_result if isinstance(export_result, dict) else {}

    grade_hash = _safe(
        approval.get("grade_verdict_hash"),
        _safe(report.get("grade_verdict_hash"), _safe(grade.get("grade_verdict_hash"), "unavailable")),
    )
    version_id = _safe(approval.get("grade_freeze_version_id"), "unavailable")
    bundle_sha = _safe(approval.get("grade_freeze_bundle_sha256"), "unavailable")
    approval_artifact = _safe(approval.get("approval_artifact_key"), "unavailable")
    execution_name = _safe(event.get("executionName"), "unavailable")
    runtime_session_id = _safe(event.get("runtimeSessionId"), "unavailable")

    finding_ids = export_result.get("finding_ids")
    if not isinstance(finding_ids, list):
        finding_ids = []
    finding_id = next((str(v) for v in finding_ids if str(v).endswith("/F-22/" + grade_hash[:16])), "")
    if not finding_id:
        finding_id = f"hacker-bob/{LIBHEIF_PROFILE}/{LIBHEIF_FINDING_ID}/{grade_hash[:16]}"

    summary = _safe(
        report.get("summary"),
        "Exact-library sanitizer replay of Hacker Bob's public historical finding; "
        "the vulnerable revision fired and the exact upstream fix rejected the range.",
    )
    caveat = _safe(
        report.get("caveat"),
        "This is a bounded public historical reproduction on an owned AWS demo path, not a fresh third-party target assessment.",
    )

    model = {
        "domain": LIBHEIF_DOMAIN,
        "severitySummary": (
            "AWS AgentCore replayed one public historical libheif finding under a pinned harness. "
            "A verifier role checked the exact WORM evidence version, wrote a content-bound approval artifact, "
            "and only then allowed the report to publish for review."
        ),
        "findings": [
            {
                "id": LIBHEIF_FINDING_ID,
                "title": "CVE-2026-49271: wrapped icef range causes libheif out-of-bounds read",
                "cwe": "CWE-125",
                "severity": "medium",
                "band": "medium",
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "cvssScore": "6.5",
                "sections": [
                    _section(
                        "F-22 — Impact",
                        "f22-impact",
                        "impact",
                        (
                            "A crafted HEIF file can drive the uncompressed decoder into an out-of-bounds read. "
                            "For the demo, AWS replays the exact historical library case instead of touching a live third-party target."
                        ),
                        "aws_agentcore_replay",
                    ),
                    _section(
                        "F-22 — Evidence",
                        "f22-evidence",
                        "evidence",
                        (
                            f"{summary} Grade verdict hash `{grade_hash}` is bound to WORM object VersionId `{version_id}` "
                            f"and bundle SHA-256 `{bundle_sha}`. Security Hub finding `{finding_id}` was exported after verifier approval."
                        ),
                        "verifier_quorum",
                    ),
                    _section(
                        "F-22 — Fix",
                        "f22-remediation",
                        "remediation",
                        (
                            "Apply the upstream libheif fix or a patched release containing the fixed range check. "
                            "Keep the parser path covered by sanitizer regression tests over the same crafted-file class."
                        ),
                        "upstream_fix",
                    ),
                    _section(
                        "F-22 — Provenance",
                        "f22-provenance",
                        "provenance",
                        (
                            "Claim mode: public historical reproduction. Rediscovery: false. "
                            f"Runtime session `{runtime_session_id}` produced the REPORT-stage row after approval artifact `{approval_artifact}` existed."
                        ),
                        "aws_step_functions",
                    ),
                ],
                "repro": [
                    "Run the pinned vulnerable libheif revision against the sealed crafted HEIF harness inside the AWS demo image.",
                    "Observe the sanitizer-confirmed out-of-bounds read on the vulnerable revision.",
                    "Run the same parsed-equivalent harness against the exact upstream fix.",
                    "Confirm the fixed revision rejects the range and stays sanitizer-clean.",
                ],
            }
        ],
        "globalSections": [
            _section(
                "AWS evidence handoff",
                "aws-evidence-handoff",
                "provenance",
                (
                    f"Step Functions execution `{execution_name}` completed verifier-on-loop orchestration: "
                    "GRADE evidence freeze → verifier check → verifier approval artifact → human-on-loop notification "
                    "→ Security Hub export → REPORT → Bob-site publish. "
                    "The Bob runtime/model never held the Bob-site ingest token or report password."
                ),
                "aws_step_functions",
            ),
            _section(
                "Scope and disclosure boundary",
                "scope-and-disclosure-boundary",
                "provenance",
                caveat,
                "operator_boundary",
            ),
        ],
        "amendments": [],
    }
    business = {
        "bottomLine": (
            "AWS turned a verified Hacker Bob evidence bundle into a sealed Bob-site report for human review. "
            "The valuable product moment is not the receipt itself; it is the system resolving that receipt into a reviewable report."
        ),
        "riskLevel": "moderate",
        "dimensions": {
            "availability": {
                "meaning": "A malformed media file can crash or destabilize a parser path in software that processes HEIF input."
            },
            "trust": {
                "meaning": "The demo proves accountable security automation: evidence is immutable, approval is verifier-bound, and review is human-facing."
            },
            "customer_data": {
                "meaning": "No customer data or live third-party system was touched in this reproduction."
            },
        },
        "ease": {
            "level": "moderate",
            "reason": "The attack needs a crafted HEIF file and a vulnerable parser path; AWS replay keeps the demo bounded to a known historical case.",
        },
        "decisions": [
            {
                "title": "Review the sealed Bob-site report",
                "effort": "Decision",
                "detail": "Use the Business and Technical modes to decide whether the evidence is sufficient to file, patch, or archive.",
            },
            {
                "title": "Keep publication boundaries explicit",
                "effort": "Operator",
                "detail": "This run is safe for demo because it is owned historical replay, not testing a live third-party target.",
            },
            {
                "title": "Preserve verifier-on-loop as the product default",
                "effort": "Engineering",
                "detail": "Human review receives the result; humans are not required to advance the automation path.",
            },
        ],
        "held": [
            "No Step Functions callback token was minted.",
            "No Bob-site secret entered AgentCore or model context.",
            "No third-party target was scanned.",
        ],
    }
    return model, business


def _build_payload(event: dict[str, Any], password: str, recipient: str) -> dict[str, Any]:
    profile = _safe(event.get("profile"))
    if profile != LIBHEIF_PROFILE:
        return {
            "skip": True,
            "reason": "unsupported_profile",
            "profile": profile or "unknown",
        }
    model, business = _build_libheif_model(event)
    return {
        "domain": model["domain"],
        "recipient": recipient or "the program owner",
        "method": "Hacker Bob · AWS AgentCore verifier-on-loop",
        "date": _now_date(),
        "model": model,
        "business": business,
        "password": password,
    }


def _post_json(base_url: str, token: str, body: dict[str, Any], opener: Any = urlopen) -> dict[str, Any]:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = Request(
        f"{base_url}/api/reports",
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "hacker-bob-aws-publisher/1",
        },
    )
    try:
        with opener(req, timeout=15) as resp:
            status = getattr(resp, "status", 200)
            data = resp.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Bob-site ingest returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Bob-site ingest failed: {exc.reason}") from exc
    if status < 200 or status >= 300:
        raise RuntimeError(f"Bob-site ingest returned HTTP {status}")
    parsed = json.loads(data.decode("utf-8"))
    if not isinstance(parsed, dict) or not parsed.get("url") or not parsed.get("slug"):
        raise RuntimeError("Bob-site ingest response did not include url and slug")
    return parsed


def handle(event: dict[str, Any], environ: dict[str, str], secrets_client: Any, opener: Any = urlopen) -> dict[str, Any]:
    base_raw = environ.get("BOB_SITE_BASE_URL", "")
    token_secret_id = environ.get("INGEST_TOKEN_SECRET_ID", "")
    password_secret_id = environ.get("REPORT_PASSWORD_SECRET_ID", "")
    recipient = environ.get("REPORT_RECIPIENT", "the program owner")

    if not _configured(base_raw) or not _configured(token_secret_id) or not _configured(password_secret_id):
        return {"version": 1, "published": False, "reason": "not_configured"}

    base_url = _validate_https_base_url(base_raw)
    token = _secret_string(secrets_client, token_secret_id)
    password = _secret_string(secrets_client, password_secret_id)
    if not _configured(token) or not _configured(password):
        return {"version": 1, "published": False, "reason": "not_configured"}

    payload = _build_payload(event, password, recipient)
    if payload.get("skip"):
        return {"version": 1, "published": False, **payload}

    result = _post_json(base_url, token, payload, opener=opener)
    return {
        "version": 1,
        "published": True,
        "bob_site_url": result["url"],
        "bob_site_slug": result["slug"],
        "domain": payload["domain"],
        "profile": _safe(event.get("profile"), "unknown"),
    }


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    # Import lazily so local unit tests can exercise handle() without a boto3
    # dependency; boto3 is present in the AWS Python Lambda runtime.
    import boto3  # type: ignore

    return handle(event, os.environ, boto3.client("secretsmanager"))

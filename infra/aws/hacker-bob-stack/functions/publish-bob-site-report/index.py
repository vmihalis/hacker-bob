"""Publish an approved Hacker Bob AWS report into Bob-site's sealed report ingest.

This Lambda is deliberately downstream of verifier approval, Security Hub export,
and the REPORT-stage AgentCore invocation. It is a bridge, not a second verdict
path: it takes already-approved AWS output, shapes the Bob-site render model, and
POSTs to Bob-site's existing /api/reports endpoint.

The AgentCore runtime/model never receives the Bob-site ingest token or the report
access password. Those secrets are only read here by this Lambda role.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


LIBHEIF_PROFILE = "libheif-cve-2026-49271"
LIBHEIF_DOMAIN = "libheif"
LIBHEIF_FINDING_ID = "F-22"
LIBHEIF_REPOSITORY = "https://github.com/strukturag/libheif"
LIBHEIF_ADVISORY_ID = "GHSA-r7qj-cg5r-r6vf"
LIBHEIF_ADVISORY_URL = (
    "https://github.com/strukturag/libheif/security/advisories/GHSA-r7qj-cg5r-r6vf"
)
LIBHEIF_REPORTER = "@vmihalis"
LIBHEIF_AFFECTED_VERSIONS = "<= 1.22.0"
LIBHEIF_FIXED_VERSION = "1.22.1"
LIBHEIF_VULNERABLE_COMMIT = "b12b733d1716595483413ccd7e2dfb73c44a8d69"
LIBHEIF_EXACT_FIX_COMMIT = "5782bca04a70ebc01c59397205a3cfff22841311"
LIBHEIF_PATCHED_RELEASE_COMMIT = "2b6d5a62fb6151e09d5f36757a5aa5e12f9c2045"
LIBHEIF_SOURCE_FRAME = "libheif/codecs/uncompressed/unc_decoder.cc:178"
LIBHEIF_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
LIBHEIF_FIXED_MARKER = "returned error? 1 output=0"
LIBHEIF_VERIFIER_CHECKS = (
    "target_binding",
    "exact_s3_version",
    "object_lock_compliance",
    "body_sha256",
    "embedded_grade_hash",
    "canonical_grade_hash",
)
LIBHEIF_CAVEAT = (
    "The harness constructs parsed-equivalent cmpC/icef decoder objects and exercises the exact "
    "vulnerable library path; it is not a complete malicious .heif parsed through the public decoder API."
)
LIBHEIF_RESOLUTION_SCHEMA_VERSION = 1
LIBHEIF_RESOLUTION_TYPE = "bedrock_stakeholder_resolution"
LIBHEIF_FEATURE_REGISTRY = "libheif-impact-v1"
LIBHEIF_RESOLUTION_FEATURES = {
    "target_kind": "oss_library",
    "impact_axis": "availability",
    "fix_state": "upstream_fixed",
    "distribution_scope": "downstream_consumers",
    "reachability": "crafted_file_with_user_interaction",
    "evidence_confidence": "high_bounded",
}
LIBHEIF_READER_LABELS = {
    "downstream_maintainer": "Downstream maintainers",
    "release_manager": "Release managers",
    "product_security_owner": "Product security owners",
}
LIBHEIF_FIRST_ACTIONS = {
    "downstream_maintainer": {"upgrade_or_backport", "map_downstream_exposure"},
    "release_manager": {"upgrade_or_backport"},
    "product_security_owner": {"map_downstream_exposure"},
}
LIBHEIF_ACTIONS = {
    "upgrade_or_backport": {
        "stakeholder": {
            "audience": "downstream_maintainers",
            "action": f"Upgrade to libheif {LIBHEIF_FIXED_VERSION} or later, or backport the exact fix.",
        },
        "decision": {
            "title": "Upgrade or backport downstream copies",
            "effort": "Engineering",
            "detail": f"Move to libheif {LIBHEIF_FIXED_VERSION} or later, or backport `{LIBHEIF_EXACT_FIX_COMMIT}`.",
        },
    },
    "map_downstream_exposure": {
        "stakeholder": {
            "audience": "packagers_and_product_security",
            "action": (
                f"Map packages and products still shipping libheif {LIBHEIF_AFFECTED_VERSIONS} "
                "and align advisory status with backports."
            ),
        },
        "decision": {
            "title": "Map releases, packages, and advisories",
            "effort": "Coordination",
            "detail": (
                f"Identify products still carrying libheif {LIBHEIF_AFFECTED_VERSIONS} and record "
                "whether each is upgraded or backported."
            ),
        },
    },
    "retain_regression_coverage": {
        "stakeholder": {
            "audience": "maintainers_and_release_managers",
            "action": "Keep the vulnerable/fixed sanitizer differential in regression coverage.",
        },
        "decision": {
            "title": "Keep the differential as a regression test",
            "effort": "Maintainer",
            "detail": "Preserve the failing vulnerable case and sanitizer-clean fixed case around the range check.",
        },
    },
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")


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


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"refusing to publish libheif report: {message}")


def _require_sha256(value: Any, field: str) -> str:
    _require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)), f"{field} is not a SHA-256 digest")
    return value


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_libheif_resolution(
    event: dict[str, Any],
    grade_hash: str,
    version_id: str,
    bundle_sha256: str,
    expected_model_id: str,
) -> dict[str, Any]:
    """Accept only the validator's normalized, evidence-bound decision."""
    resolution = event.get("resolution")
    _require(isinstance(resolution, dict), "validated report resolution is missing")
    expected_keys = {
        "status",
        "schema_version",
        "resolution_type",
        "profile",
        "target_domain",
        "grade_verdict_hash",
        "grade_freeze_bundle_sha256",
        "grade_freeze_version_id",
        "feature_registry",
        "feature_hash",
        "model_id",
        "primary_reader",
        "action_order",
        "decision_hash",
    }
    _require(set(resolution) == expected_keys, "report resolution keys are invalid")
    _require(resolution.get("status") == "validated", "report resolution is not validated")
    schema_version = resolution.get("schema_version")
    _require(
        type(schema_version) is int and schema_version == LIBHEIF_RESOLUTION_SCHEMA_VERSION,
        "report resolution schema mismatch",
    )
    _require(
        resolution.get("resolution_type") == LIBHEIF_RESOLUTION_TYPE,
        "report resolution type mismatch",
    )
    _require(resolution.get("profile") == event.get("profile"), "report resolution profile mismatch")
    _require(
        resolution.get("target_domain") == event.get("target"),
        "report resolution target mismatch",
    )
    _require(resolution.get("grade_verdict_hash") == grade_hash, "report resolution grade hash mismatch")
    _require(
        resolution.get("grade_freeze_bundle_sha256") == bundle_sha256,
        "report resolution bundle hash mismatch",
    )
    _require(
        resolution.get("grade_freeze_version_id") == version_id,
        "report resolution VersionId mismatch",
    )
    _require(
        resolution.get("feature_registry") == LIBHEIF_FEATURE_REGISTRY,
        "report resolution feature registry mismatch",
    )
    _require(
        resolution.get("feature_hash") == _canonical_hash(LIBHEIF_RESOLUTION_FEATURES),
        "report resolution feature hash mismatch",
    )
    model_id = resolution.get("model_id")
    _require(
        isinstance(expected_model_id, str) and bool(MODEL_ID_RE.fullmatch(expected_model_id)),
        "configured report decision model id is invalid",
    )
    _require(
        isinstance(model_id, str) and bool(MODEL_ID_RE.fullmatch(model_id)),
        "report resolution model id is invalid",
    )
    _require(model_id == expected_model_id, "report resolution model id mismatch")

    reader = resolution.get("primary_reader")
    order = resolution.get("action_order")
    _require(reader in LIBHEIF_READER_LABELS, "report resolution reader is not allowed")
    _require(
        isinstance(order, list)
        and len(order) == len(LIBHEIF_ACTIONS)
        and all(isinstance(action, str) for action in order)
        and set(order) == set(LIBHEIF_ACTIONS),
        "report resolution action order must be an exact unique permutation",
    )
    _require(
        order[0] in LIBHEIF_FIRST_ACTIONS[reader],
        "report resolution first action is incompatible with the reader",
    )
    decision = {
        "schema_version": LIBHEIF_RESOLUTION_SCHEMA_VERSION,
        "resolution_type": LIBHEIF_RESOLUTION_TYPE,
        "profile": event["profile"],
        "target_domain": event["target"],
        "grade_verdict_hash": grade_hash,
        "grade_freeze_bundle_sha256": bundle_sha256,
        "grade_freeze_version_id": version_id,
        "feature_registry": LIBHEIF_FEATURE_REGISTRY,
        "feature_hash": _canonical_hash(LIBHEIF_RESOLUTION_FEATURES),
        "model_id": model_id,
        "primary_reader": reader,
        "action_order": order,
    }
    _require(
        resolution.get("decision_hash") == _canonical_hash(decision),
        "report resolution decision hash mismatch",
    )
    return resolution


def _validate_libheif_transaction(event: dict[str, Any], expected_model_id: str) -> dict[str, Any]:
    """Fail closed unless every published claim belongs to one approved transaction."""
    grade = event.get("gradeResult") if isinstance(event.get("gradeResult"), dict) else {}
    approval = event.get("approval") if isinstance(event.get("approval"), dict) else {}
    report = event.get("reportResult") if isinstance(event.get("reportResult"), dict) else {}
    export_result = _payload(event.get("exportResult"))
    export_result = export_result if isinstance(export_result, dict) else {}

    _require(event.get("profile") == LIBHEIF_PROFILE, "profile is not the pinned libheif fixture")
    _require(event.get("target") == LIBHEIF_PROFILE, "event target is not the pinned libheif fixture")
    _require(isinstance(event.get("runtimeSessionId"), str) and bool(event["runtimeSessionId"]), "runtime session is missing")

    _require(grade.get("status") == "awaiting_verifier_gate", "GRADE did not reach the verifier gate")
    _require(grade.get("target") == LIBHEIF_PROFILE, "GRADE target mismatch")
    _require(grade.get("target_domain") == LIBHEIF_PROFILE, "GRADE target-domain mismatch")
    _require(grade.get("fixture_id") == LIBHEIF_PROFILE, "GRADE fixture mismatch")
    _require(grade.get("claim_mode") == "public_historical_reproduction", "GRADE claim mode mismatch")
    _require(grade.get("rediscovery") is False, "GRADE must declare rediscovery=false")
    _require(grade.get("reportable_finding_ids") == [LIBHEIF_FINDING_ID], "GRADE finding set mismatch")

    fixture_receipt = grade.get("fixture_receipt") if isinstance(grade.get("fixture_receipt"), dict) else {}
    _require(fixture_receipt.get("fixture_id") == LIBHEIF_PROFILE, "fixture receipt id mismatch")
    _require(fixture_receipt.get("claim_mode") == "public_historical_reproduction", "fixture receipt claim mode mismatch")
    _require(fixture_receipt.get("rediscovery") is False, "fixture receipt must declare rediscovery=false")
    _require(fixture_receipt.get("vulnerable_commit") == LIBHEIF_VULNERABLE_COMMIT, "vulnerable commit mismatch")
    _require(fixture_receipt.get("exact_fix_commit") == LIBHEIF_EXACT_FIX_COMMIT, "exact fix commit mismatch")
    _require(
        fixture_receipt.get("patched_release_commit") == LIBHEIF_PATCHED_RELEASE_COMMIT,
        "patched release commit mismatch",
    )
    _require_sha256(fixture_receipt.get("target_lock_sha256"), "fixture_receipt.target_lock_sha256")
    _require_sha256(fixture_receipt.get("harness_sha256"), "fixture_receipt.harness_sha256")
    semantic_proof = (
        fixture_receipt.get("semantic_proof")
        if isinstance(fixture_receipt.get("semantic_proof"), dict)
        else {}
    )
    expected_semantic_proof = {
        "bug_type": "heap-buffer-overflow",
        "access": "READ of size 2",
        "source_frame": LIBHEIF_SOURCE_FRAME,
        "vulnerable_signal_confirmed": True,
        "fixed_marker": LIBHEIF_FIXED_MARKER,
        "fixed_sanitizer_clean": True,
    }
    _require(semantic_proof == expected_semantic_proof, "semantic vulnerable/fixed proof mismatch")

    grade_hash = _require_sha256(grade.get("grade_verdict_hash"), "gradeResult.grade_verdict_hash")
    version_id = _safe(grade.get("grade_freeze_version_id"))
    _require(bool(version_id), "GRADE freeze VersionId is missing")
    bundle_sha256 = _require_sha256(
        grade.get("grade_freeze_bundle_sha256"),
        "gradeResult.grade_freeze_bundle_sha256",
    )

    _require(approval.get("decision") == "approved", "verifier decision is not approved")
    _require(approval.get("approval_mode") == "verifier_quorum", "approval mode mismatch")
    _require(approval.get("profile") == LIBHEIF_PROFILE, "approval profile mismatch")
    _require(approval.get("target") == LIBHEIF_PROFILE, "approval target mismatch")
    _require(approval.get("grade_verdict_hash") == grade_hash, "approval grade hash mismatch")
    _require(approval.get("grade_freeze_version_id") == version_id, "approval VersionId mismatch")
    _require(approval.get("grade_freeze_bundle_sha256") == bundle_sha256, "approval bundle hash mismatch")
    expected_artifact = f"approvals/{LIBHEIF_PROFILE}/{grade_hash}.approved"
    _require(approval.get("approval_artifact_key") == expected_artifact, "approval artifact key mismatch")
    _require(isinstance(approval.get("approved_at"), str) and bool(approval["approved_at"]), "approval timestamp is missing")
    verifier_checks = approval.get("verifier_quorum")
    _require(
        isinstance(verifier_checks, list)
        and len(verifier_checks) == len(LIBHEIF_VERIFIER_CHECKS)
        and all(isinstance(check, str) for check in verifier_checks)
        and set(verifier_checks) == set(LIBHEIF_VERIFIER_CHECKS),
        "verifier policy did not return the canonical six integrity checks",
    )

    _require(export_result.get("target_domain") == LIBHEIF_PROFILE, "Security Hub target mismatch")
    _require(export_result.get("grade_verdict_hash") == grade_hash, "Security Hub grade hash mismatch")
    _require(export_result.get("grade_freeze_version_id") == version_id, "Security Hub VersionId mismatch")
    _require(export_result.get("grade_freeze_bundle_sha256") == bundle_sha256, "Security Hub bundle hash mismatch")
    _require(export_result.get("verdict") == "SUBMIT", "Security Hub export verdict is not SUBMIT")
    _require(export_result.get("failed") in (None, []), "Security Hub export contains failed findings")
    exported = export_result.get("exported")
    expected_asff_id = f"hacker-bob/{LIBHEIF_PROFILE}/{LIBHEIF_FINDING_ID}/{grade_hash[:16]}"
    _require(
        isinstance(exported, list)
        and exported == [
            {
                "asff_id": expected_asff_id,
                "finding_id": LIBHEIF_FINDING_ID,
                "severity_label": "MEDIUM",
            }
        ],
        "Security Hub export is not the exact approved F-22 record",
    )

    _require(report.get("status") == "historical_replay_report_ready", "REPORT stage is not ready")
    _require(report.get("target_domain") == LIBHEIF_PROFILE, "REPORT target mismatch")
    _require(report.get("fixture_id") == LIBHEIF_PROFILE, "REPORT fixture mismatch")
    _require(report.get("claim_mode") == "public_historical_reproduction", "REPORT claim mode mismatch")
    _require(report.get("rediscovery") is False, "REPORT must declare rediscovery=false")
    _require(report.get("grade_verdict_hash") == grade_hash, "REPORT grade hash mismatch")
    _require(report.get("findings") == [LIBHEIF_FINDING_ID], "REPORT finding set mismatch")
    _require(report.get("caveat") == LIBHEIF_CAVEAT, "REPORT caveat mismatch")
    _require(isinstance(report.get("generated_at"), str) and bool(report["generated_at"]), "REPORT timestamp is missing")
    resolution = _validate_libheif_resolution(
        event,
        grade_hash,
        version_id,
        bundle_sha256,
        expected_model_id,
    )

    return {
        "approval": approval,
        "report": report,
        "grade": grade,
        "export": export_result,
        "grade_hash": grade_hash,
        "version_id": version_id,
        "bundle_sha256": bundle_sha256,
        "resolution": resolution,
    }


def _build_libheif_model(
    event: dict[str, Any],
    expected_model_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    transaction = _validate_libheif_transaction(event, expected_model_id)
    report = transaction["report"]
    grade_hash = transaction["grade_hash"]
    version_id = transaction["version_id"]
    bundle_sha256 = transaction["bundle_sha256"]
    resolution = transaction["resolution"]
    generated_at = _safe(report.get("generated_at"))
    primary_reader = resolution["primary_reader"]
    action_order = resolution["action_order"]
    stakeholder_actions = [LIBHEIF_ACTIONS[action]["stakeholder"] for action in action_order]
    business_decisions = [LIBHEIF_ACTIONS[action]["decision"] for action in action_order]

    receipt: dict[str, Any] = {
        "evidenceHash": grade_hash,
        "artifactVersion": version_id,
        "bundleSha256": bundle_sha256,
        "verifierStatus": "approved",
        "integrityChecksPassed": len(LIBHEIF_VERIFIER_CHECKS),
        "generatedAt": generated_at,
    }

    provenance_sentences = [
        (
            f"Public source binding: `{LIBHEIF_ADVISORY_ID}` / `CVE-2026-49271`, vulnerable commit "
            f"`{LIBHEIF_VULNERABLE_COMMIT}`, and exact fix `{LIBHEIF_EXACT_FIX_COMMIT}`."
        ),
        "Claim mode: public historical reproduction; rediscovery: false.",
    ]
    provenance_prose = " ".join(provenance_sentences)

    impact_prose = (
        f"libheif {LIBHEIF_AFFECTED_VERSIONS} can read past a heap buffer while decoding a crafted "
        "HEIF uncompressed item. In applications that accept untrusted HEIF files, the fault can terminate "
        "the process and interrupt image-processing workflows. The published 6.5 medium score reflects high "
        "availability impact without evidence of confidentiality or integrity impact."
    )
    root_cause_prose = (
        f"At `{LIBHEIF_SOURCE_FRAME}`, the vulnerable range check evaluates "
        "`unit_offset + unit_size` without first preventing integer wrap. A wrapped sum can pass the bounds "
        "decision and drive a two-byte read outside heap storage."
    )
    evidence_prose = (
        f"At vulnerable commit `{LIBHEIF_VULNERABLE_COMMIT}`, the parsed-equivalent harness produces "
        f"`AddressSanitizer: heap-buffer-overflow`, `READ of size 2`, and `{LIBHEIF_SOURCE_FRAME}`. "
        f"At exact fix `{LIBHEIF_EXACT_FIX_COMMIT}`, the same harness returns "
        f"`{LIBHEIF_FIXED_MARKER}` and remains sanitizer-clean."
    )
    remediation_prose = (
        f"Upstream fixed the defect in `{LIBHEIF_EXACT_FIX_COMMIT}`, released in libheif "
        f"{LIBHEIF_FIXED_VERSION}. Downstream maintainers should upgrade to {LIBHEIF_FIXED_VERSION} or later "
        "or backport the exact fix, retain the differential sanitizer case as a regression test, map packages "
        f"and products still carrying libheif {LIBHEIF_AFFECTED_VERSIONS}, and align advisories with deployed backports."
    )
    repro_steps = [
        f"Build vulnerable commit `{LIBHEIF_VULNERABLE_COMMIT}` with AddressSanitizer and the uncompressed codec enabled.",
        "Run the pinned parsed-equivalent cmpC/icef harness and observe `AddressSanitizer: heap-buffer-overflow` with `READ of size 2`.",
        f"Confirm the failing frame resolves to `{LIBHEIF_SOURCE_FRAME}`.",
        f"Run the same harness against exact fix `{LIBHEIF_EXACT_FIX_COMMIT}`; confirm `{LIBHEIF_FIXED_MARKER}` and no sanitizer marker.",
    ]

    target = {
        "kind": "oss_library",
        "name": LIBHEIF_DOMAIN,
        "repository": LIBHEIF_REPOSITORY,
        "ecosystem": "C/C++ image-processing library consumed by applications, packages, and operating-system distributions",
        "audiences": [
            "maintainers",
            "release_managers",
            "downstream_packagers",
            "dependent_vendors",
            "security_response_teams",
        ],
    }
    model = {
        "domain": LIBHEIF_DOMAIN,
        "targetKind": "oss_library",
        "target": target,
        "reportKind": "security_assessment",
        "disclosure": {
            "status": "public_historical_replay",
            "freshTargetTesting": False,
            "boundary": "Exact-library replay of a public historical finding using pinned vulnerable and fixed revisions.",
        },
        "reportResolution": {
            "status": resolution["status"],
            "resolutionType": resolution["resolution_type"],
            "schemaVersion": resolution["schema_version"],
            "featureRegistry": resolution["feature_registry"],
            "featureHash": resolution["feature_hash"],
            "modelId": resolution["model_id"],
            "primaryReader": primary_reader,
            "actionOrder": action_order,
            "decisionHash": resolution["decision_hash"],
        },
        "brief": {
            "status": "Fixed upstream · public historical reproduction",
            "primaryReader": primary_reader,
            "resolvedFor": LIBHEIF_READER_LABELS[primary_reader],
            "headline": (
                f"libheif {LIBHEIF_AFFECTED_VERSIONS} is vulnerable to a crafted-file out-of-bounds heap read; "
                f"the defect is fixed in {LIBHEIF_FIXED_VERSION}."
            ),
            "primaryAction": stakeholder_actions[0]["action"],
            "affected": LIBHEIF_AFFECTED_VERSIONS,
            "fixed": LIBHEIF_FIXED_VERSION,
            "confidence": "High for the exact vulnerable/fixed decoder-path differential, bounded by the parsed-equivalent harness caveat.",
            "riskAxes": {
                "reachability": "Requires a crafted HEIF file to be processed by a vulnerable application.",
                "ecosystemImpact": "Can crash downstream image-processing applications that accept untrusted HEIF input.",
            },
            "stakeholderActions": stakeholder_actions,
        },
        "severitySummary": (
            f"One medium-severity issue affects libheif {LIBHEIF_AFFECTED_VERSIONS}: an integer-wrapped "
            f"range check can cause a two-byte heap-buffer over-read. Upstream fixed it in {LIBHEIF_FIXED_VERSION}; "
            "downstream consumers should upgrade or backport and retain regression coverage."
        ),
        "findings": [
            {
                "id": LIBHEIF_FINDING_ID,
                "title": "CVE-2026-49271: wrapped icef range causes libheif out-of-bounds read",
                "cwe": "CWE-125",
                "severity": "medium",
                "band": "medium",
                "cvssVector": LIBHEIF_CVSS_VECTOR,
                "cvssScore": "6.5",
                "affected": {
                    "versions": LIBHEIF_AFFECTED_VERSIONS,
                    "vulnerableCommit": LIBHEIF_VULNERABLE_COMMIT,
                    "component": "uncompressed HEIF decoder",
                    "sourceFrame": LIBHEIF_SOURCE_FRAME,
                },
                "fixed": {
                    "status": "upstream_fixed",
                    "version": LIBHEIF_FIXED_VERSION,
                    "exactFixCommit": LIBHEIF_EXACT_FIX_COMMIT,
                    "patchedReleaseCommit": LIBHEIF_PATCHED_RELEASE_COMMIT,
                    "fixedMarker": LIBHEIF_FIXED_MARKER,
                    "sanitizerClean": True,
                },
                "impact": {
                    "primary": "availability",
                    "summary": "A crafted HEIF input can crash a vulnerable consuming process.",
                    "notEstablished": ["confidentiality loss", "integrity loss", "code execution"],
                },
                "reachability": {
                    "input": "crafted HEIF uncompressed item",
                    "attackerControl": "unit_offset and unit_size",
                    "preconditions": "A vulnerable application processes the supplied HEIF input; user interaction is required.",
                },
                "rootCause": {
                    "sourceFrame": LIBHEIF_SOURCE_FRAME,
                    "operation": "unit_offset + unit_size",
                    "failure": "integer wrap before the range decision",
                },
                "reproduction": {
                    "harness": "parsed-equivalent cmpC/icef decoder objects",
                    "steps": repro_steps,
                    "expectedVulnerable": [
                        "AddressSanitizer: heap-buffer-overflow",
                        "READ of size 2",
                        LIBHEIF_SOURCE_FRAME,
                    ],
                    "expectedFixed": LIBHEIF_FIXED_MARKER,
                },
                "evidence": {
                    "vulnerableSignal": "AddressSanitizer: heap-buffer-overflow",
                    "access": "READ of size 2",
                    "sourceFrame": LIBHEIF_SOURCE_FRAME,
                    "fixedMarker": LIBHEIF_FIXED_MARKER,
                    "fixedSanitizerClean": True,
                },
                "remediation": {
                    "upstreamStatus": "fixed",
                    "minimumFixedVersion": LIBHEIF_FIXED_VERSION,
                    "exactFixCommit": LIBHEIF_EXACT_FIX_COMMIT,
                    "downstreamActions": [action["action"] for action in stakeholder_actions],
                },
                "caveats": [LIBHEIF_CAVEAT, "This report is a public historical reproduction, not a fresh discovery."],
                "provenance": {
                    "claimMode": "public_historical_reproduction",
                    "rediscovery": False,
                    "advisory": LIBHEIF_ADVISORY_ID,
                    "advisoryUrl": LIBHEIF_ADVISORY_URL,
                    "reportedBy": LIBHEIF_REPORTER,
                },
                "sections": [
                    _section(
                        "F-22 — Impact",
                        "f22-impact",
                        "impact",
                        impact_prose,
                        "public_advisory",
                    ),
                    _section(
                        "F-22 — Affected range and root cause",
                        "f22-root-cause",
                        "evidence",
                        root_cause_prose,
                        "pinned_source",
                    ),
                    _section(
                        "F-22 — Vulnerable/fixed differential",
                        "f22-differential-evidence",
                        "evidence",
                        evidence_prose,
                        "sanitizer_differential",
                    ),
                    _section(
                        "F-22 — Fix and downstream action",
                        "f22-remediation",
                        "remediation",
                        remediation_prose,
                        "upstream_fix",
                    ),
                    _section(
                        "F-22 — Evidence provenance",
                        "f22-provenance",
                        "provenance",
                        provenance_prose,
                        "evidence_receipt",
                    ),
                ],
                "repro": repro_steps,
            }
        ],
        "globalSections": [
            _section(
                "Evidence boundary",
                "evidence-boundary",
                "provenance",
                (
                    f"{LIBHEIF_CAVEAT} The differential establishes behavior at the pinned vulnerable and fixed "
                    "revisions; it does not extend the claim beyond that tested decoder path."
                ),
                "bounded_reproduction",
            ),
        ],
        "amendments": [],
    }
    if receipt:
        model["receipt"] = receipt

    business = {
        "bottomLine": (
            f"libheif {LIBHEIF_AFFECTED_VERSIONS} can crash while processing a crafted HEIF input; "
            f"{LIBHEIF_FIXED_VERSION} contains the fix. Downstream projects should upgrade or backport and map "
            "products that still accept untrusted HEIF files through an affected version."
        ),
        "riskLevel": "moderate",
        "dimensions": {
            "ecosystem_impact": {
                "label": "Ecosystem impact",
                "exposure": "moderate",
                "meaning": "Affected downstream applications can terminate while processing crafted HEIF input.",
            },
            "downstream_propagation": {
                "label": "Downstream propagation",
                "exposure": "moderate",
                "meaning": f"Packages and products retaining libheif {LIBHEIF_AFFECTED_VERSIONS} remain exposed until upgraded or backported.",
            },
            "maintainer_urgency": {
                "label": "Maintainer urgency",
                "exposure": "moderate",
                "meaning": "The upstream fix exists; the urgent work is release adoption, backport tracking, and regression coverage.",
            },
            "release_advisory": {
                "label": "Release and advisory action",
                "exposure": "moderate",
                "meaning": "Downstream advisory status should reflect the version or backport actually shipped.",
            },
            "reachability": {
                "label": "Exploit reachability",
                "exposure": "moderate",
                "meaning": "A crafted file must reach a vulnerable decoder and be processed; user interaction is required.",
            },
            "confidence_caveats": {
                "label": "Evidence confidence",
                "exposure": "low",
                "meaning": "The exact-path vulnerable/fixed differential is strong; the harness does not model a complete malicious file through the public decoder API.",
            },
        },
        "ease": {
            "level": "moderate",
            "reason": "The issue needs a crafted HEIF file, a vulnerable decoder, and user or application processing of that input.",
        },
        "decisions": business_decisions,
        "held": [
            f"The exact fix returned `{LIBHEIF_FIXED_MARKER}` for the same parsed-equivalent input.",
            "The fixed revision completed without AddressSanitizer or undefined-behavior markers.",
            "The public advisory, affected range, and pinned source revisions agree.",
        ],
    }
    return model, business


def _build_payload(
    event: dict[str, Any],
    password: str,
    recipient: str,
    expected_model_id: str,
) -> dict[str, Any]:
    profile = _safe(event.get("profile"))
    if profile != LIBHEIF_PROFILE:
        return {
            "skip": True,
            "reason": "unsupported_profile",
            "profile": profile or "unknown",
        }
    model, business = _build_libheif_model(event, expected_model_id)
    publication_key = _canonical_hash(
        {
            "schema_version": 1,
            "profile": profile,
            "target_domain": event.get("target"),
            "grade_verdict_hash": model["receipt"]["evidenceHash"],
            "grade_freeze_version_id": model["receipt"]["artifactVersion"],
            "resolution_decision_hash": model["reportResolution"]["decisionHash"],
        }
    )
    payload = {
        "domain": model["domain"],
        "recipient": recipient or "the program owner",
        "method": "Hacker Bob · verified differential security assessment",
        "date": _now_date(),
        "model": model,
        "business": business,
        "consoleVisible": True,
        "publicationKey": publication_key,
        "password": password,
    }
    payload["publicationFingerprint"] = _canonical_hash(
        {
            key: value
            for key, value in payload.items()
            if key not in {"password", "publicationKey", "publicationFingerprint"}
        }
    )
    return payload


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
    profile = _safe(event.get("profile"))
    if profile != LIBHEIF_PROFILE:
        return {
            "version": 1,
            "published": False,
            "reason": "unsupported_profile",
            "profile": profile or "unknown",
        }

    base_raw = environ.get("BOB_SITE_BASE_URL", "")
    token_secret_id = environ.get("INGEST_TOKEN_SECRET_ID", "")
    password_secret_id = environ.get("REPORT_PASSWORD_SECRET_ID", "")
    expected_model_id = environ.get("REPORT_DECISION_MODEL_ID", "")
    recipient = environ.get("REPORT_RECIPIENT", "the program owner")

    _require(
        _configured(base_raw) and _configured(token_secret_id) and _configured(password_secret_id),
        "Bob-site publication is not configured",
    )

    base_url = _validate_https_base_url(base_raw)
    token = _secret_string(secrets_client, token_secret_id)
    password = _secret_string(secrets_client, password_secret_id)
    _require(_configured(token) and _configured(password), "Bob-site publication secrets are not configured")
    _require(
        len(password.strip()) >= 16,
        "report access password must contain at least 16 non-whitespace characters",
    )

    payload = _build_payload(event, password, recipient, expected_model_id)
    if payload.get("skip"):
        return {"version": 1, "published": False, **payload}

    result = _post_json(base_url, token, payload, opener=opener)
    return {
        "version": 1,
        "published": True,
        "bob_site_url": result["url"],
        "bob_site_slug": result["slug"],
        "domain": payload["domain"],
        "profile": profile,
    }


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    # Import lazily so local unit tests can exercise handle() without a boto3
    # dependency; boto3 is present in the AWS Python Lambda runtime.
    import boto3  # type: ignore

    return handle(event, os.environ, boto3.client("secretsmanager"))

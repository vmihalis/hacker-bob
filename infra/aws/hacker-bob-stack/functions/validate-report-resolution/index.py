"""Validate a bounded Bedrock stakeholder-resolution decision.

The model never authors vulnerability facts or report prose. It may choose one
primary reader and order three pre-approved action identifiers. This Lambda is
the deterministic boundary between untrusted model output and the publisher.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any


PROFILE = "libheif-cve-2026-49271"
SCHEMA_VERSION = 1
FEATURE_REGISTRY = "libheif-impact-v1"
RESOLUTION_TYPE = "bedrock_stakeholder_resolution"
TOOL_NAME = "select_report_framing"
TOOL_USE_TYPE = "tool_use"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
TOOL_USE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

FEATURES = {
    "target_kind": "oss_library",
    "impact_axis": "availability",
    "fix_state": "upstream_fixed",
    "distribution_scope": "downstream_consumers",
    "reachability": "crafted_file_with_user_interaction",
    "evidence_confidence": "high_bounded",
}
READERS = {
    "downstream_maintainer",
    "release_manager",
    "product_security_owner",
}
ACTIONS = {
    "upgrade_or_backport",
    "map_downstream_exposure",
    "retain_regression_coverage",
}
FIRST_ACTIONS = {
    "downstream_maintainer": {"upgrade_or_backport", "map_downstream_exposure"},
    "release_manager": {"upgrade_or_backport"},
    "product_security_owner": {"map_downstream_exposure"},
}


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"report resolution rejected: {message}")


def _require_hash(value: Any, field: str) -> str:
    _require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)), f"{field} is invalid")
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_tool_input(model_result: dict[str, Any]) -> dict[str, Any]:
    output = _object(model_result.get("Output"))
    message = _object(output.get("Message"))
    content = message.get("Content")
    stop_reason = model_result.get("StopReason")
    _require(stop_reason in {"tool_use", "toolUse"}, "Bedrock did not stop for tool use")
    _require(isinstance(content, list) and len(content) == 1, "expected exactly one Bedrock content block")
    block = _object(content[0])
    _require(set(block) == {"ToolUse"}, "Bedrock content must contain only one tool use")
    tool_use = _object(block.get("ToolUse"))
    # Step Functions' optimized aws-sdk integration materializes Bedrock's
    # content-block discriminator as `Type: "tool_use"`. Keep the boundary exact:
    # accept the observed service envelope, not arbitrary extra model fields.
    _require(
        set(tool_use) == {"ToolUseId", "Name", "Input", "Type"},
        "tool-use envelope keys are invalid",
    )
    _require(tool_use.get("Type") == TOOL_USE_TYPE, "unexpected Bedrock tool-use type")
    _require(tool_use.get("Name") == TOOL_NAME, "unexpected Bedrock tool name")
    _require(
        isinstance(tool_use.get("ToolUseId"), str)
        and bool(TOOL_USE_ID_RE.fullmatch(tool_use["ToolUseId"])),
        "tool-use id is invalid",
    )
    tool_input = _object(tool_use.get("Input"))
    _require(bool(tool_input), "tool input is missing")
    return tool_input


def validate(event: dict[str, Any]) -> dict[str, Any]:
    grade = _object(event.get("gradeResult"))
    approval = _object(event.get("approval"))
    report = _object(event.get("reportResult"))
    features = _object(event.get("features"))
    model_result = _object(event.get("modelResult"))
    model_id = event.get("modelId")
    expected_model_id = os.environ.get("REPORT_DECISION_MODEL_ID")

    _require(event.get("profile") == PROFILE, "profile mismatch")
    _require(event.get("target") == PROFILE, "target mismatch")
    _require(grade.get("status") == "awaiting_verifier_gate", "GRADE status mismatch")
    _require(grade.get("target_domain") == PROFILE, "GRADE target mismatch")
    grade_hash = _require_hash(grade.get("grade_verdict_hash"), "grade hash")
    bundle_hash = _require_hash(grade.get("grade_freeze_bundle_sha256"), "bundle hash")
    version_id = grade.get("grade_freeze_version_id")
    _require(isinstance(version_id, str) and bool(version_id), "GRADE VersionId is missing")

    _require(approval.get("decision") == "approved", "approval is not approved")
    _require(approval.get("target") == PROFILE, "approval target mismatch")
    _require(approval.get("grade_verdict_hash") == grade_hash, "approval grade hash mismatch")
    _require(approval.get("grade_freeze_bundle_sha256") == bundle_hash, "approval bundle hash mismatch")
    _require(approval.get("grade_freeze_version_id") == version_id, "approval VersionId mismatch")
    _require(report.get("status") == "historical_replay_report_ready", "REPORT status mismatch")
    _require(report.get("grade_verdict_hash") == grade_hash, "REPORT grade hash mismatch")

    _require(features == FEATURES, "feature vector is not the pinned registry value")
    _require(
        isinstance(expected_model_id, str) and bool(MODEL_ID_RE.fullmatch(expected_model_id)),
        "deployed model id is not configured",
    )
    _require(isinstance(model_id, str) and bool(MODEL_ID_RE.fullmatch(model_id)), "model id is invalid")
    _require(model_id == expected_model_id, "model id does not match the deployed resolver")
    tool_input = _extract_tool_input(model_result)
    _require(
        set(tool_input) == {"schema_version", "primary_reader", "action_order"},
        "tool input keys are invalid",
    )
    schema_version = tool_input.get("schema_version")
    _require(
        type(schema_version) is int and schema_version == SCHEMA_VERSION,
        "schema version mismatch",
    )
    expected_binding = {
        "profile": PROFILE,
        "target_domain": PROFILE,
        "grade_verdict_hash": grade_hash,
        "grade_freeze_bundle_sha256": bundle_hash,
        "grade_freeze_version_id": version_id,
        "feature_registry": FEATURE_REGISTRY,
        "feature_hash": _canonical_hash(FEATURES),
    }

    reader = tool_input.get("primary_reader")
    order = tool_input.get("action_order")
    _require(reader in READERS, "primary reader is not allowed")
    _require(
        isinstance(order, list)
        and len(order) == len(ACTIONS)
        and all(isinstance(action, str) for action in order)
        and set(order) == ACTIONS,
        "action order must be an exact unique permutation",
    )
    _require(order[0] in FIRST_ACTIONS[reader], "first action is incompatible with the primary reader")

    decision = {
        "schema_version": SCHEMA_VERSION,
        "resolution_type": RESOLUTION_TYPE,
        **expected_binding,
        "model_id": model_id,
        "primary_reader": reader,
        "action_order": order,
    }
    return {
        "status": "validated",
        **decision,
        "decision_hash": _canonical_hash(decision),
    }


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    return validate(event)

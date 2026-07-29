#!/usr/bin/env python3
"""
bob-approval-gate-impl.py — the human-approval gate implementation.

Matched (via scripts/generate-claude-settings.js, gated behind an AWS-branch env flag so
interactive local use is unaffected) on:
    mcp__hacker-bob__bob_advance_session   AND   mcp__hacker-bob__bob_finalize_report

Does a fast, non-blocking poll of a schema-v2 approval artifact in S3
(approvals/<engagementId>/<grade_verdict_hash>.approved) that ONLY a named human's Step
Functions SendTaskSuccess (via the ApprovalWriter Lambda) can write — the model's own execution
role has s3:GetObject on that prefix but never s3:PutObject (see template.yaml
HackerBobAgentRuntimeExecutionRole). A compromised bob can edit its own state.json but cannot
forge that write. The artifact's HMAC-SHA256 over compact UTF-8 JSON
[profile,target,grade_hash,freeze_body_sha256,freeze_version_id] is also recomputed and
compared (defense-in-depth): existence alone is not enough, since IAM is the
PRIMARY enforcement but a mis-scoped bucket policy elsewhere in the account must not silently
open a bypass. fx-hmac-content: the artifact is bound to the EXACT grade the human reviewed —
the stored grade_verdict_hash must also equal the CURRENT grade.json's canonical hash, so an
amend+re-grade after approval invalidates the same previously-valid artifact.
  exit 2  -> block (retryable): report step is withheld until a human approves.
  exit 0  -> allow: approval artifact present AND HMAC-verified (or hook out of scope / disabled).

This is a defensive gate. It adds no offensive capability.
Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md

FAIL-CLOSED BY DESIGN: this is the opposite fail direction from the sibling
bob-http-write-confirm-impl.py's "ask" default. There is no interactive human to ask inline
here — the only human signal this hook can observe is the approval artifact itself — so any
ambiguity (parse error, missing field, lookup exception, HMAC mismatch) must resolve to BLOCK
(exit 2), never silently allow the report step to proceed.
"""
import hashlib
import hmac as hmac_module
import json
import os
import sys
import string

# Bound the stdin read so a large payload can't saturate the hook timeout (a SIGKILL/timeout
# would abort with a non-2, non-0 exit; Claude Code treats non-2 as non-blocking, which would
# let an oversized/adversarial payload slip the gate open). Matches the sibling
# bob-http-write-confirm-impl.py's MAX_BODY_BYTES discipline. A truncated read fails JSON
# parsing below and falls into the fail-closed path (block), not fail-open.
MAX_BODY_BYTES = 4 * 1024 * 1024

ADVANCE_SESSION_TOOL = "mcp__hacker-bob__bob_advance_session"
FINALIZE_REPORT_TOOL = "mcp__hacker-bob__bob_finalize_report"
GATED_TOOLS = {ADVANCE_SESSION_TOOL, FINALIZE_REPORT_TOOL}
SAFE_ENGAGEMENT_ID_CHARS = set(string.ascii_letters + string.digits + "._:-")
LIBHEIF_PROFILE = "libheif-cve-2026-49271"
BINDING_VERSION = "grade-freeze-v2"


def allow():
    # Exit 0 with no stdout = the hook abstains; Claude Code proceeds with its normal flow.
    raise SystemExit(0)


def block():
    sys.stdout.write("awaiting named-human approval (Step Functions task token)\n")
    raise SystemExit(2)


def fail_closed():
    # Any unexpected error in the decision path (b-f) must not silently allow the report step.
    sys.stdout.write(
        "awaiting named-human approval (Step Functions task token) "
        "[error inspecting request; failing closed]\n"
    )
    raise SystemExit(2)


def _is_safe_engagement_id(engagement_id):
    """Return whether an untrusted tool_input target can safely key an approval lookup.

    This closes traversal/injection through path separators, "..", NUL bytes, and
    non-allowlisted characters in the MCP tool_input.target_domain field before it is used
    to build a filesystem path. When this local file lookup is replaced by S3 or DynamoDB,
    keep this validation with the backend swap: the same untrusted-input-into-backend-lookup
    risk applies to S3 keys and DynamoDB partition keys.
    """
    if not isinstance(engagement_id, str) or not engagement_id:
        return False
    if engagement_id.startswith("."):
        return False
    if "/" in engagement_id or "\\" in engagement_id:
        return False
    if ".." in engagement_id or "\x00" in engagement_id:
        return False
    return all(char in SAFE_ENGAGEMENT_ID_CHARS for char in engagement_id)


def _fetch_approval_artifact_bytes(engagement_id, current_grade_verdict_hash):
    """Fetch the raw bytes of the approval artifact, or None if absent/unreachable.

    Two backends, tried in order:
      1. Local-filesystem stand-in seam (dev/test only): when BOB_APPROVAL_ARTIFACT_DIR is
         set, reads f"{dir}/{engagement_id}/{current_grade_verdict_hash}.approved".
         Post-fx-gate-hardening, template.yaml's
         AgentCore provisioner no longer sets this in production — that writable-EFS path was
         exactly the forgeable design this hardening removes. Tests point it at a tmp dir.
      2. Real production backend: S3 GetObject on BOB_APPROVAL_BUCKET's
         approvals/<engagement_id>/<current_grade_verdict_hash>.approved key — the prefix
         HackerBobAgentRuntimeExecutionRole
         can only read, never write (see template.yaml). boto3's S3 client is natively
         synchronous, so no async bridge is needed here (contrast
         mcp/lib/approval-store.js's Node-side equivalent, which must shell out because the
         AWS SDK v3 JS clients are Promise-only).
    """
    if not _is_safe_engagement_id(engagement_id) or not _is_sha256(current_grade_verdict_hash):
        return None
    artifact_dir = os.environ.get("BOB_APPROVAL_ARTIFACT_DIR")
    if artifact_dir:
        artifact_path = os.path.join(
            artifact_dir,
            engagement_id,
            f"{current_grade_verdict_hash}.approved",
        )
        try:
            with open(artifact_path, "rb") as fh:
                return fh.read()
        except OSError:
            return None
    bucket = os.environ.get("BOB_APPROVAL_BUCKET")
    if not bucket:
        return None
    try:
        import boto3
        client = boto3.client("s3")
        resp = client.get_object(
            Bucket=bucket,
            Key=f"approvals/{engagement_id}/{current_grade_verdict_hash}.approved",
        )
        return resp["Body"].read()
    except Exception:
        return None


def _resolve_hmac_key():
    """Resolve the HMAC signing key.

    Local/dev/test stand-in: BOB_APPROVAL_HMAC_KEY, a literal key value — never set in
    production (mirrors the BOB_APPROVAL_ARTIFACT_DIR stand-in above). Production fetches
    the real key from Secrets Manager via BOB_APPROVAL_HMAC_SECRET_ID, readable by
    HackerBobAgentRuntimeExecutionRole via a narrowly-scoped secretsmanager:GetSecretValue
    grant (see template.yaml) — this is the DEFENSE-IN-DEPTH key; the IAM deny-write on
    approvals/* remains the PRIMARY enforcement, so the model knowing this key cannot let
    it forge a stored artifact it still cannot s3:PutObject.
    """
    key = os.environ.get("BOB_APPROVAL_HMAC_KEY")
    if key:
        return key.encode("utf-8")
    secret_id = os.environ.get("BOB_APPROVAL_HMAC_SECRET_ID")
    if not secret_id:
        return None
    try:
        import boto3
        client = boto3.client("secretsmanager")
        resp = client.get_secret_value(SecretId=secret_id)
        secret_string = resp.get("SecretString")
        return secret_string.encode("utf-8") if secret_string else None
    except Exception:
        return None


def _current_grade_verdict_hash(engagement_id):
    """Read and canonically hash the CURRENT grade verdict for engagement_id.

    fx-hmac-content: the approval artifact is bound to the exact grade the human reviewed,
    not merely to engagement_id. Reads
    ~/hacker-bob-sessions/<engagement_id>/grade.json -- the same on-disk path
    mcp/lib/paths.js's gradeArtifactPaths(domain) resolves to, keyed by the already-validated
    engagement_id (_is_safe_engagement_id already ran before this is called via
    _approval_artifact_present, but this function re-checks defensively since it is also a
    plausible standalone call site).

    Canonicalization matches mcp/lib/verification-contracts.js's hashCanonicalJson
    byte-for-byte for the integer/string-only grade-verdict shape written by
    mcp/lib/grade-verdict-store.js: json.dumps(doc, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False) already recursively sorts nested dict keys (Python's sort_keys is
    recursive) and drops no whitespace, matching hashCanonicalJson's recursive
    Object.keys().sort() + compact JSON.stringify -- no manual canonicalize pass is needed.

    Returns None on any ambiguity (unsafe engagement_id, unresolvable HOME, missing/
    unreadable/malformed grade.json) -- callers treat None as "no current verdict to bind
    against", which fails the artifact check CLOSED (never treated as a match).
    """
    if not _is_safe_engagement_id(engagement_id):
        return None
    home = os.environ.get("HOME")
    if not home:
        return None
    grade_path = os.path.join(home, "hacker-bob-sessions", engagement_id, "grade.json")
    try:
        with open(grade_path, "rb") as fh:
            document = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    try:
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _valid_version_id(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 1024
        and not any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
    )


def _approval_artifact_present(engagement_id):
    """Look up whether a named human's HMAC-verified, content-bound approval artifact exists.

    Fetches the artifact (S3-backed in production; see _fetch_approval_artifact_bytes),
    requires the schema-v2 full freeze binding, and recomputes HMAC-SHA256 over
    compact JSON [profile,target,grade_hash,body_sha256,version_id] — mere existence of
    a well-formed-looking object is NOT sufficient (IAM deny-write is the PRIMARY
    enforcement; this HMAC check is defense-in-depth against a write that lands in the
    bucket through some other, over-broad principal).

    fx-hmac-content: additionally requires the artifact's own stored grade_verdict_hash to
    equal _current_grade_verdict_hash(engagement_id) -- the hash of the grade verdict AS IT
    STANDS RIGHT NOW. If the report/grade was amended and re-graded after the human approved,
    the current hash no longer matches the hash the artifact was signed over, so the SAME
    previously-valid artifact is rejected. This closes the amend-and-reexport gap: one
    approval no longer permanently pre-authorizes unlimited amend+re-finalize+re-export.

    Fails CLOSED on any ambiguity: unsafe engagement_id, missing/unreadable artifact,
    malformed JSON, missing hmac field, missing/unreadable grade.json (current hash is None),
    missing/invalid profile, target, body hash, VersionId, or grade hash, a grade hash mismatch,
    unresolvable key, or an HMAC mismatch.
    """
    current_grade_verdict_hash = _current_grade_verdict_hash(engagement_id)
    if not _is_sha256(current_grade_verdict_hash):
        return False
    raw = _fetch_approval_artifact_bytes(engagement_id, current_grade_verdict_hash)
    if not raw:
        return False
    try:
        parsed = json.loads(raw)
    except Exception:
        return False
    if not isinstance(parsed, dict):
        return False
    if parsed.get("schema_version") != 2 or parsed.get("binding_version") != BINDING_VERSION:
        return False
    provided_hex = parsed.get("hmac")
    if not _is_sha256(provided_hex):
        return False
    stored_grade_verdict_hash = parsed.get("grade_verdict_hash")
    if not _is_sha256(stored_grade_verdict_hash):
        return False
    if current_grade_verdict_hash != stored_grade_verdict_hash:
        return False
    if parsed.get("target_domain") != engagement_id:
        return False
    expected_profile = LIBHEIF_PROFILE if engagement_id == LIBHEIF_PROFILE else "smoke"
    if parsed.get("profile") != expected_profile:
        return False
    body_sha256 = parsed.get("grade_freeze_bundle_sha256")
    if not _is_sha256(body_sha256):
        return False
    version_id = parsed.get("grade_freeze_version_id")
    if not _valid_version_id(version_id):
        return False
    key = _resolve_hmac_key()
    if not key:
        return False
    try:
        provided = bytes.fromhex(provided_hex)
    except ValueError:
        return False
    binding = [
        expected_profile,
        engagement_id,
        stored_grade_verdict_hash,
        body_sha256,
        version_id,
    ]
    binding_bytes = json.dumps(
        binding,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    expected = hmac_module.new(key, binding_bytes, hashlib.sha256).digest()
    return hmac_module.compare_digest(provided, expected)


def decide():
    # 2. Read the hook stdin JSON; extract tool name + (for advance_session) to_state.
    raw = sys.stdin.read(MAX_BODY_BYTES)
    try:
        payload = json.loads(raw or "{}")
    except Exception:
        # Malformed stdin while potentially in scope: fail CLOSED (opposite of the sibling
        # write-confirm gate's "ask" default — there's no human to ask inline here).
        block()

    if not isinstance(payload, dict):
        block()

    tool_name = payload.get("tool_name")
    if tool_name not in GATED_TOOLS:
        allow()  # out of scope

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        # In-scope tool but no readable tool_input: can't confirm scope/engagement -> block.
        block()

    # 3. Only gate the GRADE->REPORT edge: advance_session(to_state=="REPORT") or
    #    bob_finalize_report (always in scope when reached; it has no to_state field).
    if tool_name == ADVANCE_SESSION_TOOL:
        to_state = tool_input.get("to_state")
        if to_state != "REPORT":
            allow()  # out of scope to_state

    engagement_id = tool_input.get("target_domain")

    # 4. Look up the approval artifact keyed by engagementId (S3/DynamoDB backend swap point).
    # 5. If absent: block (retryable). If present: allow.
    if _approval_artifact_present(engagement_id):
        allow()
    block()


def main():
    # 1. Only engage on the AWS branch. Inert by default: this check happens first, before any
    # stdin read or interpreter work beyond it, mirroring bob-http-write-confirm.sh's
    # "disabled case costs nothing" discipline (that discipline lives in THIS impl, not a
    # wrapping shell, since bob-approval-gate.sh execs this file unconditionally).
    if os.environ.get("BOB_AGENTCORE") != "1":
        sys.exit(0)

    # allow()/block() raise SystemExit (a BaseException, not Exception), so they propagate as
    # the normal decision. Any OTHER error in the decision path must fail CLOSED (exit 2), never
    # silently allow the report step.
    try:
        decide()
    except Exception:
        fail_closed()


if __name__ == "__main__":
    main()

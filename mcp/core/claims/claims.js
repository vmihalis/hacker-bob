"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertEnumValue,
  normalizeOptionalText,
} = require("../io/validation.js");
const {
  assertSafeDomain,
  claimsJsonlPath,
  offensiveRunsJsonlPath,
  repoCommandRunsJsonlPath,
  sessionsRoot,
} = require("../io/paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
} = require("../io/storage.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  normalizeReferenceArray,
} = require("../io/validation.js");
const {
  readJsonlStrict,
} = require("../io/storage.js");
const {
  withDocumentHash,
} = require("../verification/document-hash.js");
const {
  normalizeTaskLens,
} = require("../session/task-lenses.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../io/envelope.js");
const {
  resolveRowVerifierSafely,
} = require("../ledger-integrity/index.js");
const {
  verifyRowWithMac,
  assertRowMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT,
} = require("../ledger-integrity/index.js");
const {
  SEVERITY_VALUES,
} = require("../constants/shared-vocabulary.js");
const {
  OFFENSIVE_OUTCOME_VALUES,
  SAFE_ORACLE_KINDS,
  OFFENSIVE_ROW_ORACLE_KIND_VALUES,
} = require("../constants/offensive-run-vocabulary.js");

// A stamped oracle_kind marks an offensive-runs row whose evidence is NOT a self-
// contained executed binding — an out-of-band callback (out_of_band_interaction) or a
// second-order stored-effect re-read (second_order_reread), both observed through a
// channel distinct from the injection point. The read-time exploit-run skip below keys
// on membership here to REFUSE self-skip: such a row must earn a finding-differential
// verified_pass against a decoy-silent control rather than self-close on one positive.
// Single-sourced from constants (same list offensive-capture-writer validates the stamp
// against), so the stampable set and this recognition can never drift.
const NON_SELF_CONTAINED_ORACLE_KINDS = new Set(OFFENSIVE_ROW_ORACLE_KIND_VALUES);
const {
  readFrontierEvents,
} = require("../frontier/frontier-events.js");

const CLAIM_VERSION = 1;
const CLAIMS_MAX_RECORDS = 20000;
const CLAIM_STATUSES = Object.freeze(["candidate", "clustered", "frozen", "verified", "dismissed", "reported"]);
const CLAIM_SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "informational"]);

// EvidenceReference schema (Cycle C.5).
//
// CandidateClaim carries a first-class evidence_refs[] payload. Each reference
// names an external artifact whose canonical-hash content is the durable
// evidence; once the claim batch is frozen, downstream stages (verification,
// evidence pack, grade, report snapshot) read evidence from these references
// rather than re-scanning live disk artifacts.
//
// Canonical shape:
//   {
//     kind: "<one of EVIDENCE_REFERENCE_KIND_VALUES>",
//     artifact_path?: relative or absolute path under the session dir,
//     content_hash?: sha256 hex of the canonical payload of the referenced
//                    artifact,
//     source_run_id?: AgentRun id that produced the evidence,
//     ref?: optional line/anchor pointer into the artifact,
//     ...kind-specific fields (finding_id, chain_attempt_id, ...)
//   }
// Plane O Cycle O.8: code-bound EvidenceReference shapes.
//
//   repo_file        : Carries the file_path, the sha256 of the file's full
//                      bytes (`content_hash`), and an optional `line_range`
//                      pointer into the file. When the EvidenceReference
//                      excerpts a specific region, `snippet_hash` is the
//                      sha256 of that excerpted region's bytes. The raw
//                      snippet stays in `repo-checks.jsonl` (which is
//                      read-guard-protected and redacted per O.5/O-P7);
//                      the EvidenceReference itself never carries excerpted
//                      content.
//
//   repo_command_run : Carries the `run_id` of the bob_repo_docker_run row,
//                      the sha256 of the command tokens (`command_hash`),
//                      the integer exit code, and the sha256 of the
//                      captured stdout/stderr files
//                      (`stdout_hash`/`stderr_hash`). The raw stdout/stderr
//                      live on disk under `repo-runs/<run_id>.{stdout,stderr}`
//                      and are read-guard-protected per O.7.
//
//   exploit_run      : Carries the `run_id` of an offensive-runs.jsonl row
//                      produced by the offensive runner, binding tool id,
//                      target URL, safe offensive outcome, command hash,
//                      exit code, and stdout/stderr capture hashes.
//                      DEFERRED (PR #108 review, Codex P2): once a frozen
//                      claim carries an exploit_run ref, the C.5
//                      freeze-completeness gate
//                      (claim-freeze.js::assertCompletenessAgainstFreeze)
//                      will mark it `missing` unless an observed projection is
//                      supplied — there is no projectOffensiveRunObservedRef
//                      yet. This is unreachable today (no tool surface emits
//                      exploit_outcome), so the projection lands with the
//                      offensive runner / tool-surface PR that defines where
//                      raw exploit output is captured. Until then the
//                      evidence-agent must supply the exploit_run observed ref
//                      explicitly, or freeze-completeness will block GRADE.
const EVIDENCE_REFERENCE_KIND_VALUES = Object.freeze([
  "finding",
  "verification_round",
  "chain_attempt",
  "http_audit",
  "smart_contract_evidence",
  "agent_run",
  "repo_file",
  "repo_command_run",
  "exploit_run",
  // ADDITIVE: a claim whose proof IS a cross-stack composition path declares it
  // with a composition_path ref carrying the path_hash bound in the audit-graded
  // composition-verified.jsonl. It is the precise machine signal that a finding's
  // proof is a cross-stack composition path (vs an incidental multi-surface
  // finding); the grade/claims cross-stack gate binds it. A claim WITHOUT this
  // ref whose surfaces are single-stack is never cross-stack and is untouched.
  "composition_path",
]);

function isHex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function assertRepoFileEvidenceShape(ref, fieldName) {
  // O.8 payload contract — repo_file:
  //   {kind, file_path, content_hash, line_range?, snippet_hash?, source_run_id?}
  // file_path + content_hash are the natural identity; snippet_hash is the
  // sha256 of an excerpted region (raw excerpt itself stays in
  // repo-checks.jsonl). line_range, when present, is {start_line, end_line}
  // with 1-based line numbers in non-decreasing order.
  if (typeof ref.file_path !== "string" || !ref.file_path.trim()) {
    throw new Error(`${fieldName}.file_path must be a non-empty string for kind="repo_file"`);
  }
  if (!isHex64(ref.content_hash)) {
    throw new Error(`${fieldName}.content_hash must be a 64-hex content digest for kind="repo_file"`);
  }
  if (ref.snippet_hash != null && !isHex64(ref.snippet_hash)) {
    throw new Error(`${fieldName}.snippet_hash must be a 64-hex content digest when present`);
  }
  if (ref.line_range != null) {
    const range = ref.line_range;
    if (typeof range !== "object" || Array.isArray(range)) {
      throw new Error(`${fieldName}.line_range must be an object {start_line, end_line} when present`);
    }
    if (!Number.isInteger(range.start_line) || range.start_line < 1) {
      throw new Error(`${fieldName}.line_range.start_line must be a positive integer`);
    }
    if (!Number.isInteger(range.end_line) || range.end_line < range.start_line) {
      throw new Error(`${fieldName}.line_range.end_line must be an integer >= start_line`);
    }
  }
}

function assertRepoCommandRunEvidenceShape(ref, fieldName) {
  // O.8 payload contract — repo_command_run:
  //   {kind, run_id, command_hash, exit_code, stdout_hash, stderr_hash, source_run_id?}
  // run_id is the natural identity (deterministic per repoDockerRun row);
  // command_hash is the sha256 of the canonicalized command tokens;
  // exit_code is the integer reported by the runtime (null is allowed for
  // pre-completion captures, but at append time we require a concrete int
  // or null); stdout_hash/stderr_hash are the sha256 of the capture files.
  if (typeof ref.run_id !== "string" || !ref.run_id.trim()) {
    throw new Error(`${fieldName}.run_id must be a non-empty string for kind="repo_command_run"`);
  }
  if (!isHex64(ref.command_hash)) {
    throw new Error(`${fieldName}.command_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (!isHex64(ref.stdout_hash)) {
    throw new Error(`${fieldName}.stdout_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (!isHex64(ref.stderr_hash)) {
    throw new Error(`${fieldName}.stderr_hash must be a 64-hex content digest for kind="repo_command_run"`);
  }
  if (ref.exit_code != null && !Number.isInteger(ref.exit_code)) {
    throw new Error(`${fieldName}.exit_code must be an integer or null for kind="repo_command_run"`);
  }
}

// Value-blind canonicalization of an exploit_run target. PR #108 review
// (Codex P1/P2, four rounds): the hash-bound `target` is persisted verbatim into
// claims.jsonl, so any credential embedded in the URL leaks on every claim read.
// A secret-NAME denylist is whack-a-mole — it kept missing userinfo, OAuth
// implicit `#access_token`, compound names (`client_secret`, `X-Amz-Signature`),
// and routed fragments (`#/cb?token=`). So we reduce structurally to
// origin + pathname: drop userinfo, the entire query, and the fragment. This is
// the only value-blind form that BOTH avoids leaking secrets AND survives the
// generic sensitive-material scan (which flags `access_token=<placeholder>` even
// with a redacted value). The exact request — query, canary, payload — stays
// bound by command_hash and recoverable from the read-guarded capture, so the
// reportable PoC is not lost; only the proof-binding identifier is reduced.
//
// This is the single canonical form the offensive runner MUST also write to the
// offensive-runs.jsonl row so the row and this ref stay byte-identical for the
// proof binding (the runner imports canonicalizeExploitTarget for exactly this).
function canonicalizeExploitTarget(targetUrl) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    // Opaque / relative targets are rejected by the shape validator; leave them
    // unchanged here rather than fabricating an origin.
    return targetUrl;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return targetUrl;
  }
  return `${parsed.origin}${parsed.pathname}`;
}

function assertExploitRunEvidenceShape(ref, fieldName) {
  // Offensive proof contract:
  //   {kind, run_id, tool_id, target, offensive_outcome, command_hash,
  //    exit_code, stdout_hash, stderr_hash, source_run_id?}
  // The row cross-check later proves this ref is backed by a real,
  // non-dry-run offensive-runs.jsonl row.
  if (typeof ref.run_id !== "string" || !ref.run_id.trim()) {
    throw new Error(`${fieldName}.run_id must be a non-empty string for kind="exploit_run"`);
  }
  if (typeof ref.tool_id !== "string" || !ref.tool_id.trim()) {
    throw new Error(`${fieldName}.tool_id must be a non-empty string for kind="exploit_run"`);
  }
  if (typeof ref.target !== "string" || !ref.target.trim()) {
    throw new Error(`${fieldName}.target must be a non-empty string for kind="exploit_run"`);
  }
  // PR #108 review (Codex P1): require an absolute http(s) URL. Relative/opaque
  // targets cannot be value-blind redacted (canonicalizeExploitTarget can only
  // parse absolute URLs) and cannot be scope-checked, so they are rejected
  // rather than persisted raw.
  let parsedTarget;
  try {
    parsedTarget = new URL(ref.target);
  } catch {
    throw new Error(`${fieldName}.target must be an absolute http(s) URL for kind="exploit_run"`);
  }
  if (parsedTarget.protocol !== "http:" && parsedTarget.protocol !== "https:") {
    throw new Error(`${fieldName}.target must use the http(s) scheme for kind="exploit_run"`);
  }
  assertEnumValue(ref.offensive_outcome, OFFENSIVE_OUTCOME_VALUES, `${fieldName}.offensive_outcome`);
  if (!isHex64(ref.command_hash)) {
    throw new Error(`${fieldName}.command_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (!isHex64(ref.stdout_hash)) {
    throw new Error(`${fieldName}.stdout_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (!isHex64(ref.stderr_hash)) {
    throw new Error(`${fieldName}.stderr_hash must be a 64-hex content digest for kind="exploit_run"`);
  }
  if (ref.exit_code != null && !Number.isInteger(ref.exit_code)) {
    throw new Error(`${fieldName}.exit_code must be an integer or null for kind="exploit_run"`);
  }
}

function assertCompositionPathEvidenceShape(ref, fieldName) {
  // composition_path payload contract:
  //   {kind: "composition_path", path_hash}
  // path_hash is the 64-hex key into the audit-graded composition-verified.jsonl
  // ledger (fullPathHash over the path's leaves). It is the only field that binds
  // the claim to a cross-stack verified_pass; the grade/claims gate tests its
  // membership in verified_path_hashes[] (re-resolved at read time). No content is
  // carried here — the proof lives in the MCP-write-only ledger.
  if (!isHex64(ref.path_hash)) {
    throw new Error(`${fieldName}.path_hash must be a 64-hex composition path_hash for kind="composition_path"`);
  }
}

function normalizeEvidenceReferenceShape(ref, fieldName = "evidence_refs[]") {
  if (ref == null || typeof ref !== "object" || Array.isArray(ref)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const kind = ref.kind;
  if (typeof kind !== "string" || !kind.trim()) {
    throw new Error(`${fieldName}.kind must be a non-empty string`);
  }
  const artifactPath = ref.artifact_path;
  if (artifactPath != null && (typeof artifactPath !== "string" || !artifactPath.trim())) {
    throw new Error(`${fieldName}.artifact_path must be a non-empty string when present`);
  }
  const contentHash = ref.content_hash;
  if (contentHash != null && !isHex64(contentHash)) {
    throw new Error(`${fieldName}.content_hash must be a 64-hex content digest when present`);
  }
  const sourceRunId = ref.source_run_id;
  if (sourceRunId != null && (typeof sourceRunId !== "string" || !sourceRunId.trim())) {
    throw new Error(`${fieldName}.source_run_id must be a non-empty string when present`);
  }
  // O.8: kind-specific payload shapes for code-bound evidence. These run
  // after the common-field checks so the existing kinds keep their
  // permissive shape and only the two new kinds carry mandatory fields.
  if (kind === "repo_file") {
    assertRepoFileEvidenceShape(ref, fieldName);
  } else if (kind === "repo_command_run") {
    assertRepoCommandRunEvidenceShape(ref, fieldName);
  } else if (kind === "exploit_run") {
    assertExploitRunEvidenceShape(ref, fieldName);
    // Value-blind redaction before the target is hash-bound into the claim, so
    // no embedded secret is ever persisted (see canonicalizeExploitTarget).
    ref.target = canonicalizeExploitTarget(ref.target);
  } else if (kind === "composition_path") {
    assertCompositionPathEvidenceShape(ref, fieldName);
  }
  return ref;
}

function evidenceReferenceLookupKey(ref) {
  // Stable identity for completeness comparison. Two refs are "the same"
  // reference when their kind + the natural identifier for that kind match.
  // Falls back to a tuple of (kind, artifact_path, content_hash) when no
  // kind-specific id is available so two arbitrary refs over the same artifact
  // compare equal.
  if (!ref || typeof ref !== "object") return null;
  const kind = typeof ref.kind === "string" ? ref.kind : "";
  if (kind === "finding" && typeof ref.finding_id === "string") {
    return `${kind}:${ref.finding_id}`;
  }
  if (kind === "verification_round") {
    const round = typeof ref.verification_round === "string"
      ? ref.verification_round
      : (typeof ref.round === "string" ? ref.round : "");
    if (round) return `${kind}:${round}`;
  }
  if (kind === "chain_attempt" && typeof ref.chain_attempt_id === "string") {
    return `${kind}:${ref.chain_attempt_id}`;
  }
  if (kind === "http_audit") {
    if (typeof ref.http_audit_id === "string") return `${kind}:${ref.http_audit_id}`;
    if (typeof ref.request_id === "string") return `${kind}:${ref.request_id}`;
  }
  if (kind === "smart_contract_evidence" && typeof ref.contract_address === "string") {
    const chain = typeof ref.chain_id === "string" || typeof ref.chain_id === "number"
      ? `:${ref.chain_id}`
      : "";
    return `${kind}:${ref.contract_address}${chain}`;
  }
  if (kind === "agent_run" && typeof ref.agent_run_id === "string") {
    return `${kind}:${ref.agent_run_id}`;
  }
  // O.8 code-bound kinds. repo_file's identity is the (file_path, content_hash)
  // pair so two refs against the same content at different excerpt windows
  // still collapse to one frozen-set entry; repo_command_run's identity is the
  // run_id, which is unique per repoDockerRun row.
  if (kind === "repo_file" && typeof ref.file_path === "string" && typeof ref.content_hash === "string") {
    return `repo_file:${ref.file_path}:${ref.content_hash}`;
  }
  if (kind === "repo_command_run" && typeof ref.run_id === "string") {
    return `repo_command_run:${ref.run_id}`;
  }
  if (kind === "exploit_run" && typeof ref.run_id === "string") {
    return `exploit_run:${ref.run_id}`;
  }
  // composition_path identity is its path_hash (the composition-verified.jsonl key).
  if (kind === "composition_path" && typeof ref.path_hash === "string") {
    return `composition_path:${ref.path_hash}`;
  }
  return `${kind}:${ref.artifact_path || ""}:${ref.content_hash || ""}`;
}

// The deep value-paths a persisted secret_evidence_bypass row is allowed to
// re-honor. Mirrors record-candidate-claim.js secretEvidenceBypassValuePaths:
// the embedded finding lives at payload.finding.<field>; a description bypass
// also covers the top-level summary; an impact bypass also covers claim.impact.
// Any persisted `path` outside this whitelist (e.g. a hand-edited row pointing
// at an arbitrary node) is ignored, so a fabricated row can only suppress the
// value-scan on the same operator-approvable fields the writer could.
const SECRET_EVIDENCE_BYPASS_FIELDS = Object.freeze(new Set([
  "description",
  "proof_of_concept",
  "response_evidence",
  "impact",
]));

// The metadata key that carries the operator-approved secret-evidence bypass
// rows. Its segment `secret` trips the structural SENSITIVE_KEY_RE, but it is a
// fixed, code-emitted metadata key (not attacker/evaluator-controlled secret
// material), so it is lifted out of the payload before the sensitive-material
// scan and validated separately. The scan still fires on every OTHER key and
// value in the payload; only this one code-owned key is exempt, and the rows'
// rationale is length-capped (matching the write-side normalizer).
const SECRET_EVIDENCE_BYPASS_KEY = "secret_evidence_bypass";
const SECRET_EVIDENCE_BYPASS_MAX_ROWS = SECRET_EVIDENCE_BYPASS_FIELDS.size * 2;
const SECRET_EVIDENCE_BYPASS_RATIONALE_MAX = 512;

function isPlainObjectValue(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Honorable value-paths for a single bypass field. A row may only suppress the
// value-scan on a path this field is allowed to cover, so a hand-edited row
// pointing at an arbitrary node is ignored.
function allowedSecretEvidenceBypassPaths(field) {
  const paths = new Set([`payload.finding.${field}`]);
  if (field === "description") paths.add("summary");
  if (field === "impact") paths.add("impact");
  return paths;
}

// Normalize + bound-check the persisted secret_evidence_bypass rows. Only rows
// that name a known field, carry a non-empty length-capped rationale, and point
// at an allowed value-path for that field are kept. Returns null when none
// survive so the metadata key is simply dropped. The rationale is operator audit
// free-text that DESCRIBES the secret-shaped evidence (it routinely mentions
// "bearer"/"cookie"); like the write-side normalizeSecretDetectionBypass it is
// length-capped, NOT value-scanned, so read stays symmetric with write. The
// anti-smuggling property here is audit-visible, not prevented (per the RCA:
// claim_hash is recomputed-not-verified and a local-FS attacker already bypasses
// the scanner).
function normalizeSecretEvidenceBypassRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  if (rows.length > SECRET_EVIDENCE_BYPASS_MAX_ROWS) {
    throw new Error(`payload.${SECRET_EVIDENCE_BYPASS_KEY} carries too many rows`);
  }
  const normalized = [];
  for (const row of rows) {
    if (row == null || typeof row !== "object" || Array.isArray(row)) continue;
    const field = typeof row.field === "string" ? row.field : null;
    const rationale = typeof row.rationale === "string" ? row.rationale : "";
    const path = typeof row.path === "string" ? row.path : null;
    if (!field || !SECRET_EVIDENCE_BYPASS_FIELDS.has(field)) continue;
    // Emptiness is checked on the trimmed value but the stored rationale is kept
    // verbatim so the read-normalized row is byte-identical to the write-persisted
    // row (stable claim_hash recompute).
    if (!rationale.trim() || rationale.length > SECRET_EVIDENCE_BYPASS_RATIONALE_MAX) continue;
    if (!path || !allowedSecretEvidenceBypassPaths(field).has(path)) continue;
    normalized.push({ field, rationale, path });
  }
  return normalized.length > 0 ? normalized : null;
}

// Reconstruct the Set<string> of value-paths whose secret value-scan is skipped,
// from already-normalized secret_evidence_bypass rows. Returns null when nothing
// is honorable so callers fall through to the default full scan.
function reconstructSecretEvidenceBypassPaths(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const paths = new Set();
  for (const row of rows) {
    if (row && typeof row.path === "string") paths.add(row.path);
  }
  return paths.size > 0 ? paths : null;
}

function normalizeConfidence(value) {
  if (value == null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error("confidence must be a number from 0 to 1");
  }
  return Number(value.toFixed(4));
}

function normalizeExploitOutcome(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("exploit_outcome must be an object when present");
  }
  const outcome = assertEnumValue(value.outcome, OFFENSIVE_OUTCOME_VALUES, "exploit_outcome.outcome");
  const safeOracle = value.safe_oracle;
  if (outcome === "exploited_safely") {
    if (safeOracle == null || typeof safeOracle !== "object" || Array.isArray(safeOracle)) {
      throw new Error("exploit_outcome.safe_oracle must be an object when outcome is exploited_safely");
    }
    const kind = assertEnumValue(safeOracle.kind, SAFE_ORACLE_KINDS, "exploit_outcome.safe_oracle.kind");
    return {
      outcome,
      safe_oracle: { kind },
    };
  }
  if (safeOracle != null) {
    throw new Error("exploit_outcome.safe_oracle is only allowed when outcome is exploited_safely");
  }
  return { outcome };
}

function generatedClaimId(fields) {
  return `CL-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeLensArray(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error("lenses must be an array");
  }
  return Array.from(new Set(value.map((lens, index) => normalizeTaskLens(lens, `lenses[${index}]`))));
}

function normalizeCandidateClaim(input, { targetDomain = null, now = new Date(), payloadBypassValuePaths = null } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("claim must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const title = normalizeId(input.title, "title", { maxLength: 240 });
  // Y.0 hotfix 1 (O2): summary cap raised to accommodate field-observed
  // payloads whose description (used as the summary fallback in
  // record-candidate-claim) routinely exceeded 2000 chars. Per-field text
  // caps for the inline finding payload live in
  // mcp/core/claims/candidate-claim-recorder.js CLAIM_TEXT_LIMITS.
  const summary = normalizeId(input.summary, "summary", { maxLength: 16000 });
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const status = assertEnumValue(input.status || "candidate", CLAIM_STATUSES, "status");
  const severity = assertEnumValue(input.severity || "medium", CLAIM_SEVERITIES, "severity");
  const surfaceIds = normalizeOptionalTextArray(input.surface_ids, "surface_ids");
  const lenses = normalizeLensArray(input.lenses);
  // C.5: evidence_refs[] are first-class EvidenceReference entries. Each must
  // carry a kind; artifact_path and content_hash are validated when present so
  // a CandidateClaim whose refs cannot be content-hash-matched at GRADE time
  // is rejected up front.
  // PR #108 review (Codex P2): normalizeReferenceArray runs the generic
  // sensitive-material scan (validateNoSensitiveMaterial) BEFORE
  // normalizeEvidenceReferenceShape. Without pre-redaction a genuinely
  // token-bearing exploit target would be REJECTED by the scan rather than
  // redacted, so a legitimate safe-exploit proof with a credential-bearing
  // callback URL could not be recorded. Canonicalize exploit_run targets first
  // so the scan only ever sees the value-redacted form.
  const preRedactedRefs = Array.isArray(input.evidence_refs)
    ? input.evidence_refs.map((ref) => (
      ref && typeof ref === "object" && ref.kind === "exploit_run" && typeof ref.target === "string"
        ? { ...ref, target: canonicalizeExploitTarget(ref.target) }
        : ref
    ))
    : input.evidence_refs;
  const evidenceRefs = normalizeReferenceArray(preRedactedRefs, "evidence_refs")
    .map((ref, index) => normalizeEvidenceReferenceShape(ref, `evidence_refs[${index}]`));
  const controlExpectation = normalizeOptionalObject(input.control_expectation, "control_expectation");
  const impact = normalizeOptionalText(input.impact, "impact");
  const exploitOutcome = normalizeExploitOutcome(input.exploit_outcome);
  const confidence = normalizeConfidence(input.confidence);
  const sourceTaskIds = normalizeOptionalTextArray(input.source_task_ids, "source_task_ids");
  const agentRunIds = normalizeOptionalTextArray(input.agent_run_ids, "agent_run_ids");
  const tags = normalizeOptionalTextArray(input.tags, "tags");
  // Y.0 hotfix 1 (O2): payload carries the embedded finding-shaped record
  // whose per-field caps were raised in
  // mcp/core/claims/candidate-claim-recorder.js. Pass the widened text cap so the
  // generic plain-object validator does not re-tighten what the writer just
  // accepted. payloadBypassValuePaths is the deep-path Set the caller built
  // from secret_detection_bypass; structural sensitive-key detection still
  // fires, only the listed value-paths skip the regex scan.
  //
  // On read (readCandidateClaims passes no payloadBypassValuePaths) we
  // reconstruct the honored paths from the persisted payload.secret_evidence_bypass
  // rows so a legitimately secret-shaped PoC, approved at write, no longer
  // re-throws on every read. The explicit caller-supplied set and the
  // reconstructed set are unioned so the write path stays a strict superset.
  //
  // The metadata key itself (secret_evidence_bypass) is lifted out of the
  // payload before the scan: its `secret` segment would otherwise trip the
  // structural SENSITIVE_KEY_RE, yet it is a fixed, code-emitted key, not secret
  // material. Every other key and value in the payload is still scanned; the
  // lifted rows are independently normalized, field-whitelisted, and capped.
  const normalizedBypassRows = normalizeSecretEvidenceBypassRows(
    isPlainObjectValue(input.payload) ? input.payload[SECRET_EVIDENCE_BYPASS_KEY] : null,
  );
  const reconstructedBypassPaths = reconstructSecretEvidenceBypassPaths(normalizedBypassRows);
  let effectiveBypassPaths = payloadBypassValuePaths instanceof Set
    ? new Set(payloadBypassValuePaths)
    : null;
  if (reconstructedBypassPaths) {
    if (!effectiveBypassPaths) effectiveBypassPaths = new Set();
    for (const path of reconstructedBypassPaths) effectiveBypassPaths.add(path);
  }
  let payloadForScan = input.payload;
  if (isPlainObjectValue(input.payload) && SECRET_EVIDENCE_BYPASS_KEY in input.payload) {
    payloadForScan = { ...input.payload };
    delete payloadForScan[SECRET_EVIDENCE_BYPASS_KEY];
  }
  const payload = normalizeOptionalObject(payloadForScan, "payload", {
    maxTextChars: 16000,
    bypassValuePaths: effectiveBypassPaths,
  });
  // Re-attach the normalized bypass rows after the scan so the claim persists
  // them verbatim for the next read's path reconstruction.
  if (payload && normalizedBypassRows) {
    payload[SECRET_EVIDENCE_BYPASS_KEY] = normalizedBypassRows;
  }

  const base = {
    version: CLAIM_VERSION,
    target_domain: domain,
    title,
    summary,
    severity,
    status,
    created_at: createdAt,
  };
  if (surfaceIds.length > 0) base.surface_ids = surfaceIds;
  if (lenses.length > 0) base.lenses = lenses;
  if (evidenceRefs.length > 0) base.evidence_refs = evidenceRefs;
  if (controlExpectation) base.control_expectation = controlExpectation;
  if (impact) base.impact = impact;
  if (exploitOutcome) base.exploit_outcome = exploitOutcome;
  if (confidence != null) base.confidence = confidence;
  if (sourceTaskIds.length > 0) base.source_task_ids = sourceTaskIds;
  if (agentRunIds.length > 0) base.agent_run_ids = agentRunIds;
  if (tags.length > 0) base.tags = tags;
  if (payload) base.payload = payload;

  const claimId = normalizeOptionalId(input.claim_id, "claim_id") || generatedClaimId(base);
  return withDocumentHash({
    claim_id: claimId,
    ...base,
  }, "claim_hash");
}

// Plane O O-P4 enforcement (cycle O.7). When a CandidateClaim is high/critical
// AND its implicated code surface(s) are native (C/C++/Rust-unsafe/asm) AND
// no evidence_ref carries `kind: "repo_command_run"`, the claim is a
// static-only native-code finding — which the realization pact forbids,
// because native-code corruption claims demand at least one live execution
// (sanitizer/fuzzer/debugger) to be credible. The validator reads frontier
// events to resolve each surface_id's kind (`code_module`) and language.
// Non-repo sessions and surfaces whose code_module language isn't native short-
// circuit; the rule only fires when all three conditions align.
const O_P4_NATIVE_LANGUAGES = Object.freeze(new Set(["c", "cpp", "rust-unsafe", "asm"]));
const O_P4_TRIGGERING_SEVERITIES = Object.freeze(new Set(["high", "critical"]));
// The standalone finding-differential gate fires at the same medium+ reportable tier
// the grade verdict's reportable-severity set uses (grade-verdict-store.js
// requireFinalReportableSeveritySet), so the executed-binding requirement is uniform.
const MEDIUM_OR_HIGHER_SEVERITIES = Object.freeze(new Set(["medium", "high", "critical"]));

function claimSurfaceLanguageMap(domain, surfaceIds) {
  // Returns surfaceId -> { kind, language } for surfaces that appear as
  // `surface.observed` events. Missing or unreadable frontier ledger collapses
  // to an empty map (non-repo sessions don't have a repo inventory to read).
  const result = new Map();
  if (!Array.isArray(surfaceIds) || surfaceIds.length === 0) return result;
  let events;
  try {
    events = readFrontierEvents(domain);
  } catch {
    return result;
  }
  const wanted = new Set(surfaceIds);
  for (const event of events) {
    if (!event || event.kind !== "surface.observed") continue;
    if (typeof event.surface_id !== "string" || !wanted.has(event.surface_id)) continue;
    const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
      ? event.payload
      : {};
    const surfaceKind = typeof payload.kind === "string" ? payload.kind.trim() : "";
    const language = typeof payload.language === "string" ? payload.language.trim().toLowerCase() : "";
    if (!surfaceKind && !language) continue;
    const existing = result.get(event.surface_id) || {};
    // Later observations win — the materializer treats surface.observed as
    // last-writer-wins for scalar fields.
    result.set(event.surface_id, {
      kind: surfaceKind || existing.kind || null,
      language: language || existing.language || null,
    });
  }
  return result;
}

function readRepoCommandRunRecords(domain) {
  // Read the append-only ledger of bob_repo_docker_run executions. The records
  // are the live-side evidence that a repro command actually ran (rather than
  // being merely cited in an evidence_ref). Missing ledger collapses to an
  // empty list so non-repo sessions short-circuit cleanly; an oversized file
  // raises a hard error rather than silently truncating.
  const filePath = repoCommandRunsJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  const stats = fs.statSync(filePath);
  if (DEFAULT_ARTIFACT_READ_MAX_BYTES != null && stats.size > DEFAULT_ARTIFACT_READ_MAX_BYTES) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `repo-command-runs.jsonl exceeds read cap of ${DEFAULT_ARTIFACT_READ_MAX_BYTES} bytes: ${filePath}`,
    );
  }
  const rows = [];
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // Malformed run-log lines never satisfy the cross-check below; they are
      // silently skipped here so a single corrupt row cannot DoS claim
      // recording for the whole session.
    }
  }
  return rows;
}

// PR #108: realpath-containment for the proof ledger. Defends a symlinked SESSION
// DIRECTORY (O_NOFOLLOW on the leaf file alone does not catch a symlinked parent dir).
// Returns null when the session dir does not exist yet (caller maps null -> []).
function resolveOffensiveRunsFilePathSecure(filePath) {
  const nominalDir = path.dirname(filePath);
  if (!fs.existsSync(nominalDir)) return null;
  const realRoot = fs.realpathSync(sessionsRoot());
  const realDir = fs.realpathSync(nominalDir);
  const expectedDir = path.join(realRoot, path.basename(nominalDir));
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs.jsonl directory must stay inside its session root without domain-directory symlinks: ${nominalDir}`,
    );
  }
  return path.join(realDir, path.basename(filePath));
}

function readOffensiveRunRecords(domain) {
  const filePath = offensiveRunsJsonlPath(domain);
  const realFilePath = resolveOffensiveRunsFilePathSecure(filePath);
  if (realFilePath === null) return [];
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  // On platforms without O_NOFOLLOW, pre-check the leaf for a symlink.
  if (!noFollow) {
    let entry;
    try {
      entry = fs.lstatSync(realFilePath);
    } catch (e) {
      if (e && e.code === "ENOENT") return [];
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Could not stat offensive-runs.jsonl: ${realFilePath} (${e.message || String(e)})`);
    }
    if (entry.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must be a regular file, not a symlink: ${realFilePath}`);
    }
  }
  let fd = null;
  let raw;
  try {
    fd = fs.openSync(realFilePath, fs.constants.O_RDONLY | noFollow);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must be a regular file: ${realFilePath}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must not be hard-linked: ${realFilePath}`);
    }
    if (DEFAULT_ARTIFACT_READ_MAX_BYTES != null && stats.size > DEFAULT_ARTIFACT_READ_MAX_BYTES) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl exceeds read cap of ${DEFAULT_ARTIFACT_READ_MAX_BYTES} bytes: ${realFilePath}`);
    }
    raw = fs.readFileSync(fd, "utf8");
  } catch (error) {
    if (error instanceof ToolError) throw error;
    if (error && error.code === "ENOENT") return [];
    if (error && error.code === "ELOOP") {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must be a regular file, not a symlink: ${realFilePath}`);
    }
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Could not read offensive-runs.jsonl: ${realFilePath} (${error.message || String(error)})`);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
  const rows = [];
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // PR #108 review (Codex P2): unlike repo-command-runs.jsonl (convenience
      // telemetry that tolerates a corrupt line), the offensive ledger is
      // audit-graded proof material. A malformed line means an interrupted
      // append or tampering, so fail closed rather than silently skipping it and
      // letting a later row satisfy the exploit-proof gate against an
      // incomplete/corrupt ledger. Blast radius is limited to exploited_safely
      // claims (the only path that reads this ledger).
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `offensive-runs.jsonl contains a malformed row; refusing to evaluate exploit proof against a corrupt proof ledger: ${realFilePath}`,
      );
    }
  }
  return rows;
}

const O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES = Object.freeze([125, 126, 127]);
const OFFENSIVE_RUN_DISALLOWED_EXIT_CODES = Object.freeze([125, 126, 127]);
const CLAIM_EXPLOIT_SEVERITY_RANK = Object.freeze(
  Object.fromEntries(SEVERITY_VALUES.map((severity, index) => [severity, SEVERITY_VALUES.length - index])),
);

// Per-offensive-tool cap on the demonstrated_severity a signed row may assert. REAL signable
// producers ONLY. FAIL-CLOSED: any tool_id that is NOT an own key resolves to "info" (lowest tier);
// `?? "critical"` would be fail-OPEN and is forbidden. Object.freeze + "use strict" means an
// in-process actor's `MAP.x = "critical"` THROWS — the map cannot be widened at runtime.
//
//   bob_http_idor_confirm: the future PR-C second-test-identity IDOR producer (does NOT exist at
//   HEAD; pre-seeded per design D5 so the ceiling enforces the day PR-C first writes a row). A safe
//   cross-tenant READ of attacker-owned SYNTHETIC objects caps at MEDIUM by construction.
//   bob_http_xss_reflect: the find-axis MVP reflected-canary XSS finder. A reflected-CONTEXT
//   survival (a benign nonce+inert-metachar sentinel survives UNESCAPED into an HTML-executable
//   sink) is reflection-context survival, NOT proven script execution, so it caps at MEDIUM by
//   construction.
//   bob_http_xss_confirm: the browser-EXECUTION reflected-XSS confirm. It drives Bob's own
//   headless browser and proves a benign nonce-keyed marker ACTUALLY EXECUTES (a control/probe
//   differential), which is proven script execution — so it caps at HIGH. It is the deferred
//   browser-execution follow-up the reflect finder anticipated; it is the FIRST HIGH-ceiling
//   signed producer (the #108 in-process-key residual now bounds a fabricated HIGH).
//   bob_oob_poll: the out-of-band interaction confirm (PR6). A target-backend callback carrying
//   the server-minted token to Bob's OWN sink proves server-side request egress reachability
//   (blind SSRF / SSTI / RCE-callback) — limited confidentiality, NOT proven RCE/exfil, and NOT
//   isolated to the bound surface (an intermediary unfurler / proxy / SIEM-scanner in the target's
//   request path can also fetch the token), so it caps at MEDIUM. The signed row's target is the
//   IN-SCOPE injection endpoint resolved at mint, NEVER the constant OOB host (the OOB host + token
//   live only in the capture). A data-returning OOB oracle that could justify HIGH is a separate
//   deferred tool, out of PR6 scope.
// DELIBERATELY ABSENT: bob_http_confirm (real, but NEGATIVE-ONLY — mints no signed row in
//   production; mapping it would grant a signable ceiling to a tool that must never sign);
//   bob_oob_mint (the OOB token allocator — it mints/returns a token + writes the token->surface
//   binding but NEVER signs a row; only bob_oob_poll signs, so mapping mint would grant a signable
//   ceiling to a non-signing tool); AND bob_nuclei_scan (PR7 — a DETECTION-only nuclei lead
//   generator: a template match is a heuristic, not a categorical witness, so it must never mint a
//   signed row. Its oracle always returns positive:false AND its absence here is the belt-and-braces
//   second lock — a future positive verdict would throw "unknown offensive tool_id" rather than sign.
//   An OOB/XSS/IDOR lead it surfaces is re-proven through bob_oob_poll / bob_http_xss_confirm /
//   bob_http_idor_confirm, which DO carry honest ceilings).
const OFFENSIVE_TOOL_DEMONSTRATED_CEILING = Object.freeze(
  Object.assign(Object.create(null), {
    bob_http_idor_confirm: "medium",
    bob_http_xss_reflect: "medium",
    bob_http_xss_confirm: "high",
    bob_oob_poll: "medium",
    // bob_secondorder_reread: the second-order / stored-effect re-read producer. A
    // server-minted canary injected at one in-scope endpoint that surfaces (exact parsed
    // leaf) on a DISTINCT in-scope re-read endpoint, with a decoy-silent control proving
    // non-ambience, demonstrates a stored/second-order effect — a MEDIUM-at-most lead
    // unless the effect itself is the impact, so it caps at MEDIUM by construction. The
    // re-read channel is Bob-controlled (safeFetch), so it carries no OOB self-hit
    // attribution weakness; its single positive still must earn a finding-differential
    // flip (oracle_kind second_order_reread is non-self-contained above).
    bob_secondorder_reread: "medium",
    bob_http_cors_confirm: "medium",
    // HIGH is the CEILING (the max a row may demonstrate), NOT what every run stamps. The producer
    // ALWAYS passes an explicit demonstratedSeverityOverride: "medium" for the v1 authn-vs-ANON
    // differential (a credentialed caller bulk-reads PII an unauthenticated client is denied — real,
    // but not machine-proof of under-privilege/BFLA), and "high" ONLY when the v2 second-AUTHENTICATED-
    // VICTIM arm proves a cross-principal break (the attacker read a subject that a distinct authenticated
    // victim reads as its own private, anon-denied scope). The override can only LOWER the ceiling
    // (offensive-capture-writer.js), so a v1 run is stamped MEDIUM on disk and the claim-vs-row cap
    // (above) then bounds any claim citing it at MEDIUM — raising the ceiling to HIGH never lets a v1
    // differential back a HIGH claim. Only the proven victim-arm row stamps demonstrated_severity:"high".
    bob_http_massread_confirm: "high",
  }),
);

function exploitSeverityRank(severity) {
  const normalized = severity === "informational" ? "info" : severity;
  return (typeof normalized === "string" && CLAIM_EXPLOIT_SEVERITY_RANK[normalized.toLowerCase()]) || 0;
}

function repoCommandRunRowSatisfiesEvidence(row, ref) {
  // The cross-check (additive to the evidence_ref shape gate): the row must
  // exist, be a live execution (not a dry-run plan), and bind back to the
  // evidence_ref via run_id + command_hash. exit_code on the ledger row must
  // also agree with the evidence_ref's claimed exit code so a flaky reviewer
  // cannot cite a different run.
  if (!row || typeof row !== "object") return false;
  if (row.dry_run === true) return false;
  if (row.timed_out === true) return false;
  if (typeof row.run_id !== "string" || row.run_id !== ref.run_id) return false;
  if (typeof row.command_hash !== "string" || row.command_hash !== ref.command_hash) return false;
  // exit_code on the row must be a concrete integer (live execution produced
  // a result). If the evidence_ref also pinned a value, it must match.
  if (!Number.isInteger(row.exit_code)) return false;
  if (O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES.includes(row.exit_code)) return false;
  if (Number.isInteger(ref.exit_code) && row.exit_code !== ref.exit_code) return false;
  return true;
}

// PR #108 review (Codex P1): bind the proof to the claim's own target_domain.
// Returns true only when the cited target URL's host is the claim domain or a
// subdomain of it, so a row planted for another host can never back a claim.
function exploitTargetHostInScope(targetUrl, domain) {
  let host;
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return false;
  }
  const scope = String(domain).toLowerCase();
  return host === scope || host.endsWith(`.${scope}`);
}

function offensiveRunRowSatisfiesEvidence(row, ref, domain, verifier) {
  if (!row || typeof row !== "object") return false;
  // The row must be MAC-signed by the trusted producer (offensive runner). New rows
  // are ed25519 (v2) — verified with the world-readable PUBLIC key; legacy rows are
  // symmetric HMAC (v1) — verified with the symmetric key. The verifier bundle carries
  // both, so verifyRowWithMac dispatches per row on the row's declared scheme. An
  // agent-authored / symlinked / tampered / wrong-key row has no valid MAC and fails
  // here before any field check. Verification is in-process crypto only (no disk
  // re-read, no subprocess on the read hot path).
  //
  // THREAT-MODEL BOUNDARY (be honest about this): the sign/verify split removes the
  // SECRET from the verifiers — they hold only the public key — but the ed25519 PRIVATE
  // key is still 0600 at the agent uid. An agent that executes arbitrary in-process code
  // (e.g. `node -e` that require()s readHandoffSigningPrivateKey and reads the 0600 key
  // via fs) can STILL read it and forge a MAC-valid row, exactly as with the symmetric
  // key. A same-UID actor reads any file its UID can; the PreToolUse hooks cannot mediate
  // in-process syscalls. The structural close requires running the signer under a separate
  // OS uid (gated by the sandbox-isolation attestation) so the agent uid cannot read the
  // key at all. The split is the necessary foundation that makes that separation
  // sufficient; it is NOT the close.
  if (!verifier || typeof verifier !== "object") return false;
  if (!verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier)) return false;
  // PR #108 review (Codex P1): require the row to AFFIRMATIVELY assert a
  // completed, non-dry-run execution. Accepting an omitted/non-boolean dry_run
  // or timed_out would let a hand-authored/incomplete row stand as proof.
  if (row.dry_run !== false) return false;
  if (row.timed_out !== false) return false;
  // Domain binding (Codex P1): the ledger is read from the claim's session, but
  // the row must also be *recorded for* this domain and the cited URL must be in
  // its scope, so a cross-domain row in the same session cannot stand as proof.
  if (typeof row.target_domain !== "string" || row.target_domain !== domain) return false;
  if (!exploitTargetHostInScope(ref.target, domain)) return false;
  if (typeof row.run_id !== "string" || row.run_id !== ref.run_id) return false;
  if (typeof row.tool_id !== "string" || row.tool_id !== ref.tool_id) return false;
  if (typeof row.target !== "string" || row.target !== ref.target) return false;
  if (typeof row.command_hash !== "string" || row.command_hash !== ref.command_hash) return false;
  if (typeof row.stdout_hash !== "string" || row.stdout_hash !== ref.stdout_hash) return false;
  if (typeof row.stderr_hash !== "string" || row.stderr_hash !== ref.stderr_hash) return false;
  if (row.offensive_outcome !== "exploited_safely") return false;
  if (ref.offensive_outcome != null && row.offensive_outcome !== ref.offensive_outcome) return false;
  if (!Number.isInteger(row.exit_code)) return false;
  if (OFFENSIVE_RUN_DISALLOWED_EXIT_CODES.includes(row.exit_code)) return false;
  if (Number.isInteger(ref.exit_code) && row.exit_code !== ref.exit_code) return false;
  // CONFIDENCE-SIGNAL BOUNDARY (Codex/Claude PR#136, intentional Option-B1): this validator does
  // NOT inspect the producer's confidence_signals[]. Those are ADVISORY forensics (e.g. a soft-gated
  // IDOR fire with unproven cross-tenant attribution), hash-bound into the row via stderr_hash but
  // NOT a schema-enforced claim gate. The consequence of weak attribution is carried instead by
  // demonstrated_severity — a soft-gated producer LOWERS its signed severity ceiling (see
  // offensive-capture-writer.js demonstratedSeverityOverride), and severity IS enforced downstream.
  // So a soft-gated row backs a claim only at the reduced severity; a consumer wanting the signal
  // text reads it from the row's stderr capture, it does not flow through this evidence gate.
  return true;
}

// The native-code surfaces a claim touches: code_module surfaces whose language
// is in the O_P4_NATIVE_LANGUAGES set (C/C++/Rust-unsafe/asm). Shared by the
// claim-record gate and the grade-time reproduction gate so both agree on which
// findings are subject to the differential-reproduction proof contract.
function nativeCodeSurfacesForClaim(domain, surfaceIds) {
  const ids = Array.isArray(surfaceIds) ? surfaceIds : [];
  if (ids.length === 0) return [];
  const surfaceInfo = claimSurfaceLanguageMap(domain, ids);
  const native = [];
  for (const surfaceId of ids) {
    const info = surfaceInfo.get(surfaceId);
    if (!info) continue;
    if (info.kind !== "code_module") continue;
    if (!info.language || !O_P4_NATIVE_LANGUAGES.has(info.language)) continue;
    native.push({ surface_id: surfaceId, language: info.language });
  }
  return native;
}

// The structured PoC recipe carried on the claim's embedded finding payload — the
// argv the reproduction verifier re-runs. Returns the validated token array, or
// null when absent/malformed (so callers can require it explicitly).
function claimReproCommandArgv(claim) {
  const finding = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
    ? claim.payload.finding
    : null;
  const argv = finding && typeof finding === "object" && !Array.isArray(finding)
    ? finding.repro_command_argv
    : null;
  if (!Array.isArray(argv) || argv.length === 0) return null;
  if (!argv.every((token) => typeof token === "string" && token.length > 0)) return null;
  return argv;
}

function assertNotStaticOnlyNativeHighSeverity(claim) {
  if (!O_P4_TRIGGERING_SEVERITIES.has(claim.severity)) return;
  const surfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
  if (surfaceIds.length === 0) return;
  const nativeSurfaces = nativeCodeSurfacesForClaim(claim.target_domain, surfaceIds);
  if (nativeSurfaces.length === 0) return;
  const evidenceRefs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
  const repoCommandRunRefs = evidenceRefs.filter((ref) => ref && ref.kind === "repo_command_run");
  if (repoCommandRunRefs.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "high/critical native-code claims must include at least one evidence_refs[] entry with kind: \"repo_command_run\"; static-only claims (repo_file / source review) cannot stand alone for C/C++/Rust-unsafe/asm at this severity.",
      {
        code: "O_P4_static_only_native_code_high_severity",
        severity: claim.severity,
        native_surfaces: nativeSurfaces,
      },
    );
  }
  const runRows = readRepoCommandRunRecords(claim.target_domain);
  // This proof gate is domain-scoped: it proves the cited repo_command_run row
  // exists and was live. File/surface-level linkage remains part of the
  // evaluator-authored evidence narrative and verifier review.
  const backedRef = repoCommandRunRefs.some((ref) => (
    runRows.some((row) => repoCommandRunRowSatisfiesEvidence(row, ref))
  ));
  if (!backedRef) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "high/critical native-code claims require at least one repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs.jsonl row.",
      {
        code: "O_P4_unbacked_repo_command_run_evidence",
        severity: claim.severity,
        native_surfaces: nativeSurfaces,
        disallowed_repo_command_exit_codes: O_P4_DISALLOWED_REPO_COMMAND_EXIT_CODES,
      },
    );
  }
  // The finding must also declare the machine-runnable PoC recipe
  // (repro_command_argv) so the verifier can re-run the differential reproduction.
  // The single repo_command_run above proves a run happened, but its banner is
  // forgeable; pairing it with a declared argv lets the grade gate later require a
  // verified_pass bound (by command_hash) to exactly this recipe.
  if (!claimReproCommandArgv(claim)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "high/critical native-code claims must declare a repro_command_argv (the PoC token array the reproduction verifier re-runs on the vulnerable and upstream-fix trees). Add the runnable recipe so a differential verified_pass can be minted.",
      {
        code: "O_P4_missing_repro_command_argv",
        severity: claim.severity,
        native_surfaces: nativeSurfaces,
      },
    );
  }
}

// O-P4 grade-time gate: the differential-reproduction proof contract. A finding
// that is FINAL-reportable at high/critical AND lives on a native-code surface
// must be backed by a verified_pass in repro-verified.jsonl whose command_hash
// binds to the finding's declared repro_command_argv. The single repo_command_run
// the claim cited is forgeable (printf a banner); only the verifier's differential
// re-run (crashes the vuln tree, quiet on the upstream-fix tree) mints a
// verified_pass, and that ledger is MCP-write-only (agent-Write-blocked). This is
// what makes the high/critical native-code claim non-fabricatable at report time.
//
// args: { reportableFindingIds: Set<finding_id>, finalSeverities: Map<finding_id, severity> }
// returns: { missing: [{ finding_id, reason }] } — empty when every native
// high/critical reportable finding is backed by a bound verified_pass.
function reproVerifiedGapForNativeReportableFindings(domain, { reportableFindingIds, finalSeverities } = {}) {
  const reportable = reportableFindingIds instanceof Set ? reportableFindingIds : new Set();
  const severities = finalSeverities instanceof Map ? finalSeverities : new Map();
  if (reportable.size === 0) return { missing: [] };

  // Index the frozen claim batch by its embedded finding id so we can resolve each
  // reportable finding's surfaces + declared recipe.
  const claimByFinding = new Map();
  let claims = [];
  try {
    claims = readCandidateClaims(domain);
  } catch {
    claims = [];
  }
  for (const claim of claims) {
    const finding = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload.finding
      : null;
    const findingId = finding && typeof finding === "object" ? finding.id : null;
    if (typeof findingId === "string" && !claimByFinding.has(findingId)) {
      claimByFinding.set(findingId, claim);
    }
  }

  const { readReproVerifiedSummary } = require("../repro-replay-verifier.js");
  let verifiedByFinding = {};
  try {
    verifiedByFinding = readReproVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    verifiedByFinding = {};
  }

  const missing = [];
  for (const findingId of reportable) {
    const severity = severities.get(findingId);
    if (!O_P4_TRIGGERING_SEVERITIES.has(severity)) continue;
    const claim = claimByFinding.get(findingId);
    if (!claim) continue; // unresolvable claim; reachability-stamp gate owns repo-module coverage
    const nativeSurfaces = nativeCodeSurfacesForClaim(domain, claim.surface_ids);
    if (nativeSurfaces.length === 0) continue;
    const argv = claimReproCommandArgv(claim);
    if (!argv) {
      // Should already have been rejected at claim-record; defensive at grade time.
      missing.push({ finding_id: findingId, reason: "no_repro_command_argv" });
      continue;
    }
    const verified = verifiedByFinding[findingId];
    if (!verified) {
      missing.push({ finding_id: findingId, reason: "no_verified_pass" });
      continue;
    }
    if (verified.command_hash !== hashCanonicalJson(argv)) {
      // A verified_pass exists but for a different command than the finding declares.
      missing.push({ finding_id: findingId, reason: "verified_pass_command_hash_mismatch" });
      continue;
    }
  }
  return { missing };
}

// exploitRunSkipReverifies — READ-TIME re-verification of the exploited_safely skip
// (mirrors reverifyFindingDifferentialRecord's read-time idiom + assertExploitedClaimHasProof's
// MAC + surface-bind). The structural skip (live exploit_outcome + a present exploit_run ref)
// is re-armable by a post-freeze runtime-indirection rewrite of claims.jsonl, so the skip is
// honored ONLY when:
//   (1) the FROZEN claim (from the hash-bound, audit-graded claim-freeze.json) for this finding
//       asserts exploit_outcome.outcome === "exploited_safely". A live rewrite cannot satisfy
//       this (the frozen doc is bound by freeze_hash and the file is agent-Write-blocked); and
//   (2) at least one of the FROZEN claim's exploit_run refs re-resolves to a MAC-valid,
//       non-dry-run/non-timed-out offensive-runs row whose MAC-covered surface_id equals the
//       FROZEN claim's single surface (the same strict single-surface bind as the record-time
//       proof gate).
// Only then is the leg an executed binding. Any throw / no MAC-valid backing row / surface
// mismatch / absent-or-non-exploited freeze => skip:false. Runs read-only.
//
// Returns { skip, asserted }: `asserted` is true when the LIVE claim carries an exploit_run
// ref (so the old structural skip WOULD have fired) but re-verification failed — the caller
// surfaces exploit_run_skip_reverification_failed in that case rather than silently falling
// through. A live claim with no exploit_run ref returns asserted:false (it never qualified for
// the structural skip).
function exploitRunSkipReverifies(domain, findingId, liveClaim) {
  const liveRefs = Array.isArray(liveClaim.evidence_refs) ? liveClaim.evidence_refs : [];
  const asserted = liveRefs.some((ref) => ref && ref.kind === "exploit_run");
  try {
    // (1) Class FROM THE FROZEN SNAPSHOT, not live claims.jsonl.
    const { readCurrentClaimFreeze } = require("./claim-freeze.js");
    const freeze = readCurrentClaimFreeze(domain);
    if (!freeze || !Array.isArray(freeze.claims)) return { skip: false, asserted };
    // Resolve the FROZEN claim for this finding — same resolution as the claimByFinding loop
    // (payload.finding.id OR a kind:"finding" evidence_ref).
    let frozenClaim = null;
    for (const claim of freeze.claims) {
      if (!claim || typeof claim !== "object") continue;
      const payloadFinding = claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
        ? claim.payload.finding
        : null;
      const payloadFindingId = payloadFinding && typeof payloadFinding === "object" ? payloadFinding.id : null;
      let matches = typeof payloadFindingId === "string" && payloadFindingId === findingId;
      if (!matches) {
        const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
        matches = refs.some((ref) => ref && ref.kind === "finding" && ref.finding_id === findingId);
      }
      if (matches) { frozenClaim = claim; break; }
    }
    if (!frozenClaim) return { skip: false, asserted };
    if (!frozenClaim.exploit_outcome || frozenClaim.exploit_outcome.outcome !== "exploited_safely") {
      return { skip: false, asserted };
    }
    // The frozen claim must carry exactly one surface (the strict single-surface bind the
    // record-time proof gate enforces); otherwise the surface bind below is not well-defined.
    const frozenSurfaceIds = Array.isArray(frozenClaim.surface_ids) ? frozenClaim.surface_ids : [];
    if (frozenSurfaceIds.length !== 1) return { skip: false, asserted };
    const frozenSurfaceId = String(frozenSurfaceIds[0]).trim();
    if (frozenSurfaceId === "") return { skip: false, asserted };

    // (2) Re-resolve + re-MAC the FROZEN exploit_run refs against the offensive-runs ledger.
    const frozenExploitRunRefs = (Array.isArray(frozenClaim.evidence_refs) ? frozenClaim.evidence_refs : [])
      .filter((ref) => ref && ref.kind === "exploit_run");
    if (frozenExploitRunRefs.length === 0) return { skip: false, asserted };
    const runRows = readOffensiveRunRecords(domain);
    // resolveRowVerifierSafely returns { publicKey, hmacKey:null } for an ed25519-only
    // session (no symmetric key on disk) instead of throwing STATE_CONFLICT into this
    // live read-time re-verification path.
    const verifier = runRows.length > 0 ? resolveRowVerifierSafely(domain) : null;
    // Track whether the ONLY surface-bound, MAC-valid exploit_run row(s) are out-of-band
    // callbacks. Such a row re-verified fine but is not a self-contained binding, so the
    // finding must fall THROUGH to the finding-differential verified_pass requirement —
    // NOT be treated as a post-freeze tamper (reverification_failed). oobOnly signals that.
    let sawValidOobRow = false;
    // oobOnly may be asserted ONLY when EVERY frozen exploit_run ref re-verified to a
    // surface-bound row AND each such row was an OOB callback. A ref that fails to resolve
    // (missing / tampered / bound to a different surface) ALONGSIDE an OOB ref is a PARTIAL
    // post-freeze tamper, not a clean OOB-only finding — it must surface the loud
    // exploit_run_skip_reverification_failed signal, never be masked by oobOnly:true.
    let everyRefResolvedToOob = true;
    for (const ref of frozenExploitRunRefs) {
      const row = runRows.find((candidate) => (
        offensiveRunRowSatisfiesEvidence(candidate, ref, domain, verifier)
      ));
      // The MAC-covered surface_id must equal the frozen claim's single surface (mirror the
      // record-time strict equality so a row produced for surface B cannot back surface A).
      const rowSurfaceId = row && typeof row.surface_id === "string" ? row.surface_id.trim() : "";
      const matchesSurface = !!row && rowSurfaceId !== "" && rowSurfaceId === frozenSurfaceId;
      if (matchesSurface && NON_SELF_CONTAINED_ORACLE_KINDS.has(row.oracle_kind)) {
        // A row carrying a stamped oracle_kind (an out-of-band external callback, or a
        // second-order stored-effect re-read observed at a distinct endpoint) is NOT a
        // self-contained executed binding: a single positive row does not, alone, prove
        // the observed effect is injection-caused rather than ambient (no in-row negative
        // control). It must earn a finding-differential verified_pass binding the positive
        // AND a blocked_by_defense decoy control on the same surface that stayed silent,
        // rather than self-skip. oracle_kind is a MAC-covered sibling, so this read is
        // non-forgeable. (The oobOnly flag below carries this "non-self-contained oracle"
        // disposition through to the caller unchanged for every such kind.)
        sawValidOobRow = true;
        continue;
      }
      if (matchesSurface) {
        // Any OTHER exploit_run row (a tool that directly observed the safe exploit) remains
        // a self-contained binding and skips as before.
        return { skip: true, asserted };
      }
      // The ref did not re-verify to a surface-bound row — this finding is not a clean
      // OOB-only finding; do not let an OOB sibling mask the tamper.
      everyRefResolvedToOob = false;
    }
    return { skip: false, asserted, oobOnly: sawValidOobRow && everyRefResolvedToOob };
  } catch {
    // Unreadable freeze / rotated offensive-runs / absent key => the executed binding is not
    // re-derivable. Fail closed (do not skip).
    return { skip: false, asserted };
  }
}

// Standalone-finding differential proof contract — the report-verdict gate that makes
// a STANDALONE non-oracle finding (auth-bypass-not-via-IDOR, manual IDOR, SSRF,
// business-logic, info-disclosure, races) non-fabricatable at report time. It is the
// symmetric sibling of reproVerifiedGapForNativeReportableFindings: a finding that is
// FINAL-reportable at medium+ AND is NOT already covered by an existing executed
// producer must be backed by a verified_pass in finding-differential-verified.jsonl
// bound to the finding_id. normalizeVerificationResult only type-validates a round
// result; the executed binding is required HERE, at grade time, class-aware, so a
// merely-claimed standalone finding cannot be graded SUBMIT (MINT != CONFIRM).
//
// Findings already covered by an existing executed producer are SKIPPED so they verify
// IDENTICALLY (the EXISTING-PRODUCER REGRESSION invariant):
//   * native-code surfaces AT HIGH/CRITICAL -> owned by the O-P4 repro gate (above). A
//     MEDIUM native finding has no O-P4 obligation (O_P4_TRIGGERING_SEVERITIES is
//     high/critical only), so it must satisfy the standalone differential here — it is
//     NOT short-circuited by the native skip.
//   * smart_contract surfaces WITH an FV invariant-verified verified_pass -> owned by
//     bob_verify_invariant_differential
//   * a freeze claim that carries an exploit_run-backed exploited_safely outcome whose
//     cited offensive-runs row RE-MAC-VERIFIES on the frozen claim's surface -> its
//     offensive-runs row is already a live re-verified executed binding
// A residual standalone finding with no constructible executed flip caps to advisory
// (excluded from the reportable set) — the RANK != BOUND outcome, applied per finding,
// never a class bound.
//
// args: { reportableFindingIds: Set<finding_id>, finalSeverities: Map<finding_id, severity> }
// returns: { missing: [{ finding_id, reason }] } — empty when every residual standalone
// medium+ reportable finding is backed by a bound verified_pass.
function findingDifferentialGapForStandaloneReportableFindings(domain, { reportableFindingIds, finalSeverities } = {}) {
  const reportable = reportableFindingIds instanceof Set ? reportableFindingIds : new Set();
  const severities = finalSeverities instanceof Map ? finalSeverities : new Map();
  if (reportable.size === 0) return { missing: [] };

  // Resolve each reportable finding's claim so we can read its surfaces + outcome.
  const claimByFinding = new Map();
  let claims = [];
  try {
    claims = readCandidateClaims(domain);
  } catch {
    claims = [];
  }
  for (const claim of claims) {
    const finding = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload.finding
      : null;
    const findingId = finding && typeof finding === "object" ? finding.id : null;
    if (typeof findingId === "string" && !claimByFinding.has(findingId)) {
      claimByFinding.set(findingId, claim);
    }
    // The dual-write tool path may carry the finding id on an evidence_ref rather than
    // payload.finding (recordFindingViaTool/seedFinalVerificationFromFrozen shape), so
    // also index by a top-level finding evidence_ref id when the payload is absent.
    if (!findingId) {
      const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
      for (const ref of refs) {
        if (ref && ref.kind === "finding" && typeof ref.finding_id === "string" && !claimByFinding.has(ref.finding_id)) {
          claimByFinding.set(ref.finding_id, claim);
        }
      }
    }
  }

  const { readFindingDifferentialVerifiedSummary } = require("../differential/index.js");
  let verifiedByFinding = {};
  try {
    verifiedByFinding = readFindingDifferentialVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    verifiedByFinding = {};
  }

  const { readInvariantVerifiedSummary } = require("../invariant-runner.js");
  let invariantVerifiedByFinding = {};
  try {
    invariantVerifiedByFinding = readInvariantVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    invariantVerifiedByFinding = {};
  }

  // A native finding whose differential reproduction already executed + flipped carries an
  // executed arm (the O-P4 repro verified_pass) regardless of its final severity, so it is
  // NOT routed to the standalone arm even at medium — it is already armed.
  const { readReproVerifiedSummary } = require("../repro-replay-verifier.js");
  let reproVerifiedByFinding = {};
  try {
    reproVerifiedByFinding = readReproVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    reproVerifiedByFinding = {};
  }

  const missing = [];
  for (const findingId of reportable) {
    const severity = severities.get(findingId);
    if (!MEDIUM_OR_HIGHER_SEVERITIES.has(severity)) continue;
    const claim = claimByFinding.get(findingId);
    if (!claim) continue; // unresolvable claim; other gates own coverage.

    // SKIP: native-code surfaces are owned by the O-P4 repro gate (verify identically)
    // at the O-P4 severities (high/critical), OR when the finding ALREADY carries an
    // executed repro verified_pass (any severity — its differential reproduction is the
    // executed arm). A MEDIUM native finding that LACKS a repro arm carries no O-P4
    // obligation and no executed binding, so it must NOT short-circuit here — it falls
    // through to the residual standalone arm and must carry a finding-differential
    // verified_pass (or be lowered below medium / dropped).
    const nativeSurfaces = nativeCodeSurfacesForClaim(domain, claim.surface_ids);
    if (nativeSurfaces.length > 0
      && (O_P4_TRIGGERING_SEVERITIES.has(severity) || reproVerifiedByFinding[findingId])) {
      continue;
    }

    const surfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
    const surfaceInfo = claimSurfaceLanguageMap(domain, surfaceIds);
    const isSmartContract = surfaceIds.some((id) => {
      const info = surfaceInfo.get(id);
      return info && info.kind === "smart_contract";
    });
    // SKIP: a smart_contract finding WITH an FV invariant-verified verified_pass is owned
    // by bob_verify_invariant_differential (verify identically). An SC finding WITHOUT one
    // falls through to the standalone arm (it must construct an on-chain executed flip OR
    // cap to advisory — the APPENDED-node outcome, consistent with the evaluating.md SC
    // surface_status rule).
    if (isSmartContract && invariantVerifiedByFinding[findingId]) continue;

    // SKIP: an exploit_run-backed exploited_safely claim is already an executed binding
    // — but RE-VERIFY it at read time off the FROZEN claim class + a re-MAC'd backing
    // row, not the live claims.jsonl + a merely-structural ref (which a post-freeze
    // runtime-indirection rewrite could re-arm with no re-proof). The skip is honored
    // ONLY when the frozen claim asserts exploited_safely AND a cited exploit_run row
    // still MAC-verifies on the frozen claim's single surface.
    if (claim.exploit_outcome && claim.exploit_outcome.outcome === "exploited_safely") {
      const reverify = exploitRunSkipReverifies(domain, findingId, claim);
      if (reverify.skip) continue;
      if (reverify.asserted && !reverify.oobOnly) {
        // The LIVE claim asserts exploited_safely (so the structural skip would have
        // fired) but the frozen-class + re-MAC re-verification no longer holds. Surface
        // a legible failure instead of silently falling through.
        missing.push({ finding_id: findingId, reason: "exploit_run_skip_reverification_failed" });
        continue;
      }
      // else: either the live claim asserts exploited_safely with no exploit_run ref at
      // all, OR the only re-verified exploit_run row is an out-of-band callback (oobOnly)
      // — a received callback is not a self-contained binding. Both fall THROUGH to the
      // residual standalone arm, where the OOB finding must earn a finding-differential
      // verified_pass (a positive callback flipping against a blocked_by_defense control)
      // rather than report on a single uncontrolled callback.
    }

    // RESIDUAL standalone class: require a verified_pass bound to this finding_id.
    const verified = verifiedByFinding[findingId];
    if (!verified) {
      missing.push({ finding_id: findingId, reason: "no_finding_differential_verified_pass" });
      continue;
    }
    // (B1.1) SURFACE BIND — the verdict's bound surface (re-derived from the MAC-covered
    // positive row by readFindingDifferentialVerifiedSummary, NOT the verdict record's
    // self-hashed field) must equal the claim's single finding surface. A verified_pass
    // minted on surface B cannot back a finding on surface A. Symmetric to the repro
    // command_hash bind (:1045) and the exploit-proof surface bind (:1311). The strict
    // single-surface requirement (claimSurfaceId==="" when length!==1) fail-closes a
    // surface-set-padded claim, mirroring exploit-proof rule (1).
    const claimSurfaceId = surfaceIds.length === 1 ? String(surfaceIds[0]).trim() : "";
    const verifiedSurfaceId = typeof verified.surface_id === "string" ? verified.surface_id.trim() : "";
    if (claimSurfaceId === "" || verifiedSurfaceId === "" || verifiedSurfaceId !== claimSurfaceId) {
      missing.push({ finding_id: findingId, reason: "finding_differential_surface_mismatch" });
      continue;
    }
    // (B1.2) DEMONSTRATED-SEVERITY CEILING — the executed flip's demonstrated severity
    // (from the re-resolved MAC-covered positive row) must be >= the finding's final
    // reportable severity, so a low/benign flip cannot back a higher-severity finding.
    // exploitSeverityRank fail-closes unknown severities to rank 0; SEVERITY_VALUES is
    // descending so a higher rank is more severe — identical to the exploit-proof ceiling
    // (:1340). `severity` is finalSeverities.get(findingId), already in hand.
    if (exploitSeverityRank(verified.demonstrated_severity) < exploitSeverityRank(severity)) {
      missing.push({ finding_id: findingId, reason: "finding_differential_severity_below_finding" });
      continue;
    }
  }
  return { missing };
}

// Cross-stack composition-path proof contract — the report-verdict gate that
// makes a reportable CROSS-STACK finding (one whose proof IS a composition path
// spanning >=2 stacks) non-fabricatable. It is a sibling of
// findingDifferentialGapForStandaloneReportableFindings, extended from a SINGLE
// surface to a cross-SURFACE path: a finding that is final-reportable at medium+
// AND whose claim is cross-stack must carry a composition path_hash that is a
// member of the audit-graded composition-verified.jsonl verified_path_hashes[]
// (re-resolved at read time — bind rows RE-MAC-verified, the flip RE-adjudicated).
//
// The cross-stack PREDICATE (precise, additive, never over-fires): the claim's
// surface_ids span >=2 DISTINCT stacks (web vs smart_contract vs code_module,
// resolved via claimSurfaceLanguageMap) OR the claim carries a composition_path
// evidence_ref with a path_hash. A SINGLE-surface or same-stack finding with no
// composition_path ref is NOT cross-stack and is left ENTIRELY to the existing
// finding-differential gate — no double-coverage, no regression.
//
// SKIP (verify identically): a cross-stack finding that ALREADY carries a bound
// cross-stack verified_pass (its declared path_hash is in verified_path_hashes[])
// is armed and skipped. Native-repro / FV-invariant / exploit_run-backed findings
// are single-surface arms and never reach the cross-stack branch (they fail the
// distinct-stacks test and carry no composition_path ref).
//
// CAP NOT DROP (RANK != BOUND): a residual cross-stack reportable medium+ finding
// with no bound flip caps to advisory (excluded from the reportable set by
// grade-verdict-store), applied PER FINDING, never a class bound, never silently
// dropped — the seam is surfaced as advisory.
//
// args: { reportableFindingIds: Set<finding_id>, finalSeverities: Map<finding_id, severity> }
// returns: { missing: [{ finding_id, reason }] }
//   reason "cross_stack_path_unbound"      -> no composition_path link on the claim
//   reason "cross_stack_path_not_verified" -> path_hash present but not a member
function crossStackPathGapForReportableFindings(domain, { reportableFindingIds, finalSeverities } = {}) {
  const reportable = reportableFindingIds instanceof Set ? reportableFindingIds : new Set();
  const severities = finalSeverities instanceof Map ? finalSeverities : new Map();
  if (reportable.size === 0) return { missing: [] };

  // Resolve each reportable finding's claim — same dual-index as the
  // finding-differential gate (payload.finding.id, else a finding evidence_ref).
  const claimByFinding = new Map();
  let claims = [];
  try {
    claims = readCandidateClaims(domain);
  } catch {
    claims = [];
  }
  for (const claim of claims) {
    const finding = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload.finding
      : null;
    const findingId = finding && typeof finding === "object" ? finding.id : null;
    if (typeof findingId === "string" && !claimByFinding.has(findingId)) {
      claimByFinding.set(findingId, claim);
    }
    if (!findingId) {
      const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
      for (const ref of refs) {
        if (ref && ref.kind === "finding" && typeof ref.finding_id === "string" && !claimByFinding.has(ref.finding_id)) {
          claimByFinding.set(ref.finding_id, claim);
        }
      }
    }
  }

  // The audit-graded set of bound CROSS-STACK path_hashes (bind rows re-resolved, gated on
  // has_bind_leaf && is_cross_stack — HIGH-3), plus the per-path bound surface_refs used to
  // reconcile the bound path against THIS claim's surfaces (HIGH-2). A guard-only or same-
  // family verified_pass is NOT in this set, so it can never satisfy a cross-stack gate.
  const { readCompositionVerifiedSummary } = require("../differential/index.js");
  let verifiedPathHashes = new Set();
  let crossStackSurfaceRefsByHash = {};
  try {
    const summary = readCompositionVerifiedSummary(domain);
    if (Array.isArray(summary.verified_cross_stack_path_hashes)) {
      verifiedPathHashes = new Set(summary.verified_cross_stack_path_hashes);
    }
    if (summary.verified_cross_stack_path_surface_refs && typeof summary.verified_cross_stack_path_surface_refs === "object") {
      crossStackSurfaceRefsByHash = summary.verified_cross_stack_path_surface_refs;
    }
  } catch {
    verifiedPathHashes = new Set();
    crossStackSurfaceRefsByHash = {};
  }

  const missing = [];
  for (const findingId of reportable) {
    const severity = severities.get(findingId);
    if (!MEDIUM_OR_HIGHER_SEVERITIES.has(severity)) continue;
    const claim = claimByFinding.get(findingId);
    if (!claim) continue; // unresolvable claim; other gates own coverage.

    const surfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
    const surfaceInfo = claimSurfaceLanguageMap(domain, surfaceIds);
    const stacks = new Set();
    for (const id of surfaceIds) {
      const info = surfaceInfo.get(id);
      const kind = info && typeof info.kind === "string" ? info.kind.trim() : "";
      if (kind === "web" || kind === "smart_contract" || kind === "code_module") {
        stacks.add(kind);
      }
    }
    const evidenceRefs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    const compositionRef = evidenceRefs.find(
      (ref) => ref && ref.kind === "composition_path" && typeof ref.path_hash === "string" && ref.path_hash,
    );

    // CROSS-STACK predicate: >=2 distinct stacks OR an explicit composition_path
    // ref. A single-surface / same-stack finding with no composition_path ref is
    // NOT cross-stack — left to the existing finding-differential gate.
    const isCrossStack = stacks.size >= 2 || compositionRef != null;
    if (!isCrossStack) continue;

    // No path_hash link on the claim -> unbound (reasoning-only proof).
    if (compositionRef == null) {
      missing.push({ finding_id: findingId, reason: "cross_stack_path_unbound" });
      continue;
    }
    // path_hash present but NOT a member of the cross-stack verified set -> binding
    // mismatch (also catches a guard-only / same-family verified_pass cited as cross-stack).
    if (!verifiedPathHashes.has(compositionRef.path_hash)) {
      missing.push({ finding_id: findingId, reason: "cross_stack_path_not_verified" });
      continue;
    }
    // HIGH-2 — SURFACE RECONCILIATION: the bound verified_pass must be bound to THIS
    // finding's surfaces, not merely be a member of the set. A verified_pass minted for
    // finding/surfaces X must not arm a cross-stack gate on a DIFFERENT finding Y just
    // because Y's claim declares X's path_hash. The bound path's surface_refs are
    // ["invariant:<finding>:<contract>", "offensive:<surface_id>"]; require either the
    // bound offensive surface_id to be one of THIS claim's surface_ids, OR the bound
    // invariant finding_id to equal THIS finding's id.
    const boundSurfaceRefs = Array.isArray(crossStackSurfaceRefsByHash[compositionRef.path_hash])
      ? crossStackSurfaceRefsByHash[compositionRef.path_hash]
      : [];
    const claimSurfaceSet = new Set(surfaceIds);
    let reconciled = false;
    for (const ref of boundSurfaceRefs) {
      if (typeof ref !== "string") continue;
      if (ref.startsWith("offensive:")) {
        if (claimSurfaceSet.has(ref.slice("offensive:".length))) { reconciled = true; break; }
      } else if (ref.startsWith("invariant:")) {
        // invariant:<finding>:<contract> — the bound finding id is the first segment.
        const rest = ref.slice("invariant:".length);
        const boundFinding = rest.indexOf(":") >= 0 ? rest.slice(0, rest.indexOf(":")) : rest;
        if (boundFinding === findingId) { reconciled = true; break; }
      }
    }
    // FAIL CLOSED on absent surface_refs. A cross-stack verified_pass ALWAYS carries
    // bound surface_refs: adjudicateCrossStackFlip gates verified_pass on a PROVABLE
    // finding-scope, which requires a non-null cause surfaceRef ("offensive:<id>") that
    // is always pushed into surface_refs — so a cross-stack member hash with an empty
    // surface_refs union cannot arise from the producer. An empty set here is therefore
    // an anomaly (a corrupted/legacy summary or a future producer regression), never a
    // benign legacy row. Refuse it rather than fall back to membership alone — matching
    // the D1comp completion-depth credit, which gives no credit on empty surface_refs.
    // Membership-without-reconciliation would let a verified_pass minted for
    // finding/surfaces X arm a cross-stack gate on a DIFFERENT finding Y that merely
    // declares X's path_hash (the HIGH-2 reuse the reconciliation closes).
    if (boundSurfaceRefs.length === 0) {
      missing.push({ finding_id: findingId, reason: "cross_stack_path_surface_refs_absent" });
      continue;
    }
    if (!reconciled) {
      missing.push({ finding_id: findingId, reason: "cross_stack_path_surface_mismatch" });
      continue;
    }
    // else: bound cross-stack verified_pass exists AND reconciles to this finding -> armed.
  }
  return { missing };
}

function assertExploitedClaimHasProof(claim, { existingClaims = [] } = {}) {
  const evidenceRefs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
  const exploitRunRefs = evidenceRefs.filter((ref) => ref && ref.kind === "exploit_run");
  // PR #108 review (Codex round-6 P1): exploit_run refs are proof-of-exploitation
  // evidence and may ONLY ride on a claim whose top-level exploit_outcome asserts
  // exploited_safely. Without this, a claim that omits exploit_outcome (or sets a
  // blocked_* outcome) could smuggle a self-authored exploit_run ref into
  // claims.jsonl/the freeze without ever reaching the MAC-backed proof gate below.
  if (claim.exploit_outcome?.outcome !== "exploited_safely") {
    if (exploitRunRefs.length > 0) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "exploit_run evidence_refs are only allowed on claims whose exploit_outcome.outcome is \"exploited_safely\".",
        {
          code: "exploit_run_ref_without_exploited_outcome",
          outcome: claim.exploit_outcome?.outcome ?? null,
        },
      );
    }
    return;
  }
  if (exploitRunRefs.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claims must include at least one evidence_refs[] entry with kind: \"exploit_run\".",
      {
        code: "exploit_proof_missing_exploit_run_evidence",
        outcome: claim.exploit_outcome.outcome,
      },
    );
  }
  const runRows = readOffensiveRunRecords(claim.target_domain);
  // Resolve the verifier bundle (public key + optional symmetric key) only when there
  // are rows to verify. resolveRowVerifierSafely never throws on a missing symmetric
  // key (an ed25519-only session), so the legitimate "no symmetric key" case cannot
  // surface STATE_CONFLICT instead of the intended INVALID_ARGUMENTS proof gate; the
  // "no rows yet" case stays null so an empty ledger reports
  // exploit_proof_unbacked_exploit_run_evidence rather than a missing-key throw.
  const verifier = runRows.length > 0 ? resolveRowVerifierSafely(claim.target_domain) : null;
  // PR #108 review (Codex P2): require EVERY exploit_run ref to be backed by an
  // in-scope, non-dry-run ledger row — not just one. `some()` would let an extra
  // unbacked or out-of-scope exploit_run ref ride along into claims.jsonl/the
  // freeze on the coattails of one valid ref, smuggling off-scope offensive
  // evidence. (Stricter than the O-P4 repo_command_run gate by design: offensive
  // target URLs are scope-sensitive in a way native-code run ids are not.)
  const backedRows = [];
  for (const ref of exploitRunRefs) {
    const row = runRows.find((candidate) => (
      offensiveRunRowSatisfiesEvidence(candidate, ref, claim.target_domain, verifier)
    ));
    if (!row) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "exploited_safely claims require every exploit_run evidence_ref to be backed by a matching in-scope, non-dry-run offensive-runs.jsonl row.",
        {
          code: "exploit_proof_unbacked_exploit_run_evidence",
          outcome: claim.exploit_outcome.outcome,
          disallowed_offensive_run_exit_codes: OFFENSIVE_RUN_DISALLOWED_EXIT_CODES,
        },
      );
    }
    backedRows.push(row);
  }

  const claimRunIds = new Set(exploitRunRefs.map((ref) => ref.run_id));
  for (const existing of existingClaims) {
    if (!existing || existing.claim_id === claim.claim_id) continue;
    const existingRefs = Array.isArray(existing.evidence_refs) ? existing.evidence_refs : [];
    for (const ref of existingRefs) {
      if (!ref || ref.kind !== "exploit_run") continue;
      if (!claimRunIds.has(ref.run_id)) continue;
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "exploit_run run_id is already consumed by a previously recorded claim; run a fresh confirmer for each finding.",
        {
          code: "exploit_run_run_id_already_consumed",
          run_id: ref.run_id,
          existing_claim_id: existing.claim_id || null,
        },
      );
    }
  }

  // Surface binding (issue #111): cross-finding severity-laundering gate.
  // Each backed row is already content-bound to its ref (offensiveRunRowSatisfiesEvidence)
  // and run_id-single-use (above) makes each row back at most ONE claim. ADD: the
  // row's producer-stamped, MAC-covered surface_id must equal the claim's own
  // finding surface, so a higher-severity row produced for surface B can never raise
  // a claim for surface A. claim.surface_ids is set by record-candidate-claim.js
  // ([finding.surface_id]) and arrives here NORMALIZED (trimmed/deduped/order-preserved
  // by normalizeOptionalTextArray) because normalizeCandidateClaim runs before this
  // assert (appendCandidateClaim). Precedent: assertNotStaticOnlyNativeHighSeverity
  // reads claim.surface_ids above.
  //
  // INTEGRITY, NOT CORRECTNESS (same boundary as #108): the MAC proves the producer
  // STAMPED this surface_id and this demonstrated_severity; it does NOT prove the
  // producer ATTACKED that surface or that the impact tier is right. A trusted producer
  // that attacks endpoint B but stamps surface_id=A (convergent mis-stamp), or stamps
  // demonstrated_severity=critical on a low read (same-surface inflation), passes here.
  // Those are PRODUCER obligations (the signed-row producer PR's AC-2 endpoint==surface,
  // AC-3 server-derived severity), not closeable in this string-binding gate. AXIS: this
  // compares only the opaque surface_id; it does not assert surface kind/axis. A single
  // web-only producer is planned; add an axis guard if a non-web offensive-row producer
  // ever lands in a session that also carries smart_contract/code_module surfaces.
  // The strict single-surface rule is stricter than issue #111's literal "membership"
  // wording but is identical for every producer today (claims carry one surface) and
  // additionally blocks surface-set padding; see docs/ISSUE_111_SURFACE_BINDING_PLAN.md.
  const claimSurfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
  // (1) STRICT single-surface. Rejects surface-set padding (surface_ids=[A,B] to satisfy
  //     membership for a B-row) AND fail-closes the non-wave null-surface path
  //     (a claim recorded with no surface normalizes to an empty array).
  if (claimSurfaceIds.length !== 1) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claims that cite exploit_run proof must carry exactly one surface_id so each cited offensive-run row binds to a single finding/surface.",
      {
        code: "exploit_proof_claim_surface_ambiguous",
        surface_id_count: claimSurfaceIds.length,
      },
    );
  }
  // Structural, not implicit (brutalist r1): normalizeOptionalTextArray already
  // trimmed and dropped empties (so the length===1 check above guarantees a
  // non-empty entry), but trim here too so the equality below does not silently
  // depend on that upstream invariant — symmetric with the row-side trim and the
  // verify mirror.
  const claimSurfaceId = claimSurfaceIds[0].trim();
  for (const row of backedRows) {
    // (2) FAIL-CLOSED on a surfaceless row. row.surface_id is MAC-covered, so a producer
    //     that forgets to stamp it is a loud reject, not silent laundering. Trim before
    //     compare so the gate matches the trimmed claim surface; the producer MUST stamp
    //     the identical, same-case routed surface id.
    const rowSurfaceId = typeof row.surface_id === "string" ? row.surface_id.trim() : "";
    if (rowSurfaceId === "") {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "exploited_safely claims require every cited offensive-runs row to carry a non-empty surface_id (the surface the safe exploit ran against).",
        {
          code: "exploit_proof_row_surface_missing",
          run_id: row.run_id || null,
        },
      );
    }
    // (3) STRICT EQUALITY — the cross-finding severity-laundering gate.
    if (rowSurfaceId !== claimSurfaceId) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "exploited_safely claim cites an offensive-runs row produced for a different surface; a cited row's surface_id must equal the claim's surface (cross-finding severity laundering is rejected).",
        {
          code: "exploit_proof_row_surface_mismatch",
          run_id: row.run_id || null,
          row_surface_id: rowSurfaceId,
          claim_surface_id: claimSurfaceId,
        },
      );
    }
  }
  const maxDemonstratedRank = backedRows.reduce((maxRank, row) => (
    Math.max(maxRank, exploitSeverityRank(row.demonstrated_severity))
  ), 0);
  const claimRank = exploitSeverityRank(claim.severity);
  // Fail closed on an unrecognized severity (rank 0): otherwise the ceiling
  // comparison below would pass unconditionally (0 > N is always false).
  if (claimRank === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claim severity is not a recognized severity tier.",
      {
        code: "exploit_proof_unrecognized_severity",
        claim_severity: claim.severity,
      },
    );
  }
  if (claimRank > maxDemonstratedRank) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claim severity exceeds the maximum demonstrated_severity of its cited offensive run rows.",
      {
        code: "exploit_proof_severity_exceeds_demonstrated",
        claim_severity: claim.severity,
        max_demonstrated_rank: maxDemonstratedRank,
      },
    );
  }

  // Per-tool demonstrated_severity ceiling (PR-A). The claim-vs-row ceiling above bounds
  // claim.severity by what the rows demonstrated; this bounds what any single row is even ALLOWED
  // to demonstrate, per the tool that produced it. FAIL-CLOSED to "info" for unknown/forged tool_ids.
  for (const row of backedRows) {
    const toolCeil = OFFENSIVE_TOOL_DEMONSTRATED_CEILING[row.tool_id] ?? "info";
    if (exploitSeverityRank(row.demonstrated_severity) > exploitSeverityRank(toolCeil)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "offensive-runs row demonstrates a severity above the ceiling permitted for the tool that produced it.",
        {
          code: "exploit_proof_tool_demonstrated_ceiling_exceeded",
          run_id: row.run_id || null,
          tool_id: row.tool_id || null,
          demonstrated_severity: row.demonstrated_severity,
          tool_ceiling: toolCeil,
        },
      );
    }
  }
}

function appendCandidateClaim(input, options = {}) {
  const claim = normalizeCandidateClaim(input, options);
  return withSessionLock(claim.target_domain, () => {
    // O-P4 and exploit-proof validators run before the JSONL append so a
    // rejected claim leaves claims.jsonl untouched. The exploit gate reads
    // existing claims while this same session lock is held, making run_id
    // single-use a real row->claim binding rather than a best-effort scan.
    const existingClaims = readCandidateClaims(claim.target_domain);
    assertNotStaticOnlyNativeHighSeverity(claim);
    assertExploitedClaimHasProof(claim, { existingClaims });
    appendJsonlLine(claimsJsonlPath(claim.target_domain), claim, {
      maxRecords: options.maxRecords == null ? CLAIMS_MAX_RECORDS : options.maxRecords,
    });
    return claim;
  });
}

function readCandidateClaims(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    claimsJsonlPath(domain),
    "claims.jsonl",
    (record) => normalizeCandidateClaim(record, { targetDomain: domain, now: null }),
  );
}

// Completion-depth contract — a surface marked surface_status:complete must bind to
// REAL work, not a bare claim. Acceptable bases are (a) an executed differential: a
// re-derived verified_pass for one of the surface's findings, read back through the
// finding-differential / repro / invariant summaries (each re-resolves the MAC-covered
// SOURCE rows and re-adjudicates the flip at read time, so a hand-written verified_*
// line whose source rows do not MAC-resolve never counts), OR (b) documented honest
// exhaustion: at least one coverage row for the surface, OR a substantive bypass_attempt.
// A surface closed complete on finding EXISTENCE alone — never executed, no probing,
// no bypass — is the surface-completion masquerade: the hunter-depth "I claimed a bug
// so the surface is done", whose harm is false exhaustion feeding coverage_closure and
// the report's "surface tested" prose. This is the GRADE-time home (post-verification,
// where the verifier-owned verified rows already exist); an evaluation-time gate would
// deadlock because evaluators cannot mint verified rows. Cross-stack composition proofs
// are path-keyed (no verified_by_finding); a re-verified cross-stack flip is credited to
// its offensive CAUSE surface via verified_cross_stack_path_surface_refs (re-derived from
// MAC-resolved bind leaves), so such a surface clears on the executed differential even
// without a coverage row. Returns
// { missing: [{ surface_id, finding_id, reason }] }; the grade door fails closed on a
// non-empty missing[].
//
// ACCESS-CONTROL CWE SET (id-bearing independence): an id-bearing crown surface's obligation
// is a CROSS-TENANT object-authorization test, so its clearing EXECUTED finding must be an
// access-control class. An executed SSRF/XSS/injection on the same surface proves impact but
// NOT that the object-level authorization was ever probed, so it does not discharge the crown
// obligation (the auth-differential FLIP or a re-verified cross-stack composition still does).
// bug_class is not persisted on the finding record; the CANONICAL CWE is (catalog-canonical on
// read-back), so the class is resolved from the CWE alone. Only catalog CWEs reach here — a
// novel/non-catalog CWE degrades to null on read-back — so an unrecognized class holds the
// surface as an honest partial, the SAFE (fail-toward-HOLD) direction.
const ID_BEARING_ACCESS_CONTROL_CWES = new Set([
  "CWE-639", // Authorization Bypass Through User-Controlled Key (IDOR)
  "CWE-284", // Improper Access Control
  "CWE-285", // Improper Authorization
  "CWE-862", // Missing Authorization
  "CWE-863", // Incorrect Authorization
]);

function completionDepthGapForCompleteSurfaces(domain, options = {}) {
  const packExecutedFindingIds = options.packExecutedFindingIds instanceof Set
    ? options.packExecutedFindingIds
    : new Set();
  const { buildWaveHandoffsDocument, listWaveAssignmentNumbers } = require("../waves/wave-handoff-store.js");
  // The handoff doc is the SOLE enumerator of which surfaces are 'complete'. Both reads that can
  // throw fail CLOSED (a single fail-open catch over both was the brutalist's HIGH finding — it
  // disabled the whole gate on any throw); the two are SEPARATE only so their distinct ERROR
  // states stay distinct, never to fail one of them open:
  //   - listWaveAssignmentNumbers RETURNS [] for a missing session dir / no waves (it does not
  //     throw): nothing is 'complete', so the gate is vacuous. buildWaveHandoffsDocument reads
  //     claims at the TOP, so it must NOT be called when there are no waves to gate (a
  //     corrupt-claims session with no waves still has nothing marked complete).
  //   - listWaveAssignmentNumbers THROWS only when an EXISTING session dir cannot be enumerated
  //     (readdir FS error / the dir was replaced) — we cannot tell whether complete surfaces are
  //     hidden behind it, so fail CLOSED (NOT the legitimate-empty case, which is the returned []
  //     above). A readdir failure on a populated session must not silently disable the gate.
  //   - Wave assignments EXIST but the handoff doc is UNREADABLE (corrupt JSONL line, torn write,
  //     transient FS error) → we cannot determine which surfaces are 'complete'. Fail CLOSED too:
  //     returning { missing: [] } would silently disable the gate so EVERY complete surface clears
  //     (the masquerade this gate closes) and dead-code the inner fail-closed arms below. Mirrors
  //     the evaluation-time finalize gate that hard-fails on this.
  let waveNumbers;
  try {
    waveNumbers = listWaveAssignmentNumbers(domain);
  } catch {
    return { missing: [{ surface_id: null, finding_id: null, reason: "completion_state_unreadable" }] };
  }
  if (!Array.isArray(waveNumbers) || waveNumbers.length === 0) return { missing: [] };
  let doc;
  try {
    doc = buildWaveHandoffsDocument(domain, waveNumbers);
  } catch {
    return { missing: [{ surface_id: null, finding_id: null, reason: "completion_state_unreadable" }] };
  }
  const completeHandoffs = (doc && Array.isArray(doc.handoffs) ? doc.handoffs : [])
    .filter((handoff) => handoff && handoff.surface_status === "complete" && handoff.surface_id);
  if (completeHandoffs.length === 0) return { missing: [] };

  // (a-honest-exhaustion) coverage rows per surface
  const coverageBySurface = new Map();
  try {
    const { readCoverageRecordsFromJsonl } = require("../frontier/coverage.js");
    for (const record of readCoverageRecordsFromJsonl(domain)) {
      if (!record || !record.surface_id) continue;
      coverageBySurface.set(record.surface_id, (coverageBySurface.get(record.surface_id) || 0) + 1);
    }
  } catch { /* no coverage ledger — surfaces fall to the executed/bypass arms */ }

  // finding_ids per surface (from the recorded claims), plus the subset whose CANONICAL CWE is
  // an access-control class. An id-bearing crown clears on an EXECUTED finding only when that
  // finding is access-control (the cross-tenant obligation); a same-surface executed SSRF/XSS
  // is impact without the object-authorization test, so it never clears the crown.
  const findingsBySurface = new Map();
  const accessControlFindingIds = new Set();
  try {
    const { findingPayloadsFromClaims } = require("./candidate-claim-recorder.js");
    for (const finding of findingPayloadsFromClaims(domain)) {
      if (!finding || !finding.surface_id || !finding.id) continue;
      if (!findingsBySurface.has(finding.surface_id)) findingsBySurface.set(finding.surface_id, []);
      findingsBySurface.get(finding.surface_id).push(finding.id);
      if (typeof finding.cwe === "string" && ID_BEARING_ACCESS_CONTROL_CWES.has(finding.cwe)) {
        accessControlFindingIds.add(finding.id);
      }
    }
  } catch { /* unreadable claims — surfaces fall to the coverage/bypass arms */ }

  // (a-executed) union of re-derived verified_pass by finding across the executed ledgers.
  // composition-verified is path-keyed (verified_by_finding absent → contributes {}).
  const executedFindings = new Set();
  // Capability-pack grade adapters can contribute execution only through this
  // explicit server-derived set.  For Plane-PH the adapter reaches this point
  // only after re-resolving the production verdict and durable campaign
  // closure, so a physical surface does not need a fake web differential row
  // merely to satisfy the shared completion-depth gate.
  for (const findingId of packExecutedFindingIds) executedFindings.add(findingId);
  const verifiedSummaryReaders = [
    () => require("../differential/index.js").readFindingDifferentialVerifiedSummary(domain),
    () => require("../repro-replay-verifier.js").readReproVerifiedSummary(domain),
    () => require("../invariant-runner.js").readInvariantVerifiedSummary(domain),
  ];
  for (const readSummary of verifiedSummaryReaders) {
    try {
      const byFinding = readSummary().verified_by_finding || {};
      for (const findingId of Object.keys(byFinding)) {
        if (byFinding[findingId]) executedFindings.add(findingId);
      }
    } catch { /* missing/unreadable ledger contributes nothing to the executed set */ }
  }

  // (a-executed, cross-stack arm) composition verified_pass rows are PATH-keyed, not
  // finding-keyed, so they never appear in verified_by_finding above. But a re-verified
  // CROSS-STACK composition flip binds its offensive CAUSE surface_ids, and that binding is
  // re-derived at read time: verified_cross_stack_path_surface_refs is built ONLY from rows
  // whose bind leaves MAC-resolve and re-adjudicate (reverifyCrossStackLeaf — a failing leaf
  // excludes the whole row), and the offensive: prefix originates from the MAC-verified
  // offensive row's surface_id, never a hand-written field. So an offensive surface that
  // participated in a re-verified cross-stack differential has an executed-differential
  // basis for completion even with no coverage row of its own. (The effect SC arm carries no
  // surface_id ref, so a complete SC effect surface still requires its own basis — the
  // conservative, fail-closed direction.)
  const compositionExecutedSurfaces = new Set();
  try {
    const { readCompositionVerifiedSummary } = require("../differential/index.js");
    const surfaceRefsByHash = readCompositionVerifiedSummary(domain).verified_cross_stack_path_surface_refs || {};
    for (const refs of Object.values(surfaceRefsByHash)) {
      if (!Array.isArray(refs)) continue;
      for (const ref of refs) {
        if (typeof ref === "string" && ref.startsWith("offensive:")) {
          compositionExecutedSurfaces.add(ref.slice("offensive:".length));
        }
      }
    }
  } catch { /* missing/unreadable composition-verified contributes nothing */ }

  const { bypassAttemptHasSubstance } = require("../waves/wave-handoff-contracts.js");

  // Aggregate evidence per complete surface — a surface may be re-tested across waves,
  // and ANY handoff supplying a substantive bypass clears it.
  const surfaceBypass = new Map();
  for (const handoff of completeHandoffs) {
    const attempts = Array.isArray(handoff.bypass_attempts) ? handoff.bypass_attempts : [];
    if (attempts.some(bypassAttemptHasSubstance)) surfaceBypass.set(handoff.surface_id, true);
    else if (!surfaceBypass.has(handoff.surface_id)) surfaceBypass.set(handoff.surface_id, false);
  }

  // Both the id-bearing FLAG and the id-bearing ENDPOINT set come from the MCP-owned route
  // (surface-routes.json), FROZEN at route time by the injected detector/extractor — never
  // re-read from agent-writable attack_surface.json at grade time. Otherwise an agent could
  // relabel a real cross-tenant flip on an easy resource onto a hard surface by adding that
  // endpoint under the target surface in agent scratch.
  const idBearingSurfaces = new Set();
  const surfaceEndpointValues = new Map();
  // The id-bearing predicate is read from surface-routes.json. Any way that read can FAIL to
  // establish a surface's id-bearing status must fail CLOSED, not silently drop the surface into
  // the non-id-bearing bypass branch (which would launder an untested crown to complete on a
  // bypass_attempt narrative). Three read outcomes, three handlings:
  //   1. MISSING routes file (no routing ran / no id-bearing surfaces) -> benign: the id-bearing
  //      set is empty and non-id-bearing surfaces clear on their own evidence (fail OPEN).
  //   2. PRESENT-but-unreadable whole file (unparseable, version mismatch, partial write, on-disk
  //      tampering of the write-guard-only file) -> readSurfaceRoutesStrict throws; the predicate
  //      cannot be established for ANY surface, so fail closed globally (routesUnverifiable).
  //   3. PRESENT + valid envelope but a per-route QUARANTINE (a stale/malformed/duplicate route
  //      silently dropped by the resilient reader into malformed_routes[] — e.g. cross-version
  //      route-field drift on a resumed session, no attacker needed): the dropped surface is absent
  //      from document.routes, so fail closed for exactly that surface (quarantinedSurfaceIds); a
  //      quarantined entry that lost its surface_id is unattributable, so fail closed globally.
  let routesUnverifiable = false;
  // Whether the routes envelope was PRESENT + parseable on this call (the strict read did not
  // throw). Distinct from routesUnverifiable: a MISSING file leaves both false (benign
  // fail-open), a present-but-CORRUPT file sets routesUnverifiable true + this false, a valid
  // envelope sets this true. The routed-surface totality check below fires ONLY when this is
  // true, so it never false-blocks a session that legitimately never routed.
  let routesDocumentReadable = false;
  const quarantinedSurfaceIds = new Set();
  // Every surface_id carrying a route entry in the readable document (routable OR unroutable,
  // id-bearing OR not). A complete surface is always an ASSIGNED surface, and every assignment
  // requires a route (wave-assignment-store's "Missing route" guard rejects an assignment with
  // no route), so a complete surface ABSENT from this set — when routes were readable — is an
  // integrity anomaly (a route lost/dropped after being written), NOT a legitimate routeless
  // surface. Its id-bearing status cannot be established, so it is held as routes-unverifiable
  // rather than laundered onto the non-id-bearing bypass branch.
  const routedSurfaceIds = new Set();
  try {
    const { readSurfaceRoutesStrict } = require("../frontier/surface-router.js");
    const routesRead = readSurfaceRoutesStrict(domain);
    for (const route of (routesRead.document.routes || [])) {
      if (route && typeof route.surface_id === "string" && route.surface_id) routedSurfaceIds.add(route.surface_id);
      // id_bearing (detector result, principal-independent) drives the strong no-bypass grade
      // branch, so a single-account run cannot launder an id-bearing surface to complete via a
      // bypass_attempt narrative. The frozen endpoints are used only by the >=2-principal flip
      // path (authDifferentialCovered); a <2-principal id-bearing surface clears only via a real
      // finding (hasExecuted) / composition, else it stays an honest partial.
      if (route && route.id_bearing === true && route.surface_id) {
        idBearingSurfaces.add(route.surface_id);
        const eps = Array.isArray(route.id_bearing_endpoints) ? route.id_bearing_endpoints : [];
        surfaceEndpointValues.set(route.surface_id, new Set(eps.filter((e) => typeof e === "string" && e)));
      }
    }
    for (const bad of (routesRead.malformed_routes || [])) {
      if (bad && typeof bad.surface_id === "string" && bad.surface_id) quarantinedSurfaceIds.add(bad.surface_id);
      else routesUnverifiable = true;
    }
    // The envelope parsed and every route/malformed row was accounted for: routedSurfaceIds is
    // now the authoritative set of surfaces that carry a route, so the totality check may run.
    routesDocumentReadable = true;
  } catch {
    // We only reach here with complete surfaces to grade (early return at the completeHandoffs===0
    // check otherwise), and every complete surface required a route at assignment time
    // (wave-assignment-store throws for a routeless assignment). So an UNREADABLE routes file here —
    // whether ABSENT (deleted / torn write / partial resume), a dangling symlink, or corrupt — is an
    // INTEGRITY ANOMALY, never the benign no-routing case. Fail CLOSED for every complete surface:
    // its id-bearing status cannot be established, so it must not masquerade as non-id-bearing and
    // clear on a coverage/bypass row (a whole-file rm needs no signing key; the write-guard gates the
    // Write tool, not rm — so absent-with-complete-handoffs is the easiest crown-launder to fail open).
    routesUnverifiable = true;
  }

  const authDifferentialCovered = new Set();
  try {
    const { readResults } = require("../auth-differential-runner.js");
    const { templatizeIdBearingEndpoint } = require("../frontier/id-bearing-endpoints.js");
    const results = readResults(domain);
    // Resolve the row verifier ONCE (a disk key read) before the loop, never per row. A
    // pre-keypair session yields null -> a present row_mac fails to verify (fail closed).
    const rowVerifier = resolveRowVerifierSafely(domain);
    for (const row of ((results && Array.isArray(results.per_endpoint)) ? results.per_endpoint : [])) {
      if (!row || typeof row.endpoint !== "string") continue;
      // Coverage requires a per-endpoint cross-tenant FLIP (MCP-computed): one VALIDATED
      // principal ACCESSED the object (2xx) while a DISTINCT VALIDATED principal was DENIED
      // it (4xx) — the negative control flipped. Same-account-twice (both 2xx, no denial)
      // and [real, junk] (junk never validated) both fail to flip, so neither clears; a
      // genuinely-secure surface (owner-in/attacker-out) does flip and correctly clears.
      if (row.cross_tenant_flip !== true) continue;
      // Cycle B keyed layer: a flipped row credits completion coverage ONLY when its row_mac
      // VERIFIES under the auth-differential context (STRICT — an unsigned, tampered, forged, or
      // cross-context row throws and is skipped, fail closed). This closes the Bash-forged-flip
      // launder past the best-effort write hook now that the ledger is audit-graded: the row must
      // carry a REAL signature over its substantive fields, not just the right shape.
      try {
        assertRowMac(AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row, rowVerifier);
      } catch {
        continue;
      }
      // Bind by surface_id: the sweep must have been RUN FOR this surface (stamped at call
      // time) AND hit one of its id-bearing endpoints. A row not stamped with a surface_id
      // (legacy / un-bound sweep) earns no coverage — fail closed, no endpoint-string bleed.
      if (typeof row.surface_id !== "string" || !row.surface_id) continue;
      const rowTemplate = templatizeIdBearingEndpoint(row.endpoint);
      if (!rowTemplate) continue;
      // base_url-relabel defense: the runner stamps effective_url = joinUrl(base_url, endpoint)
      // — the URL actually fetched — and it enters the row_mac preimage, so a MAC-verified row's
      // effective_url is the real tested URL. The signed `endpoint` alone templatizes to a frozen
      // crown path even when the arm was fetched under a relabeled base_url: an OFF-SCOPE host, or
      // a benign PATH PREFIX (e.g. /safe-prefix) that hid an easy same-host target. When
      // effective_url is present, additionally require it to resolve to an in-scope host AND to
      // templatize to one of THIS surface's frozen id-bearing endpoints; a mismatch is not
      // credited (fail closed). An ABSENT field is a legacy/pre-urlbind row: skip only this extra
      // check (back-compat) — the MAC, flip, surface_id-bind, and endpoint-template checks stand.
      let effectiveTemplate = null;
      if (typeof row.effective_url === "string" && row.effective_url) {
        if (!exploitTargetHostInScope(row.effective_url, domain)) continue;
        effectiveTemplate = templatizeIdBearingEndpoint(row.effective_url);
        if (!effectiveTemplate) continue;
      }
      for (const [surfaceId, endpoints] of surfaceEndpointValues) {
        if (row.surface_id !== surfaceId) continue;
        if (!endpoints.has(rowTemplate)) continue;
        if (effectiveTemplate !== null && !endpoints.has(effectiveTemplate)) continue;
        authDifferentialCovered.add(surfaceId);
      }
    }
  } catch { /* malformed auth-differential results contribute no coverage */ }

  const missing = [];
  for (const [surfaceId, hasBypass] of surfaceBypass) {
    const hasCoverage = (coverageBySurface.get(surfaceId) || 0) > 0;
    const findings = findingsBySurface.get(surfaceId) || [];
    const hasExecuted = findings.some((findingId) => executedFindings.has(findingId));
    // An id-bearing crown clears on an EXECUTED finding ONLY when that finding is an
    // access-control class (the cross-tenant obligation). A same-surface executed SSRF/XSS
    // proves impact but never the object-authorization test, so it does not clear the crown.
    const hasAccessControlExecuted = findings.some(
      (findingId) => executedFindings.has(findingId) && accessControlFindingIds.has(findingId),
    );
    const hasCompositionExecuted = compositionExecutedSurfaces.has(surfaceId);
    const isIdBearing = idBearingSurfaces.has(surfaceId);
    if (isIdBearing) {
      // X-DONE1 an id-bearing complete surface clears ONLY on an executed ACCESS-CONTROL finding, a
      // re-verified cross-stack composition, or MCP-owned auth-differential coverage — never on a
      // non-access-control executed finding, a coverage row, or a bypass narrative.
      if (hasAccessControlExecuted || hasCompositionExecuted || authDifferentialCovered.has(surfaceId)) continue;
      missing.push({
        surface_id: surfaceId,
        finding_id: findings.length > 0 ? findings[0] : null,
        reason: "complete_idbearing_surface_no_differential",
      });
      continue;
    }
    if (routesUnverifiable || quarantinedSurfaceIds.has(surfaceId)) {
      // Routes unreadable (whole file) or this surface's own route was quarantined: its id-bearing
      // status cannot be established, so it must not be treated as non-id-bearing and cleared on a
      // bypass narrative or a coverage row. Because the surface COULD be an id-bearing crown, apply
      // the SAME access-control bar the intact id-bearing branch requires (X-DONE1): clear only on an
      // executed ACCESS-CONTROL finding or composition — a non-access-control executed finding (an
      // XSS/SSRF) does NOT discharge a possibly-crown's cross-tenant obligation. Otherwise hold.
      if (hasAccessControlExecuted || hasCompositionExecuted) continue;
      missing.push({
        surface_id: surfaceId,
        finding_id: findings.length > 0 ? findings[0] : null,
        reason: "complete_surface_routes_unverifiable",
      });
      continue;
    }
    // TOTALITY: routes were readable but this complete surface carries NO route entry at all (not
    // id-bearing, not quarantined, not global-unverifiable). Every complete surface is assigned
    // and every assignment requires a route, so an absent route is an integrity anomaly and the
    // id-bearing status cannot be established. Hold it as routes-unverifiable rather than clearing
    // it on a coverage/bypass narrative; because it could be a crown, require the access-control bar
    // (never a non-access-control executed finding); genuine access-control/composition evidence clears.
    if (routesDocumentReadable && !routedSurfaceIds.has(surfaceId)) {
      if (hasAccessControlExecuted || hasCompositionExecuted) continue;
      missing.push({
        surface_id: surfaceId,
        finding_id: findings.length > 0 ? findings[0] : null,
        reason: "complete_surface_routes_unverifiable",
      });
      continue;
    }
    if (hasBypass || hasCoverage || hasExecuted || hasCompositionExecuted) continue;
    missing.push({
      surface_id: surfaceId,
      finding_id: findings.length > 0 ? findings[0] : null,
      reason: findings.length > 0
        ? "complete_surface_finding_not_executed"
        : "complete_surface_no_evidence",
    });
  }
  return { missing };
}

module.exports = {
  CLAIMS_MAX_RECORDS,
  CLAIM_SEVERITIES,
  CLAIM_STATUSES,
  CLAIM_VERSION,
  EVIDENCE_REFERENCE_KIND_VALUES,
  OFFENSIVE_TOOL_DEMONSTRATED_CEILING,
  OFFENSIVE_OUTCOME_VALUES,
  O_P4_NATIVE_LANGUAGES,
  O_P4_TRIGGERING_SEVERITIES,
  SAFE_ORACLE_KINDS,
  appendCandidateClaim,
  assertExploitedClaimHasProof,
  canonicalizeExploitTarget,
  assertNotStaticOnlyNativeHighSeverity,
  reproVerifiedGapForNativeReportableFindings,
  findingDifferentialGapForStandaloneReportableFindings,
  crossStackPathGapForReportableFindings,
  completionDepthGapForCompleteSurfaces,
  nativeCodeSurfacesForClaim,
  claimReproCommandArgv,
  claimSurfaceLanguageMap,
  evidenceReferenceLookupKey,
  generatedClaimId,
  normalizeCandidateClaim,
  normalizeEvidenceReferenceShape,
  normalizeExploitOutcome,
  readCandidateClaims,
  readOffensiveRunRecords,
  offensiveRunRowSatisfiesEvidence,
};

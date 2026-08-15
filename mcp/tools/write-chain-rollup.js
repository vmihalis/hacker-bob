"use strict";

// Y.3 Stage c — `bob_write_chain_rollup` (Y-D15c / Y-P13 / Y-P13b / Y-P14b).
//
// Replaces the chain-builder Write-on-chains.md leak. Chain-builder returns
// structured rollup text in its handoff; the orchestrator calls this tool to
// persist it. MCP renders `chains.md` alongside `chain-attempts.jsonl` (the
// JSONL ledger remains the authoritative attempt record; chains.md is the
// rolled-up narrative for the report-writer to read via Read).
//
// Bounded narrative cap (Y-P13b): narrative ≤ 4096 chars.
//
// Validates `chain_id` exists in `chain-attempts.jsonl` — the rollup must
// reference a known chain attempt; orphan rollups are rejected.

const fs = require("fs");
const crypto = require("crypto");
const {
  ERROR_CODES,
  ToolError,
} = require("../core/io/envelope.js");
const {
  LARGE_BODY_THRESHOLD_BYTES,
  assertSafeDomain,
  chainAttemptsJsonlPath,
  chainsMarkdownPath,
  resolveEvidencePath,
  sessionDir,
} = require("../core/io/paths.js");
const {
  withSessionLock,
} = require("../core/io/storage.js");

const NARRATIVE_MAX = 4096;
const CONFIDENCE_VALUES = Object.freeze(["low", "medium", "high"]);
const FINDING_REF_PREFIXES = Object.freeze(["frontier_event:", "verification_round:"]);
const MAX_FINDING_REFS = 32;
const MAX_FINDING_REF_LEN = 256;

// Y.3 Stage c (Y-P14b / O4) — MCP-owned binding-handle prefixes accepted in
// the NEW `evidence_refs[]` field below. These are the canonical body-binding
// handles for a recorded HTTP response (`bob_import_http_traffic`), a storage-
// distilled body retrieval (`bob_resolve_body`), or a static-scan-recorded
// artifact (`bob_static_scan`). `bob_import_static_artifact` is content-only
// for evm/solana token contracts and is NOT a body-binding handle, so its
// prefix is intentionally absent from this set.
const EVIDENCE_REF_HANDLE_PREFIXES = Object.freeze([
  "bob_import_http_traffic:",
  "bob_resolve_body:",
  "bob_static_scan:",
]);
const MAX_EVIDENCE_REFS = 50;
const MAX_EVIDENCE_REF_LEN = 512;

function assertString(value, fieldName, { maxLength, minLength = 1 } = {}) {
  if (typeof value !== "string") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be a string`);
  }
  if (value.length < minLength) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be at least ${minLength} characters`);
  }
  if (maxLength != null && value.length > maxLength) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be at most ${maxLength} characters`);
  }
  return value;
}

function chainAttemptIdExists(domain, chainId) {
  const file = chainAttemptsJsonlPath(domain);
  if (!fs.existsSync(file)) return false;
  const text = fs.readFileSync(file, "utf8");
  // chain-attempts.jsonl records carry attempt_id, chain_id, or similar; accept
  // any structural match. The producer-side IDs follow chain-attempts.js
  // conventions; substring match is safe because IDs are tightly-bounded
  // alphanumeric tokens (no escape characters or whitespace).
  return text.includes(`"chain_id":"${chainId}"`) || text.includes(`"attempt_id":"${chainId}"`);
}

function validateFindingRefs(refs) {
  if (refs == null) return [];
  if (!Array.isArray(refs)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "finding_refs must be an array");
  }
  if (refs.length > MAX_FINDING_REFS) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `finding_refs must contain at most ${MAX_FINDING_REFS} entries`);
  }
  for (let i = 0; i < refs.length; i += 1) {
    const ref = refs[i];
    if (typeof ref !== "string" || !ref) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `finding_refs[${i}] must be a non-empty string`);
    }
    if (ref.length > MAX_FINDING_REF_LEN) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `finding_refs[${i}] must be at most ${MAX_FINDING_REF_LEN} characters`);
    }
    if (!FINDING_REF_PREFIXES.some((prefix) => ref.startsWith(prefix))) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `finding_refs[${i}] must start with one of ${FINDING_REF_PREFIXES.join(", ")}`,
        { ref },
      );
    }
  }
  return refs.slice();
}

// Y.3 Stage c (Y-P14b / O4) — validator for the NEW top-level `evidence_refs[]`
// field. Each entry MUST EITHER (a) start with one of EVIDENCE_REF_HANDLE_PREFIXES,
// OR (b) be a literal `evidence/<path>` whose on-disk size is at most
// LARGE_BODY_THRESHOLD_BYTES. Entries that point at large raw bodies are
// rejected with a remediation string that names all three accepted body-binding
// handles literally; entries that match neither shape are rejected with the
// closed prefix list. This complement to FINDING_REF_PREFIXES enforces stigmergic
// producer-consumer coherence between body-binding tools and the chain rollup
// (Y-D19 producer #5 "mcp_owned_body_binding_handles").
function validateEvidenceRefs(refs, domain) {
  if (refs == null) return [];
  if (!Array.isArray(refs)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "evidence_refs must be an array");
  }
  if (refs.length > MAX_EVIDENCE_REFS) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `evidence_refs must contain at most ${MAX_EVIDENCE_REFS} entries`,
    );
  }
  for (let i = 0; i < refs.length; i += 1) {
    const ref = refs[i];
    if (typeof ref !== "string" || !ref) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `evidence_refs[${i}] must be a non-empty string`,
      );
    }
    if (ref.length > MAX_EVIDENCE_REF_LEN) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `evidence_refs[${i}] must be at most ${MAX_EVIDENCE_REF_LEN} characters`,
      );
    }
    if (EVIDENCE_REF_HANDLE_PREFIXES.some((prefix) => ref.startsWith(prefix))) {
      continue;
    }
    if (ref.startsWith("evidence/")) {
      let absolutePath;
      try {
        absolutePath = resolveEvidencePath(domain, ref);
      } catch (resolveErr) {
        throw new ToolError(
          ERROR_CODES.INVALID_ARGUMENTS,
          `evidence_refs[${i}] resolution failed: ${resolveErr.message}`,
          { ref },
        );
      }
      let stat;
      try {
        stat = fs.statSync(absolutePath);
      } catch (statErr) {
        throw new ToolError(
          ERROR_CODES.NOT_FOUND,
          `evidence_refs[${i}] cites ${ref} but the file does not exist under the session root`,
          { ref, absolutePath },
          {
            remediation: "ensure the evidence file is committed under sessionDir(<target_domain>)/evidence/ before citing it, or bind via bob_import_http_traffic / bob_resolve_body / bob_static_scan",
          },
        );
      }
      if (stat.size > LARGE_BODY_THRESHOLD_BYTES) {
        throw new ToolError(
          ERROR_CODES.INVALID_ARGUMENTS,
          `evidence_refs[${i}] cites ${ref} (${stat.size} bytes > LARGE_BODY_THRESHOLD_BYTES=${LARGE_BODY_THRESHOLD_BYTES})`,
          { ref, size_bytes: stat.size, threshold_bytes: LARGE_BODY_THRESHOLD_BYTES },
          {
            remediation: `evidence_refs[${i}] cites ${ref} (${stat.size} bytes > ${LARGE_BODY_THRESHOLD_BYTES} LARGE_BODY_THRESHOLD_BYTES); bind the response body via bob_import_http_traffic, bob_resolve_body, or bob_static_scan and cite the returned handle (e.g., bob_resolve_body:<event_id>) instead of the raw evidence/ path`,
          },
        );
      }
      continue;
    }
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `evidence_refs[${i}] must start with one of ${EVIDENCE_REF_HANDLE_PREFIXES.join(", ")} OR be a literal evidence/<path> within LARGE_BODY_THRESHOLD_BYTES=${LARGE_BODY_THRESHOLD_BYTES}`,
      { ref },
      {
        remediation: `evidence_refs[${i}] must start with one of ${EVIDENCE_REF_HANDLE_PREFIXES.join(", ")} OR be a literal evidence/<path> within LARGE_BODY_THRESHOLD_BYTES=${LARGE_BODY_THRESHOLD_BYTES}`,
      },
    );
  }
  return refs.slice();
}

function renderChainsMarkdown(rollup) {
  const banner = [
    "<!--",
    "This file is MCP-rendered by bob_write_chain_rollup. Hand-edits are NOT",
    "preserved across renders.",
    "-->",
    "",
  ].join("\n");
  const parts = [banner];
  parts.push(`# Chain Rollup — ${rollup.target_domain}`);
  parts.push("");
  parts.push(`Chain: \`${rollup.chain_id}\`  |  Confidence: \`${rollup.confidence}\``);
  parts.push("");
  parts.push(rollup.narrative);
  parts.push("");
  if (rollup.finding_refs.length > 0) {
    parts.push("## Finding References");
    parts.push("");
    for (const ref of rollup.finding_refs) {
      parts.push(`- \`${ref}\``);
    }
    parts.push("");
  }
  if (rollup.evidence_refs.length > 0) {
    parts.push("## Evidence References");
    parts.push("");
    for (const ref of rollup.evidence_refs) {
      parts.push(`- \`${ref}\``);
    }
    parts.push("");
  }
  return parts.join("\n");
}

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bob_write_chain_rollup args must be a plain object");
  }
  const domain = assertSafeDomain(args.target_domain);
  const chainId = assertString(args.chain_id, "chain_id", { maxLength: 128 });
  const narrative = assertString(args.narrative, "narrative", { maxLength: NARRATIVE_MAX });
  const confidence = args.confidence;
  if (!CONFIDENCE_VALUES.includes(confidence)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `confidence must be one of ${CONFIDENCE_VALUES.join(", ")}`,
    );
  }
  const findingRefs = validateFindingRefs(args.finding_refs);
  const evidenceRefs = validateEvidenceRefs(args.evidence_refs, domain);

  if (!chainAttemptIdExists(domain, chainId)) {
    throw new ToolError(
      ERROR_CODES.NOT_FOUND,
      `chain_id ${chainId} not found in chain-attempts.jsonl for ${domain}`,
      { chain_id: chainId, target_domain: domain },
      {
        remediation: "call bob_write_chain_attempt to record the underlying chain attempt before rolling up the narrative",
      },
    );
  }

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    const rollup = {
      target_domain: domain,
      chain_id: chainId,
      narrative,
      finding_refs: findingRefs,
      evidence_refs: evidenceRefs,
      confidence,
      rendered_at: new Date().toISOString(),
    };
    const markdown = renderChainsMarkdown(rollup);
    const file = chainsMarkdownPath(domain);
    fs.writeFileSync(file, markdown, "utf8");
    const contentHash = crypto.createHash("sha256").update(markdown, "utf8").digest("hex");
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      chain_id: chainId,
      chains_path: file,
      chains_content_hash: contentHash,
      chains_size_bytes: Buffer.byteLength(markdown, "utf8"),
      finding_refs_count: findingRefs.length,
      evidence_refs_count: evidenceRefs.length,
    });
  });
}

const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_write_chain_rollup",
  writes_audit_graded: true,
  description:
    "Render chains.md from a structured chain rollup (Y-D15c / Y-P13 / Y-P14b). Validates chain_id against chain-attempts.jsonl; renders chains.md alongside the JSONL ledger; agents no longer Write chains.md directly. Bounded narrative cap (≤4096ch) per Y-P13b; finding_refs[] limited to frontier_event:/verification_round: prefixes; evidence_refs[] limited to bob_import_http_traffic:/bob_resolve_body:/bob_static_scan: handle prefixes OR literal evidence/<path> within LARGE_BODY_THRESHOLD_BYTES.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      chain_id: { type: "string", maxLength: 128 },
      narrative: { type: "string", maxLength: NARRATIVE_MAX },
      finding_refs: {
        type: "array",
        maxItems: MAX_FINDING_REFS,
        items: { type: "string", maxLength: MAX_FINDING_REF_LEN },
      },
      evidence_refs: {
        type: "array",
        maxItems: MAX_EVIDENCE_REFS,
        items: { type: "string", maxLength: MAX_EVIDENCE_REF_LEN },
      },
      confidence: { type: "string", enum: [...CONFIDENCE_VALUES] },
    },
    required: ["target_domain", "chain_id", "narrative", "confidence"],
  },
  handler,
  role_bundles: ["chain", "orchestrator"],
  capability_id: "Y_self_reporting",
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["chains.md"],
  CONFIDENCE_VALUES,
  EVIDENCE_REF_HANDLE_PREFIXES,
  FINDING_REF_PREFIXES,
  MAX_EVIDENCE_REFS,
  MAX_EVIDENCE_REF_LEN,
  NARRATIVE_MAX,
});

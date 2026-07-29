"use strict";

// Cycle Y.7 — bob_scan_transcript_for_friction (Y-D6 + Y-P9).
//
// Adversarial post-run scan over a subagent transcript + recorded MCP
// invocations. Returns the synthesized scanner records (capability friction
// + protocol drift specs) without appending them — the orchestrator decides
// whether to forward them to bob_log_capability_friction /
// bob_log_protocol_drift. This separation keeps the scanner pure and the
// idempotency boundary owned by the log tools (Y-P3 / log-protocol-drift
// keys remain the source of truth for de-dup).
//
// Y-P9 framing: demoted tripwire. Silent attackers trivially evade
// enumeration. The operator-visible value is the co-presence signal
// (Y-P11) — voluntary friction with `detected_by: agent_self_report`
// alongside a synthetic with `detected_by: adversarial_transcript_scan`
// for the same (run_id, node_id, wanted_tool, friction_kind, purpose).
//
// Orchestrator-only at the role-bundle layer. Subagents emit voluntary
// friction; the orchestrator runs the adversarial pass.

const fs = require("fs");
const path = require("path");

const { ERROR_CODES, ToolError } = require("../envelope.js");
const {
  assertSafeDomain,
  sessionDir,
} = require("../paths.js");
const {
  loadQueuePolicy,
} = require("../queue-policy.js");
const {
  readSurfaceLeadsDocument,
} = require("../lead-intake.js");
const {
  DEFAULT_SCANNERS,
  normalizeOperatorScanner,
  scanTranscript,
  listEvidenceFiles,
} = require("../friction-scanners.js");

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asString(value, max) {
  if (typeof value !== "string") return "";
  return max && value.length > max ? value.slice(0, max) : value;
}

function buildScannerList(operatorScanners) {
  const out = DEFAULT_SCANNERS.slice();
  for (const entry of asArray(operatorScanners)) {
    const normalized = normalizeOperatorScanner(entry);
    if (normalized) out.push(normalized);
  }
  return out;
}

function loadRecordedLeadsForRun(domain, runId) {
  try {
    const doc = readSurfaceLeadsDocument(domain);
    const leads = asArray(doc.leads);
    if (!runId) return leads;
    // Filter by source_wave / source_agent / source_surface_id where the
    // run_id encoding is recoverable. The default surface-lead schema does
    // not carry a run_id field directly, so the matcher correlates by the
    // `source` field when the orchestrator passes a run-tagged source
    // string. Tests pass `source: "run-X"` explicitly so the correlation
    // mechanism is exercise-able without changing the existing
    // surface-leads schema.
    return leads.filter((lead) => {
      if (!lead || typeof lead !== "object") return false;
      const fields = [lead.source, lead.source_wave, lead.source_agent, lead.source_surface_id];
      return fields.some((f) => typeof f === "string" && f.includes(runId));
    });
  } catch {
    return [];
  }
}

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_scan_transcript_for_friction args must be a plain object",
    );
  }
  const domain = assertSafeDomain(args.target_domain);
  const runId = asString(args.run_id, 256).trim();
  const nodeId = asString(args.node_id, 256).trim();
  if (!runId) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "run_id must be a non-empty string");
  }
  if (!nodeId) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "node_id must be a non-empty string");
  }
  const transcriptText = asString(args.transcript_text, 1024 * 1024);
  const toolInvocations = asArray(args.tool_invocations);
  const voluntaryFrictions = asArray(args.voluntary_frictions);
  const handoffSummary = (args.handoff_summary && typeof args.handoff_summary === "object" && !Array.isArray(args.handoff_summary))
    ? args.handoff_summary
    : null;

  let queuePolicy = null;
  try {
    queuePolicy = loadQueuePolicy(domain);
  } catch {
    queuePolicy = null;
  }
  const operatorScanners = queuePolicy && Array.isArray(queuePolicy.friction_scanners)
    ? queuePolicy.friction_scanners
    : [];
  const scanners = buildScannerList(operatorScanners);

  const evidenceFiles = listEvidenceFiles(domain);
  const recordedLeads = loadRecordedLeadsForRun(domain, runId);

  const context = {
    target_domain: domain,
    run_id: runId,
    node_id: nodeId,
    transcript_text: transcriptText,
    tool_invocations: toolInvocations,
    voluntary_frictions: voluntaryFrictions,
    evidence_files: evidenceFiles,
    handoff_summary: handoffSummary,
    recorded_leads: recordedLeads,
    queue_policy: queuePolicy,
  };

  const records = scanTranscript(scanners, context);
  const friction_records = records.filter((r) => r.kind === "friction");
  const drift_records = records.filter((r) => r.kind === "drift");

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    run_id: runId,
    node_id: nodeId,
    scanner_count: scanners.length,
    operator_scanner_count: scanners.length - DEFAULT_SCANNERS.length,
    friction_records,
    drift_records,
  });
}

module.exports = Object.freeze({
  name: "bob_scan_transcript_for_friction",
  description:
    "Cycle Y.7 adversarial post-run scan (Y-D6 + Y-P9). The transcript- and "
    + "invocation-bearing path: pass transcript_text/tool_invocations for the "
    + "regex, mcp_invocation_failure, evidence_size, and handoff_invocation_diff "
    + "scanners the server CANNOT witness at merge time (no transcript / no "
    + "invocation stream). bob_apply_wave_merge already mechanizes the promotion "
    + "gate AND the one invocation-free scanner (handoff_ledger_diff) server-side "
    + "(CR-3); this tool adds the remaining coverage. Returns the synthesized "
    + "capability_friction + protocol_drift records detected by the closed default "
    + "scanner registry (bash_curl, bash_wget, bash_raw_http, bash_cat_ledger, "
    + "mcp_invocation_failure_scanner, curl_on_target_domain, curl_on_osint_endpoint, "
    + "python_inline_curl_parse, large_response_body_unimported, producer_trace_dropped, "
    + "silent_lead_threshold_drop) unioned with operator-extensions from "
    + "queue-policy.friction_scanners[]. The tool does NOT append events — the "
    + "orchestrator forwards each record through bob_log_capability_friction / "
    + "bob_log_protocol_drift so the Y-P3 6-tuple / log-protocol-drift idempotency "
    + "key remains the de-dup source of truth. Voluntary + synthetic frictions "
    + "coexist via Y-P11 (different detected_by → different 6-tuple).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      run_id: { type: "string" },
      node_id: { type: "string" },
      transcript_text: {
        type: "string",
        description: "Raw transcript text the agent produced. Best-effort regex; transcript shape is operator-managed.",
      },
      tool_invocations: {
        type: "array",
        description: "Recorded MCP invocations for the run. Each entry {tool, outcome, event_id, args?, output?}; mcp_invocation_failure_scanner consumes non-success outcomes with an event_id.",
        items: { type: "object" },
      },
      voluntary_frictions: {
        type: "array",
        description: "Voluntary capability_friction_observed payloads already recorded by the agent during the run. The mcp_invocation_failure_scanner suppresses synthetics that duplicate a voluntary report (Y-P11 co-presence preserved at the wider 6-tuple).",
        items: { type: "object" },
      },
      handoff_summary: {
        type: "object",
        description: "Subagent handoff summary; producer_trace_dropped + silent_lead_threshold_drop consume ranked_leads[].",
      },
    },
    required: ["target_domain", "run_id", "node_id"],
  },
  handler,
  role_bundles: ["orchestrator"],
  capability_id: "Y_self_reporting",
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});

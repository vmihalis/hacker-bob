"use strict";

// Cycle Y.7 — adversarial transcript scan (Y-D6 + Y-P9).
//
// Default `SCANNER_REGISTRY` is a closed manifest of best-effort tripwire
// scanners. Per Y-P9 the registry is demoted framing: a silent attacker
// trivially evades enumeration. Scanners are useful for the operator-visible
// co-presence signal (Y-P11) where a voluntary friction record and a
// synthetic scanner record share the same `(run_id, node_id, wanted_tool)`
// tuple but differ in `detected_by`.
//
// Operator extensions land in queue-policy.friction_scanners[] via
// `bob_set_friction_scanners` (Y.3) and are unioned with the defaults at
// scan time (the operator union is consumed by the `bob_set_friction_scanners`
// caller — see `mcp/lib/tools/scan-transcript-for-friction.js`).
//
// Closed manifest of default scanner ids:
//   * bash_curl, bash_wget, bash_raw_http, bash_cat_ledger — closed-prefix
//     patterns from rev 3 (Y-D6).
//   * mcp_invocation_failure_scanner — rev 3 D7 narrow case; emits
//     `tool_inadequate` synthetics with a witness ref.
//   * curl_on_target_domain, curl_on_osint_endpoint, python_inline_curl_parse
//     — rev 4 W2 closed-prefix extensions.
//   * large_response_body_unimported — rev 4 W2 + rev 4.1 O4 detection
//     counterpart; reads `LARGE_BODY_THRESHOLD_BYTES` from `paths.js`;
//     cross-references the run's `tool_invocations[]` for matching
//     `bob_import_http_traffic`, `bob_resolve_body`, or `bob_static_scan`
//     calls (rev-4.1 corrected handle set — NOT `bob_import_static_artifact`
//     which is content-only for evm/solana token contracts).
//   * producer_trace_dropped — rev 4 Y-P14a detection counterpart; emits a
//     synthetic `protocol_drift_observed` with
//     `drift_signature: producer_trace_dropped` when a subagent handoff
//     summary contains `ranked_leads[]` with count >= 2 and zero matching
//     `bob_record_surface_leads` invocations.
//   * silent_lead_threshold_drop — rev 4.1 defect 1 producer-side runtime
//     tripwire complement; emits a synthetic `protocol_drift_observed` with
//     `drift_signature: silent_lead_threshold_drop` when the handoff summary
//     asserts N ranked_leads while `surface-leads.json` records M < N
//     entries for the same `run_id`. Payload includes both counts and a
//     `rationale_required_but_missing` flag derived from queue-policy
//     `lead_rationale_required_when_below_threshold` (Y-D9 rev 4.1) and the
//     recorded leads' `rationale` field presence.

const fs = require("fs");
const path = require("path");

const { sessionDir, LARGE_BODY_THRESHOLD_BYTES } = require("./paths.js");

// ── default scanner manifest ───────────────────────────────────────────────
//
// Each scanner is an Object.freeze'd record. A scanner is either:
//   * pattern-matched against transcript Bash command lines (kind: "regex")
//   * derived from MCP `tool_invocations[]` failures (kind: "invocation_failure")
//   * derived from on-disk artifact + invocation cross-reference
//     (kind: "evidence_size")
//   * derived from handoff summary + invocation cross-reference
//     (kind: "handoff_invocation_diff")
//   * derived from handoff summary + surface-leads.json cross-reference
//     (kind: "handoff_ledger_diff")
//
// Each scanner emits either a `capability_friction_observed` synthetic
// (with `detected_by: adversarial_transcript_scan`) or a
// `protocol_drift_observed` synthetic (with `detected_by:
// adversarial_transcript_scan`). The scanner's `synthesize` function is
// pure and returns a list of zero or more synthetic records; the
// orchestrator/handler decides whether to call `bob_log_*` on them.

const DEFAULT_SCANNERS = Object.freeze([
  Object.freeze({
    name: "bash_curl",
    kind: "regex",
    pattern: /\bcurl\b/,
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
  }),
  Object.freeze({
    name: "bash_wget",
    kind: "regex",
    pattern: /\bwget\b/,
    fallback_used: "bash_wget",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
  }),
  Object.freeze({
    name: "bash_raw_http",
    kind: "regex",
    // `nc -v <host> 80` / `openssl s_client -connect ...` — raw socket
    // shapes the scanner can recognize without a TCP handshake.
    pattern: /(\bnc\b\s+[-\w\s]*\d{1,5}|openssl\s+s_client)/,
    fallback_used: "bash_raw_http",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
  }),
  Object.freeze({
    name: "bash_cat_ledger",
    kind: "regex",
    // Operator skipping `bob_read_*` and tailing chain-attempts.jsonl or
    // surface-leads.json directly via cat/less/tail.
    pattern: /\b(cat|less|tail)\b[^\n]*(chain-attempts\.jsonl|surface-leads\.json|surface-routes\.json)/,
    fallback_used: "bash_cat_ledger",
    friction_kind: "tool_absent",
    wanted_tool: "bob_read_chain_attempts",
    purpose: "chain_walk",
  }),
  Object.freeze({
    name: "curl_on_target_domain",
    // rev 4 W2 — narrow form of `bash_curl` that asserts the URL host
    // matches the session's target_domain (passed in scanner context).
    kind: "regex_with_context",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    buildPattern: (context) => {
      const domain = context && typeof context.target_domain === "string"
        ? context.target_domain
        : null;
      if (!domain) return null;
      const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(
        `\\bcurl\\b[^\\n]*https?://(?:[a-zA-Z0-9._-]+\\.)?${escaped}\\b`,
      );
    },
  }),
  Object.freeze({
    name: "curl_on_osint_endpoint",
    // rev 4 W2 — Bash curl against well-known OSINT endpoints when an
    // operator should be routing through `bob_public_intel`.
    kind: "regex",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    wanted_tool: "bob_public_intel",
    purpose: "evidence_pull",
    pattern: /\bcurl\b[^\n]*https?:\/\/(?:[a-zA-Z0-9._-]+\.)?(urlscan\.io|virustotal\.com|crt\.sh|securitytrails\.com|censys\.io|shodan\.io|abuseipdb\.com)/,
  }),
  Object.freeze({
    name: "python_inline_curl_parse",
    // rev 4 W2 — python -c subprocess.run(['curl', ...]) or similar shapes
    // where the agent reaches for python+subprocess+curl rather than
    // bob_http_scan + bob_resolve_body.
    kind: "regex",
    fallback_used: "bash_other",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    pattern: /\bpython3?\b[^\n]*-c[^\n]*subprocess[^\n]*['"]curl['"]/,
  }),
  Object.freeze({
    name: "mcp_invocation_failure_scanner",
    // rev 3 D7 — emit a synthetic `tool_inadequate` when the run's
    // `tool_invocations[]` recorded a non-success outcome that the agent
    // did NOT voluntarily report as friction. Requires a witness ref to
    // satisfy Y-P10 mechanical-witness.
    kind: "invocation_failure",
    fallback_used: "none",
    friction_kind: "tool_inadequate",
    purpose: "other",
    inadequacy_mode: "output_format_unsuitable",
  }),
  Object.freeze({
    name: "large_response_body_unimported",
    // rev 4 W2 + rev 4.1 O4 counterpart — evidence/<path> larger than
    // LARGE_BODY_THRESHOLD_BYTES (262144) without a matching binding-handle
    // invocation in the same run. Accepted handles match the
    // EVIDENCE_REF_HANDLE_PREFIXES family from Y.3 write-chain-rollup
    // (rev-4.1 corrected handle set — NOT `bob_import_static_artifact`).
    kind: "evidence_size",
    fallback_used: "bash_other",
    friction_kind: "tool_absent",
    wanted_tool: "bob_import_http_traffic",
    purpose: "evidence_pull",
    accepted_binding_tools: Object.freeze([
      "bob_import_http_traffic",
      "bob_resolve_body",
      "bob_static_scan",
    ]),
    threshold_bytes: LARGE_BODY_THRESHOLD_BYTES,
  }),
  Object.freeze({
    name: "producer_trace_dropped",
    // rev 4 Y-P14a counterpart — handoff summary contains ranked_leads[]
    // with count >= 2 but the run recorded zero matching
    // `bob_record_surface_leads` invocations. Emits a synthetic
    // protocol_drift_observed (advisory only — Y-P7).
    kind: "handoff_invocation_diff",
    drift_signature: "producer_trace_dropped",
    required_invocation_tool: "bob_record_surface_leads",
    summary_field: "ranked_leads",
    min_summary_count: 2,
  }),
  Object.freeze({
    name: "silent_lead_threshold_drop",
    // rev 4.1 defect 1 producer-side runtime tripwire — handoff summary
    // asserts N ranked_leads while surface-leads.json records M < N
    // entries for the same run. Emits a synthetic protocol_drift_observed
    // with `drift_signature: silent_lead_threshold_drop` and a payload
    // that includes both counts plus a `rationale_required_but_missing`
    // flag set from queue-policy lead_rationale_required_when_below_threshold
    // AND the recorded leads' rationale field presence.
    kind: "handoff_ledger_diff",
    drift_signature: "silent_lead_threshold_drop",
    summary_field: "ranked_leads",
  }),
]);

// ── synthesizers ──────────────────────────────────────────────────────────
//
// Each synthesizer is a pure function over (scanner, context). Context is
// the scanner-input bundle assembled by `bob_scan_transcript_for_friction`
// before calling `scanTranscript`. Synthesizers return zero or more
// synthetic-record specs `{kind: "friction"|"drift", payload}` that the
// caller may forward to `bob_log_capability_friction` /
// `bob_log_protocol_drift`. The scanner itself does not append events.

function bashCommandLines(transcript) {
  if (typeof transcript !== "string" || !transcript) return [];
  // Bash invocations the agent ran. The scanner is best-effort regex over
  // the raw transcript text — the transcript shape is the operator's
  // responsibility (per Y-P9 demoted framing).
  return transcript.split(/\r?\n/);
}

function synthesizeRegex(scanner, context) {
  const lines = bashCommandLines(context.transcript_text);
  const pattern = scanner.pattern;
  const hits = [];
  for (const line of lines) {
    if (pattern.test(line)) {
      hits.push(line.trim());
      if (hits.length >= 10) break;
    }
  }
  if (hits.length === 0) return [];
  return [{
    kind: "friction",
    scanner: scanner.name,
    payload: {
      target_domain: context.target_domain,
      run_id: context.run_id,
      node_id: context.node_id,
      wanted_tool: scanner.wanted_tool,
      purpose: scanner.purpose,
      fallback_used: scanner.fallback_used,
      friction_kind: scanner.friction_kind,
      detected_by: "adversarial_transcript_scan",
      rationale: `Adversarial transcript scan ${scanner.name} matched ${hits.length} Bash line(s); first hit: ${truncate(hits[0], 320)}`,
    },
  }];
}

function synthesizeRegexWithContext(scanner, context) {
  const pattern = scanner.buildPattern(context);
  if (!pattern) return [];
  return synthesizeRegex(
    { ...scanner, pattern, kind: "regex" },
    context,
  );
}

function synthesizeInvocationFailure(scanner, context) {
  const invocations = Array.isArray(context.tool_invocations)
    ? context.tool_invocations
    : [];
  const voluntaryFrictions = Array.isArray(context.voluntary_frictions)
    ? context.voluntary_frictions
    : [];
  // Witness eligibility: outcome non-success AND event_id present.
  const out = [];
  for (const inv of invocations) {
    if (!inv || typeof inv !== "object") continue;
    const outcome = inv.outcome || inv.status;
    const failed = outcome != null && outcome !== "success" && outcome !== "ok";
    if (!failed) continue;
    if (typeof inv.event_id !== "string" || !inv.event_id) continue;
    if (typeof inv.tool !== "string" || !inv.tool) continue;
    // Skip when the agent already voluntarily reported friction with the
    // same wanted_tool + run_id + node_id + this event_id as witness.
    const alreadyReported = voluntaryFrictions.some((f) => f
      && f.wanted_tool === inv.tool
      && f.inadequate_invocation_ref === `frontier_event:${inv.event_id}`
      && f.run_id === context.run_id
      && f.node_id === context.node_id);
    if (alreadyReported) continue;
    out.push({
      kind: "friction",
      scanner: scanner.name,
      payload: {
        target_domain: context.target_domain,
        run_id: context.run_id,
        node_id: context.node_id,
        wanted_tool: inv.tool,
        purpose: scanner.purpose,
        fallback_used: scanner.fallback_used,
        friction_kind: "tool_inadequate",
        inadequacy_mode: scanner.inadequacy_mode,
        inadequate_invocation_ref: `frontier_event:${inv.event_id}`,
        detected_by: "adversarial_transcript_scan",
        rationale: `Scanner ${scanner.name}: invocation of ${inv.tool} returned non-success outcome ${String(outcome)}; auto-derived tool_inadequate synthetic with witness ref.`,
      },
    });
    if (out.length >= 10) break;
  }
  return out;
}

function synthesizeEvidenceSize(scanner, context) {
  const evidenceFiles = Array.isArray(context.evidence_files)
    ? context.evidence_files
    : [];
  const invocations = Array.isArray(context.tool_invocations)
    ? context.tool_invocations
    : [];
  const acceptedTools = scanner.accepted_binding_tools;
  // Did the run import a body via any accepted binding tool? If so the
  // scanner does not fire — the operator already bound at least one body
  // (rev-4.1 cross-reference is run-scoped, not per-file).
  const hasBindingInvocation = invocations.some((inv) => inv
    && typeof inv.tool === "string"
    && acceptedTools.includes(inv.tool));
  if (hasBindingInvocation) return [];
  const oversized = evidenceFiles.filter((f) => f
    && typeof f.relative_path === "string"
    && typeof f.size_bytes === "number"
    && f.size_bytes > scanner.threshold_bytes);
  if (oversized.length === 0) return [];
  const rationaleSuffix = `Bind via one of: ${acceptedTools.join(", ")}.`;
  const out = [];
  for (const file of oversized.slice(0, 10)) {
    out.push({
      kind: "friction",
      scanner: scanner.name,
      payload: {
        target_domain: context.target_domain,
        run_id: context.run_id,
        node_id: context.node_id,
        wanted_tool: scanner.wanted_tool,
        purpose: scanner.purpose,
        fallback_used: scanner.fallback_used,
        friction_kind: scanner.friction_kind,
        detected_by: "adversarial_transcript_scan",
        rationale: `Scanner ${scanner.name}: ${file.relative_path} is ${file.size_bytes} bytes (> ${scanner.threshold_bytes}) with no binding-handle invocation in run. ${rationaleSuffix}`,
      },
    });
  }
  return out;
}

function synthesizeHandoffInvocationDiff(scanner, context) {
  const summary = context.handoff_summary;
  if (!summary || typeof summary !== "object") return [];
  const rankedLeads = Array.isArray(summary[scanner.summary_field])
    ? summary[scanner.summary_field]
    : [];
  if (rankedLeads.length < scanner.min_summary_count) return [];
  const invocations = Array.isArray(context.tool_invocations)
    ? context.tool_invocations
    : [];
  const recordingCount = invocations.filter((inv) => inv
    && inv.tool === scanner.required_invocation_tool).length;
  if (recordingCount > 0) return [];
  return [{
    kind: "drift",
    scanner: scanner.name,
    payload: {
      target_domain: context.target_domain,
      run_id: context.run_id,
      drift_signature: scanner.drift_signature,
      detected_by: "adversarial_transcript_scan",
      rationale: `Scanner ${scanner.name}: handoff summary asserts ${rankedLeads.length} ${scanner.summary_field}[] but run made 0 calls to ${scanner.required_invocation_tool}. Producer trace dropped.`,
      details: {
        scanner: scanner.name,
        summary_count: rankedLeads.length,
        required_invocation_tool: scanner.required_invocation_tool,
      },
    },
  }];
}

function synthesizeHandoffLedgerDiff(scanner, context) {
  const summary = context.handoff_summary;
  if (!summary || typeof summary !== "object") return [];
  const rankedLeads = Array.isArray(summary[scanner.summary_field])
    ? summary[scanner.summary_field]
    : [];
  const summaryCount = rankedLeads.length;
  if (summaryCount === 0) return [];
  const recordedLeads = Array.isArray(context.recorded_leads)
    ? context.recorded_leads
    : [];
  // The runtime tripwire correlates by run_id where possible; when the
  // recorded ledger lacks a per-run filter, the orchestrator passes the
  // pre-filtered subset in `context.recorded_leads`.
  const recordedCount = recordedLeads.length;
  if (recordedCount >= summaryCount) return [];
  // rationale_required_but_missing — derived from queue-policy toggle AND
  // recorded leads missing a rationale field. The scanner does not enforce
  // (that lives on bob_record_surface_leads in Y.12); it just surfaces the
  // co-presence signal so the operator can audit the producer.
  const policyRequiresRationale = Boolean(
    context.queue_policy
      && context.queue_policy.lead_rationale_required_when_below_threshold === true,
  );
  const anyRecordedLackRationale = recordedLeads.some((lead) => lead
    && (typeof lead.rationale !== "string" || !lead.rationale.trim()));
  const rationaleRequiredButMissing = policyRequiresRationale
    && anyRecordedLackRationale;
  return [{
    kind: "drift",
    scanner: scanner.name,
    payload: {
      target_domain: context.target_domain,
      run_id: context.run_id,
      drift_signature: scanner.drift_signature,
      detected_by: "adversarial_transcript_scan",
      rationale: `Scanner ${scanner.name}: handoff summary asserts ${summaryCount} ${scanner.summary_field}[] but surface-leads.json records ${recordedCount} entries for run_id ${context.run_id}. Silent lead threshold drop.`,
      details: {
        scanner: scanner.name,
        role: "surface-discovery",
        summary_count: summaryCount,
        recorded_count: recordedCount,
        rationale_required_but_missing: rationaleRequiredButMissing,
      },
    },
  }];
}

function truncate(value, max) {
  if (typeof value !== "string") return "";
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

const SYNTHESIZERS = Object.freeze({
  regex: synthesizeRegex,
  regex_with_context: synthesizeRegexWithContext,
  invocation_failure: synthesizeInvocationFailure,
  evidence_size: synthesizeEvidenceSize,
  handoff_invocation_diff: synthesizeHandoffInvocationDiff,
  handoff_ledger_diff: synthesizeHandoffLedgerDiff,
});

// ── public surface ─────────────────────────────────────────────────────────

// Resolve an operator-extended scanner (from queue-policy.friction_scanners[])
// into a runtime scanner record consumable by `synthesizeRegex`.
function normalizeOperatorScanner(entry) {
  if (!entry || typeof entry !== "object") return null;
  if (typeof entry.name !== "string" || !entry.name) return null;
  if (typeof entry.pattern !== "string" || !entry.pattern) return null;
  if (typeof entry.fallback_used !== "string" || !entry.fallback_used) return null;
  const frictionKind = entry.friction_kind === "tool_inadequate"
    ? "tool_inadequate"
    : "tool_absent";
  let pattern;
  try {
    pattern = new RegExp(entry.pattern);
  } catch {
    return null;
  }
  return Object.freeze({
    name: entry.name,
    kind: "regex",
    pattern,
    fallback_used: entry.fallback_used,
    friction_kind: frictionKind,
    // Operator-defined scanners must pick a wanted_tool/purpose that the
    // friction validator (Y.1) accepts. The scanner caller MUST set these
    // via the operator-extension prologue; we surface sensible defaults
    // that the test fixtures use for regression coverage.
    wanted_tool: typeof entry.wanted_tool === "string" && entry.wanted_tool
      ? entry.wanted_tool
      : "bob_http_scan",
    purpose: typeof entry.purpose === "string" && entry.purpose
      ? entry.purpose
      : "other",
  });
}

// `scanTranscript(scanners, context)` returns a flat array of synthetic
// records `[{kind: "friction"|"drift", scanner, payload}]`. Pure over its
// inputs (no fs/network reads) — the caller is responsible for assembling
// the context bundle (transcript_text, tool_invocations, evidence_files,
// handoff_summary, recorded_leads, queue_policy) before calling.
function scanTranscript(scanners, context) {
  if (!Array.isArray(scanners)) {
    throw new Error("scanTranscript: scanners must be an array");
  }
  if (!context || typeof context !== "object") {
    throw new Error("scanTranscript: context must be an object");
  }
  const out = [];
  for (const scanner of scanners) {
    const synth = SYNTHESIZERS[scanner.kind];
    if (!synth) continue;
    const records = synth(scanner, context);
    for (const record of records) out.push(record);
  }
  return out;
}

// Read evidence-file metadata under the session's evidence/ directory.
// Returns [] when the directory is missing. Each entry is
// `{relative_path, size_bytes}` rooted at sessionDir(domain).
function listEvidenceFiles(domain) {
  const root = sessionDir(domain);
  const evidenceRoot = path.join(root, "evidence");
  if (!fs.existsSync(evidenceRoot)) return [];
  const out = [];
  const stack = [evidenceRoot];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      let stat;
      try {
        stat = fs.statSync(abs);
      } catch {
        continue;
      }
      out.push({
        relative_path: path.relative(root, abs),
        size_bytes: stat.size,
      });
      if (out.length >= 1000) return out;
    }
  }
  return out;
}

module.exports = {
  DEFAULT_SCANNERS,
  SYNTHESIZERS,
  normalizeOperatorScanner,
  scanTranscript,
  listEvidenceFiles,
};

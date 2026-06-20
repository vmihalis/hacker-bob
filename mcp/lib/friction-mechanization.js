"use strict";

// CR-3 / I4 — server-side friction mechanization invoked by bob_apply_wave_merge.
//
// Mechanizes the load-bearing CR-3 invariant: promote a capability_friction
// group to a hypothesis at threshold WITHOUT an agent reading orchestrator prose.
// Also runs the single server-witnessable SCANNER (handoff_ledger_diff) over the
// merge-time context the SERVER already owns (raw handoff summaries + the
// surface-leads ledger; NO transcript, NO invocation stream). It forwards each
// synthetic through the SAME Y-P3 5-tuple-idempotent append the prose path uses
// — collapsing only same-detected_by duplicates (voluntary + synthetic coexist
// by design, Y-P11) — and auto-proposes ONLY tool_absent groups at threshold.
// tool_inadequate stays operator-gated (Y-P11) — this module NEVER promotes it.
//
// Scanners that require a transcript or an invocation stream (evidence_size,
// handoff_invocation_diff, the regex + invocation_failure scanners) are NOT in
// the server-witnessable set: the server cannot witness their inputs at merge
// time and running them with empty stubs MIS-fires (evidence_size would feed the
// auto-promotion threshold with false-positive tool_absent frictions). They stay
// reachable via the explicit bob_scan_transcript_for_friction agent call.
//
// MUST be called from inside an already-held session lock (withSessionLock is
// reentrant — storage.js:361-377). It assumes the caller has just written the
// merged session state.

const { readFrontierEvents, appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");
const { assertCapabilityFrictionPayload } = require("./capability-observations.js");
const {
  DEFAULT_SCANNERS,
  normalizeOperatorScanner,
  scanTranscript,
  listEvidenceFiles,
} = require("./friction-scanners.js");
const { loadQueuePolicy } = require("./queue-policy.js");
const { readSurfaceLeadsDocument } = require("./lead-intake.js");
const { handler: proposeFrictionPromotion } = require("./tools/propose-friction-promotion.js");

// The closed set of scanner KINDS whose inputs the SERVER can supply at merge
// time WITHOUT a subagent transcript AND WITHOUT a tool_invocations[] stream.
//
// Only handoff_ledger_diff qualifies: it correlates the raw handoff summary's
// ranked_leads[] against the per-run recorded_leads ledger — no invocation
// stream, no transcript. (silent_lead_threshold_drop, advisory/non-promoting.)
//
// EXCLUDED ON PURPOSE (verified against friction-scanners.js):
//   - evidence_size           — needs tool_invocations for hasBindingInvocation
//                               (L321-324); empty stream => always-fires =>
//                               false-positive tool_absent into the PROMOTION
//                               gate. NEVER server-witnessable.
//   - handoff_invocation_diff — counts bob_record_surface_leads invocations
//                               (L359-364); empty stream => always-fires drift.
//   - regex / regex_with_context / invocation_failure — need transcript_text /
//                               tool_invocations.
// All excluded scanners stay reachable through bob_scan_transcript_for_friction,
// which CAN pass transcript_text / tool_invocations.
const SERVER_WITNESSABLE_SCANNER_KINDS = Object.freeze(new Set([
  "handoff_ledger_diff",
]));

const DEFAULT_PROMOTION_THRESHOLD = 2;

// Same Y-P3 key the log tool uses (log-capability-friction.js:46-75). Kept
// byte-identical so a server-fired synthetic and an agent/prose re-forward of
// THAT SAME synthetic (same detected_by) collapse to a single frontier event.
// A voluntary agent_self_report for the same logical friction has a DIFFERENT
// detected_by and coexists by design (Y-P11) — not a double-fire.
function frictionIdempotencyKey(payload) {
  return [
    payload.run_id,
    payload.node_id,
    payload.wanted_tool,
    payload.purpose,
    payload.detected_by,
  ].join("");
}

function existingFrictionKeys(events) {
  const keys = new Set();
  for (const event of events) {
    if (!event || event.kind !== "observation.recorded") continue;
    const p = event.payload;
    if (!p || p.observation_kind !== "capability_friction_observed") continue;
    if (typeof p.run_id !== "string" || typeof p.node_id !== "string"
      || typeof p.wanted_tool !== "string" || typeof p.purpose !== "string"
      || typeof p.detected_by !== "string") continue;
    keys.add(frictionIdempotencyKey(p));
  }
  return keys;
}

function buildScannerList(operatorScanners) {
  const out = DEFAULT_SCANNERS.filter((s) => SERVER_WITNESSABLE_SCANNER_KINDS.has(s.kind));
  for (const entry of Array.isArray(operatorScanners) ? operatorScanners : []) {
    const normalized = normalizeOperatorScanner(entry);
    // Operator scanners normalize to kind:"regex" — not server-witnessable at
    // merge time (no transcript). They are deliberately NOT run here; the agent
    // scan tool runs them. Skip rather than silently mis-fire.
    if (normalized && SERVER_WITNESSABLE_SCANNER_KINDS.has(normalized.kind)) out.push(normalized);
  }
  return out;
}

// Build the per-run scan contexts the server can assemble from the merge.
// `runContexts` is [{ run_id, node_id, handoff_summary }] derived by the caller
// from the wave's received handoffs. `handoff_summary` MUST be the RAW handoff
// JSON object (which carries ranked_leads[] when a deep-surface-discovery agent
// emitted them) — NOT the validated wave-handoff payload, whose `summary` is a
// flattened string with no ranked_leads[] (wave-handoff-contracts.js:186-195).
function runMechanizedScan(domain, runContexts) {
  let queuePolicy = null;
  try { queuePolicy = loadQueuePolicy(domain); } catch { queuePolicy = null; }
  const operatorScanners = queuePolicy && Array.isArray(queuePolicy.friction_scanners)
    ? queuePolicy.friction_scanners : [];
  const scanners = buildScannerList(operatorScanners);
  if (scanners.length === 0) return { friction_records: [], drift_records: [] };

  const evidenceFiles = listEvidenceFiles(domain);
  let allLeads = [];
  try { allLeads = readSurfaceLeadsDocument(domain).leads || []; } catch { allLeads = []; }

  const friction = [];
  const drift = [];
  for (const rc of runContexts) {
    if (!rc || typeof rc.run_id !== "string" || !rc.run_id) continue;
    const recordedLeads = allLeads.filter((lead) => lead && typeof lead === "object"
      && [lead.source, lead.source_wave, lead.source_agent, lead.source_surface_id]
        .some((f) => typeof f === "string" && f.includes(rc.run_id)));
    const context = {
      target_domain: domain,
      run_id: rc.run_id,
      node_id: rc.node_id || rc.run_id,
      transcript_text: "",        // server has no transcript — regex scanners no-op
      tool_invocations: [],       // server has no invocation stream
      voluntary_frictions: [],
      evidence_files: evidenceFiles,
      handoff_summary: rc.handoff_summary || null, // RAW handoff JSON (ranked_leads[])
      recorded_leads: recordedLeads,
      queue_policy: queuePolicy,
    };
    for (const record of scanTranscript(scanners, context)) {
      if (record.kind === "friction") friction.push(record);
      else if (record.kind === "drift") drift.push(record);
    }
  }
  return { friction_records: friction, drift_records: drift };
}

// Forward friction synthetics through the SAME validator + Y-P3 idempotency as
// bob_log_capability_friction, but WITHOUT re-entering its withSessionLock
// (we are already inside the merge lock). Returns appended payloads. NOTE: the
// server-witnessable set currently produces only DRIFT records (advisory,
// handled separately), so this path is exercised today only by re-merge / future
// callers and by the unit tests; it stays correct and idempotent regardless.
function forwardFrictionSynthetics(domain, frictionRecords) {
  if (frictionRecords.length === 0) return [];
  const events = readFrontierEvents(domain);
  const seen = existingFrictionKeys(events);
  const lookupById = new Map();
  for (const e of events) if (e && typeof e.event_id === "string") lookupById.set(e.event_id, e);
  const lookupFrontierEvent = (id) => lookupById.get(id) || null;

  const appended = [];
  for (const record of frictionRecords) {
    let normalized;
    try {
      normalized = assertCapabilityFrictionPayload(record.payload, { lookupFrontierEvent });
    } catch {
      // A synthetic that fails the Y-P10 witness/shape validator is dropped
      // (best-effort tripwire — Y-P9). Never throw out of the merge.
      continue;
    }
    const key = frictionIdempotencyKey(normalized);
    // Y-P3 collapse vs an earlier same-detected_by append (re-merge / re-forward).
    // A voluntary agent_self_report with a different detected_by is NOT collapsed
    // here — it coexists by design (Y-P11). This is per-detected_by, not "no dup".
    if (seen.has(key)) continue;
    seen.add(key);
    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      surface_id: normalized.surface_id == null ? null : normalized.surface_id,
      payload: normalized,
      source: { artifact: "frontier-events.jsonl", tool: "bob_apply_wave_merge" },
    });
    appended.push({ event_id: event.event_id, payload: normalized });
  }
  return appended;
}

// Auto-propose ONLY tool_absent groups that reached threshold. tool_inadequate
// is never auto-promoted (Y-P11). Routes through the existing promotion handler
// so Y-P6 prior-promotion idempotency is inherited verbatim. Grouping is by
// (wanted_tool, surface_id) and is detected_by-independent, so a voluntary
// agent_self_report and a synthetic for the same group BOTH count toward the
// threshold (intended Y-P11 coexistence).
function autoProposeAbsentGroups(domain) {
  const events = readFrontierEvents(domain);
  let policy = null;
  try { policy = loadQueuePolicy(domain); } catch { policy = null; }
  const threshold = policy && Number.isInteger(policy.friction_promotion_threshold)
    ? policy.friction_promotion_threshold : DEFAULT_PROMOTION_THRESHOLD;

  const groups = new Map(); // key -> { wanted_tool, surface_id, count }
  for (const event of events) {
    if (!event || event.kind !== "observation.recorded") continue;
    const p = event.payload;
    if (!p || p.observation_kind !== "capability_friction_observed") continue;
    if (p.friction_kind !== "tool_absent") continue; // Y-P11: skip tool_inadequate
    const surfaceId = p.surface_id == null ? null : p.surface_id;
    const key = `${p.wanted_tool} ${surfaceId == null ? "" : surfaceId}`;
    const entry = groups.get(key) || { wanted_tool: p.wanted_tool, surface_id: surfaceId, count: 0 };
    entry.count += 1;
    groups.set(key, entry);
  }

  const proposals = [];
  for (const { wanted_tool: wantedTool, surface_id: surfaceId, count } of groups.values()) {
    if (count < threshold) continue;
    if (surfaceId == null) continue; // proposal requires a surface_ref; absent-surface groups skipped server-side
    try {
      const result = JSON.parse(proposeFrictionPromotion({
        target_domain: domain,
        wanted_tool: wantedTool,
        friction_kind: "tool_absent",
        surface_id: surfaceId,
      }));
      proposals.push(result); // includes idempotent:true short-circuits (Y-P6)
    } catch {
      // Promotion is best-effort at merge time; never fail the merge for it.
    }
  }
  return proposals;
}

function mechanizeWaveFriction(domain, runContexts) {
  const { friction_records, drift_records } = runMechanizedScan(domain, runContexts);
  const appendedFrictions = forwardFrictionSynthetics(domain, friction_records);
  const promotions = autoProposeAbsentGroups(domain);
  try { scheduleMaterialization(domain); } catch {}
  return {
    scanned_runs: runContexts.length,
    synthetic_frictions_appended: appendedFrictions.length,
    drift_records_detected: drift_records.length,
    promotions_proposed: promotions.filter((p) => p && p.promoted === true).length,
    promotions: promotions.map((p) => ({
      promoted: Boolean(p && p.promoted),
      idempotent: Boolean(p && p.idempotent),
      group_key: p && p.group_key, // {wanted_tool, friction_kind, surface_id} object
      event_id: p && p.event_id,
    })),
  };
}

module.exports = {
  mechanizeWaveFriction,
  // exported for unit tests / future re-merge callers / closure test
  frictionIdempotencyKey,
  forwardFrictionSynthetics,
  autoProposeAbsentGroups,
  buildScannerList,
  SERVER_WITNESSABLE_SCANNER_KINDS,
};

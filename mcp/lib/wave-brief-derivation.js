"use strict";

// Plane Y Cycle Y.5 — Wave-scheduler derivation helper.
//
// Y.5 wires the per-node capability-pack derivation (Y.4 / X.5) into the
// wave-side assignment brief. For each Surface/Claim wave assignment the
// scheduler materializes a synthetic Surface node, builds a wave-scoped
// 1-hop adjacency context (Y-P5), threads `friction_history` (Y-P6) and
// `target_class` (rev-4 O5), and calls the pure `derivePackForNode`. The
// caller (assignment-brief.js readAssignmentBrief) consumes the bounded
// result to (a) extend the brief's allowed-tools surface via the Y-P6
// friction widening, and (b) carry target-class auxiliaries (e.g.,
// phishing_fraud → public_intel + 3 browser tools) into the brief's
// allowed_tools_for_node[].
//
// `derivePackForNode` itself is PURE (Y-P4). All non-pure work
// (filesystem reads for friction events + queue policy + synthetic node
// adjacency) happens here, in the caller side, mirroring the
// friction-selection.js / target-class-pack-derivation.js layering. The
// helper exports `buildWaveBriefDerivation` which the brief renderer
// invokes with already-loaded session artifacts.

const fs = require("fs");

const {
  derivePackForNode,
} = require("./capability-pack-derivation.js");
const {
  selectRelevantFrictions,
} = require("./friction-selection.js");
const {
  assertTargetClass,
  TARGET_CLASS_VALUES,
} = require("./target-classes.js");
const {
  deriveAuxiliaryToolsForTargetClass,
} = require("./target-class-pack-derivation.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("./task-graph-events.js");
const {
  queuePolicyPath,
} = require("./paths.js");

// Synthetic node IDs for the wave-scheduler derivation path. The Plane X
// TaskGraph executor materializes real TG- nodes via task-graph events;
// the wave-side derivation needs a stable TG- prefix so the
// derivePackForNode validator (which rejects non-TG ids) accepts the
// synthetic input. Encoding the wave + surface id keeps the synthetic id
// deterministic per (wave, surface) pair.
function syntheticSurfaceNodeId(waveNumber, surfaceId) {
  // Encode unsafe chars conservatively — derivePackForNode validates the
  // TG- prefix only; the suffix is unbounded but we still keep it readable.
  const safeSurface = String(surfaceId).replace(/[^A-Za-z0-9._-]/g, "_");
  return `${TASK_GRAPH_NODE_ID_PREFIX}WS-w${waveNumber}-${safeSurface}`;
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Filter the frontier-event log down to capability_friction_observed
// payloads matching the assignment surface. Returns plain payloads — the
// `surface_id` field is required so friction-selection can wave-scope.
function frictionPayloadsForSurface(frontierEvents, surfaceId) {
  if (!Array.isArray(frontierEvents)) return [];
  if (typeof surfaceId !== "string" || surfaceId.length === 0) return [];
  const out = [];
  for (const event of frontierEvents) {
    if (!isPlainObject(event)) continue;
    // frontier-events.js uses `kind` (not `event_kind`) as the top-level
    // event kind field per FRONTIER_EVENT_KINDS / Y-P1.
    if (event.kind !== "observation.recorded") continue;
    const payload = isPlainObject(event.payload) ? event.payload : null;
    if (!payload) continue;
    if (payload.observation_kind !== "capability_friction_observed") continue;
    if (payload.surface_id !== surfaceId) continue;
    out.push(payload);
  }
  return out;
}

// Read the raw queue-policy JSON for the target without going through
// loadQueuePolicy's normalizer. The normalizer (mcp/lib/queue-policy.js)
// drops fields it does not yet know about; the rev-4 `target_class_default`
// field lands in Y.6 schema-side. Until Y.6 lands its writer, the
// caller-side resolver must read the raw file to surface the field that
// the (future) writer would set. Returns null on any I/O / parse failure
// so the brief composer never aborts.
function readRawQueuePolicy(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  let filePath;
  try { filePath = queuePolicyPath(domain); } catch { return null; }
  if (!fs.existsSync(filePath)) return null;
  let raw;
  try { raw = fs.readFileSync(filePath, "utf8"); } catch { return null; }
  try { return JSON.parse(raw); } catch { return null; }
}

// Resolve `target_class` per Y.5 Do step 1:
//   1. explicit `args.target_class` (caller override; not currently routed
//      through readAssignmentBrief but exposed here so future per-call
//      overrides need no helper edit)
//   2. queue-policy `target_class_default` from the raw JSON (Y.6 lands
//      the schema validator + writer; reading raw lets Y.5 surface the
//      value the moment Y.6's writer ships, with zero further edits)
//   3. null (the derivation function treats null as "no target_class
//      threading" — Y-P4 closed-enum default)
function resolveTargetClassForBrief({ explicitTargetClass, queuePolicy }) {
  if (typeof explicitTargetClass === "string" && explicitTargetClass.length > 0) {
    return assertTargetClass(explicitTargetClass);
  }
  if (isPlainObject(queuePolicy)) {
    const raw = queuePolicy.target_class_default;
    if (typeof raw === "string" && raw.length > 0) {
      // Defensive: queue-policy may carry a stale value that no longer
      // satisfies assertTargetClass (e.g., an operator hand-edit). Skip
      // rather than throw — the brief still composes without the axis.
      if (TARGET_CLASS_VALUES.includes(raw)) return raw;
    }
  }
  return null;
}

// Per-field caps for the synthetic-node surface_metadata triage scalars.
// Mirrors the ASSIGNMENT_BRIEF_SURFACE_SCALAR_LIMITS entries in
// assignment-brief.js so the synthetic node never inflates unboundedly even
// if a surface field carries an oversized scalar — same drop-in cap
// discipline the brief slim function applies (Y.5 caller-side, X-D4 bound).
const SYNTHETIC_SURFACE_TRIAGE_SCALAR_LIMITS = Object.freeze({
  surface_type: 80,
  attack_vector: 40,
  severity_ceiling: 40,
  network_reachable: 8,
});

const SYNTHETIC_SURFACE_TRIAGE_ARRAY_LIMITS = Object.freeze({
  // residual_hunt_targets is the incomplete-fix seed stamped by
  // repo-target.js. Threading it onto the synthetic node keeps the
  // derivation context faithful to the assignment surface; arrays are
  // capped at the same 20 the assignment-brief surface array limit uses.
  residual_hunt_targets: 20,
});

function isBriefScalar(value) {
  return value == null || ["string", "number", "boolean"].includes(typeof value);
}

function cappedSyntheticScalar(value, maxChars) {
  if (!isBriefScalar(value) || value == null) return null;
  const text = typeof value === "string" ? value : String(value);
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function cappedSyntheticArray(value, limit) {
  if (!Array.isArray(value)) return null;
  const out = [];
  for (const item of value) {
    if (item == null) continue;
    if (out.length >= limit) break;
    out.push(typeof item === "string" ? item : String(item));
  }
  return out;
}

// Materialize a synthetic Surface node + wave-scoped 1-hop graph context
// for `derivePackForNode`. The context is intentionally minimal (no
// adjacent nodes, no incident edges) because the wave-scheduler does not
// own a TaskGraph slice — Y-P5 says the wave scope IS the bound. The
// derivation function tolerates an empty graph_context and falls back to
// the default per-kind tool set.
//
// `surface_metadata` carries the triage scalars (`surface_type`,
// `attack_vector`, `severity_ceiling`, `network_reachable`) plus the
// `residual_hunt_targets` array when the assignment surface stamped them
// (OSS native-code surfaces from repo-target.js). Threading these keeps
// the synthetic node faithful to the assignment surface — without them a
// future derivation reader that branched on `network_reachable` would see
// `undefined` and silently misroute. Caps mirror the assignment-brief
// slim discipline so an oversized scalar never inflates the synthetic
// node.
function buildSyntheticSurfaceNode({ surfaceObj, surfaceId, waveNumber }) {
  const surfaceRefs = [surfaceId];
  const source = surfaceObj && typeof surfaceObj === "object" && !Array.isArray(surfaceObj)
    ? surfaceObj
    : {};
  const metadata = {};
  for (const [field, maxChars] of Object.entries(SYNTHETIC_SURFACE_TRIAGE_SCALAR_LIMITS)) {
    const value = cappedSyntheticScalar(source[field], maxChars);
    metadata[field] = value;
  }
  for (const [field, limit] of Object.entries(SYNTHETIC_SURFACE_TRIAGE_ARRAY_LIMITS)) {
    const value = cappedSyntheticArray(source[field], limit);
    if (value != null) metadata[field] = value;
  }
  return {
    node_id: syntheticSurfaceNodeId(waveNumber, surfaceId),
    kind: "surface",
    surface_refs: surfaceRefs,
    // Echo metadata onto the node so downstream callers can read it
    // without reaching into the assignment surface; matches the X.5
    // contract that node.surface_metadata may live alongside surface_refs.
    surface_metadata: {
      [surfaceId]: metadata,
    },
  };
}

function buildEmptyAdjacencyContext() {
  return {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {},
  };
}

// Top-level helper. The brief renderer feeds in already-loaded session
// artifacts; this function performs the pure derivation work + returns a
// bounded summary the renderer adds to the brief JSON.
//
// `queuePolicy` is optional. When omitted, the helper resolves the raw
// queue-policy JSON from `domain` directly — bypassing the normalizer
// that drops the rev-4 `target_class_default` field until Y.6 lands the
// schema-level support. Pass an explicit queuePolicy object only when
// the caller already holds the normalized policy AND has populated
// `target_class_default` on it.
function buildWaveBriefDerivation({
  surfaceObj,
  surfaceId,
  waveNumber,
  frontierEvents,
  queuePolicy,
  domain,
  explicitTargetClass,
  includeInadequacy,
}) {
  const syntheticNode = buildSyntheticSurfaceNode({ surfaceObj, surfaceId, waveNumber });
  const allFrictionPayloads = frictionPayloadsForSurface(frontierEvents, surfaceId);
  const frictionHistory = selectRelevantFrictions(
    allFrictionPayloads,
    syntheticNode,
    { include_inadequacy: includeInadequacy === true },
  );
  const effectivePolicy = queuePolicy != null ? queuePolicy : readRawQueuePolicy(domain);
  const targetClass = resolveTargetClassForBrief({ explicitTargetClass, queuePolicy: effectivePolicy });
  const derivation = derivePackForNode(
    syntheticNode,
    buildEmptyAdjacencyContext(),
    [],
    null,
    {
      friction_history: frictionHistory,
      target_class: targetClass,
    },
  );

  // Bounded summary — the renderer adds this to the brief JSON. We
  // surface ONLY the Y.5-added tools (friction-widened wanted_tools +
  // target-class auxiliaries) under `added_tools[]`, NOT the full
  // derivation.allowed_tools_for_node[]. The full union is already
  // present implicitly via per-spawn frontmatter narrowing on the
  // dispatched evaluator shell (Y.5 Do step 5); echoing it back into the
  // brief JSON would (a) inflate the brief budget unnecessarily and
  // (b) re-surface per-pack default tools (e.g., bob_browser_* under the
  // web pack) at brief sites that the lens-specific renderers
  // intentionally suppress (see T.4 browser_workflow lens regression).
  // `added_tools[]` is the load-bearing Y-P6 widening signal; the full
  // pack stays on the role-bundle layer.
  const seenAdded = new Set();
  const addedTools = [];
  for (const record of frictionHistory) {
    if (!isPlainObject(record)) continue;
    if (typeof record.wanted_tool === "string" && record.wanted_tool.length > 0) {
      if (!seenAdded.has(record.wanted_tool)) {
        seenAdded.add(record.wanted_tool);
        addedTools.push(record.wanted_tool);
      }
    }
  }
  const targetClassAuxTools = targetClass
    ? deriveAuxiliaryToolsForTargetClass(targetClass).slice()
    : [];
  for (const tool of targetClassAuxTools) {
    if (!seenAdded.has(tool)) {
      seenAdded.add(tool);
      addedTools.push(tool);
    }
  }
  addedTools.sort();

  return {
    synthetic_node_id: syntheticNode.node_id,
    target_class: targetClass,
    friction_history_count: frictionHistory.length,
    friction_history_total_for_surface: allFrictionPayloads.length,
    // `added_tools[]` is the Y-P6 + O5 widening that THIS brief
    // composition contributes on top of the base capability pack. Empty
    // when there is no friction history and no target_class auxiliary
    // surface. Wave-dispatched evaluators receive the full union via
    // frontmatter narrowing (Y.5 Do step 5).
    added_tools: addedTools,
    target_class_auxiliary_tools: targetClassAuxTools,
    // technique_pack_ids surfaces the Y.4 brief_emphasis projection so
    // operators can audit which pack ids the pure derivation chose
    // without re-running it. Bounded (cap inherited from
    // derivePackForNode's per-kind logic).
    technique_pack_ids: derivation.brief_emphasis.technique_pack_ids
      ? derivation.brief_emphasis.technique_pack_ids.slice()
      : [],
  };
}

module.exports = {
  buildWaveBriefDerivation,
  buildSyntheticSurfaceNode,
  frictionPayloadsForSurface,
  readRawQueuePolicy,
  resolveTargetClassForBrief,
  syntheticSurfaceNodeId,
};

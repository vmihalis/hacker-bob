"use strict";

// F1 — mechanism-graph chain substrate.
//
// queryMechanismView (surface-graph.js) returns a flat, unannotated mechanism
// EDGE list (principal/credential/policy_gate/effect/intervention adjacency). It
// is single-hop adjacency, not a path space, and it carries no signal of which
// effects are security-relevant. F1 projects that COVERED graph — the graph is
// itself a deterministic projection of observed session facts (auth-differential
// results, chain trees, role tables), so every node in it was OBSERVED — into
// the bounded principal->...->effect PATH SPACE the chain phase (F2) traverses,
// each path's terminal effect annotated `finding_backed`.
//
// finding_backed is derived from the effect-node id the surface-graph builder
// mints ONLY on a real divergence (`effect:<endpoint>:unauth_succeeds_where_
// auth_blocked`) or a confirmed chain verdict (`effect:chain:success`) — never
// from edge.confidence (a builder-asserted prior, forgeable) and never from a
// frontier event. Cross-surface composition is supplied separately as the COVERED
// A2 transition hops (verified cross-surface links a per-surface mechanism path
// cannot express).
//
// Pure, read-only, deterministic, fail-soft: it annotates and enumerates, never
// gates, never spawns, never writes a ledger. F2 (not F1) fans one chain-verifier
// per emitted path.

const crypto = require("crypto");

const MECHANISM_PATHS_HARD_CAP = 200;
const DEFAULT_MAX_HOPS = 4;
const MAX_HOPS_HARD_CAP = 8;
// A global ceiling on total DFS edge-traversals, independent of maxPaths. maxPaths
// bounds the COLLECTED paths; this bounds the WORK, so a pathologically dense
// mechanism graph (high fan-out, few effect terminals) cannot explore
// exponentially many simple paths before the path cap trips.
const MAX_WALK_STEPS = 20000;

// An effect node is finding-backed when its id encodes a real security
// divergence. The builder emits these ids only from observed facts, so the
// pattern is a deterministic, non-forgeable finding signal — distinct from a
// benign `effect:<endpoint>:<profile>:<response_class>` response node.
function isFindingBackedEffect(nodeId) {
  if (typeof nodeId !== "string") return false;
  return nodeId.includes("unauth_succeeds_where_auth_blocked")
    || nodeId === "effect:chain:success"
    || nodeId.endsWith(":success");
}

// The object-auth divergence effect grammar the surface-graph builder mints on a
// real auth-differential finding: `effect:<endpoint>:unauth_succeeds_where_auth_
// blocked`. Parsing the endpoint back out is the single, deterministic join key
// a chain-verifier needs to re-execute the guard live. Returns null for any other
// effect (benign responses, chain verdicts) — those are not object-auth verifiable.
const OBJECT_AUTH_DIVERGENCE_SUFFIX = ":unauth_succeeds_where_auth_blocked";

function parseObjectAuthEffectEndpoint(terminalEffect) {
  if (typeof terminalEffect !== "string") return null;
  if (!terminalEffect.startsWith("effect:")) return null;
  if (!terminalEffect.endsWith(OBJECT_AUTH_DIVERGENCE_SUFFIX)) return null;
  const middle = terminalEffect.slice(
    "effect:".length,
    terminalEffect.length - OBJECT_AUTH_DIVERGENCE_SUFFIX.length,
  );
  return middle.length > 0 ? middle : null;
}

// The CB-D1 object-auth control battery a chain-verifier must develop and run
// live for a guard leaf. AUTHORITY is composition-live-verifier.js (the
// SAME_OBJECT / DIFF_OBJECT / ANON control sets it validates); this list is the
// brief's hint to the agent of which controls to plan — the verifier remains the
// validator. Frozen so the projection stays deterministic.
const COMPOSITION_GUARD_CONTROLS = Object.freeze([
  "attacker_owned_control",
  "victim_auth_same_object",
  "no_auth_same_object",
  "nonexistent_object",
  "public_object_check",
  "stale_session_check",
  "cache_nonce_check",
]);

// F2 — project one F1 candidate path into a chain-verifier brief skeleton. It
// SELECTS (verifiable iff the path is finding-backed AND its terminal effect is a
// parseable object-auth divergence) and provides the deterministic topology the
// agent starts from — the parsed endpoint, the guard hop's edge_id, and the
// control battery to plan. It DELIBERATELY does NOT fabricate the live re-
// execution inputs (evidence_ref, primary attack request, control_plan): those
// are the chain-verifier agent's live work, and minting them here would forge the
// audit-graded composition-verified ledger. The orchestrator fans one verifier
// per verifiable path; each agent develops the leaves; the orchestrator confirms
// via bob_verify_composition_path (the sole, MCP-write-only verified_pass writer).
function compositionBriefForPath(path) {
  const terminalEffect = path && path.terminal_effect;
  const findingBacked = !!(path && path.finding_backed);
  const endpoint = parseObjectAuthEffectEndpoint(terminalEffect);
  const hops = Array.isArray(path && path.hops) ? path.hops : [];
  // The guard hop is the last edge reaching the terminal effect — the link the
  // verifier re-executes the auth differential on.
  const guardHop = hops.length > 0 ? hops[hops.length - 1] : null;
  // Verifiable requires a guard edge too: the brief is the input the verifier
  // re-executes on, so a finding-backed path with no edge is not verifiable.
  // (enumerateCandidatePaths never emits a hop-less path, but the standalone
  // helper must stay self-consistent for any caller.)
  const verifiable = findingBacked && endpoint !== null && guardHop !== null;
  let reason = null;
  if (!verifiable) {
    reason = endpoint === null
      ? "terminal effect is not a parseable object-auth divergence"
      : "path is not finding-backed";
  }
  return {
    verifiable,
    terminal_endpoint: endpoint,
    guard_edge_id: guardHop ? guardHop.edge_id : null,
    // Left for the chain-verifier agent to develop LIVE — never fabricated here.
    controls_required: verifiable ? COMPOSITION_GUARD_CONTROLS : [],
    reason,
  };
}

function pathId(edgeHashes) {
  return `mpath-${crypto.createHash("sha256").update(edgeHashes.join("|")).digest("hex").slice(0, 16)}`;
}

// Covered A2 transition hops (verified cross-surface links). A transition edge is
// an available cross-surface hop for F2 when at least one of its (edge x
// bug_class) cells is covered. covered_bug_classes = the per-kind axis minus the
// still-uncovered children the floor would re-emit.
function coveredTransitionHops(domain) {
  try {
    const { readCoverageRecordsFromJsonl } = require("./frontier/coverage.js");
    const { enumerateTransitionCellFloor } = require("./session/assignment-brief.js");
    const { TRANSITION_BUG_CLASS_AXIS } = require("./capability/capability-packs.js");
    const { CHILD_FANOUT_HARD_CAP } = require("./capability/capability-pack-derivation.js");
    const coverageRecords = readCoverageRecordsFromJsonl(domain);
    const hops = [];
    for (const edge of enumerateTransitionCellFloor({
      domain,
      coverageRecords,
      maxChildren: CHILD_FANOUT_HARD_CAP,
    })) {
      const plan = edge.plan;
      const covered = Number.isFinite(plan && plan.covered_pruned_count) ? plan.covered_pruned_count : 0;
      if (covered <= 0) continue;
      const axis = TRANSITION_BUG_CLASS_AXIS[edge.transition_kind] || [];
      const uncovered = new Set(
        (plan && Array.isArray(plan.children) ? plan.children : []).map((c) => c.bug_class),
      );
      const coveredBugClasses = axis.filter((bc) => !uncovered.has(bc));
      hops.push({
        edge_token: edge.edge_token,
        from_surface: edge.from_surface,
        to_surface: edge.to_surface,
        transition_kind: edge.transition_kind,
        covered_bug_classes: coveredBugClasses,
      });
    }
    hops.sort((a, b) => a.edge_token.localeCompare(b.edge_token));
    return hops;
  } catch {
    return [];
  }
}

// Enumerate the bounded principal->...->effect path space over the mechanism
// graph. Deterministic: principals iterated in id order, outgoing edges in
// edge_hash order, paths capped. A path is recorded whenever the walk reaches an
// effect node; the walk continues (up to maxHops) so multi-hop chains surface too.
function enumerateCandidatePaths(domain, options = {}) {
  const result = {
    paths: [],
    transition_hops: [],
    total_enumerated: 0,
    truncated: false,
    mechanism_edges: 0,
  };
  if (typeof domain !== "string" || domain.length === 0) return result;

  const maxPaths = Number.isInteger(options.max_paths) && options.max_paths > 0
    ? Math.min(options.max_paths, MECHANISM_PATHS_HARD_CAP)
    : MECHANISM_PATHS_HARD_CAP;
  const maxHops = Number.isInteger(options.max_hops) && options.max_hops > 0
    ? Math.min(options.max_hops, MAX_HOPS_HARD_CAP)
    : DEFAULT_MAX_HOPS;

  let edges;
  try {
    const { queryMechanismView } = require("./frontier/surface-graph.js");
    const view = queryMechanismView({ target_domain: domain, limit: 1000 });
    edges = Array.isArray(view.edges) ? view.edges : [];
  } catch {
    return result;
  }
  result.mechanism_edges = edges.length;
  if (edges.length === 0) {
    result.transition_hops = coveredTransitionHops(domain);
    return result;
  }

  // Adjacency over node ids (already prefixed + unique), and a node-id -> type
  // map. Outgoing edges sorted by edge_hash for deterministic traversal.
  const outgoing = new Map();
  const nodeType = new Map();
  for (const edge of edges) {
    if (!edge || !edge.source || !edge.target) continue;
    nodeType.set(edge.source.id, edge.source.type);
    nodeType.set(edge.target.id, edge.target.type);
    if (!outgoing.has(edge.source.id)) outgoing.set(edge.source.id, []);
    outgoing.get(edge.source.id).push(edge);
  }
  for (const list of outgoing.values()) {
    list.sort((a, b) => String(a.edge_hash).localeCompare(String(b.edge_hash)));
  }

  const principals = [...nodeType.entries()]
    .filter(([, type]) => type === "principal")
    .map(([id]) => id)
    .sort();

  const collected = [];
  let truncated = false;
  let steps = 0;

  const walk = (nodeId, visited, hops) => {
    if (truncated) return;
    if (nodeType.get(nodeId) === "effect") {
      const terminal = nodeId;
      const candidate = {
        path_id: pathId(hops.map((h) => h.edge_id)),
        hops: hops.map((h) => ({ ...h })),
        terminal_effect: terminal,
        hop_count: hops.length,
        finding_backed: isFindingBackedEffect(terminal),
      };
      // F2: the chain-verifier brief skeleton — which paths are verifiable and
      // the deterministic topology the agent develops its live leaves from.
      candidate.composition = compositionBriefForPath(candidate);
      collected.push(candidate);
      if (collected.length >= maxPaths) { truncated = true; return; }
    }
    if (hops.length >= maxHops) return;
    const next = outgoing.get(nodeId) || [];
    for (const edge of next) {
      if (visited.has(edge.target.id)) continue;
      if (steps >= MAX_WALK_STEPS) { truncated = true; return; }
      steps += 1;
      visited.add(edge.target.id);
      hops.push({
        edge_id: edge.edge_hash,
        edge_type: edge.edge_type,
        from_node: edge.source.id,
        to_node: edge.target.id,
      });
      walk(edge.target.id, visited, hops);
      hops.pop();
      visited.delete(edge.target.id);
      if (truncated) return;
    }
  };

  for (const principal of principals) {
    if (truncated) break;
    walk(principal, new Set([principal]), []);
  }

  // Order: finding-backed first, then longer chains, then deterministic path_id.
  collected.sort((a, b) => {
    if (a.finding_backed !== b.finding_backed) return a.finding_backed ? -1 : 1;
    if (b.hop_count !== a.hop_count) return b.hop_count - a.hop_count;
    return a.path_id.localeCompare(b.path_id);
  });

  result.paths = collected.slice(0, maxPaths);
  result.total_enumerated = collected.length;
  result.truncated = truncated;
  result.transition_hops = coveredTransitionHops(domain);
  return result;
}

module.exports = {
  isFindingBackedEffect,
  parseObjectAuthEffectEndpoint,
  COMPOSITION_GUARD_CONTROLS,
  compositionBriefForPath,
  coveredTransitionHops,
  enumerateCandidatePaths,
};

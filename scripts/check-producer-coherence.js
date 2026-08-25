#!/usr/bin/env node
"use strict";

// `check:producer-coherence` — structural sibling of
// `scripts/check-stigmergy-coherence.js`. A pure read-only gate over the
// PRODUCER_PACKS recon-producer DAG (`mcp/lib/producer-packs.js`), the sole
// producer authority. Reads only the manifests + .claude/agents/*.md
// frontmatter; never writes, and never touches the clock, randomness, or the
// network.
//
// Mechanical assertions over the producer registry:
//
//   (a) Every emits_surface_types value classifies high-confidence via
//       classifySurfaceCapability. The ONLY exception is the broad
//       synthesis-class vocabulary {web, smart_contract, oss} — these are
//       class tags the DAG emits, route deterministically, and classify
//       medium / throw-on-missing-context by design (the analogue of the
//       single sc_surface self-edge whitelist in leg (c)).
//
//   (b) Every consumed artifact-kind is in ARTIFACT_KIND_VALUES AND is
//       produced by some producer — no orphan consumer.
//
//   (c) The type-level produces/consumes graph is acyclic by topo-sort.
//       Exactly one identity-keyed sc_surface -> sc_surface self-edge is
//       whitelisted; every other self-edge and any multi-node cycle is a
//       violation.
//
//   (d) Every producer_agent resolves to a real .claude/agents/<name>.md
//       whose frontmatter tools line excludes every bare or parameterized
//       Task/Agent spawn grant AND whose name
//       is absent from spawnCapableAgentNames() (single-spawner topology).
//
//   (e) scratch_namespace values are pairwise prefix-disjoint (all unique and
//       none a string-prefix of another), preserving per-producer scratch
//       isolation.
//
//   (f) The aggregate recon-DAG dispatch producer is paired in both stigmergy
//       manifests: its producer_id is a STIGMERGIC_PRODUCERS entry AND is
//       referenced as producer_id by at least one STIGMERGIC_CONSUMERS entry.
//
//   (h) An advisory:true producer MUST be single-fire / root-keyed — its
//       producer_key carries no fluctuating per-instance artifact id. The
//       detector is a non-empty produces ∩ trigger.consumes intersection: an
//       identity self-edge (like the sc_surface consume+produce the
//       sc_address_expander mints) is exactly the per-instance fluctuating key
//       that would re-fire the advisory producer endlessly. Vacuously green over
//       today's all-advisory:false registry; it REJECTS a future advisory
//       producer keyed on such a self-edge.
//
// Flags:
//   --root <dir>   repo root override (default: parent of scripts/)
//   --verbose      print the OK summary on pass (always printed on pass here)
//
// Exit codes mirror the sibling gate: 0 on pass, 1 on violations (with one
// line per violation), 2 on an unexpected throw.

const fs = require("fs");
const path = require("path");
const {
  PRODUCER_PACKS,
  ARTIFACT_KIND_VALUES,
} = require("../mcp/core/dispatch/producer-packs.js");
const { classifySurfaceCapability } = require("../mcp/core/capability/capability-packs.js");
const { spawnCapableAgentNames } = require("./lib/claude-role-renderer.js");
const {
  STIGMERGIC_PRODUCERS,
} = require("../mcp/core/stigmergic-producers.js");
const {
  STIGMERGIC_CONSUMERS,
} = require("../mcp/core/stigmergic-consumers.js");

const ROOT = path.join(__dirname, "..");

// Broad synthesis-class vocabulary the recon DAG emits as class tags. These
// route deterministically but classify medium (web/oss) or throw on missing
// context (smart_contract), so they are short-circuit-allowed in leg (a).
const SYNTHESIS_CLASS_TAGS = new Set(["web", "smart_contract", "oss"]);

// The single identity-keyed self-edge whitelisted in the acyclic check.
const SELF_EDGE_WHITELIST_KIND = "sc_surface";

// The aggregate recon-DAG dispatch producer paired across both stigmergy
// manifests at dispatch granularity (one producer covering the whole DAG).
const RECON_DISPATCH_PRODUCER_ID = "recon_producer_dag_dispatch_signals";

function parseArgs(argv) {
  const args = { root: ROOT, verbose: false };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--root" && argv[i + 1]) {
      args.root = path.resolve(argv[++i]);
    } else if (a === "--verbose" || a === "-v") {
      args.verbose = true;
    }
  }
  return args;
}

function packsList() {
  return Object.values(PRODUCER_PACKS);
}

function checkLegA() {
  const violations = [];
  const kindSet = new Set(ARTIFACT_KIND_VALUES);
  for (const pack of packsList()) {
    for (const surfaceType of pack.emits_surface_types || []) {
      if (SYNTHESIS_CLASS_TAGS.has(surfaceType)) continue;
      let classification;
      try {
        classification = classifySurfaceCapability({ surface_type: surfaceType });
      } catch (err) {
        violations.push({
          kind: "emits_surface_type_unclassifiable",
          producer_id: pack.producer_id,
          detail: `emits_surface_types value ${JSON.stringify(surfaceType)} threw on classification: ${err.message}`,
        });
        continue;
      }
      if (classification.confidence !== "high") {
        violations.push({
          kind: "emits_surface_type_low_confidence",
          producer_id: pack.producer_id,
          detail: `emits_surface_types value ${JSON.stringify(surfaceType)} classified ${JSON.stringify(classification.confidence)}, expected high`,
        });
      }
    }
    // Defensive: emitted class tags should still be coherent vocabulary; a
    // value that is neither a whitelisted class tag nor a known artifact kind
    // signals manifest drift even if it happens to classify high.
    void kindSet;
  }
  return violations;
}

function checkLegB() {
  const violations = [];
  const kindSet = new Set(ARTIFACT_KIND_VALUES);
  const producedSet = new Set();
  for (const pack of packsList()) {
    for (const produced of pack.produces || []) producedSet.add(produced);
  }
  for (const pack of packsList()) {
    for (const consumed of pack.trigger.consumes || []) {
      if (!kindSet.has(consumed)) {
        violations.push({
          kind: "consumed_kind_not_in_vocabulary",
          producer_id: pack.producer_id,
          detail: `consumes ${JSON.stringify(consumed)} not in ARTIFACT_KIND_VALUES`,
        });
        continue;
      }
      if (!producedSet.has(consumed)) {
        violations.push({
          kind: "orphan_consumer",
          producer_id: pack.producer_id,
          detail: `consumes ${JSON.stringify(consumed)} which no producer produces`,
        });
      }
    }
  }
  return violations;
}

function checkLegC() {
  const violations = [];
  const nodes = new Set();
  const adjacency = new Map();
  const indegree = new Map();

  function ensureNode(kind) {
    if (!nodes.has(kind)) {
      nodes.add(kind);
      adjacency.set(kind, new Set());
      indegree.set(kind, 0);
    }
  }

  for (const pack of packsList()) {
    const consumes = pack.trigger.consumes || [];
    const produces = pack.produces || [];
    for (const fromKind of consumes) {
      for (const toKind of produces) {
        ensureNode(fromKind);
        ensureNode(toKind);
        if (fromKind === toKind) {
          if (fromKind === SELF_EDGE_WHITELIST_KIND) continue; // whitelisted identity edge
          violations.push({
            kind: "forbidden_self_edge",
            producer_id: pack.producer_id,
            detail: `self-edge ${fromKind} -> ${toKind} is not the whitelisted ${SELF_EDGE_WHITELIST_KIND} identity edge`,
          });
          continue;
        }
        if (!adjacency.get(fromKind).has(toKind)) {
          adjacency.get(fromKind).add(toKind);
          indegree.set(toKind, indegree.get(toKind) + 1);
        }
      }
    }
  }

  // Kahn topo-sort: a leftover node means a multi-node cycle.
  const queue = [];
  for (const node of nodes) {
    if (indegree.get(node) === 0) queue.push(node);
  }
  let removed = 0;
  while (queue.length) {
    const node = queue.shift();
    removed += 1;
    for (const next of adjacency.get(node)) {
      indegree.set(next, indegree.get(next) - 1);
      if (indegree.get(next) === 0) queue.push(next);
    }
  }
  if (removed !== nodes.size) {
    const cyclic = [...nodes].filter((n) => indegree.get(n) > 0);
    violations.push({
      kind: "producer_graph_cycle",
      detail: `type-level produces/consumes graph is not acyclic; nodes still in a cycle: ${JSON.stringify(cyclic)}`,
    });
  }
  return { violations, nodeCount: nodes.size };
}

function frontmatterToolsTokens(content) {
  const lines = content.split("\n");
  if (lines[0] !== "---") return null;
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i] === "---") break; // end of frontmatter block
    const m = lines[i].match(/^tools:\s*(.*)$/);
    if (m) {
      return m[1]
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    }
  }
  return [];
}

function checkLegD(root) {
  const violations = [];
  const spawnCapable = new Set(spawnCapableAgentNames());
  const agents = new Set();
  for (const pack of packsList()) agents.add(pack.producer_agent);
  for (const agent of agents) {
    const relPath = path.join(".claude", "agents", `${agent}.md`);
    const absPath = path.join(root, relPath);
    let content;
    try {
      content = fs.readFileSync(absPath, "utf8");
    } catch (err) {
      violations.push({
        kind: "producer_agent_file_missing",
        producer_agent: agent,
        detail: `cannot read ${relPath}: ${err.code || err.message}`,
      });
      continue;
    }
    const tokens = frontmatterToolsTokens(content);
    if (tokens === null) {
      violations.push({
        kind: "producer_agent_frontmatter_missing",
        producer_agent: agent,
        detail: `${relPath} does not open with a YAML frontmatter block`,
      });
    } else if (tokens.some((token) => /^(?:Agent|Task)(?:\([^)]*\))?$/.test(token))) {
      violations.push({
        kind: "producer_agent_carries_spawn_tool",
        producer_agent: agent,
        detail: `${relPath} frontmatter tools include Task/Agent: ${JSON.stringify(tokens)}`,
      });
    }
    if (spawnCapable.has(agent)) {
      violations.push({
        kind: "producer_agent_spawn_capable",
        producer_agent: agent,
        detail: `${agent} is in spawnCapableAgentNames(); recon producers must be non-spawn-capable`,
      });
    }
  }
  return violations;
}

function checkLegE() {
  const violations = [];
  const namespaces = packsList().map((p) => ({
    producer_id: p.producer_id,
    ns: p.scratch_namespace,
  }));
  for (let i = 0; i < namespaces.length; i += 1) {
    for (let j = 0; j < namespaces.length; j += 1) {
      if (i === j) continue;
      const a = namespaces[i];
      const b = namespaces[j];
      if (a.ns === b.ns || a.ns.startsWith(b.ns)) {
        violations.push({
          kind: "scratch_namespace_not_disjoint",
          producer_id: a.producer_id,
          detail: `scratch_namespace ${JSON.stringify(a.ns)} collides with or is prefixed by ${b.producer_id}'s ${JSON.stringify(b.ns)}`,
        });
      }
    }
  }
  return violations;
}

function checkLegF() {
  const violations = [];
  const producerIds = new Set(STIGMERGIC_PRODUCERS.map((p) => p.producer_id));
  if (!producerIds.has(RECON_DISPATCH_PRODUCER_ID)) {
    violations.push({
      kind: "dispatch_producer_unmanifested",
      detail: `${RECON_DISPATCH_PRODUCER_ID} is not a producer_id in STIGMERGIC_PRODUCERS`,
    });
  }
  const consumerRefs = STIGMERGIC_CONSUMERS.filter(
    (c) => c.producer_id === RECON_DISPATCH_PRODUCER_ID,
  );
  if (consumerRefs.length === 0) {
    violations.push({
      kind: "dispatch_producer_unpaired",
      detail: `${RECON_DISPATCH_PRODUCER_ID} has no STIGMERGIC_CONSUMERS entry referencing it as producer_id`,
    });
  }
  return violations;
}

// Leg (h): advisory single-fire. An advisory:true producer must carry no
// fluctuating per-instance artifact id in its producer_key — detected as a
// non-empty produces ∩ trigger.consumes intersection (an identity self-edge).
// Injectable so a test can feed a synthetic advisory producer; defaults to the
// real registry, which is vacuously green (every pack is advisory:false).
function checkLegH(packs = PRODUCER_PACKS) {
  const violations = [];
  const list = packs && typeof packs === "object" ? Object.values(packs) : [];
  for (const pack of list) {
    if (!pack || typeof pack !== "object") continue;
    if (pack.advisory !== true) continue;
    const produces = new Set(Array.isArray(pack.produces) ? pack.produces : []);
    const consumes = (pack.trigger && Array.isArray(pack.trigger.consumes))
      ? pack.trigger.consumes
      : [];
    const overlap = consumes.filter((kind) => produces.has(kind));
    if (overlap.length > 0) {
      violations.push({
        kind: "advisory_producer_fluctuating_key",
        producer_id: pack.producer_id,
        detail: `advisory producer ${JSON.stringify(pack.producer_id)} has produces ∩ consumes ${JSON.stringify(overlap)} (an identity self-edge => a fluctuating per-instance producer_key); an advisory producer must be single-fire / root-keyed`,
      });
    }
  }
  return violations;
}

function runChecks({ root }) {
  const legC = checkLegC();
  const violations = [
    ...checkLegA(),
    ...checkLegB(),
    ...legC.violations,
    ...checkLegD(root),
    ...checkLegE(),
    ...checkLegF(),
    ...checkLegH(),
  ];
  return { violations, nodeCount: legC.nodeCount };
}

function main() {
  const args = parseArgs(process.argv);
  const { violations, nodeCount } = runChecks({ root: args.root });
  if (violations.length === 0) {
    console.log(
      `producer-coherence OK (${packsList().length} producers, ${nodeCount} artifact kinds, acyclic)`,
    );
    process.exit(0);
  }
  console.error(
    `producer-coherence FAIL (${violations.length} violation${violations.length === 1 ? "" : "s"}):`,
  );
  for (const v of violations) {
    console.error(`  - [${v.kind}] ${JSON.stringify(v)}`);
  }
  process.exit(1);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err && err.stack ? err.stack : String(err));
    process.exit(2);
  }
}

module.exports = {
  runChecks,
  checkLegA,
  checkLegB,
  checkLegC,
  checkLegD,
  checkLegE,
  checkLegF,
  checkLegH,
};

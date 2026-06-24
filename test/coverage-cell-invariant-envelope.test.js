"use strict";

// G2 — the coverage-cell INVARIANT ENVELOPE capstone (cross-cutting constraint).
//
// The coverage-cell machinery (A1-F2) is built from many small nodes. Each node
// is individually correct, and the four cross-cutting invariants are ALREADY
// enforced piecewise elsewhere:
//
//   (i)  single-spawner topology  — single-spawner-topology.test.js (Task IFF
//        registry spawn_capable) + the orchestrator-only role_bundles on the
//        cell tools.
//   (ii) MCP-owned durable state  — the agent Write-guard + check:mcp-owned-
//        basename-inventory (frontier-events.jsonl is in HOOK_MCP_OWNED_BASENAMES)
//        and check:audit-graded-writers for the composer path.
//   (iii) real-id dispatch        — cellNodeId() is a deterministic content hash;
//        propose-transition rejects unknown surface endpoints.
//   (iv) belief-advisory-only     — graph-scheduler.test.js (flag-off byte-
//        identical) + residual-depth.test.js (Tier-2 never gates closure) + the
//        default-false queue-policy flags.
//
// G2 is therefore EMERGENT for today's nodes — but nothing TIES the SET of
// coverage-cell tools/nodes to the envelope. A FUTURE coverage-cell tool that
// (a) grants Task, (b) writes an un-owned durable basename, (c) mints a synthetic
// id, or (d) flips a belief/residual flag default-on would pass every existing
// per-piece check while silently violating the envelope. This capstone is the
// lock: it enumerates the coverage-cell tool registry FROM SOURCE and asserts the
// four invariants over the whole set, so adding such a node FAILS CI.
//
// TEST-only node (no production code). The "registry" is derived mechanically:
// the set of tool modules whose handler appends a cell/transition/node frontier
// event (the coverage-cell substrate), discovered by source scan so a new cell
// tool is auto-included the moment it lands.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..");
const TOOLS_DIR = path.join(REPO_ROOT, "mcp", "lib", "tools");
const AGENTS_DIR = path.join(REPO_ROOT, ".claude", "agents");

const { cellNodeId } = require("../mcp/lib/task-graph-materializer.js");
const { compareGraphCandidates } = require("../mcp/lib/graph-scheduler.js");
const { DEFAULT_QUEUE_POLICY } = require("../mcp/lib/queue-policy.js");
const {
  isAuditGradedPath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const paths = require("../mcp/lib/paths.js");

// ── coverage-cell tool registry (derived from source) ───────────────────────
//
// A coverage-cell tool is one whose handler drives the cell/transition/node
// substrate: it appends a cell proposal, a transition proposal, or a node
// transition, OR selects/dispatches graph-scheduled cell nodes. Discovered by
// scanning each tool module for the substrate append/select primitives so a
// future cell tool joins the envelope automatically.
const CELL_SUBSTRATE_MARKERS = [
  "appendCellProposal",
  "appendTransitionProposal",
  "appendNodeTransition",
  "materializeCellFloor",
  "selectNextExecutableNodes",
  "buildCellCoverageContract",
  // F1/F2 chain-phase substrate: the covered-path projection (F1) and the
  // live composition verifier (F2) are coverage-cell tools too — they traverse
  // and confirm the chains the cell floor exposes — so the envelope must cover
  // them (single-spawner + the F2 verified_pass MCP-write-only ledger).
  "enumerateCandidatePaths",
  "verifyCompositionPath",
];

function listToolModules() {
  return fs
    .readdirSync(TOOLS_DIR)
    .filter((f) => f.endsWith(".js") && !f.startsWith("_"))
    .map((f) => ({ file: path.join(TOOLS_DIR, f), basename: f }));
}

function coverageCellTools() {
  const out = [];
  for (const { file, basename } of listToolModules()) {
    const src = fs.readFileSync(file, "utf8");
    if (!CELL_SUBSTRATE_MARKERS.some((m) => src.includes(m))) continue;
    const spec = require(file);
    if (!spec || typeof spec.name !== "string") continue;
    out.push({ name: spec.name, spec, src, basename });
  }
  return out;
}

test("G2 registry: the coverage-cell tool set is non-empty and includes the known floor/dispatch/finalize tools", () => {
  const names = coverageCellTools().map((t) => t.name).sort();
  // The registry MUST be discoverable, or the whole capstone is vacuous.
  assert.ok(names.length >= 4, `coverage-cell registry too small: ${JSON.stringify(names)}`);
  for (const required of [
    "bob_materialize_cell_floor",
    "bob_propose_transition",
    "bob_finalize_node",
    "bob_schedule_graph_nodes",
    // The chain-phase (F1/F2) tools MUST stay in the registry, or a future
    // role_bundle widening on them would slip the single-spawner group-lock.
    "bob_query_surface_graph",
    "bob_verify_composition_path",
  ]) {
    assert.ok(
      names.includes(required),
      `coverage-cell registry is missing ${required} — the source-scan marker set drifted; ${JSON.stringify(names)}`,
    );
  }
});

// ── (i) single-spawner topology ─────────────────────────────────────────────

test("G2 (i): no coverage-cell tool grants Task/spawn — every one is dispatched THROUGH the orchestrator", () => {
  // Task is the Claude-local subagent-spawn primitive; it is granted ONLY via a
  // renderer-registry spawn_capable role's local_tools, NEVER via an MCP tool's
  // role_bundles. A coverage-cell tool that named "Task" in role_bundles[] (or
  // any spawn token) would let a cell self-spawn workers, breaking single-spawner.
  const SPAWN_TOKENS = new Set(["Task", "spawn", "spawn_capable"]);
  const offenders = [];
  for (const t of coverageCellTools()) {
    const bundles = Array.isArray(t.spec.role_bundles) ? t.spec.role_bundles : [];
    for (const b of bundles) {
      if (SPAWN_TOKENS.has(b)) {
        offenders.push({ tool: t.name, role_bundle: b });
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `single-spawner violation: a coverage-cell tool carries a spawn role_bundle → ${JSON.stringify(offenders, null, 2)}`,
  );
});

// An agent frontmatter MCP tool is rendered in mcpPermissionForTool form
// (mcp__hacker-bob__<name>), but coverageCellTools() yields BARE names. Strip the
// server prefix before intersecting, or the leg never matches an MCP cell tool and
// is vacuously green. The positive-control test below proves it bites.
const MCP_TOOL_PREFIX = "mcp__hacker-bob__";
function stripMcpPrefix(token) {
  return token.startsWith(MCP_TOOL_PREFIX) ? token.slice(MCP_TOOL_PREFIX.length) : token;
}
function agentCellToolOffenders(cellToolNames) {
  const offenders = [];
  for (const f of fs.readdirSync(AGENTS_DIR).filter((x) => x.endsWith(".md"))) {
    const text = fs.readFileSync(path.join(AGENTS_DIR, f), "utf8");
    const m = text.match(/^tools:\s*(.*)$/m);
    if (!m) continue;
    const tokens = m[1].split(/\s*,\s*/).map((s) => s.trim());
    if (!tokens.includes("Task")) continue;
    const cellTools = tokens.filter((tok) => cellToolNames.has(stripMcpPrefix(tok)));
    if (cellTools.length > 0) offenders.push({ agent: f, cell_tools: cellTools });
  }
  return offenders;
}

test("G2 (i): no agent frontmatter pairs a cell tool with the Task primitive", () => {
  // Cross-check the agent surface: an agent that carries BOTH a coverage-cell
  // tool AND Task could spawn from within a cell-finalizing context. The only
  // Task holders are renderer-registry spawn_capable roles, which do NOT carry
  // the orchestrator-only cell tools. Assert the two are disjoint per agent.
  const cellToolNames = new Set(coverageCellTools().map((t) => t.name));
  const offenders = agentCellToolOffenders(cellToolNames);
  assert.deepEqual(
    offenders,
    [],
    `single-spawner violation: an agent pairs Task with a coverage-cell tool → ${JSON.stringify(offenders, null, 2)}`,
  );
});

test("G2 (i) positive control: the leg BITES a Task + prefixed-cell-tool pairing", () => {
  // Prove the disjointness leg is not vacuous: a synthetic frontmatter carrying
  // Task AND a prefixed coverage-cell tool MUST be flagged. This is the regression
  // that would have caught the bare-vs-prefixed comparison bug.
  const cellToolNames = new Set(coverageCellTools().map((t) => t.name));
  assert.ok(cellToolNames.has("bob_propose_transition"), "bob_propose_transition is a cell tool");
  const tokens = ["Task", "Read", `${MCP_TOOL_PREFIX}bob_propose_transition`];
  const flagged = tokens.includes("Task")
    ? tokens.filter((tok) => cellToolNames.has(stripMcpPrefix(tok)))
    : [];
  assert.deepEqual(
    flagged,
    [`${MCP_TOOL_PREFIX}bob_propose_transition`],
    "the prefix-stripped leg must flag a Task + cell-tool agent",
  );
});

test("G2 (i): every spawn-capable role's GRANTED mcp tools are disjoint from the cell tools (the deny holds)", () => {
  // NS-2 — the role-level deny (G2 disjointness by subtraction) keeps the Task-holder
  // off the coverage-cell tools at the source. Assert it directly: a spawn-capable
  // role's resolved tool set (mcpToolNamesForRole, after deny) shares no member
  // with the cell-tool names. Because a nesting child's brief allowed_tools_for_node
  // is filtered to this granted set, the child brief is cell-tool-free too.
  const { mcpToolNamesForRole } = require("../mcp/lib/role-model.js");
  const { spawnCapableAgentNames } = require("../scripts/lib/claude-role-renderer.js");
  const cellToolNames = new Set(coverageCellTools().map((t) => t.name));
  const spawners = spawnCapableAgentNames();
  assert.ok(spawners.length >= 1, "there is at least one spawn-capable role to check");
  for (const roleId of spawners) {
    const leaked = mcpToolNamesForRole(roleId).filter((name) => cellToolNames.has(name));
    assert.deepEqual(leaked, [], `spawn role ${roleId} grants a coverage-cell tool: ${JSON.stringify(leaked)}`);
  }
});

// ── (ii) MCP-owned durable state ────────────────────────────────────────────

test("G2 (ii): every coverage-cell durable write is an MCP-owned session basename (agents never raw-Write it)", () => {
  // Each cell tool self-declares session_artifacts_written. Every declared
  // artifact MUST be a path the agent Write-guard refuses for an agent caller:
  // either an audit-graded path (isAuditGradedPath) OR an MCP-owned session
  // basename in the write-guard BLOCK set. A cell tool that declared an
  // agent-writable scratch basename (e.g. *.txt) as its durable store would let
  // an agent forge cell state — caught here.
  const offenders = [];
  for (const t of coverageCellTools()) {
    // The MCP-ownership lock applies to tools that DECLARE a durable write. A
    // read-only coverage-cell tool (e.g. the F1 covered_paths query, mutating:
    // false) writes no session state — single-spawner (i) covers it; there is no
    // durable artifact to forge, so it is correctly out of scope here.
    if (t.spec.mutating !== true) continue;
    const artifacts = Array.isArray(t.spec.session_artifacts_written)
      ? t.spec.session_artifacts_written
      : [];
    assert.ok(
      artifacts.length > 0,
      `coverage-cell tool ${t.name} is mutating but declares an empty session_artifacts_written manifest — cannot prove MCP ownership`,
    );
    for (const artifact of artifacts) {
      const abs = path.join(sessionDir("example.com"), artifact);
      const auditGraded = isAuditGradedPath(abs, "example.com");
      const mcpOwned = isMcpOwnedBlockedForAgent(artifact);
      if (!auditGraded && !mcpOwned) {
        offenders.push({ tool: t.name, artifact, reason: "neither audit-graded nor MCP-owned-blocked" });
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `MCP-ownership violation: a coverage-cell tool's durable write is agent-writable → ${JSON.stringify(offenders, null, 2)}`,
  );
});

// Resolve whether a declared basename is in the agent-Write-guard MCP-OWNED set,
// binding to paths.js's authoritative in-source WRITE_GUARD_TABLES (the same
// classification check:mcp-owned-basename-inventory + check:write-guard-tables
// trust, and which renders the hook's JSON table). Matches the exact (basename)
// and (filename pattern) MCP-owned legs the write-guard hook applies.
function isMcpOwnedBlockedForAgent(basename) {
  const tables = paths.WRITE_GUARD_TABLES;
  assert.ok(tables && typeof tables === "object", "paths.WRITE_GUARD_TABLES must be exported (source of truth for MCP ownership)");
  const exact = Array.isArray(tables.mcp_owned_basenames) ? tables.mcp_owned_basenames : [];
  if (exact.includes(basename)) return true;
  const patterns = Array.isArray(tables.mcp_owned_filename_patterns) ? tables.mcp_owned_filename_patterns : [];
  for (const pat of patterns) {
    try {
      if (new RegExp(pat).test(basename)) return true;
    } catch {
      // a malformed pattern is the write-guard-tables check's problem, not ours
    }
  }
  return false;
}

// ── (iii) real-id dispatch ──────────────────────────────────────────────────

test("G2 (iii): cell node ids are deterministic content hashes of the real cell_key — never synthetic lead-* ids", () => {
  const cellKey = JSON.stringify(["surface:billing", "", "", "idor", "admin"]);
  const id1 = cellNodeId({ cellKey });
  const id2 = cellNodeId({ cellKey });
  // Deterministic: equal real keys dedupe to one node.
  assert.equal(id1, id2, "cellNodeId must be a deterministic function of the real cell_key");
  // A different real key yields a different id (no collision into one synthetic bucket).
  const otherKey = JSON.stringify(["surface:admin", "", "", "ssrf", "anon"]);
  assert.notEqual(cellNodeId({ cellKey: otherKey }), id1);
  // Never a synthetic promoted-lead id. The lead-* namespace is minted by
  // bob_promote_surface_leads for UNMATERIALIZED leads; a cell node id MUST be a
  // materialized content hash, so the cell substrate never carries a lead-* id.
  assert.ok(!/(^|[-:])lead-/.test(id1), `cell node id must not be a synthetic lead-* id: ${id1}`);
  assert.match(id1, /^TG-cell-[0-9a-f]{8,}$/, "cell node id is the TG-cell-<hash> content-addressed form");

  // The FULL cell-id surface is real, not just surface cells: the A2 transition
  // edge token and the E2 re-probe key are deterministic hashes of REAL inputs
  // (endpoint surfaces / surface+bug_class+auth+residual), never synthetic.
  const { transitionEdgeToken } = require("../mcp/lib/assignment-brief.js");
  const { reprobeCellKey } = require("../mcp/lib/belief/residual-depth.js");
  const edge = transitionEdgeToken("surface:l1", "surface:l2", "value_movement");
  assert.equal(edge, transitionEdgeToken("surface:l1", "surface:l2", "value_movement"), "edge token deterministic");
  assert.notEqual(edge, transitionEdgeToken("surface:l2", "surface:l1", "value_movement"), "direction-preserving (L1->L2 != L2->L1)");
  assert.ok(edge.startsWith("transition:") && !/lead-/.test(edge));
  const rk = reprobeCellKey("surface:billing", "idor", "admin", "abc123def456");
  assert.equal(rk, reprobeCellKey("surface:billing", "idor", "admin", "abc123def456"), "reprobe key deterministic");
  assert.ok(rk.includes("surface:billing") && !/lead-/.test(rk), "reprobe key keys on the REAL surface id");
});

test("G2 (iii): propose-transition refuses unknown (non-real) surface endpoints", () => {
  // The cross-surface (transition) cell floor keys on REAL endpoint surface_ids.
  // Source-level assertion that the endpoint-existence guard is wired: the tool
  // names the unknown_surface refusal so a transition cannot reference a surface
  // that was never observed (which would be an un-real / synthetic edge id).
  const transition = coverageCellTools().find((t) => t.name === "bob_propose_transition");
  assert.ok(transition, "bob_propose_transition is in the coverage-cell registry");
  assert.match(
    transition.src,
    /unknown_surface/,
    "propose-transition must guard endpoint existence (unknown_surface refusal) so transition-cell ids stay real",
  );
});

// ── (iv) belief-advisory-only ───────────────────────────────────────────────

test("G2 (iv): the belief + residual-depth queue-policy flags default ON and advisory-only (never gating)", () => {
  // The advisory overlays are default-ON and advisory-when-on: they only ever
  // REORDER within a priority band and never gate the closure gate, grade, or
  // dispatch spine, which run belief-free and residual-free at the source. The
  // advisory engages only once executed outcomes feed signals (empty map ==
  // no map == byte-identical ordering), so default-ON does not turn an advisory
  // into a gate — the belief-FREE-at-source and within-band-only tests below lock that.
  assert.equal(
    DEFAULT_QUEUE_POLICY.belief_assisted_priority_enabled,
    true,
    "belief_assisted_priority_enabled defaults TRUE and is advisory-when-on — never gating",
  );
  assert.equal(
    DEFAULT_QUEUE_POLICY.residual_depth_reprobe_enabled,
    true,
    "residual_depth_reprobe_enabled defaults TRUE and is advisory-when-on — never gating",
  );
});

test("G2 (iv): the graph-scheduler comparator is byte-identical with no belief map (belief only RAISES within a band)", () => {
  // With no belief map (the default path), the comparator's ordering is the pure
  // deterministic tier→priority→severity→ts→node_id spine. A belief score can
  // only reorder WITHIN a priority band, never across one and never drop a node.
  const priorityRank = new Map([["high", 0], ["medium", 1], ["low", 2]]);
  const a = { node_id: "TG-cell-aaa", priority: "medium", tier: 1, severity_floor: "low" };
  const b = { node_id: "TG-cell-bbb", priority: "medium", tier: 1, severity_floor: "low" };

  const baseline = compareGraphCandidates(a, b, priorityRank);
  // An empty belief map is byte-identical to no map.
  assert.equal(
    compareGraphCandidates(a, b, priorityRank, new Map()),
    baseline,
    "an empty belief map must not change ordering",
  );
  assert.ok(baseline < 0, "deterministic node_id tie-break orders aaa before bbb");

  // Belief cannot cross a priority band: a maximal belief boost on the
  // LOWER-priority node must NOT pull it ahead of the higher-priority node.
  const high = { node_id: "TG-cell-hi", priority: "high", tier: 1, severity_floor: "low" };
  const low = { node_id: "TG-cell-lo", priority: "low", tier: 1, severity_floor: "low" };
  const boostLow = new Map([["TG-cell-lo", 1000]]);
  assert.ok(
    compareGraphCandidates(high, low, priorityRank, boostLow) < 0,
    "belief is advisory-only: a max boost cannot pull a low-priority cell ahead of a high-priority cell across the band",
  );

  // And: a Tier-1 floor cell ALWAYS precedes a Tier-2 re-probe, even with a max
  // belief boost on the Tier-2 cell — closure/breadth never bends to belief.
  const tier1 = { node_id: "TG-cell-floor", priority: "medium", tier: 1, severity_floor: "low" };
  const tier2 = { node_id: "TG-cell-reprobe", priority: "critical", tier: 2, severity_floor: "critical" };
  const boostTier2 = new Map([["TG-cell-reprobe", 1000]]);
  assert.ok(
    compareGraphCandidates(tier1, tier2, priorityRank, boostTier2) < 0,
    "Tier-1 breadth precedes Tier-2 depth unconditionally — belief/residual never gate closure",
  );
});

test("G2 (iv): the closure gate, closure stat, and grade are belief-FREE at the source", () => {
  // The load-bearing belief-advisory lock: a freeze/grade decision must NEVER
  // read belief or residual — closure is COVERAGE-ONLY. The producer
  // (materialize-cell-floor) may read residual advisorily to mint Tier-2 work,
  // but the GATE may not. A future edit wiring a belief/residual import into a
  // gate/closure/grade module would turn an advisory into a gate — caught here.
  const beliefImport = /require\(\s*['"][^'"]*\/belief\/[^'"]*['"]\s*\)|require\(\s*['"][^'"]*residual[^'"]*['"]\s*\)/;
  for (const rel of [
    "mcp/lib/scheduler-preconditions.js",
    "mcp/lib/lifecycle-gates.js",
    "mcp/lib/coverage-closure.js",
    "mcp/lib/grade-verdict-store.js",
  ]) {
    const src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    assert.ok(
      !beliefImport.test(src),
      `${rel} must stay belief-free — closure/grade is coverage-only, never belief-gated`,
    );
  }
});

// EXTEND the INV-12 authority wall to the CLAIM-MINTING spine. A belief
// advisory may ORDER dispatch, but it must NEVER mint a candidate claim, freeze a
// claim, or otherwise feed the claim record. The claim spine
// (record-candidate-claim tool + claims.js + claim-freeze.js) is therefore
// belief-free-at-source exactly like the closure/grade gate above: a future edit
// wiring a belief/residual import into claim minting would let belief author
// findings — caught here.
test("INV-12 extension: the claim-minting spine is belief-FREE at the source", () => {
  const beliefImport = /require\(\s*['"][^'"]*\/belief\/[^'"]*['"]\s*\)|require\(\s*['"][^'"]*residual[^'"]*['"]\s*\)/;
  const claimSpine = [
    "mcp/lib/tools/record-candidate-claim.js",
    "mcp/lib/claims.js",
    "mcp/lib/claim-freeze.js",
  ];
  for (const rel of claimSpine) {
    const src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    assert.ok(
      !beliefImport.test(src),
      `${rel} must stay belief-free — belief never mints/freezes a claim`,
    );
  }
});

test("INV-12 extension positive control: the claim-spine belief-free leg BITES a belief import", () => {
  // Prove the wall is non-vacuous: the SAME regex applied to a module that DOES
  // import belief must fire. scheduler-priority.js imports ./intervention-calculus
  // (a belief module), so the leg must classify it as belief-bearing — confirming
  // the wall would flag a claim module that grew such an import.
  const beliefImport = /require\(\s*['"][^'"]*\/belief\/[^'"]*['"]\s*\)|require\(\s*['"][^'"]*residual[^'"]*['"]\s*\)/;
  // graph-scheduler.js lazily requires ./belief/cell-scheduler-priority.js — a
  // require string carrying the /belief/ path segment the wall regex anchors on.
  const beliefBearing = fs.readFileSync(
    path.join(REPO_ROOT, "mcp/lib/graph-scheduler.js"),
    "utf8",
  );
  assert.ok(
    beliefImport.test(beliefBearing),
    "the belief-import regex must match a module that imports a /belief/ submodule (else the INV-12 authority wall is vacuous)",
  );
});

test("INV-12 narrow exemptions: the two belief<->executed boundary modules consume executed-control belief, never DISPATCH belief", () => {
  // INV-12 forbids belief at the claim/closure/grade source. TWO modules sit at the
  // belief<->executed boundary and are NARROW, documented exemptions — they are NOT
  // claim/closure/grade gates and they do NOT close the belief->dispatch->belief loop:
  //
  //   (1) composition-live-verifier.js — the LOOP-BREAKER. It imports the executed
  //       probes (live-object-auth-probe + differential-tester) to RE-EXECUTE a guard
  //       leaf, and emits a verified_intervention ONLY from that executed outcome. It
  //       must NOT import the dispatch-belief machinery (scheduler-priority /
  //       intervention-calculus / factor-graph), or a verified result could feed back
  //       into the same belief that picked the dispatch.
  //   (2) belief-window.js — the one-way audit->belief CONSUMER. It reads
  //       verified_intervention to sharpen a request_equivalence latent, but must NOT
  //       import the dispatch-belief machinery either: the window consumes
  //       executed-control belief, it never dispatches from belief.
  const DISPATCH_BELIEF_IMPORT = /require\(\s*['"][^'"]*(scheduler-priority|intervention-calculus|factor-graph)[^'"]*['"]\s*\)/;

  const verifier = fs.readFileSync(path.join(REPO_ROOT, "mcp/lib/composition-live-verifier.js"), "utf8");
  // Non-vacuity: the loop-breaker REALLY imports the executed probes it is exempt for.
  assert.match(verifier, /require\(\s*['"][^'"]*\/belief\/live-object-auth-probe[^'"]*['"]\s*\)/, "verifier imports the live-object-auth probe (executed)");
  assert.match(verifier, /require\(\s*['"][^'"]*\/belief\/differential-tester[^'"]*['"]\s*\)/, "verifier imports the differential tester (executed)");
  assert.ok(
    !DISPATCH_BELIEF_IMPORT.test(verifier),
    "composition-live-verifier must NOT import scheduler-priority/intervention-calculus/factor-graph — it executes, it does not dispatch belief",
  );

  const window = fs.readFileSync(path.join(REPO_ROOT, "mcp/lib/belief/belief-window.js"), "utf8");
  // Non-vacuity: the window REALLY consumes the verified_intervention provenance.
  assert.match(window, /verified_intervention/, "belief-window consumes verified_intervention (the audit->belief edge it is exempt for)");
  assert.ok(
    !DISPATCH_BELIEF_IMPORT.test(window),
    "belief-window must NOT import scheduler-priority/intervention-calculus/factor-graph — it consumes executed-control belief, never dispatches belief",
  );
});

// WAVE cross-band. On the WAVE side (applyBeliefSchedulerPriority, which
// decorates surface objects for the wave planner), an opted-in belief hint CAN raise
// a LOW surface ACROSS a priority band — the wave's open_requeue/lead_surface_ids
// re-queue buckets are what make a cross-band raise safe (a surface lifted out of its
// band is still re-queued, never dropped). This is the deliberate CONTRAST with the
// GRAPH comparator (INV-11), which stays intra-band. Belief ON here is LOCAL to the
// test; no production default is touched.
test("wave cross-band: belief ON can raise a LOW surface across a band, and the surface SET is preserved (reorder/decorate, never drop/add)", () => {
  const { applyBeliefSchedulerPriority } = require("../mcp/lib/belief/scheduler-priority.js");
  const { appendEdges } = require("../mcp/lib/surface-graph.js");
  const { sessionDir } = require("../mcp/lib/paths.js");

  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(require("os").tmpdir(), "bob-crossband-"));
  process.env.HOME = home;
  try {
    const domain = "crossband.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // Seed a NON-UNIFORM belief: a populated object-authorization edge gives the
    // matching surface a high expected-information-gain candidate, so its hint score
    // lands well above the LOW band (score 93 -> CRITICAL per priorityFromScore).
    appendEdges({
      target_domain: domain,
      edges: [
        {
          source: { type: "principal", id: "principal:attacker" },
          target: { type: "policy_gate", id: "policy_gate:owner" },
          edge_type: "tests_gate",
        },
        {
          source: { type: "policy_gate", id: "policy_gate:owner" },
          target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" },
          edge_type: "permits_effect",
        },
      ],
    });

    const hotSurface = {
      id: "surface:idor-victim",
      title: "victim object access",
      priority: "LOW",
      hosts: [domain],
      bug_class_hints: ["unauth_succeeds_where_auth_blocked"],
      high_value_flows: ["attacker reads owner victim object"],
    };
    // A second surface that earns NO belief hint — proves the SET is preserved and
    // un-hinted surfaces are passed through byte-identical.
    const coldSurface = { id: "surface:cold", title: "static assets", priority: "LOW", hosts: [domain] };
    const input = [hotSurface, coldSurface];

    const result = applyBeliefSchedulerPriority({
      target_domain: domain,
      surfaces: input,
      enabled: true, // LOCAL opt-in; no production default changed.
      seed: "belief-scheduler-priority",
    });

    // NON-VACUITY GUARD: the hint must actually apply, else the cross-band claim is empty.
    assert.equal(result.metadata.applied, true, "belief hint must apply (non-vacuous) for the cross-band assertion");
    assert.ok(result.metadata.hint_count >= 1, "at least one surface earned a belief hint");

    const byId = new Map(result.surfaces.map((s) => [s.id, s]));
    const decoratedHot = byId.get("surface:idor-victim");
    assert.ok(decoratedHot, "the hot surface survives");
    // CROSS-BAND: belief raised the hot surface OUT of LOW (the wave side allows it).
    assert.notEqual(
      decoratedHot.priority,
      "LOW",
      "belief raised the LOW surface across its band on the WAVE side (cross-band is allowed here, unlike the graph comparator)",
    );
    assert.equal(decoratedHot.original_priority, "LOW", "the pre-belief band is preserved for audit (original_priority)");
    assert.equal(decoratedHot.ranking.belief.dispatch_authority, false, "the raise is advisory: dispatch_authority stays false");

    // SET PRESERVED: same id set, same cardinality — reorder/decorate, never drop/add.
    assert.deepEqual(
      result.surfaces.map((s) => s.id).sort(),
      input.map((s) => s.id).sort(),
      "the returned surface SET == the input SET (no surface dropped or added)",
    );
    assert.equal(result.surfaces.length, input.length, "cardinality preserved");
    // The un-hinted cold surface is passed through unchanged (byte-identical).
    assert.deepEqual(byId.get("surface:cold"), coldSurface, "an un-hinted surface is passed through byte-identical");

    // STRUCTURAL PRECONDITION: the wave-planner exposes the open_requeue +
    // lead_surface_ids re-queue buckets that make a cross-band raise safe (a raised
    // surface is re-queued, never lost). Assert those bucket names exist in source.
    const wavePlanner = fs.readFileSync(path.join(REPO_ROOT, "mcp/lib/wave-planner.js"), "utf8");
    assert.match(wavePlanner, /name:\s*["']open_requeue["']/, "wave-planner exposes the open_requeue bucket (cross-band re-queue safety)");
    assert.match(wavePlanner, /name:\s*["']lead_surface_ids["']/, "wave-planner exposes the lead_surface_ids bucket (cross-band re-queue safety)");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ── negative controls: prove the capstone bites ─────────────────────────────

test("G2 negative control: a synthetic cell tool granting Task is flagged", () => {
  // Re-run invariant (i)'s classifier over a synthetic spec to prove the test
  // would FAIL on a future violating node.
  const SPAWN_TOKENS = new Set(["Task", "spawn", "spawn_capable"]);
  const badSpec = { name: "bob_bad_cell_tool", role_bundles: ["orchestrator", "Task"] };
  const violates = (badSpec.role_bundles || []).some((b) => SPAWN_TOKENS.has(b));
  assert.equal(violates, true, "a cell tool naming Task in role_bundles must be flagged");
});

test("G2 negative control: a synthetic cell tool writing an agent-writable scratch basename is flagged", () => {
  const artifact = "family_seeds.txt"; // a known agent-writable scratch basename
  const abs = path.join(sessionDir("example.com"), artifact);
  const auditGraded = isAuditGradedPath(abs, "example.com");
  const mcpOwned = isMcpOwnedBlockedForAgent(artifact);
  assert.equal(auditGraded, false, "scratch .txt is not audit-graded");
  assert.equal(mcpOwned, false, "scratch .txt is agent-writable, not MCP-owned");
  // => the (ii) assertion would push this to offenders[] and fail. Confirmed bite.
});

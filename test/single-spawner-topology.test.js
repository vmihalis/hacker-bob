"use strict";

// Cycle Y.9 (rev 4.1) — `check:single-spawner-topology` test (Y-P8).
//
// Mechanical assertions on the rendered agent surface + tool registry:
//
//   1. Registry-derived spawner topology (CN — coverage-nesting): `Task`
//      is the Claude Code subagent-spawn primitive. An agent frontmatter
//      `tools:` line may carry `Task` ONLY when that agent's role spec is
//      declared `spawn_capable` in the renderer registry (the controlled
//      nested-fan-out grant). Every other agent MUST NOT carry `Task`, and a
//      spawn_capable agent MUST carry it (the grant must actually render).
//      With no spawn_capable role declared, the allowlist is empty and this
//      degenerates to the original "no agent carries Task" invariant.
//
//   2. Audit-graded write authority (Y-P13 + Y.8 source-tree guard):
//      `report-writer.md` and `chain-builder.md` MUST NOT carry the
//      Claude-local `Write` or `Edit` tools. Their composition surfaces
//      are MCP-owned (`bob_compose_report`, `bob_write_chain_rollup`).
//
//   3. `mcp_server_internal` synthetic caller bundle MUST NOT be
//      exported from any role-bundle / role-model registry consumed by
//      the agent renderer. The bundle is constructed inline inside
//      `mcp/lib/tools/_write-base.js` per Y-D13; exporting it would
//      grant it to agent roles.
//
//   4. **Rev 4.1 (defect 3) — chain-bundle audit.** For every tool
//      whose `role_bundles[]` includes `"chain"` AND
//      `"evaluator-shared"`, the tool's source file MUST carry the
//      header comment `// chain+evaluator-shared justified: <reason>`.
//      Prevents accidental authority widening. The 5 graph tools
//      extended in Y.11 (`bob_propose_hypothesis`,
//      `bob_propose_transition`, `bob_attach_contract`,
//      `bob_append_chain_node`, `bob_query_chain_tree`) will carry the
//      justification comment when Y.11 lands. Until then the audit
//      passes vacuously (no current tool pairs the two bundles).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { spawnCapableAgentNames } = require("../scripts/lib/claude-role-renderer.js");
const { FANOUT_ROLE_REGISTRY } = require("../mcp/core/session/nested-spawn.js");

const REPO_ROOT = path.join(__dirname, "..");
const AGENTS_DIR = path.join(REPO_ROOT, ".claude", "agents");
const TOOLS_DIR = path.join(REPO_ROOT, "mcp", "tools");

function readAgentFrontmatter(file) {
  const text = fs.readFileSync(file, "utf8");
  if (!text.startsWith("---\n")) return null;
  const end = text.indexOf("\n---\n", 4);
  if (end === -1) return null;
  return text.slice(0, end + 1);
}

function listAgentFiles() {
  return fs
    .readdirSync(AGENTS_DIR)
    .filter((f) => f.endsWith(".md"))
    .map((f) => path.join(AGENTS_DIR, f));
}

function spawnGrantTokens(toolsLine) {
  return String(toolsLine || "").match(/\b(?:Agent|Task)(?:\([^)]*\))?/g) || [];
}

// Pure classifier shared by the real-tree assertion and synthetic controls.
// The one registry-declared root must carry exactly the parameterized current
// Agent(child) grant; bare Agent/Task, legacy Task(child), and foreign types are
// all violations because they widen preventive spawn authority.
function classifySpawnGrant(agentName, grants, allowedSet, expectedGrant) {
  const isAllowed = allowedSet.has(agentName);
  if (grants.length > 0 && !isAllowed) {
    return "Agent/Task granted to a non-spawn-capable agent (Y-P8: only declared spawners may spawn)";
  }
  if (isAllowed && (grants.length !== 1 || grants[0] !== expectedGrant)) {
    return `spawn_capable agent must carry exactly ${expectedGrant}; got ${JSON.stringify(grants)}`;
  }
  return null;
}

test("topology: only the declared root carries exact Agent(evaluator-fanout-child) (Y-P8, NS-7)", () => {
  const allowed = new Set(spawnCapableAgentNames());
  const expectedGrant = `Agent(${FANOUT_ROLE_REGISTRY.child.subagent_type})`;
  const offenders = [];
  for (const file of listAgentFiles()) {
    const fm = readAgentFrontmatter(file);
    if (!fm) continue;
    const toolsLineMatch = fm.match(/^tools:\s*(.*)$/m);
    if (!toolsLineMatch) continue;
    const grants = spawnGrantTokens(toolsLineMatch[1]);
    const agentName = path.basename(file, ".md");
    const reason = classifySpawnGrant(agentName, grants, allowed, expectedGrant);
    if (reason) {
      offenders.push({ file: path.relative(REPO_ROOT, file), reason, toolsLine: toolsLineMatch[1] });
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Y-P8 (registry-derived) violation → ${JSON.stringify(offenders, null, 2)}`,
  );
});

test("topology: the gate still bites — synthetic controls (CN)", () => {
  const allowed = new Set([FANOUT_ROLE_REGISTRY.root.subagent_type]);
  const expected = `Agent(${FANOUT_ROLE_REGISTRY.child.subagent_type})`;
  // Negative control: a non-allowlisted agent carrying any spawn grant.
  assert.match(
    classifySpawnGrant("evaluator-agent", [expected], allowed, expected) || "",
    /non-spawn-capable/,
  );
  // Missing, unrestricted, legacy-alias, and foreign grants all violate the exact boundary.
  assert.match(
    classifySpawnGrant(FANOUT_ROLE_REGISTRY.root.subagent_type, [], allowed, expected) || "",
    /must carry exactly/,
  );
  for (const widened of ["Agent", "Task", `Task(${FANOUT_ROLE_REGISTRY.child.subagent_type})`, "Agent(evaluator-agent)"]) {
    assert.match(
      classifySpawnGrant(FANOUT_ROLE_REGISTRY.root.subagent_type, [widened], allowed, expected) || "",
      /must carry exactly/,
    );
  }
  assert.equal(classifySpawnGrant(FANOUT_ROLE_REGISTRY.root.subagent_type, [expected], allowed, expected), null);
  assert.equal(classifySpawnGrant("evaluator-agent", [], allowed, expected), null);
});

test("topology: the spawn-capable allowlist is CLOSED to exactly one declared spawner (Y-P8 length-1, CN)", () => {
  // NS-1 — the single-spawner relaxation grants the host Task primitive to exactly ONE
  // registry role (evaluator-fanout). A SECOND spawn_capable role would silently
  // widen the allowlist (spawnCapableAgentNames() grows a Set), eroding "single
  // spawner" to "many declared spawners". Assert the closed cardinality + identity
  // so any such drift FAILS CI — the discretionary-child runtime bound
  // (validateSpawnFanout child_type_allowlist) is registry-derived from this set.
  assert.deepEqual(
    spawnCapableAgentNames(),
    [FANOUT_ROLE_REGISTRY.root.subagent_type],
    `Y-P8: expected exactly one declared spawner (evaluator-fanout); got ${JSON.stringify(spawnCapableAgentNames())}`,
  );
});

test("topology: the closed-allowlist guard bites a second spawner (negative control, CN)", () => {
  // Prove the length-1 contract is not vacuous: any allowlist that is not exactly
  // ["evaluator-fanout"] — a second declared spawner, or a renamed one — must fail
  // the same deepEqual the real-tree assertion uses.
  assert.throws(
    () => assert.deepEqual(
      [FANOUT_ROLE_REGISTRY.root.subagent_type, "evaluator-rogue"],
      [FANOUT_ROLE_REGISTRY.root.subagent_type],
    ),
    "a second declared spawner must violate the closed-allowlist contract",
  );
});

test("audit-graded write authority: Write/Edit absent from report-writer.md + chain-builder.md", () => {
  const guarded = [
    path.join(AGENTS_DIR, "report-writer.md"),
    path.join(AGENTS_DIR, "chain-builder.md"),
  ];
  const offenders = [];
  for (const file of guarded) {
    const fm = readAgentFrontmatter(file);
    assert.ok(fm, `${file} must have frontmatter`);
    const toolsLineMatch = fm.match(/^tools:\s*(.*)$/m);
    assert.ok(toolsLineMatch, `${file} must have tools line`);
    const tools = toolsLineMatch[1].split(/\s*,\s*/);
    for (const tok of tools) {
      if (tok === "Write" || tok === "Edit") {
        offenders.push({ file: path.relative(REPO_ROOT, file), token: tok });
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Y-P13 violation: report-writer/chain-builder carrying Write or Edit → ${JSON.stringify(offenders, null, 2)}`,
  );
});

test("mcp_server_internal is NOT exported from the role-model registry consumed by the renderer", () => {
  // Y-D13: mcp_server_internal is constructed inline inside
  // mcp/lib/tools/_write-base.js. It MUST NOT appear as an exported
  // bundle that any agent role could enumerate or be granted.
  const roleModel = require("../mcp/core/dispatch/role-model.js");
  for (const [exportName, exportedValue] of Object.entries(roleModel)) {
    if (exportName === "mcp_server_internal") {
      assert.fail(
        `mcp/core/dispatch/role-model.js MUST NOT export mcp_server_internal directly`,
      );
    }
    if (typeof exportedValue === "object" && exportedValue !== null) {
      for (const key of Object.keys(exportedValue)) {
        if (key === "mcp_server_internal") {
          assert.fail(
            `mcp/core/dispatch/role-model.js export ${exportName} contains mcp_server_internal key (grantable bundle)`,
          );
        }
      }
    }
  }
});

function listToolSourceFiles() {
  return fs
    .readdirSync(TOOLS_DIR)
    .filter((f) => f.endsWith(".js"))
    .map((f) => path.join(TOOLS_DIR, f));
}

function parseRoleBundles(text) {
  // Match the literal `role_bundles: [...],` declaration.
  const match = text.match(/role_bundles\s*:\s*\[([^\]]*)\]/);
  if (!match) return null;
  const inner = match[1];
  return inner
    .split(",")
    .map((s) => s.trim().replace(/^["']|["']$/g, ""))
    .filter((s) => s.length > 0);
}

test("rev 4.1 (defect 3) chain-bundle audit: every tool pairing 'chain' + 'evaluator-shared' carries justification header comment", () => {
  const violations = [];
  for (const file of listToolSourceFiles()) {
    const text = fs.readFileSync(file, "utf8");
    const bundles = parseRoleBundles(text);
    if (!bundles) continue;
    const hasChain = bundles.includes("chain");
    const hasEvaluatorShared = bundles.includes("evaluator-shared");
    if (!(hasChain && hasEvaluatorShared)) continue;
    // Both present → require justification header comment.
    const hasJustification = /\/\/\s*chain\+evaluator-shared\s+justified:/i.test(
      text,
    );
    if (!hasJustification) {
      violations.push({
        file: path.relative(REPO_ROOT, file),
        bundles,
        drift_kind: "chain_bundle_widening_unjustified",
      });
    }
  }
  assert.deepEqual(
    violations,
    [],
    `chain-bundle audit failures → ${JSON.stringify(violations, null, 2)}`,
  );
});

test("rev 4.1 chain-bundle audit fires on a synthesized unjustified pairing (negative control)", () => {
  // Negative test: prove the auditor would detect drift. We synthesize a
  // string in-memory matching the role_bundles shape with both bundles
  // but no justification comment, and assert parseRoleBundles +
  // justification regex correctly classify it as a violation.
  const synthetic = `
"use strict";
const definition = {
  name: "synthetic_drift_tool",
  role_bundles: ["chain", "evaluator-shared"],
};
module.exports = { definition };
`;
  const bundles = parseRoleBundles(synthetic);
  assert.ok(bundles, "parseRoleBundles must extract role_bundles");
  assert.ok(bundles.includes("chain"));
  assert.ok(bundles.includes("evaluator-shared"));
  const hasJustification = /\/\/\s*chain\+evaluator-shared\s+justified:/i.test(
    synthetic,
  );
  assert.equal(
    hasJustification,
    false,
    "negative-control synthetic source MUST lack justification comment",
  );
});

test("rev 4.1 chain-bundle audit accepts a justified pairing (positive control)", () => {
  const synthetic = `
"use strict";
// chain+evaluator-shared justified: chain-builder needs graph mutation/query authority via the chain bundle (rev 4.1 defect 3 absorption); single-spawner topology preserved per Y.9 chain-bundle audit
const definition = {
  name: "synthetic_ok_tool",
  role_bundles: ["chain", "evaluator-shared"],
};
module.exports = { definition };
`;
  const bundles = parseRoleBundles(synthetic);
  assert.ok(bundles.includes("chain"));
  assert.ok(bundles.includes("evaluator-shared"));
  const hasJustification = /\/\/\s*chain\+evaluator-shared\s+justified:/i.test(
    synthetic,
  );
  assert.equal(hasJustification, true);
});

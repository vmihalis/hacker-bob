"use strict";

// Cycle Y.9 (rev 4.1) — `check:single-spawner-topology` test (Y-P8).
//
// Mechanical assertions on the rendered agent surface + tool registry:
//
//   1. Single-spawner topology: every rendered `.claude/agents/*.md`
//      frontmatter `tools:` line MUST NOT contain a `Task` token.
//      `Task` is the Claude Code subagent-spawn primitive; granting it
//      to any subagent would create peer-to-peer dispatch and violate
//      Y-P8 unconditionally.
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

const REPO_ROOT = path.join(__dirname, "..");
const AGENTS_DIR = path.join(REPO_ROOT, ".claude", "agents");
const TOOLS_DIR = path.join(REPO_ROOT, "mcp", "lib", "tools");

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

test("topology: Task token absent from every rendered agent frontmatter", () => {
  const offenders = [];
  for (const file of listAgentFiles()) {
    const fm = readAgentFrontmatter(file);
    if (!fm) continue;
    const toolsLineMatch = fm.match(/^tools:\s*(.*)$/m);
    if (!toolsLineMatch) continue;
    const toolsLine = toolsLineMatch[1];
    // Match `Task` as a standalone token (comma- or whitespace-separated).
    if (/\bTask\b/.test(toolsLine)) {
      offenders.push({ file: path.relative(REPO_ROOT, file), toolsLine });
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Y-P8 violation: agents carrying Task → ${JSON.stringify(offenders, null, 2)}`,
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
  const roleModel = require("../mcp/lib/role-model.js");
  for (const [exportName, exportedValue] of Object.entries(roleModel)) {
    if (exportName === "mcp_server_internal") {
      assert.fail(
        `mcp/lib/role-model.js MUST NOT export mcp_server_internal directly`,
      );
    }
    if (typeof exportedValue === "object" && exportedValue !== null) {
      for (const key of Object.keys(exportedValue)) {
        if (key === "mcp_server_internal") {
          assert.fail(
            `mcp/lib/role-model.js export ${exportName} contains mcp_server_internal key (grantable bundle)`,
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

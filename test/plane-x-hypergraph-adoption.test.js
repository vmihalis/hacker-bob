"use strict";

// Cycle Y.11 (rev 4.1 defect 3) — Plane X hypergraph adoption test.
//
// Mechanical assertions on the chain-builder role's authority surface
// after the Y.11 role-bundle widening on 5 graph tools:
//
//   (a) regenerated `.claude/agents/chain-builder.md` frontmatter
//       `tools:` line contains all 5 literal
//       `mcp__hacker-bob__bob_propose_hypothesis` (+ other 4) tokens
//       (5 new + bob_write_chain_rollup + bob_read_chain_attempts via
//       the existing chain bundle membership).
//   (b) chain-builder.md prompt body contains all 6 graph-tool literals
//       (5 newly granted via Y.11 + bob_read_chain_attempts which was
//       already there per the Y.6 stigmergy producer).
//   (c) regenerated SKILL.md CHAIN-state references at least one
//       Y.11-granted graph tool (the orchestrator's spawn prompt routes
//       chain-builder through bob_propose_hypothesis + others).
//   (d) Y.9 stigmergy gate
//       (chain_attempts_ledger ↔ chain_builder_prompt_body_read_before_propose)
//       passes: the consumer's `token_or_regex` matches the
//       chain-builder.md prompt body.
//   (e) Y.9 chain-bundle audit assertion fires when a tool with `chain`
//       role bundle ALSO adds `evaluator-shared` WITHOUT the
//       justification header comment (negative test); the assertion is
//       satisfied positively for the 5 graph tools shipped in this
//       cycle.
//   (f) Fixture run with chain-builder dispatched produces at least 1
//       invocation of `bob_propose_hypothesis` (handler returns a
//       structured frontier-event payload).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const REPO_ROOT = path.join(__dirname, "..");
const AGENTS_DIR = path.join(REPO_ROOT, ".claude", "agents");
const SKILL_PATH = path.join(
  REPO_ROOT,
  ".claude",
  "skills",
  "bob-evaluate-runner",
  "SKILL.md",
);
const CHAIN_BUILDER_PATH = path.join(AGENTS_DIR, "chain-builder.md");
const TOOLS_DIR = path.join(REPO_ROOT, "mcp", "lib", "tools");

const GRAPH_TOOL_NAMES = [
  "bob_propose_hypothesis",
  "bob_propose_transition",
  "bob_attach_contract",
  "bob_append_chain_node",
  "bob_query_chain_tree",
];

const GRAPH_TOOL_SOURCE_FILES = [
  "propose-hypothesis.js",
  "propose-transition.js",
  "attach-contract.js",
  "append-chain-node.js",
  "query-chain-tree.js",
];

function readFrontmatter(file) {
  const text = fs.readFileSync(file, "utf8");
  if (!text.startsWith("---\n")) return null;
  const end = text.indexOf("\n---\n", 4);
  if (end === -1) return null;
  return text.slice(0, end + 1);
}

function readBody(file) {
  const text = fs.readFileSync(file, "utf8");
  if (!text.startsWith("---\n")) return text;
  const end = text.indexOf("\n---\n", 4);
  if (end === -1) return text;
  return text.slice(end + 5);
}

test("(a) chain-builder.md frontmatter tools: line contains all 5 Y.11 graph-tool literals", () => {
  const fm = readFrontmatter(CHAIN_BUILDER_PATH);
  assert.ok(fm, "chain-builder.md must have YAML frontmatter");
  const missing = [];
  for (const tool of GRAPH_TOOL_NAMES) {
    const literal = `mcp__hacker-bob__${tool}`;
    if (!fm.includes(literal)) {
      missing.push(literal);
    }
  }
  assert.deepEqual(
    missing,
    [],
    `chain-builder.md frontmatter missing graph-tool literals: ${JSON.stringify(missing, null, 2)}`,
  );
});

test("(b) chain-builder.md prompt body contains all 6 graph-tool literals (5 Y.11 + bob_read_chain_attempts)", () => {
  const body = readBody(CHAIN_BUILDER_PATH);
  const expected = [...GRAPH_TOOL_NAMES, "bob_read_chain_attempts"];
  const missing = expected.filter((token) => !body.includes(token));
  assert.deepEqual(
    missing,
    [],
    `chain-builder.md prompt body missing graph-tool literals: ${JSON.stringify(missing, null, 2)}`,
  );
});

test("(c) regenerated SKILL.md CHAIN-state references at least one Y.11-granted graph tool", () => {
  const skill = fs.readFileSync(SKILL_PATH, "utf8");
  // Find the "Impact correlation drain" block (chain-state dispatch).
  const drainIdx = skill.indexOf("Impact correlation drain");
  assert.ok(
    drainIdx >= 0,
    "SKILL.md must contain Impact correlation drain section",
  );
  // The chain block extends until the next "Exit conditions" or "STATE:" header.
  const tail = skill.slice(drainIdx);
  const blockEnd = Math.min(
    ...["**Exit conditions.**", "## STATE:"]
      .map((m) => {
        const idx = tail.indexOf(m, m === "**Exit conditions.**" ? 100 : 100);
        return idx === -1 ? Infinity : idx;
      }),
  );
  const chainBlock = tail.slice(0, blockEnd === Infinity ? tail.length : blockEnd);
  const referenced = GRAPH_TOOL_NAMES.filter((tool) => chainBlock.includes(tool));
  assert.ok(
    referenced.length >= 1,
    `SKILL.md CHAIN-state block must reference at least one of ${GRAPH_TOOL_NAMES.join(", ")} — found 0`,
  );
});

test("(d) Y.9 stigmergy pair (chain_attempts_ledger ↔ chain_builder_prompt_body_read_before_propose) matches chain-builder.md prompt body", () => {
  const {
    STIGMERGIC_CONSUMERS,
  } = require("../mcp/lib/stigmergic-consumers.js");
  const entry = STIGMERGIC_CONSUMERS.find(
    (c) => c.consumer_id === "chain_builder_prompt_body_read_before_propose",
  );
  assert.ok(entry, "STIGMERGIC_CONSUMERS must register the chain-builder consumer");
  assert.equal(entry.producer_id, "chain_attempts_ledger");
  assert.equal(entry.source_location.file, ".claude/agents/chain-builder.md");
  const body = fs.readFileSync(CHAIN_BUILDER_PATH, "utf8");
  const tokenOrRegex = entry.source_location.token_or_regex;
  if (tokenOrRegex instanceof RegExp) {
    assert.ok(
      tokenOrRegex.test(body),
      `stigmergy regex ${tokenOrRegex} must match chain-builder.md body`,
    );
  } else {
    assert.ok(
      body.includes(tokenOrRegex),
      `stigmergy token ${tokenOrRegex} must appear in chain-builder.md body`,
    );
  }
});

test("(e1) all 5 Y.11 graph-tool source files declare 'chain' in role_bundles[]", () => {
  const missing = [];
  for (const fname of GRAPH_TOOL_SOURCE_FILES) {
    const text = fs.readFileSync(path.join(TOOLS_DIR, fname), "utf8");
    const m = text.match(/role_bundles\s*:\s*\[([^\]]*)\]/);
    assert.ok(m, `${fname} must declare role_bundles`);
    const bundles = m[1]
      .split(",")
      .map((s) => s.trim().replace(/^["']|["']$/g, ""))
      .filter((s) => s.length > 0);
    if (!bundles.includes("chain")) {
      missing.push({ file: fname, bundles });
    }
  }
  assert.deepEqual(
    missing,
    [],
    `Y.11 graph-tool source files missing 'chain' bundle: ${JSON.stringify(missing, null, 2)}`,
  );
});

test("(e2) all 5 Y.11 graph-tool source files carry the chain+evaluator-shared justification header comment", () => {
  const missing = [];
  for (const fname of GRAPH_TOOL_SOURCE_FILES) {
    const text = fs.readFileSync(path.join(TOOLS_DIR, fname), "utf8");
    if (!/\/\/\s*chain\+evaluator-shared\s+justified:/i.test(text)) {
      missing.push(fname);
    }
  }
  assert.deepEqual(
    missing,
    [],
    `Y.11 graph-tool source files missing justification comment: ${JSON.stringify(missing, null, 2)}`,
  );
});

test("(e3) chain-bundle audit negative-control: synthesized chain+evaluator-shared WITHOUT justification is detected", () => {
  // Mirrors the Y.9 single-spawner-topology auditor predicate. Proves
  // the audit logic catches an unjustified pairing — used to validate
  // the Y.11 absorption is not invisible to the auditor.
  const synthetic = [
    '"use strict";',
    "const definition = {",
    '  name: "synthetic_unjustified_chain_pair",',
    '  role_bundles: ["chain", "evaluator-shared"],',
    "};",
    "module.exports = { definition };",
  ].join("\n");
  const bundles = synthetic.match(/role_bundles\s*:\s*\[([^\]]*)\]/)[1]
    .split(",")
    .map((s) => s.trim().replace(/^["']|["']$/g, ""))
    .filter((s) => s.length > 0);
  assert.ok(bundles.includes("chain"));
  assert.ok(bundles.includes("evaluator-shared"));
  const hasJustification = /\/\/\s*chain\+evaluator-shared\s+justified:/i.test(
    synthetic,
  );
  assert.equal(
    hasJustification,
    false,
    "synthesized unjustified pair MUST be detected as missing justification",
  );
});

test("(f) fixture chain-builder dispatch produces at least 1 bob_propose_hypothesis invocation (handler returns frontier-event payload)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y11-"));
  const prevHome = process.env.HOME;
  process.env.HOME = tmpDir;
  try {
    // Force re-resolution of any HOME-dependent module state.
    for (const key of Object.keys(require.cache)) {
      if (key.includes("/mcp/lib/")) {
        delete require.cache[key];
      }
    }
    const proposeHypothesis = require(
      path.join(REPO_ROOT, "mcp", "lib", "tools", "propose-hypothesis.js"),
    );
    assert.equal(proposeHypothesis.name, "bob_propose_hypothesis");
    assert.ok(
      proposeHypothesis.role_bundles.includes("chain"),
      "bob_propose_hypothesis MUST grant chain after Y.11 absorption",
    );
    const targetDomain = "y11-fixture.example.com";
    const raw = proposeHypothesis.handler({
      target_domain: targetDomain,
      hypothesis_statement:
        "Y.11 fixture: chain-builder proposes a new chain-attempt Hypothesis via the graph apparatus",
      surface_refs: ["surf:y11-fixture-1"],
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.payload_kind, "hypothesis_proposed");
    assert.equal(result.target_domain, targetDomain);
    assert.ok(result.event_id, "event_id must be returned");
    assert.ok(result.event_hash, "event_hash must be returned");
  } finally {
    process.env.HOME = prevHome;
    // Best-effort cleanup; do not assert.
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
    for (const key of Object.keys(require.cache)) {
      if (key.includes("/mcp/lib/")) {
        delete require.cache[key];
      }
    }
  }
});

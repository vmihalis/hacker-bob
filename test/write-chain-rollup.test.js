"use strict";

// Y.3 Stage c — bob_write_chain_rollup (Y-D15c / Y-P13 / Y-P13b). Asserts:
//   * Renders chains.md with the operator-edit-warning banner
//   * Validates chain_id against chain-attempts.jsonl — unknown chain_id
//     returns NOT_FOUND with structured remediation
//   * Bounded narrative cap (≤ 4096 chars)
//   * finding_refs restricted to frontier_event:/verification_round: prefixes

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const writeChainRollupTool = require("../mcp/lib/tools/write-chain-rollup.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  chainAttemptsJsonlPath,
  chainsMarkdownPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-chain-rollup-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      throw new Error("withTempHome callers must be synchronous; use awaiting wrapper for async callers");
    }
    return result;
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedChainAttempt(domain, chainId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(
    chainAttemptsJsonlPath(domain),
    `${JSON.stringify({ chain_id: chainId, outcome: "confirmed", written_at: new Date().toISOString() })}\n`,
  );
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

test("bob_write_chain_rollup renders chains.md alongside chain-attempts.jsonl", () => {
  withTempHome(() => {
    const domain = "chains.example.com";
    seedChainAttempt(domain, "CH-1");
    const result = callTool(writeChainRollupTool, {
      target_domain: domain,
      chain_id: "CH-1",
      narrative: "F-1 leaks tokens which F-2 abuses to drain treasury.",
      finding_refs: ["frontier_event:e1", "verification_round:final:F-2"],
      confidence: "high",
    });
    assert.equal(result.chain_id, "CH-1");
    assert.match(result.chains_content_hash, /^[a-f0-9]{64}$/);
    const rendered = fs.readFileSync(chainsMarkdownPath(domain), "utf8");
    assert.match(rendered, /Chain Rollup/);
    assert.match(rendered, /CH-1/);
    assert.match(rendered, /Confidence:.*high/);
    assert.match(rendered, /F-1 leaks tokens/);
    assert.match(rendered, /This file is MCP-rendered/);
  });
});

test("bob_write_chain_rollup REJECTS unknown chain_id with structured remediation", () => {
  withTempHome(() => {
    const domain = "no-chain.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "missing-chain",
        narrative: "n",
        finding_refs: [],
        confidence: "low",
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.NOT_FOUND);
    assert.match(err.remediation, /bob_write_chain_attempt/);
  });
});

test("bob_write_chain_rollup enforces narrative cap at 4096 chars (Y-P13b)", () => {
  withTempHome(() => {
    const domain = "long.example.com";
    seedChainAttempt(domain, "CH-1");
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "x".repeat(4097),
        finding_refs: [],
        confidence: "medium",
      });
    } catch (e) { err = e; }
    assert.equal(err && err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /4096/);
  });
});

test("bob_write_chain_rollup rejects finding_refs that don't start with allowed prefix", () => {
  withTempHome(() => {
    const domain = "badref.example.com";
    seedChainAttempt(domain, "CH-1");
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "n",
        finding_refs: ["http_record:R1"],
        confidence: "low",
      });
    } catch (e) { err = e; }
    assert.equal(err && err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /frontier_event:|verification_round:/);
  });
});

test("bob_write_chain_rollup confidence must be low|medium|high", () => {
  withTempHome(() => {
    const domain = "conf.example.com";
    seedChainAttempt(domain, "CH-1");
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "n",
        finding_refs: [],
        confidence: "very_high",
      });
    } catch (e) { err = e; }
    assert.equal(err && err.code, ERROR_CODES.INVALID_ARGUMENTS);
  });
});

test("bob_write_chain_rollup tool spec carries Y_self_reporting capability + chain bundle", () => {
  assert.equal(writeChainRollupTool.name, "bob_write_chain_rollup");
  assert.equal(writeChainRollupTool.capability_id, "Y_self_reporting");
  assert.ok(writeChainRollupTool.role_bundles.includes("chain"));
  assert.ok(writeChainRollupTool.session_artifacts_written.includes("chains.md"));
});

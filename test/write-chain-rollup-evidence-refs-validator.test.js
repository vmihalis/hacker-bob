"use strict";

// Y.3 Stage c (Y-P14b / O4) — bob_write_chain_rollup `evidence_refs[]` validator.
// Asserts:
//   * Entries starting with EVIDENCE_REF_HANDLE_PREFIXES are accepted
//   * Literal evidence/<path> at or under LARGE_BODY_THRESHOLD_BYTES is accepted
//   * Literal evidence/<path> over LARGE_BODY_THRESHOLD_BYTES is rejected
//     with a remediation string naming all three accepted body-binding handles
//     literally
//   * Entries with unknown prefixes (e.g. static_artifact:) are rejected
//   * Pre-existing finding_refs[] validation is unchanged (still rejects
//     prefixes outside frontier_event:/verification_round:)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const writeChainRollupTool = require("../mcp/lib/tools/write-chain-rollup.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  LARGE_BODY_THRESHOLD_BYTES,
  chainAttemptsJsonlPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-chain-rollup-erefs-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      throw new Error("withTempHome callers must be synchronous");
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

function writeEvidence(domain, relPath, size) {
  const absolutePath = path.join(sessionDir(domain), relPath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  fs.writeFileSync(absolutePath, Buffer.alloc(size, "x"));
  return absolutePath;
}

test("evidence_refs[] accepts MCP-owned binding-handle prefixes", () => {
  withTempHome(() => {
    const domain = "erefs-handles.example.com";
    seedChainAttempt(domain, "CH-1");
    const result = callTool(writeChainRollupTool, {
      target_domain: domain,
      chain_id: "CH-1",
      narrative: "rollup with handle-bound evidence",
      finding_refs: ["frontier_event:e1"],
      evidence_refs: [
        "bob_import_http_traffic:abc",
        "bob_resolve_body:def",
        "bob_static_scan:ghi",
      ],
      confidence: "high",
    });
    assert.equal(result.evidence_refs_count, 3);
  });
});

test("evidence_refs[] accepts literal evidence/<path> at or under LARGE_BODY_THRESHOLD_BYTES", () => {
  withTempHome(() => {
    const domain = "erefs-small.example.com";
    seedChainAttempt(domain, "CH-1");
    writeEvidence(domain, "evidence/small.txt", LARGE_BODY_THRESHOLD_BYTES);
    const result = callTool(writeChainRollupTool, {
      target_domain: domain,
      chain_id: "CH-1",
      narrative: "rollup with small inline evidence",
      finding_refs: [],
      evidence_refs: ["evidence/small.txt"],
      confidence: "medium",
    });
    assert.equal(result.evidence_refs_count, 1);
  });
});

test("evidence_refs[] REJECTS literal evidence/<path> over LARGE_BODY_THRESHOLD_BYTES with remediation naming all three handles literally", () => {
  withTempHome(() => {
    const domain = "erefs-large.example.com";
    seedChainAttempt(domain, "CH-1");
    writeEvidence(domain, "evidence/large.html", LARGE_BODY_THRESHOLD_BYTES + 1);
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "rollup with oversized inline evidence",
        finding_refs: [],
        evidence_refs: ["evidence/large.html"],
        confidence: "low",
      });
    } catch (e) { err = e; }
    assert.ok(err, "expected ToolError for oversized evidence");
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.ok(typeof err.remediation === "string", "remediation must be a string");
    assert.ok(
      err.remediation.includes("bob_import_http_traffic"),
      "remediation must literally name bob_import_http_traffic",
    );
    assert.ok(
      err.remediation.includes("bob_resolve_body"),
      "remediation must literally name bob_resolve_body",
    );
    assert.ok(
      err.remediation.includes("bob_static_scan"),
      "remediation must literally name bob_static_scan",
    );
  });
});

test("evidence_refs[] REJECTS unknown-prefix handles (e.g. static_artifact:)", () => {
  withTempHome(() => {
    const domain = "erefs-bad-prefix.example.com";
    seedChainAttempt(domain, "CH-1");
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "rollup with disallowed prefix",
        finding_refs: [],
        evidence_refs: ["static_artifact:xyz"],
        confidence: "low",
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /bob_import_http_traffic/);
    assert.match(err.message, /bob_resolve_body/);
    assert.match(err.message, /bob_static_scan/);
  });
});

test("finding_refs[] validation is unchanged — still rejects non-frontier_event:/verification_round: prefixes", () => {
  withTempHome(() => {
    const domain = "frefs-unchanged.example.com";
    seedChainAttempt(domain, "CH-1");
    let err;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "CH-1",
        narrative: "rollup",
        finding_refs: ["bob_import_http_traffic:abc"],
        evidence_refs: [],
        confidence: "low",
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /frontier_event:/);
    assert.match(err.message, /verification_round:/);
  });
});

test("EVIDENCE_REF_HANDLE_PREFIXES is Object.freeze'd with the canonical body-binding handle set", () => {
  assert.ok(Array.isArray(writeChainRollupTool.EVIDENCE_REF_HANDLE_PREFIXES));
  assert.ok(Object.isFrozen(writeChainRollupTool.EVIDENCE_REF_HANDLE_PREFIXES));
  assert.deepEqual(
    [...writeChainRollupTool.EVIDENCE_REF_HANDLE_PREFIXES],
    ["bob_import_http_traffic:", "bob_resolve_body:", "bob_static_scan:"],
  );
  // bob_import_static_artifact is content-only for evm/solana token contracts
  // and is NOT a body-binding handle; assert it is absent from the set.
  assert.ok(
    !writeChainRollupTool.EVIDENCE_REF_HANDLE_PREFIXES.some(
      (prefix) => prefix.startsWith("bob_import_static_artifact"),
    ),
    "bob_import_static_artifact must NOT be in the body-binding handle set",
  );
});

test("LARGE_BODY_THRESHOLD_BYTES is exported from paths.js with value 262144", () => {
  assert.equal(LARGE_BODY_THRESHOLD_BYTES, 262144);
});

test("evidence_refs[] absent defaults to empty array (back-compat with shipped pre-rev-4.1 schema)", () => {
  withTempHome(() => {
    const domain = "erefs-omitted.example.com";
    seedChainAttempt(domain, "CH-1");
    const result = callTool(writeChainRollupTool, {
      target_domain: domain,
      chain_id: "CH-1",
      narrative: "rollup without evidence_refs",
      finding_refs: ["frontier_event:e1"],
      confidence: "high",
    });
    assert.equal(result.evidence_refs_count, 0);
  });
});

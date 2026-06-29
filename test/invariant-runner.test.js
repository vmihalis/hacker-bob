"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  runInvariantForFinding,
  readInvariantRuns,
  buildTestSource,
  deriveTestNamesFromTemplate,
  renameTestFunction,
  classifyFoundryOutcome,
  classifyFoundryViolation,
  classifyHalmosViolation,
  adjudicateInvariantDifferential,
  verifyInvariantDifferential,
  readInvariantVerifiedSummary,
  computeInvariantRunHash,
  invariantFoundryResultHash,
} = require("../mcp/lib/invariant-runner.js");
const {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  invariantRunsJsonlPath,
  invariantVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");

function uniqueDomain(prefix = "bob-invariant-runner-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function makeHarness() {
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-foundry-harness-"));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  return harness;
}

function cleanupHarness(harnessPath) {
  if (harnessPath && fs.existsSync(harnessPath)) {
    fs.rmSync(harnessPath, { recursive: true, force: true });
  }
}

const SAMPLE_REENTRANCY_FINDING = Object.freeze({
  finding_id: "F-1",
  finding_hash: "h1",
  title: "Reentrancy in withdraw",
  vulnerability_class: "reentrancy",
  description: "external call before state update",
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForFile(filePath, timeoutMs = 5000) {
  const start = Date.now();
  while (!fs.existsSync(filePath)) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`Timed out waiting for file: ${filePath}`);
    }
    await sleep(25);
  }
}

async function waitForAnyFile(filePaths, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start <= timeoutMs) {
    const found = filePaths.find((filePath) => fs.existsSync(filePath));
    if (found) return found;
    await sleep(25);
  }
  throw new Error(`Timed out waiting for any file: ${filePaths.join(", ")}`);
}

function spawnInvariantRecordChild({
  domain,
  harness,
  barrierDir,
  tag,
  findingHash = `finding-${tag}`,
  targetContract = `Pool${tag}`,
  withdrawAmount = "1",
}) {
  const invariantRunnerPath = path.join(__dirname, "..", "mcp", "lib", "invariant-runner.js");
  const script = `
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runInvariantForFinding } = require(${JSON.stringify(invariantRunnerPath)});
const domain = ${JSON.stringify(domain)};
const harness = ${JSON.stringify(harness)};
const barrierDir = ${JSON.stringify(barrierDir)};
const tag = ${JSON.stringify(tag)};
const findingHash = ${JSON.stringify(findingHash)};
const targetContract = ${JSON.stringify(targetContract)};
const withdrawAmount = ${JSON.stringify(withdrawAmount)};
const signal = new Int32Array(new SharedArrayBuffer(4));
function waitForFile(filePath, label) {
  const deadline = Date.now() + 15000;
  while (!fs.existsSync(filePath)) {
    if (Date.now() > deadline) {
      throw new Error("Timed out waiting for " + label + ": " + filePath);
    }
    Atomics.wait(signal, 0, 0, 25);
  }
}
const invariantRunsPath = path.join(os.homedir(), "hacker-bob-sessions", domain, "invariant-runs.jsonl");
const originalOpenSync = fs.openSync;
let pausedOnInvariantRead = false;
fs.openSync = function patchedOpenSync(filePath, ...args) {
  const normalized = typeof filePath === "string" ? path.resolve(filePath) : "";
  if (!pausedOnInvariantRead && normalized === path.resolve(invariantRunsPath)) {
    pausedOnInvariantRead = true;
    fs.writeFileSync(path.join(barrierDir, "read-" + tag), "1\\n");
    waitForFile(path.join(barrierDir, "release-read-" + tag), "release-read-" + tag);
  }
  return originalOpenSync.apply(this, [filePath, ...args]);
};
(async () => {
  await runInvariantForFinding({
    target_domain: domain,
    finding: {
      finding_id: "F-1",
      finding_hash: findingHash,
      title: "Reentrancy " + tag,
      vulnerability_class: "reentrancy",
      description: "external call before state update"
    },
    slot_values: {
      target_contract: targetContract,
      vulnerable_function: "withdraw",
      withdraw_amount: withdrawAmount
    },
    harness_path: harness,
    foundry_run: async () => {
      fs.writeFileSync(path.join(barrierDir, "foundry-ready-" + tag), "1\\n");
      waitForFile(path.join(barrierDir, "release-foundry"), "release-foundry");
      return { tests: [{ success: true }] };
    },
    run_id: tag
  });
})().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
`;
  const child = spawn(process.execPath, ["-e", script], {
    cwd: path.join(__dirname, ".."),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  const done = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signalValue) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`Invariant child ${tag} exited with code ${code} signal ${signalValue}\nstdout:\n${stdout}\nstderr:\n${stderr}`));
      }
    });
  });
  return { child, done };
}

async function releasePausedInvariantRecordChildren(barrierDir) {
  await Promise.all([
    waitForFile(path.join(barrierDir, "foundry-ready-a")),
    waitForFile(path.join(barrierDir, "foundry-ready-b")),
  ]);
  fs.writeFileSync(path.join(barrierDir, "release-foundry"), "1\n");

  const readA = path.join(barrierDir, "read-a");
  const readB = path.join(barrierDir, "read-b");
  const firstReadPath = await waitForAnyFile([readA, readB]);
  const firstTag = firstReadPath === readA ? "a" : "b";
  const secondTag = firstTag === "a" ? "b" : "a";
  const secondReadPath = secondTag === "a" ? readA : readB;

  await sleep(300);
  assert.equal(
    fs.existsSync(secondReadPath),
    false,
    "the session lock must keep the second process from reading stale invariant-runs.jsonl before the first write completes",
  );

  fs.writeFileSync(path.join(barrierDir, `release-read-${firstTag}`), "1\n");
  await waitForFile(secondReadPath);
  fs.writeFileSync(path.join(barrierDir, `release-read-${secondTag}`), "1\n");
}

test("renameTestFunction swaps the function identifier without touching the body", () => {
  const original = "function testFoo() public { assertTrue(true); }";
  const renamed = renameTestFunction(original, "testNewName");
  assert.match(renamed, /function testNewName\(/);
  assert.match(renamed, /assertTrue\(true\)/);
  assert.doesNotMatch(renamed, /testFoo/);
});

test("renameTestFunction ignores comments and rejects ambiguous templates", () => {
  const withComment = [
    "// function testCommentTrap() public {}",
    "function testReal() public { assertTrue(true); }",
  ].join("\n");
  const renamed = renameTestFunction(withComment, "testNewName");
  assert.match(renamed, /function testNewName\(/);
  assert.match(renamed, /testCommentTrap/);
  assert.doesNotMatch(renamed, /function testReal\(/);

  const withBlockComment = [
    "/*",
    "function testBlockCommentTrap() public {}",
    "*/",
    "function testReal() public { assertTrue(true); }",
  ].join("\n");
  const renamedBlock = renameTestFunction(withBlockComment, "testNewName");
  assert.match(renamedBlock, /function testNewName\(/);
  assert.match(renamedBlock, /testBlockCommentTrap/);

  const withStringTrap = [
    "function testReal() public {",
    "    string memory payload = \"\\nfunction testStringTrap() public {}\";",
    "    assertTrue(bytes(payload).length > 0);",
    "}",
  ].join("\n");
  const renamedString = renameTestFunction(withStringTrap, "testNewName");
  assert.match(renamedString, /function testNewName\(/);
  assert.match(renamedString, /testStringTrap/);

  const withInlineBlockComment = "function testOriginal /* selector note */ () public { assertTrue(true); }";
  const renamedInlineComment = renameTestFunction(withInlineBlockComment, "testNewName");
  assert.match(renamedInlineComment, /function testNewName/);

  assert.throws(
    () => renameTestFunction("function helper() internal {}\nfunction testReal() public {}", "testNewName"),
    /exactly one function declaration; found 2/,
  );
  assert.throws(
    () => renameTestFunction("// function onlyInComment() public {}", "testNewName"),
    /exactly one function declaration; found 0/,
  );
});

test("buildTestSource produces a valid Solidity test contract envelope", () => {
  const source = buildTestSource({ contractName: "MyTest", functionBody: "function testX() public {}" });
  assert.match(source, /pragma solidity/);
  assert.match(source, /contract MyTest is Test \{/);
  assert.match(source, /function testX\(\) public \{\}/);
  assert.match(source, /function setUp\(\) public virtual/);
});

test("deriveTestNamesFromTemplate produces stable, sanitized identifiers", () => {
  const template = { template_id: "INV-REENTRANCY-CALLBACK-001", foundry_test: "function testFoo() {}" };
  const a = deriveTestNamesFromTemplate(template, SAMPLE_REENTRANCY_FINDING);
  const b = deriveTestNamesFromTemplate(template, SAMPLE_REENTRANCY_FINDING);
  assert.deepEqual(a, b);
  assert.match(a.contract_name, /^BobInvariantTest_/);
  assert.match(a.function_name, /^testBobInvariant_/);
});

test("deriveTestNamesFromTemplate includes slot values in the generated test identity", () => {
  const template = { template_id: "INV-REENTRANCY-CALLBACK-001", foundry_test: "function testFoo() {}" };
  const first = deriveTestNamesFromTemplate(template, SAMPLE_REENTRANCY_FINDING, {
    target_contract: "PoolA",
    vulnerable_function: "withdraw",
    withdraw_amount: "1",
  });
  const firstReordered = deriveTestNamesFromTemplate(template, SAMPLE_REENTRANCY_FINDING, {
    withdraw_amount: "1",
    vulnerable_function: "withdraw",
    target_contract: "PoolA",
  });
  const second = deriveTestNamesFromTemplate(template, SAMPLE_REENTRANCY_FINDING, {
    target_contract: "PoolB",
    vulnerable_function: "withdraw",
    withdraw_amount: "1",
  });
  assert.deepEqual(first, firstReordered);
  assert.notEqual(first.contract_name, second.contract_name);
  assert.notEqual(first.function_name, second.function_name);
});

// MINT ≠ CONFIRM: classifyFoundryOutcome maps a single run to its per-run
// PRIMITIVE (test_passed/test_failed/...). test_passed is an OBSERVATION here, NOT
// a verified verdict — confirmation is the differential FLIP adjudicated by
// verifyInvariantDifferential. Do not re-couple this primitive to verification.
test("classifyFoundryOutcome maps tests array, kind tags, and success flag", () => {
  assert.equal(classifyFoundryOutcome({ tests: [{ success: true }] }), "test_passed");
  assert.equal(classifyFoundryOutcome({ tests: [{ success: false }] }), "test_failed");
  assert.equal(classifyFoundryOutcome({ ok: true, tests: [{ status: "Pass" }], summary: { failed: 0 } }), "test_passed");
  assert.equal(classifyFoundryOutcome({ ok: false, tests: [{ status: "Fail" }], summary: { failed: 1 } }), "test_failed");
  assert.equal(classifyFoundryOutcome({ kind: "foundry_fork" }), "fork_blocked");
  assert.equal(classifyFoundryOutcome({ reason: "rpc_unreachable" }), "fork_blocked");
  assert.equal(classifyFoundryOutcome({ reason: "no_fork_endpoints_for_chain" }), "fork_blocked");
  assert.equal(classifyFoundryOutcome({ kind: "forge_not_in_path" }), "forge_missing");
  assert.equal(classifyFoundryOutcome({ reason: "forge_not_in_path" }), "forge_missing");
  assert.equal(classifyFoundryOutcome({ success: true }), "test_passed");
  assert.equal(classifyFoundryOutcome({ success: false }), "test_failed");
  assert.equal(classifyFoundryOutcome({}), "unknown");
});

test("dry_run returns a report without writing the test file or persisting", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      dry_run: true,
    });
    assert.equal(result.dry_run, true);
    assert.equal(result.outcome, "dry_run");
    assert.match(result.contract_name, /^BobInvariantTest_/);
    assert.equal(result.test_path, null);
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.total_in_corpus, 0);
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

// SECURITY: the cross-stack target binding's on-chain cross-check MUST query the operator-
// pinned TRUSTED RPC ladder, never the AGENT-supplied fork_urls. The agent controls the fork
// (and thus the executed target's bytecode), so resolving the "independent" on-chain value
// through the same agent endpoints would let the agent serve a fake bytecode matching its fake
// target — a forged verified_pass. This locks that agent fork_urls never reach the cross-check.
test("cross-stack target cross-check uses the TRUSTED ladder, NOT agent-supplied fork_urls (forgery fix)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const evmClient = require("../mcp/lib/evm-client.js");
  const originalAgreed = evmClient.ethGetCodeAgreed;
  let agreedArgs = null;
  evmClient.ethGetCodeAgreed = async (args) => { agreedArgs = args; return { status: "unavailable", reason: "stubbed" }; };
  const stubFoundry = async () => ({
    tests: [{ name: "testX", success: false }],
    // The pinned template's emitted binding (address + sha256 of the executed target bytecode).
    target_binding: { address: `0x${"ab".repeat(20)}`, code_sha256: `0x${"cd".repeat(32)}` },
  });
  try {
    await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-xstack-trust",
      chain_id: 1,
      fork_block: 21000000,
      // The AGENT supplies these. They drive the FORK, but must NOT reach the on-chain cross-check.
      fork_urls: ["https://attacker-controlled.example/rpc"],
    });
    assert.ok(agreedArgs, "the on-chain cross-check ran");
    assert.equal(agreedArgs.chainId, 1);
    assert.equal(agreedArgs.block, 21000000);
    // THE FIX: agent fork_urls are NOT passed as endpoints — ethGetCodeAgreed resolves the
    // operator-pinned trusted ladder itself. A regression that re-passes fork_urls fails here.
    assert.equal(agreedArgs.endpoints, undefined, "agent fork_urls must NOT reach the on-chain cross-check");
  } finally {
    evmClient.ethGetCodeAgreed = originalAgreed;
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

// SEALED ROUTING — the cross-stack template executes the RUNNER-OWNED sealed Foundry project, not
// the agent harness, so no agent Solidity / forge-std / setUp is on the execution path (closes the
// cheatcode forgery). The runner stamps the MAC-covered sealed_harness:true that the verifier requires.
test("SEALED ROUTING: a cross-stack invariant run executes the runner-owned SEALED project (NOT the agent harness) and stamps sealed_harness:true", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness(); // the agent harness — MUST be ignored for a sealed cross-stack run
  let foundryCall = null;
  let sealedSrc = null;
  const stubFoundry = async (args) => {
    foundryCall = args;
    // Capture the source DURING the run (the runner removes the sealed temp project afterward).
    try { sealedSrc = fs.readFileSync(args.match_path, "utf8"); } catch {}
    return { tests: [{ name: "t", success: false }] };
  };
  try {
    await runInvariantForFinding({
      target_domain: domain,
      finding: { finding_id: "F-1", finding_hash: "h1", title: "web auth replay on-chain", vulnerability_class: "signature_validation" },
      template_id: "INV-CROSS-STACK-AUTH-REPLAY-001",
      slot_values: { target_address: `0x${"ab".repeat(20)}`, gated_function: "execute", victim_type: "uint256", victim_value: "7" },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-sealed-1",
      chain_id: 1,
      fork_block: 21000000,
      fork_urls: ["https://attacker-controlled.example/rpc"], // drives the fork; the SOURCE is runner-owned
    });
    assert.ok(foundryCall, "foundry_run was invoked");
    assert.notEqual(foundryCall.harness_path, harness, "the agent harness_path is NOT used for a sealed run");
    assert.match(foundryCall.harness_path, /\.bob-sealed-xstack-/, "forge ran the runner-owned sealed project");
    assert.ok(sealedSrc, "the sealed test file existed during the run");
    assert.ok(!/import\s+["']forge-std/.test(sealedSrc), "no forge-std on the build path");
    assert.match(sealedSrc, /interface IBobVm/, "inlined Vm (self-contained)");
    assert.match(sealedSrc, /target\.execute\(7, capturedAuth\)/, "gated call built from the DATA slots");
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.runs.length, 1);
    assert.equal(corpus.runs[0].sealed_harness, true, "the row carries the MAC-covered sealed_harness marker");
    // The runner removed the sealed temp project after the run (single-use).
    assert.ok(!fs.existsSync(path.dirname(path.dirname(foundryCall.match_path))), "sealed project cleaned up");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("SEALED ROUTING: a cross-stack run with a malformed DATA slot is REFUSED (no Solidity injection, never runs)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  let ran = false;
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: { finding_id: "F-1", finding_hash: "h1", title: "x", vulnerability_class: "signature_validation" },
        template_id: "INV-CROSS-STACK-AUTH-REPLAY-001",
        // target_address is a Solidity expression, not a 20-byte address — the generator refuses it.
        slot_values: { target_address: "address(this)", gated_function: "execute", victim_type: "uint256", victim_value: "7" },
        harness_path: harness,
        foundry_run: async () => { ran = true; return { tests: [{ success: false }] }; },
        run_id: "inv-sealed-bad",
        chain_id: 1, fork_block: 1, fork_urls: ["https://x.example/rpc"],
      }),
      /target_address must be a 20-byte/,
    );
    assert.equal(ran, false, "forge never ran on a malformed slot");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

// The persisted test_passed here is the per-run PRIMITIVE (MINT), not a verified
// verdict (CONFIRM). A verified FV finding requires the differential flip via
// verifyInvariantDifferential; this test only asserts the run is recorded.
test("runInvariantForFinding writes the test file, dispatches foundry_run, and persists the result", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  let foundryCall = null;
  const stubFoundry = async (args) => {
    foundryCall = args;
    return { tests: [{ name: "testX", success: true, gas: 12345 }] };
  };
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-001",
    });
    assert.equal(result.outcome, "test_passed");
    assert.ok(result.test_path && fs.existsSync(result.test_path));
    assert.equal(foundryCall.harness_path, harness);
    assert.equal(foundryCall.match_test, result.function_name);
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.total_in_corpus, 1);
    assert.equal(corpus.runs[0].run_id, "inv-001");
    assert.equal(corpus.runs[0].outcome, "test_passed");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("re-running the same (finding, template, slot_values) upserts the same run_hash", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const stubFoundry = async () => ({ tests: [{ success: true }] });
  try {
    const first = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });
    const second = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });
    assert.equal(first.run_hash, second.run_hash);
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.total_in_corpus, 1);
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("runs for duplicate audit findings keep distinct final finding run_hashes", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const stubFoundry = async () => ({ tests: [{ success: true }] });
  try {
    const first = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });
    const second = await runInvariantForFinding({
      target_domain: domain,
      finding: {
        ...SAMPLE_REENTRANCY_FINDING,
        finding_id: "F-2",
      },
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });

    assert.notEqual(first.run_hash, second.run_hash);
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.total_in_corpus, 2);
    assert.deepEqual(new Set(corpus.runs.map((run) => run.finding_id)), new Set(["F-1", "F-2"]));
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("run_hash binds invariant outcome and Foundry result", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const slotValues = { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" };
    const passed = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: slotValues,
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });
    const failed = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: slotValues,
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: false }] }),
    });

    assert.notEqual(passed.run_hash, failed.run_hash);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 2);
    for (const row of corpus.runs) {
      assert.equal(row.foundry_result_hash, invariantFoundryResultHash(row.foundry_result));
      assert.equal(row.run_hash, computeInvariantRunHash(row));
    }
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("runs for different execution contexts keep distinct JSONL records", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  try {
    const first = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      fork_block: 1,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });
    const second = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      fork_block: 2,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });

    assert.notEqual(first.run_hash, second.run_hash);
    assert.notEqual(first.execution_context_hash, second.execution_context_hash);
    const records = readInvariantRuns({ target_domain: domain });
    assert.equal(records.runs.length, 2);
    assert.deepEqual(new Set(records.runs.map((run) => run.run_hash)), new Set([first.run_hash, second.run_hash]));
    assert.deepEqual(new Set(records.runs.map((run) => run.fork_block)), new Set([1, 2]));
  } finally {
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects custom match overrides that diverge from generated names", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        match_test: "testDifferentName",
        foundry_run: async () => ({ tests: [{ success: true }] }),
      }),
      /match_test overrides are unsupported/,
    );
  } finally {
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("concurrent runs for the same finding with different slot values write distinct source files", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const [first, second] = await Promise.all([
      runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "PoolA", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
        run_id: "slot-a",
      }),
      runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "PoolB", vulnerable_function: "withdraw", withdraw_amount: "2" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
        run_id: "slot-b",
      }),
    ]);

    assert.notEqual(first.contract_name, second.contract_name);
    assert.notEqual(first.function_name, second.function_name);
    assert.notEqual(first.test_path, second.test_path);
    assert.match(fs.readFileSync(first.test_path, "utf8"), /PoolA/);
    assert.match(fs.readFileSync(second.test_path, "utf8"), /PoolB/);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 2);
    assert.deepEqual(corpus.runs.map((run) => run.run_id).sort(), ["slot-a", "slot-b"]);
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("concurrent invariant runs serialize invariant-runs.jsonl upserts", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const barrierDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-jsonl-lock-"));
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  let childA = null;
  let childB = null;
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.writeFileSync(runsPath, "", "utf8");
    childA = spawnInvariantRecordChild({ domain, harness, barrierDir, tag: "a" });
    childB = spawnInvariantRecordChild({ domain, harness, barrierDir, tag: "b" });

    await releasePausedInvariantRecordChildren(barrierDir);
    await Promise.all([childA.done, childB.done]);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 2);
    assert.deepEqual(corpus.runs.map((run) => run.run_id).sort(), ["a", "b"]);
  } finally {
    if (childA) childA.child.kill("SIGKILL");
    if (childB) childB.child.kill("SIGKILL");
    try { fs.rmSync(barrierDir, { recursive: true, force: true }); } catch {}
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("cross-process runs for the same finding with different slot values keep distinct source and records", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const barrierDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-slot-process-"));
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  let childA = null;
  let childB = null;
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.writeFileSync(runsPath, "", "utf8");
    childA = spawnInvariantRecordChild({
      domain,
      harness,
      barrierDir,
      tag: "a",
      findingHash: "shared-finding",
      targetContract: "PoolA",
      withdrawAmount: "1",
    });
    childB = spawnInvariantRecordChild({
      domain,
      harness,
      barrierDir,
      tag: "b",
      findingHash: "shared-finding",
      targetContract: "PoolB",
      withdrawAmount: "2",
    });

    await releasePausedInvariantRecordChildren(barrierDir);
    await Promise.all([childA.done, childB.done]);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 2);
    const byRunId = new Map(corpus.runs.map((run) => [run.run_id, run]));
    const first = byRunId.get("a");
    const second = byRunId.get("b");
    assert.ok(first);
    assert.ok(second);
    assert.equal(first.finding_hash, "shared-finding");
    assert.equal(second.finding_hash, "shared-finding");
    assert.notEqual(first.contract_name, second.contract_name);
    assert.notEqual(first.function_name, second.function_name);
    assert.notEqual(first.test_path, second.test_path);
    assert.match(fs.readFileSync(first.test_path, "utf8"), /PoolA/);
    assert.match(fs.readFileSync(second.test_path, "utf8"), /PoolB/);
  } finally {
    if (childA) childA.child.kill("SIGKILL");
    if (childB) childB.child.kill("SIGKILL");
    try { fs.rmSync(barrierDir, { recursive: true, force: true }); } catch {}
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("runInvariantForFinding replaces symlinked invariant-runs.jsonl without importing target records", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-jsonl-symlink-"));
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  const outsideRunsPath = path.join(outside, "outside-runs.jsonl");
  const poison = {
    run_hash: "poisoned-run",
    target_domain: domain,
    finding_hash: "poisoned-finding",
    outcome: "test_passed",
  };
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.writeFileSync(outsideRunsPath, `${JSON.stringify(poison)}\n`, "utf8");
    fs.symlinkSync(outsideRunsPath, runsPath);

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
      run_id: "jsonl-symlink-replace",
    });

    assert.equal(fs.readFileSync(outsideRunsPath, "utf8"), `${JSON.stringify(poison)}\n`);
    assert.equal(fs.lstatSync(runsPath).isSymbolicLink(), false);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 1);
    assert.equal(corpus.runs[0].run_hash, result.run_hash);
    assert.equal(corpus.runs[0].run_id, "jsonl-symlink-replace");
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding replaces hard-linked invariant-runs.jsonl without importing target records", async (t) => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.homedir(), ".bob-invariant-jsonl-hardlink-"));
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  const outsideRunsPath = path.join(outside, "outside-runs.jsonl");
  const poison = {
    run_hash: "hardlink-poisoned-run",
    target_domain: domain,
    finding_hash: "hardlink-poisoned-finding",
    outcome: "test_passed",
  };
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.writeFileSync(outsideRunsPath, `${JSON.stringify(poison)}\n`, "utf8");
    try {
      fs.linkSync(outsideRunsPath, runsPath);
    } catch (error) {
      if (error && ["EPERM", "EXDEV", "EOPNOTSUPP"].includes(error.code)) {
        t.skip(`hard links unavailable in this test filesystem: ${error.code}`);
        return;
      }
      throw error;
    }

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
      run_id: "jsonl-hardlink-replace",
    });

    assert.equal(fs.readFileSync(outsideRunsPath, "utf8"), `${JSON.stringify(poison)}\n`);
    assert.equal(fs.statSync(runsPath).nlink, 1);
    const corpus = readInvariantRuns({ target_domain: domain, limit: 10 });
    assert.equal(corpus.total_in_corpus, 1);
    assert.equal(corpus.runs[0].run_hash, result.run_hash);
    assert.equal(corpus.runs[0].run_id, "jsonl-hardlink-replace");
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("readInvariantRuns rejects a dangling symlinked invariant-runs.jsonl", () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.symlinkSync(path.join(sessionPath, "missing-runs.jsonl"), runsPath);
    assert.throws(
      () => readInvariantRuns({ target_domain: domain }),
      /must be a regular file, not a symlink/,
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("readInvariantRuns rejects hard-linked invariant-runs.jsonl", (t) => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const outside = fs.mkdtempSync(path.join(os.homedir(), ".bob-invariant-jsonl-hardlink-read-"));
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  const outsideRunsPath = path.join(outside, "outside-runs.jsonl");
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.writeFileSync(outsideRunsPath, "", "utf8");
    try {
      fs.linkSync(outsideRunsPath, runsPath);
    } catch (error) {
      if (error && ["EPERM", "EXDEV", "EOPNOTSUPP"].includes(error.code)) {
        t.skip(`hard links unavailable in this test filesystem: ${error.code}`);
        return;
      }
      throw error;
    }
    assert.throws(
      () => readInvariantRuns({ target_domain: domain }),
      /must not be hard-linked/,
    );
  } finally {
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("readInvariantRuns enforces the JSONL read cap while reading from the descriptor", () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  const originalFstatSync = fs.fstatSync;
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    fs.closeSync(fs.openSync(runsPath, "w"));
    fs.truncateSync(runsPath, 16 * 1024 * 1024 + 1);
    fs.fstatSync = function patchedFstatSync(fd, ...args) {
      const stats = originalFstatSync.apply(this, [fd, ...args]);
      return new Proxy(stats, {
        get(target, property, receiver) {
          if (property === "size") return 0;
          return Reflect.get(target, property, receiver);
        },
      });
    };
    assert.throws(
      () => readInvariantRuns({ target_domain: domain }),
      /exceeds read cap/,
    );
  } finally {
    fs.fstatSync = originalFstatSync;
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects JSONL writes that would exceed the read cap", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const runsPath = path.join(os.homedir(), "hacker-bob-sessions", domain, "invariant-runs.jsonl");
  try {
    const oversizedEvidence = "x".repeat(DEFAULT_ARTIFACT_READ_MAX_BYTES + 1);
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }], oversized_evidence: oversizedEvidence }),
      }),
      /invariant-runs\.jsonl record exceeds write cap/,
    );
    assert.equal(fs.existsSync(runsPath), false);
  } finally {
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding trims oldest JSONL records to stay under the read cap", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const sessionPath = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const runsPath = path.join(sessionPath, "invariant-runs.jsonl");
  try {
    fs.mkdirSync(sessionPath, { recursive: true });
    let payloadLength = DEFAULT_ARTIFACT_READ_MAX_BYTES - 512;
    let oldRecord = null;
    let oldContent = "";
    while (payloadLength > 0) {
      oldRecord = {
        run_hash: "old-run",
        recorded_at: "2000-01-01T00:00:00.000Z",
        foundry_result: { payload: "x".repeat(payloadLength) },
      };
      oldContent = `${JSON.stringify(oldRecord)}\n`;
      const byteLength = Buffer.byteLength(oldContent, "utf8");
      if (byteLength < DEFAULT_ARTIFACT_READ_MAX_BYTES && byteLength > DEFAULT_ARTIFACT_READ_MAX_BYTES - 4096) {
        break;
      }
      payloadLength -= 512;
    }
    assert.ok(Buffer.byteLength(oldContent, "utf8") < DEFAULT_ARTIFACT_READ_MAX_BYTES);
    fs.writeFileSync(runsPath, oldContent, "utf8");

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }], padding: "y".repeat(8192) }),
    });

    assert.deepEqual(result.invariant_runs_retention, {
      total: 2,
      retained: 1,
      dropped: 1,
      max_bytes: DEFAULT_ARTIFACT_READ_MAX_BYTES,
    });
    const records = readInvariantRuns({ target_domain: domain });
    assert.deepEqual(records.runs.map((run) => run.run_hash), [result.run_hash]);
    assert.ok(Buffer.byteLength(fs.readFileSync(runsPath, "utf8"), "utf8") <= DEFAULT_ARTIFACT_READ_MAX_BYTES);
  } finally {
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects invariant-runs.jsonl temp hard-link races", async (t) => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.homedir(), ".bob-invariant-jsonl-temp-hardlink-"));
  const hardlinkPath = path.join(outside, "temp-hardlink.jsonl");
  const originalRenameSync = fs.renameSync;
  try {
    const probeSource = path.join(outside, "probe-source");
    const probeLink = path.join(outside, "probe-link");
    fs.writeFileSync(probeSource, "", "utf8");
    try {
      fs.linkSync(probeSource, probeLink);
    } catch (error) {
      if (error && ["EPERM", "EXDEV", "EOPNOTSUPP"].includes(error.code)) {
        t.skip(`hard links unavailable in this test filesystem: ${error.code}`);
        return;
      }
      throw error;
    }
    fs.renameSync = function patchedRenameSync(oldPath, newPath) {
      if (
        typeof oldPath === "string"
        && typeof newPath === "string"
        && path.basename(newPath) === "invariant-runs.jsonl"
        && path.basename(oldPath).includes("invariant-runs.jsonl")
        && !fs.existsSync(hardlinkPath)
      ) {
        fs.linkSync(oldPath, hardlinkPath);
      }
      return originalRenameSync.apply(this, arguments);
    };

    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
      }),
      /invariant-runs\.jsonl file must not be hard-linked/,
    );
    const runsPath = path.join(os.homedir(), "hacker-bob-sessions", domain, "invariant-runs.jsonl");
    assert.equal(fs.existsSync(runsPath), false);
  } finally {
    fs.renameSync = originalRenameSync;
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding attempts invariant-runs.jsonl cleanup when post-rename lstat fails", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const runsPath = path.join(os.homedir(), "hacker-bob-sessions", domain, "invariant-runs.jsonl");
  const originalRenameSync = fs.renameSync;
  const originalLstatSync = fs.lstatSync;
  let jsonlRenamed = false;
  try {
    fs.renameSync = function patchedRenameSync(oldPath, newPath) {
      const result = originalRenameSync.apply(this, arguments);
      if (
        typeof newPath === "string"
        && path.resolve(newPath) === path.resolve(runsPath)
        && path.basename(oldPath).includes("invariant-runs.jsonl")
      ) {
        jsonlRenamed = true;
      }
      return result;
    };
    fs.lstatSync = function patchedLstatSync(filePath, ...args) {
      if (jsonlRenamed && typeof filePath === "string" && path.resolve(filePath) === path.resolve(runsPath)) {
        const error = new Error("simulated JSONL post-rename lstat failure");
        error.code = "EACCES";
        throw error;
      }
      return originalLstatSync.apply(this, [filePath, ...args]);
    };

    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
      }),
      /invariant-runs\.jsonl file must be a regular file inside the target directory/,
    );
    assert.equal(fs.existsSync(runsPath), false);
  } finally {
    fs.renameSync = originalRenameSync;
    fs.lstatSync = originalLstatSync;
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding removes final files that fail post-rename validation", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-final-validation-"));
  const outsideTarget = path.join(outside, "outside.t.sol");
  const originalRealpathSync = fs.realpathSync;
  try {
    fs.writeFileSync(outsideTarget, "outside\n", "utf8");
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const finalPath = path.join(harness, "test", "bob-invariants", `${plan.contract_name}.t.sol`);
    fs.realpathSync = function patchedRealpathSync(filePath, ...args) {
      if (typeof filePath === "string" && path.resolve(filePath) === path.resolve(finalPath)) {
        return outsideTarget;
      }
      return originalRealpathSync.apply(this, [filePath, ...args]);
    };

    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
      }),
      /Foundry invariant test file must be a regular file inside the target directory/,
    );
    assert.equal(fs.existsSync(finalPath), false);
    assert.equal(fs.readFileSync(outsideTarget, "utf8"), "outside\n");
  } finally {
    fs.realpathSync = originalRealpathSync;
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding attempts final cleanup when post-rename lstat fails", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const originalLstatSync = fs.lstatSync;
  try {
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const finalPath = path.join(harness, "test", "bob-invariants", `${plan.contract_name}.t.sol`);
    fs.lstatSync = function patchedLstatSync(filePath, ...args) {
      if (typeof filePath === "string" && path.resolve(filePath) === path.resolve(finalPath)) {
        const error = new Error("simulated post-rename lstat failure");
        error.code = "EACCES";
        throw error;
      }
      return originalLstatSync.apply(this, [filePath, ...args]);
    };

    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({ tests: [{ success: true }] }),
      }),
      /Foundry invariant test file must be a regular file inside the target directory/,
    );
    assert.equal(fs.existsSync(finalPath), false);
  } finally {
    fs.lstatSync = originalLstatSync;
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects symlinked session domain directories before persisting invariant runs", async () => {
  const domain = uniqueDomain();
  cleanupDomain(domain);
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-session-dir-symlink-"));
  const sessionsPath = path.join(os.homedir(), "hacker-bob-sessions");
  const sessionPath = path.join(sessionsPath, domain);
  try {
    fs.mkdirSync(sessionsPath, { recursive: true });
    fs.symlinkSync(outside, sessionPath, "dir");
    let foundryCalled = false;
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => {
          foundryCalled = true;
          return { tests: [{ success: true }] };
        },
      }),
      /domain-directory symlinks/,
    );
    assert.equal(foundryCalled, false);
    assert.equal(fs.existsSync(path.join(outside, ".session.lock")), false);
    assert.equal(fs.existsSync(path.join(outside, "invariant-runs.jsonl")), false);
  } finally {
    try { fs.unlinkSync(sessionPath); } catch {}
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("missing class returns no_template and does not invoke foundry_run", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  let called = false;
  const stubFoundry = async () => { called = true; return {}; };
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: { finding_id: "F-1", finding_hash: "x", vulnerability_class: "no_such_class" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });
    assert.equal(result.outcome, "no_template");
    assert.equal(result.template_id, null);
    assert.equal(called, false);
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("real foundry runner envelope reasons classify invariant outcomes", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const stubFoundry = async () => ({
    ok: false,
    reason: "rpc_unreachable",
    fork_attempts: [{ endpoint: "https://rpc.example/rpc", ok: false }],
    rpc_policy_rejections: [],
    tests: [],
    summary: { total: 0, passed: 0, failed: 0 },
  });
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: stubFoundry,
    });
    assert.equal(result.outcome, "fork_blocked");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("readInvariantRuns filters by outcome and template_id", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const passing = async () => ({ tests: [{ success: true }] });
  const failing = async () => ({ tests: [{ success: false }] });
  try {
    await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "PoolA", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: passing,
    });
    await runInvariantForFinding({
      target_domain: domain,
      finding: { ...SAMPLE_REENTRANCY_FINDING, finding_hash: "h2" },
      slot_values: { target_contract: "PoolB", vulnerable_function: "withdraw", withdraw_amount: "2" },
      harness_path: harness,
      foundry_run: failing,
    });
    const passed = readInvariantRuns({ target_domain: domain, outcome_filter: "test_passed" });
    assert.equal(passed.total_matched, 1);
    const failed = readInvariantRuns({ target_domain: domain, outcome_filter: "test_failed" });
    assert.equal(failed.total_matched, 1);
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("missing harness test/ directory throws a clear error", async () => {
  const domain = uniqueDomain();
  const noTestHarness = fs.mkdtempSync(path.join(os.homedir(), ".bob-no-test-harness-"));
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: noTestHarness,
        foundry_run: async () => ({}),
      }),
      /test\/ directory/,
    );
  } finally {
    cleanupDomain(domain);
    cleanupHarness(noTestHarness);
  }
});

test("runInvariantForFinding rejects symlink-escaping harness paths before writing", async () => {
  const domain = uniqueDomain();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-escape-"));
  fs.mkdirSync(path.join(outside, "test"), { recursive: true });
  const linkPath = path.join(os.homedir(), `.bob-invariant-escape-link-${crypto.randomBytes(4).toString("hex")}`);
  fs.symlinkSync(outside, linkPath, "dir");
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: linkPath,
        foundry_run: async () => ({}),
      }),
      /home directory after symlink resolution/,
    );
    assert.equal(fs.existsSync(path.join(outside, "test", "bob-invariants")), false);
  } finally {
    try { fs.unlinkSync(linkPath); } catch {}
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects symlink-escaping test directories before writing", async () => {
  const domain = uniqueDomain();
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-foundry-harness-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-test-escape-"));
  fs.symlinkSync(outside, path.join(harness, "test"), "dir");
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({}),
      }),
      /test\/ directory must stay inside/,
    );
    assert.equal(fs.existsSync(path.join(outside, "bob-invariants")), false);
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding rejects symlink-escaping invariant output directories before writing", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-output-escape-"));
  const bobDir = path.join(harness, "test", "bob-invariants");
  fs.symlinkSync(outside, bobDir, "dir");
  try {
    await assert.rejects(
      () => runInvariantForFinding({
        target_domain: domain,
        finding: SAMPLE_REENTRANCY_FINDING,
        slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
        harness_path: harness,
        foundry_run: async () => ({}),
      }),
      /output directory must stay inside/,
    );
    assert.deepEqual(fs.readdirSync(outside), []);
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding replaces a final-file symlink instead of following it", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-final-symlink-"));
  const outsideTarget = path.join(outside, "outside.t.sol");
  fs.writeFileSync(outsideTarget, "outside original\n", "utf8");
  try {
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const bobDir = path.join(harness, "test", "bob-invariants");
    fs.mkdirSync(bobDir, { recursive: true });
    const finalPath = path.join(bobDir, `${plan.contract_name}.t.sol`);
    fs.symlinkSync(outsideTarget, finalPath);

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });

    assert.equal(fs.readFileSync(outsideTarget, "utf8"), "outside original\n");
    assert.equal(fs.lstatSync(result.test_path).isSymbolicLink(), false);
    assert.match(fs.readFileSync(result.test_path, "utf8"), new RegExp(plan.contract_name));
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding replaces a dangling final-file symlink", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-dangling-symlink-"));
  const missingTarget = path.join(outside, "missing.t.sol");
  try {
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const bobDir = path.join(harness, "test", "bob-invariants");
    fs.mkdirSync(bobDir, { recursive: true });
    const finalPath = path.join(bobDir, `${plan.contract_name}.t.sol`);
    fs.symlinkSync(missingTarget, finalPath);

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });

    assert.equal(fs.existsSync(missingTarget), false);
    assert.equal(fs.lstatSync(result.test_path).isSymbolicLink(), false);
    assert.match(fs.readFileSync(result.test_path, "utf8"), new RegExp(plan.contract_name));
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding replaces a final-file symlink chain without touching the outside target", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-chain-symlink-"));
  const outsideTarget = path.join(outside, "outside-chain.t.sol");
  fs.writeFileSync(outsideTarget, "outside chain original\n", "utf8");
  try {
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const bobDir = path.join(harness, "test", "bob-invariants");
    fs.mkdirSync(bobDir, { recursive: true });
    const intermediatePath = path.join(bobDir, "intermediate-link.t.sol");
    const finalPath = path.join(bobDir, `${plan.contract_name}.t.sol`);
    fs.symlinkSync(outsideTarget, intermediatePath);
    fs.symlinkSync(intermediatePath, finalPath);

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });

    assert.equal(fs.readFileSync(outsideTarget, "utf8"), "outside chain original\n");
    assert.equal(fs.lstatSync(intermediatePath).isSymbolicLink(), true);
    assert.equal(fs.lstatSync(result.test_path).isSymbolicLink(), false);
    assert.match(fs.readFileSync(result.test_path, "utf8"), new RegExp(plan.contract_name));
  } finally {
    cleanupHarness(harness);
    cleanupHarness(outside);
    cleanupDomain(domain);
  }
});

test("runInvariantForFinding overwrites a pre-existing regular invariant file", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const plan = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      dry_run: true,
    });
    const bobDir = path.join(harness, "test", "bob-invariants");
    fs.mkdirSync(bobDir, { recursive: true });
    const finalPath = path.join(bobDir, `${plan.contract_name}.t.sol`);
    fs.writeFileSync(finalPath, "old invariant source\n", "utf8");

    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: true }] }),
    });

    const source = fs.readFileSync(result.test_path, "utf8");
    assert.doesNotMatch(source, /old invariant source/);
    assert.match(source, new RegExp(plan.contract_name));
  } finally {
    cleanupHarness(harness);
    cleanupDomain(domain);
  }
});

test("input validation rejects unsafe target_domain and missing finding/harness_path/foundry_run", async () => {
  await assert.rejects(
    () => runInvariantForFinding({
      target_domain: "../escape",
      finding: SAMPLE_REENTRANCY_FINDING,
      harness_path: "/tmp",
      foundry_run: async () => ({}),
    }),
    /target_domain/,
  );
  await assert.rejects(
    () => runInvariantForFinding({
      target_domain: "ok.example",
      finding: null,
      harness_path: "/tmp",
      foundry_run: async () => ({}),
    }),
    /finding/,
  );
  await assert.rejects(
    () => runInvariantForFinding({
      target_domain: "ok.example",
      finding: { finding_hash: "h1", vulnerability_class: "reentrancy" },
      harness_path: "/tmp",
      foundry_run: async () => ({}),
    }),
    /finding\.finding_id/,
  );
  await assert.rejects(
    () => runInvariantForFinding({
      target_domain: "ok.example",
      finding: SAMPLE_REENTRANCY_FINDING,
      harness_path: "",
      foundry_run: async () => ({}),
    }),
    /harness_path/,
  );
  await assert.rejects(
    () => runInvariantForFinding({
      target_domain: "ok.example",
      finding: SAMPLE_REENTRANCY_FINDING,
      harness_path: "/tmp",
      foundry_run: null,
    }),
    /foundry_run/,
  );
});

// ---------------------------------------------------------------------------
// The refuting-control requirement. classifyFoundryOutcome stays the honest
// per-run PRIMITIVE; CONFIRM is the adjudicated FLIP over a {positive, control}
// pair written only to the MCP-owned invariant-verified.jsonl ledger.
// ---------------------------------------------------------------------------

// Build a fully-bound invariant-runs.jsonl row: outcome derived from the
// foundry_result, run_hash from computeInvariantRunHash — exactly as
// runInvariantForFinding persists it, so the verifier's re-validation passes.
function makeInvariantRunRow(domain, {
  findingId = "F-1",
  outcome,
  treeRef,
  checkoutKind = "tree",
  templateId = "INV-REENTRANCY-CALLBACK-001",
  contractName = "BobInvariantTest_fixture",
  functionName = "testBobInvariant_fixture",
  executionContextHash = "ctx-hash-shared",
  slotValues = { a: "1" },
} = {}) {
  const foundryResult = outcome === "test_failed"
    ? { tests: [{ success: false }] }
    : { tests: [{ success: true }] };
  const row = {
    target_domain: domain,
    finding_id: findingId,
    finding_hash: null,
    template_id: templateId,
    slot_values: slotValues,
    contract_name: contractName,
    function_name: functionName,
    execution_context_hash: executionContextHash,
    tree_ref: treeRef || null,
    checkout_kind: checkoutKind || null,
    outcome,
    foundry_result_hash: invariantFoundryResultHash(foundryResult),
    foundry_result: foundryResult,
    dry_run: false,
  };
  row.run_hash = computeInvariantRunHash(row);
  appendJsonlLine(invariantRunsJsonlPath(domain), row);
  return row;
}

function verifiedRecords(domain) {
  const filePath = invariantVerifiedJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8")
    .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

test("classifyFoundryViolation maps the per-run primitive to invariant direction", () => {
  assert.equal(classifyFoundryViolation({ tests: [{ success: false }] }), "violated");
  assert.equal(classifyFoundryViolation({ tests: [{ success: true }] }), "held");
  assert.equal(classifyFoundryViolation({ kind: "foundry_fork" }), "degraded");
  assert.equal(classifyFoundryViolation({ kind: "forge_not_in_path" }), "degraded");
  assert.equal(classifyFoundryViolation({}), "degraded");
});

test("adjudicateInvariantDifferential reuses the repro flip rule on violation semantics", () => {
  assert.equal(adjudicateInvariantDifferential({
    positiveRun: { violation: "violated" }, controlRun: { violation: "held" },
  }).result, "verified_pass");
  assert.equal(adjudicateInvariantDifferential({
    positiveRun: { violation: "held" }, controlRun: { violation: "held" },
  }).result, "refuted");
  assert.equal(adjudicateInvariantDifferential({
    positiveRun: { violation: "violated" }, controlRun: { violation: "violated" },
  }).result, "refuted");
  assert.equal(adjudicateInvariantDifferential({
    positiveRun: { violation: "degraded" }, controlRun: { violation: "held" },
  }).result, "inconclusive");
});

test("verifyInvariantDifferential refuses a single-run pass with no control arm", () => {
  const domain = uniqueDomain();
  try {
    // The exact rubber-stamp the readiness probe flagged: a bare positive run,
    // no control. It must NOT mint a verified_pass.
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
    });
    assert.equal(result.result, "inconclusive");
    const records = verifiedRecords(domain);
    assert.equal(records.filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential verifies a real two-sided differential", () => {
  const domain = uniqueDomain();
  try {
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    const control = makeInvariantRunRow(domain, { outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix" });
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: control.run_hash,
    });
    assert.equal(result.result, "verified_pass");
    const summary = readInvariantVerifiedSummary(domain);
    assert.equal(summary.verified_pass_count, 1);
    assert.deepEqual(summary.verified_by_finding["F-1"], {
      positive_run_hash: positive.run_hash,
      control_run_hash: control.run_hash,
      template_id: positive.template_id,
      // HIGH-1: the re-resolved positive row carries no container_isolated field
      // (makeInvariantRunRow predates it / omits it), so the summary surfaces false
      // (fail-closed un-isolated) — the gate then refuses to trust an SC reportable
      // backed by this verdict unless the run was containerized.
      container_isolated: false,
    });
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential refuses a forgery that fails both arms", () => {
  const domain = uniqueDomain();
  try {
    // A tautology-false / mis-authored assertion fails on the known-safe baseline
    // too: no flip → refused as a harness/template artifact.
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    const control = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "fixed", checkoutKind: "upstream_fix" });
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: control.run_hash,
    });
    assert.equal(result.result, "refuted");
    assert.match(result.reason, /no differential flip/);
    assert.equal(verifiedRecords(domain).filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential refuses a non-reproducing claim", () => {
  const domain = uniqueDomain();
  try {
    // Positive HELD on the real target: the violation did not reproduce.
    const positive = makeInvariantRunRow(domain, { outcome: "test_passed", treeRef: "target" });
    const control = makeInvariantRunRow(domain, { outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix" });
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: control.run_hash,
    });
    assert.equal(result.result, "refuted");
    assert.match(result.reason, /did not reproduce/);
    assert.equal(verifiedRecords(domain).filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential returns inconclusive on a degraded arm", () => {
  const domain = uniqueDomain();
  try {
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    // A fork_blocked control arm cannot establish the baseline.
    const forkBlockedResult = { kind: "foundry_fork" };
    const controlRow = {
      target_domain: domain,
      finding_id: "F-1",
      finding_hash: null,
      template_id: positive.template_id,
      slot_values: positive.slot_values,
      contract_name: positive.contract_name,
      function_name: positive.function_name,
      execution_context_hash: positive.execution_context_hash,
      tree_ref: "fixed",
      checkout_kind: "upstream_fix",
      outcome: classifyFoundryOutcome(forkBlockedResult),
      foundry_result_hash: invariantFoundryResultHash(forkBlockedResult),
      foundry_result: forkBlockedResult,
      dry_run: false,
    };
    controlRow.run_hash = computeInvariantRunHash(controlRow);
    appendJsonlLine(invariantRunsJsonlPath(domain), controlRow);
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
      control_run_hash: controlRow.run_hash,
    });
    assert.equal(result.result, "inconclusive");
    assert.equal(verifiedRecords(domain).filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential rejects a control bound to a different template/contract/slots", () => {
  const domain = uniqueDomain();
  try {
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    // Control shares finding_id but is a DIFFERENT test (different execution context):
    // not the same discriminator on a different tree.
    const control = makeInvariantRunRow(domain, {
      outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix",
      executionContextHash: "ctx-hash-DIFFERENT",
    });
    assert.throws(
      () => verifyInvariantDifferential({
        target_domain: domain,
        finding_id: "F-1",
        positive_run_hash: positive.run_hash,
        control_run_hash: control.run_hash,
      }),
      /SAME test on a different tree/,
    );
    assert.equal(verifiedRecords(domain).filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("verifyInvariantDifferential rejects a control on the SAME tree (non-discriminating)", () => {
  const domain = uniqueDomain();
  try {
    const positive = makeInvariantRunRow(domain, { outcome: "test_failed", treeRef: "target" });
    // Same tree_ref + checkout_kind → cannot discriminate target from control.
    const control = makeInvariantRunRow(domain, { outcome: "test_passed", treeRef: "target", checkoutKind: "tree" });
    assert.throws(
      () => verifyInvariantDifferential({
        target_domain: domain,
        finding_id: "F-1",
        positive_run_hash: positive.run_hash,
        control_run_hash: control.run_hash,
      }),
      /DIFFERENT tree\/checkout/,
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("classifyHalmosViolation: ok is a single-run primitive, not a verified verdict", () => {
  // A halmos run with no counterexample is merely "held" — alone it cannot
  // confirm. Routed through the differential with no control arm, it is
  // inconclusive (closes the halmos mint-ok leg).
  assert.equal(classifyHalmosViolation({ summary: { total: 3, passed: 3, failed: 0 } }), "held");
  assert.equal(classifyHalmosViolation({ summary: { total: 2, passed: 1, failed: 1 } }), "violated");
  assert.equal(classifyHalmosViolation({ reason: "halmos_not_in_path" }), "degraded");
  assert.equal(classifyHalmosViolation({ summary: { total: 0, passed: 0, failed: 0 } }), "degraded");
  assert.equal(classifyHalmosViolation({ timed_out: true, summary: { total: 1, passed: 1, failed: 0 } }), "degraded");

  const domain = uniqueDomain();
  try {
    // A halmos "held" persisted as a foundry-shaped primitive (test_passed), with
    // NO control arm, yields inconclusive — never verified.
    const positive = makeInvariantRunRow(domain, { outcome: "test_passed", treeRef: "target" });
    const result = verifyInvariantDifferential({
      target_domain: domain,
      finding_id: "F-1",
      positive_run_hash: positive.run_hash,
    });
    assert.equal(result.result, "inconclusive");
    assert.equal(verifiedRecords(domain).filter((r) => r.result === "verified_pass").length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

// ── HIGH-1: executed-test identity binding (shadow-test poison) ──────────────────────────
//
// A REAL forge --json envelope carries per-test rows with string `suite` ("<path>:<Contract>")
// and `test` ("<fn-sig>()") fields (summarizeForgeJson). The runner pins --match-path to the
// generated file and anchors the filters; THIS bind is the result-side line: EVERY executed
// row must map to the generated <writtenPath>:<contract>::<fn>, and EXACTLY one must run. A
// shadow contract/test that slips through is refused (outcome:"identity_unbound").

function richForgeResult({ suite, test, status = "Fail", containerIsolated = true }) {
  return {
    ok: status === "Pass",
    summary: { total: 1, passed: status === "Pass" ? 1 : 0, failed: status === "Pass" ? 0 : 1 },
    tests: [{ suite, test, status }],
    container_isolated: containerIsolated,
    command: ["forge", "test", "--json"],
    fork_attempts: [],
  };
}

// A foundry_run stub returning the GENUINE rich envelope: it reads the generated identity
// off the args the runner threads in (match_path/match_contract/match_test), so the executed
// identity is exactly the generated contract::function@path.
function genuineRichFoundry(status = "Fail") {
  return async (args) => {
    const rel = path.relative(fs.realpathSync(args.harness_path), args.match_path);
    return richForgeResult({ suite: `${rel}:${args.match_contract}`, test: `${args.match_test}()`, status });
  };
}

test("HIGH-1: a GENUINE rich forge envelope binds — the executed identity maps to the generated contract::function@path (outcome NOT identity_unbound)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: genuineRichFoundry("Fail"),
    });
    assert.equal(result.outcome, "test_failed");
    const corpus = readInvariantRuns({ target_domain: domain });
    assert.equal(corpus.runs[0].outcome, "test_failed");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("HIGH-1: a SHADOW contract whose name CONTAINS the generated name is REFUSED (outcome=identity_unbound, can never be violated)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const shadowFoundry = async (args) => {
    // forge ran an EVIL contract at a DIFFERENT path whose name is a SUPERSTRING of the
    // generated one — exactly the poison an unanchored --match-contract would let through.
    return richForgeResult({ suite: `test/Evil.t.sol:Evil${args.match_contract}`, test: `${args.match_test}()`, status: "Fail" });
  };
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: shadowFoundry,
    });
    assert.equal(result.outcome, "identity_unbound", "a shadow contract's executed identity does not bind");
    assert.notEqual(result.outcome, "test_failed");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("HIGH-1: a run where MORE THAN ONE test executed (a shadow function also matched) is REFUSED (outcome=identity_unbound)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const extraFoundry = async (args) => {
    const rel = path.relative(fs.realpathSync(args.harness_path), args.match_path);
    const suite = `${rel}:${args.match_contract}`;
    return {
      ok: false,
      summary: { total: 2, passed: 0, failed: 2 },
      tests: [
        { suite, test: `${args.match_test}()`, status: "Fail" },
        { suite, test: "testShadowExtra()", status: "Fail" },
      ],
      container_isolated: true,
      command: ["forge", "test", "--json"],
      fork_attempts: [],
    };
  };
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: extraFoundry,
    });
    assert.equal(result.outcome, "identity_unbound", "more than the generated test ran -> unbound");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("HIGH-1: a SHADOW function (correct contract, wrong function) is REFUSED (outcome=identity_unbound)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  const wrongFnFoundry = async (args) => {
    const rel = path.relative(fs.realpathSync(args.harness_path), args.match_path);
    return richForgeResult({ suite: `${rel}:${args.match_contract}`, test: "testNotTheGeneratedFunction()", status: "Fail" });
  };
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: wrongFnFoundry,
    });
    assert.equal(result.outcome, "identity_unbound", "the executed function is not the generated one -> unbound");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("HIGH-1: the SIMPLIFIED forge shape (no suite/test identity fields) is SKIPPED — legacy/test fixtures stay green", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    const result = await runInvariantForFinding({
      target_domain: domain,
      finding: SAMPLE_REENTRANCY_FINDING,
      slot_values: { target_contract: "Pool", vulnerable_function: "withdraw", withdraw_amount: "1 ether" },
      harness_path: harness,
      foundry_run: async () => ({ tests: [{ success: false }] }),
    });
    assert.equal(result.outcome, "test_failed", "no identity fields -> strict bind not applicable -> normal classification");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

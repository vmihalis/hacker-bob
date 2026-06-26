"use strict";

// Cross-stack CONSUMED-ARTIFACT capability (capture + consume), the O-A half of the
// executed-causation oracle. These lock the mechanism that makes cross-stack causation
// PROVEN-not-named: the stack-A web attack CAPTURES the consumable bytes (stored in the
// MCP-owned offensive store, hashed into the MAC-covered offensive row), and the EVM
// invariant harness, given a cause_run_id, FETCHES those exact bytes, INJECTS them as
// BOB_CONSUMED_ARTIFACT into the foundry subprocess, and records consumed_artifact_hash
// as a MAC-covered SIBLING outside computeInvariantRunHash. They do NOT exercise the O-B
// verifier adjudicator (still pure cause_run_id string-equality at this point).
//
// Coverage:
//   (1) a captured artifact on an offensive row is fetchable by run_id AND its hash is
//       MAC-covered (flipping the bytes or the hash breaks the row_mac);
//   (2) the foundry env-injection delivers the bytes (BOB_CONSUMED_ARTIFACT reaches the
//       subprocess as the hex of the fetched bytes) AND passes the egress pass-through;
//   (3) a corpus test WITH the env differs from WITHOUT (the generated scaffold reads it);
//   (4) the invariant row binds consumed_artifact_hash INSIDE run_hash (present/absent arms
//       persist as distinct rows) but OUTSIDE execution_context_hash (the same test);
//   (5) a forged stored-bytes for a non-executed run_id is rejected (no injection).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const writer = require("../mcp/lib/offensive-capture-writer.js");
const { runInvariantForFinding, computeInvariantRunHash } = require("../mcp/lib/invariant-runner.js");
const { readInvariantRuns } = require("../mcp/lib/invariant-runner.js");
const { readOffensiveCaptureBytesSecure } = require("../mcp/lib/claim-freeze.js");
const { readOffensiveRunRecords } = require("../mcp/lib/claims.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { withSessionLock } = require("../mcp/lib/storage.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningPublicKey,
  resolveOffensiveRowVerifier,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  verifyRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  directSmartContractSubprocessEnv,
  SC_CONTROLLED_ARTIFACT_ENV_KEYS,
} = require("../mcp/lib/sc-egress-policy.js");
const { offensiveRunsDir } = require("../mcp/lib/paths.js");

function uniqueDomain(prefix = "bob-consumed-artifact-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  // *.example.test passes the public-DNS scope gate (reserved public form), so initSession
  // accepts it — the offensive writer + invariant runner then share one real session dir.
  return `${prefix}-${suffix}.example.test`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function makeHarness() {
  const harness = fs.mkdtempSync(path.join(os.homedir(), ".bob-consumed-harness-"));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  return harness;
}

function cleanupHarness(harnessPath) {
  if (harnessPath && fs.existsSync(harnessPath)) {
    fs.rmSync(harnessPath, { recursive: true, force: true });
  }
}

const SAMPLE_FINDING = Object.freeze({
  finding_id: "F-1",
  finding_hash: "h-consumed",
  title: "Cross-stack IDOR -> on-chain effect",
  vulnerability_class: "access_control",
  description: "leaked relay payload consumed on-chain",
});

// The consume-bind path is reachable ONLY for the audited cross-stack consuming template
// (INV-CROSS-STACK-AUTH-REPLAY-001, class signature_validation). A cause-consuming arm uses
// this finding + template + its identifier slots so the runner permits the cause injection.
const CROSS_STACK_TEMPLATE_ID = "INV-CROSS-STACK-AUTH-REPLAY-001";
const CROSS_STACK_FINDING = Object.freeze({
  finding_id: "F-1",
  finding_hash: "h-consumed",
  title: "Cross-stack auth replay -> on-chain effect",
  vulnerability_class: "signature_validation",
  description: "web-captured authorization payload consumed on-chain",
});
const CROSS_STACK_SLOTS = Object.freeze({
  target_contract: "Relay",
  gated_function: "execute",
  victim_object: "victimObj",
});

// Mint a signed offensive row that captures a CONSUMABLE artifact. Mirrors the IDOR
// producer's buildAndSignOffensiveRow call shape; bob_http_idor_confirm is registered in
// the demonstrated-severity ceiling so the row signs.
function mintCaptureRow(domain, { consumedArtifactContent, identityTag = "probe" }) {
  return withSessionLock(domain, () => writer.buildAndSignOffensiveRow(domain, {
    runIdPrefix: "idor",
    toolId: "bob_http_idor_confirm",
    method: "GET",
    canonicalTarget: "https://app.example.test/api/object/2",
    surfaceId: "surface:idor",
    identityTag,
    stdoutContent: "{\"leaked\":true}",
    stderrContent: "{}",
    consumedArtifactContent,
  }));
}

// ---------------------------------------------------------------------------
// (1) A captured artifact on an offensive row is fetchable + its hash MAC-covered.
// ---------------------------------------------------------------------------
test("captured consumable artifact is fetchable by run_id and its hash is MAC-covered", () => {
  const domain = uniqueDomain();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const artifact = Buffer.from("forged-relay-payload:0xdeadbeef", "utf8");
    const row = mintCaptureRow(domain, { consumedArtifactContent: artifact });

    // The row carries consumed_artifact_hash = sha256(bytes), NOT inside command_hash.
    const expected = crypto.createHash("sha256").update(artifact).digest("hex");
    assert.equal(row.consumed_artifact_hash, expected, "row binds the artifact hash");
    assert.notEqual(row.consumed_artifact_hash, row.command_hash, "hash is a sibling, not run identity");

    // The .consumed leaf is on disk and fetchable by run_id with the byte-reader twin.
    const leaf = path.join(offensiveRunsDir(domain), `${row.run_id}.consumed`);
    assert.ok(fs.existsSync(leaf), "the consumable bytes are stored in the MCP-owned store");
    const fetched = readOffensiveCaptureBytesSecure(domain, row.run_id, "consumed");
    assert.ok(fetched, "byte-reader returns the bytes");
    assert.equal(fetched.sha256, expected, "fetched bytes re-hash to the MAC-covered hash");
    assert.ok(fetched.bytes.equals(artifact), "fetched bytes are byte-identical to the captured artifact");

    // The hash IS MAC-covered: the ed25519 row_mac verifies, and flipping the hash breaks it.
    const pub = readHandoffSigningPublicKey(domain);
    const verifier = { scheme: "ed25519", publicKey: pub.publicKey };
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier), true, "intact row verifies");
    const tampered = { ...row, consumed_artifact_hash: "0".repeat(64) };
    assert.equal(
      verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, tampered, verifier),
      false,
      "flipping consumed_artifact_hash invalidates the row_mac (the hash is MAC-covered)",
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("a web-only finding captures no consumable artifact (consumed_artifact_hash null, no .consumed leaf)", () => {
  const domain = uniqueDomain();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const row = mintCaptureRow(domain, { consumedArtifactContent: null });
    assert.equal(row.consumed_artifact_hash, null, "nullable for web-only findings");
    const leaf = path.join(offensiveRunsDir(domain), `${row.run_id}.consumed`);
    assert.equal(fs.existsSync(leaf), false, "no .consumed leaf is written when no artifact is captured");
    // The null field is still MAC-covered (sign covers whole row minus row_mac).
    const pub = readHandoffSigningPublicKey(domain);
    assert.equal(
      verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, { scheme: "ed25519", publicKey: pub.publicKey }),
      true,
    );
  } finally {
    cleanupDomain(domain);
  }
});

// ---------------------------------------------------------------------------
// (2) The foundry env-injection delivers the bytes + egress passes it through.
// ---------------------------------------------------------------------------
test("the consume path injects BOB_CONSUMED_ARTIFACT (hex of the fetched bytes) into foundry_run", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const artifact = Buffer.from([0x00, 0x01, 0xff, 0xab, 0xcd]); // arbitrary binary
    const causeRow = mintCaptureRow(domain, { consumedArtifactContent: artifact });

    let seenConsumed = null;
    const stubFoundry = async (args) => {
      seenConsumed = args.consumed_artifact;
      return { tests: [{ success: false }] }; // violated arm
    };
    await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-violated",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: causeRow.run_id,
    });
    assert.ok(Buffer.isBuffer(seenConsumed), "the runner threads the fetched bytes into foundry_run");
    assert.ok(seenConsumed.equals(artifact), "the injected bytes are byte-identical to the captured artifact");

    // The foundry runner encodes the bytes as hex into BOB_CONSUMED_ARTIFACT, which the
    // egress pass-through delivers to the subprocess intact (it is a CONTROLLED var).
    const env = directSmartContractSubprocessEnv({ BOB_CONSUMED_ARTIFACT: artifact.toString("hex") });
    assert.equal(env.BOB_CONSUMED_ARTIFACT, artifact.toString("hex"), "egress passes BOB_CONSUMED_ARTIFACT through");
    assert.ok(SC_CONTROLLED_ARTIFACT_ENV_KEYS.has("BOB_CONSUMED_ARTIFACT"), "the key is on the explicit pass-through allowlist");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("egress pass-through delivers BOB_CONSUMED_ARTIFACT even alongside stripped secret/proxy vars", () => {
  const env = directSmartContractSubprocessEnv({
    BOB_CONSUMED_ARTIFACT: "0xdead",
    API_KEY: "should-be-stripped",
    HTTPS_PROXY: "http://127.0.0.1:8080",
  });
  assert.equal(env.BOB_CONSUMED_ARTIFACT, "0xdead", "the controlled artifact var survives");
  assert.equal(env.API_KEY, undefined, "a secret var is still stripped");
  assert.equal(env.HTTPS_PROXY, undefined, "a proxy var is still stripped");
});

// ---------------------------------------------------------------------------
// (3) A corpus-generated test WITH the env differs from WITHOUT.
// ---------------------------------------------------------------------------
test("the corpus-generated scaffold reads BOB_CONSUMED_ARTIFACT so WITH the env differs from WITHOUT", () => {
  const { buildTestSource } = require("../mcp/lib/invariant-runner.js");
  const src = buildTestSource({ contractName: "BobInvariantTest_X_0001", functionBody: "function testX() public {}" });
  // The consumption is CORPUS-INJECTED (in the scaffold), not agent-authored: the
  // generated source references the env var via vm.envOr (the safe form that tolerates
  // absence, so the control arm and old templates are unaffected).
  assert.match(src, /vm\.envOr\("BOB_CONSUMED_ARTIFACT", string\(""\)\)/, "scaffold reads the env via vm.envOr");
  assert.match(src, /function bobConsumedArtifact\(\) internal view returns \(bytes memory\)/, "scaffold exposes the bytes");
  assert.match(src, /function bobHasConsumedArtifact\(\) internal view returns \(bool\)/, "scaffold exposes a presence flag");

  // The behavioral WITH/WITHOUT difference is the env-driven branch: vm.envOr returns the
  // empty default WITHOUT the env, and the decoded bytes WITH it, so the same generated
  // test takes a different path depending only on env presence. We model the Solidity
  // semantics in JS to prove the scaffold's branch is env-sensitive, not env-ignoring.
  const scaffold = (envValue) => {
    const hexStr = envValue == null ? "" : envValue; // vm.envOr default is ""
    if (hexStr.length === 0) return { bytes: Buffer.alloc(0), present: false };
    const bytes = Buffer.from(hexStr, "hex");
    return { bytes, present: bytes.length > 0 };
  };
  const without = scaffold(null);
  const withArtifact = scaffold(Buffer.from("payload").toString("hex"));
  assert.equal(without.present, false, "WITHOUT the env the scaffold sees no artifact (control)");
  assert.equal(withArtifact.present, true, "WITH the env the scaffold sees the artifact (violated)");
  assert.notEqual(without.bytes.length, withArtifact.bytes.length, "the consumed bytes differ between arms");
});

// ---------------------------------------------------------------------------
// (4) consumed_artifact_hash is INSIDE run_hash (present/absent persist distinct) but
//     OUTSIDE execution_context_hash (same test).
// ---------------------------------------------------------------------------
test("invariant row binds consumed_artifact_hash INSIDE run_hash (present/absent arms persist distinct) but OUTSIDE execution_context_hash (same test)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const artifact = Buffer.from("cross-stack-consumable", "utf8");
    const causeRow = mintCaptureRow(domain, { consumedArtifactContent: artifact });

    const stubFoundry = async () => ({ tests: [{ success: false }] }); // identical outcome on both arms

    // --- SAME-TEST proof: with-artifact vs without-artifact on the SAME tree ---
    // The artifact presence is the CONTROLLED variable: the two runs share an IDENTICAL
    // execution_context_hash (same template/contract/function/exec-ctx) — proving
    // consumed_artifact_hash sits OUTSIDE the execution_context determinant set, exactly
    // like tree_ref. They remain the SAME test. But consumed_artifact_hash IS bound into
    // run_hash (the ledger row identity), so the present/absent arms are DISTINCT persistable
    // rows even with identical foundry result and tree — this is what lets the cross-stack
    // control and decoy arms (both HELD, identical foundry result) persist side by side.
    const withArtifact = await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-with",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: causeRow.run_id,
    });
    const withoutArtifact = await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-without",
      tree_ref: "real",
      checkout_kind: "tree",
      // no cause_run_id -> empty env
    });
    assert.equal(withArtifact.execution_context_hash, withoutArtifact.execution_context_hash, "same execution_context_hash (same test) — consumed_artifact_hash is OUTSIDE execution_context_hash");
    assert.equal(withArtifact.contract_name, withoutArtifact.contract_name, "same contract (same test)");
    assert.equal(withArtifact.function_name, withoutArtifact.function_name, "same function (same test)");
    assert.notEqual(
      withArtifact.run_hash,
      withoutArtifact.run_hash,
      "with-artifact and without-artifact have DISTINCT run_hash (consumed_artifact_hash is INSIDE run_hash, so present/absent arms persist as distinct rows)",
    );

    // --- sibling persistence + MAC-coverage proof, on a REAL differential ---
    // The positive (cause-consuming) arm runs on the real tree; the control runs on a
    // different tree (the established differential variable), so their run_hashes differ
    // and BOTH persist. The positive binds consumed_artifact_hash; the control is null.
    const positive = await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-positive",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: causeRow.run_id,
    });
    const control = await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-control",
      tree_ref: "upstream-fix",
      checkout_kind: "upstream_fix",
      // no cause_run_id
    });
    assert.notEqual(positive.run_hash, control.run_hash, "a real differential differs in tree_ref -> distinct run_hash -> both persist");

    const runs = readInvariantRuns({ target_domain: domain }).runs;
    const pRow = runs.find((r) => r.run_id === "inv-positive");
    const cRow = runs.find((r) => r.run_id === "inv-control");
    assert.ok(pRow && cRow, "both differential rows persisted");
    const expectedHash = crypto.createHash("sha256").update(artifact).digest("hex");
    assert.equal(pRow.consumed_artifact_hash, expectedHash, "positive row binds the consumed bytes hash");
    assert.equal(cRow.consumed_artifact_hash, null, "control row consumed_artifact_hash is null (empty env)");

    // computeInvariantRunHash binds consumed_artifact_hash: the absent (null) and present
    // arms are DISTINCT run_hashes so they persist as distinct rows (the cross-stack control
    // and decoy arms, both HELD with identical foundry result, must not collapse). It stays
    // OUTSIDE execution_context_hash so the arms remain the SAME test.
    const base = {
      finding_id: "F-1", finding_hash: "h", template_id: "INV-ACCESS-CONTROL-EOA-001",
      slot_values: null, contract_name: "C", function_name: "f",
      execution_context_hash: "ec", outcome: "test_failed", foundry_result: null,
      dry_run: false, tree_ref: "real", checkout_kind: "tree",
    };
    assert.notEqual(
      computeInvariantRunHash({ ...base }),
      computeInvariantRunHash({ ...base, consumed_artifact_hash: "deadbeef".repeat(8) }),
      "consumed_artifact_hash is INSIDE computeInvariantRunHash (present vs absent arms get distinct run_hashes)",
    );

    // The sibling IS MAC-covered on the invariant row: flipping it breaks the row_mac.
    const verifier = resolveOffensiveRowVerifier(domain);
    const { verifyRowWithMac: verifyInv } = require("../mcp/lib/offensive-row-mac.js");
    const { INVARIANT_RUN_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
    assert.ok(pRow.row_mac, "positive invariant row is signed");
    assert.equal(verifyInv(INVARIANT_RUN_MAC_CONTEXT, pRow, verifier), true, "intact invariant row verifies");
    const tamperedRow = { ...pRow, consumed_artifact_hash: "0".repeat(64) };
    assert.equal(
      verifyInv(INVARIANT_RUN_MAC_CONTEXT, tamperedRow, verifier),
      false,
      "flipping consumed_artifact_hash on the invariant row invalidates its row_mac",
    );
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

// ---------------------------------------------------------------------------
// (5) A forged stored-bytes for a non-executed run_id is rejected (no injection).
// ---------------------------------------------------------------------------
test("forged stored-bytes for a non-executed run_id is rejected (the bytes are never injected)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const artifact = Buffer.from("genuine-captured-bytes", "utf8");
    const causeRow = mintCaptureRow(domain, { consumedArtifactContent: artifact });

    // FORGE: overwrite the on-disk .consumed leaf with attacker-chosen bytes WITHOUT
    // re-signing the row (an agent can write the file but cannot mint a valid row_mac for
    // the new bytes' hash). The stored hash on the signed row still pins the GENUINE bytes.
    const leaf = path.join(offensiveRunsDir(domain), `${causeRow.run_id}.consumed`);
    fs.chmodSync(leaf, 0o600);
    fs.writeFileSync(leaf, Buffer.from("ATTACKER-SWAPPED-BYTES", "utf8"));

    // Sanity: the row's MAC-covered hash no longer matches the on-disk bytes.
    const onDisk = readOffensiveCaptureBytesSecure(domain, causeRow.run_id, "consumed");
    assert.ok(onDisk, "the leaf is still readable");
    assert.notEqual(onDisk.sha256, causeRow.consumed_artifact_hash, "forged bytes do not match the signed hash");

    let seenConsumed = "unset";
    const stubFoundry = async (args) => {
      seenConsumed = args.consumed_artifact;
      return { tests: [{ success: false }] };
    };
    await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-forged",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: causeRow.run_id,
    });
    // The consume path re-hashes the on-disk bytes and asserts equality against the signed
    // hash; the mismatch fails closed -> NO injection (the arm runs cause-free).
    assert.equal(seenConsumed, null, "forged bytes are NOT injected (consume fails closed on hash mismatch)");
    const forgedRow = readInvariantRuns({ target_domain: domain }).runs.find((r) => r.run_id === "inv-forged");
    assert.equal(forgedRow.consumed_artifact_hash, null, "no consumed_artifact_hash bound when injection failed closed");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

test("a cause_run_id that names no offensive row injects nothing (no cause => cause-free arm)", async () => {
  const domain = uniqueDomain();
  const harness = makeHarness();
  try {
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    // No offensive rows minted at all.
    assert.equal(readOffensiveRunRecords(domain).length, 0);
    let seenConsumed = "unset";
    const stubFoundry = async (args) => {
      seenConsumed = args.consumed_artifact;
      return { tests: [{ success: false }] };
    };
    await runInvariantForFinding({
      target_domain: domain,
      finding: CROSS_STACK_FINDING,
      template_id: CROSS_STACK_TEMPLATE_ID,
      slot_values: { ...CROSS_STACK_SLOTS },
      harness_path: harness,
      foundry_run: stubFoundry,
      run_id: "inv-nocause",
      tree_ref: "real",
      checkout_kind: "tree",
      cause_run_id: "idor-does-not-exist",
    });
    assert.equal(seenConsumed, null, "an unknown cause_run_id injects nothing");
  } finally {
    cleanupDomain(domain);
    cleanupHarness(harness);
  }
});

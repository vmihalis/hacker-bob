"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  normalizeProofBundlesDocument,
  writeProofBundles,
} = require("../mcp/core/proof-bundle.js");
const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
  verifyInvariantDifferential,
} = require("../mcp/core/invariant-runner.js");
const {
  verifyReproReproduction,
} = require("../mcp/domains/repo/repro-replay-verifier.js");
const composeReportTool = require("../mcp/tools/compose-report.js");
const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  pipelineEventsJsonlPath,
  proofBundlePaths,
  invariantRunsJsonlPath,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/core/io/paths.js");
const {
  appendJsonlLine,
} = require("../mcp/core/io/storage.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");
const { persistingRunner } = require("./helpers/repro-run-pair.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-proof-bundle-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function seedFinding(domain, overrides = {}) {
  return JSON.parse(recordFindingTool.handler({
    target_domain: domain,
    title: "Parser crash in fixture input",
    severity: "high",
    cwe: "CWE-787",
    endpoint: "/src/parser.c",
    description: "The parser crashes on a crafted local file.",
    proof_of_concept: "Run the offline fixture replay command against the crafted input.",
    response_evidence: "ASAN reports a reproducible heap overflow in the parser.",
    impact: "Maintainer-controlled parser crash with memory corruption signal.",
    validated: true,
    surface_id: "surface-a",
    // The CVSS/CWE annotation layer requires cvss_inputs on high findings;
    // supply a valid base vector so these proof-bundle fixtures record. The
    // derived score is irrelevant here — these tests exercise proof-bundle /
    // invariant logic, not scoring. Overridable via `overrides`.
    cvss_inputs: {
      attack_vector: "local",
      privileges_required: "none",
      confidentiality: "high",
      integrity: "high",
      availability: "high",
    },
    ...overrides,
  }));
}

// Seed a genuine, re-derivable finding-differential verified_pass arm bound to surface-a,
// so bob_compose_report's executed-flip report-door gate is satisfied for these proof-bundle
// compose fixtures (they render a final-reportable high finding). A real MAC-signed
// exploited_safely positive + blocked_by_defense control + the verdict line that binds them.
function seedFindingDifferentialArm(domain, findingId = "F-1", surfaceId = "surface-a") {
  const { canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
  const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
  const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
  const { offensiveRowHash } = require("../mcp/core/differential/finding-differential-verifier.js");
  const { findingDifferentialVerifiedJsonlPath, offensiveRunsJsonlPath } = require("../mcp/core/io/paths.js");
  const mkRow = (suffix, outcome, ch) => {
    const row = {
      version: 1, target_domain: domain, run_id: `${findingId}-${suffix}`, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/x`),
      offensive_outcome: outcome, dry_run: false, timed_out: false,
      command_hash: ch, exit_code: 0, stdout_hash: "b".repeat(64), stderr_hash: "c".repeat(64),
      demonstrated_severity: "high", surface_id: surfaceId,
    };
    signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow("pos", "exploited_safely", "1".repeat(64));
  const control = mkRow("ctl", "blocked_by_defense", "2".repeat(64));
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: surfaceId, source: "offensive_runs",
    positive_run_id: `${findingId}-pos`, positive_row_hash: offensiveRowHash(positive),
    control_run_id: `${findingId}-ctl`, control_row_hash: offensiveRowHash(control),
  });
}

function seedFinalRound(domain, results, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const paths = verificationRoundPaths(domain, "final");
  fs.writeFileSync(paths.json, `${JSON.stringify({
    version: overrides.version || 1,
    target_domain: domain,
    round: "final",
    notes: null,
    results,
    ...(overrides.verification_attempt_id ? { verification_attempt_id: overrides.verification_attempt_id } : {}),
    ...(overrides.verification_snapshot_hash ? { verification_snapshot_hash: overrides.verification_snapshot_hash } : {}),
    ...(overrides.final_verification_hash ? { final_verification_hash: overrides.final_verification_hash } : {}),
  }, null, 2)}\n`);
}

function appendRepoRunFixture(domain, runId = "run-fixture", replayCommand = ["sh", "-lc", "./repro.sh"], options = {}) {
  const stdout = options.stdout || "asan fired\n";
  const stderr = options.stderr || "";
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), stdout);
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stderr`), stderr);
  const replayCommandHash = sha256Hex(JSON.stringify(replayCommand));
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: replayCommandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: sha256Hex(JSON.stringify(["run", "--network", "none"])),
    network_mode: options.network_mode || "none",
    mount_mode: options.mount_mode || "read_only",
    work_mount_mode: options.work_mount_mode || "read_write",
    replay_context: options.replay_context || { finding_id: options.finding_id || "F-1" },
    image_tag: options.image_tag || "bob-oss-fixture:stable",
    timeout_ms: 300000,
    exit_code: 1,
    signal: null,
    timed_out: false,
    stdout_hash: sha256Hex(stdout),
    stderr_hash: sha256Hex(stderr),
    stdout_size_bytes: Buffer.byteLength(stdout),
    stderr_size_bytes: Buffer.byteLength(stderr),
    stdout_truncated: false,
    stderr_truncated: false,
  };
  for (const key of [
    "checkout_ref",
    "checkout_kind",
    "checkout_object",
    "checkout_object_format",
    "checkout_patch_hash",
  ]) {
    if (options[key] != null) row[key] = options[key];
  }
  if (options.omit_work_mount_mode) delete row.work_mount_mode;
  appendJsonlLine(repoCommandRunsJsonlPath(domain), row);
}

// REFUTING-ARM (universal): a replay_script proof bundle is no longer minted on a
// lone executed repo-command-run. It must be backed by a VERIFIED_PASS in the
// MCP-write-only repro-verified.jsonl, keyed by finding_id AND the SAME command the
// proof bundle replays. This seeds exactly such a differential: the verifier re-runs
// the replay argv on the vuln tree (an attributable /src ASAN crash) and the
// upstream-fix tree (clean exit 0). The flip mints verified_pass; its command_hash
// equals sha256(JSON.stringify(replayCommand)) — the row's replay_command_hash.
const REPLAY_SRC_ASAN_CRASH = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in mu::ParserBase::Parse() const /src/parser.c:1242:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:1242:10`;
async function seedReproVerified(domain, findingId = "F-1", replayCommand = ["sh", "-lc", "./repro.sh"]) {
  let n = 0;
  const repoDockerRunFn = async ({ checkout }) => {
    n += 1;
    // A run WITH a checkout is the upstream-fix (control) tree; without is the vuln tree.
    if (checkout) return { run_id: `repro-control-${n}`, exit_code: 0, stdout_text: "", stderr_text: "All tests passed\n" };
    return { run_id: `repro-vuln-${n}`, exit_code: 1, stdout_text: "", stderr_text: REPLAY_SRC_ASAN_CRASH };
  };
  const verdict = await verifyReproReproduction(
    {
      target_domain: domain,
      finding_id: findingId,
      command: replayCommand,
      control_ref: "322716256d60e316c9a3b905a387be36d4e47368",
    },
    // Persist each run as a genuine repo-command-runs row + capture files so the minted
    // verified_pass survives readReproVerifiedSummary's read-time re-adjudication.
    { repoDockerRunFn: persistingRunner(domain, repoDockerRunFn) },
  );
  return verdict;
}

function appendInvariantRunFixture(domain, runHashSeed = "invariant-run-fixture", options = {}) {
  const outcome = options.outcome || "test_passed";
  const foundryResult = options.foundry_result || (outcome === "test_passed"
    ? { tests: [{ success: true }] }
    : { tests: [{ success: false }] });
  const row = {
    target_domain: domain,
    finding_id: options.finding_id || "F-1",
    finding_hash: options.finding_hash || "finding-hash-fixture",
    template_id: "reentrancy-basic",
    contract_name: "BobInvariantTest_fixture",
    function_name: "testBobInvariant_fixture",
    execution_context_hash: options.execution_context_hash || sha256Hex(String(runHashSeed || "context")),
    tree_ref: options.tree_ref || null,
    checkout_kind: options.checkout_kind || null,
    test_path: "/tmp/harness/test/bob-invariants/BobInvariantTest_fixture.t.sol",
    outcome,
    foundry_result_hash: invariantFoundryResultHash(foundryResult),
    foundry_result: foundryResult,
    dry_run: options.dry_run === true ? true : false,
  };
  row.run_hash = options.force_run_hash || computeInvariantRunHash(row);
  if (options.omit_finding_id) delete row.finding_id;
  appendJsonlLine(invariantRunsJsonlPath(domain), row);
  return row;
}

// REFUTING-ARM: an accepted invariant proof bundle needs BOTH a positive run
// (the invariant FAILS on the real target) and a control run (it HOLDS on the
// control tree), AND a VERIFIED_PASS differential verdict minted by the real
// verifier into the MCP-owned invariant-verified.jsonl. Returns
// { positive, control, verdict } so a test can build a flipping invariant
// artifact. controlOutcome can be flipped to "test_failed" to forge a
// non-flipping pair (the verdict then mints REFUTED, not VERIFIED_PASS).
function seedInvariantDifferential(domain, { findingId = "F-1", controlOutcome = "test_passed" } = {}) {
  // The positive and control MUST be the SAME test (shared execution_context_hash),
  // differing ONLY in the tree.
  const ctx = sha256Hex(`inv-ctx-${findingId}`);
  const positive = appendInvariantRunFixture(domain, "inv-positive", {
    finding_id: findingId, outcome: "test_failed", tree_ref: "target", checkout_kind: "tree",
    execution_context_hash: ctx,
  });
  const control = appendInvariantRunFixture(domain, "inv-control", {
    finding_id: findingId, outcome: controlOutcome, tree_ref: "fixed", checkout_kind: "upstream_fix",
    execution_context_hash: ctx,
  });
  const verdict = verifyInvariantDifferential({
    target_domain: domain,
    finding_id: findingId,
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  return { positive, control, verdict };
}

function replayBundle(findingId = "F-1", runId = "run-fixture", replayCommand = ["sh", "-lc", "./repro.sh"]) {
  return {
    finding_id: findingId,
    bundle_kind: "replay_script",
    artifacts: [{
      run_id: runId,
      replay_command: replayCommand,
      replay_summary: "Offline sandbox replay reproduces the parser crash.",
      snippet: "The fixture command exits non-zero with an ASAN finding.",
    }],
  };
}

function reportableResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Final replay confirmed the finding.",
    ...overrides,
  };
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

function writeNormalizedProofBundleDocument(domain, { binding = null } = {}) {
  const document = normalizeProofBundlesDocument({
    version: 1,
    target_domain: domain,
    ...(binding || {}),
    packs: [replayBundle()],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
    verificationBinding: binding,
  });
  fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

test("bob_write_proof_bundle rejects bundles for non-reportable final findings", async () => {
  await withTempHome(async () => {
    const domain = "proof-non-reportable.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult("F-1", {
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Final replay did not reproduce.",
    })]);
    appendRepoRunFixture(domain);

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /Proof bundle references non-reportable final finding_id: F-1/,
    );
  });
});

test("ProofBundle normalizer requires explicit finding and final reportable sets", async () => {
  assert.throws(
    () => normalizeProofBundlesDocument({
      version: 1,
      target_domain: "proof-normalizer-contract.example.com",
      packs: [replayBundle()],
    }),
    /findingIdSet is required for proof bundle normalization/,
  );

  assert.throws(
    () => normalizeProofBundlesDocument({
      version: 1,
      target_domain: "proof-normalizer-contract.example.com",
      packs: [replayBundle()],
    }, {
      findingIdSet: new Set(["F-1"]),
    }),
    /finalReportableIdSet is required for proof bundle normalization/,
  );
});

test("bob_write_proof_bundle rejects replay artifacts missing a repo docker run_id", async () => {
  await withTempHome(async () => {
    const domain = "proof-missing-run.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "replay_script",
          artifacts: [{ replay_command: ["sh", "-lc", "./repro.sh"] }],
        }],
      }),
      /run_id must be a non-empty string/,
    );
  });
});

test("bob_write_proof_bundle accepts legacy replay rows without recorded /work mount mode", async () => {
  await withTempHome(async () => {
    const domain = "proof-legacy-work-mount.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"], { omit_work_mount_mode: true });
    await seedReproVerified(domain);

    const written = JSON.parse(writeProofBundles({ target_domain: domain, packs: [replayBundle()] }));

    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    assert.equal(doc.packs[0].artifacts[0].work_mount_mode, "read_write");
    assert.equal(doc.packs[0].artifacts[0].work_mount_mode_legacy_assumed, true);
  });
});

test("bob_write_proof_bundle rejects replay rows with a non-read-write /work mount mode", async () => {
  await withTempHome(async () => {
    const domain = "proof-wrong-work-mount.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"], { work_mount_mode: "read_only" });

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /read-write \/work repo docker run/,
    );
  });
});

test("bob_write_proof_bundle rejects replay-script proofs backed by checkout runs", async () => {
  await withTempHome(async () => {
    const domain = "proof-checkout-run.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-checkout", ["sh", "-lc", "./repro.sh"], {
      checkout_kind: "patch",
      checkout_object: "control",
      checkout_patch_hash: sha256Hex("patch"),
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [replayBundle("F-1", "run-checkout")],
      }),
      /without checkout fields/,
    );
  });
});

test("bob_write_proof_bundle rejects replay rows bound to another finding", async () => {
  await withTempHome(async () => {
    const domain = "proof-wrong-replay-finding.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"], { finding_id: "F-2" });

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /does not match proof bundle finding_id F-1/,
    );
  });
});

// REFUTING-ARM (universal): a replay_script bundle backed by a LONE executed
// repo-command-run — no differential, no flip — is REFUSED. An exit-0 banner run
// (or any single run) satisfied the old gate; now it cannot mint a "proven by
// reproduction script" artifact because repro-verified.jsonl holds no VERIFIED_PASS
// for the finding. This is the bare-pass-refused proof for the replay_script hole.
test("bob_write_proof_bundle rejects a replay bundle with a lone run and no differential verdict", async () => {
  await withTempHome(async () => {
    const domain = "proof-replay-no-differential.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    // A real, executed, finding-bound repo run — but NO repro-verified differential.
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"]);

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /requires a VERIFIED_PASS differential reproduction in repro-verified\.jsonl for finding_id F-1/,
    );
  });
});

// A VERIFIED_PASS that flipped on a DIFFERENT command than this bundle replays is
// rejected: the differential must bind to the exact command the proof bundle runs,
// closing the "pair a real finding's verdict with an unrelated replay command" hole.
test("bob_write_proof_bundle rejects a replay bundle whose verified_pass flipped on a different command", async () => {
  await withTempHome(async () => {
    const domain = "proof-replay-command-mismatch.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"]);
    // The verified differential flipped on a DIFFERENT argv than the bundle replays.
    await seedReproVerified(domain, "F-1", ["sh", "-lc", "./other-poc.sh"]);

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /replay_command does not match the VERIFIED_PASS differential reproduction command for finding_id F-1/,
    );
  });
});

// The positive arm: a real differential that FLIPS (crashes the vuln tree with a
// /src ASAN frame, quiet on the upstream-fix tree) on the SAME command the bundle
// replays mints the verified replay_script artifact and binds the verdict.
test("bob_write_proof_bundle accepts a replay bundle backed by a flipping repro differential", async () => {
  await withTempHome(async () => {
    const domain = "proof-replay-differential-ok.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"]);
    const verdict = await seedReproVerified(domain, "F-1", ["sh", "-lc", "./repro.sh"]);
    assert.equal(verdict.result, "verified_pass");

    const written = JSON.parse(writeProofBundles({ target_domain: domain, packs: [replayBundle()] }));
    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    const artifact = doc.packs[0].artifacts[0];
    assert.equal(artifact.artifact_kind, "replay_script");
    assert.equal(artifact.verdict, "verified_pass");
    assert.equal(artifact.repro_verified_command_hash, artifact.replay_command_hash);
    assert.equal(artifact.crash_class, "heap-buffer-overflow");
  });
});

test("bob_write_proof_bundle rejects an invariant bundle backed by a lone run with no differential verdict", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-outcome.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    // A lone passing/failing row with no refuting control and no minted verdict.
    // The old gate accepted a bare test_passed; the current gate refuses a lone
    // run_hash invariant proof — there is nothing to flip against.
    const row = appendInvariantRunFixture(domain, "invariant-run", { outcome: "test_failed" });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ run_hash: row.run_hash }],
        }],
      }),
      /positive_run_hash \+ control_run_hash/,
    );
  });
});

test("bob_write_proof_bundle rejects an invariant bundle with a positive arm but no control verdict", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-no-verdict.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    // Positive + control rows exist but verifyInvariantDifferential was never run,
    // so invariant-verified.jsonl has no VERIFIED_PASS for this finding.
    const ctx = sha256Hex("inv-no-verdict-ctx");
    const positive = appendInvariantRunFixture(domain, "inv-positive", {
      outcome: "test_failed", tree_ref: "target", checkout_kind: "tree", execution_context_hash: ctx,
    });
    const control = appendInvariantRunFixture(domain, "inv-control", {
      outcome: "test_passed", tree_ref: "fixed", checkout_kind: "upstream_fix", execution_context_hash: ctx,
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ positive_run_hash: positive.run_hash, control_run_hash: control.run_hash }],
        }],
      }),
      /requires a VERIFIED_PASS invariant differential/,
    );
  });
});

test("bob_write_proof_bundle accepts an invariant bundle backed by a VERIFIED_PASS differential", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-verified.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    const { positive, control, verdict } = seedInvariantDifferential(domain);
    assert.equal(verdict.result, "verified_pass");

    const written = JSON.parse(writeProofBundles({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "invariant",
        artifacts: [{ positive_run_hash: positive.run_hash, control_run_hash: control.run_hash }],
      }],
    }));
    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    const artifact = doc.packs[0].artifacts[0];
    assert.equal(artifact.verdict, "verified_pass");
    assert.equal(artifact.positive_run_hash, positive.run_hash);
    assert.equal(artifact.control_run_hash, control.run_hash);
    assert.equal(Object.hasOwn(artifact, "test_path"), false);
  });
});

test("bob_write_proof_bundle rejects an invariant bundle whose verdict is refuted (non-flipping pair)", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-refuted.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    // control ALSO fails → the verifier mints REFUTED, never VERIFIED_PASS.
    const { positive, control, verdict } = seedInvariantDifferential(domain, { controlOutcome: "test_failed" });
    assert.equal(verdict.result, "refuted");

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          // a REFUTED control fails the positive-arm test_failed requirement first.
          artifacts: [{ positive_run_hash: positive.run_hash, control_run_hash: control.run_hash }],
        }],
      }),
      /outcome test_passed|VERIFIED_PASS invariant differential/,
    );
  });
});

test("bob_write_proof_bundle rejects an invariant bundle whose run_hashes do not match the verdict record", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-mismatch.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    // A real VERIFIED_PASS exists for (positive, control). Forge a bundle that
    // references the real positive but a DIFFERENT control row — the ledger match
    // (positive_run_hash AND control_run_hash AND finding_id) must reject it.
    const { positive } = seedInvariantDifferential(domain);
    // Same test identity (shared ctx) so the artifact passes the same-test check
    // and reaches the ledger match — but this control was never adjudicated, so its
    // run hash is absent from the VERIFIED_PASS record.
    const otherControl = appendInvariantRunFixture(domain, "inv-other-control", {
      outcome: "test_passed", tree_ref: "other-fixed", checkout_kind: "upstream_fix",
      execution_context_hash: sha256Hex("inv-ctx-F-1"),
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ positive_run_hash: positive.run_hash, control_run_hash: otherControl.run_hash }],
        }],
      }),
      /requires a VERIFIED_PASS invariant differential/,
    );
  });
});

test("bob_write_proof_bundle rejects invariant rows with unbound forged outcomes", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-forged-outcome.example.com";
    const legacyRunHash = sha256Hex("legacy-unbound-invariant-run");
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendInvariantRunFixture(domain, "forged-invariant-run", {
      force_run_hash: legacyRunHash,
      outcome: "test_failed",
      foundry_result: { tests: [{ success: true }] },
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ positive_run_hash: legacyRunHash, control_run_hash: sha256Hex("c") }],
        }],
      }),
      /does not bind the invariant run outcome and Foundry result/,
    );
  });
});

test("bob_write_proof_bundle rejects legacy invariant rows without finding_id remediation", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-legacy-row.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    const row = appendInvariantRunFixture(domain, "legacy-invariant-run", {
      omit_finding_id: true, outcome: "test_failed", tree_ref: "target",
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ positive_run_hash: row.run_hash, control_run_hash: sha256Hex("c") }],
        }],
      }),
      /legacy invariant row without finding_id; re-run the invariant for proof bundle finding_id F-1/,
    );
  });
});

test("bob_write_proof_bundle finds invariant rows beyond the read-tool display cap", async () => {
  await withTempHome(async () => {
    const domain = "proof-invariant-cap.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    for (let i = 0; i < 55; i += 1) {
      appendInvariantRunFixture(domain, sha256Hex(`invariant-run-${i}`), { outcome: "test_failed" });
    }
    // The flipping pair + minted verdict is appended last, beyond the read-tool
    // display cap; the proof-bundle gate reads the full corpus + the ledger.
    const { positive, control } = seedInvariantDifferential(domain);

    const written = JSON.parse(writeProofBundles({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "invariant",
        artifacts: [{ positive_run_hash: positive.run_hash, control_run_hash: control.run_hash }],
      }],
    }));

    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    assert.equal(doc.packs[0].artifacts[0].positive_run_hash, positive.run_hash);
    assert.equal(doc.packs[0].artifacts[0].control_run_hash, control.run_hash);
    assert.equal(
      Object.hasOwn(doc.packs[0].artifacts[0], "test_path"),
      false,
      "proof bundle artifacts must not contain local test_path values",
    );
  });
});

test("bob_compose_report rejects proof_bundle refs stale against current final verification", async () => {
  await withTempHome(async () => {
    const domain = "proof-stale-ref.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    const paths = proofBundlePaths(domain);
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verification_attempt_id: "old-attempt",
      verification_snapshot_hash: "old-snapshot",
      final_verification_hash: "old-final",
      packs: [{
        finding_id: "F-1",
        bundle_kind: "replay_script",
        artifacts: [],
        bundle_hash: sha256Hex("bundle"),
      }],
    }, null, 2)}\n`);

    assert.throws(
      () => callTool(composeReportTool, {
        target_domain: domain,
        sections: [{
          kind: "proof_bundle",
          heading: "Runnable Proof Bundle",
          prose: "The reportable parser crash has a sandboxed replay bundle attached.",
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
        }],
      }),
      /proof_bundle:F-1 does not resolve/,
    );
  });
});

test("bob_compose_report rejects unbound proof_bundle refs when current final verification is V2", async () => {
  await withTempHome(async () => {
    const domain = "proof-unbound-v2-ref.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()], {
      version: 2,
      verification_attempt_id: "attempt-current",
      verification_snapshot_hash: "a".repeat(64),
      final_verification_hash: "b".repeat(64),
    });
    const paths = proofBundlePaths(domain);
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "replay_script",
        artifacts: [],
        bundle_hash: sha256Hex("bundle"),
      }],
    }, null, 2)}\n`);

    assert.throws(
      () => callTool(composeReportTool, {
        target_domain: domain,
        sections: [{
          kind: "proof_bundle",
          heading: "Runnable Proof Bundle",
          prose: "The reportable parser crash has a sandboxed replay bundle attached.",
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
        }],
      }),
      /proof_bundle:F-1 does not resolve/,
    );
  });
});

test("bob_compose_report rejects proof_bundle refs with malformed bundle shape", async () => {
  await withTempHome(async () => {
    const domain = "proof-malformed-ref.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    const binding = {
      verification_attempt_id: "attempt-current",
      verification_snapshot_hash: "e".repeat(64),
      final_verification_hash: "f".repeat(64),
    };
    seedFinalRound(domain, [reportableResult()], {
      version: 2,
      ...binding,
    });
    const paths = proofBundlePaths(domain);
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      ...binding,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "replay_script",
        artifacts: [],
        bundle_hash: sha256Hex("bundle"),
      }],
    }, null, 2)}\n`);

    assert.throws(
      () => callTool(composeReportTool, {
        target_domain: domain,
        sections: [{
          kind: "proof_bundle",
          heading: "Runnable Proof Bundle",
          prose: "The reportable parser crash has a sandboxed replay bundle attached.",
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
        }],
      }),
      /proof_bundle:F-1 does not resolve/,
    );
  });
});

test("bob_compose_report accepts proof_bundle refs bound to current V2 final verification", async () => {
  await withTempHome(async () => {
    const domain = "proof-bound-v2-ref.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    const binding = {
      verification_attempt_id: "attempt-current",
      verification_snapshot_hash: "c".repeat(64),
      final_verification_hash: "d".repeat(64),
    };
    seedFinalRound(domain, [reportableResult()], {
      version: 2,
      ...binding,
    });
    appendRepoRunFixture(domain);
    await seedReproVerified(domain);
    // The final-reportable high finding needs an executed-flip binding to compose (report-door gate).
    seedFindingDifferentialArm(domain);
    writeNormalizedProofBundleDocument(domain, { binding });

    const result = withIsolatedSigner(() => callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "proof_bundle",
        heading: "Runnable Proof Bundle",
        prose: "The reportable parser crash has a sandboxed replay bundle attached.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
      }],
    }));

    assert.equal(result.target_domain, domain);
  });
});

test("ProofBundle bundle_hash is stable across two target domains while proof-bundles.json keeps target_domain", async () => {
  await withTempHome(async () => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    const documentHashes = [];
    for (const domain of ["proof-stable-a.example.com", "proof-stable-b.example.com"]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: `bob-oss-${domain}:abcdef1234567890` });
      await seedReproVerified(domain, "F-1", replayCommand);
      const document = normalizeProofBundlesDocument({
        version: 1,
        target_domain: domain,
        packs: [replayBundle("F-1", "run-fixture", replayCommand)],
      }, {
        expectedDomain: domain,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      });
      hashes.push(document.packs[0].bundle_hash);
      documentHashes.push(sha256Hex(JSON.stringify(document)));
      assert.equal(document.packs[0].artifacts[0].image_tag, `bob-oss-${domain}:abcdef1234567890`);
      assert.equal(document.packs[0].artifacts[0].image_identity, "bob-oss:abcdef1234567890");
    }

    assert.equal(hashes[0], hashes[1], "bundle_hash must be target-domain independent for identical proof inputs");
    assert.notEqual(documentHashes[0], documentHashes[1], "proof-bundles.json must retain target_domain in the document payload");
  });
});

test("ProofBundle bundle_hash changes when the replay image identity changes", async () => {
  await withTempHome(async () => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    for (const [domain, imageTag] of [
      ["proof-image-a.example.com", "bob-oss-proof-image-a.example.com:aaaaaaaaaaaaaaaa"],
      ["proof-image-b.example.com", "bob-oss-proof-image-b.example.com:bbbbbbbbbbbbbbbb"],
    ]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: imageTag });
      await seedReproVerified(domain, "F-1", replayCommand);
      const document = normalizeProofBundlesDocument({
        version: 1,
        target_domain: domain,
        packs: [replayBundle("F-1", "run-fixture", replayCommand)],
      }, {
        expectedDomain: domain,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      });
      hashes.push(document.packs[0].bundle_hash);
    }

    assert.notEqual(hashes[0], hashes[1], "bundle_hash must bind replay image identity changes");
  });
});

test("ProofBundle image_identity only strips the current target-domain image prefix", async () => {
  await withTempHome(async () => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const documents = [];
    for (const [domain, imageTag] of [
      ["proof-image-scope-a.example.com", "bob-oss-external-a.example.com:dddddddddddddddd"],
      ["proof-image-scope-b.example.com", "bob-oss-external-b.example.com:dddddddddddddddd"],
    ]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: imageTag });
      await seedReproVerified(domain, "F-1", replayCommand);
      documents.push(normalizeProofBundlesDocument({
        version: 1,
        target_domain: domain,
        packs: [replayBundle("F-1", "run-fixture", replayCommand)],
      }, {
        expectedDomain: domain,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      }));
    }

    assert.equal(
      documents[0].packs[0].artifacts[0].image_identity,
      "bob-oss-external-a.example.com:dddddddddddddddd",
    );
    assert.equal(
      documents[1].packs[0].artifacts[0].image_identity,
      "bob-oss-external-b.example.com:dddddddddddddddd",
    );
    assert.notEqual(
      documents[0].packs[0].bundle_hash,
      documents[1].packs[0].bundle_hash,
      "non-target bob-oss image prefixes must remain hash-distinct",
    );
  });
});

test("ProofBundle bundle_hash is stable across different repo run_id handles", async () => {
  await withTempHome(async () => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    for (const [domain, runId] of [
      ["proof-run-id-a.example.com", "run-alpha"],
      ["proof-run-id-b.example.com", "run-beta"],
    ]) {
      appendRepoRunFixture(domain, runId, replayCommand, { image_tag: "bob-oss-shared:cccccccccccccccc" });
      await seedReproVerified(domain, "F-1", replayCommand);
      const document = normalizeProofBundlesDocument({
        version: 1,
        target_domain: domain,
        packs: [replayBundle("F-1", runId, replayCommand)],
      }, {
        expectedDomain: domain,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      });
      hashes.push(document.packs[0].bundle_hash);
      assert.equal(document.packs[0].artifacts[0].run_id, runId);
    }

    assert.equal(hashes[0], hashes[1], "bundle_hash must not depend on random repo run_id handles");
  });
});

test("bob_compose_report accepts a proof_bundle evidence_ref after proof bundle write", async () => {
  await withTempHome(async () => {
    const domain = "proof-compose.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain);
    await seedReproVerified(domain);
    // The final-reportable high finding needs an executed-flip binding to compose (report-door gate).
    seedFindingDifferentialArm(domain);

    const written = JSON.parse(writeProofBundles({ target_domain: domain, packs: [replayBundle()] }));
    assert.equal(written.bundles_count, 1);
    assert.deepEqual(written.missing_finding_ids, []);
    assert.equal(fs.existsSync(proofBundlePaths(domain).json), true);

    const result = withIsolatedSigner(() => callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "proof_bundle",
        heading: "Runnable Proof Bundle",
        prose: "The reportable parser crash has a sandboxed replay bundle attached.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
      }],
    }));

    assert.equal(result.target_domain, domain);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /Runnable Proof Bundle/);
    assert.match(rendered, /proof_bundle:F-1/);

    const events = fs.readFileSync(pipelineEventsJsonlPath(domain), "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.ok(events.some((event) => event.type === "proof_bundle_written"));
  });
});

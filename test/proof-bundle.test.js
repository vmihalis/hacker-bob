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
} = require("../mcp/lib/proof-bundle.js");
const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
} = require("../mcp/lib/invariant-runner.js");
const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  pipelineEventsJsonlPath,
  proofBundlePaths,
  invariantRunsJsonlPath,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-proof-bundle-"));
  process.env.HOME = home;
  try {
    return fn(home);
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

test("bob_write_proof_bundle rejects bundles for non-reportable final findings", () => {
  withTempHome(() => {
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

test("ProofBundle normalizer requires explicit finding and final reportable sets", () => {
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

test("bob_write_proof_bundle rejects replay artifacts missing a repo docker run_id", () => {
  withTempHome(() => {
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

test("bob_write_proof_bundle accepts legacy replay rows without recorded /work mount mode", () => {
  withTempHome(() => {
    const domain = "proof-legacy-work-mount.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"], { omit_work_mount_mode: true });

    const written = JSON.parse(writeProofBundles({ target_domain: domain, packs: [replayBundle()] }));

    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    assert.equal(doc.packs[0].artifacts[0].work_mount_mode, "read_write");
    assert.equal(doc.packs[0].artifacts[0].work_mount_mode_legacy_assumed, true);
  });
});

test("bob_write_proof_bundle rejects replay rows with a non-read-write /work mount mode", () => {
  withTempHome(() => {
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

test("bob_write_proof_bundle rejects replay-script proofs backed by checkout runs", () => {
  withTempHome(() => {
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

test("bob_write_proof_bundle rejects replay rows bound to another finding", () => {
  withTempHome(() => {
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

test("bob_write_proof_bundle rejects non-reproducing invariant rows", () => {
  withTempHome(() => {
    const domain = "proof-invariant-outcome.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
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
      /outcome test_passed/,
    );
  });
});

test("bob_write_proof_bundle rejects invariant rows with unbound forged outcomes", () => {
  withTempHome(() => {
    const domain = "proof-invariant-forged-outcome.example.com";
    const legacyRunHash = sha256Hex("legacy-unbound-invariant-run");
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendInvariantRunFixture(domain, "forged-invariant-run", {
      force_run_hash: legacyRunHash,
      outcome: "test_passed",
      foundry_result: { tests: [{ success: false }] },
    });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ run_hash: legacyRunHash }],
        }],
      }),
      /does not bind the invariant run outcome and Foundry result/,
    );
  });
});

test("bob_write_proof_bundle rejects legacy invariant rows without finding_id remediation", () => {
  withTempHome(() => {
    const domain = "proof-invariant-legacy-row.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    const row = appendInvariantRunFixture(domain, "legacy-invariant-run", { omit_finding_id: true });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ run_hash: row.run_hash }],
        }],
      }),
      /legacy invariant row without finding_id; re-run the invariant for proof bundle finding_id F-1/,
    );
  });
});

test("bob_write_proof_bundle finds invariant rows beyond the read-tool display cap", () => {
  withTempHome(() => {
    const domain = "proof-invariant-cap.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    for (let i = 0; i < 55; i += 1) {
      appendInvariantRunFixture(domain, sha256Hex(`invariant-run-${i}`));
    }
    const targetRow = appendInvariantRunFixture(domain, "invariant-run-target");

    const written = JSON.parse(writeProofBundles({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "invariant",
        artifacts: [{ run_hash: targetRow.run_hash }],
      }],
    }));

    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    assert.equal(doc.packs[0].artifacts[0].run_hash, targetRow.run_hash);
    assert.equal(
      Object.hasOwn(doc.packs[0].artifacts[0], "test_path"),
      false,
      "proof bundle artifacts must not contain local test_path values",
    );
  });
});

test("bob_compose_report rejects proof_bundle refs stale against current final verification", () => {
  withTempHome(() => {
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

test("bob_compose_report rejects unbound proof_bundle refs when current final verification is V2", () => {
  withTempHome(() => {
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

test("bob_compose_report rejects proof_bundle refs with malformed bundle shape", () => {
  withTempHome(() => {
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

test("bob_compose_report accepts proof_bundle refs bound to current V2 final verification", () => {
  withTempHome(() => {
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
    writeNormalizedProofBundleDocument(domain, { binding });

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "proof_bundle",
        heading: "Runnable Proof Bundle",
        prose: "The reportable parser crash has a sandboxed replay bundle attached.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
      }],
    });

    assert.equal(result.target_domain, domain);
  });
});

test("ProofBundle bundle_hash is stable across two target domains while proof-bundles.json keeps target_domain", () => {
  withTempHome(() => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    const documentHashes = [];
    for (const domain of ["proof-stable-a.example.com", "proof-stable-b.example.com"]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: `bob-oss-${domain}:abcdef1234567890` });
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

test("ProofBundle bundle_hash changes when the replay image identity changes", () => {
  withTempHome(() => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    for (const [domain, imageTag] of [
      ["proof-image-a.example.com", "bob-oss-proof-image-a.example.com:aaaaaaaaaaaaaaaa"],
      ["proof-image-b.example.com", "bob-oss-proof-image-b.example.com:bbbbbbbbbbbbbbbb"],
    ]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: imageTag });
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

test("ProofBundle image_identity only strips the current target-domain image prefix", () => {
  withTempHome(() => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const documents = [];
    for (const [domain, imageTag] of [
      ["proof-image-scope-a.example.com", "bob-oss-external-a.example.com:dddddddddddddddd"],
      ["proof-image-scope-b.example.com", "bob-oss-external-b.example.com:dddddddddddddddd"],
    ]) {
      appendRepoRunFixture(domain, "run-fixture", replayCommand, { image_tag: imageTag });
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

test("ProofBundle bundle_hash is stable across different repo run_id handles", () => {
  withTempHome(() => {
    const replayCommand = ["sh", "-lc", "./repro.sh"];
    const hashes = [];
    for (const [domain, runId] of [
      ["proof-run-id-a.example.com", "run-alpha"],
      ["proof-run-id-b.example.com", "run-beta"],
    ]) {
      appendRepoRunFixture(domain, runId, replayCommand, { image_tag: "bob-oss-shared:cccccccccccccccc" });
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

test("bob_compose_report accepts a proof_bundle evidence_ref after proof bundle write", () => {
  withTempHome(() => {
    const domain = "proof-compose.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain);

    const written = JSON.parse(writeProofBundles({ target_domain: domain, packs: [replayBundle()] }));
    assert.equal(written.bundles_count, 1);
    assert.deepEqual(written.missing_finding_ids, []);
    assert.equal(fs.existsSync(proofBundlePaths(domain).json), true);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "proof_bundle",
        heading: "Runnable Proof Bundle",
        prose: "The reportable parser crash has a sandboxed replay bundle attached.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1", "proof_bundle:F-1"],
      }],
    });

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

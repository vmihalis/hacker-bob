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
  if (options.omit_work_mount_mode) delete row.work_mount_mode;
  appendJsonlLine(repoCommandRunsJsonlPath(domain), row);
}

function appendInvariantRunFixture(domain, runHash, options = {}) {
  appendJsonlLine(invariantRunsJsonlPath(domain), {
    run_hash: runHash,
    target_domain: domain,
    finding_id: options.finding_id || "F-1",
    finding_hash: options.finding_hash || "finding-hash-fixture",
    template_id: "reentrancy-basic",
    contract_name: "BobInvariantTest_fixture",
    function_name: "testBobInvariant_fixture",
    execution_context_hash: sha256Hex("context"),
    test_path: "/tmp/harness/test/bob-invariants/BobInvariantTest_fixture.t.sol",
    outcome: options.outcome || "test_passed",
    dry_run: options.dry_run === true ? true : false,
  });
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

test("bob_write_proof_bundle rejects replay rows without a recorded /work mount mode", () => {
  withTempHome(() => {
    const domain = "proof-missing-work-mount.example.com";
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendRepoRunFixture(domain, "run-fixture", ["sh", "-lc", "./repro.sh"], { omit_work_mount_mode: true });

    assert.throws(
      () => writeProofBundles({ target_domain: domain, packs: [replayBundle()] }),
      /read-write \/work repo docker run/,
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
    const runHash = sha256Hex("invariant-run");
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    appendInvariantRunFixture(domain, runHash, { outcome: "test_failed" });

    assert.throws(
      () => writeProofBundles({
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "invariant",
          artifacts: [{ run_hash: runHash }],
        }],
      }),
      /outcome test_passed/,
    );
  });
});

test("bob_write_proof_bundle finds invariant rows beyond the read-tool display cap", () => {
  withTempHome(() => {
    const domain = "proof-invariant-cap.example.com";
    const targetRunHash = sha256Hex("invariant-run-target");
    seedFinding(domain);
    seedFinalRound(domain, [reportableResult()]);
    for (let i = 0; i < 55; i += 1) {
      appendInvariantRunFixture(domain, sha256Hex(`invariant-run-${i}`));
    }
    appendInvariantRunFixture(domain, targetRunHash);

    const written = JSON.parse(writeProofBundles({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        bundle_kind: "invariant",
        artifacts: [{ run_hash: targetRunHash }],
      }],
    }));

    assert.equal(written.bundles_count, 1);
    const doc = JSON.parse(fs.readFileSync(proofBundlePaths(domain).json, "utf8"));
    assert.equal(doc.packs[0].artifacts[0].run_hash, targetRunHash);
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

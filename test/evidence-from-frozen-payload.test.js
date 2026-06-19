"use strict";

// Cycle C.5 invariant: the evidence pipeline sources its work-set from the
// frozen EvidenceReference set carried by every CandidateClaim in
// claim-freeze.json, NOT from a live re-scan of findings.jsonl. Adding an
// inline evidence artifact after the freeze must not change the evidence
// pipeline's view; reading an evidence pack must agree on content_hash with
// the frozen reference; and the completeness gate must fail when a required
// EvidenceReference is missing and pass when every reference is present.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendCandidateClaim,
  evidenceReferenceLookupKey,
  normalizeEvidenceReferenceShape,
} = require("../mcp/lib/claims.js");
const {
  assertCompletenessAgainstFreeze,
  buildClaimFreeze,
  iterateFrozenEvidenceRefs,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  assertEvidenceCompletenessForFreeze,
  normalizeEvidencePacksDocument,
  readFrozenEvidenceFindingIdSet,
  renderEvidencePacksMarkdown,
} = require("../mcp/lib/evidence.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  sessionDir,
  repoCommandRunsJsonlPath,
  repoRunsDir,
} = require("../mcp/lib/paths.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-evidence-from-frozen-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function recordFindingViaTool(domain, overrides = {}) {
  const args = {
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://victim.example/api/billing/1",
    description: overrides.description || "Tenant boundary allows cross-account view",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
    // Cross-tenant billing IDOR: network-reachable, low-privilege attacker
    // tenant, confidentiality impact.
    cvss_inputs: overrides.cvss_inputs || {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  };
  return JSON.parse(recordFindingTool.handler(args));
}

function appendClaimsJsonlDirect(domain, id, overrides = {}) {
  // Mutate claims.jsonl post-freeze. The frozen evidence work-set is built off
  // the freeze artifact, so this new claim must not appear in
  // readFrozenEvidenceFindingIdSet.
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  return appendCandidateClaim({
    target_domain: domain,
    title: overrides.title || `Post-freeze claim ${id}`,
    summary: overrides.description || "Mutated after the freeze",
    severity: overrides.severity || "high",
    status: "candidate",
    surface_ids: [overrides.surface_id || "surface:post-freeze"],
    impact: overrides.impact || "Should not change evidence completeness",
    evidence_refs: [{
      kind: "finding",
      finding_id: id,
      content_hash: "0".repeat(64),
    }],
  });
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function appendRepoRunFixture(domain, runId, {
  stdout = "",
  network_mode: networkMode = "none",
  dry_run: dryRun = false,
  omit_dry_run: omitDryRun = false,
  command_hash: commandHash = "a".repeat(64),
  replay_command_hash: replayCommandHash = commandHash,
  stderr_hash: stderrHash = "b".repeat(64),
  exit_code: exitCode = 0,
  timed_out: timedOut = false,
  mount_mode: mountMode = "read_only",
  checkout_ref: checkoutRef = null,
  checkout_kind: checkoutKind = null,
  checkout_object: checkoutObject = checkoutRef ? "d".repeat(40) : null,
  checkout_object_format: checkoutObjectFormat = checkoutObject && checkoutObject.length === 64 ? "sha256" : "sha1",
  checkout_patch_hash: checkoutPatchHash = checkoutKind === "self_patch" ? sha256Hex("fixture patch\n") : null,
} = {}) {
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), stdout);
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stderr`), "");
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    command_hash: commandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: "c".repeat(64),
    network_mode: networkMode,
    mount_mode: mountMode,
    image_tag: `bob-oss-${domain}:fixture`,
    exit_code: exitCode,
    timed_out: timedOut,
    stdout_hash: sha256Hex(stdout),
    stderr_hash: stderrHash,
  };
  if (!omitDryRun) row.dry_run = dryRun;
  if (checkoutRef) row.checkout_ref = checkoutRef;
  if (checkoutKind) row.checkout_kind = checkoutKind;
  if (checkoutObject) row.checkout_object = checkoutObject;
  if (checkoutObject) row.checkout_object_format = checkoutObjectFormat;
  if (checkoutPatchHash) row.checkout_patch_hash = checkoutPatchHash;
  appendJsonlLine(repoCommandRunsJsonlPath(domain), row);
}

function baseEvidencePack(findingId = "F-1", differential = null) {
  return {
    finding_id: findingId,
    sample_type: "oss_dynamic_replay",
    sample_count: 1,
    aggregate_counts: { runs: 1 },
    representative_samples: [{ run_id: differential ? differential.vuln_run_id : "run-vuln" }],
    sensitive_clusters: [],
    replay_summary: "Sanitizer harness reproduced the issue in the repo sandbox.",
    redaction_notes: null,
    report_snippet: "The sanitizer harness reproduces attacker-controlled parser memory corruption.",
    ...(differential ? { differential } : {}),
  };
}

function normalizePacksForC10(domain, differential) {
  return normalizeEvidencePacksDocument({
    version: 1,
    target_domain: domain,
    packs: [baseEvidencePack("F-1", differential)],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
  });
}

test("C10 differential normalizer accepts each control_kind truth-table verdict", () => {
  withTempHome(() => {
    const domain = "evidence-c10-truth-table.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-upstream", {
      stdout: "upstream still fired\n",
      checkout_ref: "upstream-fix",
      checkout_kind: "upstream_fix",
    });
    appendRepoRunFixture(domain, "run-self-patch", {
      stdout: "patched quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-pre-intro", {
      stdout: "pre intro quiet\n",
      checkout_ref: "pre-introduction",
      checkout_kind: "pre_introduction",
    });

    const cases = [
      {
        control_kind: "upstream_fix",
        control_run_id: "run-upstream",
        control_ref: "upstream-fix",
        control_fired: true,
        verdict: "residual_confirmed",
      },
      {
        control_kind: "self_patch",
        control_run_id: "run-self-patch",
        control_ref: "HEAD",
        control_fired: false,
        verdict: "patch_fixes",
      },
      {
        control_kind: "pre_introduction",
        control_run_id: "run-pre-intro",
        control_ref: "pre-introduction",
        control_fired: false,
        verdict: "regression_localized",
      },
    ];

    for (const item of cases) {
      const document = normalizePacksForC10(domain, {
        control_kind: item.control_kind,
        vuln_run_id: "run-vuln",
        control_run_id: item.control_run_id,
        control_ref: item.control_ref,
        vuln_fired: true,
        control_fired: item.control_fired,
        verdict: item.verdict,
        control_summary: "Control replay completed in the offline repo sandbox.",
      });
      const differential = document.packs[0].differential;
      assert.equal(differential.verdict, item.verdict);
      assert.equal(differential.replay_command_hash, "a".repeat(64));
      assert.equal(differential.vuln_exit_code, 0);
      assert.equal(differential.control_exit_code, 0);
      assert.equal(differential.control_checkout_object, "d".repeat(40));
      assert.equal(differential.control_checkout_object_format, "sha1");
      assert.equal(differential.firedness_source, "agent_asserted_from_replay_output");
      assert.equal(differential.vuln_stdout_hash, sha256Hex("vuln fired\n"));
      assert.match(differential.control_stdout_hash, /^[0-9a-f]{64}$/);
      if (item.control_kind === "self_patch") {
        assert.equal(differential.patch_hash, sha256Hex("fixture patch\n"));
      }
      assert.equal(Object.prototype.hasOwnProperty.call(differential, "stdout"), false);
    }
  });
});

test("C10 differential rejects corrupt JSONL rows before resolving live proof rows", () => {
  withTempHome(() => {
    const domain = "evidence-c10-corrupt-jsonl.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    fs.appendFileSync(repoCommandRunsJsonlPath(domain), "{\"run_id\":\n");
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Corrupt JSONL row must block audit-grade evidence rows.",
      }),
      /repo-command-runs\.jsonl contains malformed JSON at line 2/,
    );
  });
});

test("C10 differential rejects oversized repo command run ledgers", () => {
  withTempHome(() => {
    const domain = "evidence-c10-oversized-jsonl.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    const runLogPath = repoCommandRunsJsonlPath(domain);
    const originalStatSync = fs.statSync;
    try {
      fs.statSync = function patchedStatSync(filePath, ...args) {
        const stats = originalStatSync.call(this, filePath, ...args);
        if (path.resolve(String(filePath)) !== path.resolve(runLogPath)) {
          return stats;
        }
        return Object.create(stats, {
          size: {
            value: 17 * 1024 * 1024,
            enumerable: true,
          },
        });
      };
      assert.throws(
        () => normalizePacksForC10(domain, {
          control_kind: "self_patch",
          vuln_run_id: "run-vuln",
          control_run_id: "run-control",
          control_ref: "HEAD",
          vuln_fired: true,
          control_fired: false,
          verdict: "patch_fixes",
          control_summary: "Oversized repo-command-runs ledger should not be read into memory.",
        }),
        /repo-command-runs\.jsonl exceeds read cap/,
      );
    } finally {
      fs.statSync = originalStatSync;
    }
  });
});

test("C10 differential rejects ambiguous duplicate repo run rows", () => {
  withTempHome(() => {
    const domain = "evidence-c10-duplicate-run-row.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet replay\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Duplicate run rows must not bind evidence by first match.",
      }),
      /ambiguous duplicate entries/,
    );
  });
});

test("C10 differential rejects unsafe run ids, tampered stdout captures, and malformed exit codes", () => {
  withTempHome(() => {
    const unsafeDomain = "evidence-c10-unsafe-run-id.example.com";
    appendRepoRunFixture(unsafeDomain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    assert.throws(
      () => normalizePacksForC10(unsafeDomain, {
        control_kind: "self_patch",
        vuln_run_id: "../escape",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Unsafe run ids must not become capture-file paths.",
      }),
      /path-safe repo run id/,
    );

    const tamperDomain = "evidence-c10-tampered-stdout.example.com";
    appendRepoRunFixture(tamperDomain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(tamperDomain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    fs.writeFileSync(path.join(repoRunsDir(tamperDomain), "run-vuln.stdout"), "tampered stdout\n");
    assert.throws(
      () => normalizePacksForC10(tamperDomain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "The JSONL stdout hash must agree with the capture file.",
      }),
      /stdout_hash does not match/,
    );

    const malformedDomain = "evidence-c10-malformed-exit.example.com";
    appendRepoRunFixture(malformedDomain, "run-vuln", {
      stdout: "vuln fired\n",
      exit_code: null,
    });
    appendRepoRunFixture(malformedDomain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    assert.throws(
      () => normalizePacksForC10(malformedDomain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "C10 firedness requires an actual live-run exit code.",
      }),
      /integer exit_code/,
    );
  });
});

test("C10 differential rejects identical run ids, dry-run rows, network-tainted controls, and command mismatch", () => {
  withTempHome(() => {
    const domain = "evidence-c10-rejects.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-vuln-missing-replay-hash", {
      stdout: "vuln fired\n",
      replay_command_hash: null,
    });
    appendRepoRunFixture(domain, "run-vuln-read-write", {
      stdout: "vuln fired after source mutation\n",
      mount_mode: "read_write",
    });
    appendRepoRunFixture(domain, "run-control-dry-run", {
      stdout: "control plan only\n",
      dry_run: true,
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control-missing-dry-run", {
      stdout: "control row without dry_run flag\n",
      omit_dry_run: true,
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control-network", {
      stdout: "control fired\n",
      network_mode: "bridge",
      checkout_ref: "abcdef123456",
      checkout_kind: "upstream_fix",
    });
    appendRepoRunFixture(domain, "run-control-command-mismatch", {
      stdout: "control quiet\n",
      replay_command_hash: "f".repeat(64),
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control-timeout", {
      stdout: "control timed out\n",
      timed_out: true,
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    for (const exitCode of [125, 126, 127]) {
      appendRepoRunFixture(domain, `run-control-exit-${exitCode}`, {
        stdout: `control infra failure ${exitCode}\n`,
        exit_code: exitCode,
        checkout_ref: "HEAD",
        checkout_kind: "self_patch",
      });
    }

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "upstream_fix",
        vuln_run_id: "run-vuln",
        control_run_id: "run-vuln",
        control_ref: "abcdef123456",
        vuln_fired: true,
        control_fired: true,
        verdict: "residual_confirmed",
        control_summary: "Same run should be rejected.",
      }),
      /must differ/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control-dry-run",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Plan rows should be rejected.",
      }),
      /live non-dry-run/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control-missing-dry-run",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Rows must explicitly prove they were live runs.",
      }),
      /live non-dry-run/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "upstream_fix",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control-network",
        control_ref: "abcdef123456",
        vuln_fired: true,
        control_fired: true,
        verdict: "residual_confirmed",
        control_summary: "Network-tainted control should be rejected.",
      }),
      /--network none/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control-command-mismatch",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Different commands cannot prove patched-vs-unpatched.",
      }),
      /same replay command hash/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control-timeout",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Timed-out controls cannot prove a quiet replay.",
      }),
      /timed-out run/,
    );

    for (const exitCode of [125, 126, 127]) {
      assert.throws(
        () => normalizePacksForC10(domain, {
          control_kind: "self_patch",
          vuln_run_id: "run-vuln",
          control_run_id: `run-control-exit-${exitCode}`,
          control_ref: "HEAD",
          vuln_fired: true,
          control_fired: false,
          verdict: "patch_fixes",
          control_summary: "Docker/runtime infrastructure failures cannot prove a quiet replay.",
        }),
        /infrastructure failure exit code/,
      );
    }

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln-missing-replay-hash",
        control_run_id: "run-control-command-mismatch",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Legacy rows without replay hashes cannot prove command equality.",
      }),
      /replay_command_hash/,
    );

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln-read-write",
        control_run_id: "run-control-command-mismatch",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "The vulnerable baseline must not have mutable source access.",
      }),
      /read-only \/src/,
    );
  });
});

test("C10 differential rejects controls without matching S14 checkout provenance", () => {
  withTempHome(() => {
    const domain = "evidence-c10-checkout-binding.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-vuln-checkout", {
      stdout: "control checkout on the vuln side\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control-unbound", { stdout: "control quiet\n" });
    appendRepoRunFixture(domain, "run-control-wrong-ref", {
      stdout: "control quiet\n",
      checkout_ref: "other-ref",
      checkout_kind: "self_patch",
    });
    appendRepoRunFixture(domain, "run-control-wrong-kind", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "upstream_fix",
    });

    for (const controlRunId of ["run-control-unbound", "run-control-wrong-ref", "run-control-wrong-kind"]) {
      assert.throws(
        () => normalizePacksForC10(domain, {
          control_kind: "self_patch",
          vuln_run_id: "run-vuln",
          control_run_id: controlRunId,
          control_ref: "HEAD",
          vuln_fired: true,
          control_fired: false,
          verdict: "patch_fixes",
          control_summary: "Control binding must match the S14 checkout provenance.",
        }),
        /matching S14 checkout run/,
      );
    }

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln-checkout",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "The vulnerable side must be the baseline run, not another checkout.",
      }),
      /baseline non-checkout run/,
    );
  });
});

test("C10 differential is scrub-validated before persistence", () => {
  withTempHome(() => {
    const domain = "evidence-c10-scrub.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control quiet\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });

    assert.throws(
      () => normalizePacksForC10(domain, {
        control_kind: "self_patch",
        vuln_run_id: "run-vuln",
        control_run_id: "run-control",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "eyJhbGciOiJxxx.aabbccddeexxxxx.aabbccddeexxxxx",
      }),
      /secrets|secret|tokens|cookies/i,
    );
  });
});

test("C10 inconsistent control downgrades to inconclusive without dropping the finding", () => {
  withTempHome(() => {
    const domain = "evidence-c10-inconclusive.example.com";
    appendRepoRunFixture(domain, "run-vuln", { stdout: "vuln fired\n" });
    appendRepoRunFixture(domain, "run-control", {
      stdout: "control also fired\n",
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });

    const document = normalizePacksForC10(domain, {
      control_kind: "self_patch",
      vuln_run_id: "run-vuln",
      control_run_id: "run-control",
      control_ref: "HEAD",
      vuln_fired: true,
      control_fired: true,
      verdict: "patch_fixes",
      control_summary: "The self patch did not quiet the proof; record the ambiguity.",
    });

    assert.equal(document.packs.length, 1);
    assert.equal(document.packs[0].finding_id, "F-1");
    assert.equal(document.packs[0].differential.verdict, "inconclusive");
    assert.equal(document.packs[0].differential._verdict_overridden, true);
    assert.equal(document.packs[0].differential._supplied_verdict, "patch_fixes");
    assert.equal(document.packs[0].differential._expected_verdict, "inconclusive");
    const markdown = renderEvidencePacksMarkdown(document);
    assert.match(markdown, /- Differential:/);
    assert.match(markdown, /Verdict: inconclusive/);
    assert.match(markdown, /Verdict Override: supplied=patch_fixes; expected=inconclusive/);
    assert.match(markdown, /Vulnerable Exit Code: 0/);
    assert.match(markdown, /Control Exit Code: 0/);
    assert.match(markdown, /Firedness Source: agent_asserted_from_replay_output/);
    assert.match(markdown, /Replay Command Hash: [0-9a-f]{64}/);
    assert.match(markdown, /Patch Hash: [0-9a-f]{64}/);
    assert.match(markdown, /Vulnerable Stdout Hash: [0-9a-f]{64}/);
    assert.match(markdown, /Control Stdout Hash: [0-9a-f]{64}/);
  });
});

test("evidence work-set derives from frozen EvidenceReference set, not live findings.jsonl", () => {
  withTempHome(() => {
    const domain = "evidence-frozen-source.example.com";
    // N=3 findings via the dual-write tool. Each produces a CandidateClaim
    // carrying a single evidence_ref of kind="finding".
    const ids = [];
    for (let i = 1; i <= 3; i += 1) {
      const response = recordFindingViaTool(domain, {
        title: `Pre-freeze finding ${i}`,
        endpoint: `https://victim.example/api/billing/${i}`,
        poc: `GET /api/billing/${i} returns another tenant payload`,
      });
      assert.equal(response.recorded, true);
      ids.push(response.finding_id);
    }

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 3);

    // Pre-mutation: work-set has exactly the 3 ids encoded in the freeze.
    const beforeIds = readFrozenEvidenceFindingIdSet(domain);
    assert.equal(beforeIds.size, 3);
    for (const id of ids) {
      assert.ok(beforeIds.has(id), `frozen work-set must contain ${id}`);
    }

    // Append a claim directly to claims.jsonl AFTER the freeze so the live
    // ledger drifts. The frozen evidence work-set must remain anchored to the
    // freeze artifact.
    appendClaimsJsonlDirect(domain, "F-99");

    // Post-mutation: the work-set still derives from the freeze, which is
    // unchanged. The new claim is IGNORED.
    const afterIds = readFrozenEvidenceFindingIdSet(domain);
    assert.equal(afterIds.size, 3, "frozen payload is authoritative; live ledger mutation is ignored");
    for (const id of ids) {
      assert.ok(afterIds.has(id));
    }
    assert.ok(!afterIds.has("F-99"), "post-freeze claims.jsonl row must not appear in the frozen work-set");
  });
});

test("iterating frozen evidence refs yields each CandidateClaim's content-hash-bound EvidenceReference", () => {
  withTempHome(() => {
    const domain = "evidence-frozen-refs.example.com";
    // M=2 findings -> 2 claims, each with 1 evidence ref.
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/A" });
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/B" });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 2);

    const entries = [...iterateFrozenEvidenceRefs(freeze)];
    assert.equal(entries.length, 2, "iteration must visit every evidence ref");
    for (const entry of entries) {
      assert.equal(entry.ref.kind, "finding");
      assert.equal(typeof entry.ref.finding_id, "string");
      assert.equal(typeof entry.ref.content_hash, "string");
      assert.equal(entry.ref.content_hash.length, 64);
      assert.equal(typeof entry.claim_id, "string");
      assert.equal(entry.ref_key, evidenceReferenceLookupKey(entry.ref));
    }
  });
});

test("completeness gate fails when a required evidence_ref is missing, and passes when every ref is present", () => {
  withTempHome(() => {
    const domain = "evidence-completeness.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/2" });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 2);

    const frozenRefs = [];
    for (const entry of iterateFrozenEvidenceRefs(freeze)) {
      frozenRefs.push(entry.ref);
    }
    assert.equal(frozenRefs.length, 2);

    // Case 1: supply only one of the two refs -> completeness fails with a
    // structured missing entry that names the affected claim_id.
    const partial = assertCompletenessAgainstFreeze(freeze, [frozenRefs[0]]);
    assert.equal(partial.complete, false, "missing one ref must fail completeness");
    assert.equal(partial.required, 2);
    assert.equal(partial.satisfied, 1);
    assert.equal(partial.missing.length, 1);
    assert.equal(partial.missing[0].kind, "finding");
    assert.ok(typeof partial.missing[0].claim_id === "string");

    // Case 2: supply both refs -> completeness passes.
    const complete = assertCompletenessAgainstFreeze(freeze, frozenRefs);
    assert.equal(complete.complete, true, "supplying every ref must satisfy completeness");
    assert.equal(complete.satisfied, 2);
    assert.equal(complete.missing.length, 0);
    assert.equal(complete.mismatched.length, 0);

    // Case 3: supply a ref whose content_hash does not match -> mismatch.
    const tampered = {
      ...frozenRefs[0],
      content_hash: "0".repeat(64),
    };
    const mismatch = assertCompletenessAgainstFreeze(freeze, [tampered, frozenRefs[1]]);
    assert.equal(mismatch.complete, false, "content_hash mismatch must fail completeness");
    assert.equal(mismatch.mismatched.length, 1);
    assert.equal(mismatch.mismatched[0].expected_hash, frozenRefs[0].content_hash);
    assert.equal(mismatch.mismatched[0].observed_hash, "0".repeat(64));
  });
});

test("normalizeEvidenceReferenceShape rejects refs without a kind", () => {
  // Plain shape contract: kind is the only required field; artifact_path and
  // content_hash are validated when present.
  assert.throws(
    () => normalizeEvidenceReferenceShape({ artifact_path: "findings.jsonl" }),
    /kind must be a non-empty string/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "finding", content_hash: "not-a-hash" }),
    /content_hash must be a 64-hex content digest/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "finding", artifact_path: "" }),
    /artifact_path must be a non-empty string/,
  );
  // Valid: a finding ref with full descriptors round-trips.
  const ok = normalizeEvidenceReferenceShape({
    kind: "finding",
    artifact_path: "findings.jsonl",
    finding_id: "F-1",
    content_hash: "a".repeat(64),
    source_run_id: "AR-1",
  });
  assert.equal(ok.kind, "finding");
  assert.equal(ok.finding_id, "F-1");
});

test("appendCandidateClaim enforces EvidenceReference shape on every evidence_refs[] entry", () => {
  withTempHome(() => {
    const domain = "evidence-shape-guard.example.com";
    // A CandidateClaim with a malformed evidence ref is rejected up front so a
    // later completeness gate cannot encounter ill-typed entries.
    assert.throws(
      () => appendCandidateClaim({
        target_domain: domain,
        title: "Bad ref claim",
        summary: "Carries an evidence ref without a kind.",
        severity: "high",
        evidence_refs: [{ artifact_path: "findings.jsonl" }],
      }),
      /kind must be a non-empty string/,
    );

    // A well-formed ref accepts.
    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "Well-formed claim",
      summary: "Carries a complete EvidenceReference.",
      severity: "high",
      evidence_refs: [{
        kind: "finding",
        artifact_path: "findings.jsonl",
        finding_id: "F-1",
        content_hash: "b".repeat(64),
        source_run_id: "AR-7",
      }],
    });
    assert.equal(claim.evidence_refs.length, 1);
    assert.equal(claim.evidence_refs[0].kind, "finding");
  });
});

test("evidence pack content_hash agrees with the frozen reference", () => {
  withTempHome(() => {
    const domain = "evidence-pack-hash.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 1);

    // Read the frozen ref straight off the freeze on disk and confirm
    // round-trip identity with the in-memory document.
    const onDisk = readCurrentClaimFreeze(domain);
    assert.ok(onDisk, "freeze must persist to disk");
    assert.equal(onDisk.claim_count, 1);

    const frozenRef = onDisk.claims[0].evidence_refs[0];
    assert.equal(frozenRef.kind, "finding");
    assert.equal(typeof frozenRef.content_hash, "string");
    assert.equal(frozenRef.content_hash.length, 64);

    // Pull the same ref via the iterator and confirm content_hash equality.
    const fromIterator = [...iterateFrozenEvidenceRefs(onDisk)][0].ref;
    assert.equal(fromIterator.content_hash, frozenRef.content_hash);
  });
});

test("assertEvidenceCompletenessForFreeze reads the on-disk freeze and reports a structured verdict", () => {
  withTempHome(() => {
    const domain = "evidence-on-disk.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/2" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });

    // No evidence pack yet -> completeness fails because no observed refs.
    const empty = assertEvidenceCompletenessForFreeze(domain);
    assert.equal(empty.complete, false);
    assert.equal(empty.required, 2);
    assert.equal(empty.satisfied, 0);
    assert.equal(empty.missing.length, 2);

    // Supply every ref directly -> completeness passes.
    const freeze = readCurrentClaimFreeze(domain);
    const refs = [];
    for (const entry of iterateFrozenEvidenceRefs(freeze)) {
      refs.push(entry.ref);
    }
    const full = assertEvidenceCompletenessForFreeze(domain, { suppliedRefs: refs });
    assert.equal(full.complete, true);
    assert.equal(full.required, 2);
    assert.equal(full.satisfied, 2);
  });
});

test("completeness gate when no freeze exists: blocker_reason explains the missing source", () => {
  withTempHome(() => {
    const domain = "evidence-no-freeze.example.com";
    const verdict = assertEvidenceCompletenessForFreeze(domain);
    assert.equal(verdict.complete, false);
    assert.equal(verdict.blocker_reason, "no claim freeze available");
  });
});

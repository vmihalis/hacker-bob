"use strict";

// Determinism CI canary. Runs every v2-style content-addressed artifact
// pipeline that lands in this branch through two identical inputs and
// asserts the resulting on-disk hashes are byte-stable across runs. Future
// changes that quietly break the deterministic-replay invariant on any one
// artifact surface here without slipping past the per-module tests.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  ingestSchemaDoc,
} = require("../mcp/lib/schema-contracts-store.js");
const {
  runDocDelta,
  readResults: readDocDeltaResults,
} = require("../mcp/lib/doc-delta-runner.js");
const {
  runAuthDifferential,
  readResults: readAuthDifferentialResults,
} = require("../mcp/lib/auth-differential-runner.js");
const {
  appendEdges,
} = require("../mcp/lib/surface-graph.js");
const {
  buildSurfaceGraph,
} = require("../mcp/lib/surface-graph-builder.js");
const {
  normalizeEvidencePacksDocument,
} = require("../mcp/lib/evidence.js");
const {
  normalizeProofBundlesDocument,
} = require("../mcp/lib/proof-bundle.js");
const {
  proofBundlePaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

const FIXTURE_CHECKOUT_OBJECT = "1".repeat(40);

function uniqueDomain(prefix = "bob-determinism-ci") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function domainDir(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = domainDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function readFile(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function hashFile(filePath) {
  return crypto.createHash("sha256").update(readFile(filePath)).digest("hex");
}

function writeAttackSurface(domain, surfaces) {
  const dir = domainDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "attack_surface.json"),
    JSON.stringify({ surfaces }, null, 2),
  );
}

const FIXTURE_OPENAPI = JSON.stringify({
  openapi: "3.0.3",
  paths: {
    "/users": {
      get: {
        security: [{ bearerAuth: [] }],
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["id"],
                  properties: { id: { type: "string" }, name: { type: "string" } },
                },
              },
            },
          },
        },
      },
    },
    "/health": {
      get: {
        responses: {
          "200": {
            description: "ok",
            content: { "application/json": { schema: { type: "object" } } },
          },
        },
      },
    },
  },
});

const FIXTURE_ATTACK_SURFACE = Object.freeze([
  {
    id: "S-1",
    hosts: ["api.example.com"],
    endpoints: ["/users", "/health"],
    tech_stack: ["express"],
  },
]);

function fixtureFetch({ contract }) {
  if (contract.endpoint === "/users") {
    return {
      status: 200,
      content_type: "application/json",
      body: { id: "u-1", name: "Alice" },
      sent_with_auth: true,
    };
  }
  return {
    status: 200,
    content_type: "application/json",
    body: {},
    sent_with_auth: false,
  };
}

function fixtureFetchByProfile({ auth_profile, endpoint }) {
  if (endpoint === "/admin") {
    if (auth_profile === "admin") {
      return {
        status: 200,
        content_type: "application/json",
        body: { id: "a-1", role: "admin" },
        sent_with_auth: true,
      };
    }
    return {
      status: 403,
      content_type: "application/json",
      body: null,
      sent_with_auth: true,
    };
  }
  return {
    status: 200,
    content_type: "application/json",
    body: { id: "u-1" },
    sent_with_auth: true,
  };
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function appendRepoRunFixture(domain, runId, stdout, {
  checkout_ref: checkoutRef = null,
  checkout_kind: checkoutKind = null,
  checkout_object: checkoutObject = checkoutRef ? FIXTURE_CHECKOUT_OBJECT : null,
  checkout_object_format: checkoutObjectFormat = checkoutObject ? "sha1" : null,
} = {}) {
  const replayCommandHash = sha256Hex(JSON.stringify(["sh", "-lc", "./repro.sh"]));
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), stdout);
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stderr`), "");
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: replayCommandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: sha256Hex(JSON.stringify(["run", "--network", "none"])),
    network_mode: "none",
    mount_mode: "read_only",
    work_mount_mode: "read_write",
    replay_context: { finding_id: "F-1" },
    image_tag: "bob-oss-fixture:stable",
    exit_code: 0,
    timed_out: false,
    stdout_hash: sha256Hex(stdout),
    stderr_hash: sha256Hex(""),
  };
  if (checkoutRef) row.checkout_ref = checkoutRef;
  if (checkoutKind) row.checkout_kind = checkoutKind;
  if (checkoutObject) row.checkout_object = checkoutObject;
  if (checkoutObjectFormat) row.checkout_object_format = checkoutObjectFormat;
  if (checkoutKind === "self_patch") row.checkout_patch_hash = sha256Hex("fixture patch\n");
  appendJsonlLine(repoCommandRunsJsonlPath(domain), row);
}

function exerciseDifferentialEvidence(domain) {
  appendRepoRunFixture(domain, "det-ci-vuln-run", "vuln fired\n");
  appendRepoRunFixture(domain, "det-ci-control-run", "control quiet\n", {
    checkout_ref: "HEAD",
    checkout_kind: "self_patch",
  });
  const document = normalizeEvidencePacksDocument({
    version: 1,
    target_domain: domain,
    packs: [{
      finding_id: "F-1",
      sample_type: "oss_dynamic_replay",
      sample_count: 1,
      aggregate_counts: { runs: 2 },
      representative_samples: [{ run_id: "det-ci-vuln-run" }],
      sensitive_clusters: [],
      replay_summary: "Deterministic differential fixture replay.",
      redaction_notes: null,
      report_snippet: "The self patch quiets the fixture proof.",
      differential: {
        control_kind: "self_patch",
        vuln_run_id: "det-ci-vuln-run",
        control_run_id: "det-ci-control-run",
        control_ref: "HEAD",
        vuln_fired: true,
        control_fired: false,
        verdict: "patch_fixes",
        control_summary: "Control run did not fire in the offline fixture.",
      },
    }],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
  });
  return {
    differential_hash: hashCanonicalJson(document.packs[0].differential),
  };
}

function exerciseProofBundle(domain) {
  const document = normalizeProofBundlesDocument({
    version: 1,
    target_domain: domain,
    packs: [{
      finding_id: "F-1",
      bundle_kind: "replay_script",
      artifacts: [{
        run_id: "det-ci-vuln-run",
        replay_command: ["sh", "-lc", "./repro.sh"],
        replay_summary: "Deterministic proof bundle fixture replay.",
      }],
    }],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
  });
  const paths = proofBundlePaths(domain);
  fs.writeFileSync(paths.json, `${JSON.stringify(document, null, 2)}\n`);
  return {
    bundle_hash: document.packs[0].bundle_hash,
    document_hash: hashCanonicalJson(document),
  };
}

async function exerciseDeterministicPipelines(domain) {
  ingestSchemaDoc({
    target_domain: domain,
    raw_doc: FIXTURE_OPENAPI,
    source_uri: "https://fixture.example/openapi.json",
  });

  const docDelta = await runDocDelta({
    target_domain: domain,
    base_url: "https://api.example.com",
    fetch_fn: fixtureFetch,
    run_id: "det-ci-doc-delta",
  });

  const authDiff = await runAuthDifferential({
    target_domain: domain,
    base_url: "https://api.example.com",
    endpoints: ["/users", "/admin"],
    auth_profiles: ["admin", "user"],
    fetch_fn: fixtureFetchByProfile,
    run_id: "det-ci-auth-diff",
  });

  writeAttackSurface(domain, FIXTURE_ATTACK_SURFACE);
  buildSurfaceGraph({ target_domain: domain });

  appendEdges({
    target_domain: domain,
    edges: [
      {
        source: { type: "endpoint", id: "/users" },
        target: { type: "endpoint", id: "/users/{id}" },
        edge_type: "references",
        source_artifact: "determinism-ci.test.js",
      },
    ],
  });

  const c10 = exerciseDifferentialEvidence(domain);
  const proofBundle = exerciseProofBundle(domain);
  return { docDelta, authDiff, c10, proofBundle };
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return readFile(filePath)
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}

// Per-record content hash sets stay stable across runs even though some
// records embed wall-clock timestamps (ingested_at, indexed_at,
// observed_at). The content hashes (contract_hash, edge_hash) are computed
// from the canonical payload only and therefore replay-deterministic.
function snapshotContentHashSets(domain) {
  const dir = domainDir(domain);
  return {
    "schema-contracts.jsonl": new Set(
      readJsonl(path.join(dir, "schema-contracts.jsonl"))
        .map((row) => row.contract_hash)
        .filter((hash) => typeof hash === "string"),
    ),
    "surface-graph.jsonl": new Set(
      readJsonl(path.join(dir, "surface-graph.jsonl"))
        .map((row) => row.edge_hash)
        .filter((hash) => typeof hash === "string"),
    ),
  };
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const value of a) {
    if (!b.has(value)) return false;
  }
  return true;
}

test("determinism CI: every v2-style content-addressed artifact reproduces byte-stably across runs", async () => {
  const domainA = uniqueDomain();
  const domainB = uniqueDomain();
  try {
    const runA = await exerciseDeterministicPipelines(domainA);
    const runB = await exerciseDeterministicPipelines(domainB);

    // Per-record content hash sets stay stable across the two independent
    // target sessions even though wall-clock timestamps in each record
    // differ. Content hashes (contract_hash, edge_hash) and stable IDs
    // (finding_id) are computed from canonical payload fields only, with no
    // domain dependency, so the *set* of artifact identities matches across
    // runs against different target_domains.
    const setsA = snapshotContentHashSets(domainA);
    const setsB = snapshotContentHashSets(domainB);
    for (const name of Object.keys(setsA)) {
      assert.ok(setsA[name].size > 0, `expected non-empty ${name} in run A`);
      assert.ok(setsetEqualOrThrow(setsA[name], setsB[name], name));
    }

    // doc-delta and auth-differential results_hash bake target_domain into
    // the canonical payload so they legitimately differ across distinct
    // domains. Confirm that fact instead of asserting equality - this
    // guards against future churn that accidentally drops target_domain
    // from the summary (which would silently break per-target replay
    // bookkeeping).
    assert.notEqual(runA.docDelta.results_hash, runB.docDelta.results_hash, "doc-delta results_hash must include target_domain so cross-domain hashes diverge");
    assert.notEqual(runA.authDiff.results_hash, runB.authDiff.results_hash, "auth-differential results_hash must include target_domain so cross-domain hashes diverge");
    assert.notEqual(runA.proofBundle.document_hash, runB.proofBundle.document_hash, "proof-bundles.json hash must include target_domain so cross-domain hashes diverge");
    assert.equal(runA.c10.differential_hash, runB.c10.differential_hash, "C10 differential hash must be target-domain independent");
    assert.equal(runA.proofBundle.bundle_hash, runB.proofBundle.bundle_hash, "C14 bundle_hash must be target-domain independent");
    assert.ok(typeof runA.docDelta.results_hash === "string" && runA.docDelta.results_hash.length === 64);
    assert.ok(typeof runA.authDiff.results_hash === "string" && runA.authDiff.results_hash.length === 64);
    assert.ok(typeof runA.c10.differential_hash === "string" && runA.c10.differential_hash.length === 64);
    assert.ok(typeof runA.proofBundle.bundle_hash === "string" && runA.proofBundle.bundle_hash.length === 64);
    assert.ok(typeof runA.proofBundle.document_hash === "string" && runA.proofBundle.document_hash.length === 64);
    // The disk-resident copy must match the in-memory result we got back.
    assert.equal(readDocDeltaResults(domainA).results_hash, runA.docDelta.results_hash);
    assert.equal(readAuthDifferentialResults(domainA).results_hash, runA.authDiff.results_hash);
  } finally {
    cleanupDomain(domainA);
    cleanupDomain(domainB);
  }
});

test("determinism CI: re-running the same pipeline against the same target produces stable content-hash sets and results_hash", async () => {
  const domain = uniqueDomain();
  try {
    const firstRun = await exerciseDeterministicPipelines(domain);
    const firstSets = snapshotContentHashSets(domain);
    const secondRun = await exerciseDeterministicPipelines(domain);
    const secondSets = snapshotContentHashSets(domain);
    for (const name of Object.keys(firstSets)) {
      assert.ok(setsetEqualOrThrow(firstSets[name], secondSets[name], `${name} (same target, two passes)`));
    }
    assert.equal(firstRun.docDelta.results_hash, secondRun.docDelta.results_hash, "doc-delta results_hash drifted on second pass against the same target");
    assert.equal(firstRun.authDiff.results_hash, secondRun.authDiff.results_hash, "auth-differential results_hash drifted on second pass against the same target");
    assert.equal(firstRun.c10.differential_hash, secondRun.c10.differential_hash, "C10 differential hash drifted on second pass against the same target");
    assert.equal(firstRun.proofBundle.bundle_hash, secondRun.proofBundle.bundle_hash, "C14 bundle_hash drifted on second pass against the same target");
    assert.equal(firstRun.proofBundle.document_hash, secondRun.proofBundle.document_hash, "proof-bundles.json hash drifted on second pass against the same target");
  } finally {
    cleanupDomain(domain);
  }
});

function setsetEqualOrThrow(a, b, label) {
  if (setsEqual(a, b)) return true;
  const onlyA = [...a].filter((v) => !b.has(v));
  const onlyB = [...b].filter((v) => !a.has(v));
  throw new Error(`${label} content-hash set drift: only_in_a=${JSON.stringify(onlyA.slice(0, 5))} only_in_b=${JSON.stringify(onlyB.slice(0, 5))}`);
}

"use strict";

// Plane O Cycle O.6 — OSS surfacing (lenses + observation kinds + technique
// packs + cli-tool packs + brief slice profile).
//
// Reviewer-B parsimony: O.6 is the MERGED surfacing cycle. It covers:
//   - 3 new task lenses (code_surface_scout, taint_trace, fuzz_run) bringing
//     TASK_LENSES from 10 → 13. NOT 5: dependency_audit collapses into
//     taint_trace; reproduction_in_container reuses reproduction_check.
//   - profile: "oss" brief slice registry distinct from web / smart_contract.
//   - 4 observation kinds (dependency_observed, unsafe_sink_observed,
//     crash_observed, config_misuse_observed). NOT 5: known_cve_ids[] in the
//     dependency payload subsumes the would-be cve_signal_observed.
//   - 7 OSS technique packs with hunting vocabulary in `summary` content +
//     id alias map for typo / legacy-id recovery.
//   - 7 OSS cli-tool packs (semgrep, trivy, codeql, coccinelle,
//     cargo-audit, npm-audit, pip-audit).
//     Deferred: bandit, gosec, syft, grype, radare2/binwalk/ghidra.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  TASK_LENSES,
  isTaskLens,
  normalizeTaskLens,
} = require("../mcp/lib/task-lenses.js");
const {
  ASSIGNMENT_BRIEF_SLICE_REGISTRY,
  OSS_BRIEF_SLICE_REGISTRY,
  OSS_LENSES,
  REPO_WORKFLOW_TEXT,
  buildBriefExtrasForProfile,
  briefSliceRegistryForProfile,
  isOssLens,
} = require("../mcp/lib/assignment-brief.js");
const {
  OSS_OBSERVATION_KIND_VALUES,
  OSS_OBSERVATION_BUILDERS,
  buildOssObservationPayload,
  isOssObservationKind,
  recordOssObservation,
} = require("../mcp/lib/repo-target.js");
const {
  CLI_TOOL_PACKS,
  selectCliToolPacks,
} = require("../mcp/lib/cli-tool-packs.js");
const {
  OSS_TECHNIQUE_PACKS,
  OSS_TECHNIQUE_PACK_ID_ALIASES,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  findOssTechniquePack,
  resolveOssTechniquePackId,
} = require("../mcp/lib/technique-packs.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  CAPABILITY_PACKS,
} = require("../mcp/lib/capability-packs.js");

// ── Fixture helpers ──────────────────────────────────────────────────────────

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oss-surfacing-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function readFrontierEvents(domain) {
  const eventsPath = path.join(sessionDir(domain), "frontier-events.jsonl");
  if (!fs.existsSync(eventsPath)) return [];
  return fs.readFileSync(eventsPath, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

// ── Lens enum membership (3 added; 13 total) ────────────────────────────────

test("TASK_LENSES adds code_surface_scout, taint_trace, fuzz_run (3 OSS lenses → 13 total)", () => {
  assert.equal(TASK_LENSES.length, 13, "TASK_LENSES must total 13 after Cycle O.6");
  assert.ok(TASK_LENSES.includes("code_surface_scout"), "must enumerate code_surface_scout");
  assert.ok(TASK_LENSES.includes("taint_trace"), "must enumerate taint_trace");
  assert.ok(TASK_LENSES.includes("fuzz_run"), "must enumerate fuzz_run");
  // Reviewer B parsimony: DROPPED lenses must NOT be added.
  assert.ok(!TASK_LENSES.includes("dependency_audit"), "dependency_audit must NOT be added (collapses into taint_trace)");
  assert.ok(!TASK_LENSES.includes("reproduction_in_container"), "reproduction_in_container must NOT be added (reuses reproduction_check)");
  // Regression: HTTP / browser lenses still present.
  assert.ok(TASK_LENSES.includes("behavior_probe"));
  assert.ok(TASK_LENSES.includes("browser_behavior_probe"));
  assert.ok(TASK_LENSES.includes("reproduction_check"));
});

test("isTaskLens recognises the new OSS lenses", () => {
  assert.equal(isTaskLens("code_surface_scout"), true);
  assert.equal(isTaskLens("taint_trace"), true);
  assert.equal(isTaskLens("fuzz_run"), true);
  assert.equal(isTaskLens("not_a_real_lens"), false);
});

test("normalizeTaskLens accepts the new OSS lenses and rejects unknowns", () => {
  assert.equal(normalizeTaskLens("code_surface_scout"), "code_surface_scout");
  assert.equal(normalizeTaskLens("taint_trace"), "taint_trace");
  assert.equal(normalizeTaskLens("fuzz_run"), "fuzz_run");
  // Regression: existing HTTP lens still normalises.
  assert.equal(normalizeTaskLens("behavior_probe"), "behavior_probe");
  assert.throws(
    () => normalizeTaskLens("dependency_audit"),
    /lens/,
    "normalizer must reject the dropped dependency_audit lens",
  );
});

test("isOssLens identifies only the three OSS lenses", () => {
  assert.equal(isOssLens("code_surface_scout"), true);
  assert.equal(isOssLens("taint_trace"), true);
  assert.equal(isOssLens("fuzz_run"), true);
  // Non-OSS lenses must NOT trigger the OSS dispatch.
  assert.equal(isOssLens("behavior_probe"), false);
  assert.equal(isOssLens("browser_behavior_probe"), false);
  assert.equal(isOssLens("surface_scout"), false);
  assert.equal(isOssLens(null), false);
  assert.equal(isOssLens(undefined), false);
});

// ── Profile: "oss" brief slice registry ─────────────────────────────────────

test("ASSIGNMENT_BRIEF_SLICE_REGISTRY exposes an `oss` profile distinct from web / smart_contract", () => {
  assert.ok(ASSIGNMENT_BRIEF_SLICE_REGISTRY.web, "web profile present (regression)");
  assert.ok(ASSIGNMENT_BRIEF_SLICE_REGISTRY.smart_contract, "smart_contract profile present (regression)");
  assert.ok(ASSIGNMENT_BRIEF_SLICE_REGISTRY.oss, "oss profile must be registered under its own key");
  // The three registries must be DISTINCT objects (not aliased), so future
  // changes to one don't bleed into another.
  assert.notEqual(ASSIGNMENT_BRIEF_SLICE_REGISTRY.oss, ASSIGNMENT_BRIEF_SLICE_REGISTRY.web);
  assert.notEqual(ASSIGNMENT_BRIEF_SLICE_REGISTRY.oss, ASSIGNMENT_BRIEF_SLICE_REGISTRY.smart_contract);
});

test("briefSliceRegistryForProfile('oss') returns the OSS registry", () => {
  assert.equal(briefSliceRegistryForProfile("oss"), OSS_BRIEF_SLICE_REGISTRY);
  // Regression: web + smart_contract resolutions unchanged.
  assert.equal(briefSliceRegistryForProfile("web"), ASSIGNMENT_BRIEF_SLICE_REGISTRY.web);
  assert.equal(briefSliceRegistryForProfile("smart_contract_evm"), ASSIGNMENT_BRIEF_SLICE_REGISTRY.smart_contract);
  assert.equal(briefSliceRegistryForProfile("unknown_profile"), null);
});

test("OSS capability packs use the oss brief profile while keeping generic evaluator spawn", () => {
  for (const packId of [
    "oss_dependency",
    "oss_native_code",
    "oss_api_schema",
    "oss_authz",
    "oss_ci_cd",
    "oss_secrets_config",
    "oss_docs_behavior",
  ]) {
    const pack = CAPABILITY_PACKS[packId];
    assert.ok(pack, `${packId} must be registered`);
    assert.equal(pack.brief_profile, "oss");
    assert.equal(pack.spawn.profile, "web");
    assert.deepEqual(pack.role_bundles, ["evaluator-shared", "evaluator-web"]);
  }
});

test("OSS_BRIEF_SLICE_REGISTRY carries the required slice keys per O-D8", () => {
  const keys = OSS_BRIEF_SLICE_REGISTRY.map((slice) => slice.key);
  const expected = [
    "repo_workflow",
    "governance",
    "goal_orientation",
    "code_surface_pack",
    "technique_packs",
    "cli_tools",
    "recap_and_handoff",
  ];
  for (const key of expected) {
    assert.ok(keys.includes(key), `OSS_BRIEF_SLICE_REGISTRY must include slice '${key}'`);
  }
  // repo_workflow must LEAD the registry (per spec: "leads the brief").
  assert.equal(keys[0], "repo_workflow", "repo_workflow must be the first slice");
});

test("repo_workflow slice fires under each OSS lens and is empty under non-OSS lenses", () => {
  const slice = OSS_BRIEF_SLICE_REGISTRY.find((s) => s.key === "repo_workflow");
  assert.ok(slice, "repo_workflow slice must exist");
  // OSS lens contexts → render the stanza.
  for (const lens of OSS_LENSES) {
    const text = slice.read({ taskLens: lens });
    assert.equal(text, REPO_WORKFLOW_TEXT, `repo_workflow must render under lens=${lens}`);
  }
  // Non-OSS lenses → empty string. The registry assembly pass drops empty
  // slices so the brief renderer does not emit an empty header.
  for (const lens of ["behavior_probe", "browser_behavior_probe", "surface_scout", null]) {
    const text = slice.read({ taskLens: lens });
    assert.equal(text, "", `repo_workflow must be empty under lens=${String(lens)}`);
  }
});

test("REPO_WORKFLOW_TEXT names the repo-bound tools and SUPPRESSES the curl-shaped HTTP playbook", () => {
  // The stanza must name each repo-bound MCP tool the evaluator should call.
  assert.match(REPO_WORKFLOW_TEXT, /bob_repo_inventory/);
  assert.match(REPO_WORKFLOW_TEXT, /bob_repo_check/);
  assert.match(REPO_WORKFLOW_TEXT, /bob_repo_docker_run/);
  // Sandbox / scope vocabulary the operator must read on first scan.
  assert.match(REPO_WORKFLOW_TEXT, /sandboxed/);
  // The curl-shaped playbook must be explicitly DE-EMPHASIZED so the
  // evaluator does not lead with HTTP probes (mirrors T.4's pattern). The
  // bob_http_scan tool name must appear under a de-emphasis stanza, not as
  // a recommended first step.
  assert.match(REPO_WORKFLOW_TEXT, /bob_http_scan/);
  assert.match(REPO_WORKFLOW_TEXT, /de-emphasized/);
});

// ── Observation kinds (4 added; payload shapes; secret leakage regression) ──

test("OSS_OBSERVATION_KIND_VALUES enumerates the four observation kinds per Cycle O.6", () => {
  assert.equal(OSS_OBSERVATION_KIND_VALUES.length, 4, "exactly four OSS observation kinds (Reviewer B parsimony)");
  assert.ok(OSS_OBSERVATION_KIND_VALUES.includes("dependency_observed"));
  assert.ok(OSS_OBSERVATION_KIND_VALUES.includes("unsafe_sink_observed"));
  assert.ok(OSS_OBSERVATION_KIND_VALUES.includes("crash_observed"));
  assert.ok(OSS_OBSERVATION_KIND_VALUES.includes("config_misuse_observed"));
  // Reviewer B: cve_signal_observed must NOT be added — it's subsumed by
  // dependency_observed.known_cve_ids[].
  assert.ok(!OSS_OBSERVATION_KIND_VALUES.includes("cve_signal_observed"));
});

test("isOssObservationKind recognises each of the four kinds", () => {
  for (const kind of OSS_OBSERVATION_KIND_VALUES) {
    assert.equal(isOssObservationKind(kind), true, `isOssObservationKind(${kind}) must be true`);
  }
  assert.equal(isOssObservationKind("jwt_observed"), false);
  assert.equal(isOssObservationKind("cve_signal_observed"), false);
});

test("dependency_observed payload accepts the required fields plus optional known_cve_ids[]", () => {
  const payload = buildOssObservationPayload("dependency_observed", {
    ecosystem: "npm",
    package: "lodash",
    version: "4.17.20",
    manifest_path: "package.json",
    has_lockfile: true,
    known_cve_ids: ["CVE-2021-23337"],
  });
  assert.equal(payload.observation_kind, "dependency_observed");
  assert.equal(payload.ecosystem, "npm");
  assert.equal(payload.package, "lodash");
  assert.equal(payload.version, "4.17.20");
  assert.equal(payload.manifest_path, "package.json");
  assert.equal(payload.has_lockfile, true);
  assert.deepEqual(payload.known_cve_ids, ["CVE-2021-23337"]);

  // Optional known_cve_ids omitted → field absent from payload (no empty array).
  const minimal = buildOssObservationPayload("dependency_observed", {
    ecosystem: "cargo",
    package: "serde",
    version: "1.0.0",
    manifest_path: "Cargo.toml",
    has_lockfile: false,
  });
  assert.equal(Object.prototype.hasOwnProperty.call(minimal, "known_cve_ids"), false);

  // Wrong shape → throws.
  assert.throws(() => buildOssObservationPayload("dependency_observed", {
    ecosystem: "npm",
    // missing package
    version: "1.0.0",
    manifest_path: "package.json",
    has_lockfile: true,
  }), /package/);
  assert.throws(() => buildOssObservationPayload("dependency_observed", {
    ecosystem: "npm",
    package: "x",
    version: "1.0.0",
    manifest_path: "package.json",
    has_lockfile: "not-a-boolean",
  }), /has_lockfile/);
});

test("unsafe_sink_observed payload requires file_path, symbol, sink_kind, language", () => {
  const payload = buildOssObservationPayload("unsafe_sink_observed", {
    file_path: "src/parser.c",
    symbol: "parse_record",
    sink_kind: "memcpy_unchecked_length",
    language: "c",
  });
  assert.equal(payload.observation_kind, "unsafe_sink_observed");
  assert.equal(payload.file_path, "src/parser.c");
  assert.equal(payload.symbol, "parse_record");
  assert.equal(payload.sink_kind, "memcpy_unchecked_length");
  assert.equal(payload.language, "c");

  assert.throws(() => buildOssObservationPayload("unsafe_sink_observed", {
    file_path: "src/parser.c",
    symbol: "",  // empty
    sink_kind: "memcpy",
    language: "c",
  }), /symbol/);
});

test("crash_observed payload requires harness, exit_code, asan_report_hash; supports optional signal + file_path", () => {
  const payload = buildOssObservationPayload("crash_observed", {
    harness: "fuzz_parse_record",
    exit_code: 1,
    signal: "SIGSEGV",
    asan_report_hash: "a".repeat(64),
    file_path: "crashes/crash-001",
  });
  assert.equal(payload.observation_kind, "crash_observed");
  assert.equal(payload.harness, "fuzz_parse_record");
  assert.equal(payload.exit_code, 1);
  assert.equal(payload.signal, "SIGSEGV");
  assert.equal(payload.asan_report_hash, "a".repeat(64));
  assert.equal(payload.file_path, "crashes/crash-001");

  // Minimal payload (no signal, no file_path).
  const minimal = buildOssObservationPayload("crash_observed", {
    harness: "fuzz_x",
    exit_code: 134,
    asan_report_hash: "b".repeat(64),
  });
  assert.equal(Object.prototype.hasOwnProperty.call(minimal, "signal"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(minimal, "file_path"), false);

  // exit_code missing → throws.
  assert.throws(() => buildOssObservationPayload("crash_observed", {
    harness: "fuzz_x",
    asan_report_hash: "c".repeat(64),
  }), /exit_code/);
});

test("config_misuse_observed payload carries file_path, key, value_hash, misuse_class", () => {
  const payload = buildOssObservationPayload("config_misuse_observed", {
    file_path: "config/production.yaml",
    key: "tls_min_version",
    value_hash: "d".repeat(64),
    misuse_class: "weak_tls_version",
  });
  assert.equal(payload.observation_kind, "config_misuse_observed");
  assert.equal(payload.file_path, "config/production.yaml");
  assert.equal(payload.key, "tls_min_version");
  assert.equal(payload.value_hash, "d".repeat(64));
  assert.equal(payload.misuse_class, "weak_tls_version");
});

test("OSS_OBSERVATION_BUILDERS exposes a builder per kind for parameterized tests", () => {
  for (const kind of OSS_OBSERVATION_KIND_VALUES) {
    assert.equal(typeof OSS_OBSERVATION_BUILDERS[kind], "function", `builder for ${kind} must be a function`);
  }
});

// ── Secret-leakage regression on observation payloads ───────────────────────

test("dependency_observed payload REJECTS a raw secret in known_cve_ids[]", () => {
  // A defender-grade test: even if a producer accidentally stuffs a bearer
  // token into the known_cve_ids[] array, the validator MUST refuse the
  // payload — no raw secret bytes can land in the frontier ledger.
  assert.throws(() => buildOssObservationPayload("dependency_observed", {
    ecosystem: "npm",
    package: "lodash",
    version: "4.17.20",
    manifest_path: "package.json",
    has_lockfile: true,
    known_cve_ids: ["CVE-2021-23337", "Authorization: Bearer abcdef1234567890"],
  }), /secret|auth|token/i);
});

test("config_misuse_observed payload REJECTS a raw secret stuffed into the value", () => {
  // The `value_hash` field carries a sha256 — never the raw value. If a
  // producer regression accidentally renames a field to `value` and passes
  // the raw bytes, sensitive-material guard MUST refuse.
  assert.throws(() => buildOssObservationPayload("config_misuse_observed", {
    file_path: "config/x.yaml",
    key: "tls_min",
    value_hash: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ",
    misuse_class: "weak_tls_version",
  }), /secret|auth|token|jwt/i);
});

test("recordOssObservation emits an observation.recorded event whose payload is scrubbed", () => {
  withTempHome(() => {
    const domain = uniqueDomain("oss-observation");
    ensureSessionDir(domain);
    const event = recordOssObservation({
      target_domain: domain,
      surface_id: "repo:dependency:package.json",
      observation_kind: "dependency_observed",
      payload: {
        ecosystem: "npm",
        package: "lodash",
        version: "4.17.20",
        manifest_path: "package.json",
        has_lockfile: true,
      },
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.observation_kind, "dependency_observed");
    assert.equal(event.payload.ecosystem, "npm");
    // Persisted to disk.
    const events = readFrontierEvents(domain);
    const matching = events.filter((e) => (
      e.kind === "observation.recorded"
      && e.payload && e.payload.observation_kind === "dependency_observed"
    ));
    assert.equal(matching.length, 1, "exactly one observation event persisted");
    // Negative regression: the raw bearer token literal MUST NOT appear in the
    // serialized event content.
    const raw = JSON.stringify(matching[0]);
    assert.ok(!/bearer /i.test(raw), "no raw bearer-token bytes may surface in the event");
  });
});

// ── Pack auto-surfacing per observation kind ────────────────────────────────

test("dependency_observed.ecosystem='cargo' surfaces cargo-audit pack", () => {
  const result = selectCliToolPacks({
    surface_fingerprint: { kind: "repo" },
    observations: [{ kind: "dependency_observed", payload: { ecosystem: "cargo" } }],
  });
  const ids = result.map((pack) => pack.id);
  assert.ok(ids.includes("cargo-audit"), "cargo-audit must surface when ecosystem === 'cargo'");
  assert.ok(!ids.includes("npm-audit"), "npm-audit must NOT surface for cargo dependency");
  assert.ok(!ids.includes("pip-audit"), "pip-audit must NOT surface for cargo dependency");
});

test("dependency_observed.ecosystem='npm' surfaces npm-audit pack", () => {
  const result = selectCliToolPacks({
    surface_fingerprint: { kind: "repo" },
    observations: [{ kind: "dependency_observed", payload: { ecosystem: "npm" } }],
  });
  const ids = result.map((pack) => pack.id);
  assert.ok(ids.includes("npm-audit"), "npm-audit must surface when ecosystem === 'npm'");
  assert.ok(!ids.includes("cargo-audit"));
});

test("dependency_observed.ecosystem='pypi' surfaces pip-audit pack", () => {
  const result = selectCliToolPacks({
    surface_fingerprint: { kind: "repo" },
    observations: [{ kind: "dependency_observed", payload: { ecosystem: "pypi" } }],
  });
  const ids = result.map((pack) => pack.id);
  assert.ok(ids.includes("pip-audit"), "pip-audit must surface when ecosystem === 'pypi'");
});

test("repo-gated static analyzers surface for every OSS repo surface (no observation required)", () => {
  // Both are always-applicable OSS packs: `surface.kind === "repo"` is the
  // only predicate. Mailing it without any observations.
  const result = selectCliToolPacks({
    surface_fingerprint: { kind: "repo" },
    observations: [],
  });
  const ids = result.map((pack) => pack.id);
  assert.ok(ids.includes("semgrep"), "semgrep must surface for every OSS surface");
  assert.ok(ids.includes("trivy"), "trivy must surface for every OSS surface");
  assert.ok(ids.includes("codeql"), "codeql must surface for every OSS surface");
  assert.ok(ids.includes("coccinelle"), "coccinelle must surface for every OSS surface");
});

test("non-repo surfaces (web / smart_contract) do NOT surface the OSS packs", () => {
  for (const kind of ["web", "smart_contract", "mail"]) {
    const result = selectCliToolPacks({
      surface_fingerprint: { kind },
      observations: [{ kind: "dependency_observed", payload: { ecosystem: "cargo" } }],
    });
    const ids = result.map((pack) => pack.id);
    assert.ok(!ids.includes("semgrep"), `semgrep must NOT surface on surface.kind=${kind}`);
    assert.ok(!ids.includes("trivy"), `trivy must NOT surface on surface.kind=${kind}`);
    assert.ok(!ids.includes("codeql"), `codeql must NOT surface on surface.kind=${kind}`);
    assert.ok(!ids.includes("coccinelle"), `coccinelle must NOT surface on surface.kind=${kind}`);
    // cargo-audit's predicate is observation-driven (not surface-driven), so it
    // still fires when the dependency_observed event names cargo. That is the
    // intentional shape — operators want the per-ecosystem audit even when
    // running on a non-OSS surface that happened to carry a dependency event.
    assert.ok(ids.includes("cargo-audit"), `cargo-audit applies based on observation, not surface (surface.kind=${kind})`);
  }
});

test("CLI_TOOL_PACKS includes the 7 OSS packs alongside the prior Plane T packs", () => {
  const ids = CLI_TOOL_PACKS.map((pack) => pack.id);
  for (const ossId of ["semgrep", "trivy", "codeql", "coccinelle", "cargo-audit", "npm-audit", "pip-audit"]) {
    assert.ok(ids.includes(ossId), `CLI_TOOL_PACKS must include ${ossId}`);
  }
  // Regression: the prior Plane T packs still ship.
  for (const priorId of ["ffuf", "arjun", "jwt-tool", "schemathesis", "graphql-cop"]) {
    assert.ok(ids.includes(priorId), `prior Plane T pack ${priorId} must still ship (regression)`);
  }
});

// ── Technique-pack content carries native-code bug-class vocabulary ─────────

test("OSS_TECHNIQUE_PACKS includes the 7 packs per Cycle O.6", () => {
  assert.equal(OSS_TECHNIQUE_PACKS.length, 7, "exactly 7 OSS technique packs");
  const ids = OSS_TECHNIQUE_PACKS.map((pack) => pack.id);
  const expected = [
    "oss_dependency",
    "oss_native_code",
    "oss_api_schema",
    "oss_authz",
    "oss_ci_cd",
    "oss_secrets_config",
    "oss_docs_behavior",
  ];
  for (const id of expected) {
    assert.ok(ids.includes(id), `OSS_TECHNIQUE_PACKS must include ${id}`);
  }
});

test("oss_native_code pack `summary` carries the full MVP bug-class vocabulary", () => {
  // Per D's carry-back: hunting vocabulary lives in pack content, not in
  // role-prompt prose. The test asserts the load-bearing terms appear so a
  // future quality-erosion regression (stripping the vocab into a generic
  // one-liner) trips the test.
  const pack = findOssTechniquePack("oss_native_code");
  assert.ok(pack, "oss_native_code pack must exist");
  assert.equal(typeof pack.summary, "string");
  const summary = pack.summary.toLowerCase();
  // Spec-required terms — keep the assertion explicit so a future doc cleanup
  // cannot accidentally strip them.
  assert.match(summary, /bounds checks/, "summary must mention 'bounds checks'");
  assert.match(summary, /double-free|use-after-free/, "summary must mention 'double-free' or 'use-after-free'");
  // Additional MVP vocabulary terms that should be present.
  assert.match(summary, /integer truncation/, "summary must mention 'integer truncation'");
  assert.match(summary, /signed\/unsigned/, "summary must mention 'signed/unsigned' conversion");
  assert.match(summary, /allocation/, "summary must mention 'allocation' math");
  assert.match(summary, /state-machine confusion/, "summary must mention 'state-machine confusion'");
  assert.match(summary, /lifetime|ownership/, "summary must mention 'lifetime' or 'ownership'");
  // NFS/XDR named-project example per spec.
  assert.match(summary, /nfs|xdr|protocol/i, "summary must reference NFS/XDR/protocol projects");
});

test("each OSS technique pack declares a lens_affinity from the OSS lens set", () => {
  for (const pack of OSS_TECHNIQUE_PACKS) {
    assert.ok(Array.isArray(pack.lens_affinity), `${pack.id}: lens_affinity must be an array`);
    assert.ok(pack.lens_affinity.length > 0, `${pack.id}: lens_affinity must be non-empty`);
    for (const lens of pack.lens_affinity) {
      assert.ok(OSS_LENSES.includes(lens), `${pack.id}: lens_affinity ${lens} must be one of the OSS lenses`);
    }
  }
});

test("OSS technique-pack content carries the spec-required hunting vocabulary per pack", () => {
  const pack = (id) => findOssTechniquePack(id);
  assert.match(pack("oss_dependency").summary, /lockfile drift|vendored fork|transitive dependency/i);
  assert.match(pack("oss_api_schema").summary, /openapi|graphql/i);
  assert.match(pack("oss_authz").summary, /decorator|middleware|idor/i);
  assert.match(pack("oss_ci_cd").summary, /pull_request_target|github_token/i);
  assert.match(pack("oss_secrets_config").summary, /committed|weak crypto|debug flag|\.env/i);
  assert.match(pack("oss_docs_behavior").summary, /docs claim|rate.?limit/i);
});

test("OSS brief technique_packs slice names root-cause families for native-code lenses", () => {
  const extras = buildBriefExtrasForProfile("oss", {
    domain: "repo-oss-family-slice",
    surface: {
      id: "repo:module:src-parser.c",
      title: "src/parser.c",
      surface_type: "oss_native_code",
      file_path: "src/parser.c",
      language: "c",
      bug_class_hints: ["length_field", "bound_check_site"],
    },
    assignment: {
      surface_id: "repo:module:src-parser.c",
      task_lens: "taint_trace",
    },
    routeMetadata: {
      capability_pack: "oss_native_code",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      context_budget: {
        candidate_pack_limit: 5,
        full_pack_read_limit: 2,
        attempt_log_required: true,
      },
    },
  });

  assert.ok(extras.technique_packs.root_cause_families.length > 0);
  const familyNames = extras.technique_packs.root_cause_families.map((family) => family.family);
  assert.ok(familyNames.includes("validate_vs_consume"));
  assert.ok(familyNames.includes("crypto_ordering"));
  assert.equal(extras.technique_packs.root_cause_family_limits.unmatched_lens, false);
});

test("OSS brief omits native root-cause families for non-native surfaces", () => {
  const extras = buildBriefExtrasForProfile("oss", {
    domain: "repo-oss-family-ci",
    surface: {
      id: "repo:workflow:ci",
      title: ".github/workflows/test.yml",
      surface_type: "oss_ci_cd",
      file_path: ".github/workflows/test.yml",
      language: "yaml",
      bug_class_hints: ["pull_request_target", "github_token"],
    },
    assignment: {
      surface_id: "repo:workflow:ci",
      task_lens: "code_surface_scout",
    },
    routeMetadata: {
      capability_pack: "oss_ci_cd",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      context_budget: {
        candidate_pack_limit: 5,
        full_pack_read_limit: 2,
        attempt_log_required: true,
      },
    },
  });

  assert.ok(extras.technique_packs.selected.some((pack) => pack.id === "oss_ci_cd"));
  assert.deepEqual(extras.technique_packs.root_cause_families, []);
  assert.deepEqual(extras.technique_packs.root_cause_family_limits, {
    lens: "code_surface_scout",
    family_count: 0,
    unmatched_lens: false,
    item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
    limit: 0,
    returned: 0,
  });
});

// ── Technique-pack id alias resolves ────────────────────────────────────────

test("OSS_TECHNIQUE_PACK_ID_ALIASES carries the legacy/hyphenated id forms", () => {
  // The MVP shipped under longer descriptive ids; the alias map preserves the
  // id-typo recovery wisdom. Pin a few load-bearing aliases.
  assert.equal(OSS_TECHNIQUE_PACK_ID_ALIASES["oss-native-code-c-parser-review"], "oss_native_code");
  assert.equal(OSS_TECHNIQUE_PACK_ID_ALIASES["oss-native-code-protocol-memory"], "oss_native_code");
  assert.equal(OSS_TECHNIQUE_PACK_ID_ALIASES["oss-native-code"], "oss_native_code");
});

test("resolveOssTechniquePackId resolves canonical ids and legacy aliases alike", () => {
  // Canonical ids round-trip.
  for (const pack of OSS_TECHNIQUE_PACKS) {
    assert.equal(resolveOssTechniquePackId(pack.id), pack.id, `canonical ${pack.id} must round-trip`);
  }
  // Legacy aliases resolve to the canonical id.
  assert.equal(resolveOssTechniquePackId("oss-native-code-c-parser-review"), "oss_native_code");
  assert.equal(resolveOssTechniquePackId("oss-native-code-protocol-memory"), "oss_native_code");
  assert.equal(resolveOssTechniquePackId("oss-dependency"), "oss_dependency");
  // Unknown id resolves to null (rather than throwing — callers may want to
  // probe the alias map without try/catch).
  assert.equal(resolveOssTechniquePackId("not_a_real_pack"), null);
  assert.equal(resolveOssTechniquePackId(""), null);
  assert.equal(resolveOssTechniquePackId(null), null);
});

test("findOssTechniquePack returns the same pack for both the canonical id and its aliases", () => {
  const canonical = findOssTechniquePack("oss_native_code");
  const viaLegacyId = findOssTechniquePack("oss-native-code-c-parser-review");
  const viaProtocolAlias = findOssTechniquePack("oss-native-code-protocol-memory");
  assert.ok(canonical, "canonical pack must exist");
  assert.equal(viaLegacyId, canonical, "alias must resolve to the canonical pack object");
  assert.equal(viaProtocolAlias, canonical, "protocol alias must resolve to the canonical pack object");
});

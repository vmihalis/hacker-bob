"use strict";

const os = require("os");
const path = require("path");
const {
  HARNESS_ID_RE,
  SEED_CORPUS_ID_RE,
  SESSION_LOCK_NAME,
  STATIC_ARTIFACT_ID_RE,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertNonEmptyString,
} = require("./validation.js");

function assertSafeDomain(domain) {
  const trimmed = assertNonEmptyString(domain, "target_domain");
  if (/[\/\\]/.test(trimmed) || /(?:^|\.)\.\.(?:\.|$)/.test(trimmed)) {
    throw new Error(`target_domain contains invalid path characters: ${trimmed}`);
  }
  return trimmed;
}

function sessionDir(domain) {
  const safe = assertSafeDomain(domain);
  return path.join(sessionsRoot(), safe);
}

// bob_init_session (lab-target-attest.recordLabAuthorization) when the operator
// attests ownership of a loopback/RFC1918 target. Audit-graded (see
// AUDIT_GRADED_BASENAMES) so an agent cannot forge it via the Write tool to
// self-grant a private-target scan. The scope kernel reads it to permit the
// otherwise-rejected private target_domain.
function labAuthorizationPath(domain) {
  return path.join(sessionDir(domain), "lab-authorization.json");
}

// Canonical session root. Cycle P.2 of the frontier-topology realization
// hypergraph moves the session root from `~/bounty-agent-sessions` to
// `~/hacker-bob-sessions`. Per Risk R6, the legacy root is *preserved*: it is
// still resolvable as a read-fallback (so sessions created before the
// migration remain readable), and the migration shim copies — never moves —
// legacy session directories into the canonical location. The destructive
// purge is gated behind the explicit `--purge-legacy-session-root` flag and
// is reserved for v2.1.0.
function sessionsRoot() {
  return path.join(os.homedir(), "hacker-bob-sessions");
}

function legacySessionsRoot() {
  return path.join(os.homedir(), "bounty-agent-sessions");
}

const TELEMETRY_DIR_NAME = "bounty-agent-telemetry";
const TELEMETRY_TOOL_INVOCATIONS_FILE_NAME = "tool-invocations.jsonl";

function telemetryDir(env = process.env) {
  const override = typeof env.BOUNTY_TELEMETRY_DIR === "string"
    ? env.BOUNTY_TELEMETRY_DIR.trim()
    : "";
  return override ? path.resolve(override) : path.join(os.homedir(), TELEMETRY_DIR_NAME);
}

function telemetryToolInvocationsJsonlPath(env = process.env) {
  return path.join(telemetryDir(env), TELEMETRY_TOOL_INVOCATIONS_FILE_NAME);
}


function statePath(domain) {
  return path.join(sessionDir(domain), "state.json");
}

function attackSurfacePath(domain) {
  return path.join(sessionDir(domain), "attack_surface.json");
}

function surfaceLeadsPath(domain) {
  return path.join(sessionDir(domain), "surface-leads.json");
}

function surfaceRoutesPath(domain) {
  return path.join(sessionDir(domain), "surface-routes.json");
}

function sessionLockPath(domain) {
  return path.join(sessionDir(domain), SESSION_LOCK_NAME);
}

function waveAssignmentsPath(domain, waveNumber) {
  return path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
}

function liveDeadEndsJsonlPath(domain, wave, agent) {
  return path.join(sessionDir(domain), `live-dead-ends-${wave}-${agent}.jsonl`);
}

function handoffSigningKeyPath(domain) {
  return path.join(sessionDir(domain), ".handoff-signing-key.json");
}

function scopeWarningsPath(domain) {
  return path.join(sessionDir(domain), "scope-warnings.log");
}

function coverageJsonlPath(domain) {
  return path.join(sessionDir(domain), "coverage.jsonl");
}

function techniqueAttemptsJsonlPath(domain) {
  return path.join(sessionDir(domain), "technique-attempts.jsonl");
}

function techniquePackReadsJsonlPath(domain) {
  return path.join(sessionDir(domain), "technique-pack-reads.jsonl");
}

function chainAttemptsJsonlPath(domain) {
  return path.join(sessionDir(domain), "chain-attempts.jsonl");
}

function pipelineEventsJsonlPath(domain) {
  return path.join(sessionDir(domain), "pipeline-events.jsonl");
}

function frontierEventsJsonlPath(domain) {
  return path.join(sessionDir(domain), "frontier-events.jsonl");
}

function compositionResultsJsonlPath(domain) {
  return path.join(sessionDir(domain), "composition-results.jsonl");
}

// SC1 confirm-half live-verifier ledger. Written ONLY by
// bob_verify_composition_path (composition-live-verifier.js) and audit-graded
// below so agents cannot Write-forge a verified_pass — SC1 is graded on this
// ledger's verified_pass count, never on a forgeable frontier event.
function compositionVerifiedJsonlPath(domain) {
  return path.join(sessionDir(domain), "composition-verified.jsonl");
}

// OSS native-code reproduction-gate ledger. Written ONLY by
// bob_verify_repro_reproduction (repro-replay-verifier.js) and audit-graded below,
// so a verified_pass cannot be hand-forged via the Write tool — the O-P4 claim gate
// requires a verified_pass that only the differential re-execution tool can mint.
function reproVerifiedJsonlPath(domain) {
  return path.join(sessionDir(domain), "repro-verified.jsonl");
}

// FV-confirm ledger. Written ONLY by bob_verify_invariant_differential
// (invariant-runner.js::verifyInvariantDifferential) and audit-graded below, so an
// FV verified_pass cannot be hand-forged via the Write tool. The proof-bundle gate
// requires a VERIFIED_PASS record here whose positive/control run hashes match the
// bundle's invariant artifact — a bare single-run pass can no longer mint verified.
function invariantVerifiedJsonlPath(domain) {
  return path.join(sessionDir(domain), "invariant-verified.jsonl");
}

// Web-standalone finding-differential ledger. Written ONLY by
// bob_verify_finding_differential (finding-differential-verifier.js) and
// audit-graded below, so a verified_pass cannot be hand-forged via the Write
// tool. The grade-time gate for standalone non-oracle reportable findings
// (auth-bypass, IDOR, SSRF, business-logic, info-disclosure, races) requires a
// VERIFIED_PASS record here bound by finding_id whose positive/control run hashes
// flip on the SAME surface — a bare single declared row no longer mints verified.
function findingDifferentialVerifiedJsonlPath(domain) {
  return path.join(sessionDir(domain), "finding-differential-verified.jsonl");
}

function sessionNucleusPath(domain) {
  return path.join(sessionDir(domain), "session-nucleus.json");
}

function sessionEventsJsonlPath(domain) {
  return path.join(sessionDir(domain), "session-events.jsonl");
}

function surfaceIndexPath(domain) {
  return path.join(sessionDir(domain), "surface-index.json");
}

function taskQueuePath(domain) {
  return path.join(sessionDir(domain), "task-queue.json");
}

// Plane X Cycle X.2 — task-graph.json materialized view. Lives alongside
// surface-index.json + task-queue.json under the session root. Folded from
// frontier-events.jsonl by mcp/lib/task-graph-materializer.js on every
// producer-event session-lock release (via frontier-materialize-debounce).
function taskGraphPath(domain) {
  return path.join(sessionDir(domain), "task-graph.json");
}

function queuePolicyPath(domain) {
  return path.join(sessionDir(domain), "queue-policy.json");
}

function agentRunsJsonlPath(domain) {
  return path.join(sessionDir(domain), "agent-runs.jsonl");
}

function schedulerDecisionsJsonlPath(domain) {
  return path.join(sessionDir(domain), "scheduler-decisions.jsonl");
}

// CN (coverage-nesting) Step B — the MCP-owned spawn ledger. An append JSONL the
// MCP server writes at the mutating dispatch step (one row per emitted nesting
// envelope), NEVER on the read-brief path. It is the detective audit of how much
// of the session spawn budget has been handed out; the read-path bounder reads its
// total to cap the next plan's width. HOOK_MCP_OWNED so the write-guard fences the
// evaluator-fanout Bash/Write channel (the spawner holds Bash for OSS harness work).
function spawnLedgerJsonlPath(domain) {
  return path.join(sessionDir(domain), "spawn-ledger.jsonl");
}

function claimsJsonlPath(domain) {
  return path.join(sessionDir(domain), "claims.jsonl");
}

function claimClustersJsonlPath(domain) {
  return path.join(sessionDir(domain), "claim-clusters.jsonl");
}

function claimFreezePath(domain) {
  return path.join(sessionDir(domain), "claim-freeze.json");
}

function reportSnapshotsJsonlPath(domain) {
  return path.join(sessionDir(domain), "report-snapshots.jsonl");
}

function httpAuditJsonlPath(domain) {
  return path.join(sessionDir(domain), "http-audit.jsonl");
}

function trafficJsonlPath(domain) {
  return path.join(sessionDir(domain), "traffic.jsonl");
}

function publicIntelPath(domain) {
  return path.join(sessionDir(domain), "public-intel.json");
}

function bobSpecPath(domain) {
  return path.join(sessionDir(domain), "bob-spec.json");
}

function assertStaticArtifactId(artifactId) {
  const normalized = assertNonEmptyString(artifactId, "artifact_id");
  if (!STATIC_ARTIFACT_ID_RE.test(normalized)) {
    throw new Error("artifact_id must match SA-N");
  }
  return normalized;
}

function staticArtifactImportDir(domain) {
  return path.join(sessionDir(domain), "static-imports");
}

function staticArtifactPath(domain, artifactId) {
  return path.join(staticArtifactImportDir(domain), `${assertStaticArtifactId(artifactId)}.txt`);
}

function staticArtifactsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-artifacts.jsonl");
}

// Imported fuzz harnesses (bob_import_harness). Session-owned scratch, MCP-write-only
// (the agent Write tool is fenced from harnesses/ — provenance flows only through the
// tool). NOT audit-graded. Stored as .cc so the recipe's harness discovery treats it
// as a C++ TU (works for both c and cpp harnesses).
function assertHarnessId(harnessId) {
  const normalized = assertNonEmptyString(harnessId, "harness_id");
  if (!HARNESS_ID_RE.test(normalized)) {
    throw new Error("harness_id must match H-N");
  }
  return normalized;
}

function harnessImportDir(domain) {
  return path.join(sessionDir(domain), "harnesses");
}

function harnessPath(domain, harnessId) {
  return path.join(harnessImportDir(domain), `${assertHarnessId(harnessId)}.cc`);
}

function harnessesJsonlPath(domain) {
  return path.join(sessionDir(domain), "harnesses.jsonl");
}

// Imported grammar-generated seed corpora (bob_import_seed_corpus). Session-owned
// scratch, MCP-write-only (agent Write fenced; provenance flows only through the tool).
// NOT audit-graded. One import -> seed-corpus/<SC-N>/ holding many raw seed files.
function assertSeedCorpusId(corpusId) {
  const normalized = assertNonEmptyString(corpusId, "corpus_id");
  if (!SEED_CORPUS_ID_RE.test(normalized)) {
    throw new Error("corpus_id must match SC-N");
  }
  return normalized;
}

function seedCorpusDir(domain) {
  return path.join(sessionDir(domain), "seed-corpus");
}

function seedCorpusEntryDir(domain, corpusId) {
  return path.join(seedCorpusDir(domain), assertSeedCorpusId(corpusId));
}

function seedCorpusJsonlPath(domain) {
  return path.join(sessionDir(domain), "seed-corpus.jsonl");
}

function schemaContractsJsonlPath(domain) {
  return path.join(sessionDir(domain), "schema-contracts.jsonl");
}

function docDeltaResultsPath(domain) {
  return path.join(sessionDir(domain), "doc-delta-results.json");
}

function authDifferentialResultsPath(domain) {
  return path.join(sessionDir(domain), "auth-differential-results.json");
}

function evmRoleTableResultsPath(domain) {
  return path.join(sessionDir(domain), "evm-role-table-results.json");
}

function surfaceGraphJsonlPath(domain) {
  return path.join(sessionDir(domain), "surface-graph.jsonl");
}

function beliefScratchDir(domain) {
  return path.join(sessionDir(domain), "belief-scratch");
}

function beliefSignalsJsonlPath(domain) {
  return path.join(beliefScratchDir(domain), "belief-signals.jsonl");
}

function beliefSamplesJsonlPath(domain) {
  return path.join(beliefScratchDir(domain), "belief-samples.jsonl");
}

function beliefModelInfoPath(domain) {
  return path.join(beliefScratchDir(domain), "belief-model-info.json");
}

function chainTreeJsonlPath(domain) {
  return path.join(sessionDir(domain), "chain-tree.jsonl");
}

function auditReportsJsonlPath(domain) {
  return path.join(sessionDir(domain), "audit-reports.jsonl");
}

// The per-session registry of advisory candidate mechanism templates. MCP-owned
// (written only by bob_register_mechanism_template) but explicitly NOT
// audit-graded: a candidate is tier-3 advisory data that ranks/seeds attention
// and re-verifies on every reuse, never a verdict. Agent-readable, MCP-write-only.
function mechanismCandidatesJsonlPath(domain) {
  return path.join(sessionDir(domain), "mechanism-candidates.jsonl");
}

function invariantRunsJsonlPath(domain) {
  return path.join(sessionDir(domain), "invariant-runs.jsonl");
}

function symbolSurfaceIndexPath(domain) {
  return path.join(sessionDir(domain), "symbol-surface-index.json");
}

function staticScanResultsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-scan-results.jsonl");
}

function staticAnalysisResultsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-analysis-results.jsonl");
}

function staticAnalysisIndexPath(domain) {
  return path.join(sessionDir(domain), "static-analysis-index.jsonl");
}

function verificationRoundPaths(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  const fileNames = VERIFICATION_ROUND_FILE_MAP[normalizedRound];
  const dir = sessionDir(domain);
  return {
    round: normalizedRound,
    json: path.join(dir, fileNames.json),
    markdown: path.join(dir, fileNames.markdown),
  };
}

function gradeArtifactPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "grade.json"),
    markdown: path.join(dir, "grade.md"),
  };
}

function evidencePackPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "evidence-packs.json"),
    markdown: path.join(dir, "evidence-packs.md"),
  };
}

function proofBundlePaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "proof-bundles.json"),
    markdown: path.join(dir, "proof-bundles.md"),
  };
}

function verificationSnapshotPath(domain) {
  return path.join(sessionDir(domain), "verification-input-snapshot.json");
}

function verificationAdjudicationPath(domain) {
  return path.join(sessionDir(domain), "verification-adjudication.json");
}

function verificationManifestPath(domain) {
  return path.join(sessionDir(domain), "verification-manifest.json");
}

function verificationAttemptsDir(domain) {
  return path.join(sessionDir(domain), "verification-attempts");
}

function verificationReplayLeaseDir(domain) {
  return path.join(sessionDir(domain), "verification-replay-leases");
}

// Staging area for finding-keyed verification-round partials. Each per-finding
// worker writes ONE file here (filename = sha256(round:finding_id)); the server
// unions all partials into the single round document at commit time. This dir is
// scratch, not audit-graded — the committed round document remains the only
// MCP-owned audit-graded round artifact (verificationRoundPaths).
function verificationRoundPartialDir(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  return path.join(sessionDir(domain), "verification-round-partials", normalizedRound);
}

function reportMarkdownPath(domain) {
  return path.join(sessionDir(domain), "report.md");
}

// Y.3 Stage c — chains.md is now MCP-rendered alongside chain-attempts.jsonl.
// Authored by `bob_write_chain_rollup`; agents no longer Write here directly.
function chainsMarkdownPath(domain) {
  return path.join(sessionDir(domain), "chains.md");
}

// Y.3 Stage c — append-only operator-amendment ledger backing
// `bob_amend_report` (Y-P13a). Each line: {section_id, new_prose, rationale,
// timestamp, operator_attestation?}.
function reportAmendmentsJsonlPath(domain) {
  return path.join(sessionDir(domain), "report-amendments.jsonl");
}

// Cycle O.2: repo-inventory.json is materialized by bob_repo_inventory.
// Lives alongside attack_surface.json so the same target_domain key
// addresses both web and OSS surface-axis projections.
function repoInventoryPath(domain) {
  return path.join(sessionDir(domain), "repo-inventory.json");
}

// Operator-attested lab/private-target authorization. Written ONCE by
// bob_init_session (lab-target-attest.recordLabAuthorization) when the operator
// attests ownership of a loopback/RFC1918 target. Audit-graded (see
// AUDIT_GRADED_BASENAMES) so an agent cannot forge it via the Write tool to
// self-grant a private-target scan. The scope kernel reads it to permit the
// otherwise-rejected private target_domain.
function labAuthorizationPath(domain) {
  return path.join(sessionDir(domain), "lab-authorization.json");
}

// Cycle O.S4 — diff-impact.json is written by bob_summarize_diff_impact after
// diff impact analysis. Records which files/line-ranges were touched by the
// diff and which surface IDs they map to. This is MCP-owned; agents MUST NOT
// write it directly via the Write tool.
function diffImpactPath(domain) {
  return path.join(sessionDir(domain), "diff-impact.json");
}

// Cycle O.4: repo-command-runs.jsonl is the append-only run ledger for
// bob_repo_docker_run. Each entry carries the run id, command hash, exit
// code, duration, network/mount/image identity, and the on-disk paths to
// stdout/stderr capture files. NEVER carries raw stdout/stderr content.
function repoCommandRunsJsonlPath(domain) {
  return path.join(sessionDir(domain), "repo-command-runs.jsonl");
}

// Offensive proof ledger for safe web exploit attempts. This mirrors
// repo-command-runs.jsonl as an append-only MCP-owned ledger, but is
// audit-graded because exploit proof rows become the un-fakeable claim gate.
function offensiveRunsJsonlPath(domain) {
  return path.join(sessionDir(domain), "offensive-runs.jsonl");
}

// Raw request/response capture files for bob_http_confirm. These are
// read-guarded because they can contain target bytes and synthetic proof
// material; rows in offensive-runs.jsonl carry only paths and hashes.
function offensiveRunsDir(domain) {
  return path.join(sessionDir(domain), "offensive-runs");
}

// PR6 OOB collector — the token->surface binding ledger. AUDIT-GRADED (see
// AUDIT_GRADED_BASENAMES): each row binds a server-minted OOB token to the
// in-scope canonical_target + surface_id resolved at mint time, and bob_oob_poll
// re-reads it to stamp the signed row's target/surface, so an agent Write here
// would be the OOB analogue of the #111 cross-surface laundering vector.
function oobTokensJsonlPath(domain) {
  return path.join(sessionDir(domain), "oob-tokens.jsonl");
}

// Cycle O.4: repo-runs/<run_id>.{stdout,stderr} are the bounded (16 MB
// each) capture files for each docker run. Lives under sessionDir so
// session-read-guard.sh can extend BLOCKED_DIRS to it in cycle O.7.
function repoRunsDir(domain) {
  return path.join(sessionDir(domain), "repo-runs");
}

// Cycle O.4: per-session writable area mounted at /work inside the
// container. Stays out of /src (read-only mount of the bound repo).
function repoWorkDir(domain) {
  return path.join(sessionDir(domain), "repo-work");
}

// Cycle O.4/S14: host-materialized differential checkouts mounted as
// /src:ro. Kept outside repo-work so the writable /work bind never aliases
// the control tree.
function repoCheckoutDir(domain) {
  return path.join(sessionDir(domain), "repo-checkouts");
}

// Cycle O.5: repo-checks.jsonl is the append-only read-only evidence-probe
// ledger written by bob_repo_check. Each entry carries the check id, the
// probed file path, the optional literal/regex pattern, the match result,
// matched-line excerpts (REDACTED per O-P7 before they land here), and the
// file content hash for downstream EvidenceReference binding (cycle O.8).
function repoChecksJsonlPath(domain) {
  return path.join(sessionDir(domain), "repo-checks.jsonl");
}

function repoEnvPath(domain) {
  return path.join(sessionDir(domain), "repo-env.json");
}

function repoDockerfilePath(domain) {
  return path.join(sessionDir(domain), "Dockerfile.bob");
}

// Y.3 Stage b — Y-P13 audit-graded path registry.
//
// An *audit-graded session path* is one whose content is hash-bound, immutable,
// or chain-anchored. Agents NEVER call the Write tool on these paths. MCP
// renders them server-side via `bob_compose_report` (report.md),
// `bob_write_chain_rollup` (chains.md), `bob_write_evidence_packs`
// (evidence-packs.md), `bob_write_grade_verdict` (grade.md),
// `bob_write_verification_round` (verification-round mirrors), and
// `bob_write_wave_handoff` (wave-handoff mirrors). Y.9 subtest D-2 runs a
// mechanical negative-grep that fails CI on any agent Write whose absolute
// path matches `isAuditGradedPath(file_path, target_domain)`.
//
// Scratch artifacts (subdomains.txt, attack_surface.json, family_seeds.txt,
// surface-discovery-tools.txt, plus the entire static-imports/ tree) are
// explicitly NOT audit-graded and remain agent-writable. The positive-list
// model means: every new hash-bound or chain-anchored artifact MUST be added
// here to inherit Y-P13 enforcement. Y-R22 acknowledgement: this scope is
// intentionally narrower than the conceptual class; expansion lives in future
// Plane Z if scratch ever becomes audit-graded.
//
// Each entry is either a fixed basename (matched against `path.basename`) or a
// directory prefix (matched against relative path under sessionDir). The
// renderer-bound prefixes cover:
//   * verification-attempts/<file>  — round JSON + markdown mirrors
//   * verification-replay-leases/   — replay lease snapshots
//   * verification-input-snapshot   — frozen verifier input
//   * Plus any future hash-bound artifact added to AUDIT_GRADED_PATHS.
const AUDIT_GRADED_BASENAMES = Object.freeze([
  // Operator-attested lab/private-target authorization. MCP-write-only (written
  // only by bob_init_session) so a prompt-injected agent cannot forge it via the
  // Write tool to self-grant a loopback/RFC1918 scan past the public-DNS gate.
  "lab-authorization.json",
  "report.md",
  "chains.md",
  "evidence-packs.md",
  "evidence-packs.json",
  "proof-bundles.md",
  "proof-bundles.json",
  "grade.md",
  "grade.json",
  "claim-freeze.json",
  "verification-manifest.json",
  "verification-input-snapshot.json",
  "verification-adjudication.json",
  "report-snapshots.jsonl",
  "report-amendments.jsonl",
  "chain-attempts.jsonl",
  // SC1 confirm-half: the live-verifier's verified_pass ledger. MCP-write-only so
  // a verified_pass cannot be hand-forged via the Write tool; SC1 grades on it.
  "composition-verified.jsonl",
  // OSS native-code reproduction-gate: the differential verified_pass ledger.
  // MCP-write-only so a reproduction verdict cannot be hand-forged; the O-P4
  // claim gate grades on it.
  "repro-verified.jsonl",
  // FV-confirm: the invariant differential verified_pass ledger. MCP-write-only
  // so an FV verified_pass cannot be hand-forged; the proof-bundle invariant gate
  // grades on it (a bare single-run pass no longer mints verified).
  "invariant-verified.jsonl",
  // Web-standalone finding-differential verified_pass ledger. MCP-write-only so a
  // standalone-class verdict cannot be hand-forged; the grade-time gate for
  // residual reportable findings (auth-bypass/IDOR/SSRF/business-logic/info-
  // disclosure/races) grades on it. A verdict mints verified ONLY when a flipping
  // negative control bound to the finding_id resolves an executed positive.
  "finding-differential-verified.jsonl",
  // Deliberate asymmetry: repo-command-runs.jsonl is MCP-owned but not
  // audit-graded; offensive-runs.jsonl is both because exploit-proof claims
  // are structurally rejected unless backed by a real row in this ledger.
  "offensive-runs.jsonl",
  // PR6: the OOB token->surface binding ledger. Audit-graded because bob_oob_poll
  // re-reads it to stamp the signed row's in-scope target + surface_id; an agent
  // Write would forge that binding (the OOB analogue of the #111 surface gate). The
  // ledger READ is additionally O_NOFOLLOW/realpath-hardened in oob-collector.js so
  // a Bash-planted symlink cannot smuggle a binding either.
  "oob-tokens.jsonl",
  "diff-impact.json",
  // Verification-round mirrors live at the session root with fixed names.
  "brutalist.json",
  "brutalist.md",
  "balanced.json",
  "balanced.md",
  "verified-final.json",
  "verified-final.md",
]);

const AUDIT_GRADED_RELATIVE_DIRS = Object.freeze([
  "verification-attempts",
  "verification-replay-leases",
  "wave-handoffs",
  "claim-freeze",
  "offensive-runs",
]);

// Wave-handoff per-agent files live at the session root and follow the
// pattern `handoff-w<N>-a<N>.json` / `.md`. Match the prefix mechanically so
// future renaming (e.g., wave-handoffs/ subdirectory) inherits the registry
// automatically.
const AUDIT_GRADED_FILENAME_PATTERNS = Object.freeze([
  /^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.json$/,
  /^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.md$/,
]);

const AUDIT_GRADED_PATHS = Object.freeze({
  basenames: AUDIT_GRADED_BASENAMES,
  relative_dirs: AUDIT_GRADED_RELATIVE_DIRS,
  filename_patterns: AUDIT_GRADED_FILENAME_PATTERNS,
});

// CR-2: single source of truth for the external PreToolUse write-guard hooks
// (.claude/hooks/session-write-guard.sh and adapters/kimi/hooks/session-write-guard.sh).
// The hooks MUST NOT hand-maintain their own classification tables; they read
// the rendered projection produced by scripts/generate-write-guard-tables.js,
// which is asserted equal to this data by `npm run test:prompts`.
//
// Three sets, evaluated in this precedence inside the hook:
//   1. AUDIT_GRADED  -> block (MCP renders these server-side; never agent Write)
//   2. MCP_OWNED     -> block (structured state the agent must write via MCP tools)
//   3. AGENT_WRITABLE-> allow (compact scratch / discovery / report-input)
//   default          -> block (unknown file in session dir)
//
// report.md and chains.md are DELIBERATELY ABSENT from AGENT_WRITABLE: they are
// in AUDIT_GRADED_BASENAMES (MCP-rendered via bob_compose_report /
// bob_write_chain_rollup). Listing them as agent-writable was the classification
// contradiction this registry closes.
//
// SCOPE: the audit_graded_* sub-sets below are re-exported BY REFERENCE from
// AUDIT_GRADED_PATHS, so a new audit-graded basename/pattern/dir is closed
// automatically. HOOK_MCP_OWNED_BASENAMES is a HAND-MAINTAINED list, but it is
// no longer allowed to drift from the path-function inventory: every basename a
// session-root path function in this file produces must classify into exactly
// one write-guard class, and `scripts/check-mcp-owned-basename-inventory.js`
// (wired into `npm run test:prompts`) fails on any unclassified basename. A new
// MCP-owned path function therefore turns the inventory check RED until its
// basename is added here (or to an MCP-owned dir/pattern), closing both the
// hand-maintained drift and the `*.txt`-before-MCP-owned precedence gap.
const HOOK_MCP_OWNED_BASENAMES = Object.freeze([
  "state.json",
  "coverage.jsonl",
  "technique-attempts.jsonl",
  "technique-pack-reads.jsonl",
  "findings.jsonl",
  "findings.md",
  "SESSION_HANDOFF.md",
  "auth.json",
  "http-audit.jsonl",
  "traffic.jsonl",
  "public-intel.json",
  "Dockerfile.bob",
  "repo-checks.jsonl",
  "repo-command-runs.jsonl",
  "repo-env.json",
  "repo-inventory.json",
  "surface-routes.json",
  "static-artifacts.jsonl",
  "harnesses.jsonl",
  "seed-corpus.jsonl",
  "static-analysis-results.jsonl",
  "static-analysis-index.jsonl",
  "static-scan-results.jsonl",
  "pipeline-events.jsonl",
  ".handoff-signing-key.json",
  // T8 inventory closure — MCP-owned session-root artifacts the path-function
  // inventory produces. These were silently relying on the default-block; now
  // they are explicitly MCP-owned so the inventory check is closed against the
  // resolver set (and so none is shadowed by the agent-writable *.txt allow).
  ".session.lock",
  "session-nucleus.json",
  "session-events.jsonl",
  "bob-spec.json",
  "queue-policy.json",
  "task-queue.json",
  "task-graph.json",
  "surface-index.json",
  "symbol-surface-index.json",
  "surface-leads.json",
  "surface-graph.jsonl",
  "agent-runs.jsonl",
  "scheduler-decisions.jsonl",
  "frontier-events.jsonl",
  "composition-results.jsonl",
  "claims.jsonl",
  "claim-clusters.jsonl",
  "chain-tree.jsonl",
  "audit-reports.jsonl",
  // Advisory tier-3 candidate-mechanism registry. MCP-write-only (an agent Write
  // is blocked) but NOT audit-graded — it carries leads that re-verify on reuse,
  // never a hash-bound verdict the grader reads.
  "mechanism-candidates.jsonl",
  "invariant-runs.jsonl",
  "schema-contracts.jsonl",
  "doc-delta-results.json",
  "auth-differential-results.json",
  "evm-role-table-results.json",
  "spawn-ledger.jsonl",
]);
// NB: brutalist/balanced/verified-final/evidence-packs/grade/chain-attempts/
// diff-impact are intentionally NOT repeated here — they are already in
// AUDIT_GRADED_BASENAMES and enter the BLOCK set via audit_graded_basenames.
// Repeating them would re-introduce drift; the class test asserts the two sets
// are disjoint, so an accidental duplicate is caught.

// MCP-owned by basename-pattern (per-wave artifacts at the session root).
const HOOK_MCP_OWNED_FILENAME_PATTERNS = Object.freeze([
  /^wave-[0-9]+-assignments\.json$/,
  /^live-dead-ends-w[0-9]+-a[0-9]+\.jsonl$/,
  // handoff-w<N>-a<N>.json|md is already covered by AUDIT_GRADED_FILENAME_PATTERNS.
]);

// Whole directories that are MCP-owned regardless of filename (matched by
// session-RELATIVE path component, same as MCP_OWNED_DIRS in the hook today).
// T8 inventory closure: belief-scratch (MCP-internal belief outputs, written
// only by the belief samplers), and repo-runs / repo-work / repo-checkouts
// (docker-run capture + S14 control checkouts, already read-blocked by the
// session-read-guard) are MCP-owned dirs so their contents are classified by
// dir and the inventory check is closed against the path-function inventory.
const HOOK_MCP_OWNED_DIRS = Object.freeze([
  "static-imports",
  "harnesses",
  "seed-corpus",
  "belief-scratch",
  "repo-runs",
  "repo-work",
  "repo-checkouts",
  // Finding-keyed verification-round partial staging. MCP-owned (write-fenced
  // from agents) NOT because the partials are audit-graded — they are not; the
  // committed round document is the only audit-graded artifact — but because a
  // partial is unioned verbatim into that round at commit, so a forgeable
  // worker-Write here would poison the audit-graded union. The server stages
  // each partial via stageVerificationRoundPartial (validated + attempt-bound).
  "verification-round-partials",
]);

// Compact scratch / discovery / report-INPUT artifacts the agent may Write.
// report.md and chains.md are NOT here — they are audit-graded.
const HOOK_AGENT_WRITABLE_BASENAMES = Object.freeze([
  "attack_surface.json",
  "deep-summary.json",
  "surface-discovery-summary.json",
  // Agent-written on-chain inventory: the deep-surface-discovery agent (which
  // has Write but not bob_record_surface_leads) builds this scratch input during
  // collection; step-7 reads it to synthesize smart_contract surfaces/leads.
  // Like attack_surface.json it is agent scratch, not MCP-owned state.
  "onchain_inventory.json",
  "scope-warnings.log",
  "deny-list.txt",
]);

const HOOK_AGENT_WRITABLE_FILENAME_PATTERNS = Object.freeze([
  /^.*\.txt$/,
]);

// The projection both the generator and any in-process guard consume. The
// audit-graded sets are re-exported by reference so a new audit-graded basename
// automatically becomes a hook BLOCK with no second edit. regex `.source` is
// exported (string form) so the JSON manifest is serializable and the Python
// hooks can compile identical patterns.
const WRITE_GUARD_TABLES = Object.freeze({
  // BLOCK precedence 1: audit-graded (MCP-rendered). Reuses AUDIT_GRADED_PATHS.
  audit_graded_basenames: AUDIT_GRADED_BASENAMES,
  audit_graded_filename_patterns: AUDIT_GRADED_FILENAME_PATTERNS.map((re) => re.source),
  audit_graded_relative_dirs: AUDIT_GRADED_RELATIVE_DIRS,
  // BLOCK precedence 2: MCP-owned structured state.
  mcp_owned_basenames: HOOK_MCP_OWNED_BASENAMES,
  mcp_owned_filename_patterns: HOOK_MCP_OWNED_FILENAME_PATTERNS.map((re) => re.source),
  mcp_owned_dirs: HOOK_MCP_OWNED_DIRS,
  // ALLOW precedence 3: agent-writable scratch.
  agent_writable_basenames: HOOK_AGENT_WRITABLE_BASENAMES,
  agent_writable_filename_patterns: HOOK_AGENT_WRITABLE_FILENAME_PATTERNS.map((re) => re.source),
});

// Y.3 Stage c (Y-P14b / O4) — threshold above which a cited response body MUST
// be bound to an MCP-owned import handle (`bob_import_http_traffic`,
// `bob_resolve_body`, or `bob_static_scan`) rather than referenced as a raw
// `evidence/<path>` string. Consumers:
//   * `mcp/lib/tools/write-chain-rollup.js` `evidence_refs[]` validator
//   * `mcp/lib/friction-scanners.js` `large_response_body_unimported` scanner
// Threshold value is committed here so callers import a single constant; no
// duplicated literals across validator + scanner.
const LARGE_BODY_THRESHOLD_BYTES = 262144;

// Y.3 Stage c (Y-P14b / O4) — resolve a relative `evidence/<path>` reference
// against the session directory. Returns an absolute path; throws ToolError-
// equivalent guard if the reference would escape the session root. Callers are
// expected to wrap in their own error envelope.
function resolveEvidencePath(domain, evidenceRef) {
  const root = sessionDir(domain);
  const normalizedRoot = path.resolve(root);
  const resolved = path.resolve(normalizedRoot, evidenceRef);
  if (resolved !== normalizedRoot && !resolved.startsWith(`${normalizedRoot}${path.sep}`)) {
    throw new Error(`evidence reference '${evidenceRef}' escapes session root`);
  }
  return resolved;
}

// Predicate consumed by:
//   * `belief/authority.js` via assertAgentWriteAllowed (Y-P13, fail-closed
//     in-process). This guards MCP-INTERNAL writes only (belief outputs + the
//     audit-graded composers) as defense-in-depth; it is NOT on the harness
//     agent Write tool path. The harness Write tool is fenced by the PreToolUse
//     hook (.claude/hooks/session-write-guard.sh), which is rendered from
//     WRITE_GUARD_TABLES — hook↔paths agreement is enforced by
//     `npm run check:write-guard-tables`. An in-process predicate cannot survive
//     a stripped hook for agent Write; the hook is that enforcement surface.
//   * `_write-base.js` for the FLAG↔WHITELIST closure on MCP-composer specs.
//   * `scripts/check-single-spawner-topology` Y-P13d frontmatter guard (Y.8)
//   * Y.9 subtest D-2 mechanical negative-grep
//
// Returns true if `absolutePath` lives under the session root for
// `target_domain` AND matches a known audit-graded basename, directory prefix,
// or filename pattern. Scratch paths return false. Non-session paths return
// false (defensive — the predicate is session-scoped).
function isAuditGradedPath(absolutePath, target_domain) {
  if (typeof absolutePath !== "string" || !absolutePath) return false;
  if (typeof target_domain !== "string" || !target_domain) return false;
  let root;
  try {
    root = sessionDir(target_domain);
  } catch {
    return false;
  }
  const normalized = path.resolve(absolutePath);
  const normalizedRoot = path.resolve(root);
  if (!normalized.startsWith(`${normalizedRoot}${path.sep}`) && normalized !== normalizedRoot) {
    return false;
  }
  const rel = path.relative(normalizedRoot, normalized);
  if (!rel || rel.startsWith("..")) return false;
  const basename = path.basename(normalized);
  if (AUDIT_GRADED_BASENAMES.includes(basename)) return true;
  for (const pattern of AUDIT_GRADED_FILENAME_PATTERNS) {
    if (pattern.test(basename)) return true;
  }
  for (const prefix of AUDIT_GRADED_RELATIVE_DIRS) {
    if (rel === prefix || rel.startsWith(`${prefix}${path.sep}`)) return true;
  }
  return false;
}

// Y-P13 (T4) — MCP-composer whitelist. The ONLY tool names permitted to emit an
// audit-graded path through an in-process write decision. Every entry MUST
// correspond to a wrapWriteTool() spec that sets `writes_audit_graded: true`.
// This registry is closed by two legs: (1) the FLAG↔WHITELIST bijection
// (auditGradedWriterClosure + the wrap-time throws in _write-base.js), and
// (2) the GROUND-TRUTH anchor in scripts/check-audit-graded-writers.js, which
// independently derives the writer set from the audit-graded path helpers each
// caller reaches and asserts equality with this list.
const AUDIT_GRADED_WRITER_TOOLS = Object.freeze([
  "bob_write_verification_round",
  "bob_write_evidence_packs",
  "bob_write_grade_verdict",
  "bob_write_wave_handoff",
  "bob_write_chain_attempt",
  "bob_finalize_report",
  "bob_compose_report",
  "bob_write_chain_rollup",
  "bob_amend_report",
  "bob_write_proof_bundle",
]);

// Y-P13 (T4) — alias→canonical. Six audit-graded writers ship a `bounty_*`
// alias; a caller identity arriving under an alias normalizes to its canonical
// name before the whitelist membership check, so an alias-dispatch is not
// falsely denied. (amend/compose/chain-rollup/finalize have no alias.)
const AUDIT_GRADED_WRITER_ALIASES = Object.freeze({
  bounty_write_verification_round: "bob_write_verification_round",
  bounty_write_evidence_packs: "bob_write_evidence_packs",
  bounty_write_grade_verdict: "bob_write_grade_verdict",
  bounty_write_wave_handoff: "bob_write_wave_handoff",
  bounty_write_chain_attempt: "bob_write_chain_attempt",
  bounty_write_proof_bundle: "bob_write_proof_bundle",
});

function canonicalWriterName(toolName) {
  if (toolName == null) return null;
  return AUDIT_GRADED_WRITER_ALIASES[toolName] || toolName;
}

// Y-P13 (T4) — in-process fail-closed audit-graded write predicate. Throws when
// a NON-whitelisted caller targets an audit-graded path. `callerToolName ===
// null` denotes a write with no MCP composer identity (e.g. belief outputs) and
// is ALWAYS rejected for an audit-graded target — the fail-closed default. A
// whitelisted MCP composer (canonical or alias) is allowed through.
//
// SCOPE (honest): this predicate guards IN-PROCESS / MCP-INTERNAL writes only
// (belief outputs and the audit-graded composers) as defense-in-depth. It is
// NOT on the harness agent Write tool path — that tool is intercepted only by
// the PreToolUse hook (.claude/hooks/session-write-guard.sh), which runs in a
// separate process and is rendered from WRITE_GUARD_TABLES (agreement enforced
// by `npm run check:write-guard-tables`). T4 does NOT make audit-graded
// enforcement survive a stripped hook for agent Write; the hook is that surface.
//
// Returns the resolved absolute path on success (mirrors assertBeliefScratch
// WritePath's return contract). Throws Error on denial; callers wrap in their
// own ToolError envelope.
function assertAgentWriteAllowed(absolutePath, target_domain, callerToolName = null) {
  if (typeof absolutePath !== "string" || !absolutePath) {
    throw new Error("assertAgentWriteAllowed requires an absolute file path");
  }
  const resolved = path.resolve(absolutePath);
  if (!isAuditGradedPath(resolved, target_domain)) {
    // Not an audit-graded target — no gate applies here.
    return resolved;
  }
  const canonical = canonicalWriterName(callerToolName);
  if (canonical != null && AUDIT_GRADED_WRITER_TOOLS.includes(canonical)) {
    return resolved;
  }
  throw new Error(
    `audit-graded path '${path.basename(resolved)}' is MCP-composer-owned (Y-P13); ` +
    `the Write tool and non-whitelisted callers cannot write it. ` +
    `Use the owning bob_* composer instead.`,
  );
}

// Y-P13 (T4) — FLAG↔WHITELIST closure leg for AUDIT_GRADED_WRITER_TOOLS. Given
// the set of wrapWriteTool specs that declare writes_audit_graded:true, asserts
// a bijection with AUDIT_GRADED_WRITER_TOOLS: no whitelisted name lacks a
// declaring spec (orphan), and no declaring spec is missing from the whitelist
// (undeclared). This is the internal-consistency leg ONLY; the ground-truth
// anchor is scripts/check-audit-graded-writers.js.
function auditGradedWriterClosure(declaredWriterNames) {
  const declared = new Set(declaredWriterNames);
  const whitelisted = new Set(AUDIT_GRADED_WRITER_TOOLS);
  const orphans = [...whitelisted].filter((n) => !declared.has(n));
  const undeclared = [...declared].filter((n) => !whitelisted.has(n));
  return { ok: orphans.length === 0 && undeclared.length === 0, orphans, undeclared };
}

// T8 (CR-2) — session-root path-function inventory. Source of truth for
// `scripts/check-mcp-owned-basename-inventory.js`, which classifies every
// session-root path a resolver produces and fails on any that is not in exactly
// one write-guard class. Keeping the resolver enumeration here (rather than in
// the check script) makes it registry-driven: a NEW exported *Path/*Paths/*Dir/
// *Jsonl* resolver is picked up automatically, so its basename must be
// classified or the inventory check goes RED.

// Constant dummy domain — deterministic, no Date/random. The probe wave/agent/
// round/artifact tokens are constants so the produced basenames are stable.
const INVENTORY_PROBE_DOMAIN = "example.com";

// Resolvers that DO NOT produce a session-root path (homedir telemetry roots,
// path predicates that take an absolute path, the session root itself). They are
// excluded from the inventory by name so the enumeration is explicit, not
// best-effort.
const SESSION_ROOT_NON_INVENTORY_RESOLVERS = Object.freeze([
  "sessionDir",
  "sessionsRoot",
  "legacySessionsRoot",
  "telemetryDir",
  "telemetryToolInvocationsJsonlPath",
  "isAuditGradedPath",
  "resolveEvidencePath",
]);

// Resolvers with arity > 1: the extra args needed to produce a concrete path.
// Dynamic-token resolvers (handoff/live-dead-ends/wave-assignments) get tokens
// that exercise the per-wave/agent filename patterns. verificationRoundPaths
// fans out over every round value.
const SESSION_ROOT_RESOLVER_EXTRA_ARGS = Object.freeze({
  liveDeadEndsJsonlPath: ["w1", "a3"],
  staticArtifactPath: ["SA-1"],
  harnessPath: ["H-1"],
  seedCorpusEntryDir: ["SC-1"],
  waveAssignmentsPath: [1],
  // Per-round partial staging dir takes a round enum; probe one round so the
  // inventory classifies the path by its MCP-owned parent dir membership.
  verificationRoundPartialDir: ["brutalist"],
});

// Returns every session-root path a resolver in this module produces, as
// { resolver, abs } records. `verificationRoundPaths` fans out over all rounds.
// Resolvers returning an object (`*Paths`) contribute each string value.
function sessionRootPathInventory(domain = INVENTORY_PROBE_DOMAIN) {
  const records = [];
  const isResolverName = (n) => /Path$|Paths$|Dir$/.test(n) || /Jsonl/.test(n);
  const push = (resolver, value) => {
    if (typeof value === "string" && value) records.push({ resolver, abs: value });
  };
  for (const [name, fn] of Object.entries(module.exports)) {
    if (typeof fn !== "function") continue;
    if (!isResolverName(name)) continue;
    if (SESSION_ROOT_NON_INVENTORY_RESOLVERS.includes(name)) continue;
    if (name === "verificationRoundPaths") {
      for (const round of VERIFICATION_ROUND_VALUES) {
        const out = fn(domain, round);
        // `out.round` is the round label, not a path — only json/markdown are paths.
        push(name, out.json);
        push(name, out.markdown);
      }
      continue;
    }
    const extra = SESSION_ROOT_RESOLVER_EXTRA_ARGS[name] || [];
    const out = fn(domain, ...extra);
    if (typeof out === "string") push(name, out);
    else if (out && typeof out === "object") for (const v of Object.values(out)) push(name, v);
  }
  return records;
}

module.exports = {
  INVENTORY_PROBE_DOMAIN,
  SESSION_ROOT_NON_INVENTORY_RESOLVERS,
  SESSION_ROOT_RESOLVER_EXTRA_ARGS,
  sessionRootPathInventory,
  AUDIT_GRADED_PATHS,
  AUDIT_GRADED_WRITER_TOOLS,
  AUDIT_GRADED_WRITER_ALIASES,
  canonicalWriterName,
  assertAgentWriteAllowed,
  auditGradedWriterClosure,
  WRITE_GUARD_TABLES,
  LARGE_BODY_THRESHOLD_BYTES,
  TELEMETRY_DIR_NAME,
  TELEMETRY_TOOL_INVOCATIONS_FILE_NAME,
  assertHarnessId,
  assertSeedCorpusId,
  assertSafeDomain,
  assertStaticArtifactId,
  attackSurfacePath,
  beliefScratchDir,
  beliefModelInfoPath,
  beliefSamplesJsonlPath,
  beliefSignalsJsonlPath,
  bobSpecPath,
  chainAttemptsJsonlPath,
  chainsMarkdownPath,
  coverageJsonlPath,
  evidencePackPaths,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  liveDeadEndsJsonlPath,
  pipelineEventsJsonlPath,
  proofBundlePaths,
  publicIntelPath,
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  oobTokensJsonlPath,
  queuePolicyPath,
  reportMarkdownPath,
  resolveEvidencePath,
  repoChecksJsonlPath,
  repoCommandRunsJsonlPath,
  repoCheckoutDir,
  repoDockerfilePath,
  repoEnvPath,
  repoInventoryPath,
  labAuthorizationPath,
  repoRunsDir,
  repoWorkDir,
  scopeWarningsPath,
  labAuthorizationPath,
  sessionDir,
  sessionEventsJsonlPath,
  sessionLockPath,
  sessionNucleusPath,
  sessionsRoot,
  statePath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  handoffSigningKeyPath,
  auditReportsJsonlPath,
  mechanismCandidatesJsonlPath,
  authDifferentialResultsPath,
  evmRoleTableResultsPath,
  agentRunsJsonlPath,
  diffImpactPath,
  chainTreeJsonlPath,
  claimClustersJsonlPath,
  claimFreezePath,
  claimsJsonlPath,
  compositionResultsJsonlPath,
  compositionVerifiedJsonlPath,
  reproVerifiedJsonlPath,
  docDeltaResultsPath,
  frontierEventsJsonlPath,
  invariantRunsJsonlPath,
  invariantVerifiedJsonlPath,
  findingDifferentialVerifiedJsonlPath,
  isAuditGradedPath,
  legacySessionsRoot,
  reportAmendmentsJsonlPath,
  reportSnapshotsJsonlPath,
  schedulerDecisionsJsonlPath,
  schemaContractsJsonlPath,
  spawnLedgerJsonlPath,
  surfaceIndexPath,
  surfaceGraphJsonlPath,
  symbolSurfaceIndexPath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  harnessImportDir,
  harnessPath,
  harnessesJsonlPath,
  seedCorpusDir,
  seedCorpusEntryDir,
  seedCorpusJsonlPath,
  staticAnalysisIndexPath,
  staticAnalysisResultsJsonlPath,
  staticScanResultsJsonlPath,
  taskGraphPath,
  taskQueuePath,
  telemetryDir,
  telemetryToolInvocationsJsonlPath,
  trafficJsonlPath,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationManifestPath,
  verificationReplayLeaseDir,
  verificationRoundPartialDir,
  verificationRoundPaths,
  verificationSnapshotPath,
  waveAssignmentsPath,
};

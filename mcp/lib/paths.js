"use strict";

const os = require("os");
const path = require("path");
const {
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

function schemaContractsJsonlPath(domain) {
  return path.join(sessionDir(domain), "schema-contracts.jsonl");
}

function docDeltaResultsPath(domain) {
  return path.join(sessionDir(domain), "doc-delta-results.json");
}

function authDifferentialResultsPath(domain) {
  return path.join(sessionDir(domain), "auth-differential-results.json");
}

function surfaceGraphJsonlPath(domain) {
  return path.join(sessionDir(domain), "surface-graph.jsonl");
}

function chainTreeJsonlPath(domain) {
  return path.join(sessionDir(domain), "chain-tree.jsonl");
}

function auditReportsJsonlPath(domain) {
  return path.join(sessionDir(domain), "audit-reports.jsonl");
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
//   * `_write-base.js` for defense-in-depth (future use)
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

module.exports = {
  AUDIT_GRADED_PATHS,
  LARGE_BODY_THRESHOLD_BYTES,
  TELEMETRY_DIR_NAME,
  TELEMETRY_TOOL_INVOCATIONS_FILE_NAME,
  assertSafeDomain,
  assertStaticArtifactId,
  attackSurfacePath,
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
  queuePolicyPath,
  reportMarkdownPath,
  resolveEvidencePath,
  repoChecksJsonlPath,
  repoCommandRunsJsonlPath,
  repoCheckoutDir,
  repoDockerfilePath,
  repoEnvPath,
  repoInventoryPath,
  repoRunsDir,
  repoWorkDir,
  scopeWarningsPath,
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
  authDifferentialResultsPath,
  agentRunsJsonlPath,
  diffImpactPath,
  chainTreeJsonlPath,
  claimClustersJsonlPath,
  claimFreezePath,
  claimsJsonlPath,
  docDeltaResultsPath,
  frontierEventsJsonlPath,
  invariantRunsJsonlPath,
  isAuditGradedPath,
  legacySessionsRoot,
  reportAmendmentsJsonlPath,
  reportSnapshotsJsonlPath,
  schedulerDecisionsJsonlPath,
  schemaContractsJsonlPath,
  surfaceIndexPath,
  surfaceGraphJsonlPath,
  symbolSurfaceIndexPath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
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
  verificationRoundPaths,
  verificationSnapshotPath,
  waveAssignmentsPath,
};

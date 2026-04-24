#!/usr/bin/env node
// Bounty Agent MCP Server facade — tool registry, public exports, and CLI startup
// Provides: bounty_http_scan, bounty_record_finding, bounty_read_findings,
//           bounty_list_findings, bounty_write_verification_round,
//           bounty_read_verification_round, bounty_write_grade_verdict,
//           bounty_read_grade_verdict, bounty_init_session,
//           bounty_read_session_state, bounty_read_state_summary,
//           bounty_transition_phase,
//           bounty_start_wave, bounty_apply_wave_merge,
//           bounty_write_handoff, bounty_write_wave_handoff,
//           bounty_wave_handoff_status, bounty_merge_wave_handoffs,
//           bounty_read_handoff, bounty_log_dead_ends, bounty_log_coverage,
//           bounty_auth_manual, bounty_wave_status,
//           bounty_temp_email, bounty_signup_detect, bounty_auth_store,
//           bounty_auto_signup, bounty_import_http_traffic,
//           bounty_read_http_audit, bounty_public_intel,
//           bounty_import_static_artifact, bounty_static_scan

const { redactUrlSensitiveValues } = require("./redaction.js");
const {
  bountyPublicIntel,
  executeTool,
  importStaticArtifact,
  importHttpTraffic,
  readHttpAudit,
  staticScan,
} = require("./lib/dispatch.js");
const { startStdioServer } = require("./lib/transport.js");
const {
  SESSION_LOCK_STALE_MS,
} = require("./lib/constants.js");
const { normalizeStringArray } = require("./lib/validation.js");
const {
  assertSafeDomain,
  attackSurfacePath,
  coverageJsonlPath,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  publicIntelPath,
  sessionDir,
  sessionLockPath,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScanResultsJsonlPath,
  trafficJsonlPath,
  verificationRoundPaths,
} = require("./lib/paths.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("./lib/storage.js");
const {
  compactSessionState,
  initSession,
  normalizeSessionStateDocument,
  readSessionState,
  readStateSummary,
  transitionPhase,
} = require("./lib/session-state.js");
const {
  buildCoverageSummaryForSurface,
  computeCoverageRequeueSurfaceIds,
  logCoverage,
  normalizeCoverageRecord,
  readCoverageRecordsFromJsonl,
} = require("./lib/coverage.js");
const {
  buildCircuitBreakerSummary,
  normalizeHttpAuditRecord,
  normalizeTrafficRecord,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
} = require("./lib/http-records.js");
const {
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
  summarizeStaticScanHints,
} = require("./lib/static-artifacts.js");
const { validateScanUrl } = require("./lib/url-surface.js");
const {
  listFindings,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeVerificationRoundDocument,
  readFindings,
  readFindingsFromJsonl,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  summarizeFindings,
  writeGradeVerdict,
  writeVerificationRound,
} = require("./lib/findings.js");
const {
  rankAttackSurfaces,
} = require("./lib/ranking.js");
const {
  filterExclusionsByHosts,
  readScopeExclusions,
} = require("./lib/scope.js");
const {
  readHunterBrief,
  resolveHunterKnowledge,
} = require("./lib/hunter-brief.js");
const {
  authManual,
  authStore,
  buildHeaderProfile,
  migrateAuthJson,
  readAuthJson,
  resolveAuthJsonPath,
} = require("./lib/auth.js");
const { tempEmail } = require("./lib/temp-email.js");
const {
  autoSignup,
  signupDetect,
} = require("./lib/signup.js");
const {
  applyWaveMerge,
  logDeadEnds,
  mergeWaveHandoffs,
  readHandoff,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
} = require("./lib/waves.js");

const { TOOLS } = require("./lib/tool-definitions.js");

function startServer() {
  startStdioServer({ tools: TOOLS, executeTool });
}

module.exports = {
  TOOLS,
  SESSION_LOCK_STALE_MS,
  assertSafeDomain,
  validateScanUrl,
  attackSurfacePath,
  appendJsonlLine,
  applyWaveMerge,
  autoSignup,
  authStore,
  buildHeaderProfile,
  buildCoverageSummaryForSurface,
  buildCircuitBreakerSummary,
  computeCoverageRequeueSurfaceIds,
  coverageJsonlPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  importStaticArtifact,
  importHttpTraffic,
  initSession,
  listFindings,
  logCoverage,
  mergeWaveHandoffs,
  migrateAuthJson,
  normalizeCoverageRecord,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeHttpAuditRecord,
  normalizeSessionStateDocument,
  normalizeTrafficRecord,
  publicIntelPath,
  bountyPublicIntel,
  readAuthJson,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScan,
  staticScanResultsJsonlPath,
  startWave,
  findingsJsonlPath,
  findingsMarkdownPath,
  trafficJsonlPath,
  readFindings,
  readCoverageRecordsFromJsonl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
  readTrafficRecordsFromJsonl,
  readFindingsFromJsonl,
  redactUrlSensitiveValues,
  filterExclusionsByHosts,
  readHunterBrief,
  rankAttackSurfaces,
  resolveHunterKnowledge,
  readGradeVerdict,
  readScopeExclusions,
  readSessionState,
  readStateSummary,
  compactSessionState,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  signupDetect,
  summarizeStaticScanHints,
  summarizeFindings,
  tempEmail,
  transitionPhase,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  normalizeStringArray,
  writeFileAtomic,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}

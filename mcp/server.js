#!/usr/bin/env node
// Hacker Bob MCP server facade - tool registry, public exports, and CLI startup
// Provides: bounty_http_scan, bounty_record_finding, bounty_read_findings,
//           bounty_list_findings, bounty_write_verification_round,
//           bounty_read_verification_round, bounty_write_grade_verdict,
//           bounty_read_grade_verdict, bounty_init_session,
//           bounty_read_session_state, bounty_read_state_summary,
//           bounty_transition_phase,
//           bounty_start_wave, bounty_apply_wave_merge,
//           bounty_write_handoff, bounty_write_wave_handoff,
//           bounty_finalize_hunter_run, bounty_wave_handoff_status,
//           bounty_merge_wave_handoffs, bounty_log_dead_ends, bounty_log_coverage,
//           bounty_wave_status,
//           bounty_temp_email, bounty_signup_detect, bounty_auth_store,
//           bounty_auto_signup, bounty_import_http_traffic,
//           bounty_read_http_audit, bounty_public_intel,
//           bounty_import_static_artifact, bounty_static_scan,
//           bounty_list_auth_profiles, bounty_read_wave_handoffs,
//           bounty_write_chain_attempt, bounty_read_chain_attempts,
//           bounty_write_evidence_packs, bounty_read_evidence_packs,
//           bounty_read_tool_telemetry, bounty_read_pipeline_analytics,
//           bounty_record_surface_leads, bounty_read_surface_leads,
//           bounty_read_session_summary, bounty_set_operator_note,
//           bounty_clear_operator_note,
//           bounty_promote_surface_leads, bounty_route_surfaces,
//           bounty_get_context_budget, bounty_select_technique_packs,
//           bounty_read_technique_pack, bounty_log_technique_attempt

const { redactUrlSensitiveValues } = require("./redaction.js");
const {
  executeTool,
} = require("./lib/dispatch.js");
const {
  importHttpTraffic,
} = require("./lib/tools/import-http-traffic.js");
const {
  bountyPublicIntel,
} = require("./lib/tools/public-intel.js");
const {
  importStaticArtifact,
} = require("./lib/tools/import-static-artifact.js");
const {
  readHttpAudit,
} = require("./lib/tools/read-http-audit.js");
const {
  staticScan,
} = require("./lib/tools/static-scan.js");
const {
  TOOL_MANIFEST,
  TOOLS,
} = require("./lib/tool-registry.js");
const { startStdioServer } = require("./lib/transport.js");
const {
  SESSION_LOCK_STALE_MS,
} = require("./lib/constants.js");
const { normalizeStringArray } = require("./lib/validation.js");
const {
  assertSafeDomain,
  attackSurfacePath,
  chainAttemptsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  pipelineEventsJsonlPath,
  publicIntelPath,
  reportMarkdownPath,
  sessionDir,
  sessionLockPath,
  sessionsRoot,
  statePath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
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
  clearOperatorNote,
  clearTerminalBlock,
  initSession,
  normalizeSessionStateDocument,
  readSessionState,
  reportWritten,
  setOperatorNote,
  readStateSummary,
  transitionPhase,
} = require("./lib/session-state.js");
const {
  readSessionSummary,
} = require("./lib/session-summary.js");
const {
  routeSurfaces,
} = require("./lib/surface-router.js");
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
  normalizeEvidencePacksDocument,
  readEvidencePacks,
  renderEvidencePacksMarkdown,
  writeEvidencePacks,
} = require("./lib/evidence.js");
const {
  readChainAttempts,
  readChainAttemptsFromJsonl,
  writeChainAttempt,
} = require("./lib/chain-attempts.js");
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
  getContextBudget,
} = require("./lib/context-budget.js");
const {
  loadTechniqueRegistry,
  logTechniqueAttempt,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackReadRecordsFromJsonl,
  selectTechniquePacks,
} = require("./lib/technique-packs.js");
const {
  authStore,
  buildHeaderProfile,
  listAuthProfiles,
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
  finalizeHunterRun,
} = require("./lib/hunter-completion.js");
const {
  applyWaveMerge,
  logDeadEnds,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
} = require("./lib/waves.js");
const {
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
} = require("./lib/pipeline-analytics.js");
const {
  promoteSurfaceLeads,
  readSurfaceLeads,
  recordSurfaceLeads,
} = require("./lib/surface-leads.js");

function startServer() {
  startStdioServer({ tools: TOOLS, executeTool });
}

module.exports = {
  TOOLS,
  TOOL_MANIFEST,
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
  chainAttemptsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  gradeArtifactPaths,
  getContextBudget,
  httpAuditJsonlPath,
  importStaticArtifact,
  importHttpTraffic,
  initSession,
  listFindings,
  listAuthProfiles,
  loadTechniqueRegistry,
  logCoverage,
  logTechniqueAttempt,
  mergeWaveHandoffs,
  migrateAuthJson,
  normalizeCoverageRecord,
  normalizeEvidencePacksDocument,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeHttpAuditRecord,
  normalizeSessionStateDocument,
  normalizeTrafficRecord,
  pipelineEventsJsonlPath,
  publicIntelPath,
  bountyPublicIntel,
  readAuthJson,
  readChainAttempts,
  readChainAttemptsFromJsonl,
  readEvidencePacks,
  resolveAuthJsonPath,
  reportMarkdownPath,
  routeSurfaces,
  sessionDir,
  sessionLockPath,
  sessionsRoot,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScan,
  staticScanResultsJsonlPath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
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
  readPipelineAnalytics,
  readPipelineEvents,
  readSurfaceLeads,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackReadRecordsFromJsonl,
  readWaveHandoffs,
  rankAttackSurfaces,
  resolveHunterKnowledge,
  readGradeVerdict,
  readScopeExclusions,
  readSessionArtifactSummary,
  readSessionState,
  readSessionSummary,
  readStateSummary,
  setOperatorNote,
  selectTechniquePacks,
  compactSessionState,
  readVerificationRound,
  recordFinding,
  recordSurfaceLeads,
  renderEvidencePacksMarkdown,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  signupDetect,
  summarizeStaticScanHints,
  summarizeFindings,
  promoteSurfaceLeads,
  tempEmail,
  transitionPhase,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeEvidencePacks,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  normalizeStringArray,
  writeFileAtomic,
  writeChainAttempt,
  clearOperatorNote,
  clearTerminalBlock,
  reportWritten,
  executeTool,
  finalizeHunterRun,
  startServer,
};

if (require.main === module) {
  startServer();
}

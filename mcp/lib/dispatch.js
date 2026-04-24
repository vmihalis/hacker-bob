const {
  importHttpTraffic: importHttpTrafficRecords,
  readHttpAudit: readHttpAuditRecordsTool,
} = require("./http-records.js");
const { httpScan } = require("./http-scan.js");
const { bountyPublicIntel: bountyPublicIntelTool } = require("./public-intel.js");
const { readAttackSurfaceStrict } = require("./attack-surface.js");
const { rankAttackSurfaces } = require("./ranking.js");
const {
  authManual,
  authStore,
} = require("./auth.js");
const {
  listFindings,
  readFindings,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  writeGradeVerdict,
  writeVerificationRound,
} = require("./findings.js");
const {
  initSession,
  readSessionState,
  readStateSummary,
  transitionPhase,
} = require("./session-state.js");
const { logCoverage } = require("./coverage.js");
const { tempEmail } = require("./temp-email.js");
const {
  autoSignup,
  signupDetect,
} = require("./signup.js");
const { readHunterBrief } = require("./hunter-brief.js");
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
} = require("./waves.js");

function importHttpTraffic(args) {
  return importHttpTrafficRecords(args, { rankAttackSurfaces });
}

function readHttpAudit(args) {
  return readHttpAuditRecordsTool(args, { readAttackSurfaceStrict });
}

async function bountyPublicIntel(args) {
  return bountyPublicIntelTool(args, { rankAttackSurfaces });
}

const TOOL_HANDLERS = Object.freeze({
  bounty_http_scan: httpScan,
  bounty_record_finding: recordFinding,
  bounty_read_findings: readFindings,
  bounty_list_findings: listFindings,
  bounty_write_verification_round: writeVerificationRound,
  bounty_read_verification_round: readVerificationRound,
  bounty_write_grade_verdict: writeGradeVerdict,
  bounty_read_grade_verdict: readGradeVerdict,
  bounty_init_session: initSession,
  bounty_read_session_state: readSessionState,
  bounty_read_state_summary: readStateSummary,
  bounty_transition_phase: transitionPhase,
  bounty_start_wave: startWave,
  bounty_apply_wave_merge: applyWaveMerge,
  bounty_write_handoff: writeHandoff,
  bounty_log_dead_ends: logDeadEnds,
  bounty_log_coverage: logCoverage,
  bounty_write_wave_handoff: writeWaveHandoff,
  bounty_wave_handoff_status: waveHandoffStatus,
  bounty_merge_wave_handoffs: mergeWaveHandoffs,
  bounty_read_handoff: readHandoff,
  bounty_auth_manual: authManual,
  bounty_wave_status: waveStatus,
  bounty_import_http_traffic: importHttpTraffic,
  bounty_read_http_audit: readHttpAudit,
  bounty_public_intel: bountyPublicIntel,
  bounty_temp_email: tempEmail,
  bounty_signup_detect: signupDetect,
  bounty_auth_store: authStore,
  bounty_auto_signup: autoSignup,
  bounty_read_hunter_brief: readHunterBrief,
});

async function executeTool(name, args) {
  const handler = TOOL_HANDLERS[name];
  if (!handler) {
    return JSON.stringify({ error: `Unknown tool: ${name}` });
  }

  return handler(args);
}

module.exports = {
  TOOL_HANDLERS,
  bountyPublicIntel,
  executeTool,
  importHttpTraffic,
  readHttpAudit,
};

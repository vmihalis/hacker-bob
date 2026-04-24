"use strict";

const FINDING_ID_RE = /^F-([1-9]\d*)$/;
const WAVE_ID_RE = /^w([1-9]\d*)$/;
const AGENT_ID_RE = /^a([1-9]\d*)$/;

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
const PHASE_VALUES = ["RECON", "AUTH", "HUNT", "CHAIN", "VERIFY", "GRADE", "REPORT", "EXPLORE"];
const AUTH_STATUS_VALUES = ["pending", "authenticated", "unauthenticated"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];
const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const GRADE_VERDICT_VALUES = ["SUBMIT", "HOLD", "SKIP"];

const COVERAGE_STATUS_VALUES = ["tested", "blocked", "promising", "needs_auth", "requeue"];
const COVERAGE_UNFINISHED_STATUS_VALUES = ["promising", "needs_auth", "requeue"];
const COVERAGE_SUMMARY_MAX_ITEMS = 40;
const COVERAGE_LOG_MAX_RECORDS = 5_000;
const HTTP_AUDIT_SUMMARY_MAX_ITEMS = 40;
const HTTP_AUDIT_LOG_MAX_RECORDS = 5_000;
const TRAFFIC_SUMMARY_MAX_ITEMS = 40;
const TRAFFIC_IMPORT_MAX_ENTRIES = 500;
const TRAFFIC_LOG_MAX_RECORDS = 5_000;
const PUBLIC_INTEL_MAX_ITEMS = 10;
const STATIC_ARTIFACT_ID_RE = /^SA-([1-9]\d*)$/;
const STATIC_ARTIFACT_TYPE_VALUES = ["evm_token_contract", "solana_token_contract"];
const STATIC_ARTIFACT_MAX_CHARS = 200_000;
const STATIC_ARTIFACT_LOG_MAX_RECORDS = 500;
const STATIC_SCAN_RESULTS_MAX_RECORDS = 1_000;
const STATIC_SCAN_FINDING_MAX_ITEMS = 100;
const STATIC_SCAN_HINT_MAX_ITEMS = 10;
const CIRCUIT_BREAKER_THRESHOLD = 3;

const SESSION_LOCK_NAME = ".session.lock";
const SESSION_LOCK_STALE_MS = 300_000;
const SESSION_PUBLIC_STATE_FIELDS = [
  "target",
  "target_url",
  "phase",
  "hunt_wave",
  "pending_wave",
  "total_findings",
  "explored",
  "dead_ends",
  "waf_blocked_endpoints",
  "lead_surface_ids",
  "scope_exclusions",
  "hold_count",
  "auth_status",
];

const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "balanced.json", markdown: "balanced.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

module.exports = {
  AGENT_ID_RE,
  AUTH_STATUS_VALUES,
  CIRCUIT_BREAKER_THRESHOLD,
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
  FINDING_ID_RE,
  GRADE_VERDICT_VALUES,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  HTTP_AUDIT_SUMMARY_MAX_ITEMS,
  PHASE_VALUES,
  PUBLIC_INTEL_MAX_ITEMS,
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
  SESSION_PUBLIC_STATE_FIELDS,
  SEVERITY_VALUES,
  STATIC_ARTIFACT_ID_RE,
  STATIC_ARTIFACT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  STATIC_ARTIFACT_TYPE_VALUES,
  STATIC_SCAN_FINDING_MAX_ITEMS,
  STATIC_SCAN_HINT_MAX_ITEMS,
  STATIC_SCAN_RESULTS_MAX_RECORDS,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
  TRAFFIC_SUMMARY_MAX_ITEMS,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
  WAVE_ID_RE,
};

"use strict";

const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const VERIFICATION_CONFIDENCE_VALUES = ["high", "medium", "low"];
const VERIFICATION_CONFIDENCE_REASON_VALUES = [
  "fresh_replay_passed",
  "auth_expired",
  "tooling_blocked",
  "state_changed",
  "manual_inference",
  "roast_disagreement",
  "disambiguation_failed",
  "agreement_not_replayed",
  "unruled_confounder",
  "missing_control",
  "exploit_replay_confirmed",
];
const VERIFICATION_REASONING_DIVERGENCE_VALUES = [
  "none",
  "artifact_key_divergence",
  "artifact_hash_divergence",
];
const VERIFICATION_REPLAY_PURPOSE_VALUES = ["verification_replay", "evidence_replay"];
const VERIFY_SMALL_REPORTABLE_THRESHOLD = 5;
const VERIFY_QA_SAMPLE_MAX = 10;
const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "balanced.json", markdown: "balanced.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

module.exports = {
  VERIFICATION_CONFIDENCE_REASON_VALUES,
  VERIFICATION_CONFIDENCE_VALUES,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_REASONING_DIVERGENCE_VALUES,
  VERIFICATION_REPLAY_PURPOSE_VALUES,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFY_QA_SAMPLE_MAX,
  VERIFY_SMALL_REPORTABLE_THRESHOLD,
};

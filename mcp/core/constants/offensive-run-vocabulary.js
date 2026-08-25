"use strict";

const OFFENSIVE_OUTCOME_VALUES = ["exploited_safely", "blocked_by_defense", "blocked_by_infra"];
const SAFE_ORACLE_KINDS = [
  "out_of_band_interaction",
  "reflected_canary",
  "differential_response",
  "benign_state_change",
  "blind_boolean_timing",
  "benign_command_marker",
];
const OFFENSIVE_ROW_ORACLE_KIND_VALUES = [
  "out_of_band_interaction",
  "second_order_reread",
];

module.exports = {
  OFFENSIVE_OUTCOME_VALUES,
  OFFENSIVE_ROW_ORACLE_KIND_VALUES,
  SAFE_ORACLE_KINDS,
};

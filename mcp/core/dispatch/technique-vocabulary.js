"use strict";

const TECHNIQUE_ATTEMPT_STATUS_VALUES = ["selected", "attempted", "not_applicable", "promising", "validated", "failed", "skipped"];
const TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS = 5_000;
const TECHNIQUE_PACK_READ_LOG_MAX_RECORDS = 5_000;

module.exports = {
  TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  TECHNIQUE_PACK_READ_LOG_MAX_RECORDS,
};

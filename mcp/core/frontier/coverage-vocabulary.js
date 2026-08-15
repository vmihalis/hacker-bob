"use strict";

const COVERAGE_STATUS_VALUES = ["tested", "blocked", "promising", "needs_auth", "requeue"];
const COVERAGE_UNFINISHED_STATUS_VALUES = ["promising", "needs_auth", "requeue"];
const COVERAGE_SUMMARY_MAX_ITEMS = 40;
const COVERAGE_LOG_MAX_RECORDS = 5_000;

module.exports = {
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
};

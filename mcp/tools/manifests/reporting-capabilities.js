"use strict";

module.exports = Object.freeze([
  require("../compose-report.js"),
  require("../amend-report.js"),
  require("../write-chain-rollup.js"),
  require("../set-friction-scanners.js"),
  require("../read-assignment-brief.js"),
  require("../read-capability-playbook.js"),
  require("../get-context-budget.js"),
  require("../select-technique-packs.js"),
  require("../read-technique-pack.js"),
  require("../log-technique-attempt.js"),
  require("../read-tool-telemetry.js"),
  require("../read-pipeline-analytics.js"),
  require("../read-capability-metrics.js"),
  require("../evaluate-capabilities.js"),
  require("../ingest-audit-report.js"),
  require("../query-audit-reports.js"),
  require("../register-mechanism-template.js"),
  require("../web/extract-routes.js"),
  require("../repo/build-symbol-surface-index.js"),
  require("../repo/summarize-diff-impact.js"),
]);

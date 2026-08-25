"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  offensiveRunsJsonlPath,
} = require("../../mcp/core/io/paths.js");
const {
  ensureHandoffSigningKey,
  signOffensiveRunRow,
} = require("../../mcp/core/ledger-integrity/index.js");
const {
  verifyFindingDifferential,
} = require("../../mcp/core/differential/index.js");

function sha256(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function safeIdSegment(value) {
  return String(value).replace(/[^A-Za-z0-9-]/g, "-").replace(/^-+|-+$/g, "") || "proof";
}

function appendSignedOffensiveRow(domain, row) {
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

function buildOffensiveRow(domain, {
  runId,
  surfaceId,
  outcome,
  demonstratedSeverity = "medium",
  salt,
}) {
  return {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/proof/${encodeURIComponent(runId)}`,
    offensive_outcome: outcome,
    dry_run: false,
    timed_out: false,
    command_hash: sha256(`${salt}:command`),
    exit_code: 0,
    stdout_hash: sha256(`${salt}:stdout`),
    stderr_hash: sha256(`${salt}:stderr`),
    demonstrated_severity: demonstratedSeverity,
    surface_id: surfaceId,
  };
}

function seedFindingDifferentialProof(domain, surfaceId, findingId = "F-CLOSE-ON-PROOF") {
  const segment = safeIdSegment(`${surfaceId}-${findingId}`);
  const positive = appendSignedOffensiveRow(domain, buildOffensiveRow(domain, {
    runId: `run-${segment}-positive`,
    surfaceId,
    outcome: "exploited_safely",
    salt: `${segment}:positive`,
  }));
  const control = appendSignedOffensiveRow(domain, buildOffensiveRow(domain, {
    runId: `run-${segment}-control`,
    surfaceId,
    outcome: "blocked_by_defense",
    salt: `${segment}:control`,
  }));
  return verifyFindingDifferential({
    target_domain: domain,
    finding_id: findingId,
    surface_id: surfaceId,
    positive_run_ref: { ledger: "offensive_runs", row_id: positive.run_id },
    control_run_ref: { ledger: "offensive_runs", row_id: control.run_id },
  });
}

module.exports = {
  seedFindingDifferentialProof,
};

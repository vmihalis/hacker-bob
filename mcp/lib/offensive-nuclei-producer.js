"use strict";

// offensive-nuclei-producer.js — PR7: the FIRST consumer of the dormant offensive
// container runner (offensive-runner.js). A DETECTION-ONLY nuclei lead generator.
//
// WHY DETECTION-ONLY (no signed row): a nuclei template "match" is a heuristic, not a
// categorical witness — signing one would be the #110 trap (server noise MAC-signed as
// proof). So this producer's classify ALWAYS returns positive:false: the runner therefore
// NEVER reaches its sign path, and bob_nuclei_scan is DELIBERATELY ABSENT from
// OFFENSIVE_TOOL_DEMONSTRATED_CEILING (claims.js) so even a future positive verdict would
// throw "unknown offensive tool_id" rather than mint a row. nuclei output is a LEAD the
// evaluator triages and re-proves through a real signing producer (bob_oob_mint/poll for an
// OOB-suspect lead; bob_http_xss_reflect/confirm for reflected XSS; bob_http_idor_confirm
// for IDOR). Leads ride the runner's PR7 detection channel: a bounded, secret-scanned
// counts/template-id/endpoint summary on masked_summary.detection — never raw output.
//
// OAST IS FORCED OFF: nuclei mints its own interactsh correlation IDs in interactsh's wire
// scheme, which are incompatible with Bob's OOB token (oob+32hex) and Bob's sink does not
// speak the interactsh protocol — so nuclei's OAST cannot be soundly pointed at Bob's sink.
// The forced -no-interactsh disables it entirely (no correlation is attempted, so no false
// OAST signal can arise). A future signed OOB path injects a Bob-minted token as a PLAIN
// nuclei template variable and confirms via bob_oob_poll — never via nuclei's interactsh.
//
// SAFETY POSTURE (inherited from the runner, not re-implemented here): the wide-open
// hardened container, the fail-closed flag ALLOWLIST, the AIM-check that scope-gates every
// URL flag value, the secret-scan backstop on captured output, the per-session run/infra
// budgets, and the CONTAINER_RUN audit row all live in offensive-runner.js. This module
// only supplies the server-controlled flagSpec/forcedFlags, the detection classify, and the
// image preflight, then reshapes the runner result into an agent-facing lead report.

const { ERROR_CODES, ToolError } = require("./envelope.js");
const { runOffensiveTool, defaultOffensiveDocker } = require("./offensive-runner.js");
const { resolveOffensiveImageDigest, assertOffensiveImagePresent } = require("./offensive-image.js");

const NUCLEI_TOOL_ID = "bob_nuclei_scan";

// nuclei severity vocabulary (used by the input schema enum + the producer-side filter).
const NUCLEI_SEVERITIES = Object.freeze(["info", "low", "medium", "high", "critical", "unknown"]);

// Server-controlled flag allowlist — covers EXACTLY the tokens this producer puts into
// toolArgv (the tightest fail-closed allowlist). The runner rejects anything else. `url`
// names every target-bearing flag so the runner's AIM-check scope-gates the value.
const NUCLEI_FLAG_SPEC = Object.freeze({
  binary: "nuclei",
  boolean: Object.freeze([]),
  value: Object.freeze(["-u", "-severity", "-tags"]),
  url: Object.freeze(["-u"]),
});

// Runner-injected (TRUSTED) control flags — never agent-suppliable. -no-interactsh forces
// nuclei's OAST fully OFF (the structural-soundness fix above). The rest make the run
// non-interactive and machine-parseable for the detection classify. None carry a URL value
// (the runner rejects a forced flag with a URL value).
const NUCLEI_FORCED_FLAGS = Object.freeze([
  "-no-interactsh",        // disable nuclei's interactsh/OAST entirely (no correlation attempted)
  "-disable-update-check", // no startup template/engine update fetch
  "-jsonl",                // JSONL findings — the classify oracle parses these
  "-silent",               // findings only (no banner / progress)
  "-no-color",             // no ANSI in captured stdout
]);

// How many parsed JSONL lines to walk (bounds classify work on a huge capture) and how many
// unique template-ids / matched endpoints to surface (bounds the returned summary size).
const MAX_NUCLEI_LINES = 5000;
const MAX_TRACKED = 25;
const MAX_LEAD_STR = 256;

const NUCLEI_DETECTION_NOTE =
  "DETECTION-ONLY: nuclei findings are LEADS for the evaluator to triage, NOT proof. This " +
  "tool can never mint a signed offensive-runs row (it is absent from the demonstrated-" +
  "severity ceiling registry and its oracle never returns positive). Re-prove an OOB-suspect " +
  "lead via bob_oob_mint + bob_oob_poll, a reflected-XSS lead via bob_http_xss_reflect/" +
  "bob_http_xss_confirm, and an IDOR lead via bob_http_idor_confirm.";

function rejectInvalid(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function clampStr(value) {
  return String(value).slice(0, MAX_LEAD_STR);
}

// Optional inputs are normalized to a bounded, comma-joined CSV the runner allowlist will
// accept (defense-in-depth on top of the input schema enum/pattern). Returns null when
// absent/empty so the producer omits the flag entirely.
function normalizeSeverityList(severity) {
  if (!Array.isArray(severity) || severity.length === 0) return null;
  const allowed = severity.filter((s) => typeof s === "string" && NUCLEI_SEVERITIES.includes(s));
  if (allowed.length === 0) return null;
  return Array.from(new Set(allowed)).join(",");
}

function normalizeTagList(tags) {
  if (!Array.isArray(tags) || tags.length === 0) return null;
  const clean = tags.filter((t) => typeof t === "string" && /^[a-z0-9][a-z0-9_-]{0,39}$/i.test(t));
  if (clean.length === 0) return null;
  return Array.from(new Set(clean)).slice(0, MAX_TRACKED).join(",");
}

// Parse nuclei -jsonl stdout into a BOUNDED lead summary. Extracts ONLY non-sensitive
// metadata (template-id, severity, matched-at endpoint) — never extracted-results, request,
// or response bodies (which could carry target data; the runner's secret-scan is the
// backstop regardless). Malformed lines are skipped, not thrown on.
function summarizeNucleiJsonl(stdoutText) {
  const by_severity = Object.create(null);
  for (const sev of NUCLEI_SEVERITIES) by_severity[sev] = 0;
  const templateIds = new Set();
  const matched = new Set();
  let findingsCount = 0;
  let truncated = false;

  const lines = typeof stdoutText === "string" ? stdoutText.split("\n") : [];
  let walked = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (walked >= MAX_NUCLEI_LINES) { truncated = true; break; }
    walked += 1;
    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      continue; // not a JSONL finding line (progress text, etc.)
    }
    if (!obj || typeof obj !== "object") continue;
    findingsCount += 1;
    const sev = obj.info && typeof obj.info === "object" && typeof obj.info.severity === "string"
      ? obj.info.severity.toLowerCase()
      : "unknown";
    by_severity[Object.prototype.hasOwnProperty.call(by_severity, sev) ? sev : "unknown"] += 1;
    const tid = obj["template-id"] || obj.templateID || obj.template_id || obj.template;
    if (typeof tid === "string" && tid && templateIds.size < MAX_TRACKED) templateIds.add(clampStr(tid));
    const at = obj["matched-at"] || obj.matched || obj.host;
    if (typeof at === "string" && at && matched.size < MAX_TRACKED) matched.add(clampStr(at));
  }
  if (findingsCount > MAX_TRACKED) truncated = true;

  return {
    findings_count: findingsCount,
    by_severity,
    template_ids: Array.from(templateIds),
    matched_endpoints: Array.from(matched),
    truncated,
  };
}

// The DETECTION oracle: ALWAYS returns positive:false (this tool can never sign). The
// bounded summary rides the runner's detection channel; the runner secret-scans + caps it.
function classifyNucleiDetection({ stdoutText } = {}) {
  return {
    positive: false,
    reason: "detection_only",
    detection: summarizeNucleiJsonl(stdoutText),
  };
}

// MCP handler for bob_nuclei_scan. Runs nuclei in the hardened wide-open container via the
// runner and returns triage LEADS. Deps are injectable for tests (no docker, no disk).
async function runNucleiScan(args, deps = {}) {
  const {
    docker = defaultOffensiveDocker,
    resolveDigest = resolveOffensiveImageDigest,
    runTool = runOffensiveTool,
    timeoutMs,
  } = deps;

  const a = args && typeof args === "object" ? args : {};
  const domain = typeof a.target_domain === "string" ? a.target_domain.trim() : "";
  const targetUrl = typeof a.target_url === "string" ? a.target_url.trim() : "";
  if (!domain) rejectInvalid("target_domain is required");
  if (!targetUrl) rejectInvalid("target_url is required");
  const severity = normalizeSeverityList(a.severity);
  const tags = normalizeTagList(a.tags);

  // Resolve + preflight the digest-pinned arsenal image. An unpinned/absent image is an
  // operator-setup condition (the image must be re-minted to include nuclei) → a clean
  // blocked_by_infra, never a crash. Ships dormant until the operator provisions it.
  let imageDigest;
  try {
    imageDigest = resolveDigest();
    await assertOffensiveImagePresent(imageDigest, docker);
  } catch (err) {
    return {
      tool: "nuclei",
      tool_id: NUCLEI_TOOL_ID,
      target_domain: domain,
      ran: false,
      confirmed: false,
      row_written: false,
      offensive_outcome: "blocked_by_infra",
      reason: "offensive_image_unavailable",
      detail: String(err && err.message ? err.message : err).slice(0, 300),
      leads: null,
      note: NUCLEI_DETECTION_NOTE,
    };
  }

  // Server-controlled argv: binary + producer-allowlisted flags ONLY. The runner injects
  // the forced control flags and scope-gates every -u value before any container spawn.
  const toolArgv = ["nuclei", "-u", targetUrl];
  if (severity) toolArgv.push("-severity", severity);
  if (tags) toolArgv.push("-tags", tags);

  const result = await runTool({
    domain,
    toolId: NUCLEI_TOOL_ID,
    imageDigest,
    toolArgv,
    flagSpec: NUCLEI_FLAG_SPEC,
    forcedFlags: NUCLEI_FORCED_FLAGS,
    classify: classifyNucleiDetection,
    docker,
    ...(timeoutMs != null ? { timeoutMs } : {}),
  });

  const masked = result && typeof result.masked_summary === "object" ? result.masked_summary : null;
  const ran = !!result && result.offensive_outcome !== "blocked_by_infra";
  return {
    tool: "nuclei",
    tool_id: NUCLEI_TOOL_ID,
    target_domain: domain,
    ran,
    confirmed: false,
    row_written: false,
    offensive_outcome: result ? result.offensive_outcome : "blocked_by_infra",
    reason: result ? result.reason : "no_result",
    exit_code: masked ? masked.exit_code : null,
    leads: masked && masked.detection ? masked.detection : null,
    note: NUCLEI_DETECTION_NOTE,
  };
}

module.exports = {
  runNucleiScan,
  classifyNucleiDetection,
  summarizeNucleiJsonl,
  normalizeSeverityList,
  normalizeTagList,
  NUCLEI_TOOL_ID,
  NUCLEI_FLAG_SPEC,
  NUCLEI_FORCED_FLAGS,
  NUCLEI_SEVERITIES,
};

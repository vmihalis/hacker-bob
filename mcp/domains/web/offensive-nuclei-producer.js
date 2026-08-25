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

const { ERROR_CODES, ToolError } = require("../../core/io/envelope.js");
const { runOffensiveTool, defaultOffensiveDocker } = require("./offensive-runner.js");
const { resolveOffensiveImageDigest, assertOffensiveImagePresent } = require("./offensive-image.js");
const { readSessionStateStrict } = require("../../core/session/session-state-store.js");
const { blockInternalHostsPolicyFields } = require("../../core/session/session-state-contracts.js");
const { redactUrlSensitiveValues } = require("../../redaction.js");

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

// Runner-injected (TRUSTED) control flags — never agent-suppliable. None carry a URL value
// (the runner rejects a forced flag with a URL value); value-bearing caps use the `=` form
// because forcedFlags are single tokens, not flag+value pairs.
const NUCLEI_FORCED_FLAGS = Object.freeze([
  // machine output — the classify oracle parses JSONL
  "-jsonl",
  "-omit-raw",                     // exclude request/response pairs from JSONL (included by default) —
                                   // the lead summary never needs them, and raw target bodies on
                                   // authed pages can carry session/CSRF tokens into the captured stream
  "-silent",                       // findings only (no banner / progress)
  "-no-color",                     // no ANSI in captured stdout
  "-disable-update-check",         // no startup template/engine update fetch
  // OAST hard-off — the structural-soundness fix above (nuclei interactsh is incompatible
  // with Bob's OOB sink; no correlation is attempted, so no false OAST signal can arise)
  "-no-interactsh",
  // scope + aggression bounds: one MCP call must not become an invasive full-corpus sweep
  // that bypasses the per-session run budget, follow redirects off-scope, or fire mutating
  // templates. The runner scope-gates only the initial -u, so redirects are forced OFF.
  "-disable-redirects",                  // nuclei templates can follow up to 10 redirects → off-scope egress
  "-exclude-tags=intrusive,dos,fuzz",    // drop the most aggressive / mutating template classes (detection-only)
  "-rate-limit=50",                      // cap req/s (nuclei default 150) — responsible scanning + WAF-safety
  "-concurrency=10",                     // cap parallel templates (default 25)
  "-timeout=10",                         // per-request timeout (seconds)
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
    // Redact sensitive query/credential values in the matched-at URL before surfacing it
    // as a lead — a matched-at can carry auth-callback codes, signed-URL params, or opaque
    // ids that the runner's pattern-based secret scan won't catch. Use Bob's canonical URL
    // redaction (same helper the audit log uses).
    if (typeof at === "string" && at && matched.size < MAX_TRACKED) matched.add(clampStr(redactUrlSensitiveValues(String(at))));
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

// The DETECTION oracle: ALWAYS returns positive:false (this tool can never sign). The bounded
// summary rides the runner's detection channel; the runner secret-scans + caps it. A non-zero
// nuclei exit AFTER the container started (Docker startup codes 125/126/127 are infra and never
// reach here) means the scan did not complete correctly — e.g. a missing/stale template corpus
// or a runtime config error — so it is surfaced as a scan error, NOT a false negative-detection
// (which an evaluator could otherwise record as a real "no leads" result for a scan that failed).
function classifyNucleiDetection({ exitCode, stdoutText } = {}) {
  const detection = summarizeNucleiJsonl(stdoutText);
  const scanOk = exitCode === 0;
  detection.scan_ok = scanOk;
  detection.exit_code = typeof exitCode === "number" ? exitCode : null;
  return {
    positive: false,
    reason: scanOk ? "detection_only" : "nuclei_scan_error",
    detection,
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
  // Reject credentials (userinfo) and strip any fragment BEFORE the URL reaches the docker/
  // nuclei argv — `https://user:pass@host/` or a `#access_token=...` fragment copied from an
  // auth callback would otherwise be visible via process listings / `docker inspect` and bypass
  // the audit + lead redaction paths.
  let cleanTargetUrl;
  try {
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.username || parsedUrl.password) {
      rejectInvalid("target_url must not contain credentials (userinfo)", { code: "nuclei_target_url_userinfo" });
    }
    parsedUrl.hash = "";
    cleanTargetUrl = parsedUrl.toString();
  } catch (err) {
    if (err instanceof ToolError) throw err;
    rejectInvalid("target_url must be a valid absolute URL", { code: "nuclei_target_url_invalid" });
  }
  const severity = normalizeSeverityList(a.severity);
  const tags = normalizeTagList(a.tags);

  // The offensive container is operator-locked WIDE-OPEN egress (no proxy / no gate), so it
  // CANNOT honor a session block_internal_hosts policy. If the operator set it, fail closed
  // rather than send wide-open traffic that could reach internal/metadata hosts — mirroring
  // the in-process producers' refuse-when-internal-blocking-cannot-be-honored convention.
  const { state } = readSessionStateStrict(domain);
  if (blockInternalHostsPolicyFields(state).block_internal_hosts === true) {
    return {
      tool: "nuclei",
      tool_id: NUCLEI_TOOL_ID,
      target_domain: domain,
      ran: false,
      confirmed: false,
      row_written: false,
      offensive_outcome: "blocked_by_design",
      reason: "block_internal_hosts_unsupported_in_wide_open_container",
      leads: null,
      note: NUCLEI_DETECTION_NOTE,
    };
  }
  // The wide-open container is direct-egress, so a non-default (proxy/VPN) egress_profile cannot
  // be honored either — refuse rather than leak the operator's real egress for an attribution-
  // bound session. (Init forbids block_internal_hosts + a proxy profile together, so this is the
  // proxy-only case.)
  const egressProfile = typeof state.egress_profile === "string" ? state.egress_profile.trim() : "";
  if (egressProfile && egressProfile !== "default") {
    return {
      tool: "nuclei",
      tool_id: NUCLEI_TOOL_ID,
      target_domain: domain,
      ran: false,
      confirmed: false,
      row_written: false,
      offensive_outcome: "blocked_by_design",
      reason: "session_egress_profile_unsupported_in_wide_open_container",
      leads: null,
      note: NUCLEI_DETECTION_NOTE,
    };
  }

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
  const toolArgv = ["nuclei", "-u", cleanTargetUrl];
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
  // A timed-out run DID execute — the container consumed a real run-budget slot (the runner
  // labels a timeout blocked_by_infra, but its own comment notes the container actually ran).
  // Only the pre-spawn infra blocks (budget / network / spawn / container-failed-to-start)
  // mean nuclei never ran, so treat everything EXCEPT a non-timeout infra block as having run
  // — keeping `ran` consistent with the run-budget accounting.
  const ran = !!result && (result.offensive_outcome !== "blocked_by_infra" || result.reason === "offensive_run_timed_out");
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

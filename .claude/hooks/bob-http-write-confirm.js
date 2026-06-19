#!/usr/bin/env node
"use strict";

// PreToolUse hook — "ask before writing" gate for bob_http_scan.
//
// FLAG-CONTROLLED + INERT BY DEFAULT. Bob ships FULLY-AUTONOMOUS (an operator-locked
// default), so this gate stays off unless the operator opts in by setting a truthy
// BOB_HTTP_WRITE_CONFIRM in the environment Claude Code launches under. When enabled, a
// bob_http_scan call carrying a target-MUTATING method (POST/PUT/PATCH/DELETE) returns
// permissionDecision:"ask" so the operator confirms before Bob writes to the target.
// GET/HEAD/OPTIONS (and every other tool) pass through untouched (exit 0, no prompt) — read
// probes, including the IDOR/CORS/XSS confirmers, keep running autonomously.
//
// Scope is deliberately bob_http_scan only: bob_auto_signup already carries the temp-email
// provenance guard (PR #116), and the offensive confirmers fire GETs. The gate keys on the
// actual outbound HTTP method, NOT a tool's `mutating` descriptor flag (which also covers
// internal audit-ledger writes) — the operator asked about TARGET writes, not Bob's bookkeeping.
//
// Hook I/O contract (Claude Code PreToolUse): read the tool-call payload as JSON on stdin;
// exit 0 with no stdout = allow; exit 0 with a hookSpecificOutput.permissionDecision = decide.

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SCAN_TOOL = "mcp__hacker-bob__bob_http_scan";

function flagEnabled() {
  const raw = String(process.env.BOB_HTTP_WRITE_CONFIRM || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function allow() {
  // No stdout + exit 0 = the hook abstains; Claude Code proceeds with its normal flow.
  process.exit(0);
}

function ask(method, url) {
  const reason =
    `Bob is about to send a ${method} (write) request to ${url}. ` +
    "Confirm before it mutates the target. " +
    "(This gate is on because BOB_HTTP_WRITE_CONFIRM is set; unset it to let writes run autonomously.)";
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: reason,
      },
    }),
  );
  process.exit(0);
}

function main() {
  if (!flagEnabled()) allow();

  let raw = "";
  try {
    raw = require("fs").readFileSync(0, "utf8");
  } catch {
    allow(); // no readable stdin — harness anomaly; the matcher already scopes us to bob_http_scan
  }

  let payload = {};
  try {
    payload = JSON.parse(raw || "{}");
  } catch {
    allow(); // unparseable payload — abstain rather than block the harness on a malformed call
  }

  // Defensive: the settings matcher should already scope this hook to bob_http_scan, but a
  // broad/regex matcher (or an operator edit) could route other tools here — only act on the scan.
  if (payload.tool_name && payload.tool_name !== SCAN_TOOL) allow();

  const toolInput = (payload && typeof payload.tool_input === "object" && payload.tool_input) || {};
  const method = String(toolInput.method || "").trim().toUpperCase();
  // bob_http_scan REQUIRES method as a fixed enum, so an absent/unknown method here is not a
  // write — treat it as a read and abstain (allow), keeping the gate to genuine mutations.
  if (!WRITE_METHODS.has(method)) allow();

  const url = String(toolInput.url || "(unknown url)");
  ask(method, url);
}

main();

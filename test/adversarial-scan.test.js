"use strict";

// Cycle Y.7 — adversarial-scan baseline tests (rev 3 surface preserved).
//
// Covers:
//   * SCANNER_REGISTRY is Object.freeze'd with the canonical default ids.
//   * bash_curl / bash_wget / bash_raw_http / bash_cat_ledger regex hits.
//   * mcp_invocation_failure_scanner emits a tool_inadequate synthetic
//     with a witness ref; suppresses when the agent already voluntarily
//     reported friction with the same witness.
//   * scanTranscript is pure over its inputs (no fs reads when context is
//     supplied directly).
//   * bob_scan_transcript_for_friction tool returns shaped JSON with
//     friction_records + drift_records arrays; role_bundles is
//     orchestrator-only; capability_id is Y_self_reporting.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  DEFAULT_SCANNERS,
  scanTranscript,
  normalizeOperatorScanner,
} = require("../mcp/lib/friction-scanners.js");
const scanTool = require("../mcp/lib/tools/scan-transcript-for-friction.js");
const { sessionDir } = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y7-scan-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

const EXPECTED_DEFAULT_SCANNER_NAMES = [
  "bash_curl",
  "bash_wget",
  "bash_raw_http",
  "bash_cat_ledger",
  "curl_on_target_domain",
  "curl_on_osint_endpoint",
  "python_inline_curl_parse",
  "mcp_invocation_failure_scanner",
  "large_response_body_unimported",
  "producer_trace_dropped",
  "silent_lead_threshold_drop",
];

// ── registry shape ─────────────────────────────────────────────────────────

test("DEFAULT_SCANNERS is Object.freeze'd with the closed manifest", () => {
  assert.ok(Object.isFrozen(DEFAULT_SCANNERS));
  const names = DEFAULT_SCANNERS.map((s) => s.name);
  for (const expected of EXPECTED_DEFAULT_SCANNER_NAMES) {
    assert.ok(names.includes(expected), `expected default scanner ${expected}`);
  }
  // Every entry is itself frozen.
  for (const scanner of DEFAULT_SCANNERS) {
    assert.ok(Object.isFrozen(scanner), `scanner ${scanner.name} not frozen`);
  }
});

test("scanner kinds are drawn from a closed set", () => {
  const allowedKinds = new Set([
    "regex",
    "regex_with_context",
    "invocation_failure",
    "evidence_size",
    "handoff_invocation_diff",
    "handoff_ledger_diff",
  ]);
  for (const scanner of DEFAULT_SCANNERS) {
    assert.ok(allowedKinds.has(scanner.kind), `scanner ${scanner.name} unknown kind ${scanner.kind}`);
  }
});

// ── tool registration ─────────────────────────────────────────────────────

test("bob_scan_transcript_for_friction is orchestrator-only and read-only", () => {
  assert.equal(scanTool.name, "bob_scan_transcript_for_friction");
  assert.equal(scanTool.capability_id, "Y_self_reporting");
  assert.deepEqual(scanTool.role_bundles, ["orchestrator"]);
  assert.equal(scanTool.mutating, false);
  assert.deepEqual(scanTool.session_artifacts_written, []);
});

// ── Bash regex scanners ────────────────────────────────────────────────────

test("bash_curl scanner emits a synthetic capability_friction record", () => {
  const transcript = [
    "step 1 — verify the endpoint",
    "$ curl https://example.com/api/v1/whoami -H 'Authorization: Bearer x'",
    "200 OK",
  ].join("\n");
  const records = scanTranscript(DEFAULT_SCANNERS.filter((s) => s.name === "bash_curl"), {
    target_domain: "scan.example.com",
    run_id: "run-curl",
    node_id: "N-1",
    transcript_text: transcript,
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.kind, "friction");
  assert.equal(record.scanner, "bash_curl");
  assert.equal(record.payload.fallback_used, "bash_curl");
  assert.equal(record.payload.friction_kind, "tool_absent");
  assert.equal(record.payload.detected_by, "adversarial_transcript_scan");
  assert.equal(record.payload.wanted_tool, "bob_http_scan");
  assert.equal(record.payload.purpose, "http_probe");
});

test("bash_cat_ledger scanner fires on chain-attempts.jsonl tail", () => {
  const transcript = "$ tail -n 5 ~/hacker-bob-sessions/foo/chain-attempts.jsonl";
  const records = scanTranscript(DEFAULT_SCANNERS.filter((s) => s.name === "bash_cat_ledger"), {
    target_domain: "scan.example.com",
    run_id: "run-cat",
    node_id: "N-2",
    transcript_text: transcript,
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].scanner, "bash_cat_ledger");
  assert.equal(records[0].payload.wanted_tool, "bob_read_chain_attempts");
});

test("bash regex scanners ignore unrelated transcript text", () => {
  const transcript = "$ bob_http_scan target_url=https://example.com/\n200 OK";
  const records = scanTranscript(DEFAULT_SCANNERS.filter((s) => s.kind === "regex"), {
    target_domain: "scan.example.com",
    run_id: "run-clean",
    node_id: "N-3",
    transcript_text: transcript,
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 0);
});

// ── mcp_invocation_failure_scanner (D7) ───────────────────────────────────

test("mcp_invocation_failure_scanner emits tool_inadequate with witness ref", () => {
  const records = scanTranscript(
    DEFAULT_SCANNERS.filter((s) => s.name === "mcp_invocation_failure_scanner"),
    {
      target_domain: "scan.example.com",
      run_id: "run-fail",
      node_id: "N-4",
      transcript_text: "",
      tool_invocations: [
        { tool: "bob_http_scan", outcome: "error", event_id: "evt-7" },
        { tool: "bob_resolve_body", outcome: "success", event_id: "evt-8" },
      ],
      voluntary_frictions: [],
      evidence_files: [],
      handoff_summary: null,
      recorded_leads: [],
      queue_policy: null,
    },
  );
  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.payload.friction_kind, "tool_inadequate");
  assert.equal(record.payload.inadequate_invocation_ref, "frontier_event:evt-7");
  assert.equal(record.payload.inadequacy_mode, "output_format_unsuitable");
  assert.equal(record.payload.wanted_tool, "bob_http_scan");
});

test("mcp_invocation_failure_scanner suppresses when voluntary report already exists", () => {
  const records = scanTranscript(
    DEFAULT_SCANNERS.filter((s) => s.name === "mcp_invocation_failure_scanner"),
    {
      target_domain: "scan.example.com",
      run_id: "run-vol",
      node_id: "N-5",
      transcript_text: "",
      tool_invocations: [
        { tool: "bob_http_scan", outcome: "error", event_id: "evt-9" },
      ],
      voluntary_frictions: [
        {
          run_id: "run-vol",
          node_id: "N-5",
          wanted_tool: "bob_http_scan",
          inadequate_invocation_ref: "frontier_event:evt-9",
        },
      ],
      evidence_files: [],
      handoff_summary: null,
      recorded_leads: [],
      queue_policy: null,
    },
  );
  assert.equal(records.length, 0);
});

// ── operator scanner normalization ────────────────────────────────────────

test("normalizeOperatorScanner accepts well-formed operator entries", () => {
  const scanner = normalizeOperatorScanner({
    name: "bash_xargs_curl",
    pattern: "xargs\\s+curl",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
  });
  assert.ok(scanner);
  assert.equal(scanner.name, "bash_xargs_curl");
  assert.equal(scanner.kind, "regex");
  assert.ok(scanner.pattern instanceof RegExp);
  assert.equal(scanner.friction_kind, "tool_absent");
});

test("normalizeOperatorScanner rejects malformed patterns", () => {
  const scanner = normalizeOperatorScanner({
    name: "bad",
    pattern: "[invalid",
    fallback_used: "bash_other",
    friction_kind: "tool_absent",
  });
  assert.equal(scanner, null);
});

// ── tool wrapper end-to-end ───────────────────────────────────────────────

test("bob_scan_transcript_for_friction handler returns shaped output", () => {
  withTempHome(() => {
    const domain = "tool-shape.example.com";
    ensureSessionDir(domain);
    const response = JSON.parse(scanTool.handler({
      target_domain: domain,
      run_id: "run-shape",
      node_id: "N-1",
      transcript_text: "",
      tool_invocations: [],
    }));
    assert.equal(response.version, 1);
    assert.equal(response.target_domain, domain);
    assert.equal(response.run_id, "run-shape");
    assert.equal(response.node_id, "N-1");
    assert.ok(Array.isArray(response.friction_records));
    assert.ok(Array.isArray(response.drift_records));
    assert.equal(response.scanner_count, DEFAULT_SCANNERS.length);
    assert.equal(response.operator_scanner_count, 0);
  });
});

test("bob_scan_transcript_for_friction handler rejects empty run_id", () => {
  withTempHome(() => {
    const domain = "tool-reject.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => scanTool.handler({ target_domain: domain, run_id: "", node_id: "N-1" }),
      /run_id must be a non-empty string/,
    );
  });
});

test("bob_scan_transcript_for_friction handler surfaces bash_curl hit", () => {
  withTempHome(() => {
    const domain = "tool-bash-curl.example.com";
    ensureSessionDir(domain);
    const transcript = "$ curl https://foo.example/bar";
    const response = JSON.parse(scanTool.handler({
      target_domain: domain,
      run_id: "run-x",
      node_id: "N-2",
      transcript_text: transcript,
      tool_invocations: [],
    }));
    const names = response.friction_records.map((r) => r.scanner);
    assert.ok(names.includes("bash_curl"), `expected bash_curl synth, got ${names.join(",")}`);
  });
});

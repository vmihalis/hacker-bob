"use strict";

// Cycle Y.7 (rev 4 W2 + rev 4.1 defect 1) — W2 scanner extensions +
// silent_lead_threshold_drop runtime tripwire.
//
// Asserts:
//   (a) curl_on_target_domain fires when transcript curls the session's
//       target_domain (regex_with_context).
//   (b) curl_on_osint_endpoint fires on urlscan.io / virustotal.com /
//       crt.sh / shodan.io / censys.io / securitytrails.com / abuseipdb.com.
//   (c) python_inline_curl_parse fires on python3 -c subprocess+curl.
//   (d) large_response_body_unimported fires on evidence/ >262144 bytes
//       WITHOUT a matching bob_import_http_traffic / bob_resolve_body /
//       bob_static_scan invocation; rationale names all 3 binding tools.
//   (e) producer_trace_dropped fires when ranked_leads[].length >= 2 and
//       zero bob_record_surface_leads invocations.
//   (f) silent_lead_threshold_drop fires when summary asserts N and
//       surface-leads.json records M < N for the same run_id; payload
//       includes both counts + rationale_required_but_missing flag.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  DEFAULT_SCANNERS,
  scanTranscript,
  listEvidenceFiles,
} = require("../mcp/lib/friction-scanners.js");
const scanTool = require("../mcp/lib/tools/scan-transcript-for-friction.js");
const {
  sessionDir,
  LARGE_BODY_THRESHOLD_BYTES,
  queuePolicyPath,
  surfaceLeadsPath,
} = require("../mcp/lib/paths.js");
const { DRIFT_SIGNATURE_VALUES } = require("../mcp/lib/capability-observations.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y7-w2-"));
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

function writeEvidence(domain, relPath, sizeBytes) {
  const abs = path.join(sessionDir(domain), relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, Buffer.alloc(sizeBytes, "X"));
  return abs;
}

function writeQueuePolicy(domain, policy) {
  const policyPath = queuePolicyPath(domain);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
}

function writeSurfaceLeads(domain, leads) {
  const leadsPath = surfaceLeadsPath(domain);
  fs.mkdirSync(path.dirname(leadsPath), { recursive: true });
  fs.writeFileSync(leadsPath, `${JSON.stringify({ version: 1, leads }, null, 2)}\n`);
}

function defaultsByName(name) {
  return DEFAULT_SCANNERS.filter((s) => s.name === name);
}

// ── drift-signature wiring ─────────────────────────────────────────────────

test("DRIFT_SIGNATURE_VALUES includes the two Y.7 scanner-synthesized signatures", () => {
  assert.ok(DRIFT_SIGNATURE_VALUES.includes("producer_trace_dropped"));
  assert.ok(DRIFT_SIGNATURE_VALUES.includes("silent_lead_threshold_drop"));
});

// ── (a) curl_on_target_domain (regex_with_context) ────────────────────────

test("curl_on_target_domain fires on the session's target_domain", () => {
  const records = scanTranscript(defaultsByName("curl_on_target_domain"), {
    target_domain: "target.example.com",
    run_id: "run-w2a",
    node_id: "N-1",
    transcript_text: "$ curl https://api.target.example.com/admin",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].scanner, "curl_on_target_domain");
  assert.equal(records[0].payload.wanted_tool, "bob_http_scan");
});

test("curl_on_target_domain does NOT fire on unrelated hosts", () => {
  const records = scanTranscript(defaultsByName("curl_on_target_domain"), {
    target_domain: "target.example.com",
    run_id: "run-w2a-neg",
    node_id: "N-2",
    transcript_text: "$ curl https://unrelated.example.org/whoami",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  // bash_curl is NOT in this filtered scanner list; only the contextual
  // narrow form is. Unrelated host must not trigger it.
  assert.equal(records.length, 0);
});

// ── (b) curl_on_osint_endpoint ────────────────────────────────────────────

test("curl_on_osint_endpoint fires on urlscan.io probes", () => {
  const records = scanTranscript(defaultsByName("curl_on_osint_endpoint"), {
    target_domain: "scan.example.com",
    run_id: "run-w2b",
    node_id: "N-1",
    transcript_text: "$ curl https://urlscan.io/api/v1/scan/abc",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.wanted_tool, "bob_public_intel");
});

test("curl_on_osint_endpoint fires on crt.sh / shodan / virustotal", () => {
  const hosts = [
    "https://crt.sh/?q=example",
    "https://api.shodan.io/host/1.1.1.1",
    "https://www.virustotal.com/api/v3/files/x",
  ];
  for (const url of hosts) {
    const records = scanTranscript(defaultsByName("curl_on_osint_endpoint"), {
      target_domain: "scan.example.com",
      run_id: `run-w2b-${url.length}`,
      node_id: "N-1",
      transcript_text: `$ curl ${url}`,
      tool_invocations: [],
      voluntary_frictions: [],
      evidence_files: [],
      handoff_summary: null,
      recorded_leads: [],
      queue_policy: null,
    });
    assert.equal(records.length, 1, `expected hit for ${url}`);
  }
});

// ── (c) python_inline_curl_parse ──────────────────────────────────────────

test("python_inline_curl_parse fires on python3 -c subprocess curl", () => {
  const records = scanTranscript(defaultsByName("python_inline_curl_parse"), {
    target_domain: "scan.example.com",
    run_id: "run-w2c",
    node_id: "N-1",
    transcript_text: "$ python3 -c \"import subprocess; subprocess.run(['curl', 'https://x'])\"",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: null,
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.fallback_used, "bash_other");
});

// ── (d) large_response_body_unimported ────────────────────────────────────

test("large_response_body_unimported fires on evidence/ over threshold without binding", () => {
  withTempHome(() => {
    const domain = "evidence-large.example.com";
    ensureSessionDir(domain);
    writeEvidence(domain, "evidence/large.html", LARGE_BODY_THRESHOLD_BYTES + 1024);
    const files = listEvidenceFiles(domain);
    assert.ok(files.some((f) => f.relative_path === path.join("evidence", "large.html") && f.size_bytes > LARGE_BODY_THRESHOLD_BYTES));

    const records = scanTranscript(defaultsByName("large_response_body_unimported"), {
      target_domain: domain,
      run_id: "run-w2d",
      node_id: "N-1",
      transcript_text: "",
      tool_invocations: [{ tool: "bob_http_scan", outcome: "success", event_id: "evt-1" }],
      voluntary_frictions: [],
      evidence_files: files,
      handoff_summary: null,
      recorded_leads: [],
      queue_policy: null,
    });
    assert.equal(records.length, 1);
    const [record] = records;
    assert.equal(record.payload.wanted_tool, "bob_import_http_traffic");
    // Rationale MUST name all 3 accepted binding tools literally.
    assert.match(record.payload.rationale, /bob_import_http_traffic/);
    assert.match(record.payload.rationale, /bob_resolve_body/);
    assert.match(record.payload.rationale, /bob_static_scan/);
    // Rev-4.1 disk-reality correction: bob_import_static_artifact is NOT
    // in the accepted handle set.
    assert.equal(record.payload.rationale.includes("bob_import_static_artifact"), false);
  });
});

test("large_response_body_unimported suppresses when a binding tool was invoked in the run", () => {
  withTempHome(() => {
    const domain = "evidence-bound.example.com";
    ensureSessionDir(domain);
    writeEvidence(domain, "evidence/large.html", LARGE_BODY_THRESHOLD_BYTES + 4096);
    const files = listEvidenceFiles(domain);

    const records = scanTranscript(defaultsByName("large_response_body_unimported"), {
      target_domain: domain,
      run_id: "run-w2d-bind",
      node_id: "N-2",
      transcript_text: "",
      tool_invocations: [{ tool: "bob_resolve_body", outcome: "success", event_id: "evt-2" }],
      voluntary_frictions: [],
      evidence_files: files,
      handoff_summary: null,
      recorded_leads: [],
      queue_policy: null,
    });
    assert.equal(records.length, 0);
  });
});

// ── (e) producer_trace_dropped ────────────────────────────────────────────

test("producer_trace_dropped fires when ranked_leads >=2 and zero record-surface-leads invocations", () => {
  const records = scanTranscript(defaultsByName("producer_trace_dropped"), {
    target_domain: "scan.example.com",
    run_id: "run-w2e",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [{ tool: "bob_http_scan", outcome: "success", event_id: "evt-3" }],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1", score: 80 },
        { lead_id: "L2", score: 70 },
        { lead_id: "L3", score: 60 },
      ],
    },
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.kind, "drift");
  assert.equal(record.payload.drift_signature, "producer_trace_dropped");
  assert.equal(record.payload.detected_by, "adversarial_transcript_scan");
  assert.equal(record.payload.details.summary_count, 3);
});

test("producer_trace_dropped does NOT fire when there is at least one bob_record_surface_leads call", () => {
  const records = scanTranscript(defaultsByName("producer_trace_dropped"), {
    target_domain: "scan.example.com",
    run_id: "run-w2e-ok",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [{ tool: "bob_record_surface_leads", outcome: "success", event_id: "evt-4" }],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1", score: 80 },
        { lead_id: "L2", score: 70 },
      ],
    },
    recorded_leads: [],
    queue_policy: null,
  });
  assert.equal(records.length, 0);
});

// ── (f) silent_lead_threshold_drop ────────────────────────────────────────

test("silent_lead_threshold_drop fires when summary asserts N and ledger records M<N", () => {
  const records = scanTranscript(defaultsByName("silent_lead_threshold_drop"), {
    target_domain: "scan.example.com",
    run_id: "run-w2f",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1", score: 80 },
        { lead_id: "L2", score: 70 },
        { lead_id: "L3", score: 60 },
      ],
    },
    recorded_leads: [
      { id: "SL-1", source: "run-w2f", score: 80 },
    ],
    queue_policy: {
      lead_rationale_required_when_below_threshold: true,
    },
  });
  assert.equal(records.length, 1);
  const [record] = records;
  assert.equal(record.kind, "drift");
  assert.equal(record.payload.drift_signature, "silent_lead_threshold_drop");
  assert.equal(record.payload.details.summary_count, 3);
  assert.equal(record.payload.details.recorded_count, 1);
  assert.equal(record.payload.details.rationale_required_but_missing, true);
  assert.equal(record.payload.details.role, "surface-discovery");
});

test("silent_lead_threshold_drop sets rationale_required_but_missing FALSE when policy toggle is off", () => {
  const records = scanTranscript(defaultsByName("silent_lead_threshold_drop"), {
    target_domain: "scan.example.com",
    run_id: "run-w2f-off",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1", score: 80 },
        { lead_id: "L2", score: 70 },
      ],
    },
    recorded_leads: [
      { id: "SL-1", source: "run-w2f-off" },
    ],
    queue_policy: {
      lead_rationale_required_when_below_threshold: false,
    },
  });
  assert.equal(records.length, 1);
  assert.equal(records[0].payload.details.rationale_required_but_missing, false);
});

test("silent_lead_threshold_drop does NOT fire when ledger count meets or exceeds summary", () => {
  const records = scanTranscript(defaultsByName("silent_lead_threshold_drop"), {
    target_domain: "scan.example.com",
    run_id: "run-w2f-ok",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1" },
        { lead_id: "L2" },
      ],
    },
    recorded_leads: [
      { id: "SL-1", source: "run-w2f-ok" },
      { id: "SL-2", source: "run-w2f-ok" },
      { id: "SL-3", source: "run-w2f-ok" },
    ],
    queue_policy: null,
  });
  assert.equal(records.length, 0);
});

// ── tool wrapper exercising surface-leads.json + queue-policy ─────────────

test("bob_scan_transcript_for_friction surfaces silent_lead_threshold_drop end-to-end via session ledger", () => {
  withTempHome(() => {
    const domain = "tool-tripwire.example.com";
    ensureSessionDir(domain);
    writeQueuePolicy(domain, {
      version: 1,
      lead_rationale_required_when_below_threshold: true,
      friction_scanners: [],
    });
    writeSurfaceLeads(domain, [
      { id: "SL-1", source: "run-tripwire", title: "weak lead", hosts: [], endpoints: [] },
    ]);
    const response = JSON.parse(scanTool.handler({
      target_domain: domain,
      run_id: "run-tripwire",
      node_id: "N-1",
      transcript_text: "",
      tool_invocations: [],
      handoff_summary: {
        ranked_leads: [
          { lead_id: "L1", score: 80 },
          { lead_id: "L2", score: 70 },
          { lead_id: "L3", score: 60 },
        ],
      },
    }));
    const drift = response.drift_records.find((r) => r.scanner === "silent_lead_threshold_drop");
    assert.ok(drift, `expected silent_lead_threshold_drop drift, got ${JSON.stringify(response.drift_records)}`);
    assert.equal(drift.payload.details.summary_count, 3);
    assert.equal(drift.payload.details.recorded_count, 1);
    assert.equal(drift.payload.details.rationale_required_but_missing, true);
  });
});

test("operator-extended scanners union with defaults via queue-policy.friction_scanners", () => {
  withTempHome(() => {
    const domain = "tool-operator.example.com";
    ensureSessionDir(domain);
    writeQueuePolicy(domain, {
      version: 1,
      friction_scanners: [
        {
          name: "bash_xargs_curl",
          pattern: "xargs\\s+curl",
          fallback_used: "bash_curl",
          friction_kind: "tool_absent",
        },
      ],
    });
    const response = JSON.parse(scanTool.handler({
      target_domain: domain,
      run_id: "run-operator",
      node_id: "N-1",
      transcript_text: "$ cat urls.txt | xargs curl",
      tool_invocations: [],
    }));
    assert.equal(response.operator_scanner_count, 1);
    const names = response.friction_records.map((r) => r.scanner);
    assert.ok(names.includes("bash_xargs_curl"), `expected operator scanner hit, got ${names.join(",")}`);
  });
});

"use strict";

// PR7 — offensive-nuclei-producer.js: the first runner-backed offensive tool. DETECTION-ONLY
// (leads, never a signed row). Seeded + in-process: the docker seam is stubbed (no real
// docker), the image preflight is stubbed, and resolveDigest is injected — NO live network.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runNucleiScan,
  classifyNucleiDetection,
  summarizeNucleiJsonl,
  normalizeSeverityList,
  normalizeTagList,
  NUCLEI_TOOL_ID,
  NUCLEI_FORCED_FLAGS,
  NUCLEI_FLAG_SPEC,
} = require("../mcp/lib/offensive-nuclei-producer.js");
const { offensiveRunCount } = require("../mcp/lib/offensive-runner.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { repoRunsDir, httpAuditJsonlPath, offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
const { OFFENSIVE_TOOL_DEMONSTRATED_CEILING } = require("../mcp/lib/claims.js");

const DIGEST = "ghcr.io/bobnetsec/bob-offense@sha256:" + "c".repeat(64);

function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-nuclei-"));
  process.env.HOME = home;
  return Promise.resolve().then(() => fn(home)).finally(() => {
    if (prev === undefined) delete process.env.HOME; else process.env.HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  });
}

function setup(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

// Stub docker seam — like offensive-runner.test.js makeStubDocker, plus inspectImage for
// the PR7 fail-closed image preflight. Records each `run`'s full docker argv so tests can
// assert the forced flags + the in-scope target reached the container command.
function makeStubDocker({ runResult, writeStdout = "", writeStderr = "", imagePresent = true } = {}) {
  const calls = { networkCreate: [], networkRm: [], kill: [], run: [], inspect: [] };
  return {
    calls,
    sweep() {},
    inspectImage(digest) { calls.inspect.push(digest); return Promise.resolve(imagePresent); },
    networkCreate(name) { calls.networkCreate.push(name); },
    networkRm(name) { calls.networkRm.push(name); },
    kill(name) { calls.kill.push(name); },
    async run({ args, stdoutPath, stderrPath, containerName }) {
      calls.run.push({ args, containerName });
      fs.writeFileSync(stdoutPath, writeStdout);
      fs.writeFileSync(stderrPath, writeStderr);
      return runResult || { exit_code: 0, timed_out: false, out_bytes: Buffer.byteLength(writeStdout), err_bytes: Buffer.byteLength(writeStderr) };
    },
  };
}

// A few seeded nuclei -jsonl finding lines (only the fields the summary extracts).
function jsonlFinding(templateId, severity, matchedAt, extra = {}) {
  return JSON.stringify({ "template-id": templateId, info: { name: templateId, severity }, "matched-at": matchedAt, type: "http", ...extra });
}

const offensiveRunsExists = (domain) => fs.existsSync(offensiveRunsJsonlPath(domain));
const lastContainerRunAudit = (domain) => {
  const lines = fs.readFileSync(httpAuditJsonlPath(domain), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return lines.reverse().find((r) => r.method === "CONTAINER_RUN");
};

// ───────────────────────── pure helpers ─────────────────────────

test("summarizeNucleiJsonl: counts, by_severity, bounded template-ids + endpoints", () => {
  const out = [
    jsonlFinding("tech-detect", "info", "https://x.example/"),
    jsonlFinding("cve-2024-1", "high", "https://x.example/a"),
    jsonlFinding("cve-2024-1", "high", "https://x.example/a"), // dup template+endpoint
    jsonlFinding("ssrf-probe", "medium", "https://x.example/b"),
  ].join("\n");
  const s = summarizeNucleiJsonl(out);
  assert.equal(s.findings_count, 4);
  assert.equal(s.by_severity.high, 2);
  assert.equal(s.by_severity.medium, 1);
  assert.equal(s.by_severity.info, 1);
  assert.deepEqual(s.template_ids.sort(), ["cve-2024-1", "ssrf-probe", "tech-detect"]);
  assert.deepEqual(s.matched_endpoints.sort(), ["https://x.example/", "https://x.example/a", "https://x.example/b"]);
  assert.equal(s.truncated, false);
});

test("summarizeNucleiJsonl: malformed lines skipped, missing severity → unknown, no crash", () => {
  const out = ["not json at all", "", jsonlFinding("t1", undefined, "https://x.example/"), '{"template-id":"t2"}'].join("\n");
  const s = summarizeNucleiJsonl(out);
  assert.equal(s.findings_count, 2); // two valid JSON objects; the bare text + blank are skipped
  assert.equal(s.by_severity.unknown, 2);
});

test("summarizeNucleiJsonl: does NOT surface extracted-results / response bodies (only metadata)", () => {
  const out = jsonlFinding("leaky", "high", "https://x.example/p", {
    "extracted-results": ["AKIAIOSFODNN7EXAMPLE"],
    response: "HTTP/1.1 200 ... secret body ...",
    request: "GET /p HTTP/1.1",
  });
  const serialized = JSON.stringify(summarizeNucleiJsonl(out));
  assert.ok(!serialized.includes("AKIAIOSFODNN7EXAMPLE"), "extracted-results must not appear in the summary");
  assert.ok(!serialized.includes("secret body"), "response body must not appear in the summary");
  assert.ok(!serialized.includes("GET /p"), "request must not appear in the summary");
});

test("summarizeNucleiJsonl: caps tracked template-ids/endpoints at 25 and flags truncated", () => {
  const lines = [];
  for (let i = 0; i < 40; i += 1) lines.push(jsonlFinding(`t${i}`, "low", `https://x.example/${i}`));
  const s = summarizeNucleiJsonl(lines.join("\n"));
  assert.equal(s.findings_count, 40);
  assert.ok(s.template_ids.length <= 25, "template-ids capped");
  assert.ok(s.matched_endpoints.length <= 25, "endpoints capped");
  assert.equal(s.truncated, true);
});

test("normalizeSeverityList: filters to valid nuclei severities, dedupes, joins; null on empty/invalid", () => {
  assert.equal(normalizeSeverityList(["high", "medium", "high"]), "high,medium");
  assert.equal(normalizeSeverityList(["bogus", 7, null]), null);
  assert.equal(normalizeSeverityList([]), null);
  assert.equal(normalizeSeverityList(undefined), null);
});

test("normalizeTagList: pattern-filters, dedupes, caps, joins; null on empty/invalid", () => {
  assert.equal(normalizeTagList(["cve", "ssrf", "cve"]), "cve,ssrf");
  assert.equal(normalizeTagList(["has space", "semi;colon", "../etc"]), null); // all rejected by pattern
  assert.equal(normalizeTagList([]), null);
});

test("classifyNucleiDetection: ALWAYS positive:false even with findings (can never sign)", () => {
  const v = classifyNucleiDetection({ exitCode: 0, stdoutText: jsonlFinding("cve-x", "critical", "https://x.example/") });
  assert.equal(v.positive, false);
  assert.equal(v.reason, "detection_only");
  assert.equal(v.detection.findings_count, 1);
  assert.equal(v.detection.by_severity.critical, 1);
  assert.equal(v.detection.scan_ok, true);
});

test("classifyNucleiDetection: a non-zero nuclei exit is a scan error, not a false no-leads", () => {
  const v = classifyNucleiDetection({ exitCode: 1, stdoutText: "" });
  assert.equal(v.positive, false);
  assert.equal(v.reason, "nuclei_scan_error");
  assert.equal(v.detection.scan_ok, false);
  assert.equal(v.detection.exit_code, 1);
});

test("bob_nuclei_scan is DELIBERATELY ABSENT from the demonstrated-severity ceiling registry", () => {
  assert.equal(
    Object.prototype.hasOwnProperty.call(OFFENSIVE_TOOL_DEMONSTRATED_CEILING, NUCLEI_TOOL_ID),
    false,
    "a detection-only tool must never carry a signable ceiling",
  );
});

test("forced flags hard-disable OAST + redirects + cap aggression (detection-only posture)", () => {
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-no-interactsh"));
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-jsonl"));
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-omit-raw"), "raw req/resp omitted from JSONL");
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-silent"));
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-disable-redirects"), "redirects forced off (off-scope egress)");
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-exclude-tags=intrusive,dos,fuzz"), "intrusive/mutating templates excluded");
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-rate-limit=50"), "rate cap");
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-concurrency=10"), "concurrency cap");
  assert.ok(NUCLEI_FORCED_FLAGS.includes("-timeout=10"), "per-request timeout cap");
  // Every forced flag is a single token starting with '-' and carries no URL value (the
  // runner rejects forced flags that are bare args, the '--' separator, or URL-bearing).
  for (const f of NUCLEI_FORCED_FLAGS) {
    assert.ok(typeof f === "string" && f.startsWith("-") && f !== "--", `forced flag ${f} is a flag token`);
    const inline = f.includes("=") ? f.slice(f.indexOf("=") + 1) : "";
    assert.ok(!/^([a-z][a-z0-9+.-]*:)?\/\//i.test(inline), `forced flag ${f} carries no URL value`);
  }
  // The allowlist names every target-bearing flag so the runner AIM-check scope-gates it.
  assert.deepEqual([...NUCLEI_FLAG_SPEC.url], ["-u"]);
});

test("summarizeNucleiJsonl: redacts query values in matched-at endpoints (no secret leaks as a lead)", () => {
  const out = jsonlFinding("oauth-leak", "high", "https://x.example/cb?code=SECRETAUTHCODE&state=abc");
  const s = summarizeNucleiJsonl(out);
  const joined = s.matched_endpoints.join(" ");
  assert.ok(!joined.includes("SECRETAUTHCODE"), "sensitive query value must be redacted from the lead");
  assert.ok(joined.includes("REDACTED"), "redaction marker present");
  assert.ok(joined.includes("x.example/cb"), "endpoint locus preserved");
});

// ───────────────────────── runNucleiScan end-to-end (real runner + stub docker) ─────────────────────────

test("happy path: runs container, returns LEADS, writes NO signed row, consumes budget + audit", () => withTempHome(async () => {
  const domain = "nuclei-ok.example.test";
  setup(domain);
  const stdout = [
    jsonlFinding("tech-detect", "info", `https://${domain}/`),
    jsonlFinding("cve-2024-9", "high", `https://${domain}/login`),
  ].join("\n");
  const docker = makeStubDocker({ writeStdout: stdout });
  const r = await runNucleiScan(
    { target_domain: domain, target_url: `https://${domain}/`, severity: ["high", "info"] },
    { docker, resolveDigest: () => DIGEST },
  );

  assert.equal(r.tool_id, NUCLEI_TOOL_ID);
  assert.equal(r.ran, true);
  assert.equal(r.row_written, false);
  assert.equal(r.confirmed, false);
  assert.equal(r.offensive_outcome, "blocked_by_defense"); // detection-only never signs
  assert.equal(r.reason, "detection_only");
  assert.equal(r.exit_code, 0);
  assert.equal(r.leads.findings_count, 2);
  assert.equal(r.leads.by_severity.high, 1);
  assert.deepEqual(r.leads.template_ids.sort(), ["cve-2024-9", "tech-detect"]);

  assert.equal(offensiveRunsExists(domain), false, "DETECTION-only must write NO offensive-runs row");
  assert.equal(offensiveRunCount(domain), 1, "one offensive-run budget slot consumed");
  const audit = lastContainerRunAudit(domain);
  assert.ok(audit, "a CONTAINER_RUN audit row is written for circuit-breaker accounting");
}));

test("forced OAST-off + scope-gated target reach the container command", () => withTempHome(async () => {
  const domain = "nuclei-cmd.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "" });
  await runNucleiScan(
    { target_domain: domain, target_url: `https://${domain}/app`, severity: ["high"], tags: ["ssrf", "cve"] },
    { docker, resolveDigest: () => DIGEST },
  );
  assert.equal(docker.calls.run.length, 1);
  const argv = docker.calls.run[0].args;
  assert.ok(argv.includes("nuclei"), "binary present");
  assert.ok(argv.includes("-no-interactsh"), "nuclei OAST forced off");
  assert.ok(argv.includes("-jsonl") && argv.includes("-silent") && argv.includes("-omit-raw"), "machine output forced, raw omitted");
  assert.ok(argv.includes(`https://${domain}/app`), "in-scope target reached the command");
  assert.ok(argv.includes("-severity") && argv.includes("high"), "severity flag passed");
  assert.ok(argv.includes("-tags") && argv.includes("ssrf,cve"), "tags flag passed");
}));

test("scope gate: an out-of-scope target_url is rejected before any container spawn", () => withTempHome(async () => {
  const domain = "nuclei-scope.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "" });
  await assert.rejects(
    runNucleiScan({ target_domain: domain, target_url: "https://evil.example/" }, { docker, resolveDigest: () => DIGEST }),
    /scope|SCOPE/,
  );
  assert.equal(docker.calls.run.length, 0, "no container ran for an out-of-scope target");
  assert.equal(offensiveRunCount(domain), 0, "no budget slot consumed");
}));

test("rejects target_url credentials (userinfo) before building argv", () => withTempHome(async () => {
  const domain = "nuclei-creds.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "" });
  await assert.rejects(
    runNucleiScan({ target_domain: domain, target_url: `https://user:pass@${domain}/` }, { docker, resolveDigest: () => DIGEST }),
    /credentials|userinfo/,
  );
  assert.equal(docker.calls.run.length, 0, "no container ran for a credentialed URL");
}));

test("strips the URL fragment before it reaches the container argv", () => withTempHome(async () => {
  const domain = "nuclei-frag.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "" });
  await runNucleiScan({ target_domain: domain, target_url: `https://${domain}/p#access_token=SECRETFRAG` }, { docker, resolveDigest: () => DIGEST });
  const argv = docker.calls.run[0].args;
  assert.ok(!argv.some((x) => typeof x === "string" && x.includes("SECRETFRAG")), "fragment secret must not reach the argv");
  assert.ok(argv.includes(`https://${domain}/p`), "the fragment-stripped URL is used");
}));

test("image not pinned: resolveDigest throws → blocked_by_infra, no run, no budget", () => withTempHome(async () => {
  const domain = "nuclei-nopin.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "" });
  const r = await runNucleiScan(
    { target_domain: domain, target_url: `https://${domain}/` },
    { docker, resolveDigest: () => { throw new Error("offensive image not pinned"); } },
  );
  assert.equal(r.ran, false);
  assert.equal(r.offensive_outcome, "blocked_by_infra");
  assert.equal(r.reason, "offensive_image_unavailable");
  assert.equal(r.leads, null);
  assert.equal(docker.calls.run.length, 0);
  assert.equal(offensiveRunCount(domain), 0);
}));

test("image not present locally: inspectImage→false → blocked_by_infra, no run", () => withTempHome(async () => {
  const domain = "nuclei-absent.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "", imagePresent: false });
  const r = await runNucleiScan(
    { target_domain: domain, target_url: `https://${domain}/` },
    { docker, resolveDigest: () => DIGEST },
  );
  assert.equal(r.ran, false);
  assert.equal(r.offensive_outcome, "blocked_by_infra");
  assert.equal(r.reason, "offensive_image_unavailable");
  assert.equal(docker.calls.inspect.length, 1, "preflight inspected the image");
  assert.equal(docker.calls.run.length, 0, "no run after a failed preflight");
}));

test("ran reflects execution: a timed-out run is ran:true (container executed + burned a budget slot)", () => withTempHome(async () => {
  const domain = "nuclei-timeout.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: true } });
  const r = await runNucleiScan({ target_domain: domain, target_url: `https://${domain}/` }, { docker, resolveDigest: () => DIGEST });
  assert.equal(r.offensive_outcome, "blocked_by_infra");
  assert.equal(r.reason, "offensive_run_timed_out");
  assert.equal(r.ran, true, "a timed-out container DID run (vs a pre-spawn infra block)");
  assert.equal(offensiveRunCount(domain), 1, "a timeout is a genuine run — the budget slot is NOT refunded");
}));

test("fails closed when block_internal_hosts is set (the wide-open container can't honor it)", () => withTempHome(async () => {
  const domain = "nuclei-internal.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/`, block_internal_hosts: true }));
  const docker = makeStubDocker({ writeStdout: "" });
  const r = await runNucleiScan({ target_domain: domain, target_url: `https://${domain}/` }, { docker, resolveDigest: () => DIGEST });
  assert.equal(r.ran, false);
  assert.equal(r.offensive_outcome, "blocked_by_design");
  assert.equal(r.reason, "block_internal_hosts_unsupported_in_wide_open_container");
  assert.equal(docker.calls.run.length, 0, "no container ran under block_internal_hosts");
  assert.equal(offensiveRunCount(domain), 0, "no budget slot consumed");
}));

test("redaction backstop: secret-shaped nuclei output blocks, surfaces no leads, signs nothing", () => withTempHome(async () => {
  const domain = "nuclei-secret.example.test";
  setup(domain);
  // A finding whose serialized line carries a bearer token → the runner's full-stdout
  // secret scan fires BEFORE classify, so no lead summary is built and nothing is signed.
  const stdout = jsonlFinding("leaky", "high", `https://${domain}/p`, {
    matcher_status: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
  });
  const docker = makeStubDocker({ writeStdout: stdout });
  const r = await runNucleiScan(
    { target_domain: domain, target_url: `https://${domain}/` },
    { docker, resolveDigest: () => DIGEST },
  );
  assert.equal(r.offensive_outcome, "blocked_operator_pii");
  assert.equal(r.reason, "offensive_output_contains_sensitive_value");
  assert.equal(r.leads, null, "no lead summary leaks when output tripped the secret scan");
  assert.equal(offensiveRunsExists(domain), false);
}));

test("module hygiene: the producer does NOT spawn processes itself (container exec goes through the runner)", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "mcp", "lib", "offensive-nuclei-producer.js"), "utf8");
  // Catch a child_process require/import in ALL forms: node: prefix, single/double quotes,
  // surrounding whitespace, ESM `from`, and dynamic import().
  const cpImport = /(?:require|import)\s*\(\s*["'](?:node:)?child_process["']\s*\)|from\s+["'](?:node:)?child_process["']/;
  assert.ok(!cpImport.test(src), "producer must not require/import child_process directly");
});

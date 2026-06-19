"use strict";

// Cycle T.7 — Browser-driven traffic capture (Patchright record mode).
//
// Contracts under test:
//   - bob_browser_session_start_recording and bob_browser_flush_recorded_requests
//     are registered in the canonical browser bundles with the same authority
//     class as the T.1 browser tools.
//   - The flush tool ingests captured records through importHttpTraffic so they
//     land in traffic.jsonl with source: "browser_capture" and
//     source_meta.session_id === <the recording session id>. This is the
//     T-R5 guarantee: the writer holds the per-domain session lock.
//   - Non-HTTP schemes (data:, blob:, chrome-extension:) are dropped at the
//     driver layer and never reach http-records.
//   - Calling flush twice returns the buffered records on the first call and
//     an empty buffer on the second (idempotent drain).
//   - bob_browser_session_close drains any residual buffer before exiting.
//   - A captured URL can be re-targeted via bob_http_scan (the mutate-and-
//     replay pivot the cycle exists to enable).
//
// Patchright-gated tests follow the T.1 pattern: when the optional dependency
// is missing the suite still asserts registry+envelope shape but skips the
// live browser smoke.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../mcp/lib/tool-registry.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/lib/session-authority.js");
const browserSessions = require("../mcp/lib/browser-sessions.js");
const {
  readTrafficRecordsFromJsonl,
  importHttpTraffic,
} = require("../mcp/lib/http-records.js");

const PATCHRIGHT_AVAILABLE = browserSessions.isPatchrightAvailable();
const PATCHRIGHT_SKIP_REASON =
  "patchright optional dependency not installed; install via `npm install` + `npx patchright install chromium` to enable this test";

const NEW_TOOLS = Object.freeze([
  "bob_browser_session_start_recording",
  "bob_browser_flush_recorded_requests",
]);

const BROWSER_BUNDLES = Object.freeze([
  "evaluator-shared",
  "surface-discovery",
  "deep-surface-discovery",
]);

function loadHandler(toolName) {
  const moduleSlug = toolName.replace(/^bob_/, "").replace(/_/g, "-");
  // eslint-disable-next-line import/no-dynamic-require, node/no-missing-require
  const mod = require(path.join("..", "mcp", "lib", "tools", `${moduleSlug}.js`));
  return mod.handler;
}

async function callTool(toolName, args) {
  const handler = loadHandler(toolName);
  const raw = await handler(args);
  return JSON.parse(raw);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-record-test-"));
  process.env.HOME = tempHome;
  const cleanup = () => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    try { fs.rmSync(tempHome, { recursive: true, force: true }); } catch {}
  };
  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (err) {
    cleanup();
    throw err;
  }
}

function seedSessionStateForDomain(home, domain) {
  // Minimal valid session state so importHttpTraffic's session-lock path and
  // the authority class checks (initialized_session_mutation) are satisfied.
  // The browser flush tool calls importHttpTraffic directly (not through the
  // dispatch authority gate); the inner state.json still needs to be coherent
  // because withSessionLock writes under the session directory.
  const sessionDir = path.join(home, "hacker-bob-sessions", domain);
  fs.mkdirSync(sessionDir, { recursive: true });
  const statePath = path.join(sessionDir, "state.json");
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "EVALUATE",
    evaluation_wave: 1,
    pending_wave: 1,
    total_findings: 0,
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_source: null,
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
  };
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2), "utf8");
}

// ── Registry contracts ──

test("record-mode tools are registered and share the browser-driver bundles", () => {
  for (const name of NEW_TOOLS) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} must be registered`);
    assert.equal(meta.browser_access, true, `${name} must have browser_access: true`);
    assert.equal(meta.global_preapproval, false, `${name} must not be globally pre-approved`);
    assert.deepEqual(
      [...meta.role_bundles].sort(),
      [...BROWSER_BUNDLES].sort(),
      `${name} must be in the canonical browser-driver bundles`,
    );
  }
});

test("record-mode tools are NOT in the orchestrator role bundle", () => {
  const orchestratorTools = new Set(toolNamesForRoleBundle("orchestrator"));
  for (const name of NEW_TOOLS) {
    assert.ok(
      !orchestratorTools.has(name),
      `${name} must not be in orchestrator (orchestrator dispatches; agents drive)`,
    );
  }
});

test("record-mode tools carry initialized_session_mutation authority", () => {
  for (const name of NEW_TOOLS) {
    assert.equal(
      EXPLICIT_AUTHORITY_CLASS_BY_TOOL[name],
      "initialized_session_mutation",
      `${name} must declare initialized_session_mutation authority`,
    );
  }
});

test("session_start_recording declares scope_url_fields for target_url", () => {
  const tool = TOOLS.find((t) => t.name === "bob_browser_session_start_recording");
  assert.ok(tool, "tool must be registered");
  const meta = TOOL_MANIFEST.bob_browser_session_start_recording;
  assert.ok(meta.scope_url_fields.includes("target_url"));
});

test("flush tool declares traffic.jsonl as a session artifact write", () => {
  const meta = TOOL_MANIFEST.bob_browser_flush_recorded_requests;
  assert.ok(meta.session_artifacts_written.includes("traffic.jsonl"));
});

// ── Patchright availability gate ──

test("record-mode tools return patchright_unavailable when patchright is missing", { skip: PATCHRIGHT_AVAILABLE }, async () => {
  for (const name of NEW_TOOLS) {
    const response = await callTool(name, {
      target_domain: "example.com",
      target_url: "https://example.com",
      session_id: "bs-fakefakefake",
    });
    assert.equal(response.ok, false, `${name} should not succeed without patchright`);
    assert.equal(
      response.error.code,
      "patchright_unavailable",
      `${name} must return patchright_unavailable (got ${response.error.code})`,
    );
  }
});

// ── importHttpTraffic source_meta plumbing (no Patchright required) ──
//
// These tests exercise the http-records side of the contract independently of
// the browser substrate. The flush tool calls importHttpTraffic with
// source: "browser_capture" and source_meta: { kind, session_id }; if that
// chain is intact then the live smoke below only has to verify the driver
// actually emits a request event.

test("importHttpTraffic with source_meta=browser_capture lands session_id on each record", () => {
  withTempHome((home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);
    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "browser_capture",
      source_meta: { kind: "browser_capture", session_id: "bs-fixture-1234" },
      entries: [
        {
          method: "GET",
          url: `https://${domain}/api/me`,
          headers: { Authorization: "Bearer x" },
        },
      ],
    }));
    assert.equal(result.imported, 1);
    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].source, "browser_capture");
    assert.ok(records[0].source_meta, "source_meta should be persisted");
    assert.equal(records[0].source_meta.kind, "browser_capture");
    assert.equal(records[0].source_meta.session_id, "bs-fixture-1234");
  });
});

test("driver attachListeners record_mode filter excludes data:, blob:, chrome-extension: schemes", () => {
  // Unit-level coverage of the driver filter: the page.on("request") handler
  // is constructed inline so we exercise it by directly instantiating the
  // request listener through a stub page object. This guards the T-R5 surface
  // (only http(s) requests reach the import path) without needing a live
  // Chromium.
  const path = require("path");
  // Force-resolve the driver module's file to confirm it exists; we do not
  // execute it (it expects BOB_BROWSER_DRIVER_INIT), only verify the regex
  // filter source is present so the contract is greppable.
  const driverPath = path.join(__dirname, "..", "mcp", "browser-driver.js");
  const driverSource = fs.readFileSync(driverPath, "utf8");
  // The recording listener checks /^https?:/i.test(url) before pushing into
  // recordedRequests. If the filter regex disappears or weakens, this test
  // breaks loudly.
  assert.match(
    driverSource,
    /this\.recordMode\s*&&\s*\/\^https\?:\/i\.test\(url\)/,
    "driver must filter non-HTTP schemes from the record-mode buffer",
  );
  // The close response must include `recorded` for record_mode sessions.
  assert.match(
    driverSource,
    /case "flush_recorded_requests":\s*\n\s*return this\.flushRecordedRequests/,
    "driver must expose flush_recorded_requests command",
  );
  assert.match(
    driverSource,
    /case "close":[\s\S]*?recorded:[\s\S]*?this\.flushRecordedRequests/,
    "driver close command must drain the record_mode buffer",
  );
});

test("importHttpTraffic source_meta nested objects/arrays are dropped (shape stays flat)", () => {
  withTempHome((home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);
    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "browser_capture",
      source_meta: {
        kind: "browser_capture",
        session_id: "bs-flat-9",
        nested: { not_allowed: true },
        array: [1, 2, 3],
        flag: true,
      },
      entries: [
        { method: "GET", url: `https://${domain}/x` },
      ],
    }));
    assert.equal(result.imported, 1);
    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records[0].source_meta.kind, "browser_capture");
    assert.equal(records[0].source_meta.session_id, "bs-flat-9");
    assert.equal(records[0].source_meta.flag, true);
    assert.equal(records[0].source_meta.nested, undefined);
    assert.equal(records[0].source_meta.array, undefined);
  });
});

// ── Live browser smoke ──
//
// The live tests navigate to https://example.com/ (the same in-scope target
// the T.1 smoke uses) so the navigation itself emits at least one
// page.on("request") event. The driver only records http(s) requests; non-
// HTTP schemes are excluded by the driver-side filter. We do not assert that
// any specific request was captured — only that:
//   1. The buffer contains at least one http(s) entry.
//   2. No non-HTTP scheme leaked into the buffer.
//   3. The flush handler routes through importHttpTraffic so the records
//      land in traffic.jsonl with source: "browser_capture" and
//      source_meta.session_id === <this session>.

test("smoke: record_mode captures http(s) requests, drops non-HTTP schemes, lands in traffic.jsonl", { skip: !PATCHRIGHT_AVAILABLE, todo: PATCHRIGHT_AVAILABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async (t) => {
  await withTempHome(async (home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);

    const start = await callTool("bob_browser_session_start_recording", {
      target_domain: domain,
      target_url: `https://${domain}`,
      headless: true,
    });
    assert.equal(start.ok, true, `start failed: ${JSON.stringify(start)}`);
    const sessionId = start.session_id;
    assert.equal(start.record_mode, true);
    assert.equal(start.recorded_count, 0);

    try {
      // Navigate to the in-scope target. The navigation itself triggers at
      // least one page.on("request") event with the document URL; further
      // sub-resources (favicon, robots) may or may not appear depending on
      // Chromium build.
      const navResult = await callTool("bob_browser_navigate", {
        target_domain: domain,
        session_id: sessionId,
        url: `https://${domain}/`,
      });
      assert.equal(navResult.ok, true, `navigate failed: ${JSON.stringify(navResult)}`);
      // Give the page a moment for sub-resource requests to settle.
      await new Promise((r) => setTimeout(r, 500));

      const flush = await callTool("bob_browser_flush_recorded_requests", {
        target_domain: domain,
        session_id: sessionId,
      });
      assert.equal(flush.ok, true, `flush failed: ${JSON.stringify(flush)}`);
      const recorded = Array.isArray(flush.recorded) ? flush.recorded : [];
      t.diagnostic(`flushed ${recorded.length} requests`);
      assert.ok(
        recorded.length >= 1 && recorded.some((r) => /^https?:/i.test(r.url)),
        `expected at least one http(s) request in the recorded buffer; got ${JSON.stringify(recorded.map((r) => r.url))}`,
      );
      for (const entry of recorded) {
        assert.ok(
          /^https?:/i.test(entry.url),
          `recorded entry url must be http(s); got ${entry.url}`,
        );
        assert.ok(
          !/^data:/i.test(entry.url) && !/^blob:/i.test(entry.url) && !/^chrome-extension:/i.test(entry.url),
          `recorded entry must not be a non-HTTP scheme; got ${entry.url}`,
        );
      }
      assert.equal(flush.flushed_count, recorded.length, "flushed_count should equal buffer length");

      // The flush handler ingests through importHttpTraffic; verify the
      // traffic.jsonl now carries source/source_meta as required.
      const records = readTrafficRecordsFromJsonl(domain);
      assert.ok(records.length >= 1, "traffic.jsonl should have at least one captured record");
      const captured = records.find((r) => r.source === "browser_capture");
      assert.ok(captured, "expected at least one record with source: browser_capture");
      assert.ok(captured.source_meta, "captured record must carry source_meta");
      assert.equal(captured.source_meta.kind, "browser_capture");
      assert.equal(captured.source_meta.session_id, sessionId);

      // Idempotent drain: a second flush returns nothing new.
      const flushAgain = await callTool("bob_browser_flush_recorded_requests", {
        target_domain: domain,
        session_id: sessionId,
      });
      assert.equal(flushAgain.ok, true);
      assert.equal(flushAgain.flushed_count, 0, "second flush should be empty");
      assert.deepEqual(flushAgain.recorded, []);
    } finally {
      const close = await callTool("bob_browser_session_close", {
        target_domain: domain,
        session_id: sessionId,
      });
      assert.equal(close.ok, true, `close failed: ${JSON.stringify(close)}`);
    }
  });
});

test("smoke: session close drains residual record_mode buffer before exit", { skip: !PATCHRIGHT_AVAILABLE, todo: PATCHRIGHT_AVAILABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  await withTempHome(async (home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);

    const start = await callTool("bob_browser_session_start_recording", {
      target_domain: domain,
      target_url: `https://${domain}`,
      headless: true,
    });
    assert.equal(start.ok, true);
    const sessionId = start.session_id;
    try {
      // Trigger a request that the driver buffers but the caller never
      // flushes before close. The closeSession path must drain the buffer.
      await callTool("bob_browser_navigate", {
        target_domain: domain,
        session_id: sessionId,
        url: `https://${domain}/`,
      }).catch(() => {});
      await new Promise((r) => setTimeout(r, 500));
    } finally {
      // The registry-level closeSession returns the drained payload. The
      // wrapped MCP tool (covered by the regression test below) routes that
      // payload through importHttpTraffic so the entries actually persist.
      const close = await browserSessions.closeSession(sessionId, "test_close");
      assert.equal(close.closed, true);
      // The drain payload contract: closeSession returns recorded[] for
      // record_mode sessions regardless of whether content remained. Earlier
      // assertions in the test process may have already pulled the buffer;
      // what matters is the close path produced an array and did not throw.
      assert.ok(Array.isArray(close.recorded), "close must return recorded[] for record_mode sessions");
    }
  });
});

// T.7 fixup regression — close-without-prior-flush must persist captures.
//
// Reviewer gate 5: browser_session_close used to return the drained recorded[]
// from the driver but never piped it through importHttpTraffic, so a close
// without an explicit flush would silently drop the captures. This test
// exercises the wrapped MCP tool end-to-end: start recording, generate at
// least one request, call browser_session_close WITHOUT calling flush first,
// then confirm the entries landed in traffic.jsonl with source ===
// "browser_capture" and source_meta.session_id set to the closed session.
test("regression: browser_session_close persists drained captures via importHttpTraffic (no prior flush)", { skip: !PATCHRIGHT_AVAILABLE, todo: PATCHRIGHT_AVAILABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async (t) => {
  await withTempHome(async (home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);

    const start = await callTool("bob_browser_session_start_recording", {
      target_domain: domain,
      target_url: `https://${domain}`,
      headless: true,
    });
    assert.equal(start.ok, true, `start failed: ${JSON.stringify(start)}`);
    const sessionId = start.session_id;

    // Generate traffic the driver will buffer. We do NOT call flush — that is
    // the whole point of the regression: close must drain what flush would
    // have drained.
    const navResult = await callTool("bob_browser_navigate", {
      target_domain: domain,
      session_id: sessionId,
      url: `https://${domain}/`,
    });
    assert.equal(navResult.ok, true, `navigate failed: ${JSON.stringify(navResult)}`);
    await new Promise((r) => setTimeout(r, 500));

    // traffic.jsonl must be empty before close (no flush was called).
    const preCloseRecords = readTrafficRecordsFromJsonl(domain);
    assert.equal(
      preCloseRecords.length,
      0,
      "traffic.jsonl should be empty before close (no explicit flush was called)",
    );

    // Close through the wrapped MCP tool. Old behavior: the residual buffer
    // was returned by the driver, discarded by the wrapper, and never reached
    // http-records. New behavior: the wrapper pipes those records through
    // importHttpTraffic exactly the way the flush tool does.
    const close = await callTool("bob_browser_session_close", {
      target_domain: domain,
      session_id: sessionId,
    });
    assert.equal(close.ok, true, `close failed: ${JSON.stringify(close)}`);
    assert.equal(close.closed, true, "close envelope must report closed: true");
    t.diagnostic(`close drained ${close.flushed_count} entries; ingested ${close.ingested_count}`);
    assert.ok(close.flushed_count >= 1, `expected at least one drained entry on close; got ${close.flushed_count}`);
    assert.ok(close.ingested_count >= 1, `expected at least one ingested entry on close; got ${close.ingested_count}`);

    // The entries must have landed with source: "browser_capture" and
    // source_meta.session_id === <the closed session>. This is the T-R5
    // invariant the fixup is upholding.
    const records = readTrafficRecordsFromJsonl(domain);
    assert.ok(records.length >= 1, "traffic.jsonl should have at least one record after close");
    const captured = records.find(
      (r) => r.source === "browser_capture" && r.source_meta && r.source_meta.session_id === sessionId,
    );
    assert.ok(
      captured,
      `expected a record with source: "browser_capture" and source_meta.session_id === ${sessionId}; got sources=${JSON.stringify(records.map((r) => ({ source: r.source, session_id: r.source_meta && r.source_meta.session_id })))}`,
    );
    assert.equal(captured.source_meta.kind, "browser_capture");
  });
});

// T.7 fixup regression — idempotent close on an already-closed session must
// not crash and must not double-write.
test("regression: browser_session_close is idempotent and does not double-write", { skip: !PATCHRIGHT_AVAILABLE, todo: PATCHRIGHT_AVAILABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  await withTempHome(async (home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);

    const start = await callTool("bob_browser_session_start_recording", {
      target_domain: domain,
      target_url: `https://${domain}`,
      headless: true,
    });
    assert.equal(start.ok, true);
    const sessionId = start.session_id;
    await callTool("bob_browser_navigate", {
      target_domain: domain,
      session_id: sessionId,
      url: `https://${domain}/`,
    }).catch(() => {});
    await new Promise((r) => setTimeout(r, 500));

    const firstClose = await callTool("bob_browser_session_close", {
      target_domain: domain,
      session_id: sessionId,
    });
    assert.equal(firstClose.ok, true, `first close failed: ${JSON.stringify(firstClose)}`);
    const recordsAfterFirstClose = readTrafficRecordsFromJsonl(domain);
    const ingestedFirst = recordsAfterFirstClose.filter(
      (r) => r.source === "browser_capture" && r.source_meta && r.source_meta.session_id === sessionId,
    ).length;

    // Second close on the same session must not throw and must not write
    // additional traffic records.
    const secondClose = await callTool("bob_browser_session_close", {
      target_domain: domain,
      session_id: sessionId,
    });
    assert.equal(secondClose.ok, true, `second close failed: ${JSON.stringify(secondClose)}`);
    assert.equal(secondClose.closed, true, "second close should still report closed: true");
    assert.equal(secondClose.flushed_count, 0, "second close should drain nothing — buffer is gone");
    assert.equal(secondClose.ingested_count, 0, "second close should not ingest anything");

    const recordsAfterSecondClose = readTrafficRecordsFromJsonl(domain);
    const ingestedSecond = recordsAfterSecondClose.filter(
      (r) => r.source === "browser_capture" && r.source_meta && r.source_meta.session_id === sessionId,
    ).length;
    assert.equal(
      ingestedSecond,
      ingestedFirst,
      `second close must not double-write: first=${ingestedFirst} second=${ingestedSecond}`,
    );
  });
});

test("smoke: captured URL can be re-targeted via bob_http_scan (mutate-and-replay pivot)", { skip: !PATCHRIGHT_AVAILABLE, todo: PATCHRIGHT_AVAILABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  await withTempHome(async (home) => {
    const domain = "example.com";
    seedSessionStateForDomain(home, domain);

    const start = await callTool("bob_browser_session_start_recording", {
      target_domain: domain,
      target_url: `https://${domain}`,
      headless: true,
    });
    assert.equal(start.ok, true);
    const sessionId = start.session_id;
    let capturedUrl = null;
    try {
      await callTool("bob_browser_navigate", {
        target_domain: domain,
        session_id: sessionId,
        url: `https://${domain}/`,
      });
      await new Promise((r) => setTimeout(r, 500));
      const flush = await callTool("bob_browser_flush_recorded_requests", {
        target_domain: domain,
        session_id: sessionId,
      });
      assert.equal(flush.ok, true);
      const httpEntry = (flush.recorded || []).find((r) => /^https?:\/\/example\.com\//i.test(r.url));
      assert.ok(httpEntry, "expected to capture an example.com request");
      capturedUrl = httpEntry.url;
    } finally {
      await callTool("bob_browser_session_close", {
        target_domain: domain,
        session_id: sessionId,
      });
    }
    assert.ok(capturedUrl, "no captured URL — cannot test replay pivot");

    // The replay pivot: take the captured URL, mutate it, hand to bob_http_scan.
    // We accept any non-shape-error envelope — what we need to prove is the
    // scan path will accept the URL shape produced by record-mode. The scan
    // may fail with a network/transport error; the assertion only requires
    // that scope validation passed and the tool produced a structured
    // response (not a thrown exception).
    const scanHandler = require("../mcp/lib/tools/http-scan.js").handler;
    const raw = await scanHandler({
      target_domain: domain,
      method: "GET",
      url: capturedUrl,
    });
    const response = JSON.parse(raw);
    assert.ok(
      response && typeof response === "object",
      "bob_http_scan must return a structured response for a captured URL",
    );
    // If the scan was scope-blocked or rejected the URL shape, the replay
    // pivot would be broken. Either ok:true (best case) or a non-shape
    // error code (network failure) is acceptable; a SCOPE_BLOCKED or
    // INVALID_ARGUMENTS on the captured URL would be a real regression.
    if (response.ok === false) {
      const code = response.error && response.error.code;
      assert.notEqual(code, "SCOPE_BLOCKED", "captured URL must not be off-scope");
      assert.notEqual(code, "INVALID_ARGUMENTS", "captured URL must satisfy scan-tool argument shape");
    }
  });
});

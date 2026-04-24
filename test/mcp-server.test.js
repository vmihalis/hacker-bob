const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("child_process");
const { EventEmitter } = require("events");
const { Readable } = require("stream");
const dns = require("dns");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");
const serverModule = require("../mcp/server.js");
const {
  TOOL_HANDLERS,
} = require("../mcp/lib/dispatch.js");
const {
  buildToolRegistry,
} = require("../mcp/lib/tool-registry.js");
const {
  createMcpMessageHandler,
  createStdioServer,
} = require("../mcp/lib/transport.js");
const {
  COVERAGE_LOG_MAX_RECORDS,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
} = require("../mcp/lib/constants.js");
const {
  appendHttpAuditRecord,
} = require("../mcp/lib/http-records.js");
const {
  acquireSessionLock,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  trimJsonlFile,
} = require("../mcp/lib/storage.js");
const {
  safeFetch,
} = require("../mcp/lib/safe-fetch.js");
const {
  normalizeAutoSignupResult,
} = require("../mcp/lib/signup.js");

const {
  TOOLS,
  TOOL_MANIFEST,
  SESSION_LOCK_STALE_MS,
  assertSafeDomain,
  validateScanUrl,
  appendJsonlLine,
  applyWaveMerge,
  attackSurfacePath,
  autoSignup,
  authStore,
  buildHeaderProfile,
  buildCircuitBreakerSummary,
  buildCoverageSummaryForSurface,
  coverageJsonlPath,
  executeTool,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  initSession,
  importHttpTraffic,
  logCoverage,
  migrateAuthJson,
  bountyPublicIntel,
  readScopeExclusions,
  readSessionState,
  readStateSummary,
  readCoverageRecordsFromJsonl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  compactSessionState,
  listFindings,
  listAuthProfiles,
  mergeWaveHandoffs,
  httpAuditJsonlPath,
  importStaticArtifact,
  publicIntelPath,
  rankAttackSurfaces,
  readFindings,
  readGradeVerdict,
  readVerificationRound,
  readWaveHandoffs,
  recordFinding,
  redactUrlSensitiveValues,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  startWave,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScan,
  staticScanResultsJsonlPath,
  tempEmail,
  transitionPhase,
  trafficJsonlPath,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeFileAtomic,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  filterExclusionsByHosts,
  readHunterBrief,
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
} = serverModule;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  process.env.HOME = tempHome;

  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };

  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function seedSessionState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {
    target: domain,
    target_url: "https://example.com",
    phase: "HUNT",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    ...overrides,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  return state;
}

function seedAssignments(domain, waveNumber, assignments) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  writeFileAtomic(path.join(dir, `wave-${waveNumber}-assignments.json`), `${JSON.stringify({
    wave_number: waveNumber,
    assignments,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaceIds = ["surface-a", "surface-b", "surface-c"]) {
  const surfaces = surfaceIds.map((surfaceId) => ({
    id: surfaceId,
    hosts: [`https://${domain}`],
  }));
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function seedAttackSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function writeUnexpectedHandoff(domain, wave, agent, payload = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  writeFileAtomic(path.join(dir, `handoff-${wave}-${agent}.json`), `${JSON.stringify({
    target_domain: domain,
    wave,
    agent,
    surface_id: "surface-z",
    surface_status: "complete",
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    ...payload,
  }, null, 2)}\n`);
}

function ensureFindingAssignment(domain, wave, agent) {
  if (wave == null || agent == null) {
    return null;
  }

  const waveNumber = Number(String(wave).slice(1));
  const assignmentsPath = path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
  if (fs.existsSync(assignmentsPath)) {
    const assignmentDoc = JSON.parse(fs.readFileSync(assignmentsPath, "utf8"));
    const assignment = assignmentDoc.assignments.find((item) => item.agent === agent);
    return assignment ? assignment.surface_id : "surface-a";
  }

  seedAssignments(domain, waveNumber, [
    { agent, surface_id: "surface-a" },
  ]);
  return "surface-a";
}

function seedFinding(domain, overrides = {}) {
  const wave = Object.prototype.hasOwnProperty.call(overrides, "wave") ? overrides.wave : "w1";
  const agent = Object.prototype.hasOwnProperty.call(overrides, "agent") ? overrides.agent : "a1";
  const assignedSurfaceId = ensureFindingAssignment(domain, wave, agent);
  const surfaceId = Object.prototype.hasOwnProperty.call(overrides, "surface_id")
    ? overrides.surface_id
    : assignedSurfaceId;

  return JSON.parse(recordFinding({
    target_domain: domain,
    title: "IDOR on account export",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/api/export",
    description: "Authenticated user can export another account's data by changing account_id.",
    proof_of_concept: "curl https://example.com/api/export?account_id=2",
    response_evidence: "{\"account_id\":2}",
    impact: "Cross-account PII disclosure.",
    validated: true,
    wave,
    agent,
    surface_id: surfaceId,
    ...overrides,
  }));
}

async function withMockSafeFetch(routes, fn, { dnsRecords = {} } = {}) {
  const originalLookup = dns.lookup;
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  const requestedUrls = [];

  dns.lookup = (hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    const records = dnsRecords[hostname] || [{ address: "93.184.216.34", family: 4 }];
    if (Array.isArray(records)) {
      cb(null, records);
    } else {
      cb(null, [records]);
    }
  };

  const makeRequest = (requestOptions, callback) => {
    const protocol = requestOptions.protocol || "https:";
    const host = requestOptions.hostname;
    const port = requestOptions.port ? `:${requestOptions.port}` : "";
    const requestPath = requestOptions.path || "/";
    const url = `${protocol}//${host}${port}${requestPath}`;
    requestedUrls.push(url);

    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = () => req;
    req.destroy = (error) => {
      if (error) process.nextTick(() => req.emit("error", error));
    };
    req.end = () => {
      const route = typeof routes === "function" ? routes(url, requestOptions) : routes[url];
      process.nextTick(() => {
        if (!route) {
          req.emit("error", new Error(`No mock route for ${url}`));
          return;
        }
        if (route.error) {
          req.emit("error", route.error);
          return;
        }

        const body = Buffer.isBuffer(route.body)
          ? route.body
          : Buffer.from(route.body == null ? "" : String(route.body));
        const res = Readable.from([body]);
        res.statusCode = route.status || 200;
        res.statusMessage = route.statusText || "OK";
        res.headers = route.headers || { "content-type": "text/plain" };
        callback(res);
      });
    };
    return req;
  };

  http.request = makeRequest;
  https.request = makeRequest;

  try {
    return await fn(requestedUrls);
  } finally {
    dns.lookup = originalLookup;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
  }
}

function runScopeGuard(command, { home, env = {} }) {
  return spawnSync("bash", [path.join(__dirname, "..", ".claude", "hooks", "scope-guard.sh")], {
    input: JSON.stringify({ tool_input: { command } }),
    encoding: "utf8",
    env: { ...process.env, HOME: home, ...env },
  });
}

function runMcpScopeGuard(toolInput, { home, env = {} }) {
  return spawnSync("bash", [path.join(__dirname, "..", ".claude", "hooks", "scope-guard-mcp.sh")], {
    input: JSON.stringify({ tool_input: toolInput }),
    encoding: "utf8",
    env: { ...process.env, HOME: home, ...env },
  });
}

function runHunterSubagentStop(payload, { home, env = {} }) {
  return spawnSync(process.execPath, [path.join(__dirname, "..", ".claude", "hooks", "hunter-subagent-stop.js")], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, HOME: home, CLAUDE_PROJECT_DIR: path.join(__dirname, ".."), ...env },
  });
}

test("mcp server public exports remain stable", () => {
  assert.deepEqual(Object.keys(serverModule).sort(), [
    "SESSION_LOCK_STALE_MS",
    "TOOLS",
    "TOOL_MANIFEST",
    "appendJsonlLine",
    "applyWaveMerge",
    "assertSafeDomain",
    "attackSurfacePath",
    "authStore",
    "autoSignup",
    "bountyPublicIntel",
    "buildCircuitBreakerSummary",
    "buildCoverageSummaryForSurface",
    "buildHeaderProfile",
    "compactSessionState",
    "computeCoverageRequeueSurfaceIds",
    "coverageJsonlPath",
    "executeTool",
    "filterExclusionsByHosts",
    "findingsJsonlPath",
    "findingsMarkdownPath",
    "gradeArtifactPaths",
    "httpAuditJsonlPath",
    "importHttpTraffic",
    "importStaticArtifact",
    "initSession",
    "listAuthProfiles",
    "listFindings",
    "logCoverage",
    "mergeWaveHandoffs",
    "migrateAuthJson",
    "normalizeCoverageRecord",
    "normalizeFindingRecord",
    "normalizeGradeVerdictDocument",
    "normalizeHttpAuditRecord",
    "normalizeSessionStateDocument",
    "normalizeStringArray",
    "normalizeTrafficRecord",
    "publicIntelPath",
    "rankAttackSurfaces",
    "readAuthJson",
    "readCoverageRecordsFromJsonl",
    "readFindings",
    "readFindingsFromJsonl",
    "readGradeVerdict",
    "readHttpAudit",
    "readHttpAuditRecordsFromJsonl",
    "readHunterBrief",
    "readScopeExclusions",
    "readSessionState",
    "readStateSummary",
    "readStaticArtifactRecordsFromJsonl",
    "readStaticScanResultsFromJsonl",
    "readTrafficRecordsFromJsonl",
    "readVerificationRound",
    "readWaveHandoffs",
    "recordFinding",
    "redactUrlSensitiveValues",
    "renderFindingMarkdownEntry",
    "renderGradeVerdictMarkdown",
    "renderVerificationRoundMarkdown",
    "resolveAuthJsonPath",
    "resolveHunterKnowledge",
    "sessionDir",
    "sessionLockPath",
    "signupDetect",
    "startServer",
    "startWave",
    "statePath",
    "staticArtifactImportDir",
    "staticArtifactPath",
    "staticArtifactsJsonlPath",
    "staticScan",
    "staticScanResultsJsonlPath",
    "summarizeFindings",
    "summarizeStaticScanHints",
    "tempEmail",
    "trafficJsonlPath",
    "transitionPhase",
    "validateScanUrl",
    "verificationRoundPaths",
    "waveHandoffStatus",
    "waveStatus",
    "writeFileAtomic",
    "writeGradeVerdict",
    "writeHandoff",
    "writeVerificationRound",
    "writeWaveHandoff",
  ]);
});

test("MCP tool registry and dispatch cases stay in sync", async () => {
  const toolNames = TOOLS.map((tool) => tool.name);
  assert.deepEqual([...toolNames].sort(), [...new Set(toolNames)].sort(), "tool names must be unique");
  assert.ok(toolNames.every((name) => name.startsWith("bounty_")));
  for (const representativeTool of [
    "bounty_http_scan",
    "bounty_record_finding",
    "bounty_read_hunter_brief",
    "bounty_static_scan",
  ]) {
    assert.ok(toolNames.includes(representativeTool), `${representativeTool} missing from exported registry`);
  }
  assert.ok(!toolNames.includes("bounty_auth_manual"));
  assert.ok(!toolNames.includes("bounty_read_handoff"));
  assert.equal(
    TOOLS.find((tool) => tool.name === "bounty_static_scan").inputSchema.properties.artifact_id.pattern,
    "^SA-[1-9][0-9]*$",
  );

  const dispatchNames = Object.keys(TOOL_HANDLERS);

  assert.deepEqual([...dispatchNames].sort(), [...toolNames].sort());
  assert.deepEqual(Object.keys(TOOL_MANIFEST).sort(), [...toolNames].sort());
  assert.deepEqual(JSON.parse(await executeTool("__unknown_tool__", {})), {
    error: "Unknown tool: __unknown_tool__",
  });
});

test("MCP tool manifest exposes required policy metadata for every tool", () => {
  for (const tool of TOOLS) {
    const metadata = TOOL_MANIFEST[tool.name];
    assert.ok(metadata, `${tool.name} missing manifest metadata`);
    assert.ok(Array.isArray(metadata.role_bundles) && metadata.role_bundles.length > 0);
    assert.equal(typeof metadata.mutating, "boolean");
    assert.equal(typeof metadata.global_preapproval, "boolean");
    assert.equal(typeof metadata.network_access, "boolean");
    assert.equal(typeof metadata.browser_access, "boolean");
    assert.equal(typeof metadata.scope_required, "boolean");
    assert.equal(typeof metadata.sensitive_output, "boolean");
    assert.ok(Array.isArray(metadata.session_artifacts_written));
    assert.equal(typeof metadata.hook_required, "boolean");
  }
});

test("MCP per-tool module pilot preserves representative tool behavior", () => {
  const byName = new Map(TOOLS.map((tool) => [tool.name, tool]));
  assert.equal(byName.get("bounty_read_http_audit").inputSchema.required[0], "target_domain");
  assert.equal(byName.get("bounty_start_wave").inputSchema.properties.assignments.type, "array");
  assert.equal(byName.get("bounty_http_scan").inputSchema.properties.url.type, "string");
  assert.equal(TOOL_MANIFEST.bounty_read_http_audit.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_start_wave.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.network_access, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.scope_required, true);
  assert.equal(TOOL_MANIFEST.bounty_http_scan.hook_required, true);
});

test("MCP tool registry validation rejects incomplete or inconsistent entries", () => {
  const completeModule = {
    name: "bounty_test_tool",
    description: "Test tool.",
    inputSchema: { type: "object", properties: {} },
    handler: () => ({}),
    role_bundles: ["hunter"],
    mutating: false,
    global_preapproval: true,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: [],
    hook_required: false,
  };

  assert.throws(
    () => buildToolRegistry({
      toolModules: [completeModule, { ...completeModule }],
      toolDefinitions: [],
      toolMetadata: {},
      toolHandlers: {},
    }),
    /Duplicate tool name/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, handler: undefined }],
      toolDefinitions: [],
      toolMetadata: {},
      toolHandlers: {},
    }),
    /has no handler/,
  );

  const missingGlobalPreapproval = { ...completeModule };
  delete missingGlobalPreapproval.global_preapproval;
  assert.throws(
    () => buildToolRegistry({
      toolModules: [missingGlobalPreapproval],
      toolDefinitions: [],
      toolMetadata: {},
      toolHandlers: {},
    }),
    /missing global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, global_preapproval: "yes" }],
      toolDefinitions: [],
      toolMetadata: {},
      toolHandlers: {},
    }),
    /invalid global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, role_bundles: ["mystery"] }],
      toolDefinitions: [],
      toolMetadata: {},
      toolHandlers: {},
    }),
    /unknown role bundle mystery/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [],
      toolDefinitions: [{
        name: "bounty_legacy_tool",
        description: "Legacy test tool.",
        inputSchema: { type: "object", properties: {} },
      }],
      toolMetadata: {},
      toolHandlers: { bounty_legacy_tool: () => ({}) },
    }),
    /Missing tool manifest metadata/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [],
      toolDefinitions: [{
        name: "bounty_legacy_tool",
        description: "Legacy test tool.",
        inputSchema: { type: "object", properties: {} },
      }],
      toolMetadata: {
        bounty_legacy_tool: {
          role_bundles: ["hunter"],
          mutating: false,
          global_preapproval: true,
          network_access: false,
          browser_access: false,
          scope_required: false,
          sensitive_output: false,
          session_artifacts_written: [],
          hook_required: false,
        },
      },
      toolHandlers: {},
    }),
    /has no handler/,
  );
});

test("executeTool rejects unknown top-level arguments while allowing nested map-like fields", async () => {
  await withTempHome(async () => {
    const unknown = JSON.parse(await executeTool("bounty_http_scan", {
      method: "GET",
      url: "https://example.com/",
      target_domain: "example.com",
      surprise: true,
    }));
    assert.match(unknown.error, /surprise is not allowed/);

    const traffic = JSON.parse(await executeTool("bounty_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    }));
    assert.equal(traffic.imported, 1);

    const auth = JSON.parse(await executeTool("bounty_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      headers: { "X-Custom": "ok" },
      cookies: { session: "abc" },
      local_storage: { access_token: "eyJabc" },
    }));
    assert.equal(auth.success, true);
  });
});

test("executeTool returns standard envelopes and recursively validates schema arguments", async () => {
  await withTempHome(async () => {
    const unknown = await executeTool("__unknown_tool__", {});
    assert.deepEqual(unknown, {
      ok: false,
      error: { code: "UNKNOWN_TOOL", message: "Unknown tool: __unknown_tool__" },
      meta: { tool: "__unknown_tool__", version: 1 },
    });

    const nested = await executeTool("bounty_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      credentials: {
        email: "a@example.com",
        password: "secret",
        unexpected: true,
      },
    });
    assert.equal(nested.ok, false);
    assert.equal(nested.error.code, "INVALID_ARGUMENTS");
    assert.match(nested.error.message, /credentials\.unexpected is not allowed/);

    const badWave = await executeTool("bounty_log_coverage", {
      target_domain: "example.com",
      wave: "1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [],
    });
    assert.equal(badWave.ok, false);
    assert.equal(badWave.error.code, "INVALID_ARGUMENTS");
    assert.match(badWave.error.message, /wave must match pattern \^w\[0-9\]\+\$/);

    const badEntries = await executeTool("bounty_log_coverage", {
      target_domain: "example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: "not-array",
    });
    assert.equal(badEntries.ok, false);
    assert.equal(badEntries.error.code, "INVALID_ARGUMENTS");
    assert.match(badEntries.error.message, /entries must be array/);

    const traffic = await executeTool("bounty_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    });
    assert.equal(traffic.ok, true);
    assert.equal(traffic.data.imported, 1);
  });
});

test("MCP message handler lists tools, routes calls, and wraps thrown errors", async () => {
  const sent = [];
  const calls = [];
  const handleMessage = createMcpMessageHandler({
    tools: [{ name: "bounty_fake", inputSchema: { type: "object" } }],
    executeTool: async (name, args) => {
      calls.push({ name, args });
      if (name === "bounty_throw") {
        throw new Error("boom");
      }
      return { ok: true, args };
    },
    send: (message) => sent.push(message),
  });

  await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  await handleMessage({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "bounty_fake", arguments: { x: 1 } },
  });
  await handleMessage({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "bounty_throw", arguments: {} },
  });

  assert.deepEqual(sent[0], {
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "bounty_fake", inputSchema: { type: "object" } }] },
  });
  assert.deepEqual(calls, [
    { name: "bounty_fake", args: { x: 1 } },
    { name: "bounty_throw", args: {} },
  ]);
  assert.deepEqual(JSON.parse(sent[1].result.content[0].text), { ok: true, args: { x: 1 } });
  assert.deepEqual(JSON.parse(sent[2].result.content[0].text), {
    ok: false,
    error: { code: "INTERNAL_ERROR", message: "boom" },
    meta: { tool: "bounty_throw", version: 1 },
  });
});

test("stdio transport accepts framed and raw JSON-RPC messages", () => {
  const framedOutput = [];
  const framedServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => framedOutput.push(String(chunk)) },
    stderr: { write() {} },
  });
  const framedBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });

  framedServer.handleChunk(`Content-Length: ${Buffer.byteLength(framedBody)}\r\n\r\n${framedBody}`);

  const framedResponse = framedOutput.join("");
  const framedPayload = JSON.parse(framedResponse.slice(framedResponse.indexOf("\r\n\r\n") + 4));
  assert.deepEqual(framedPayload, { jsonrpc: "2.0", id: 1, result: {} });

  const rawOutput = [];
  const rawServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => rawOutput.push(String(chunk)) },
    stderr: { write() {} },
  });

  rawServer.handleChunk(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\n`);

  assert.deepEqual(JSON.parse(rawOutput.join("").trim()), { jsonrpc: "2.0", id: 2, result: {} });
});

test("bounty_init_session creates the initial state and bounty_read_session_state returns public fields only", () => {
  withTempHome(() => {
    const domain = "example.com";
    const targetUrl = "https://example.com";
    const expectedState = {
      target: domain,
      target_url: targetUrl,
      phase: "RECON",
      hunt_wave: 0,
      pending_wave: null,
      total_findings: 0,
      explored: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      scope_exclusions: [],
      hold_count: 0,
      auth_status: "pending",
    };

    const created = JSON.parse(initSession({ target_domain: domain, target_url: targetUrl }));
    assert.deepEqual(created, {
      version: 1,
      created: true,
      session_dir: sessionDir(domain),
      state: expectedState,
    });

    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.deepEqual(rawState, expectedState);
    assert.deepEqual(JSON.parse(readSessionState({ target_domain: domain })), {
      version: 1,
      state: expectedState,
    });
  });
});

test("bounty_init_session rejects existing state and non-empty session dirs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "RECON" });
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      /Session already initialized:/,
    );

    const otherDomain = "example.org";
    const otherDir = sessionDir(otherDomain);
    fs.mkdirSync(otherDir, { recursive: true });
    fs.writeFileSync(path.join(otherDir, "stray.txt"), "x");
    assert.throws(
      () => initSession({ target_domain: otherDomain, target_url: "https://example.org" }),
      /Session directory is not empty:/,
    );
  });
});

test("bounty_init_session ignores .session.lock when checking if the session dir is empty", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);

    const result = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(result.created, true);
    assert.ok(fs.existsSync(statePath(domain)));
  });
});

test("missing session state errors surface on read and mutating state tools", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(() => readSessionState({ target_domain: domain }), /Missing session state:/);
    assert.throws(() => transitionPhase({ target_domain: domain, to_phase: "AUTH" }), /Missing session state:/);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Missing session state:/,
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Missing session state:/,
    );
  });
});

test("legacy state normalization is applied while unknown fields remain on disk across writes", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target: "other.com",
      target_url: "https://example.com",
      phase: "RECON",
      extra_field: "keep-me",
    }, null, 2)}\n`);

    assert.deepEqual(JSON.parse(readSessionState({ target_domain: domain })), {
      version: 1,
      state: {
        target: domain,
        target_url: "https://example.com",
        phase: "RECON",
        hunt_wave: 0,
        pending_wave: null,
        total_findings: 0,
        explored: [],
        dead_ends: [],
        waf_blocked_endpoints: [],
        lead_surface_ids: [],
        scope_exclusions: [],
        hold_count: 0,
        auth_status: "pending",
      },
    });

    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "AUTH" }));
    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(rawState.extra_field, "keep-me");
    assert.equal(rawState.target, domain);
    assert.equal(rawState.phase, "AUTH");
  });
});

test("malformed legacy state hard-fails session reads", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target_url: "https://example.com",
      phase: "BOGUS",
    }, null, 2)}\n`);

    assert.throws(() => readSessionState({ target_domain: domain }), /Malformed session state:/);
  });
});

test("bounty_transition_phase allows the configured edges and increments hold_count on GRADE -> HUNT", () => {
  withTempHome(() => {
    const domain = "example.com";
    const cases = [
      { from: "RECON", to: "AUTH" },
      { from: "AUTH", to: "HUNT", auth_status: "authenticated" },
      { from: "HUNT", to: "CHAIN" },
      { from: "CHAIN", to: "VERIFY" },
      { from: "VERIFY", to: "GRADE" },
      { from: "GRADE", to: "REPORT" },
      { from: "GRADE", to: "HUNT", hold_count: 1 },
    ];

    for (const scenario of cases) {
      seedSessionState(domain, {
        phase: scenario.from,
        hold_count: scenario.hold_count ?? 0,
      });

      const result = JSON.parse(transitionPhase({
        target_domain: domain,
        to_phase: scenario.to,
        auth_status: scenario.auth_status,
      }));

      assert.equal(result.transitioned, true);
      assert.equal(result.from_phase, scenario.from);
      assert.equal(result.to_phase, scenario.to);
      assert.equal(result.state.phase, scenario.to);

      if (scenario.from === "AUTH") {
        assert.equal(result.state.auth_status, "authenticated");
      }
      if (scenario.from === "GRADE" && scenario.to === "HUNT") {
        assert.equal(result.state.hold_count, 2);
      }
    }
  });
});

test("bounty_transition_phase rejects invalid edges and stray auth_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "RECON" });
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "HUNT" }),
      /Invalid phase transition: RECON -> HUNT/,
    );
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "AUTH", auth_status: "authenticated" }),
      /auth_status is only allowed for AUTH -> HUNT/,
    );

    seedSessionState(domain, { phase: "AUTH" });
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "HUNT" }),
      /auth_status is required for AUTH -> HUNT/,
    );
  });
});

test("session lock busy blocks mutating tools and stale locks are recoverable", () => {
  withTempHome(() => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "AUTH" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);
    const created = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(created.created, true);
  });
});

test("bounty_start_wave validates inputs, writes assignments, and updates pending_wave", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const expectedState = {
      target: domain,
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 2,
      total_findings: 0,
      explored_count: 0,
      dead_ends_count: 0,
      waf_blocked_count: 0,
      lead_surface_ids: [],
      hold_count: 0,
      auth_status: "pending",
    };

    const result = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }));

    assert.deepEqual({
      ...result,
      assignments: result.assignments.map(({ handoff_token, ...assignment }) => {
        assert.match(handoff_token, /^[A-Za-z0-9_-]{32}$/);
        return assignment;
      }),
    }, {
      version: 1,
      started: true,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
      assignments_path: path.join(sessionDir(domain), "wave-2-assignments.json"),
      state: expectedState,
    });
    const assignmentDoc = JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "wave-2-assignments.json"), "utf8"));
    assert.ok(assignmentDoc.assignments.every((assignment) => /^[a-f0-9]{64}$/.test(assignment.handoff_token_sha256)));
    assert.doesNotMatch(JSON.stringify(assignmentDoc), new RegExp(result.assignments[0].handoff_token));
  });
});

test("bounty_start_wave rejects invalid state, duplicate inputs, and pre-existing assignment files", () => {
  withTempHome(() => {
    const domain = "example.com";

    seedSessionState(domain, { phase: "AUTH" });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires phase HUNT or EXPLORE/,
    );

    seedSessionState(domain, { phase: "HUNT", pending_wave: 3 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 4, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires pending_wave null/,
    );

    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 5, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /wave_number must equal hunt_wave \+ 1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a1", surface_id: "surface-b" },
        ],
      }),
      /Duplicate assignment for a1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a2", surface_id: "surface-a" },
        ],
      }),
      /Duplicate surface_id in assignments: surface-a/,
    );
    seedAttackSurface(domain, ["surface-a"]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-z" }] }),
      /Unknown surface_id in assignments: surface-z/,
    );

    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Assignment file already exists:/,
    );
  });
});

test("bounty_start_wave rolls back the assignment file if the state write fails", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const originalRenameSync = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (to === statePath(domain)) {
        throw new Error("boom");
      }
      return originalRenameSync(from, to);
    };

    try {
      assert.throws(
        () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
        /State write failed after writing assignments; rollback succeeded:/,
      );
    } finally {
      fs.renameSync = originalRenameSync;
    }

    assert.ok(!fs.existsSync(path.join(sessionDir(domain), "wave-1-assignments.json")));
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).pending_wave, null);
  });
});

test("bounty_apply_wave_merge returns pending without mutating state when handoffs are incomplete", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const before = fs.readFileSync(statePath(domain), "utf8");
    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result, {
      version: 1,
      status: "pending",
      wave_number: 1,
      force_merge: false,
      readiness: {
        assignments_total: 2,
        handoffs_total: 1,
        received_agents: ["a1"],
        missing_agents: ["a2"],
        unexpected_agents: [],
        is_complete: false,
      },
      state: JSON.parse(readStateSummary({ target_domain: domain })).state,
    });
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
  });
});

test("bounty_apply_wave_merge merges state, findings, requeues, and scope exclusions", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      dead_ends: ["/existing"],
      waf_blocked_endpoints: ["/old-waf"],
      lead_surface_ids: ["surface-c"],
    });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d"]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: ["/new-dead-end"],
      lead_surface_ids: ["surface-a", "surface-c"],
    });
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      waf_blocked_endpoints: ["/new-waf"],
      lead_surface_ids: ["surface-d", "surface-x"],
    });

    seedFinding(domain, { wave: "w1", agent: "a1", severity: "high" });
    seedFinding(domain, {
      wave: "w1",
      agent: "a2",
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves exploit development.",
    });

    fs.writeFileSync(path.join(sessionDir(domain), "scope-warnings.log"), [
      "[2026-01-01T00:00:00Z] OUT-OF-SCOPE: OOS.example.net (command: curl https://OOS.example.net)",
      "[2026-01-01T00:00:01Z] OUT-OF-SCOPE (http_scan): api.other.example (url: https://api.other.example/admin)",
    ].join("\n"));

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.readiness, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
    assert.deepEqual(result.merge, {
      received_agents: ["a1", "a2"],
      invalid_agents: [],
      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      requeue_surface_ids: ["surface-b"],
      new_dead_ends_count: 1,
      new_waf_blocked_count: 1,
      lead_surface_ids: ["surface-a", "surface-c", "surface-d", "surface-x"],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: ["a1", "a2"],
      },
    });
    assert.deepEqual(result.findings, {
      total: 2,
      by_severity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
    });
    // compact state returns counts, not arrays — verify via full state read
    assert.equal(result.state.explored_count, 1);
    assert.equal(result.state.dead_ends_count, 2);
    assert.equal(result.state.waf_blocked_count, 2);
    assert.deepEqual(result.state.lead_surface_ids, ["surface-c", "surface-d"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 1);
    assert.equal(result.state.total_findings, 2);
    // verify full state on disk has the arrays
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.explored, ["surface-a"]);
    assert.deepEqual(fullState.dead_ends, ["/existing", "/new-dead-end"]);
    assert.deepEqual(fullState.waf_blocked_endpoints, ["/old-waf", "/new-waf"]);
    assert.deepEqual(fullState.scope_exclusions, ["oos.example.net", "api.other.example"]);
    assert.deepEqual(readScopeExclusions(domain), ["oos.example.net", "api.other.example"]);
  });
});

test("bounty_apply_wave_merge requeues unfinished coverage without treating tested or blocked as unfinished", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
      { agent: "a4", surface_id: "surface-d" },
      { agent: "a5", surface_id: "surface-e" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/v1/export",
        method: "GET",
        bug_class: "idor",
        auth_profile: "attacker-victim",
        status: "promising",
        evidence_summary: "victim replay changed response size",
        next_step: "test CSV export variant",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "promising",
          evidence_summary: "initial IDOR suspicion",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "tested",
          evidence_summary: "latest replay returned 403 for attacker and victim",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a3",
      surface_id: "surface-c",
      entries: [{
        endpoint: "/search",
        method: "POST",
        bug_class: "xss",
        status: "blocked",
        evidence_summary: "WAF blocks reflected payloads",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a4",
      surface_id: "surface-d",
      entries: [{
        endpoint: "/billing/refunds",
        method: "POST",
        bug_class: "business_logic",
        status: "needs_auth",
        evidence_summary: "refund path requires a victim billing role",
        next_step: "retry after victim billing profile exists",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a5",
      surface_id: "surface-e",
      entries: [{
        endpoint: "/api/v2/admin/export",
        method: "GET",
        bug_class: "authz",
        status: "requeue",
        evidence_summary: "admin export route discovered late in the wave",
        next_step: "test admin role boundaries",
      }],
    });

    for (const [agent, surfaceId] of [
      ["a1", "surface-a"],
      ["a2", "surface-b"],
      ["a3", "surface-c"],
      ["a4", "surface-d"],
      ["a5", "surface-e"],
    ]) {
      writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent,
        surface_id: surfaceId,
        surface_status: "complete",
        summary: `${agent} complete.`,
        content: `# ${agent}`,
      });
    }

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.merge.completed_surface_ids, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);
    assert.deepEqual(result.merge.partial_surface_ids, []);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-a", "surface-d", "surface-e"]);

    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.explored, ["surface-b", "surface-c"]);
  });
});

test("bounty_apply_wave_merge preserves existing scope exclusions when the log is absent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      pending_wave: 1,
      scope_exclusions: ["legacy.example"],
    });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedAttackSurface(domain, ["surface-a"]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    // compact state doesn't include scope_exclusions — verify via full state read
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.scope_exclusions, ["legacy.example"]);
  });
});

test("bounty_apply_wave_merge force-merges missing and invalid handoffs and computes requeue_surface_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", pending_wave: 2, hunt_wave: 1 });
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c"]);

    writeFileAtomic(path.join(sessionDir(domain), "handoff-w2-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a3",
      surface_id: "surface-c",
      surface_status: "partial",
      summary: "A3 partial.",
      content: "# A3",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 2,
      force_merge: true,
    }));

    assert.equal(result.status, "merged");
    assert.equal(result.force_merge, true);
    assert.deepEqual(result.merge.invalid_agents, ["a1"]);
    assert.deepEqual(result.merge.missing_surface_ids, ["surface-b"]);
    assert.deepEqual(result.merge.partial_surface_ids, ["surface-c"]);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-c", "surface-b", "surface-a"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 2);
  });
});

test("bounty_apply_wave_merge rejects invalid state invariants and hard-fails on missing or malformed attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "CHAIN", pending_wave: 1 });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Wave merge requires phase HUNT or EXPLORE/,
    );

    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Missing attack surface JSON:/,
    );

    writeFileAtomic(attackSurfacePath(domain), "{bad json");
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Malformed attack surface JSON:/,
    );
  });
});

test("bounty_write_wave_handoff rejects unassigned or mismatched handoffs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Invalid agent handoff.",
        content: "# nope",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Mismatched surface handoff.",
        content: "# nope",
      }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
  });
});

test("bounty_record_finding rejects partial or invalid wave metadata and still allows null/null", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
      }),
      /wave and agent must either both be provided or both be omitted/,
    );

    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a1",
      }),
      /surface_id must be a non-empty string/,
    );
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-a",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    const recorded = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Unscoped finding",
      severity: "low",
      endpoint: "/b",
      description: "d",
      proof_of_concept: "poc",
      validated: true,
      wave: null,
      agent: null,
    }));
    assert.equal(recorded.recorded, true);

    const finding = JSON.parse(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim());
    assert.equal(finding.wave, null);
    assert.equal(finding.agent, null);
    assert.equal(finding.surface_id, null);
    assert.equal(finding.auth_profile, null);
  });
});

test("bounty_write_handoff still writes SESSION_HANDOFF.md without wave fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(writeHandoff({
      target_domain: domain,
      session_number: 7,
      target_url: "https://example.com",
      explored_with_results: ["surface-a"],
      must_do_next: [{ priority: "P1", description: "Keep testing surface-a" }],
    }));

    const handoffPath = path.join(sessionDir(domain), "SESSION_HANDOFF.md");
    assert.equal(result.written, handoffPath);
    assert.ok(fs.existsSync(handoffPath));

    const content = fs.readFileSync(handoffPath, "utf8");
    assert.match(content, /# Handoff — Session 7/);
    assert.match(content, /## Explored/);
    assert.doesNotMatch(content, /handoff-w7-a1/);
  });
});

test("bounty_write_wave_handoff writes matching markdown and json with normalized defaults", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const content = "# Handoff\n\nFreeform markdown.";
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Freeform handoff summary.",
      content,
    }));

    assert.ok(fs.existsSync(result.written_md));
    assert.ok(fs.existsSync(result.written_json));
    assert.equal(fs.readFileSync(result.written_md, "utf8"), content);

    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.deepEqual(payload, {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      provenance: "legacy_unverified",
      summary: "Freeform handoff summary.",
      chain_notes: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
  });
});

test("tokenized wave handoffs require the correct token and report verified provenance", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);
    const token = started.data.assignments[0].handoff_token;
    const assignmentText = fs.readFileSync(path.join(sessionDir(domain), "wave-1-assignments.json"), "utf8");
    assert.doesNotMatch(assignmentText, new RegExp(token));
    assert.match(assignmentText, /handoff_token_sha256/);

    const missing = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "INVALID_ARGUMENTS");
    assert.match(missing.error.message, /handoff_token is required/);

    const wrong = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: "wrong-token-value",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.error.code, "INVALID_ARGUMENTS");
    assert.match(wrong.error.message, /handoff_token does not match/);

    const written = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "Tested the assigned surface.",
      chain_notes: ["No chainable primitive found."],
      content: "# handoff",
    });
    assert.equal(written.ok, true);
    assert.equal(written.data.provenance, "verified");

    const handoffs = await executeTool("bounty_read_wave_handoffs", {
      target_domain: domain,
      wave_number: 1,
    });
    assert.equal(handoffs.ok, true);
    assert.equal(handoffs.data.handoffs[0].provenance, "verified");
    assert.equal(handoffs.data.handoffs[0].summary, "Tested the assigned surface.");
    assert.deepEqual(handoffs.data.handoffs[0].chain_notes, ["No chainable primitive found."]);

    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.deepEqual(merged.data.merge.provenance, {
      verified_agents: ["a1"],
      legacy_unverified_agents: [],
    });
  });
});

test("executeTool smoke path uses envelopes for init, wave, handoff, and merge", async () => {
  await withTempHome(async () => {
    const domain = "smoke.example";
    const init = await executeTool("bounty_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(init.ok, true);

    seedAttackSurface(domain, ["surface-a"]);
    assert.equal((await executeTool("bounty_transition_phase", { target_domain: domain, to_phase: "AUTH" })).ok, true);
    assert.equal((await executeTool("bounty_transition_phase", {
      target_domain: domain,
      to_phase: "HUNT",
      auth_status: "unauthenticated",
    })).ok, true);

    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);

    const handoff = await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "Smoke handoff summary.",
      chain_notes: ["Smoke chain note."],
      content: "# Smoke",
    });
    assert.equal(handoff.ok, true);

    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.equal(merged.data.state.hunt_wave, 1);
  });
});

test("hunter SubagentStop hook blocks missing final marker", () => {
  withTempHome((tempHome) => {
    const result = runHunterSubagentStop({
      last_assistant_message: "I wrote notes but no marker.",
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /BOB_HUNTER_DONE/);
    assert.match(result.stderr, /bounty_write_wave_handoff/);
  });
});

test("hunter SubagentStop hook blocks missing structured handoff", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /must call bounty_write_wave_handoff/);
  });
});

test("hunter SubagentStop hook blocks invalid structured handoff", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /wrote an invalid handoff/);
  });
});

test("hunter SubagentStop hook allows incomplete waves without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    });
    const token = started.data.assignments.find((assignment) => assignment.agent === "a1").handoff_token;
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "a1 complete",
      content: "# a1",
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.hunt_wave, 0);
  });
});

test("hunter SubagentStop hook allows a complete wave without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.hunt_wave, 0);
  });
});

test("hunter SubagentStop hook treats stale completion notifications as valid handoffs", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bounty_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bounty_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });
    const merged = await executeTool("bounty_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");

    const result = runHunterSubagentStop({
      last_assistant_message: 'BOB_HUNTER_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, null);
    assert.equal(state.hunt_wave, 1);
  });
});

test("bounty_log_coverage appends validated records to coverage.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const result = JSON.parse(logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "attacker/victim replay both returned 403",
          next_step: "try legacy export route",
        },
        {
          endpoint: "/api/v1/export",
          bug_class: "business_logic",
          status: "promising",
          evidence_summary: "export job accepted attacker-controlled account_id",
        },
      ],
    }));

    assert.equal(result.appended, 2);
    assert.equal(result.log_path, coverageJsonlPath(domain));
    assert.deepEqual(result.statuses, {
      tested: 1,
      blocked: 0,
      promising: 1,
      needs_auth: 0,
      requeue: 0,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, 2);
    assert.equal(records[0].target_domain, domain);
    assert.equal(records[0].method, "GET");
    assert.equal(records[0].bug_class, "idor");
    assert.equal(records[0].auth_profile, "attacker-victim");
    assert.equal(records[0].next_step, "try legacy export route");
    assert.equal(records[1].method, null);
  });
});

test("appendJsonlLine retention keeps the newest records", () => {
  withTempHome((tempHome) => {
    const logPath = path.join(tempHome, "retention.jsonl");
    for (let index = 0; index < 5; index += 1) {
      appendJsonlLine(logPath, { index }, { maxRecords: 3 });
    }

    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [2, 3, 4],
    );

    const trimResult = trimJsonlFile(logPath, 2);
    assert.deepEqual(trimResult, { trimmed: true, total: 3, retained: 2 });
    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [3, 4],
    );
  });
});

test("coverage log retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const entries = Array.from({ length: COVERAGE_LOG_MAX_RECORDS + 1 }, (_, index) => ({
      endpoint: `/api/coverage-${index}`,
      bug_class: "idor",
      status: "tested",
      evidence_summary: `coverage ${index}`,
    }));

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, COVERAGE_LOG_MAX_RECORDS);
    assert.equal(records[0].endpoint, "/api/coverage-1");
    assert.equal(records.at(-1).endpoint, `/api/coverage-${COVERAGE_LOG_MAX_RECORDS}`);
  });
});

test("HTTP audit retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    for (let index = 0; index < HTTP_AUDIT_LOG_MAX_RECORDS + 1; index += 1) {
      appendHttpAuditRecord({
        version: 1,
        ts: new Date(index).toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${domain}/audit-${index}`,
        host: domain,
        scope_decision: "allowed",
        status: 200,
      });
    }

    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, HTTP_AUDIT_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/audit-1");
    assert.equal(records.at(-1).path, `/audit-${HTTP_AUDIT_LOG_MAX_RECORDS}`);
  });
});

test("imported traffic retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    let nextIndex = 0;
    const totalEntries = TRAFFIC_LOG_MAX_RECORDS + 1;

    while (nextIndex < totalEntries) {
      const batchSize = Math.min(TRAFFIC_IMPORT_MAX_ENTRIES, totalEntries - nextIndex);
      const entries = Array.from({ length: batchSize }, (_, offset) => {
        const index = nextIndex + offset;
        return {
          method: "GET",
          url: `https://${domain}/traffic-${index}`,
          status: 200,
        };
      });

      importHttpTraffic({
        target_domain: domain,
        source: "manual",
        entries,
      });
      nextIndex += batchSize;
    }

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, TRAFFIC_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/traffic-1");
    assert.equal(records.at(-1).path, `/traffic-${TRAFFIC_LOG_MAX_RECORDS}`);
  });
});

test("bounty_log_coverage rejects invalid assignment metadata and malformed entries", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const validEntry = {
      endpoint: "/api/v1/users/123",
      bug_class: "idor",
      status: "tested",
      evidence_summary: "403 for attacker and victim",
    };

    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "1", agent: "a1", surface_id: "surface-a", entries: [validEntry] }),
      /wave must match wN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "agent1", surface_id: "surface-a", entries: [validEntry] }),
      /agent must match aN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a2", surface_id: "surface-a", entries: [validEntry] }),
      /Agent a2 is not assigned in wave w1/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-b", entries: [validEntry] }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a", entries: [] }),
      /entries must be a non-empty array/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, status: "done" }],
      }),
      /entries\[0\]\.status must be one of tested, blocked, promising, needs_auth, requeue/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, endpoint: " " }],
      }),
      /entries\[0\]\.endpoint must be a non-empty string/,
    );
  });
});

test("bounty_wave_handoff_status reports complete when all assigned handoffs exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
    });

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));

    assert.deepEqual(status, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("markdown-only handoffs do not satisfy readiness or advance merges", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(dir, "handoff-w1-a1.md"), "# markdown only\n");

    const before = fs.readFileSync(statePath(domain), "utf8");
    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));
    assert.deepEqual(status, {
      assignments_total: 1,
      handoffs_total: 0,
      received_agents: [],
      missing_agents: ["a1"],
      unexpected_agents: [],
      is_complete: false,
    });

    const pending = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(pending.status, "pending");
    assert.deepEqual(pending.readiness, status);
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
    assert.ok(!fs.existsSync(path.join(dir, "wave-2-assignments.json")));

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Structured handoff summary.",
      content: "# structured handoff",
    });

    const merged = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(merged.status, "merged");
    assert.deepEqual(merged.readiness, {
      assignments_total: 1,
      handoffs_total: 1,
      received_agents: ["a1"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("bounty_wave_handoff_status reports partial completion and unexpected handoffs without parsing payloads", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w2-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w2", "a9");

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(status, {
      assignments_total: 3,
      handoffs_total: 2,
      received_agents: ["a1"],
      missing_agents: ["a2", "a3"],
      unexpected_agents: ["a9"],
      is_complete: false,
    });
  });
});

test("bounty_wave_handoff_status hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => waveHandoffStatus({ target_domain: "example.com", wave_number: 7 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_merge_wave_handoffs merges valid handoffs and dedupes optional arrays", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: [" /users/1 ", "/users/1", ""],
      waf_blocked_endpoints: ["/admin"],
      lead_surface_ids: ["surface-b", "surface-b", "surface-c"],
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      dead_ends: ["/billing"],
      waf_blocked_endpoints: ["/admin", " /reports "],
      lead_surface_ids: ["surface-c", "surface-d"],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      invalid_agents: [],
      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      dead_ends: ["/users/1", "/billing"],
      waf_blocked_endpoints: ["/admin", "/reports"],
      lead_surface_ids: ["surface-b", "surface-c", "surface-d"],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: ["a1", "a2"],
      },
    });
  });
});

test("bounty_merge_wave_handoffs requeues missing and invalid assigned handoffs while ignoring unexpected agents", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 3, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w3-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w3", "a9", { dead_ends: ["/ignored"] });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 3 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: [],
      invalid_agents: ["a1"],
      unexpected_agents: ["a9"],
      completed_surface_ids: [],
      partial_surface_ids: [],
      missing_surface_ids: ["surface-b"],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      provenance: {
        verified_agents: [],
        legacy_unverified_agents: [],
      },
    });
  });
});

test("bounty_read_wave_handoffs returns validated structured summaries and ignores markdown", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      content: "# ignored markdown details",
      dead_ends: ["/old"],
      lead_surface_ids: ["surface-b"],
    });
    writeFileAtomic(path.join(dir, "handoff-w1-a2.md"), "# markdown only\n");

    const result = JSON.parse(readWaveHandoffs({ target_domain: domain }));
    assert.deepEqual(result.wave_numbers, [1]);
    assert.deepEqual(result.handoffs, [{
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      provenance: "legacy_unverified",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      dead_ends: ["/old"],
      waf_blocked_endpoints: [],
      lead_surface_ids: ["surface-b"],
    }]);
    assert.deepEqual(result.missing_handoffs, [{ wave: "w1", agent: "a2", surface_id: "surface-b" }]);
    assert.deepEqual(result.invalid_handoffs, []);
    assert.deepEqual(result.unexpected_handoffs, []);
  });
});

test("bounty_merge_wave_handoffs hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => mergeWaveHandoffs({ target_domain: "example.com", wave_number: 4 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_record_finding appends findings.jsonl and bounty_read_findings preserves insertion order", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const second = seedFinding(domain, {
      title: "Stored XSS in comments",
      severity: "medium",
      endpoint: "/comments",
      description: "Unsanitized comment body executes in admin view.",
      proof_of_concept: "<script>alert(1)</script>",
      response_evidence: "<script>alert(1)</script>",
      impact: "Admin session compromise.",
      wave: "w2",
      agent: "a2",
    });

    assert.equal(first.finding_id, "F-1");
    assert.equal(second.finding_id, "F-2");

    const findingsPath = findingsJsonlPath(domain);
    const jsonlLines = fs.readFileSync(findingsPath, "utf8").trim().split("\n");
    assert.equal(jsonlLines.length, 2);
    assert.equal(JSON.parse(jsonlLines[0]).id, "F-1");
    assert.equal(JSON.parse(jsonlLines[1]).id, "F-2");

    const readResult = JSON.parse(readFindings({ target_domain: domain }));
    assert.match(readResult.findings[0].dedupe_key, /^[a-f0-9]{24}$/);
    assert.match(readResult.findings[1].dedupe_key, /^[a-f0-9]{24}$/);
    const readResultWithoutDedupeKeys = {
      ...readResult,
      findings: readResult.findings.map(({ dedupe_key, ...finding }) => finding),
    };
    assert.deepEqual(readResultWithoutDedupeKeys, {
      version: 1,
      target_domain: domain,
      findings: [
        {
          id: "F-1",
          target_domain: domain,
          title: "IDOR on account export",
          severity: "high",
          cwe: "CWE-639",
          endpoint: "/api/export",
          description: "Authenticated user can export another account's data by changing account_id.",
          proof_of_concept: "curl https://example.com/api/export?account_id=2",
          response_evidence: "{\"account_id\":2}",
          impact: "Cross-account PII disclosure.",
          validated: true,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
          auth_profile: null,
        },
        {
          id: "F-2",
          target_domain: domain,
          title: "Stored XSS in comments",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "/comments",
          description: "Unsanitized comment body executes in admin view.",
          proof_of_concept: "<script>alert(1)</script>",
          response_evidence: "<script>alert(1)</script>",
          impact: "Admin session compromise.",
          validated: true,
          wave: "w2",
          agent: "a2",
          surface_id: "surface-a",
          auth_profile: null,
        },
      ],
    });
  });
});

test("bounty_record_finding still writes readable findings.md", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const markdown = fs.readFileSync(findingsMarkdownPath(domain), "utf8");
    assert.match(markdown, /## FINDING 1 \(HIGH\): IDOR on account export/);
    assert.match(markdown, /\*\*ID:\*\* F-1/);
    assert.match(markdown, /curl https:\/\/example.com\/api\/export\?account_id=2/);
  });
});

test("bounty_record_finding deduplicates exact findings unless force_record is set", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const duplicate = seedFinding(domain);

    assert.equal(first.finding_id, "F-1");
    assert.equal(duplicate.recorded, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.finding_id, "F-1");
    assert.equal(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").length, 1);

    const forced = seedFinding(domain, { force_record: true });
    assert.equal(forced.recorded, true);
    assert.equal(forced.finding_id, "F-2");
    assert.equal(forced.force_record, true);

    const records = fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(records.length, 2);
    assert.equal(records[1].force_record, true);
    assert.equal(records[0].dedupe_key, records[1].dedupe_key);
  });
});

test("bounty_record_finding returns warning metadata when markdown sync fails after JSONL success", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(path.join(dir, "findings.md"), { recursive: true });

    const result = seedFinding(domain);

    assert.equal(result.recorded, true);
    assert.equal(result.finding_id, "F-1");
    assert.ok(result.markdown_sync_error);
    assert.equal(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").length, 1);
    assert.ok(fs.statSync(path.join(dir, "findings.md")).isDirectory());
  });
});

test("bounty_read_findings, bounty_list_findings, and bounty_wave_status return empty-state results when findings.jsonl is absent", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.deepEqual(JSON.parse(readFindings({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      findings: [],
    });
    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 0,
      findings: [],
    });
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status, {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      has_high_or_critical: false,
      coverage: null,
      http_audit: { total: 0, shown: 0, omitted: 0, cap: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, errors: 0, scope_blocked: 0, recent: [] },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, note: null },
      findings_summary: [],
    });
  });
});

test("malformed findings.jsonl hard-fails bounty_read_findings, bounty_list_findings, and bounty_wave_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      findingsJsonlPath(domain),
      `${JSON.stringify({
        id: "F-1",
        target_domain: domain,
        title: "Valid first line",
        severity: "low",
        cwe: null,
        endpoint: "/ok",
        description: "Still valid.",
        proof_of_concept: "curl https://example.com/ok",
        response_evidence: null,
        impact: null,
        validated: true,
        wave: null,
        agent: null,
      })}\nnot-json\n`,
    );

    assert.throws(() => readFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => listFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => waveStatus({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
  });
});

test("bounty_list_findings and bounty_wave_status keep their external shapes while reading findings.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "critical" });
    seedFinding(domain, {
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves exploit development.",
      wave: null,
      agent: null,
    });

    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 2,
      findings: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
        },
      ],
    });

    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 2,
      by_severity: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
      coverage: null,
      http_audit: { total: 0, shown: 0, omitted: 0, cap: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, errors: 0, scope_blocked: 0, recent: [] },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, note: null },
      findings_summary: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
          wave_agent: "w1/a1",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
          wave_agent: null,
        },
      ],
    });
  });
});

test("bounty_write_verification_round writes the correct JSON and markdown pair for each round", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    for (const round of ["brutalist", "balanced", "final"]) {
      const result = JSON.parse(writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [],
      }));
      const paths = verificationRoundPaths(domain, round);

      assert.equal(result.round, round);
      assert.equal(result.results_count, 0);
      assert.equal(result.written_json, paths.json);
      assert.equal(result.written_md, paths.markdown);

      assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
      assert.match(fs.readFileSync(paths.markdown, "utf8"), /No verification results recorded\./);

      assert.deepEqual(JSON.parse(readVerificationRound({ target_domain: domain, round })), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
    }
  });
});

test("bounty_write_verification_round accepts notes null and validates duplicate and unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [
        {
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Still exploitable.",
        },
        {
          finding_id: "F-1",
          disposition: "downgraded",
          severity: "medium",
          reportable: true,
          reasoning: "Duplicate entry should fail.",
        },
      ],
    }), /Duplicate finding_id in results: F-1/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Unknown ID.",
        },
      ],
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_write_verification_round rejects balanced/final rounds that drop prior-round findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedFinding(domain, { title: "Second finding", endpoint: "/api/second" });

    const fullResult = (id) => ({
      finding_id: id,
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Valid.",
    });

    // Write brutalist round with both findings
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Balanced round missing F-2 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1")],
    }), /balanced round is missing 1 finding.*F-2/);

    // Balanced round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Final round missing F-1 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-2")],
    }), /final round is missing 1 finding.*F-1/);

    // Final round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });
  });
});

test("bounty_write_verification_round requires valid prior round artifacts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [],
    }), /Missing brutalist verification round JSON/);

    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [],
    });
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [],
    }), /Missing balanced verification round JSON/);
  });
});

test("bounty_read_verification_round hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Missing final verification round JSON/,
    );

    const paths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Malformed final verification round JSON/,
    );
  });
});

test("bounty_read_verification_round rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = verificationRoundPaths(domain, "balanced");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Manually edited bad artifact.",
        },
      ],
    }, null, 2)}\n`);

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "balanced" }),
      /Unknown finding_id: F-99/,
    );
  });
});

test("bounty_write_grade_verdict writes grade.json and grade.md and accepts empty findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const result = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }));
    const paths = gradeArtifactPaths(domain);

    assert.equal(result.verdict, "SKIP");
    assert.equal(result.findings_count, 0);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /No graded findings\./);

    assert.deepEqual(JSON.parse(readGradeVerdict({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
  });
});

test("bounty_write_grade_verdict enforces score totals, thresholds, and final reportability", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const verified = [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }];
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({ target_domain: domain, round, notes: null, results: verified });
    }

    const gradeFinding = {
      finding_id: "F-1",
      impact: 20,
      proof_quality: 10,
      severity_accuracy: 5,
      chain_potential: 5,
      report_quality: 5,
      total_score: 45,
      feedback: null,
    };

    const valid = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }));
    assert.equal(valid.verdict, "SUBMIT");

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 44,
      findings: [gradeFinding],
      feedback: null,
    }), /total_score must equal the maximum per-finding score/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SUBMIT/);
  });
});

test("bounty_write_grade_verdict rejects submit when final verification has no medium-or-higher reportable finding", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const unreportable = [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }];
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({ target_domain: domain, round, notes: null, results: unreportable });
    }

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 45,
        feedback: null,
      }],
      feedback: null,
    }), /expected SKIP/);
  });
});

test("bounty_write_grade_verdict rejects duplicate or unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 80,
      findings: [
        {
          finding_id: "F-1",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
        {
          finding_id: "F-1",
          impact: 10,
          proof_quality: 10,
          severity_accuracy: 10,
          chain_potential: 10,
          report_quality: 10,
          total_score: 50,
          feedback: "duplicate",
        },
      ],
      feedback: "Need stronger chain.",
    }), /Duplicate finding_id in findings: F-1/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 80,
      findings: [
        {
          finding_id: "F-99",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
      ],
      feedback: null,
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_read_grade_verdict hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";
    const paths = gradeArtifactPaths(domain);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Missing grade verdict JSON/,
    );

    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Malformed grade verdict JSON/,
    );
  });
});

test("bounty_read_grade_verdict rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "HOLD",
      total_score: 10,
      findings: [
        {
          finding_id: "F-99",
          impact: 2,
          proof_quality: 2,
          severity_accuracy: 2,
          chain_potential: 2,
          report_quality: 2,
          total_score: 10,
          feedback: null,
        },
      ],
      feedback: "Bad manual edit.",
    }, null, 2)}\n`);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Unknown finding_id: F-99/,
    );
  });
});

// ── bounty_auth_store tests ──

test("bounty_auth_store writes v2 auth.json with attacker profile", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });

    const result = JSON.parse(await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
      cookies: { "session": "abc123" },
    }));

    assert.equal(result.success, true);
    assert.equal(result.profile_name, "attacker");
    assert.equal(result.has_attacker, true);
    assert.equal(result.has_victim, false);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.ok(saved.profiles.attacker);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.attacker.Cookie, "session=abc123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store adds victim profile to existing v2 auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });

    // Write attacker first
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    // Now add victim
    const result = JSON.parse(await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    }));

    assert.equal(result.success, true);
    assert.equal(result.has_attacker, true);
    assert.equal(result.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store accepts arbitrary profile names without clobbering existing profiles", async () => {
  await withTempHome(async () => {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer attacker" },
    });
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "tenant_b",
      headers: { Authorization: "Bearer tenant-b" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.tenant_b.Authorization, "Bearer tenant-b");
    assert.deepEqual(Object.keys(saved.profiles).sort(), ["attacker", "tenant_b"]);
  });
});

test("bounty_auth_store migrates legacy auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });

    // Write legacy format (flat object, no version)
    fs.writeFileSync(path.join(targetDir, "auth.json"), JSON.stringify({
      Authorization: "Bearer legacy",
      Cookie: "old=val",
    }));

    // Add victim — should migrate legacy to attacker and add victim
    const result = JSON.parse(await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    }));

    assert.equal(result.success, true);
    assert.equal(result.has_attacker, true);
    assert.equal(result.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer legacy");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store stores credentials alongside headers", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });

    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer t" },
      credentials: { email: "test@mail.tm", password: "secret123" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.credentials.email, "test@mail.tm");
    assert.equal(saved.profiles.attacker.credentials.password, "secret123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store writes and migrates auth.json with 0600 permissions", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const targetDir = path.join(tempHome, "bounty-agent-sessions", "target.com");
    const authPath = path.join(targetDir, "auth.json");
    fs.mkdirSync(targetDir, { recursive: true });

    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      cookies: { sessionid: "abc" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);

    fs.writeFileSync(authPath, JSON.stringify({ Authorization: "Bearer legacy" }), { mode: 0o644 });
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { Authorization: "Bearer victim" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store reports persistence failures instead of claiming success", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const authPath = path.join(tempHome, "bounty-agent-sessions", "target.com", "auth.json");
    fs.mkdirSync(authPath, { recursive: true });

    const envelope = await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    assert.equal(envelope.ok, false);
    assert.equal(envelope.error.code, "INTERNAL_ERROR");
    assert.equal(envelope.error.details.auth_path, authPath);
    const result = JSON.parse(envelope);
    assert.equal(result.success, false);
    assert.match(result.error, /failed to persist auth profile/i);
    assert.equal(result.auth_path, authPath);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_store preserves concurrent attacker and victim profile writes", async () => {
  await withTempHome(async () => {
    await Promise.all([
      executeTool("bounty_auth_store", {
        target_domain: "target.com",
        profile_name: "attacker",
        headers: { Authorization: "Bearer attacker" },
      }),
      executeTool("bounty_auth_store", {
        target_domain: "target.com",
        profile_name: "victim",
        headers: { Authorization: "Bearer victim" },
      }),
    ]);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.victim.Authorization, "Bearer victim");
  });
});

test("bounty_list_auth_profiles redacts secrets while reporting profile status", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer secret-token" },
      cookies: { sessionid: "cookie-secret" },
      credentials: { email: "attacker@example.com", password: "password-secret" },
    });

    const result = JSON.parse(listAuthProfiles({ target_domain: "target.com" }));
    assert.equal(result.has_attacker, true);
    assert.equal(result.profiles[0].profile_name, "attacker");
    assert.deepEqual(result.profiles[0].header_keys.sort(), ["Authorization", "Cookie"].sort());
    assert.deepEqual(result.profiles[0].cookie_names, ["sessionid"]);
    assert.equal(result.profiles[0].has_credentials, true);
    assert.deepEqual(result.profiles[0].credential_fields.sort(), ["email", "password"].sort());
    assert.doesNotMatch(JSON.stringify(result), /secret-token|cookie-secret|password-secret|attacker@example\.com/);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_http_scan resolves auth by explicit target_domain and first-party subdomain only", async () => {
  await withTempHome(async () => {
    await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer target-token" },
    });
    await executeTool("bounty_auth_store", {
      target_domain: "other.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer other-token" },
    });
    const listed = JSON.parse(listAuthProfiles({ target_domain: "api.target.com" }));
    assert.equal(listed.has_attacker, true);

    await withMockSafeFetch((url, requestOptions) => ({
      status: requestOptions.headers.Authorization === "Bearer target-token" ? 200 : 401,
      body: "ok",
    }), async (requestedUrls) => {
      const allowed = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: "target.com",
        method: "GET",
        url: "https://api.target.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      }));
      assert.equal(allowed.status, 200);

      const blocked = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: "missing.com",
        method: "GET",
        url: "https://api.missing.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      }));
      assert.match(blocked.error, /auth_profile "attacker" requested but not found/);
      assert.deepEqual(requestedUrls, ["https://api.target.com/private"]);
    });
  });
});

// ── bounty_temp_email tests ──

test("bounty_temp_email create returns email with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url, opts) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc", address: "x@test.tm" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      return { ok: false, status: 500 };
    };

    const result = JSON.parse(await executeTool("bounty_temp_email", { operation: "create" }));
    assert.equal(result.success, true);
    assert.ok(result.email_address.endsWith("@test.tm"));
    assert.equal(result.provider, "mail.tm");
    assert.ok(result.password.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email create falls back to guerrillamail on mail.tm failure", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url) => {
      if (url.includes("mail.tm")) {
        return { ok: false, status: 500, text: async () => "Service Unavailable" };
      }
      if (url.includes("guerrillamail") && url.includes("get_email_address")) {
        return { ok: true, json: async () => ({ email_addr: "test_user@guerrillamail.com", sid_token: "sid123" }) };
      }
      return { ok: false, status: 500, text: async () => "" };
    };

    const result = JSON.parse(await executeTool("bounty_temp_email", { operation: "create" }));
    assert.equal(result.success, true);
    assert.equal(result.email_address, "test_user@guerrillamail.com");
    assert.equal(result.provider, "guerrillamail");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email create returns error when all providers fail", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async () => ({ ok: false, status: 500, text: async () => "Internal Server Error" });

    const result = JSON.parse(await executeTool("bounty_temp_email", { operation: "create" }));
    assert.equal(result.success, false);
    assert.ok(result.providers_tried.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email poll returns messages with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    // First create a mailbox to populate tempMailboxes
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages") && !url.includes("/messages/")) {
        return {
          ok: true,
          json: async () => ({
            "hydra:member": [
              { id: "msg1", from: { address: "noreply@target.com" }, subject: "Verify your email", createdAt: "2026-01-01" },
            ],
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = JSON.parse(await executeTool("bounty_temp_email", { operation: "create" }));
    const pollResult = JSON.parse(await executeTool("bounty_temp_email", {
      operation: "poll",
      email_address: createResult.email_address,
    }));

    assert.equal(pollResult.success, true);
    assert.equal(pollResult.messages.length, 1);
    assert.equal(pollResult.messages[0].from, "noreply@target.com");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email extract finds codes and links", async () => {
  const originalFetch = global.fetch;
  try {
    // Create mailbox first
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages/msg1")) {
        return {
          ok: true,
          json: async () => ({
            text: "Your verification code is 847291. Or click https://target.com/verify?token=abc123 to confirm.",
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = JSON.parse(await executeTool("bounty_temp_email", { operation: "create" }));
    const extractResult = JSON.parse(await executeTool("bounty_temp_email", {
      operation: "extract",
      email_address: createResult.email_address,
      message_id: "msg1",
    }));

    assert.equal(extractResult.success, true);
    assert.ok(extractResult.verification_codes.includes("847291"));
    assert.ok(extractResult.verification_links.some((l) => l.includes("target.com/verify")));
  } finally {
    global.fetch = originalFetch;
  }
});

test("bounty_temp_email poll for unknown email returns error", async () => {
  const result = JSON.parse(await executeTool("bounty_temp_email", {
    operation: "poll",
    email_address: "nonexistent@nowhere.com",
  }));
  assert.ok(result.error);
  assert.ok(result.error.includes("Unknown email"));
});

test("auto-signup result normalization fails ambiguous states and preserves diagnostics", () => {
  const signupUrl = "https://example.com/signup/";
  const ambiguous = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/signup#done",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { theme: "light" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);

  assert.equal(ambiguous.success, false);
  assert.equal(ambiguous.fallback, "manual");
  assert.equal(ambiguous.diagnostics.submitted, true);
  assert.deepEqual(ambiguous.auth_evidence.cookie_keys, []);

  const successful = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/dashboard",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { sessionid: "abc" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);
  assert.equal(successful.success, true);
  assert.deepEqual(successful.auth_evidence.cookie_keys, ["sessionid"]);
});

test("bounty_auto_signup blocks unsafe and out-of-scope signup URLs before browser launch", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    for (const signupUrl of [
      "http://127.0.0.1/signup",
      "https://third-party.example.net/signup",
      "https://blocked.example.com/signup",
    ]) {
      const result = JSON.parse(await autoSignup({
        target_domain: domain,
        signup_url: signupUrl,
        email: "a@example.test",
        password: "Password123!",
      }));
      assert.equal(result.success, false);
      assert.equal(result.scope_decision, "blocked");
      assert.equal(result.fallback, "manual");
    }
  });
});

// ── migrateAuthJson unit tests ──

test("migrateAuthJson wraps legacy flat object as attacker profile", () => {
  const legacy = { Authorization: "Bearer old", Cookie: "s=1" };
  const result = migrateAuthJson(legacy);
  assert.equal(result.version, 2);
  assert.deepStrictEqual(result.profiles.attacker, legacy);
});

test("migrateAuthJson returns v2 unchanged", () => {
  const v2 = { version: 2, profiles: { attacker: { Authorization: "Bearer a" } } };
  const result = migrateAuthJson(v2);
  assert.equal(result, v2);
});

test("migrateAuthJson handles null/undefined", () => {
  assert.deepStrictEqual(migrateAuthJson(null), { version: 2, profiles: {} });
  assert.deepStrictEqual(migrateAuthJson(undefined), { version: 2, profiles: {} });
});

// ── HTTP audit, imported traffic, public intel, and ranking tests ──

test("bounty_http_scan writes audit entries for success, HTTP error, timeout, and scope-blocked requests", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const timeoutError = new Error("The operation was aborted");
    timeoutError.name = "AbortError";

    await withMockSafeFetch({
      "https://example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://example.com/forbidden": { status: 403, statusText: "Forbidden", body: "no" },
      "https://example.com/timeout": { error: timeoutError },
    }, async () => {
      assert.equal(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        method: "GET",
        url: "https://example.com/ok",
        response_mode: "status_only",
      })).status, 200);
      assert.equal(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/forbidden",
        response_mode: "status_only",
      })).status, 403);
      assert.match(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/timeout",
      })).error, /timeout/i);
      assert.match(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "http://127.0.0.1/admin",
      })).error, /Blocked internal\/private host/);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 4);
      assert.deepEqual(records.map((record) => record.status), [200, 403, null, null]);
      assert.deepEqual(records.map((record) => record.scope_decision), ["allowed", "allowed", "request_error", "blocked"]);
      assert.equal(records[0].wave, "w1");
      assert.equal(records[0].agent, "a1");
      assert.equal(records[0].surface_id, "surface-a");

      const audit = JSON.parse(readHttpAudit({ target_domain: domain, limit: 2 }));
      assert.equal(audit.summary.total, 4);
      assert.equal(audit.summary.shown, 2);
      assert.equal(audit.summary.by_status_class["4xx"], 1);
      assert.equal(audit.summary.scope_blocked, 1);
      assert.ok(fs.existsSync(httpAuditJsonlPath(domain)));
    });
  });
});

test("bounty_http_scan redacts persisted audit URLs while sending the original request", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/callback?token=secret-token&code=oauth-code&id=123": {
        status: 200,
        statusText: "OK",
        body: "ok",
      },
    }, async (requestedUrls) => {
      await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/callback?token=secret-token&code=oauth-code&id=123#client-fragment",
        response_mode: "status_only",
      });

      assert.equal(requestedUrls[0], "https://example.com/callback?token=secret-token&code=oauth-code&id=123");
      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].url, "https://example.com/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.equal(records[0].path, "/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.doesNotMatch(JSON.stringify(records), /secret-token|oauth-code|client-fragment|id=123/);

      const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
      assert.doesNotMatch(JSON.stringify(audit), /secret-token|oauth-code|client-fragment|id=123/);
    });
  });
});

test("bounty_http_scan blocks out-of-scope and deny-listed hosts while allowing target, attack-surface, and target-referenced public intel hosts", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-api", hosts: [`https://api.partner-service.com`] },
    ]);
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    await withMockSafeFetch({
      "https://app.example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://api.partner-service.com/v1/users": { status: 200, statusText: "OK", body: "ok" },
      "https://crt.sh/?q=example.com": { status: 200, statusText: "OK", body: "ok" },
    }, async (requestedUrls) => {
      assert.equal(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://app.example.com/ok",
        response_mode: "status_only",
      })).status, 200);
      assert.equal(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://api.partner-service.com/v1/users",
        response_mode: "status_only",
      })).status, 200);
      assert.equal(JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://crt.sh/?q=example.com",
        response_mode: "status_only",
      })).status, 200);

      const thirdParty = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://third-party.example.net/api",
      }));
      assert.match(thirdParty.error, /out-of-scope host/);
      assert.equal(thirdParty.scope_decision, "blocked");

      const unrelatedIntel = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://crt.sh/?q=other.com",
      }));
      assert.match(unrelatedIntel.error, /out-of-scope host/);
      assert.equal(unrelatedIntel.scope_decision, "blocked");

      const denied = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://blocked.example.com/admin",
      }));
      assert.match(denied.error, /deny-listed host/);
      assert.equal(denied.scope_decision, "blocked");

      assert.deepEqual(requestedUrls, [
        "https://app.example.com/ok",
        "https://api.partner-service.com/v1/users",
        "https://crt.sh/?q=example.com",
      ]);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 6);
      assert.deepEqual(records.map((record) => record.scope_decision), [
        "allowed",
        "allowed",
        "allowed",
        "blocked",
        "blocked",
        "blocked",
      ]);
    });
  });
});

test("bounty_http_scan requires target_domain instead of inferring scope from other sessions", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);

    const blocked = JSON.parse(await executeTool("bounty_http_scan", {
      method: "GET",
      url: "https://app.example.com/ok",
      response_mode: "status_only",
    }));
    assert.match(blocked.error, /target_domain is required/);
    assert.equal(blocked.scope_decision, "blocked");
  });
});

test("bounty_http_scan blocks unsafe redirect targets before fetching them", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/redirect": {
        status: 302,
        statusText: "Found",
        headers: { location: "http://127.0.0.1/admin" },
      },
    }, async (requestedUrls) => {
      const result = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/redirect",
        follow_redirects: true,
      }));

      assert.match(result.error, /Blocked internal\/private host/);
      assert.equal(result.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, ["https://example.com/redirect"]);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].scope_decision, "blocked");
      assert.match(records[0].error, /Blocked internal\/private host/);
    });
  });
});

test("bounty_http_scan blocks public hostnames that resolve to private IPs before connecting", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/private-dns": { status: 200, body: "should not connect" },
    }, async (requestedUrls) => {
      const result = JSON.parse(await executeTool("bounty_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/private-dns",
      }));
      assert.match(result.error, /Blocked internal\/private DNS address/);
      assert.equal(result.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, []);
    }, { dnsRecords: { "example.com": [{ address: "10.0.0.5", family: 4 }] } });
  });
});

test("safeFetch enforces response byte caps without buffering the full body", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/large": { status: 200, body: "abcdef" },
    }, async () => {
      const response = await safeFetch("https://example.com/large", {
        targetDomain: domain,
        maxResponseBytes: 4,
      });
      assert.equal(response.bodyTruncated, true);
      assert.equal(response.bodyByteLength, 6);
      assert.equal(await response.text(), "abcd");
    });
  });
});

test("bounty_import_http_traffic validates, dedupes, stores session-local traffic, and briefs only relevant surface traffic", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api/me"],
        interesting_params: ["id"],
        nuclei_hits: [],
        priority: "LOW",
      },
      {
        id: "surface-admin",
        hosts: [`https://admin.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/admin"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
          startedDateTime: "2026-04-24T00:00:00.000Z",
        },
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123#frag`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
        },
        {
          method: "GET",
          url: "https://evil.example.net/api/me",
          status: 200,
        },
        {
          method: "GET",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.duplicates, 1);
    assert.equal(result.rejected, 2);
    assert.ok(fs.existsSync(trafficJsonlPath(domain)));
    assert.equal(readTrafficRecordsFromJsonl(domain).length, 1);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.traffic_summary.total, 1);
    assert.equal(brief.traffic_summary.authenticated_count, 1);
    assert.match(brief.traffic_summary.recent[0].url, /\/api\/me/);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("imported_traffic"));
    assert.ok(brief.ranking_summary.reasons.includes("authenticated_observed_traffic"));
    assert.doesNotMatch(JSON.stringify(brief.traffic_summary), /evil\.example\.net/);
  });
});

test("bounty_import_http_traffic redacts persisted URLs and rejected reasons", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          method: "GET",
          url: "https://app.example.com/api/me?token=secret-token&email=user@example.com&id=123#frag",
          status: 200,
          headers: { Cookie: "sid=secret" },
        },
        {
          method: "GET",
          url: "not a url with token=secret-token",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.rejected, 1);
    assert.doesNotMatch(JSON.stringify(result.rejected_reasons), /secret-token/);

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].url, "https://app.example.com/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.equal(records[0].path, "/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.deepEqual(records[0].query_keys, ["email", "id", "token"]);
    assert.doesNotMatch(JSON.stringify(records), /secret-token|user@example\.com|id=123|frag/);
  });
});

test("redactUrlSensitiveValues redacts query values, credentials, and fragments", () => {
  assert.equal(
    redactUrlSensitiveValues("https://alice:secret@example.com/path?token=abc&id=123#frag"),
    "https://REDACTED:REDACTED@example.com/path?token=REDACTED&id=REDACTED",
  );
  assert.equal(redactUrlSensitiveValues("not a url token=abc"), "not a url token=abc");
});

test("legacy raw audit and traffic records are redacted on read", () => {
  withTempHome(() => {
    const domain = "example.com";
    appendJsonlLine(httpAuditJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      method: "GET",
      url: "https://example.com/callback?token=old-secret&id=123#frag",
      host: "example.com",
      path: "/callback?token=old-secret&id=123",
      status: 200,
      error: null,
      scope_decision: "allowed",
      final_url: "https://example.com/done?code=final-secret",
    });
    appendJsonlLine(trafficJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      source: "legacy",
      method: "GET",
      url: "https://app.example.com/api/me?session=old-secret&id=123#frag",
      host: "app.example.com",
      path: "/api/me?session=old-secret&id=123",
      status: 200,
      has_auth: true,
      header_names: ["cookie"],
      query_keys: ["id", "session"],
    });

    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    const trafficRecords = readTrafficRecordsFromJsonl(domain);
    assert.doesNotMatch(JSON.stringify({ auditRecords, trafficRecords }), /old-secret|final-secret|id=123|frag/);
    assert.equal(auditRecords[0].final_url, "https://example.com/done?code=REDACTED");
    assert.equal(trafficRecords[0].path, "/api/me?session=REDACTED&id=REDACTED");
  });
});

test("bounty_import_static_artifact stores redacted session-owned content and rejects unsafe imports", () => {
  withTempHome(() => {
    const domain = "example.com";
    const source = `
      contract RugToken {
        string public apiKey = "super-secret-token-value";
        mapping(address => bool) private _isBlacklisted;
      }
    `;

    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        path: "/tmp/RugToken.sol",
        content: source,
      }),
      /Path imports are not supported/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: "x".repeat(STATIC_ARTIFACT_MAX_CHARS + 1),
      }),
      /content exceeds static artifact cap/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: source,
      }),
      /Missing session state:/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-1" }),
      /Missing session state:/,
    );
    assert.equal(fs.existsSync(sessionDir(domain)), false);
    assert.equal(JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` })).created, true);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      source_name: "/tmp/RugToken.sol",
      label: "Rug token",
      surface_id: "surface-api",
      content: source,
    }));

    assert.equal(imported.artifact_id, "SA-1");
    assert.equal(imported.source_name, "RugToken.sol");
    assert.ok(imported.artifact_path.startsWith(staticArtifactImportDir(domain)));
    assert.equal(imported.artifact_path, staticArtifactPath(domain, "SA-1"));
    assert.ok(fs.existsSync(staticArtifactsJsonlPath(domain)));
    assert.ok(fs.existsSync(staticArtifactPath(domain, "SA-1")));
    assert.equal(readStaticArtifactRecordsFromJsonl(domain).length, 1);

    const stored = fs.readFileSync(staticArtifactPath(domain, "SA-1"), "utf8");
    assert.match(stored, /REDACTED/);
    assert.doesNotMatch(stored, /super-secret-token-value|\/tmp\/RugToken/);
  });
});

test("bounty_static_scan reports deduped findings separately from capped returned findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Duplicate honeypot",
      content: `
        contract DuplicateHoneypot {
          function block(address account) external {
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
          }
        }
      `,
    }));

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      limit: 1,
    }));

    assert.equal(scan.findings_count, 1);
    assert.equal(scan.findings_returned, 1);
    assert.equal(scan.findings_capped, false);
    assert.equal(scan.findings_shown, 1);
    assert.equal(scan.findings_omitted, 0);
    assert.equal(scan.risk_score, 25);
  });
});

test("bounty_static_scan scans only imported artifacts and feeds bounded hunter brief hints", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-token",
        hosts: [`https://app.${domain}`],
        tech_stack: ["EVM token"],
        endpoints: ["/token"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-token" }]);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Classic rug",
      source_name: "ClassicRug.sol",
      surface_id: "surface-token",
      content: `
        contract ClassicRug {
          mapping(address => bool) private _isBlacklisted;
          uint256 private _sellFee = 1;
          function blacklist(address account) external onlyOwner {
            _isBlacklisted[account] = true;
          }
          function setFees(uint256 fee) external onlyOwner {
            _sellFee = fee;
          }
          function emergencyWithdraw(address token) external onlyOwner {}
          function renounceOwnership() public override {}
          string private token = "secret-static-token";
        }
      `,
    }));

    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "../SA-1" }),
      /artifact_id must match SA-N/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-999" }),
      /Static artifact SA-999 not found/,
    );

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      scan_type: "token_contract",
      limit: 10,
    }));
    assert.equal(scan.artifact_id, "SA-1");
    assert.equal(scan.chain, "evm");
    assert.ok(scan.risk_score >= 25);
    assert.match(scan.verdict, /RISK/);
    assert.ok(scan.findings.some((finding) => finding.category === "honeypot"));
    assert.ok(scan.findings.some((finding) => finding.category === "lp_drain"));
    assert.ok(fs.existsSync(staticScanResultsJsonlPath(domain)));
    assert.equal(readStaticScanResultsFromJsonl(domain).length, 1);
    assert.doesNotMatch(JSON.stringify(scan), /secret-static-token/);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.static_scan_hints.available, true);
    assert.equal(brief.static_scan_hints.total_results, 1);
    assert.ok(brief.static_scan_hints.findings.length > 0);
    assert.ok(brief.static_scan_hints.findings.length <= 10);
    assert.equal(brief.static_scan_hints.artifacts[0].artifact_id, "SA-1");
    assert.doesNotMatch(JSON.stringify(brief.static_scan_hints), /secret-static-token|_isBlacklisted|evidence/);
  });
});

test("circuit breaker summary marks repeated failures per host without blocking unrelated hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://api.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/api"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
      {
        id: "surface-app",
        hosts: [`https://app.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/home"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    for (const [host, status, error] of [
      [`api.${domain}`, 403, null],
      [`api.${domain}`, 429, null],
      [`api.${domain}`, null, "timeout after 1000ms"],
      [`app.${domain}`, 403, null],
    ]) {
      appendJsonlLine(httpAuditJsonlPath(domain), {
        version: 1,
        ts: new Date().toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${host}/api`,
        host,
        path: "/api",
        status,
        error,
        scope_decision: error ? "request_error" : "allowed",
      });
    }

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.circuit_breaker_summary.tripped_count, 1);
    assert.equal(brief.circuit_breaker_summary.tripped_hosts[0].host, `api.${domain}`);
    assert.doesNotMatch(JSON.stringify(brief.circuit_breaker_summary), new RegExp(`app\\.${domain}`));
  });
});

test("bounty_public_intel caps output, persists optional intel, handles API failures, and feeds hunter brief hints", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const previousFetch = global.fetch;
    try {
      global.fetch = async (url) => {
        const textUrl = String(url);
        if (textUrl.includes("/example-program.json")) {
          return new Response(JSON.stringify({
            handle: "example-program",
            name: "Example Program",
            policy: "Only test owned assets. Report IDOR and auth bypass with proof.",
            offers_bounties: true,
            resolved_report_count: 42,
            structured_scopes: [
              { asset_identifier: `*.${domain}`, asset_type: "URL", eligible_for_bounty: true, instruction: "Main app and API." },
            ],
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (textUrl.includes("hacktivity")) {
          return new Response('<a href="/reports/123">IDOR in team export</a><a href="/reports/456">GraphQL auth bypass</a>', {
            status: 200,
            headers: { "content-type": "text/html" },
          });
        }
        return new Response("no", { status: 500 });
      };

      seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["GraphQL"],
        endpoints: ["/graphql", "/api/team/export"],
        interesting_params: ["team_id"],
        nuclei_hits: [],
        priority: "LOW",
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

      const result = JSON.parse(await bountyPublicIntel({
        target_domain: domain,
        program: "https://hackerone.com/example-program",
        keywords: ["team export", "graphql"],
        limit: 1,
      }));
      assert.equal(result.disclosed_reports.length, 1);
      assert.equal(result.structured_scopes.length, 1);
      assert.equal(result.program_stats.resolved_report_count, 42);
      assert.match(result.policy_summary, /Only test owned assets/);
      assert.ok(fs.existsSync(publicIntelPath(domain)));

      const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.intel_hints.available, true);
      assert.equal(brief.intel_hints.reports.length, 1);
      assert.ok(brief.ranking_summary.reasons.includes("disclosed_report_hints"));

      global.fetch = async () => { throw new Error("network down"); };
      const failed = JSON.parse(await bountyPublicIntel({ target_domain: "empty.example", keywords: ["none"], limit: 2 }));
      assert.equal(failed.disclosed_reports.length, 0);
      assert.ok(failed.errors.some((error) => /network down/.test(error)));
    } finally {
      global.fetch = previousFetch;
    }
  });
});

test("rankAttackSurfaces adds ranking fields without removing required attack_surface fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}", "/billing/refund"],
      interesting_params: ["user_id", "account_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);

    const ranked = rankAttackSurfaces(domain);
    assert.equal(ranked.surfaces.length, 1);
    const surface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8")).surfaces[0];
    for (const field of ["id", "hosts", "tech_stack", "endpoints", "interesting_params", "nuclei_hits", "priority"]) {
      assert.ok(Object.prototype.hasOwnProperty.call(surface, field), `missing ${field}`);
    }
    assert.ok(surface.ranking.score > 0);
    assert.ok(surface.ranking.reasons.includes("api_or_mobile_surface"));
    assert.ok(priorityRankForTest(surface.priority) >= priorityRankForTest("HIGH"));
  });
});

test("read-style status and hunter brief compute ranking without mutating attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}"],
      interesting_params: ["user_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const before = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    const after = fs.readFileSync(attackSurfacePath(domain), "utf8");

    assert.equal(after, before);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("api_or_mobile_surface"));
    assert.equal(status.coverage.unexplored_high, 1);
  });
});

function priorityRankForTest(priority) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(priority || "").toUpperCase()] || 0;
}

// ── bounty_read_hunter_brief tests ──

test("bounty_read_hunter_brief returns surface, exclusions, and valid IDs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      dead_ends: ["/api/old"],
      waf_blocked_endpoints: ["/admin"],
      scope_exclusions: ["third-party.com"],
    });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    const brief = JSON.parse(readHunterBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    }));

    assert.equal(brief.wave, "w1");
    assert.equal(brief.agent, "a1");
    assert.equal(brief.surface.id, "surface-a");
    assert.deepEqual(brief.valid_surface_ids, ["surface-a", "surface-b"]);
    assert.deepEqual(brief.dead_ends, ["/api/old"]);
    assert.deepEqual(brief.waf_blocked_endpoints, ["/admin"]);
    assert.strictEqual(brief.scope_exclusions, undefined);
    assert.ok(brief.exclusions_summary);
    assert.equal(brief.exclusions_summary.dead_ends_total, 1);
    assert.equal(brief.exclusions_summary.waf_blocked_total, 1);
    assert.equal(brief.auth_hint, undefined);
    assert.match(brief.auth_profiles_hint, /bounty_list_auth_profiles/);
    assert.doesNotMatch(JSON.stringify(brief), /auth\.json/i);
  });
});

test("bounty_read_hunter_brief caps assigned surface arrays and reports surface_limits", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      priority: "HIGH",
      hosts: Array.from({ length: 25 }, (_, index) => `https://h${index}.${domain}`),
      tech_stack: Array.from({ length: 25 }, (_, index) => `tech-${index}`),
      endpoints: Array.from({ length: 90 }, (_, index) => `/api/${index}`),
      interesting_params: Array.from({ length: 45 }, (_, index) => `param_${index}`),
      nuclei_hits: Array.from({ length: 35 }, (_, index) => `hit-${index}`),
      bug_class_hints: Array.from({ length: 25 }, (_, index) => `bug-${index}`),
      high_value_flows: Array.from({ length: 25 }, (_, index) => `flow-${index}`),
      evidence: Array.from({ length: 30 }, (_, index) => `evidence-${index}`),
      js_hints: Array.from({ length: 200 }, (_, index) => `js-${index}`),
      ranking: { version: 1, score: 77, priority: "HIGH", reasons: ["api_or_mobile_surface"] },
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.id, "surface-rich");
    assert.equal(brief.surface.priority, "HIGH");
    assert.equal(brief.surface.ranking.version, 1);
    assert.ok(Array.isArray(brief.surface.ranking.reasons));
    assert.equal(brief.surface.hosts.length, 20);
    assert.equal(brief.surface.endpoints.length, 80);
    assert.equal(brief.surface.interesting_params.length, 40);
    assert.equal(brief.surface.nuclei_hits.length, 30);
    assert.equal(brief.surface.bug_class_hints.length, 20);
    assert.equal(brief.surface.high_value_flows.length, 20);
    assert.equal(brief.surface.evidence.length, 25);
    assert.equal(brief.surface.js_hints, undefined);
    assert.deepEqual(brief.surface_limits.hosts, { shown: 20, total: 25, omitted: 5 });
    assert.deepEqual(brief.surface_limits.endpoints, { shown: 80, total: 90, omitted: 10 });
  });
});

test("bounty_read_hunter_brief caps scalar strings and omits unknown scalar fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    const huge = "x".repeat(5000);
    seedAttackSurfaces(domain, [{
      id: "surface-scalar",
      hosts: [`https://${domain}`],
      tech_stack: ["Custom"],
      endpoints: [`/${huge}`],
      interesting_params: ["id"],
      priority: "HIGH",
      surface_type: huge,
      description: huge,
      recon_blob: huge,
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-scalar" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.surface_type.length, 80);
    assert.equal(brief.surface.description.length, 500);
    assert.equal(brief.surface.endpoints[0].length, 500);
    assert.equal(brief.surface.recon_blob, undefined);
    assert.deepEqual(brief.surface_limits.surface_type, {
      shown_chars: 80,
      total_chars: 5000,
      omitted_chars: 4920,
    });
    assert.deepEqual(brief.surface_limits.description, {
      shown_chars: 500,
      total_chars: 5000,
      omitted_chars: 4500,
    });
    assert.equal(brief.surface_limits.endpoints.truncated_values, 1);
    assert.equal(brief.surface_limits.endpoints.max_value_chars, 500);
    assert.doesNotMatch(JSON.stringify(brief), new RegExp("x{1000}"));
  });
});

test("bounty_read_hunter_brief includes assigned-surface coverage summary with latest-per-key dedupe", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "first replay returned 403",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          auth_profile: "attacker-victim",
          status: "promising",
          evidence_summary: "legacy query param still returns profile metadata",
          next_step: "try export route",
        },
        {
          endpoint: "/search",
          method: "POST",
          bug_class: "xss",
          status: "blocked",
          evidence_summary: "WAF blocks reflected payloads",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [{
        endpoint: "/admin",
        bug_class: "authz",
        status: "promising",
        evidence_summary: "admin path reveals feature flags",
      }],
    });

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.surface_id, "surface-a");
    assert.equal(brief.coverage_summary.total, 2);
    assert.equal(brief.coverage_summary.shown, 2);
    assert.equal(brief.coverage_summary.omitted, 0);
    assert.deepEqual(brief.coverage_summary.tested, []);
    assert.equal(brief.coverage_summary.promising.length, 1);
    assert.equal(brief.coverage_summary.promising[0].endpoint, "/api/v1/users/123");
    assert.equal(brief.coverage_summary.promising[0].method, "GET");
    assert.equal(brief.coverage_summary.promising[0].bug_class, "idor");
    assert.equal(brief.coverage_summary.promising[0].next_step, "try export route");
    assert.equal(brief.coverage_summary.blocked.length, 1);
    assert.equal(brief.coverage_summary.blocked[0].endpoint, "/search");
    assert.doesNotMatch(JSON.stringify(brief.coverage_summary), /\/admin/);
  });
});

test("bounty_read_hunter_brief caps coverage summary output", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: Array.from({ length: 45 }, (_, index) => ({
        endpoint: `/api/v1/items/${index}`,
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: `item ${index} returned 403`,
      })),
    });

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.total, 45);
    assert.equal(brief.coverage_summary.shown, 40);
    assert.equal(brief.coverage_summary.omitted, 5);
    assert.equal(brief.coverage_summary.tested.length, 40);

    const directSummary = buildCoverageSummaryForSurface(readCoverageRecordsFromJsonl(domain), "surface-a", 3);
    assert.equal(directSummary.total, 45);
    assert.equal(directSummary.shown, 3);
    assert.equal(directSummary.omitted, 42);
  });
});

test("bounty_read_hunter_brief rejects unassigned agent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => readHunterBrief({ target_domain: domain, wave: "w1", agent: "a9" }),
      /Agent a9 is not assigned/,
    );
  });
});

test("bounty_read_hunter_brief includes WordPress-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-wp",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "PHP"],
      endpoints: ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php"],
      interesting_params: ["author", "action", "nonce"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-wp" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "wordpress"));
    assert.ok(brief.payload_hints.some((entry) => entry.id === "wordpress"));
    assert.match(JSON.stringify(brief.techniques), /WordPress/);
  });
});

test("bounty_read_hunter_brief includes GraphQL-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "Apollo"],
      endpoints: ["/graphql"],
      interesting_params: ["query", "variables", "operationName"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "graphql"));
    assert.match(JSON.stringify(brief.payload_hints), /alias|updateUserRole|__schema/i);
  });
});

test("bounty_read_hunter_brief includes generic REST/API guidance for API surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["Express", "JSON API"],
      endpoints: ["/api/v1/users/123", "/api/v2/admin/export"],
      interesting_params: ["id", "user_id", "role", "limit"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "generic-rest-api"));
    assert.match(JSON.stringify(brief.techniques), /object access|parser differentials|old API versions/i);
  });
});

test("bounty_read_hunter_brief matches IDOR and authz bug_class_hints to REST/API authorization guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-object-access",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/dashboard"],
      interesting_params: ["q"],
      bug_class_hints: ["idor", "authz"],
      evidence: ["archived export URL exposed account_id and org_id"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-object-access" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const restEntry = brief.techniques.find((entry) => entry.id === "generic-rest-api");
    assert.ok(restEntry);
    assert.ok(restEntry.matched.some((match) => /hint:(idor|authz)/.test(match)));
    assert.match(JSON.stringify(restEntry.guidance), /object access|authorization/i);
  });
});

test("bounty_read_hunter_brief matches billing metadata and high-value flows to business-logic guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-billing",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/account"],
      interesting_params: ["q"],
      surface_type: "billing",
      high_value_flows: ["checkout", "refund"],
      bug_class_hints: ["business_logic"],
      evidence: ["JS route references refund and subscription flows"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-billing" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "business-logic-race"));
    assert.match(JSON.stringify(brief.techniques), /checkout|refund|business logic/i);
  });
});

test("bounty_read_hunter_brief matches upload surface_type to upload guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-upload",
      hosts: [`https://assets.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/profile"],
      interesting_params: ["q"],
      surface_type: "upload",
      high_value_flows: ["uploads"],
      bug_class_hints: ["upload"],
      evidence: ["live page contains avatar upload form"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-upload" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "upload-xss-file"));
    assert.match(JSON.stringify(brief.payload_hints), /file\.php\.jpg|Content-Type/i);
  });
});

test("bounty_read_hunter_brief falls back to generic guidance for unknown tech", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-unknown",
      hosts: [`https://unknown.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/home"],
      interesting_params: ["q"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-unknown" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.deepEqual(brief.techniques.map((entry) => entry.id), ["generic-rest-api"]);
    assert.deepEqual(brief.techniques[0].matched, ["fallback:generic-rest-api"]);
  });
});

test("bounty_read_hunter_brief knowledge remains bounded and excludes full source docs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "GraphQL", "Next.js", "JWT", "OAuth", "SSRF", "storage"],
      endpoints: [
        "/wp-json/wp/v2/users",
        "/graphql",
        "/_next/image",
        "/oauth/authorize",
        "/api/v1/users",
        "/upload",
        "/billing/checkout",
      ],
      interesting_params: ["query", "variables", "url", "redirect_uri", "user_id", "file", "amount"],
      nuclei_hits: ["swagger exposed", "graphql endpoint", "wp-json exposed"],
      js_hints: ["__NEXT_DATA__", "Bearer token handling"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readHunterBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.knowledge_summary.entries_returned <= 4);
    assert.ok(brief.knowledge_summary.char_count <= brief.knowledge_summary.max_chars);
    assert.doesNotMatch(JSON.stringify(brief), /Complete reference library|Advanced Bug Bounty Hunting Techniques|scripts\/|tools\//);
  });
});

// ── filterExclusionsByHosts tests ──

test("filterExclusionsByHosts filters dead ends by surface hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 1,
      dead_ends: [
        "api.example.com - /v1/users returns 404",
        "admin.example.com - /panel gives 403",
        "All /api/* endpoints return 401",
      ],
      waf_blocked_endpoints: [
        "api.example.com - /v1/debug blocked by WAF",
        "admin.example.com - /admin/config blocked",
        "Generic WAF rule on POST",
      ],
    });

    // Create surfaces with distinct hosts
    const surfaces = [
      { id: "surface-api", hosts: ["https://api.example.com"] },
      { id: "surface-admin", hosts: ["https://admin.example.com"] },
    ];
    writeFileAtomic(
      attackSurfacePath(domain),
      `${JSON.stringify({ surfaces }, null, 2)}\n`,
    );
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-api" },
      { agent: "a2", surface_id: "surface-admin" },
    ]);

    // Agent a1 should see api.example.com dead ends + generic
    const brief1 = JSON.parse(readHunterBrief({
      target_domain: domain, wave: "w1", agent: "a1",
    }));
    assert.deepEqual(brief1.dead_ends, [
      "api.example.com - /v1/users returns 404",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief1.waf_blocked_endpoints, [
      "api.example.com - /v1/debug blocked by WAF",
      "Generic WAF rule on POST",
    ]);

    // Agent a2 should see admin.example.com dead ends + generic
    const brief2 = JSON.parse(readHunterBrief({
      target_domain: domain, wave: "w1", agent: "a2",
    }));
    assert.deepEqual(brief2.dead_ends, [
      "admin.example.com - /panel gives 403",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief2.waf_blocked_endpoints, [
      "admin.example.com - /admin/config blocked",
      "Generic WAF rule on POST",
    ]);
  });
});

test("filterExclusionsByHosts caps at limit and reports omitted count", () => {
  const entries = Array.from({ length: 150 }, (_, i) => `generic entry ${i}`);
  const result = filterExclusionsByHosts(entries, ["https://example.com"], 100);
  assert.equal(result.filtered.length, 100);
  assert.equal(result.total, 150);
  assert.equal(result.omitted, 50);
});

test("filterExclusionsByHosts handles empty and null input", () => {
  assert.deepStrictEqual(filterExclusionsByHosts([], []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(null, []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(undefined, []), { filtered: [], total: 0, omitted: 0 });
});

// ── Bug 1: Path traversal via target_domain ──

test("assertSafeDomain rejects path traversal sequences", () => {
  assert.throws(() => assertSafeDomain("../../etc"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/../bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain(".."), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo\\bar"), /invalid path characters/);
});

test("assertSafeDomain accepts valid domain names", () => {
  assert.equal(assertSafeDomain("example.com"), "example.com");
  assert.equal(assertSafeDomain("sub.example.com"), "sub.example.com");
  assert.equal(assertSafeDomain("my-target.io"), "my-target.io");
});

test("sessionDir rejects path traversal in target_domain", () => {
  assert.throws(() => sessionDir("../../.ssh"), /invalid path characters/);
  assert.throws(() => sessionDir("../secrets"), /invalid path characters/);
});

test("initSession rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => initSession({ target_domain: "../../etc", target_url: "https://evil.com" }),
      /invalid path characters/,
    );
  });
});

// ── Bug 2: writeHandoff validates domain and uses atomic writes ──

test("writeHandoff rejects missing target_domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_url: "https://example.com", session_number: 1 }),
      /target_domain/,
    );
  });
});

test("writeHandoff rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_domain: "../evil", target_url: "https://example.com", session_number: 1 }),
      /invalid path characters/,
    );
  });
});

test("writeHandoff writes file atomically", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeHandoff({
      target_domain: domain,
      target_url: "https://example.com",
      session_number: 1,
      findings_summary: [{ id: "F-1", severity: "high", title: "Test" }],
    });

    const handoffPath = path.join(dir, "SESSION_HANDOFF.md");
    assert.ok(fs.existsSync(handoffPath));
    const content = fs.readFileSync(handoffPath, "utf8");
    assert.ok(content.includes("F-1"));
  });
});

// ── Bug 3: auth path resolution requires explicit target domain ──

test("resolveAuthJsonPath requires an explicit domain by default and keeps fallback legacy-only", () => {
  withTempHome((tempHome) => {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");

    // Create two session dirs: aaa-old.com (older) and zzz-new.com (newer alphabetically but older mtime)
    const oldDir = path.join(sessionsDir, "zzz-alphabetically-last.com");
    const newDir = path.join(sessionsDir, "aaa-alphabetically-first.com");
    fs.mkdirSync(oldDir, { recursive: true });
    fs.mkdirSync(newDir, { recursive: true });

    // Touch the "aaa" dir to make it most recent
    const now = new Date();
    fs.utimesSync(oldDir, new Date(now - 60000), new Date(now - 60000));
    fs.utimesSync(newDir, now, now);

    assert.equal(resolveAuthJsonPath(null), null);
    const legacyResult = resolveAuthJsonPath(null, { allowLegacyFallback: true });
    assert.ok(legacyResult.includes("aaa-alphabetically-first.com"));
  });
});

test("auth storage rejects path traversal target domains", () => {
  withTempHome(() => {
    assert.throws(
      () => resolveAuthJsonPath("../evil"),
      /invalid path characters/,
    );
    assert.throws(
      () => authStore({ target_domain: "../evil", profile_name: "attacker", headers: { Authorization: "Bearer token" } }),
      /invalid path characters/,
    );
  });
});

// ── Bug 4: httpScan URL validation ──

test("validateScanUrl rejects localhost", () => {
  assert.throws(() => validateScanUrl("http://localhost/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://%6c%6f%63%61%6c%68%6f%73%74/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://127.0.0.1/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://127.1/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://0177.0.0.1/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://2130706433/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://0x7f000001/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://0.0.0.0/"), /Blocked internal/);
});

test("validateScanUrl rejects private IP ranges", () => {
  assert.throws(() => validateScanUrl("http://10.0.0.1/secret"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://192.168.1.1/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://172.16.0.1/internal"), /Blocked internal/);
});

test("validateScanUrl rejects private, link-local, and IPv4-mapped IPv6 addresses", () => {
  assert.throws(() => validateScanUrl("http://[::1]/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://[fc00::1]/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://[fd12:3456::1]/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://[fe80::1]/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://[::ffff:127.0.0.1]/admin"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://[::ffff:7f00:1]/admin"), /Blocked internal/);
});

test("validateScanUrl rejects cloud metadata endpoint", () => {
  assert.throws(() => validateScanUrl("http://169.254.169.254/latest/meta-data/"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://metadata.google.internal/computeMetadata/v1/"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://metadata/latest/meta-data/"), /Blocked internal/);
});

test("validateScanUrl rejects unsupported protocols", () => {
  assert.throws(() => validateScanUrl("ftp://example.com/file"), /Unsupported protocol/);
  assert.throws(() => validateScanUrl("file:///etc/passwd"), /Unsupported protocol/);
});

test("validateScanUrl rejects internal/local domains", () => {
  assert.throws(() => validateScanUrl("http://service.internal/api"), /Blocked internal/);
  assert.throws(() => validateScanUrl("http://printer.local/status"), /Blocked internal/);
});

test("validateScanUrl accepts valid external URLs", () => {
  assert.doesNotThrow(() => validateScanUrl("https://example.com/api/v1/users"));
  assert.doesNotThrow(() => validateScanUrl("http://target.io/login"));
});

test("validateScanUrl rejects malformed URLs", () => {
  assert.throws(() => validateScanUrl("not-a-url"), /Invalid URL/);
});

test("scope guard blocks out-of-scope Bash network commands by default and redacts query values", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain);

    const blocked = runScopeGuard('curl "https://evil.example/path?token=supersecret"', { home: tempHome });
    assert.equal(blocked.status, 2);
    assert.match(blocked.stderr, /evil\.example/);
    assert.match(blocked.stderr, /example\.com/);
    assert.doesNotMatch(blocked.stderr, /supersecret/);

    const logContent = fs.readFileSync(path.join(sessionDir(domain), "scope-warnings.log"), "utf8");
    assert.match(logContent, /OUT-OF-SCOPE: evil\.example/);
    assert.match(logContent, /\?REDACTED/);
    assert.doesNotMatch(logContent, /supersecret/);

    const logOnly = runScopeGuard('curl "https://other.example.net/path?token=still-secret"', {
      home: tempHome,
      env: { BOUNTY_SCOPE_LOG_ONLY: "1" },
    });
    assert.equal(logOnly.status, 0);

    const allowed = runScopeGuard("curl https://app.example.com/ok", { home: tempHome });
    assert.equal(allowed.status, 0);
  });
});

test("scope guard deny-list blocks even when out-of-scope log-only mode is set", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain);
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    const denied = runScopeGuard("curl https://blocked.example.com/admin", {
      home: tempHome,
      env: { BOUNTY_SCOPE_LOG_ONLY: "1" },
    });
    assert.equal(denied.status, 2);
    assert.match(denied.stderr, /deny list/);
  });
});

test("scope guards allow public-intel hosts only when URL references the active target", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain);

    const bashUnrelated = runScopeGuard('curl "https://crt.sh/?q=other.com"', { home: tempHome });
    assert.equal(bashUnrelated.status, 2);
    assert.match(bashUnrelated.stderr, /crt\.sh/);

    const bashTarget = runScopeGuard('curl "https://crt.sh/?q=example.com"', { home: tempHome });
    assert.equal(bashTarget.status, 0);

    const mcpUnrelated = runMcpScopeGuard({
      target_domain: domain,
      method: "GET",
      url: "https://crt.sh/?q=other.com",
    }, { home: tempHome });
    assert.equal(mcpUnrelated.status, 0);
    assert.match(fs.readFileSync(path.join(sessionDir(domain), "scope-warnings.log"), "utf8"), /OUT-OF-SCOPE \(http_scan\): crt\.sh/);

    const mcpTarget = runMcpScopeGuard({
      target_domain: domain,
      method: "GET",
      url: "https://crt.sh/?q=example.com",
    }, { home: tempHome });
    assert.equal(mcpTarget.status, 0);

    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "crt.sh\n");
    const denied = runMcpScopeGuard({
      target_domain: domain,
      method: "GET",
      url: "https://crt.sh/?q=example.com",
    }, { home: tempHome });
    assert.equal(denied.status, 2);
    assert.match(denied.stderr, /deny list/);
  });
});

// ── Bug 5: Session lock uses owner metadata for ownership verification ──

test("session lock creates an atomic metadata lock file", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    const release = acquireSessionLock(domain);
    try {
      const lockPath = sessionLockPath(domain);
      assert.ok(fs.statSync(lockPath).isFile());
      const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(metadata.pid, process.pid);
      assert.ok(metadata.hostname);
      assert.ok(metadata.timestamp);
      assert.ok(metadata.token);
    } finally {
      release();
    }
    assert.ok(!fs.existsSync(sessionLockPath(domain)));
  });
});

test("session lock stale override uses JSON timestamp and does not remove replacement locks", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const lockPath = sessionLockPath(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "old",
    })}\n`);
    const freshDate = new Date();
    fs.utimesSync(lockPath, freshDate, freshDate);

    const release = acquireSessionLock(domain);
    try {
      const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(metadata.pid, process.pid);
      assert.notEqual(metadata.token, "old");
    } finally {
      release();
    }

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "stale",
    })}\n`);
    const snapshot = readSessionLockSnapshot(lockPath);
    assert.equal(snapshot.isStale, true);

    fs.rmSync(lockPath, { force: true });
    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: process.pid,
      hostname: "new-host",
      timestamp: new Date().toISOString(),
      token: "replacement",
    })}\n`);

    assert.equal(removeStaleSessionLock(lockPath, snapshot), false);
    assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token, "replacement");
  });
});

// ── Fix 1: Verification round filename mapping ──

test("verificationRoundPaths returns balanced.json for balanced round (not brutalist-final.json)", () => {
  withTempHome(() => {
    const paths = verificationRoundPaths("example.com", "balanced");
    assert.ok(paths.json.endsWith("balanced.json"), `Expected balanced.json, got ${paths.json}`);
    assert.ok(paths.markdown.endsWith("balanced.md"), `Expected balanced.md, got ${paths.markdown}`);
    assert.ok(!paths.json.includes("brutalist-final"), "Should not contain brutalist-final");
  });
});

// ── Fix 2: Finding counter race condition (sequential IDs under lock) ──

test("recordFinding produces sequential IDs without gaps when called rapidly", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 1, pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const ids = [];
    for (let i = 0; i < 5; i++) {
      const result = JSON.parse(recordFinding({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        title: `Finding ${i}`,
        severity: "medium",
        endpoint: `/api/test${i}`,
        description: "Test",
        proof_of_concept: "curl test",
        response_evidence: "200 OK",
        impact: "Test impact",
        validated: true,
      }));
      ids.push(result.finding_id);
    }

    assert.deepEqual(ids, ["F-1", "F-2", "F-3", "F-4", "F-5"]);
  });
});

// ── Fix 3: Session lock stale timeout ──

test("SESSION_LOCK_STALE_MS is 300 seconds", () => {
  assert.equal(SESSION_LOCK_STALE_MS, 300_000);
});

// ── Fix 6: waveStatus returns coverage data ──

test("bounty_wave_status returns coverage_pct when attack surface and state exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: null,
      explored: ["surface-a"],
    });

    // Seed attack surface with priorities
    const surfaces = [
      { id: "surface-a", hosts: ["https://example.com"], priority: "CRITICAL" },
      { id: "surface-b", hosts: ["https://api.example.com"], priority: "HIGH" },
      { id: "surface-c", hosts: ["https://cdn.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.ok(result.coverage != null, "coverage should not be null");
    assert.equal(result.coverage.total_surfaces, 3);
    assert.equal(result.coverage.non_low_total, 2);     // CRITICAL + HIGH
    assert.equal(result.coverage.non_low_explored, 1);   // only surface-a explored
    assert.equal(result.coverage.coverage_pct, 50);       // 1/2 = 50%
    assert.equal(result.coverage.unexplored_high, 1);     // surface-b is HIGH and unexplored
  });
});

test("bounty_wave_status coverage_pct is 100 when all surfaces are LOW", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "HUNT", hunt_wave: 0, pending_wave: null });

    const surfaces = [
      { id: "surface-a", hosts: ["https://cdn.example.com"], priority: "LOW" },
      { id: "surface-b", hosts: ["https://static.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.equal(result.coverage.non_low_total, 0);
    assert.equal(result.coverage.coverage_pct, 100);  // 0/0 → 100% (no non-LOW to explore)
  });
});

// ── Auth silent fallback: httpScan returns error when auth_profile not found ──

test("httpScan returns error when auth_profile is requested but not found", async () => {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-authtest-"));
  process.env.HOME = tempHome;
  try {
    const result = JSON.parse(await executeTool("bounty_http_scan", {
      target_domain: "example.com",
      method: "GET",
      url: "https://example.com/",
      auth_profile: "nonexistent_test_profile_xyz",
    }));
    assert.ok(result.error, `Should return an error, got keys: ${JSON.stringify(Object.keys(result))}`);
    assert.ok(result.error.includes("not found"), `Error should mention profile not found: ${result.error}`);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

// ── Verification completeness: malformed prior round is a hard error, not skipped ──

test("writeVerificationRound rejects balanced round when brutalist JSON is malformed", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain, { severity: "high" });

    // Write valid brutalist round first
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
    });

    // Corrupt the brutalist JSON
    const brutalistPath = verificationRoundPaths(domain, "brutalist").json;
    fs.writeFileSync(brutalistPath, "NOT VALID JSON{{{");

    // Balanced round should fail because prior round is malformed (not silently skip)
    assert.throws(
      () => writeVerificationRound({
        target_domain: domain,
        round: "balanced",
        results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
      }),
      /Unexpected token/,  // JSON.parse error
    );
  });
});

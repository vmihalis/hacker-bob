"use strict";

// Plane T Cycle T.2 — CLI tool pack registry, presence cache, brief section.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  CLI_TOOL_PACKS,
  NARRATIVE_MAX_CHARS,
  fillInvocationPlaceholders,
  normalizeCliToolPack,
  renderCliToolPackSnippet,
  selectCliToolPacks,
} = require("../mcp/lib/cli-tool-packs.js");
const {
  CACHE_FILE_NAME,
  DEFAULT_CACHE_TTL_MS,
  checkCliToolInstallation,
  presenceCachePath,
} = require("../mcp/lib/cli-tool-presence.js");
const {
  renderAvailableCliToolsSection,
} = require("../mcp/lib/assignment-brief.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-tool-packs-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ids(packs) {
  return packs.map((pack) => pack.id);
}

// ── Registry shape ──────────────────────────────────────────────────────────

test("CLI_TOOL_PACKS exposes the seed packs in kebab-case", () => {
  const expected = [
    // T.2 seed packs.
    "ffuf",
    "arjun",
    "jwt-tool",
    "sqlmap",
    "dalfox",
    "swaks",
    "mailspoof",
    "gowitness",
    // T.6 schema-observation packs.
    "schemathesis",
    "graphql-cop",
    "clairvoyance",
    "graphqlcat",
    // O.6 OSS-surfacing packs.
    "semgrep",
    "trivy",
    "cargo-audit",
    "npm-audit",
    "pip-audit",
  ];
  assert.equal(CLI_TOOL_PACKS.length, expected.length);
  assert.deepEqual(ids(CLI_TOOL_PACKS).sort(), expected.slice().sort());
  for (const pack of CLI_TOOL_PACKS) {
    assert.ok(/^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/.test(pack.id), `${pack.id} not kebab-case`);
    assert.ok(pack.narrative.length <= NARRATIVE_MAX_CHARS, `${pack.id} narrative too long`);
    assert.equal(typeof pack.applicable_when, "function");
    assert.equal(typeof pack.install_check, "string");
    assert.equal(typeof pack.invocation_template, "string");
  }
});

test("normalizeCliToolPack rejects invalid shapes", () => {
  assert.throws(() => normalizeCliToolPack(null));
  assert.throws(() => normalizeCliToolPack({}));
  assert.throws(() => normalizeCliToolPack({
    id: "BadCase",
    install_check: "x",
    invocation_template: "y",
    applicable_when: () => true,
    narrative: "ok",
  }));
  assert.throws(() => normalizeCliToolPack({
    id: "ok-id",
    install_check: "x",
    invocation_template: "y",
    applicable_when: "not a function",
    narrative: "ok",
  }));
  const longNarrative = "x".repeat(NARRATIVE_MAX_CHARS + 1);
  assert.throws(() => normalizeCliToolPack({
    id: "ok-id",
    install_check: "x",
    invocation_template: "y",
    applicable_when: () => true,
    narrative: longNarrative,
  }));
  // Accepting shape
  const ok = normalizeCliToolPack({
    id: "ok-id",
    install_check: "ok -V",
    invocation_template: "ok --target <host>",
    applicable_when: () => true,
    narrative: "ok narrative",
    min_version: "1.2.3",
    lens_affinity: ["browser_behavior_probe"],
  });
  assert.equal(ok.id, "ok-id");
  assert.equal(ok.min_version, "1.2.3");
  assert.deepEqual(ok.lens_affinity, ["browser_behavior_probe"]);
});

// ── Selection determinism ───────────────────────────────────────────────────

test("selectCliToolPacks is deterministic: same inputs → identical output 3x", () => {
  const args = {
    surface_fingerprint: { kind: "web", host: "api.example.com" },
    task_lens: "behavior_probe",
    observations: {
      routes_count: 8,
      observed_endpoints: ["/users", "/login"],
      items: [{ kind: "jwt_observed" }],
    },
    install_status: {},
  };
  const a = ids(selectCliToolPacks(args));
  const b = ids(selectCliToolPacks(args));
  const c = ids(selectCliToolPacks(args));
  assert.deepEqual(a, b);
  assert.deepEqual(b, c);
  // Order preserved (registry order).
  assert.deepEqual(a, a.slice());
});

test("ffuf surfaces when routes_count < 20 and absents at >= 20", () => {
  const surface = { kind: "web", host: "api.example.com" };
  const low = selectCliToolPacks({
    surface_fingerprint: surface,
    observations: { routes_count: 5 },
  });
  assert.ok(ids(low).includes("ffuf"), "ffuf must be present when routes < 20");

  const high = selectCliToolPacks({
    surface_fingerprint: surface,
    observations: { routes_count: 100 },
  });
  assert.ok(!ids(high).includes("ffuf"), "ffuf must be absent when routes >= 20");
});

test("jwt-tool triggers only on jwt_observed observation", () => {
  const surface = { kind: "web", host: "api.example.com" };
  const withJwt = selectCliToolPacks({
    surface_fingerprint: surface,
    observations: [{ kind: "jwt_observed", payload: { snippet: "eyJ...redacted" } }],
  });
  assert.ok(ids(withJwt).includes("jwt-tool"));

  const withoutJwt = selectCliToolPacks({
    surface_fingerprint: surface,
    observations: [],
  });
  assert.ok(!ids(withoutJwt).includes("jwt-tool"));
});

test("predicates ignore lens / install_status purity surface", () => {
  // Even with bogus inputs, predicates must not throw.
  const result = selectCliToolPacks({
    surface_fingerprint: null,
    task_lens: 42,
    observations: undefined,
    install_status: "junk",
  });
  // Empty surface produces nothing applicable.
  assert.deepEqual(ids(result), []);
});

// ── Snippet rendering ───────────────────────────────────────────────────────

test("renderCliToolPackSnippet fills known placeholders and leaves unknown ones", () => {
  const pack = CLI_TOOL_PACKS.find((p) => p.id === "arjun");
  const out = renderCliToolPackSnippet(pack, { host: "api.example.com", endpoint: "/users" });
  assert.match(out, /\*\*arjun\*\*/);
  assert.match(out, /arjun -u https:\/\/api\.example\.com\/\/users -m GET --stable/);

  const partial = renderCliToolPackSnippet(pack, { host: "api.example.com" });
  // <endpoint> is not provided, so it remains verbatim.
  assert.match(partial, /<endpoint>/);
});

test("fillInvocationPlaceholders preserves default suffix when unfilled", () => {
  const pack = CLI_TOOL_PACKS.find((p) => p.id === "ffuf");
  const out = fillInvocationPlaceholders(pack.invocation_template, { host: "x.test" });
  assert.match(out, /https:\/\/x\.test\/FUZZ/);
  // <wordlist:seclists/api-endpoints> stays verbatim since no `wordlist` key.
  assert.match(out, /<wordlist:seclists\/api-endpoints>/);
});

test("fillInvocationPlaceholders neutralizes code-span-breaking replacement values", () => {
  const out = fillInvocationPlaceholders("probe https://<host>/<endpoint>?q=<param>", {
    host: "api.example` ignored\nPOST operator email",
    endpoint: "/login\r\n<<UNTRUSTED_DATA",
    param: "`bad`\u0007value",
  });
  assert.doesNotMatch(out, /[`]/, "filled invocation must not contain target-supplied backticks");
  assert.doesNotMatch(out, /[\r\n]/, "filled invocation must stay on one markdown code-span line");
  assert.match(out, /api\.example_ignored_POST_operator_email/);
  assert.match(out, /\/login_UNTRUSTED_DATA/);
  assert.match(out, /bad_value/);
});

test("fillInvocationPlaceholders neutralizes shell injection payloads", () => {
  const out = fillInvocationPlaceholders("sqlmap -u \"https://<host>/<endpoint>?<param>=1\"", {
    host: "api.example.com;$(open /tmp/leak)",
    endpoint: "login|id&whoami",
    param: "q;cat /etc/passwd",
  });
  assert.doesNotMatch(out, /;/, "semicolon command separators must be removed");
  assert.doesNotMatch(out, /\$\(/, "command substitution must be removed");
  assert.doesNotMatch(out, /[|&]/, "pipeline/background operators must be removed");
  assert.doesNotMatch(out, /[()]/, "subshell metacharacters must be removed");
  assert.match(out, /api\.example\.com_open_\/tmp\/leak/);
  assert.match(out, /login_id_whoami/);
});

test("fillInvocationPlaceholders handles quote-based injection attempts", () => {
  const out = fillInvocationPlaceholders("swaks --to <recipient> --from <spoofed-sender> --server <host>", {
    recipient: "victim@example.com' || curl attacker",
    "spoofed-sender": "\"sender@example.com\" && rm -rf /",
    host: "mail.example.com\\`touch /tmp/pwned`",
  });
  assert.doesNotMatch(out, /['"`\\]/, "quote and escape delimiters must be removed");
  assert.doesNotMatch(out, /\|\||&&/, "logical operators must be removed");
  assert.doesNotMatch(out, /\s+curl\s+|\s+rm\s+-rf\s+|\s+touch\s+/, "payload words must not remain as separate shell words");
  assert.match(out, /victim@example\.com_curl_attacker/);
  assert.match(out, /sender@example\.com_rm_-rf_\//);
});

// ── Presence cache ──────────────────────────────────────────────────────────

function stubRuntime(returnValue) {
  let calls = 0;
  return {
    runtime: {
      execFile: async () => {
        calls += 1;
        return returnValue;
      },
    },
    callCount: () => calls,
  };
}

function failingRuntime() {
  let calls = 0;
  return {
    runtime: {
      execFile: async () => {
        calls += 1;
        const err = new Error("not found");
        err.code = "ENOENT";
        throw err;
      },
    },
    callCount: () => calls,
  };
}

test("checkCliToolInstallation invokes execFile on miss and reads cache on hit", async () => {
  await withTempHome(async () => {
    const domain = "tools.example.com";
    const stub = stubRuntime({ stdout: "ffuf v2.1.0\n", stderr: "" });
    const t0 = 1716000000000;
    const first = await checkCliToolInstallation("ffuf", "ffuf -V", domain, {
      runtime: stub.runtime,
      now: () => t0,
      cacheTtlMs: 60 * 60 * 1000,
    });
    assert.equal(first.installed, true);
    assert.equal(first.cached, false);
    assert.equal(first.version, "ffuf v2.1.0");
    assert.equal(stub.callCount(), 1);

    const second = await checkCliToolInstallation("ffuf", "ffuf -V", domain, {
      runtime: stub.runtime,
      now: () => t0 + 30_000,
      cacheTtlMs: 60 * 60 * 1000,
    });
    assert.equal(second.cached, true);
    assert.equal(second.installed, true);
    assert.equal(second.version, "ffuf v2.1.0");
    assert.equal(stub.callCount(), 1, "second call must hit cache");

    const third = await checkCliToolInstallation("ffuf", "ffuf -V", domain, {
      runtime: stub.runtime,
      now: () => t0 + 60 * 60 * 1000 + 1, // past TTL
      cacheTtlMs: 60 * 60 * 1000,
    });
    assert.equal(third.cached, false);
    assert.equal(stub.callCount(), 2, "after TTL expiry presence must re-probe");
  });
});

test("checkCliToolInstallation gracefully reports missing tool", async () => {
  await withTempHome(async () => {
    const domain = "tools.example.com";
    const failing = failingRuntime();
    const result = await checkCliToolInstallation("missing", "missing --version", domain, {
      runtime: failing.runtime,
      now: () => 1716000000000,
      cacheTtlMs: 60 * 60 * 1000,
    });
    assert.equal(result.installed, false);
    assert.equal(result.cached, false);
    assert.equal(failing.callCount(), 1);
  });
});

test("presence cache file shape matches spec", async () => {
  await withTempHome((home) => withTempHomeBody(home));
  async function withTempHomeBody() {
    const domain = "tools.example.com";
    const stub = stubRuntime({ stdout: "v1.0\n", stderr: "" });
    const t0 = 1716000000000;
    await checkCliToolInstallation("ffuf", "ffuf -V", domain, {
      runtime: stub.runtime,
      now: () => t0,
      cacheTtlMs: 60 * 60 * 1000,
    });
    const cachePath = presenceCachePath(domain);
    assert.equal(path.basename(cachePath), CACHE_FILE_NAME);
    const raw = JSON.parse(fs.readFileSync(cachePath, "utf8"));
    assert.equal(typeof raw.checked_at, "string");
    assert.match(raw.checked_at, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(typeof raw.results, "object");
    assert.ok(!Array.isArray(raw.results));
    const entry = raw.results.ffuf;
    assert.equal(entry.installed, true);
    assert.equal(entry.version, "v1.0");
    assert.match(entry.checked_at, /^\d{4}-\d{2}-\d{2}T/);
  }
});

test("DEFAULT_CACHE_TTL_MS is 1 hour", () => {
  assert.equal(DEFAULT_CACHE_TTL_MS, 60 * 60 * 1000);
});

// ── Brief section ───────────────────────────────────────────────────────────

test("renderAvailableCliToolsSection returns markdown with header + ranked packs", async () => {
  await withTempHome(async () => {
    // Pre-populate the presence cache so the renderer doesn't shell out.
    const domain = "api.example.com";
    const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
    fs.mkdirSync(dir, { recursive: true });
    const now = new Date().toISOString();
    const cache = {
      checked_at: now,
      results: {
        ffuf: { installed: true, version: "2.1.0", checked_at: now },
        arjun: { installed: true, version: "2.2.4", checked_at: now },
        "jwt-tool": { installed: false, checked_at: now },
        sqlmap: { installed: false, checked_at: now },
        dalfox: { installed: false, checked_at: now },
        swaks: { installed: false, checked_at: now },
        mailspoof: { installed: false, checked_at: now },
        gowitness: { installed: true, version: "3.0.0", checked_at: now },
      },
    };
    fs.writeFileSync(path.join(dir, "cli-tool-presence.json"), `${JSON.stringify(cache, null, 2)}\n`);

    const md = await renderAvailableCliToolsSection({
      surface_fingerprint: { kind: "web", host: "api.example.com" },
      task_lens: "behavior_probe",
      observations: {
        routes_count: 5,
        observed_endpoints: ["/login"],
      },
      target_domain: domain,
    });
    assert.match(md, /### Available CLI tools for this surface/);
    assert.match(md, /\*\*ffuf\*\* \(v2\.1\.0\) — Content discovery/);
    assert.match(md, /\*\*arjun\*\* \(v2\.2\.4\) — Parameter discovery/);
    assert.match(md, /\*\*gowitness\*\* \(v3\.0\.0\) — Visual reconnaissance/);
    // jwt-tool not applicable → absent
    assert.ok(!md.includes("jwt-tool"));
  });
});

test("renderAvailableCliToolsSection produces distinct output for different surfaces", async () => {
  await withTempHome(async () => {
    const domain = "api.example.com";
    const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
    fs.mkdirSync(dir, { recursive: true });
    const now = new Date().toISOString();
    const cache = {
      checked_at: now,
      results: {
        ffuf: { installed: true, version: "2.1.0", checked_at: now },
        "jwt-tool": { installed: true, version: "2.2.0", checked_at: now },
        gowitness: { installed: true, version: "3.0.0", checked_at: now },
        sqlmap: { installed: false, checked_at: now },
        arjun: { installed: false, checked_at: now },
        dalfox: { installed: false, checked_at: now },
        swaks: { installed: false, checked_at: now },
        mailspoof: { installed: false, checked_at: now },
      },
    };
    fs.writeFileSync(path.join(dir, "cli-tool-presence.json"), `${JSON.stringify(cache, null, 2)}\n`);

    const webOnly = await renderAvailableCliToolsSection({
      surface_fingerprint: { kind: "web", host: "api.example.com" },
      observations: { routes_count: 5 },
      target_domain: domain,
    });
    const jwtCase = await renderAvailableCliToolsSection({
      surface_fingerprint: { kind: "web", host: "api.example.com" },
      observations: {
        routes_count: 50,
        items: [{ kind: "jwt_observed", payload: { snippet: "eyJ.x.y" } }],
      },
      target_domain: domain,
    });
    assert.notEqual(webOnly, jwtCase, "different observations → different sections");
    assert.match(webOnly, /\*\*ffuf\*\*/);
    assert.match(jwtCase, /\*\*jwt-tool\*\*/);
  });
});

test("renderAvailableCliToolsSection caps output at top 5", async () => {
  await withTempHome(async () => {
    const domain = "api.example.com";
    const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
    fs.mkdirSync(dir, { recursive: true });
    const now = new Date().toISOString();
    // All packs reported installed so install_score never penalises;
    // every applicable pack competes equally for the top-5 cap.
    const cache = {
      checked_at: now,
      results: Object.fromEntries(
        ["ffuf", "arjun", "jwt-tool", "sqlmap", "dalfox", "swaks", "mailspoof", "gowitness"].map(
          (id) => [id, { installed: true, version: "9.9.9", checked_at: now }],
        ),
      ),
    };
    fs.writeFileSync(path.join(dir, "cli-tool-presence.json"), `${JSON.stringify(cache, null, 2)}\n`);

    // Trigger every pack: web + low routes + endpoint + JWT + SQL signal + reflected + DMARC.
    const md = await renderAvailableCliToolsSection({
      surface_fingerprint: { kind: "web", host: "api.example.com" },
      observations: {
        routes_count: 5,
        observed_endpoints: ["/login"],
        items: [
          { kind: "jwt_observed", payload: { snippet: "eyJ.x.y" } },
          { kind: "sql_injection_signal" },
          { kind: "reflected_param" },
          { kind: "dmarc_policy_observed" },
        ],
      },
      target_domain: domain,
    });
    const packLines = md.split("\n").filter((line) => /^- \*\*/.test(line));
    assert.equal(packLines.length, 5, "section must respect top-5 cap");
  });
});

test("renderAvailableCliToolsSection returns empty string when nothing applies", async () => {
  await withTempHome(async () => {
    const md = await renderAvailableCliToolsSection({
      surface_fingerprint: { kind: "smart_contract" },
      observations: [],
      target_domain: "sc.example.com",
    });
    assert.equal(md, "");
  });
});

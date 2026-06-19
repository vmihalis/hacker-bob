"use strict";

// Plane T Cycle T.8 — adaptive pack-telemetry curation.
//
// These tests pin the contract Cycle T.8 introduces on top of the T.3
// scoring formula:
//
//   - Default-off (T-D5): a session with no pack-telemetry-config.json sees
//     every promotion = 0 and the relevance ranking is identical to T.3.
//   - Adaptive-on with no telemetry: still returns zero promotions because
//     `loadPackTelemetry` synthesizes no signal.
//   - Adaptive-on with synthetic invocations: claim_correlation reflects
//     how often a candidate-claim followed a pack invocation within the
//     correlation window; telemetry_promotion = claim_correlation -
//     baseline_rate.
//   - Adaptive-on with low-correlation, high-invocation pack: the pack is
//     marked `demoted: true` in `selectCliToolPacks` output and drops below
//     other applicable packs once the brief renderer applies the -1.0
//     penalty (and likely falls out of the top-5 cap).
//   - bob_set_pack_telemetry_config round-trips through disk and is read by
//     the brief assembly path.
//   - Determinism (T-R8): the same telemetry + the same `now` produces the
//     same scoring output, even with adaptive curation enabled.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  CLI_TOOL_PACKS,
  selectCliToolPacks,
} = require("../mcp/lib/cli-tool-packs.js");
const {
  DEFAULT_BASELINE_RATE,
  DEFAULT_CORRELATION_WINDOW_MS,
  DEMOTION_SCORE_PENALTY,
  loadPackTelemetry,
  packTelemetryConfigPath,
  readPackTelemetryConfig,
  writePackTelemetryConfig,
} = require("../mcp/lib/pack-telemetry.js");
const {
  renderAvailableCliToolsSectionSync,
} = require("../mcp/lib/assignment-brief.js");
const {
  toolInvocationTelemetryPath,
} = require("../mcp/lib/tool-telemetry.js");
const {
  TOOL_HANDLERS,
  TOOL_MANIFEST,
} = require("../mcp/lib/tool-registry.js");

function withTempEnv(fn) {
  const prevHome = process.env.HOME;
  const prevTelemetryDir = process.env.BOUNTY_TELEMETRY_DIR;
  const prevWindow = process.env.BOB_PACK_TELEMETRY_WINDOW_MS;
  const prevCorrelation = process.env.BOB_PACK_TELEMETRY_CORRELATION_WINDOW_MS;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pack-telemetry-"));
  const telemetryDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pack-telemetry-tel-"));
  process.env.HOME = home;
  process.env.BOUNTY_TELEMETRY_DIR = telemetryDir;
  delete process.env.BOB_PACK_TELEMETRY_WINDOW_MS;
  delete process.env.BOB_PACK_TELEMETRY_CORRELATION_WINDOW_MS;
  try {
    return fn({ home, telemetryDir });
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevTelemetryDir === undefined) {
      delete process.env.BOUNTY_TELEMETRY_DIR;
    } else {
      process.env.BOUNTY_TELEMETRY_DIR = prevTelemetryDir;
    }
    if (prevWindow === undefined) {
      delete process.env.BOB_PACK_TELEMETRY_WINDOW_MS;
    } else {
      process.env.BOB_PACK_TELEMETRY_WINDOW_MS = prevWindow;
    }
    if (prevCorrelation === undefined) {
      delete process.env.BOB_PACK_TELEMETRY_CORRELATION_WINDOW_MS;
    } else {
      process.env.BOB_PACK_TELEMETRY_CORRELATION_WINDOW_MS = prevCorrelation;
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(telemetryDir, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function writeTelemetryLines(records) {
  const filePath = toolInvocationTelemetryPath(process.env);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const body = records.map((record) => JSON.stringify(record)).join("\n");
  fs.writeFileSync(filePath, `${body}\n`);
}

function isoAt(ms) {
  return new Date(ms).toISOString();
}

// Seed enough installs that the install_score term doesn't suppress packs we
// want to observe; mirrors the cli-tools brief integration test helper.
function seedInstallPresence(targetDomain, packIds) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", targetDomain);
  fs.mkdirSync(dir, { recursive: true });
  const results = {};
  const checkedAt = new Date().toISOString();
  for (const pack of CLI_TOOL_PACKS) {
    results[pack.id] = packIds.includes(pack.id)
      ? { installed: true, version: "9.9.9", checked_at: checkedAt }
      : { installed: false, checked_at: checkedAt };
  }
  fs.writeFileSync(
    path.join(dir, "cli-tool-presence.json"),
    `${JSON.stringify({ checked_at: checkedAt, results }, null, 2)}\n`,
  );
}

// ── Default-off (T-D5) ─────────────────────────────────────────────────────

test("default-off: with no pack-telemetry-config.json, every promotion is 0", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("default-off");
    // Even with telemetry lines on disk, default-off must suppress the read.
    writeTelemetryLines([
      { ts: isoAt(Date.now() - 1000), command: "ffuf -w wl -u https://example.com/FUZZ" },
      { ts: isoAt(Date.now() - 500), tool: "bob_record_candidate_claim" },
    ]);
    const telemetry = loadPackTelemetry(domain);
    assert.ok(telemetry.size === CLI_TOOL_PACKS.length);
    for (const pack of CLI_TOOL_PACKS) {
      const entry = telemetry.get(pack.id);
      assert.equal(entry.telemetry_promotion, 0, `${pack.id} promotion must be 0 when adaptive_curation is off`);
      assert.equal(entry.invocation_count, 0, `${pack.id} invocation_count must be 0 when adaptive_curation is off`);
      assert.equal(entry.claim_correlation, 0, `${pack.id} claim_correlation must be 0 when adaptive_curation is off`);
      assert.equal(entry.demoted, false);
    }
  });
});

// ── Adaptive-on, no signal ─────────────────────────────────────────────────

test("adaptive enabled with no invocations: still returns zero promotions", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("adaptive-empty");
    writePackTelemetryConfig(domain, { adaptive_curation: true });
    // No telemetry file at all — file absence is graceful.
    const telemetry = loadPackTelemetry(domain);
    for (const pack of CLI_TOOL_PACKS) {
      const entry = telemetry.get(pack.id);
      assert.equal(entry.invocation_count, 0);
      assert.equal(entry.telemetry_promotion, 0);
      assert.equal(entry.demoted, false);
    }
  });
});

// ── Adaptive-on, synthetic signal ──────────────────────────────────────────

test("adaptive enabled: 10 sqlmap invocations with 8 claim-correlated hit ~0.8 correlation", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("adaptive-signal");
    writePackTelemetryConfig(domain, { adaptive_curation: true });

    const base = Date.parse("2026-05-20T00:00:00.000Z");
    const records = [];
    for (let i = 0; i < 10; i += 1) {
      const invocationTs = base + i * 60_000; // 1 minute apart
      records.push({
        ts: isoAt(invocationTs),
        command: `sqlmap -u "https://example.com/api?id=${i}" --batch`,
      });
      if (i < 8) {
        // claim filed 30 seconds after each of the first 8 invocations,
        // inside the default 5-minute correlation window
        records.push({
          ts: isoAt(invocationTs + 30_000),
          tool: "bob_record_candidate_claim",
        });
      }
    }
    writeTelemetryLines(records);

    const now = base + 11 * 60_000; // just after the last invocation
    const telemetry = loadPackTelemetry(domain, { now: () => now });
    const sqlmap = telemetry.get("sqlmap");
    assert.equal(sqlmap.invocation_count, 10);
    assert.ok(
      Math.abs(sqlmap.claim_correlation - 0.8) < 1e-9,
      `claim_correlation expected ~0.8, got ${sqlmap.claim_correlation}`,
    );
    const expectedPromotion = 0.8 - DEFAULT_BASELINE_RATE;
    assert.ok(
      Math.abs(sqlmap.telemetry_promotion - expectedPromotion) < 1e-9,
      `telemetry_promotion expected ${expectedPromotion}, got ${sqlmap.telemetry_promotion}`,
    );
    // Other packs should still be at zero invocations.
    const ffuf = telemetry.get("ffuf");
    assert.equal(ffuf.invocation_count, 0);
    assert.equal(ffuf.claim_correlation, 0);
    assert.equal(ffuf.telemetry_promotion, 0);
  });
});

// ── Demotion ───────────────────────────────────────────────────────────────

test("adaptive enabled: low-correlation high-invocation pack is demoted and falls below top-5", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("adaptive-demotion");
    // Pick a tiny baseline / floor so the demotion math fires reliably for a
    // 10-invocation / 0-claim pack on a 7-day window.
    writePackTelemetryConfig(domain, {
      adaptive_curation: true,
      baseline_rate: 0.1,
      demotion_floor: 0.05,
      min_invocation_count: 5,
    });

    // Anchor to real Date.now() so the render path (which uses real time as
    // the rolling-window pivot) sees the synthetic invocations inside the
    // 7-day window. The loadPackTelemetry direct assertions below take an
    // explicit `now` so they remain pinned to the same anchor.
    const nowMs = Date.now();
    const base = nowMs - 60 * 60_000; // 1 hour ago
    const records = [];
    for (let i = 0; i < 10; i += 1) {
      records.push({
        ts: isoAt(base + i * 60_000),
        command: `dalfox url "https://example.com/q?x=${i}"`,
      });
      // ZERO claims correlated with dalfox.
    }
    writeTelemetryLines(records);

    const telemetry = loadPackTelemetry(domain, { now: () => nowMs });
    const dalfox = telemetry.get("dalfox");
    assert.equal(dalfox.invocation_count, 10);
    assert.equal(dalfox.claim_correlation, 0);
    // 10 invocations / 7-day window = ~1.43/week; multiplied by 0 correlation
    // = 0, which is below the 0.05 floor → demoted.
    assert.equal(dalfox.demoted, true, "dalfox must be demoted with zero claim correlation");

    // selectCliToolPacks should annotate the demoted pack.
    const surface = { kind: "web", host: "example.com" };
    const observations = {
      observed_endpoints: ["/api/users"],
      items: [{ kind: "reflected_param" }, { kind: "dmarc_policy_observed" }],
    };
    const selected = selectCliToolPacks({
      surface_fingerprint: surface,
      task_lens: "behavior_probe",
      observations,
      pack_telemetry: telemetry,
    });
    const dalfoxSelected = selected.find((p) => p.id === "dalfox");
    assert.ok(dalfoxSelected, "dalfox is applicable on a reflected_param web surface");
    assert.equal(dalfoxSelected.demoted, true, "demoted flag must be set on selected pack");

    // The brief renderer should drop dalfox below other top-relevance picks
    // via the -1.0 penalty. With enough competing applicable packs, dalfox
    // falls out of the top-5 entirely. ffuf/arjun/gowitness all apply for a
    // web surface with low routes_count + endpoints; swaks/mailspoof apply
    // for dmarc_policy_observed. That gives 5 non-demoted candidates ⇒
    // dalfox (score 1+2-1-0.05=1.95) is below all of them (score 3.0).
    seedInstallPresence(domain, CLI_TOOL_PACKS.map((p) => p.id));
    const md = renderAvailableCliToolsSectionSync({
      surface_fingerprint: surface,
      task_lens: "behavior_probe",
      observations,
      target_domain: domain,
    });
    const packLines = md.split("\n").filter((line) => /^- \*\*/.test(line));
    const dalfoxLine = packLines.find((line) => /\*\*dalfox\*\*/.test(line));
    assert.equal(
      dalfoxLine,
      undefined,
      "dalfox must drop out of the top-5 when 5+ non-demoted applicable packs exist",
    );
    // The five non-demoted high-score packs should all surface.
    const ids = packLines
      .map((line) => {
        const match = line.match(/^- \*\*([a-z0-9_-]+)\*\*/);
        return match ? match[1] : null;
      })
      .filter(Boolean);
    assert.deepEqual(
      ids.sort(),
      ["arjun", "ffuf", "gowitness", "mailspoof", "swaks"].sort(),
      "top-5 must contain the non-demoted candidates",
    );

    // Penalty math sanity: a demoted applicable pack scores at most
    // 1 (install) + 2 (applicable) + 0 (promotion) - 1 (demotion) = 2,
    // whereas a non-demoted installed applicable pack scores 3+.
    const dalfoxScoreFloor = 1 + 2 + (dalfox.telemetry_promotion * 0.5) + DEMOTION_SCORE_PENALTY;
    assert.ok(dalfoxScoreFloor <= 2.0, `demoted score must collapse below 3.0 (got ${dalfoxScoreFloor})`);
  });
});

test("demoted pack carries the (demoted) label when it does surface", () => {
  // When fewer than 5 non-demoted packs exist, a demoted applicable pack
  // can still appear in the rendered top-5 — and when it does, the label
  // must say so. This exercises the label-rendering branch independently
  // from the top-5 cap behaviour.
  withTempEnv(() => {
    const domain = uniqueDomain("demoted-label");
    writePackTelemetryConfig(domain, {
      adaptive_curation: true,
      baseline_rate: 0.1,
      demotion_floor: 0.05,
      min_invocation_count: 5,
    });
    const nowMs = Date.now();
    const base = nowMs - 60 * 60_000;
    const records = [];
    for (let i = 0; i < 10; i += 1) {
      records.push({ ts: isoAt(base + i * 60_000), command: `dalfox url x${i}` });
    }
    writeTelemetryLines(records);
    seedInstallPresence(domain, ["dalfox"]);

    // Web surface with reflected_param ONLY — dalfox is the only applicable
    // pack (ffuf, arjun, gowitness need different conditions or installs).
    // Actually web surfaces fire ffuf/arjun/gowitness on kind alone; we
    // restrict by withholding their installs so install_score = 0 keeps
    // their total at 2 (applicable only). Dalfox installed = 1+2-1 = 2.
    // Tie → alphabetical, so we expect dalfox + the others.
    const md = renderAvailableCliToolsSectionSync({
      surface_fingerprint: { kind: "web", host: "example.com", target_domain: domain },
      task_lens: "behavior_probe",
      observations: { observed_endpoints: ["/api/users"], items: [{ kind: "reflected_param" }] },
      target_domain: domain,
    });
    const dalfoxLine = md.split("\n").find((line) => /\*\*dalfox\*\*/.test(line));
    if (dalfoxLine) {
      assert.match(dalfoxLine, /\(demoted\)/, "rendered demoted pack must carry the label");
    }
  });
});

// ── Tool round-trip ────────────────────────────────────────────────────────

test("bob_set_pack_telemetry_config round-trips and the brief reflects the persisted config", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("set-tool");
    seedInstallPresence(domain, CLI_TOOL_PACKS.map((p) => p.id));
    const setHandler = TOOL_HANDLERS.bob_set_pack_telemetry_config;
    assert.equal(typeof setHandler, "function", "bob_set_pack_telemetry_config must be registered");

    // 1. With default-off, the brief renders the cli-tools section using the
    //    T.3 formula (no telemetry promotion, no demoted labels).
    const surface = { kind: "web", host: "example.com" };
    const observations = {
      observed_endpoints: ["/api/users"],
      items: [],
    };
    const mdBefore = renderAvailableCliToolsSectionSync({
      surface_fingerprint: surface,
      task_lens: "behavior_probe",
      observations,
      target_domain: domain,
    });
    assert.ok(!mdBefore.includes("(demoted)"), "default-off must never label a pack as demoted");

    // 2. Flip adaptive curation on via the tool.
    const responseRaw = setHandler({
      target_domain: domain,
      config: {
        adaptive_curation: true,
        baseline_rate: 0.2,
        demotion_floor: 0.05,
        min_invocation_count: 3,
      },
    });
    const response = JSON.parse(responseRaw);
    assert.equal(response.pack_telemetry_config.adaptive_curation, true);
    assert.equal(response.pack_telemetry_config.baseline_rate, 0.2);
    assert.equal(response.pack_telemetry_config.demotion_floor, 0.05);

    // 3. Read back through the library entry point.
    const reread = readPackTelemetryConfig(domain);
    assert.equal(reread.adaptive_curation, true);
    assert.equal(reread.baseline_rate, 0.2);
    assert.equal(reread.demotion_floor, 0.05);

    // 4. File exists at the canonical path.
    assert.ok(fs.existsSync(packTelemetryConfigPath(domain)));
    const raw = JSON.parse(fs.readFileSync(packTelemetryConfigPath(domain), "utf8"));
    assert.equal(raw.adaptive_curation, true);

    // 5. Tool is orchestrator-only and registered as mutating.
    const manifest = TOOL_MANIFEST.bob_set_pack_telemetry_config;
    assert.deepEqual(Array.from(manifest.role_bundles), ["orchestrator"]);
    assert.equal(manifest.mutating, true);
    assert.equal(manifest.global_preapproval, false);
    assert.equal(manifest.network_access, false);

    // 6. After flip, the brief STILL renders deterministically (no telemetry
    //    file → no signal → no demoted labels). What changed is that
    //    promotions COULD enter; absent telemetry they are 0.
    const mdAfter = renderAvailableCliToolsSectionSync({
      surface_fingerprint: surface,
      task_lens: "behavior_probe",
      observations,
      target_domain: domain,
    });
    assert.equal(typeof mdAfter, "string");
    assert.ok(!mdAfter.includes("(demoted)"));
  });
});

// ── Determinism (T-R8) ─────────────────────────────────────────────────────

test("determinism (T-R8): adaptive mode produces identical scoring for fixed telemetry", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("determ");
    seedInstallPresence(domain, ["ffuf", "arjun", "gowitness"]);
    writePackTelemetryConfig(domain, { adaptive_curation: true });

    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      { ts: isoAt(base), command: "ffuf -u https://example.com/FUZZ -w wl" },
      { ts: isoAt(base + 1000), tool: "bob_record_candidate_claim" },
      { ts: isoAt(base + 60_000), command: "ffuf -u https://example.com/FUZZ -w wl2" },
      { ts: isoAt(base + 61_000), tool: "bob_record_candidate_claim" },
    ]);

    const now = base + 120_000;
    const t1 = loadPackTelemetry(domain, { now: () => now });
    const t2 = loadPackTelemetry(domain, { now: () => now });
    const t3 = loadPackTelemetry(domain, { now: () => now });
    for (const pack of CLI_TOOL_PACKS) {
      assert.deepEqual(t1.get(pack.id), t2.get(pack.id), `pack ${pack.id} entry must be deterministic`);
      assert.deepEqual(t2.get(pack.id), t3.get(pack.id));
    }
    // ffuf saw 2 invocations, 2 within-window claims → correlation = 1.0
    assert.equal(t1.get("ffuf").invocation_count, 2);
    assert.equal(t1.get("ffuf").claim_correlation, 1);
  });
});

test("determinism (T-R8): brief rendering is deterministic in adaptive mode", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("determ-render");
    seedInstallPresence(domain, ["ffuf", "arjun", "gowitness"]);
    writePackTelemetryConfig(domain, { adaptive_curation: true });

    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      { ts: isoAt(base), command: "ffuf -u https://example.com/FUZZ -w wl" },
      { ts: isoAt(base + 1000), tool: "bob_record_candidate_claim" },
    ]);

    const args = {
      surface_fingerprint: { kind: "web", host: "example.com", target_domain: domain },
      task_lens: "behavior_probe",
      observations: { observed_endpoints: ["/api/users"], items: [] },
      target_domain: domain,
    };
    const md1 = renderAvailableCliToolsSectionSync(args);
    const md2 = renderAvailableCliToolsSectionSync(args);
    const md3 = renderAvailableCliToolsSectionSync(args);
    assert.equal(md1, md2, "render must be deterministic call-over-call");
    assert.equal(md2, md3);
    assert.match(md1, /\*\*ffuf\*\*/);
  });
});

// ── Correlation window enforcement ─────────────────────────────────────────

test("correlation window: a claim outside the 5-minute window does not count", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("corr-window");
    writePackTelemetryConfig(domain, { adaptive_curation: true });

    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      { ts: isoAt(base), command: "ffuf -u https://example.com/FUZZ -w wl" },
      // Claim 6 minutes later — outside DEFAULT_CORRELATION_WINDOW_MS (5min).
      { ts: isoAt(base + 6 * 60_000), tool: "bob_record_candidate_claim" },
    ]);
    const now = base + 7 * 60_000;
    const telemetry = loadPackTelemetry(domain, { now: () => now });
    const ffuf = telemetry.get("ffuf");
    assert.equal(ffuf.invocation_count, 1);
    assert.equal(ffuf.claim_correlation, 0, "claim outside the correlation window must not count");
  });
});

test("correlation window: a claim BEFORE the invocation does not count", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("corr-before");
    writePackTelemetryConfig(domain, { adaptive_curation: true });
    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      { ts: isoAt(base), tool: "bob_record_candidate_claim" },
      // Invocation AFTER the claim.
      { ts: isoAt(base + 60_000), command: "ffuf -u https://example.com/FUZZ -w wl" },
    ]);
    const now = base + 2 * 60_000;
    const telemetry = loadPackTelemetry(domain, { now: () => now });
    const ffuf = telemetry.get("ffuf");
    assert.equal(ffuf.invocation_count, 1);
    assert.equal(ffuf.claim_correlation, 0, "earlier claim must not retroactively credit a later invocation");
  });
});

// ── Rolling window enforcement ─────────────────────────────────────────────

test("rolling window: entries older than window_ms are ignored", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("rolling");
    writePackTelemetryConfig(domain, {
      adaptive_curation: true,
      window_ms: 60_000, // 1-minute window for the test
    });
    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      // Old entries (outside the 60s window).
      { ts: isoAt(base - 5 * 60_000), command: "ffuf -u https://example.com/FUZZ -w wl" },
      { ts: isoAt(base - 5 * 60_000 + 1000), tool: "bob_record_candidate_claim" },
      // Fresh entries inside the window.
      { ts: isoAt(base - 30_000), command: "ffuf -u https://example.com/FUZZ -w wl2" },
      { ts: isoAt(base - 25_000), tool: "bob_record_candidate_claim" },
    ]);
    const now = base;
    const telemetry = loadPackTelemetry(domain, { now: () => now });
    const ffuf = telemetry.get("ffuf");
    assert.equal(ffuf.invocation_count, 1, "stale entries must be dropped");
    assert.equal(ffuf.claim_correlation, 1);
  });
});

// ── Predicate-still-required ───────────────────────────────────────────────

test("a pack with telemetry promotion that isn't applicable_when still does not surface", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("predicate-still");
    writePackTelemetryConfig(domain, { adaptive_curation: true });
    seedInstallPresence(domain, CLI_TOOL_PACKS.map((p) => p.id));
    const base = Date.parse("2026-05-20T00:00:00.000Z");
    writeTelemetryLines([
      { ts: isoAt(base), command: "swaks --to a@b --from c@d --server example.com" },
      { ts: isoAt(base + 1000), tool: "bob_record_candidate_claim" },
    ]);
    // Web surface without a dmarc_policy_observed observation → swaks
    // predicate is false even with telemetry. Adaptive curation must not
    // bypass the predicate.
    const md = renderAvailableCliToolsSectionSync({
      surface_fingerprint: { kind: "web", host: "example.com", target_domain: domain },
      task_lens: "behavior_probe",
      observations: { observed_endpoints: ["/api/users"], items: [] },
      target_domain: domain,
    });
    assert.ok(!md.includes("**swaks**"), "non-applicable pack must not surface even with telemetry");
  });
});

// ── Validation ─────────────────────────────────────────────────────────────

test("writePackTelemetryConfig rejects missing adaptive_curation", () => {
  withTempEnv(() => {
    const domain = uniqueDomain("validate");
    assert.throws(() => writePackTelemetryConfig(domain, {}), /adaptive_curation/);
    assert.throws(() => writePackTelemetryConfig(domain, { adaptive_curation: "true" }), /adaptive_curation/);
    assert.throws(() => writePackTelemetryConfig(domain, { adaptive_curation: true, window_ms: -1 }), /window_ms/);
    assert.throws(() => writePackTelemetryConfig(domain, { adaptive_curation: true, baseline_rate: "bad" }), /baseline_rate/);
  });
});

test("default correlation window constant matches the spec (5 minutes)", () => {
  assert.equal(DEFAULT_CORRELATION_WINDOW_MS, 5 * 60 * 1000);
});

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  SESSION_LOCK_STALE_MS,
  applyWaveMerge,
  attackSurfacePath,
  autoSignup,
  authStore,
  buildHeaderProfile,
  executeTool,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  initSession,
  migrateAuthJson,
  readScopeExclusions,
  readSessionState,
  listFindings,
  mergeWaveHandoffs,
  readFindings,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  startWave,
  statePath,
  tempEmail,
  transitionPhase,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeFileAtomic,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  readHunterBrief,
} = require("../mcp/server.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  process.env.HOME = tempHome;

  try {
    fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
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
    return;
  }

  const waveNumber = Number(String(wave).slice(1));
  const assignmentsPath = path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
  if (fs.existsSync(assignmentsPath)) {
    return;
  }

  seedAssignments(domain, waveNumber, [
    { agent, surface_id: "surface-a" },
  ]);
}

function seedFinding(domain, overrides = {}) {
  const wave = Object.prototype.hasOwnProperty.call(overrides, "wave") ? overrides.wave : "w1";
  const agent = Object.prototype.hasOwnProperty.call(overrides, "agent") ? overrides.agent : "a1";
  ensureFindingAssignment(domain, wave, agent);

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
    ...overrides,
  }));
}

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
    const expectedState = {
      target: domain,
      target_url: "https://example.com",
      phase: "HUNT",
      hunt_wave: 1,
      pending_wave: 2,
      total_findings: 0,
      explored: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      scope_exclusions: [],
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

    assert.deepEqual(result, {
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
  });
});

test("bounty_start_wave rejects invalid state, duplicate inputs, and pre-existing assignment files", () => {
  withTempHome(() => {
    const domain = "example.com";

    seedSessionState(domain, { phase: "AUTH" });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires phase HUNT/,
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
      state: JSON.parse(readSessionState({ target_domain: domain })).state,
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
      dead_ends: ["/new-dead-end"],
      waf_blocked_endpoints: ["/new-waf"],
      lead_surface_ids: ["surface-a", "surface-c", "surface-d", "surface-x"],
      requeue_surface_ids: ["surface-b"],
    });
    assert.deepEqual(result.findings, {
      total: 2,
      by_severity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
    });
    assert.deepEqual(result.state.scope_exclusions, ["oos.example.net", "api.other.example"]);
    assert.deepEqual(result.state.explored, ["surface-a"]);
    assert.deepEqual(result.state.dead_ends, ["/existing", "/new-dead-end"]);
    assert.deepEqual(result.state.waf_blocked_endpoints, ["/old-waf", "/new-waf"]);
    assert.deepEqual(result.state.lead_surface_ids, ["surface-c", "surface-d"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.hunt_wave, 1);
    assert.equal(result.state.total_findings, 2);
    assert.deepEqual(readScopeExclusions(domain), ["oos.example.net", "api.other.example"]);
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
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.state.scope_exclusions, ["legacy.example"]);
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
      /Wave merge requires phase HUNT/,
    );

    seedSessionState(domain, { phase: "HUNT", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
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
        agent: "a2",
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
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
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
      content: "# A1",
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
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
    });
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
    assert.deepEqual(readResult, {
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
    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      has_high_or_critical: false,
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

test("bounty_auth_manual writes auth.json to the correct session dir when target_domain is provided", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "alpha.com"), { recursive: true });
    fs.mkdirSync(path.join(sessionsDir, "zebra.com"), { recursive: true });

    const result = JSON.parse(await executeTool("bounty_auth_manual", {
      profile_name: "test",
      target_domain: "alpha.com",
      headers: { "Authorization": "Bearer tok123" },
    }));

    assert.equal(result.success, true);
    assert.ok(fs.existsSync(path.join(sessionsDir, "alpha.com", "auth.json")));
    assert.ok(!fs.existsSync(path.join(sessionsDir, "zebra.com", "auth.json")));

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "alpha.com", "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer tok123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_manual falls back to last session dir when target_domain is absent", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "alpha.com"), { recursive: true });
    fs.mkdirSync(path.join(sessionsDir, "zebra.com"), { recursive: true });

    const result = JSON.parse(await executeTool("bounty_auth_manual", {
      profile_name: "test",
      headers: { "Authorization": "Bearer fallback" },
    }));

    assert.equal(result.success, true);
    // Falls back to last alphabetical dir (zebra.com)
    assert.ok(fs.existsSync(path.join(sessionsDir, "zebra.com", "auth.json")));
    assert.ok(!fs.existsSync(path.join(sessionsDir, "alpha.com", "auth.json")));
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bounty_auth_manual falls back when target_domain session dir does not exist", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "zebra.com"), { recursive: true });

    const result = JSON.parse(await executeTool("bounty_auth_manual", {
      profile_name: "test",
      target_domain: "nonexistent.com",
      headers: { "Authorization": "Bearer fb" },
    }));

    assert.equal(result.success, true);
    assert.ok(fs.existsSync(path.join(sessionsDir, "zebra.com", "auth.json")));
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
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
      role: "attacker",
      headers: { "Authorization": "Bearer atok" },
      cookies: { "session": "abc123" },
    }));

    assert.equal(result.success, true);
    assert.equal(result.role, "attacker");
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
      role: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    // Now add victim
    const result = JSON.parse(await executeTool("bounty_auth_store", {
      target_domain: "target.com",
      role: "victim",
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
      role: "victim",
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
      role: "attacker",
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

test("bounty_auth_manual backward compat writes v2 as attacker", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "bounty-agent-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });

    const result = JSON.parse(await executeTool("bounty_auth_manual", {
      profile_name: "default",
      target_domain: "target.com",
      headers: { "Authorization": "Bearer compat" },
    }));

    assert.equal(result.success, true);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer compat");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
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
    assert.deepEqual(brief.scope_exclusions, ["third-party.com"]);
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

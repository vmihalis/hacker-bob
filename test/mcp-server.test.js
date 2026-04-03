const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  mergeWaveHandoffs,
  sessionDir,
  waveHandoffStatus,
  writeFileAtomic,
  writeHandoff,
  writeWaveHandoff,
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
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-1-assignments.json"), `${JSON.stringify({
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

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

test("bounty_wave_handoff_status reports partial completion and unexpected handoffs without parsing payloads", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-2-assignments.json"), `${JSON.stringify({
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
        { agent: "a3", surface_id: "surface-c" },
      ],
    }, null, 2)}\n`);

    writeFileAtomic(path.join(dir, "handoff-w2-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a9",
      surface_id: "surface-z",
      surface_status: "complete",
      content: "# unexpected",
    });

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
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-2-assignments.json"), `${JSON.stringify({
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

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

    writeFileAtomic(path.join(dir, "wave-3-assignments.json"), `${JSON.stringify({
      wave_number: 3,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

    writeFileAtomic(path.join(dir, "handoff-w3-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w3",
      agent: "a9",
      surface_id: "surface-z",
      surface_status: "complete",
      content: "# unexpected",
      dead_ends: ["/ignored"],
    });

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

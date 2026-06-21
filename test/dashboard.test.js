const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {
  buildDashboardSnapshot,
  dashboardUsageText,
  parseDashboardArgs,
  startDashboardServer,
} = require("../mcp/lib/dashboard.js");
const {
  repoInventoryPath,
  pipelineEventsJsonlPath,
  frontierEventsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  normalizePipelineEvent,
} = require("../mcp/lib/pipeline-events.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-dashboard-test-"));
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

function requestText(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, body });
      });
    });
    req.on("error", reject);
  });
}

function seedRepoSession(domain, repoPath) {
  JSON.parse(initSession({
    target_domain: domain,
    target_url: `repo://${domain}`,
    target_kind: "repo",
    repo: {
      root_path: repoPath,
      branch: "main",
      commit: "abc1234",
    },
  }));
  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    repo_path: repoPath,
    generated_at: "2026-01-01T00:00:00.000Z",
    counts: {
      files: 12,
      surfaces: 2,
      native_source_files: 3,
    },
    tech_stack: ["C/C++", "Autotools"],
    reachability: {
      max_credible_severity_ceiling: "CRITICAL",
      network_reachable_surface_ids: ["OSS-NATIVE-CODE"],
    },
  }, null, 2)}\n`);
}

function appendPipelineEvent(domain, type, fields) {
  fs.appendFileSync(
    pipelineEventsJsonlPath(domain),
    `${JSON.stringify(normalizePipelineEvent(domain, type, fields))}\n`,
    "utf8",
  );
}

function appendFrontierRaw(domain, record) {
  fs.appendFileSync(frontierEventsJsonlPath(domain), `${JSON.stringify(record)}\n`, "utf8");
}

function parseSse(raw) {
  const events = [];
  for (const block of raw.split("\n\n")) {
    if (!block.trim()) continue;
    const ev = {};
    for (const line of block.split("\n")) {
      if (line.startsWith("id:")) ev.id = line.slice(3).trim();
      else if (line.startsWith("event:")) ev.event = line.slice(6).trim();
      else if (line.startsWith("data:")) ev.data = line.slice(5).trim();
      else if (line.startsWith(":")) ev.comment = `${ev.comment || ""}${line.slice(1).trim()}`;
    }
    if (ev.id || ev.event || ev.data) events.push(ev);
  }
  return events;
}

// SSE responses never "end"; read for a short settle window, then tear down.
function collectSse(url, { headers = {}, settleMs = 300 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };
    const req = http.get(url, { headers }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { buf += chunk; });
      res.on("error", () => {});
      setTimeout(() => {
        req.destroy();
        finish({ statusCode: res.statusCode, raw: buf, events: parseSse(buf) });
      }, settleMs);
    });
    req.on("error", () => finish({ statusCode: 0, raw: "", events: [] }));
  });
}

test("dashboard arg parser handles local server and JSON flags", () => {
  const parsed = parseDashboardArgs([
    "--repo-only",
    "--json",
    "--host",
    "127.0.0.1",
    "--port=0",
    "--window-days",
    "14",
    "--limit",
    "25",
  ]);
  assert.equal(parsed.repo_only, true);
  assert.equal(parsed.json, true);
  assert.equal(parsed.host, "127.0.0.1");
  assert.equal(parsed.port, 0);
  assert.equal(parsed.window_days, 14);
  assert.equal(parsed.limit, 25);
  assert.match(dashboardUsageText(), /hacker-bob dashboard/);
  assert.throws(() => parseDashboardArgs(["--port", "70000"]), /port must be between/);
});

test("dashboard snapshot filters repo sessions and keeps compact repo metadata", () => {
  withTempHome((home) => {
    const repoPath = path.join(home, "repo");
    fs.mkdirSync(repoPath, { recursive: true });
    seedRepoSession("repo-dashboard.example", repoPath);
    JSON.parse(initSession({
      target_domain: "web-dashboard.example",
      target_url: "https://web-dashboard.example",
    }));

    const snapshot = buildDashboardSnapshot({ repo_only: true, window_days: 30, limit: 10 });
    assert.equal(snapshot.version, 1);
    assert.equal(snapshot.filters.repo_only, true);
    assert.equal(snapshot.totals.sessions, 1);
    assert.equal(snapshot.totals.repo_sessions, 1);
    assert.equal(snapshot.sessions[0].target_domain, "repo-dashboard.example");
    assert.equal(snapshot.sessions[0].repo.is_repo, true);
    assert.equal(snapshot.sessions[0].repo.root_path, repoPath);
    assert.equal(snapshot.sessions[0].repo.inventory.counts.files, 12);
    assert.deepEqual(snapshot.sessions[0].repo.inventory.tech_stack, ["C/C++", "Autotools"]);
  });
});

test("dashboard snapshot totals use all matched sessions before display limit", () => {
  withTempHome((home) => {
    const firstRepoPath = path.join(home, "repo-one");
    const secondRepoPath = path.join(home, "repo-two");
    fs.mkdirSync(firstRepoPath, { recursive: true });
    fs.mkdirSync(secondRepoPath, { recursive: true });
    seedRepoSession("repo-dashboard-one.example", firstRepoPath);
    seedRepoSession("repo-dashboard-two.example", secondRepoPath);
    JSON.parse(initSession({
      target_domain: "web-dashboard.example",
      target_url: "https://web-dashboard.example",
    }));

    const snapshot = buildDashboardSnapshot({ repo_only: true, window_days: 30, limit: 1 });
    assert.equal(snapshot.sessions.length, 1);
    assert.equal(snapshot.analytics_bounds.sessions_matched, 2);
    assert.equal(snapshot.analytics_bounds.sessions_displayed, 1);
    assert.equal(snapshot.totals.sessions, 2);
    assert.equal(snapshot.totals.repo_sessions, 2);
  });
});

test("dashboard snapshot exposes lead promotion avoided-run telemetry", () => {
  withTempHome(() => {
    const domain = "lead-promotion-dashboard.example";
    JSON.parse(initSession({
      target_domain: domain,
      target_url: `https://${domain}`,
    }));
    appendPipelineEvent(domain, "evaluator_run_avoided", {
      source: "bob_promote_surface_leads",
      counts: {
        promoted: 2,
        filtered: 3,
        evaluator_runs_avoided: 3,
        deferred_by_limit: 1,
      },
    });

    const snapshot = buildDashboardSnapshot({ window_days: 30, limit: 10 });
    const session = snapshot.sessions.find((item) => item.target_domain === domain);
    assert.ok(session);
    assert.deepEqual(session.lead_promotion, {
      promotions: 2,
      leads_filtered: 3,
      evaluator_runs_avoided: 3,
      deferred_by_limit: 1,
    });
    assert.equal(snapshot.totals.evaluator_runs_avoided, 3);
  });
});

test("pipeline analytics reports zero lead promotion telemetry when no events exist", () => {
  withTempHome(() => {
    const domain = "lead-promotion-zero.example";
    JSON.parse(initSession({
      target_domain: domain,
      target_url: `https://${domain}`,
    }));

    const snapshot = buildDashboardSnapshot({ window_days: 30, limit: 10 });
    const session = snapshot.sessions.find((item) => item.target_domain === domain);
    assert.ok(session);
    assert.deepEqual(session.lead_promotion, {
      promotions: 0,
      leads_filtered: 0,
      evaluator_runs_avoided: 0,
      deferred_by_limit: 0,
    });
  });
});

test("dashboard server serves HTML and API JSON", async () => {
  await withTempHome(async () => {
    const started = await startDashboardServer({ host: "127.0.0.1", port: 0, repo_only: true });
    try {
      const html = await requestText(started.url);
      assert.equal(html.statusCode, 200);
      assert.match(html.body, /Hacker Bob Dashboard/);
      assert.match(html.body, /if \(avoided > 0\)/);

      const api = await requestText(`${started.url}api/snapshot?repo_only=true&limit=5`);
      assert.equal(api.statusCode, 200);
      const parsed = JSON.parse(api.body);
      assert.equal(parsed.version, 1);
      assert.equal(parsed.filters.repo_only, true);
      assert.equal(parsed.filters.limit, 5);
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

test("dashboard server warns when binding outside loopback", async () => {
  await withTempHome(async () => {
    let warning = "";
    const started = await startDashboardServer({
      host: "0.0.0.0",
      port: 0,
      repo_only: true,
    }, {
      stderr: {
        write(chunk) {
          warning += chunk;
        },
      },
    });
    try {
      assert.match(warning, /unauthenticated/);
      assert.match(warning, /0\.0\.0\.0/);
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

test("dashboard SSE route streams folded frontier + pipeline frames", async () => {
  await withTempHome(async () => {
    const domain = "sse-stream.example";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    appendFrontierRaw(domain, {
      event_id: "FE-1",
      ts: "2026-06-21T10:00:00.000Z",
      kind: "surface.observed",
      target_domain: domain,
      payload: { surface_type: "web_route" },
    });
    appendPipelineEvent(domain, "finding_recorded", { ts: "2026-06-21T10:00:01.000Z", surface_id: "S-1" });

    const started = await startDashboardServer({ host: "127.0.0.1", port: 0 });
    try {
      const sse = await collectSse(`${started.url}api/session/${domain}/events`);
      assert.equal(sse.statusCode, 200);
      const sources = sse.events.map((e) => e.event);
      assert.ok(sources.includes("frontier"), "streams a frontier frame");
      assert.ok(sources.includes("pipeline"), "streams a pipeline frame (the verification/wave/finding merge)");
      const frontier = sse.events.find((e) => e.event === "frontier");
      assert.equal(JSON.parse(frontier.data).event_id, "FE-1");
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

test("dashboard SSE route resumes after Last-Event-ID without replaying the cursor", async () => {
  await withTempHome(async () => {
    const domain = "sse-resume.example";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    appendFrontierRaw(domain, { event_id: "FE-1", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, payload: {} });
    appendFrontierRaw(domain, { event_id: "FE-2", ts: "2026-06-21T10:00:01.000Z", kind: "surface.observed", target_domain: domain, payload: {} });

    const started = await startDashboardServer({ host: "127.0.0.1", port: 0 });
    try {
      const first = await collectSse(`${started.url}api/session/${domain}/events`);
      const ids = first.events.filter((e) => e.id).map((e) => e.id);
      // initSession seeds its own frontier/pipeline events, so assert resume
      // relative to the actual ordered frame list rather than a fixed count.
      assert.ok(ids.length >= 2, "more than one frame to resume across");
      const cursor = ids[0];
      const resumed = await collectSse(`${started.url}api/session/${domain}/events`, {
        headers: { "last-event-id": cursor },
      });
      const resumedIds = resumed.events.filter((e) => e.id).map((e) => e.id);
      assert.ok(!resumedIds.includes(cursor), "does not replay the cursor frame");
      assert.deepEqual(resumedIds, ids.slice(1));
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

test("dashboard SSE route refuses off-loopback with 403 loopback_only", async () => {
  await withTempHome(async () => {
    const started = await startDashboardServer({ host: "0.0.0.0", port: 0 }, { stderr: { write() {} } });
    try {
      const port = started.server.address().port;
      const res = await requestText(`http://127.0.0.1:${port}/api/session/x.example/events`);
      assert.equal(res.statusCode, 403);
      assert.match(res.body, /loopback_only/);
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

test("dashboard SSE route survives a partial trailing ledger line", async () => {
  await withTempHome(async () => {
    const domain = "sse-tolerant.example";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    appendFrontierRaw(domain, { event_id: "FE-ok", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, payload: {} });
    fs.appendFileSync(frontierEventsJsonlPath(domain), '{"event_id":"FE-partial","ts":"2026', "utf8");

    const started = await startDashboardServer({ host: "127.0.0.1", port: 0 });
    try {
      const sse = await collectSse(`${started.url}api/session/${domain}/events`);
      assert.equal(sse.statusCode, 200);
      const ids = sse.events.filter((e) => e.id).map((e) => e.id);
      assert.ok(ids.some((id) => id.includes("FE-ok")), "valid frame still streamed past the partial line");
    } finally {
      await new Promise((resolve, reject) => {
        started.server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});

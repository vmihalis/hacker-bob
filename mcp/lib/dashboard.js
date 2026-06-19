"use strict";

const fs = require("fs");
const http = require("http");
const { URL } = require("url");
const {
  readPipelineAnalytics,
} = require("./pipeline-analytics.js");
const {
  repoInventoryPath,
  sessionsRoot,
  statePath,
} = require("./paths.js");

const DASHBOARD_VERSION = 1;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 4873;
const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 365;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const JSON_READ_MAX_BYTES = 2 * 1024 * 1024;

function dashboardUsageText() {
  return `Usage:
  hacker-bob dashboard [--host 127.0.0.1] [--port 4873] [--repo-only] [--window-days 30] [--limit 50] [--json]

Starts a local read-only dashboard over ~/hacker-bob-sessions.
Use --json to print the same dashboard snapshot without starting a server.`;
}

function readFlagValue(args, index, flag) {
  const value = args[index + 1];
  if (!value || value.startsWith("-")) {
    throw new Error(`${flag} requires a value`);
  }
  return { value, nextIndex: index + 1 };
}

function parseInteger(value, field, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const text = String(value);
  if (!/^\d+$/.test(text)) {
    throw new Error(`${field} must be an integer`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${field} must be between ${min} and ${max}`);
  }
  return parsed;
}

function parseHost(value) {
  const host = String(value || "").trim();
  if (!host) throw new Error("--host requires a value");
  if (/[\s/]/.test(host)) throw new Error("--host must be a hostname or IP address");
  return host;
}

function isLoopbackHost(host) {
  const normalized = String(host || "").toLowerCase();
  if (normalized === "localhost" || normalized === "::1" || normalized === "[::1]") {
    return true;
  }
  const ipv4Match = normalized.match(/^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!ipv4Match && ipv4Match.slice(1).every((part) => {
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function normalizeDashboardOptions(options = {}) {
  return {
    host: parseHost(options.host || DEFAULT_HOST),
    port: options.port == null
      ? DEFAULT_PORT
      : parseInteger(options.port, "port", { min: 0, max: 65535 }),
    repo_only: options.repo_only === true,
    window_days: options.window_days == null
      ? DEFAULT_WINDOW_DAYS
      : parseInteger(options.window_days, "window_days", { min: 1, max: MAX_WINDOW_DAYS }),
    limit: options.limit == null
      ? DEFAULT_LIMIT
      : parseInteger(options.limit, "limit", { min: 1, max: MAX_LIMIT }),
    json: options.json === true,
    help: options.help === true,
  };
}

function parseDashboardArgs(args = []) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "-h" || arg === "--help") {
      options.help = true;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--repo-only") {
      options.repo_only = true;
    } else if (arg === "--host") {
      const parsed = readFlagValue(args, index, "--host");
      options.host = parsed.value;
      index = parsed.nextIndex;
    } else if (arg.startsWith("--host=")) {
      options.host = arg.slice("--host=".length);
    } else if (arg === "--port") {
      const parsed = readFlagValue(args, index, "--port");
      options.port = parsed.value;
      index = parsed.nextIndex;
    } else if (arg.startsWith("--port=")) {
      options.port = arg.slice("--port=".length);
    } else if (arg === "--window-days") {
      const parsed = readFlagValue(args, index, "--window-days");
      options.window_days = parsed.value;
      index = parsed.nextIndex;
    } else if (arg.startsWith("--window-days=")) {
      options.window_days = arg.slice("--window-days=".length);
    } else if (arg === "--limit") {
      const parsed = readFlagValue(args, index, "--limit");
      options.limit = parsed.value;
      index = parsed.nextIndex;
    } else if (arg.startsWith("--limit=")) {
      options.limit = arg.slice("--limit=".length);
    } else {
      throw new Error(`Unknown dashboard option: ${arg}`);
    }
  }
  return normalizeDashboardOptions(options);
}

function readJsonFileSafe(filePath) {
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) {
      return { exists: true, document: null, error: "not a regular file" };
    }
    if (stats.size > JSON_READ_MAX_BYTES) {
      return { exists: true, document: null, error: `exceeds ${JSON_READ_MAX_BYTES} byte read cap` };
    }
    return {
      exists: true,
      document: JSON.parse(fs.readFileSync(filePath, "utf8")),
      error: null,
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return { exists: false, document: null, error: null };
    }
    return {
      exists: true,
      document: null,
      error: error && error.message ? error.message : String(error),
    };
  }
}

function capArray(value, limit = 8) {
  return Array.isArray(value) ? value.slice(0, limit) : [];
}

function readRepoDashboardInfo(targetDomain) {
  const stateRead = readJsonFileSafe(statePath(targetDomain));
  const state = stateRead.document && typeof stateRead.document === "object" && !Array.isArray(stateRead.document)
    ? stateRead.document
    : {};
  const inventoryRead = readJsonFileSafe(repoInventoryPath(targetDomain));
  const inventory = inventoryRead.document && typeof inventoryRead.document === "object" && !Array.isArray(inventoryRead.document)
    ? inventoryRead.document
    : {};
  const repo = state.repo && typeof state.repo === "object" && !Array.isArray(state.repo) ? state.repo : null;
  const isRepo = state.target_kind === "repo" || state.target_url === `repo://${targetDomain}` || inventoryRead.exists;
  return {
    is_repo: isRepo,
    target_kind: state.target_kind || (isRepo ? "repo" : "web"),
    root_path: repo && typeof repo.root_path === "string" ? repo.root_path : inventory.repo_path || null,
    source_url: repo && typeof repo.source_url === "string" ? repo.source_url : null,
    branch: repo && typeof repo.branch === "string" ? repo.branch : null,
    commit: repo && typeof repo.commit === "string" ? repo.commit : null,
    inventory: {
      exists: inventoryRead.exists,
      error: inventoryRead.error,
      generated_at: typeof inventory.generated_at === "string" ? inventory.generated_at : null,
      counts: inventory.counts && typeof inventory.counts === "object" && !Array.isArray(inventory.counts)
        ? inventory.counts
        : {},
      tech_stack: capArray(inventory.tech_stack),
      reachability: inventory.reachability && typeof inventory.reachability === "object" && !Array.isArray(inventory.reachability)
        ? {
            max_credible_severity_ceiling: inventory.reachability.max_credible_severity_ceiling || null,
            network_reachable_surface_ids: capArray(inventory.reachability.network_reachable_surface_ids),
          }
        : null,
    },
  };
}

function compactDashboardSession(row) {
  const repo = readRepoDashboardInfo(row.target_domain);
  return {
    target_domain: row.target_domain,
    phase: row.phase || null,
    health: row.health || { status: "unknown", reasons: [] },
    latest_activity_ts: row.latest_activity_ts || null,
    auth_status: row.auth_status || null,
    waves: row.waves || {},
    findings: row.findings || { total: 0, by_severity: {} },
    lead_promotion: row.lead_promotion || {
      promotions: 0,
      leads_filtered: 0,
      evaluator_runs_avoided: 0,
      deferred_by_limit: 0,
    },
    chain_attempts_count: row.chain_attempts_count || 0,
    technique_attempts: row.technique_attempts || { total: 0 },
    final_verification_count: row.final_verification_count || 0,
    final_reportable_count: row.final_reportable_count || 0,
    evidence: row.evidence || { exists: false, valid: false },
    grade_verdict: row.grade_verdict || null,
    report_present: row.report_present === true,
    egress: row.egress || {},
    geofence_warnings: row.geofence_warnings || null,
    repo,
  };
}

function increment(bucket, key) {
  const normalized = key || "unknown";
  bucket[normalized] = (bucket[normalized] || 0) + 1;
}

function buildDashboardTotals(sessions) {
  const totals = {
    sessions: sessions.length,
    repo_sessions: 0,
    by_phase: {},
    by_health: {},
    findings: 0,
    final_reportable: 0,
    reports_present: 0,
    grades_present: 0,
    pending_handoffs_missing: 0,
    pending_handoffs_invalid: 0,
    evaluator_runs_avoided: 0,
  };
  for (const session of sessions) {
    if (session.repo.is_repo) totals.repo_sessions += 1;
    increment(totals.by_phase, session.phase);
    increment(totals.by_health, session.health.status);
    totals.findings += session.findings.total || 0;
    totals.final_reportable += session.final_reportable_count || 0;
    if (session.report_present) totals.reports_present += 1;
    if (session.grade_verdict) totals.grades_present += 1;
    totals.pending_handoffs_missing += session.waves.pending_handoffs_missing || 0;
    totals.pending_handoffs_invalid += session.waves.pending_handoffs_invalid || 0;
    totals.evaluator_runs_avoided += session.lead_promotion.evaluator_runs_avoided || 0;
  }
  return totals;
}

function buildDashboardBottlenecks(sessions) {
  const grouped = new Map();
  for (const session of sessions) {
    const reasons = Array.isArray(session.health.reasons) ? session.health.reasons : [];
    for (const reason of reasons) {
      if (!grouped.has(reason)) {
        grouped.set(reason, {
          code: reason,
          affected_count: 0,
          affected_targets: [],
        });
      }
      const group = grouped.get(reason);
      group.affected_count += 1;
      group.affected_targets.push(session.target_domain);
    }
  }
  return Array.from(grouped.values())
    .sort((a, b) => b.affected_count - a.affected_count || a.code.localeCompare(b.code));
}

function actionForDashboardBottleneck(bottleneck) {
  const actionByCode = {
    unreadable_artifacts: "Repair malformed session artifacts before resuming orchestration.",
    hunter_handoff_failures: "Resume or reconcile the pending wave after hunter handoffs are complete.",
    repeated_hunter_stops: "Inspect repeated SubagentStop blockers before launching more hunters.",
    low_coverage: "Launch another wave for unexplored non-low surfaces before verification.",
    chain_phase_no_attempts: "Run chain-builder until every required chain path has a terminal attempt.",
    missing_verification: "Write a valid final verification round before grading.",
    missing_evidence: "Run the evidence agent before grading or reporting.",
    missing_grade: "Write a valid grade verdict before report completion.",
    missing_report: "Write the canonical report.md or move the session out of REPORT.",
    stale_pending_wave: "Re-enter the resume flow and reconcile the stale pending wave.",
    delayed_wave_reconciliation: "Audit resume flow latency after hunter completion.",
  };
  return {
    code: bottleneck.code,
    action: actionByCode[bottleneck.code] || "Inspect this bottleneck before continuing.",
    affected_count: bottleneck.affected_count,
    affected_targets: bottleneck.affected_targets,
  };
}

function buildDashboardNextActions(bottlenecks, limit) {
  return bottlenecks.slice(0, limit).map(actionForDashboardBottleneck);
}

function buildDashboardSnapshot(options = {}, context = {}) {
  const normalized = normalizeDashboardOptions(options);
  const analytics = JSON.parse(readPipelineAnalytics({
    window_days: normalized.window_days,
    limit: normalized.limit,
    include_events: false,
  }, {
    env: context.env || process.env,
  }));
  const matchedSessions = analytics.sessions
    .map(compactDashboardSession)
    .filter((session) => !normalized.repo_only || session.repo.is_repo);
  const sessions = matchedSessions.slice(0, normalized.limit);
  const bottlenecks = buildDashboardBottlenecks(matchedSessions).slice(0, normalized.limit);
  return {
    version: DASHBOARD_VERSION,
    generated_at: new Date().toISOString(),
    sessions_root: sessionsRoot(),
    filters: {
      repo_only: normalized.repo_only,
      window_days: normalized.window_days,
      limit: normalized.limit,
    },
    totals: buildDashboardTotals(matchedSessions),
    bottlenecks,
    next_actions: buildDashboardNextActions(bottlenecks, normalized.limit),
    sessions,
    analytics_bounds: {
      ...(analytics.analytics_bounds || {}),
      sessions_matched: matchedSessions.length,
      sessions_displayed: sessions.length,
    },
  };
}

function booleanFromQuery(value) {
  if (value == null) return false;
  return value === "" || value === "1" || value === "true" || value === "yes";
}

function optionsFromUrl(url, baseOptions) {
  return normalizeDashboardOptions({
    ...baseOptions,
    repo_only: url.searchParams.has("repo_only")
      ? booleanFromQuery(url.searchParams.get("repo_only"))
      : baseOptions.repo_only,
    window_days: url.searchParams.get("window_days") || baseOptions.window_days,
    limit: url.searchParams.get("limit") || baseOptions.limit,
  });
}

function sendJson(res, statusCode, body, headOnly = false) {
  const text = `${JSON.stringify(body, null, 2)}\n`;
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(text),
  });
  if (!headOnly) res.end(text);
  else res.end();
}

function sendHtml(res, body, headOnly = false) {
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(body),
  });
  if (!headOnly) res.end(body);
  else res.end();
}

function renderDashboardHtml(options) {
  const initialOptions = {
    repo_only: options.repo_only,
    window_days: options.window_days,
    limit: options.limit,
  };
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hacker Bob Dashboard</title>
  <style>
    :root { color-scheme: light; --ink: #15191f; --muted: #5e6875; --line: #d9dee5; --soft: #f5f7fa; --ok: #0f7b4f; --warn: #9a5a00; --bad: #b42318; --accent: #2457d6; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #ffffff; }
    header { border-bottom: 1px solid var(--line); padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
    h1 { font-size: 20px; line-height: 1.2; margin: 0; letter-spacing: 0; }
    main { padding: 20px 24px 28px; }
    .toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    label { color: var(--muted); font-size: 13px; display: inline-flex; align-items: center; gap: 6px; }
    input[type="number"] { width: 72px; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; font: inherit; }
    button { border: 1px solid var(--accent); background: var(--accent); color: #fff; border-radius: 6px; padding: 7px 10px; font: inherit; cursor: pointer; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 18px; }
    .stat { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; min-height: 72px; }
    .stat .label { color: var(--muted); font-size: 12px; }
    .stat .value { font-size: 26px; font-weight: 700; margin-top: 4px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 18px; align-items: start; }
    table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 10px; vertical-align: top; font-size: 13px; }
    th { background: var(--soft); color: var(--muted); font-weight: 600; }
    tr:last-child td { border-bottom: 0; }
    .badge { display: inline-flex; align-items: center; min-height: 22px; border-radius: 999px; padding: 2px 8px; font-size: 12px; border: 1px solid var(--line); background: #fff; }
    .healthy { color: var(--ok); border-color: rgba(15, 123, 79, .35); background: rgba(15, 123, 79, .08); }
    .needs_attention { color: var(--warn); border-color: rgba(154, 90, 0, .35); background: rgba(154, 90, 0, .08); }
    .blocked { color: var(--bad); border-color: rgba(180, 35, 24, .35); background: rgba(180, 35, 24, .08); }
    .muted { color: var(--muted); }
    aside { border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
    aside h2 { font-size: 15px; margin: 0 0 10px; letter-spacing: 0; }
    .list { display: grid; gap: 10px; }
    .item { border-top: 1px solid var(--line); padding-top: 10px; }
    .item:first-child { border-top: 0; padding-top: 0; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    @media (max-width: 860px) { header, main { padding-left: 14px; padding-right: 14px; } .layout { grid-template-columns: 1fr; } table { display: block; overflow-x: auto; } }
  </style>
</head>
<body>
  <header>
    <h1>Hacker Bob Dashboard</h1>
    <div class="toolbar">
      <label><input id="repoOnly" type="checkbox"> Repo only</label>
      <label>Days <input id="windowDays" type="number" min="1" max="${MAX_WINDOW_DAYS}"></label>
      <label>Limit <input id="limit" type="number" min="1" max="${MAX_LIMIT}"></label>
      <button id="refresh" type="button">Refresh</button>
    </div>
  </header>
  <main>
    <section id="stats" class="stats"></section>
    <section class="layout">
      <div>
        <table>
          <thead>
            <tr><th>Session</th><th>Phase</th><th>Health</th><th>Findings</th><th>Verification</th><th>Activity</th></tr>
          </thead>
          <tbody id="sessions"></tbody>
        </table>
      </div>
      <aside>
        <h2>Bottlenecks</h2>
        <div id="bottlenecks" class="list"></div>
      </aside>
    </section>
  </main>
  <script>
    const initialOptions = ${JSON.stringify(initialOptions)};
    const repoOnly = document.getElementById("repoOnly");
    const windowDays = document.getElementById("windowDays");
    const limit = document.getElementById("limit");
    const stats = document.getElementById("stats");
    const sessions = document.getElementById("sessions");
    const bottlenecks = document.getElementById("bottlenecks");
    repoOnly.checked = initialOptions.repo_only;
    windowDays.value = initialOptions.window_days;
    limit.value = initialOptions.limit;

    function text(value) { return value == null || value === "" ? "-" : String(value); }
    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
    function cell(row, value) { const td = document.createElement("td"); td.textContent = text(value); row.appendChild(td); return td; }
    function badge(value) { const span = document.createElement("span"); span.className = "badge " + text(value); span.textContent = text(value); return span; }
    function stat(label, value) {
      const node = document.createElement("div");
      node.className = "stat";
      const labelNode = document.createElement("div");
      labelNode.className = "label";
      labelNode.textContent = label;
      const valueNode = document.createElement("div");
      valueNode.className = "value";
      valueNode.textContent = text(value);
      node.append(labelNode, valueNode);
      return node;
    }
    function formatActivity(ts) {
      if (!ts) return "-";
      const date = new Date(ts);
      return Number.isNaN(date.getTime()) ? ts : date.toLocaleString();
    }
    async function load() {
      const params = new URLSearchParams({
        repo_only: repoOnly.checked ? "true" : "false",
        window_days: windowDays.value,
        limit: limit.value,
      });
      const response = await fetch("/api/snapshot?" + params.toString(), { cache: "no-store" });
      if (!response.ok) throw new Error("snapshot failed: " + response.status);
      render(await response.json());
    }
    function render(snapshot) {
      clear(stats);
      stats.append(
        stat("Sessions", snapshot.totals.sessions),
        stat("Findings", snapshot.totals.findings),
        stat("Reportable", snapshot.totals.final_reportable),
        stat("Missing Handoffs", snapshot.totals.pending_handoffs_missing),
        stat("Evaluator Runs Avoided", snapshot.totals.evaluator_runs_avoided)
      );
      clear(sessions);
      for (const session of snapshot.sessions) {
        const row = document.createElement("tr");
        const name = cell(row, session.target_domain);
        if (session.repo && session.repo.root_path) {
          const path = document.createElement("div");
          path.className = "muted";
          path.textContent = session.repo.root_path;
          name.appendChild(path);
        }
        cell(row, session.phase);
        const healthCell = document.createElement("td");
        healthCell.appendChild(badge(session.health && session.health.status));
        row.appendChild(healthCell);
        cell(row, session.findings ? session.findings.total : 0);
        cell(row, String(session.final_verification_count || 0) + " / " + String(session.final_reportable_count || 0));
        const activity = cell(row, formatActivity(session.latest_activity_ts));
        const avoided = session.lead_promotion ? session.lead_promotion.evaluator_runs_avoided || 0 : 0;
        if (avoided > 0) {
          const avoidedNode = document.createElement("div");
          avoidedNode.className = "muted";
          avoidedNode.textContent = String(avoided) + " evaluator runs avoided this session";
          activity.appendChild(avoidedNode);
        }
        sessions.appendChild(row);
      }
      if (!snapshot.sessions.length) {
        const row = document.createElement("tr");
        const empty = cell(row, "No sessions match the current filters.");
        empty.colSpan = 6;
        sessions.appendChild(row);
      }
      clear(bottlenecks);
      for (const item of snapshot.bottlenecks) {
        const node = document.createElement("div");
        node.className = "item";
        const title = document.createElement("div");
        title.appendChild(badge(item.code));
        const detail = document.createElement("div");
        detail.className = "muted";
        detail.textContent = String(item.affected_count) + " session(s): " + item.affected_targets.join(", ");
        node.append(title, detail);
        bottlenecks.appendChild(node);
      }
      if (!snapshot.bottlenecks.length) {
        const empty = document.createElement("div");
        empty.className = "muted";
        empty.textContent = "No active bottlenecks.";
        bottlenecks.appendChild(empty);
      }
    }
    document.getElementById("refresh").addEventListener("click", () => load().catch((error) => alert(error.message)));
    load().catch((error) => { sessions.innerHTML = "<tr><td colspan=\\"6\\"></td></tr>"; sessions.querySelector("td").textContent = error.message; });
  </script>
</body>
</html>`;
}

function routeDashboardRequest(req, res, baseOptions, context = {}) {
  const headOnly = req.method === "HEAD";
  if (req.method !== "GET" && req.method !== "HEAD") {
    sendJson(res, 405, { error: "method_not_allowed" }, headOnly);
    return;
  }
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (url.pathname === "/" || url.pathname === "/index.html") {
    sendHtml(res, renderDashboardHtml(baseOptions), headOnly);
    return;
  }
  if (url.pathname === "/api/snapshot") {
    try {
      const options = optionsFromUrl(url, baseOptions);
      sendJson(res, 200, buildDashboardSnapshot(options, context), headOnly);
    } catch (error) {
      sendJson(res, 400, { error: error && error.message ? error.message : String(error) }, headOnly);
    }
    return;
  }
  sendJson(res, 404, { error: "not_found" }, headOnly);
}

function hostForUrl(host) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function startDashboardServer(options = {}, context = {}) {
  const normalized = normalizeDashboardOptions(options);
  if (!isLoopbackHost(normalized.host)) {
    const warning = `warning: dashboard is unauthenticated and bound to ${normalized.host}; session analytics may be reachable from the network\n`;
    if (context.stderr && typeof context.stderr.write === "function") {
      context.stderr.write(warning);
    } else {
      process.stderr.write(warning);
    }
  }
  const server = http.createServer((req, res) => routeDashboardRequest(req, res, normalized, context));
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(normalized.port, normalized.host, () => {
      server.off("error", reject);
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : normalized.port;
      resolve({
        server,
        options: normalized,
        url: `http://${hostForUrl(normalized.host)}:${port}/`,
      });
    });
    if (context.unref === true) server.unref();
  });
}

module.exports = {
  DASHBOARD_VERSION,
  DEFAULT_HOST,
  DEFAULT_PORT,
  DEFAULT_WINDOW_DAYS,
  DEFAULT_LIMIT,
  buildDashboardSnapshot,
  dashboardUsageText,
  normalizeDashboardOptions,
  parseDashboardArgs,
  startDashboardServer,
};

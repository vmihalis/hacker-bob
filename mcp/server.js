#!/usr/bin/env node
// Bounty Agent MCP Server — stdio transport, zero dependencies
// Provides: bounty_http_scan, bounty_record_finding, bounty_list_findings,
//           bounty_write_handoff, bounty_write_wave_handoff,
//           bounty_wave_handoff_status, bounty_merge_wave_handoffs,
//           bounty_read_handoff, bounty_auth_manual, bounty_wave_status

const fs = require("fs");
const path = require("path");
const os = require("os");

// ── In-memory state ──
const authProfiles = new Map();
const findingCounters = new Map(); // domain → counter

// ── Tool definitions ──
const TOOLS = [
  {
    name: "bounty_http_scan",
    description:
      "Make an HTTP request and auto-analyze for security issues. Returns status, headers, body, plus detected tech stack, leaked secrets, misconfigs, and endpoints.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] },
        url: { type: "string" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: { type: "string" },
        follow_redirects: { type: "boolean" },
        timeout_ms: { type: "number" },
        auth_profile: { type: "string" },
      },
      required: ["method", "url"],
    },
  },
  {
    name: "bounty_record_finding",
    description: "Record a validated security finding to disk. Survives context rotation.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        title: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        cwe: { type: "string" },
        endpoint: { type: "string" },
        description: { type: "string" },
        proof_of_concept: { type: "string" },
        response_evidence: { type: "string" },
        impact: { type: "string" },
        validated: { type: "boolean" },
        wave: { type: "string" },
        agent: { type: "string" },
      },
      required: ["target_domain", "title", "severity", "endpoint", "description", "proof_of_concept", "validated"],
    },
  },
  {
    name: "bounty_list_findings",
    description: "List all recorded findings for a target.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_write_handoff",
    description: "Write session handoff for context rotation.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        session_number: { type: "number" },
        target_url: { type: "string" },
        program_url: { type: "string" },
        findings_summary: { type: "array", items: { type: "object", properties: { id: { type: "string" }, severity: { type: "string" }, title: { type: "string" } } } },
        attack_surface_map: { type: "array", items: { type: "string" } },
        explored_with_results: { type: "array", items: { type: "string" } },
        dead_ends: { type: "array", items: { type: "string" } },
        blockers: { type: "array", items: { type: "string" } },
        unexplored: { type: "array", items: { type: "string" } },
        must_do_next: { type: "array", items: { type: "object", properties: { priority: { type: "string" }, description: { type: "string" } } } },
        promising_leads: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "session_number", "target_url", "explored_with_results", "must_do_next"],
    },
  },
  {
    name: "bounty_write_wave_handoff",
    description: "Write one structured wave handoff as both markdown and JSON.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
        surface_id: { type: "string" },
        surface_status: { type: "string", enum: ["complete", "partial"] },
        content: { type: "string" },
        dead_ends: { type: "array", items: { type: "string" } },
        waf_blocked_endpoints: { type: "array", items: { type: "string" } },
        lead_surface_ids: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "wave", "agent", "surface_id", "surface_status", "content"],
    },
  },
  {
    name: "bounty_wave_handoff_status",
    description: "Read-only readiness check for one wave. Compares expected assignments to present handoff JSON files without validating payload contents.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
      },
      required: ["target_domain", "wave_number"],
    },
  },
  {
    name: "bounty_merge_wave_handoffs",
    description: "Merge structured wave handoffs for one wave using the persisted assignment file.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
      },
      required: ["target_domain", "wave_number"],
    },
  },
  {
    name: "bounty_read_handoff",
    description: "Read previous session handoff to resume hunting.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_auth_manual",
    description: "Store auth tokens as a profile for use with bounty_http_scan.",
    inputSchema: {
      type: "object",
      properties: {
        profile_name: { type: "string" },
        cookies: { type: "object", additionalProperties: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        local_storage: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["profile_name"],
    },
  },
  {
    name: "bounty_wave_status",
    description: "Read-only hunt status summary for wave decisions. Returns finding counts, severity breakdown, and per-finding metadata.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
];

// ── Session path helper ──
function sessionDir(domain) {
  return path.join(os.homedir(), "bounty-agent-sessions", domain);
}

const WAVE_ID_RE = /^w([1-9]\d*)$/;
const AGENT_ID_RE = /^a([1-9]\d*)$/;

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function parseWaveId(value, fieldName = "wave") {
  const wave = assertNonEmptyString(value, fieldName);
  if (!WAVE_ID_RE.test(wave)) {
    throw new Error(`${fieldName} must match wN`);
  }
  return wave;
}

function parseAgentId(value, fieldName = "agent") {
  const agent = assertNonEmptyString(value, fieldName);
  if (!AGENT_ID_RE.test(agent)) {
    throw new Error(`${fieldName} must match aN`);
  }
  return agent;
}

function parseWaveNumber(value, fieldName = "wave_number") {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

function parseSurfaceStatus(value) {
  if (value !== "complete" && value !== "partial") {
    throw new Error(`surface_status must be "complete" or "partial"`);
  }
  return value;
}

function normalizeStringArray(value, fieldName) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array of strings`);
  }

  const normalized = [];
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string") {
      throw new Error(`${fieldName} must contain only strings`);
    }
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    normalized.push(trimmed);
  }
  return normalized;
}

function pushUnique(target, seen, values) {
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    target.push(value);
  }
}

function compareAgentLabels(a, b) {
  const aMatch = typeof a === "string" && a.match(AGENT_ID_RE);
  const bMatch = typeof b === "string" && b.match(AGENT_ID_RE);

  if (aMatch && bMatch) {
    return Number(aMatch[1]) - Number(bMatch[1]);
  }
  if (aMatch) return -1;
  if (bMatch) return 1;
  return String(a).localeCompare(String(b));
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeFileAtomic(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
  fs.writeFileSync(tempPath, content);
  fs.renameSync(tempPath, filePath);
}

function loadWaveAssignments(domain, waveNumber) {
  const dir = sessionDir(domain);
  const assignmentsPath = path.join(dir, `wave-${waveNumber}-assignments.json`);

  if (!fs.existsSync(assignmentsPath)) {
    throw new Error(`Missing assignment file: ${assignmentsPath}`);
  }

  const assignmentsDoc = readJsonFile(assignmentsPath);
  if (assignmentsDoc == null || typeof assignmentsDoc !== "object" || Array.isArray(assignmentsDoc)) {
    throw new Error(`Invalid assignment file: ${assignmentsPath}`);
  }
  if (assignmentsDoc.wave_number !== waveNumber) {
    throw new Error(`Assignment file wave_number mismatch in ${assignmentsPath}`);
  }
  if (!Array.isArray(assignmentsDoc.assignments)) {
    throw new Error(`Assignment file assignments must be an array in ${assignmentsPath}`);
  }

  const assignments = [];
  const assignmentByAgent = new Map();
  for (const assignment of assignmentsDoc.assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error(`Invalid assignment entry in ${assignmentsPath}`);
    }
    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");
    if (assignmentByAgent.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent} in ${assignmentsPath}`);
    }
    const normalizedAssignment = { agent, surface_id: surfaceId };
    assignments.push(normalizedAssignment);
    assignmentByAgent.set(agent, normalizedAssignment);
  }

  return { dir, wave: `w${waveNumber}`, assignments, assignmentByAgent };
}

function listWaveHandoffFiles(dir, wave) {
  const handoffPrefix = `handoff-${wave}-`;
  return fs.existsSync(dir)
    ? fs.readdirSync(dir)
        .filter((name) => name.startsWith(handoffPrefix) && name.endsWith(".json"))
        .sort()
    : [];
}

function buildWaveHandoffFileIndex(dir, wave, assignmentByAgent) {
  const handoffFiles = listWaveHandoffFiles(dir, wave);
  const handoffPathByAgent = new Map();
  const unexpectedAgentSet = new Set();

  for (const fileName of handoffFiles) {
    const rawAgent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!assignmentByAgent.has(rawAgent)) {
      unexpectedAgentSet.add(rawAgent);
      continue;
    }
    handoffPathByAgent.set(rawAgent, path.join(dir, fileName));
  }

  return {
    handoffFiles,
    handoffPathByAgent,
    unexpectedAgents: Array.from(unexpectedAgentSet).sort(compareAgentLabels),
  };
}

// ── Tool implementations ──

async function httpScan(args) {
  const method = args.method;
  const url = args.url;
  const headers = args.headers || {};
  const body = args.body || undefined;
  const followRedirects = args.follow_redirects ?? false;
  const timeoutMs = args.timeout_ms || 10000;
  const authProfile = args.auth_profile;

  if (authProfile && authProfiles.has(authProfile)) {
    const auth = authProfiles.get(authProfile);
    for (const [k, v] of Object.entries(auth)) {
      if (!headers[k]) headers[k] = v;
    }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const resp = await fetch(url, {
      method,
      headers,
      body,
      redirect: followRedirects ? "follow" : "manual",
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const respHeaders = {};
    resp.headers.forEach((v, k) => { respHeaders[k] = v; });

    const ct = resp.headers.get("content-type") || "";
    let respBody;
    if (ct.includes("text") || ct.includes("json") || ct.includes("xml") || ct.includes("javascript") || ct.includes("html")) {
      const text = await resp.text();
      respBody = text.slice(0, 12000);
      if (text.length > 12000) respBody += `\n[TRUNCATED — ${text.length} chars]`;
    } else {
      const buf = await resp.arrayBuffer();
      respBody = `[Binary: ${buf.byteLength} bytes, type: ${ct}]`;
    }

    const analysis = analyzeResponse(url, resp.status, respHeaders, respBody);

    return JSON.stringify({
      status: resp.status,
      status_text: resp.statusText,
      headers: respHeaders,
      body: respBody,
      redirected: resp.redirected,
      final_url: resp.url,
      analysis,
    }, null, 2);
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

function analyzeResponse(url, status, headers, body) {
  const tech = [];
  const issues = [];
  const secrets = [];
  const endpoints = [];
  const authInfo = [];

  // Tech fingerprinting
  if (headers["x-powered-by"]) tech.push(`X-Powered-By: ${headers["x-powered-by"]}`);
  if (headers["server"]) tech.push(`Server: ${headers["server"]}`);
  if (body.includes("__NEXT_DATA__")) tech.push("Next.js");
  if (body.includes("__nuxt")) tech.push("Nuxt.js");
  if (body.includes("ng-version")) tech.push("Angular");
  if (body.includes("__vue__")) tech.push("Vue.js");
  if (body.includes("firebase")) tech.push("Firebase");
  if (body.includes("graphql")) tech.push("GraphQL");
  if (body.includes("wp-content")) tech.push("WordPress");
  if (body.includes("laravel") || body.includes("XSRF-TOKEN")) tech.push("Laravel");
  if (body.includes("django") || body.includes("csrfmiddlewaretoken")) tech.push("Django");
  if (headers["cf-ray"]) tech.push("Cloudflare");
  if (headers["x-vercel-id"]) tech.push("Vercel");
  if (headers["x-amzn-requestid"]) tech.push("AWS");

  // Security headers
  if (!headers["strict-transport-security"]) issues.push("Missing HSTS");
  if (!headers["x-content-type-options"]) issues.push("Missing X-Content-Type-Options");
  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors"))
    issues.push("No clickjacking protection");
  if (headers["access-control-allow-origin"] === "*") issues.push("CORS: wildcard origin (*)");
  if (headers["access-control-allow-credentials"] === "true")
    issues.push(`CORS: credentials + origin ${headers["access-control-allow-origin"] || "?"} — test reflection`);

  // Cookie analysis
  const sc = headers["set-cookie"] || "";
  if (sc) {
    if (!sc.includes("HttpOnly")) authInfo.push("Cookie missing HttpOnly");
    if (!sc.includes("Secure")) authInfo.push("Cookie missing Secure flag");
    if (!sc.includes("SameSite")) authInfo.push("Cookie missing SameSite");
  }

  // Secret detection
  const patterns = [
    { re: /AKIA[A-Z0-9]{16}/, label: "AWS Access Key" },
    { re: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub PAT" },
    { re: /gho_[a-zA-Z0-9]{36}/, label: "GitHub OAuth" },
    { re: /sk-[a-zA-Z0-9]{32,}/, label: "Secret key (sk-)" },
    { re: /sk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Live" },
    { re: /pk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Publishable" },
    { re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/, label: "JWT" },
    { re: /xox[bpas]-[a-zA-Z0-9-]+/, label: "Slack token" },
    { re: /AIza[a-zA-Z0-9_-]{35}/, label: "Google API key" },
    { re: /GOCSPX-[a-zA-Z0-9_-]+/, label: "Google OAuth secret" },
    { re: /-----BEGIN (?:RSA )?PRIVATE KEY-----/, label: "Private key" },
    { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})/i, label: "API key" },
    { re: /(?:secret|password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})/i, label: "Secret/password" },
    { re: /mongodb(\+srv)?:\/\/[^\s"']+/, label: "MongoDB URI" },
    { re: /postgres(ql)?:\/\/[^\s"']+/, label: "PostgreSQL URI" },
    { re: /redis:\/\/[^\s"']+/, label: "Redis URI" },
    { re: /smtp:\/\/[^\s"']+/, label: "SMTP URI" },
  ];
  for (const { re, label } of patterns) {
    const m = body.match(re);
    if (m) secrets.push(`${label}: ${m[0].slice(0, 50)}...`);
  }

  // Endpoint extraction
  const urls = body.match(/(?:https?:\/\/[^\s"'<>{}]+|\/api\/[^\s"'<>{}]+|\/v[0-9]+\/[^\s"'<>{}]+)/g) || [];
  endpoints.push(...[...new Set(urls)].slice(0, 30));

  // Status hints
  if (status === 403) issues.push("403 — try different auth/methods");
  if (status === 405) issues.push("405 — try other HTTP methods");
  if (status === 500) issues.push("500 — possible injection vector");

  return { tech_stack: tech, security_issues: issues, leaked_secrets: secrets, discovered_endpoints: endpoints, auth_info: authInfo };
}

function recordFinding(args) {
  const domain = args.target_domain;
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const findingsPath = path.join(dir, "findings.md");

  // Lazy-load counter from disk per domain (survives server restart)
  if (!findingCounters.has(domain)) {
    let count = 0;
    try {
      const existing = fs.readFileSync(findingsPath, "utf8");
      count = (existing.match(/^## FINDING/gm) || []).length;
    } catch {}
    findingCounters.set(domain, count);
  }

  // Monotonic increment — no TOCTOU race (Node.js single-threaded)
  const counter = findingCounters.get(domain) + 1;
  findingCounters.set(domain, counter);
  const id = `F-${counter}`;

  const waveAgent = args.wave || args.agent
    ? `\n- **Wave/Agent:** ${args.wave || "?"}/${args.agent || "?"}`
    : "";

  const entry = [
    `## FINDING ${counter} (${args.severity.toUpperCase()}): ${args.title}`,
    `- **ID:** ${id}`,
    `- **CWE:** ${args.cwe || "N/A"}`,
    `- **Endpoint:** ${args.endpoint}`,
    `- **Validated:** ${args.validated ? "YES" : "NO"}`,
    `- **Description:** ${args.description}`,
    `- **PoC:**`,
    "```",
    args.proof_of_concept,
    "```",
    `- **Evidence:** ${args.response_evidence || "See PoC"}`,
    `- **Impact:** ${args.impact || "N/A"}`,
    waveAgent,
    "---\n\n",
  ].join("\n");

  fs.appendFileSync(findingsPath, entry);
  return JSON.stringify({ recorded: true, finding_id: id, total: counter });
}

function listFindings(args) {
  const dir = sessionDir(args.target_domain);
  const findingsPath = path.join(dir, "findings.md");
  try {
    const content = fs.readFileSync(findingsPath, "utf8");
    const findings = [];
    const blocks = content.split(/^## FINDING /gm).slice(1);
    for (const block of blocks) {
      const titleMatch = block.match(/^\d+\s*\((\w+)\):\s*(.+)/);
      const endpointMatch = block.match(/\*\*Endpoint:\*\*\s*(.+)/);
      const idMatch = block.match(/\*\*ID:\*\*\s*(F-\d+)/);
      findings.push({
        id: idMatch ? idMatch[1] : null,
        severity: titleMatch ? titleMatch[1].toLowerCase() : null,
        title: titleMatch ? titleMatch[2].trim() : null,
        endpoint: endpointMatch ? endpointMatch[1].trim() : null,
      });
    }
    return JSON.stringify({ count: findings.length, findings });
  } catch {
    return JSON.stringify({ count: 0, findings: [] });
  }
}

function waveStatus(args) {
  const dir = sessionDir(args.target_domain);
  const findingsPath = path.join(dir, "findings.md");
  try {
    const content = fs.readFileSync(findingsPath, "utf8");
    const findings = [];
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const blocks = content.split(/^## FINDING /gm).slice(1);
    for (const block of blocks) {
      const titleMatch = block.match(/^\d+\s*\((\w+)\):\s*(.+)/);
      const endpointMatch = block.match(/\*\*Endpoint:\*\*\s*(.+)/);
      const idMatch = block.match(/\*\*ID:\*\*\s*(F-\d+)/);
      const waveMatch = block.match(/\*\*Wave\/Agent:\*\*\s*(.+)/);
      const sev = titleMatch ? titleMatch[1].toLowerCase() : "info";
      if (bySeverity[sev] !== undefined) bySeverity[sev]++;
      findings.push({
        id: idMatch ? idMatch[1] : null,
        severity: sev,
        title: titleMatch ? titleMatch[2].trim() : null,
        endpoint: endpointMatch ? endpointMatch[1].trim() : null,
        wave_agent: waveMatch ? waveMatch[1].trim() : null,
      });
    }
    return JSON.stringify({
      total: findings.length,
      by_severity: bySeverity,
      has_high_or_critical: bySeverity.critical + bySeverity.high > 0,
      findings_summary: findings,
    });
  } catch {
    return JSON.stringify({ total: 0, by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, has_high_or_critical: false, findings_summary: [] });
  }
}

function writeHandoff(args) {
  const domain = args.target_domain;
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lines = [];
  lines.push(`# Handoff — Session ${args.session_number}`);
  lines.push(`## Target: ${args.target_url}`);
  if (args.program_url) lines.push(`## Program: ${args.program_url}`);
  const findings = args.findings_summary || [];
  lines.push(`\n## Findings (${findings.length})`);
  for (const f of findings) lines.push(`- ${f.id} [${(f.severity || "").toUpperCase()}]: ${f.title}`);
  lines.push("\n## Explored");
  for (const e of args.explored_with_results || []) lines.push(`- ${e}`);
  lines.push("\n## Dead Ends");
  for (const d of args.dead_ends || []) lines.push(`- ${d}`);
  lines.push("\n## Unexplored");
  for (const u of args.unexplored || []) lines.push(`- ${u}`);
  lines.push("\n## Must Do Next");
  for (const m of args.must_do_next || []) lines.push(`- [${m.priority}] ${m.description}`);
  lines.push("\n## Promising Leads");
  for (const p of args.promising_leads || []) lines.push(`- ${p}`);

  const handoffPath = path.join(dir, `SESSION_HANDOFF.md`);
  fs.writeFileSync(handoffPath, lines.join("\n") + "\n");
  return JSON.stringify({ written: handoffPath });
}

function writeWaveHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(args.surface_status);

  if (typeof args.content !== "string") {
    throw new Error("content must be a string");
  }

  const handoff = {
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    surface_status: surfaceStatus,
    dead_ends: normalizeStringArray(args.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(args.lead_surface_ids, "lead_surface_ids"),
  };

  const dir = sessionDir(domain);
  const markdownPath = path.join(dir, `handoff-${wave}-${agent}.md`);
  const jsonPath = path.join(dir, `handoff-${wave}-${agent}.json`);

  writeFileAtomic(markdownPath, args.content);
  writeFileAtomic(jsonPath, JSON.stringify(handoff, null, 2) + "\n");

  return JSON.stringify({
    written_md: markdownPath,
    written_json: jsonPath,
  });
}

function validateWaveHandoffPayload(payload, { targetDomain, wave, agent, surfaceId }) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("handoff payload must be an object");
  }

  if (payload.target_domain != null && assertNonEmptyString(payload.target_domain, "target_domain") !== targetDomain) {
    throw new Error("handoff target_domain does not match merge target");
  }

  const payloadWave = parseWaveId(payload.wave);
  const payloadAgent = parseAgentId(payload.agent);
  const payloadSurfaceId = assertNonEmptyString(payload.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(payload.surface_status);

  if (payloadWave !== wave) throw new Error("handoff wave does not match assignment wave");
  if (payloadAgent !== agent) throw new Error("handoff agent does not match assignment");
  if (payloadSurfaceId !== surfaceId) throw new Error("handoff surface_id does not match assignment");

  return {
    dead_ends: normalizeStringArray(payload.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(payload.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(payload.lead_surface_ids, "lead_surface_ids"),
    surface_status: surfaceStatus,
  };
}

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { dir, wave, assignments, assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const { handoffFiles, handoffPathByAgent, unexpectedAgents } = buildWaveHandoffFileIndex(dir, wave, assignmentByAgent);

  const receivedAgents = [];
  const missingAgents = [];

  for (const assignment of assignments) {
    if (handoffPathByAgent.has(assignment.agent)) {
      receivedAgents.push(assignment.agent);
    } else {
      missingAgents.push(assignment.agent);
    }
  }

  return JSON.stringify({
    assignments_total: assignments.length,
    handoffs_total: handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    unexpected_agents: unexpectedAgents,
    is_complete: missingAgents.length === 0,
  });
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { dir, wave, assignments, assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const { handoffFiles, handoffPathByAgent, unexpectedAgents } = buildWaveHandoffFileIndex(dir, wave, assignmentByAgent);

  const receivedAgents = [];
  const invalidAgents = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  for (const assignment of assignments) {
    const filePath = handoffPathByAgent.get(assignment.agent);
    if (!filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const payload = validateWaveHandoffPayload(readJsonFile(filePath), {
        targetDomain: domain,
        wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      });

      receivedAgents.push(assignment.agent);
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
    } catch {
      invalidAgents.push(assignment.agent);
    }
  }

  return JSON.stringify({
    assignments_total: assignments.length,
    handoffs_total: handoffFiles.length,
    received_agents: receivedAgents,
    invalid_agents: invalidAgents,
    unexpected_agents: unexpectedAgents,
    completed_surface_ids: completedSurfaceIds,
    partial_surface_ids: partialSurfaceIds,
    missing_surface_ids: missingSurfaceIds,
    dead_ends: deadEnds,
    waf_blocked_endpoints: wafBlockedEndpoints,
    lead_surface_ids: leadSurfaceIds,
  });
}

function readHandoff(args) {
  const dir = sessionDir(args.target_domain);
  const handoffPath = path.join(dir, "SESSION_HANDOFF.md");
  try {
    const content = fs.readFileSync(handoffPath, "utf8");
    return JSON.stringify({ handoff: content });
  } catch {
    return JSON.stringify({ handoff: null, message: "No handoff found" });
  }
}

function authManual(args) {
  const name = args.profile_name;
  const profile = {};
  const headers = args.headers || {};
  const cookies = args.cookies || {};
  const storage = args.local_storage || {};

  Object.assign(profile, headers);
  if (Object.keys(cookies).length) {
    profile["Cookie"] = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  }
  for (const [k, v] of Object.entries(storage)) {
    if (typeof v === "string" && v.startsWith("eyJ") && !profile["Authorization"]) {
      profile["Authorization"] = `Bearer ${v}`;
    }
  }

  authProfiles.set(name, profile);

  // Also save to session dir if we can find one
  const sessionsDir = path.join(os.homedir(), "bounty-agent-sessions");
  try {
    const dirs = fs.readdirSync(sessionsDir).sort();
    if (dirs.length > 0) {
      const authPath = path.join(sessionsDir, dirs[dirs.length - 1], "auth.json");
      fs.writeFileSync(authPath, JSON.stringify(profile, null, 2));
    }
  } catch {}

  return JSON.stringify({ success: true, profile_name: name, keys: Object.keys(profile) });
}

// ── Tool dispatch ──
async function executeTool(name, args) {
  switch (name) {
    case "bounty_http_scan": return httpScan(args);
    case "bounty_record_finding": return recordFinding(args);
    case "bounty_list_findings": return listFindings(args);
    case "bounty_write_handoff": return writeHandoff(args);
    case "bounty_write_wave_handoff": return writeWaveHandoff(args);
    case "bounty_wave_handoff_status": return waveHandoffStatus(args);
    case "bounty_merge_wave_handoffs": return mergeWaveHandoffs(args);
    case "bounty_read_handoff": return readHandoff(args);
    case "bounty_auth_manual": return authManual(args);
    case "bounty_wave_status": return waveStatus(args);
    default: return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// ── MCP stdio transport ──
let transportMode = "framed";
let buffer = "";

function send(msg) {
  const json = JSON.stringify(msg);
  if (transportMode === "raw") {
    process.stdout.write(`${json}\n`);
    return;
  }
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
}

async function handleMessage(rpc) {
  switch (rpc.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: {
          protocolVersion: rpc.params?.protocolVersion || "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: "bountyagent", version: "1.0.0" },
        },
      });
      break;

    case "ping":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: {},
      });
      break;

    case "notifications/initialized":
      // No response needed for notifications
      break;

    case "tools/list":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: { tools: TOOLS },
      });
      break;

    case "tools/call": {
      const { name, arguments: args } = rpc.params;
      try {
        const result = await executeTool(name, args || {});
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            content: [{ type: "text", text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }],
          },
        });
      } catch (e) {
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            content: [{ type: "text", text: JSON.stringify({ error: e.message || String(e) }) }],
          },
        });
      }
      break;
    }

    default:
      if (rpc.id) {
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          error: { code: -32601, message: `Method not found: ${rpc.method}` },
        });
      }
      break;
  }
}

function startServer() {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    while (true) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        const trimmed = buffer.trim();
        if (!trimmed) break;

        // Claude Code health checks may send a single raw JSON-RPC message
        // without Content-Length framing. Accept that shape too.
        try {
          const msg = JSON.parse(trimmed);
          transportMode = "raw";
          buffer = "";
          handleMessage(msg);
          continue;
        } catch {
          if (buffer.includes("\n")) {
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            let parsedAny = false;
            for (const line of lines.map((l) => l.trim()).filter(Boolean)) {
              try {
                transportMode = "raw";
                handleMessage(JSON.parse(line));
                parsedAny = true;
              } catch {
                buffer = `${line}\n${buffer}`;
              }
            }
            if (parsedAny) continue;
          }
        }
        break;
      }

      const headerPart = buffer.slice(0, headerEnd);
      const match = headerPart.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        // Try parsing as raw JSON (some clients skip Content-Length)
        try {
          const lines = buffer.split("\n").filter((l) => l.trim());
          for (const line of lines) {
            const msg = JSON.parse(line);
            handleMessage(msg);
          }
          buffer = "";
          return;
        } catch {
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
      }

      const contentLength = parseInt(match[1], 10);
      transportMode = "framed";
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) break;

      const body = buffer.slice(bodyStart, bodyStart + contentLength);
      buffer = buffer.slice(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body);
        handleMessage(msg);
      } catch {
        send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      }
    }
  });

  process.stderr.write("bountyagent MCP server running (stdio)\n");
}

module.exports = {
  TOOLS,
  sessionDir,
  writeHandoff,
  writeWaveHandoff,
  waveHandoffStatus,
  mergeWaveHandoffs,
  normalizeStringArray,
  writeFileAtomic,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}

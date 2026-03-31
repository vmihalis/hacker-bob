#!/usr/bin/env node
// Bounty Agent MCP Server — stdio transport, zero dependencies
// Provides: bounty_http_scan, bounty_record_finding, bounty_list_findings,
//           bounty_write_handoff, bounty_read_handoff, bounty_auth_manual

const fs = require("fs");
const path = require("path");
const os = require("os");

// ── In-memory state ──
const authProfiles = new Map();

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
];

// ── Session path helper ──
function sessionDir(domain) {
  return path.join(os.homedir(), "bounty-agent-sessions", domain);
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
  let existing = "";
  try { existing = fs.readFileSync(findingsPath, "utf8"); } catch {}

  const count = (existing.match(/^## FINDING/gm) || []).length + 1;
  const id = `F-${count}`;
  const entry = `## FINDING ${count} (${args.severity.toUpperCase()}): ${args.title}\n- **ID:** ${id}\n- **CWE:** ${args.cwe || "N/A"}\n- **Endpoint:** ${args.endpoint}\n- **Validated:** ${args.validated ? "YES" : "NO"}\n- **Description:** ${args.description}\n- **PoC:** \`${args.proof_of_concept.slice(0, 300)}\`\n- **Evidence:** ${args.response_evidence || "See PoC"}\n- **Impact:** ${args.impact || "N/A"}\n---\n\n`;

  fs.appendFileSync(findingsPath, entry);
  return JSON.stringify({ recorded: true, finding_id: id });
}

function listFindings(args) {
  const dir = sessionDir(args.target_domain);
  const findingsPath = path.join(dir, "findings.md");
  try {
    const content = fs.readFileSync(findingsPath, "utf8");
    const count = (content.match(/^## FINDING/gm) || []).length;
    return JSON.stringify({ count, findings: content });
  } catch {
    return JSON.stringify({ count: 0, findings: "" });
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
    case "bounty_read_handoff": return readHandoff(args);
    case "bounty_auth_manual": return authManual(args);
    default: return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// ── MCP stdio transport ──
function send(msg) {
  const json = JSON.stringify(msg);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
}

let buffer = "";

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  while (true) {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) break;

    const headerPart = buffer.slice(0, headerEnd);
    const match = headerPart.match(/Content-Length:\s*(\d+)/i);
    if (!match) {
      // Try parsing as raw JSON (some clients skip Content-Length)
      try {
        const lines = buffer.split("\n").filter(l => l.trim());
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
    const bodyStart = headerEnd + 4;
    if (buffer.length < bodyStart + contentLength) break;

    const body = buffer.slice(bodyStart, bodyStart + contentLength);
    buffer = buffer.slice(bodyStart + contentLength);

    try {
      const msg = JSON.parse(body);
      handleMessage(msg);
    } catch (e) {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    }
  }
});

async function handleMessage(rpc) {
  switch (rpc.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "bountyagent", version: "1.0.0" },
        },
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

process.stderr.write("bountyagent MCP server running (stdio)\n");

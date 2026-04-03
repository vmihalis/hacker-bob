#!/usr/bin/env node
// Bounty Agent MCP Server — stdio transport, zero dependencies
// Provides: bounty_http_scan, bounty_record_finding, bounty_read_findings,
//           bounty_list_findings, bounty_write_verification_round,
//           bounty_read_verification_round, bounty_write_grade_verdict,
//           bounty_read_grade_verdict, bounty_write_handoff,
//           bounty_write_wave_handoff, bounty_wave_handoff_status,
//           bounty_merge_wave_handoffs, bounty_read_handoff,
//           bounty_log_dead_ends, bounty_auth_manual,
//           bounty_wave_status

const fs = require("fs");
const path = require("path");
const os = require("os");

// ── In-memory state ──
const authProfiles = new Map();
const findingCounters = new Map(); // findings.jsonl path → counter

const FINDING_ID_RE = /^F-([1-9]\d*)$/;
const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];
const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const GRADE_VERDICT_VALUES = ["SUBMIT", "HOLD", "SKIP"];
const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "brutalist-final.json", markdown: "brutalist-final.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

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
    description: "Record a validated security finding to structured disk artifacts. Survives context rotation.",
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
    name: "bounty_read_findings",
    description: "Read all recorded findings for a target from authoritative structured storage.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
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
    name: "bounty_write_verification_round",
    description: "Write one verifier round to authoritative JSON plus a markdown mirror.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        round: { type: "string", enum: VERIFICATION_ROUND_VALUES },
        notes: { type: ["string", "null"] },
        results: {
          type: "array",
          items: {
            type: "object",
            properties: {
              finding_id: { type: "string" },
              disposition: { type: "string", enum: VERIFICATION_DISPOSITION_VALUES },
              severity: { enum: [...SEVERITY_VALUES, null] },
              reportable: { type: "boolean" },
              reasoning: { type: "string" },
            },
            required: ["finding_id", "disposition", "severity", "reportable", "reasoning"],
          },
        },
      },
      required: ["target_domain", "round", "notes", "results"],
    },
  },
  {
    name: "bounty_read_verification_round",
    description: "Read one verification round JSON document.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        round: { type: "string", enum: VERIFICATION_ROUND_VALUES },
      },
      required: ["target_domain", "round"],
    },
  },
  {
    name: "bounty_write_grade_verdict",
    description: "Write the authoritative grading verdict JSON plus a markdown mirror.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        verdict: { type: "string", enum: GRADE_VERDICT_VALUES },
        total_score: { type: "number" },
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              finding_id: { type: "string" },
              impact: { type: "number" },
              proof_quality: { type: "number" },
              severity_accuracy: { type: "number" },
              chain_potential: { type: "number" },
              report_quality: { type: "number" },
              total_score: { type: "number" },
              feedback: { type: ["string", "null"] },
            },
            required: [
              "finding_id",
              "impact",
              "proof_quality",
              "severity_accuracy",
              "chain_potential",
              "report_quality",
              "total_score",
              "feedback",
            ],
          },
        },
        feedback: { type: ["string", "null"] },
      },
      required: ["target_domain", "verdict", "total_score", "findings", "feedback"],
    },
  },
  {
    name: "bounty_read_grade_verdict",
    description: "Read the authoritative grade verdict JSON document.",
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
        target_domain: { type: "string" },
        profile_name: { type: "string" },
        cookies: { type: "object", additionalProperties: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        local_storage: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["profile_name"],
    },
  },
  {
    name: "bounty_log_dead_ends",
    description:
      "Append dead ends and WAF-blocked endpoints discovered so far. Call periodically (~every 30 turns) so terrain survives if the hunter hits maxTurns. Validated against wave assignments.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
        surface_id: { type: "string" },
        dead_ends: { type: "array", items: { type: "string" } },
        waf_blocked_endpoints: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "wave", "agent", "surface_id"],
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

function assertRequiredText(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeOptionalText(value, fieldName) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string or null`);
  }
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function assertBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new Error(`${fieldName} must be a boolean`);
  }
  return value;
}

function assertInteger(value, fieldName, { min = undefined, max = undefined } = {}) {
  if (!Number.isInteger(value)) {
    throw new Error(`${fieldName} must be an integer`);
  }
  if (min != null && value < min) {
    throw new Error(`${fieldName} must be >= ${min}`);
  }
  if (max != null && value > max) {
    throw new Error(`${fieldName} must be <= ${max}`);
  }
  return value;
}

function assertEnumValue(value, allowedValues, fieldName) {
  if (!allowedValues.includes(value)) {
    throw new Error(`${fieldName} must be one of ${allowedValues.join(", ")}`);
  }
  return value;
}

function parseFindingId(value, fieldName = "finding_id") {
  const findingId = assertNonEmptyString(value, fieldName);
  if (!FINDING_ID_RE.test(findingId)) {
    throw new Error(`${fieldName} must match F-N`);
  }
  return findingId;
}

function findingsJsonlPath(domain) {
  return path.join(sessionDir(domain), "findings.jsonl");
}

function findingsMarkdownPath(domain) {
  return path.join(sessionDir(domain), "findings.md");
}

function verificationRoundPaths(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  const fileNames = VERIFICATION_ROUND_FILE_MAP[normalizedRound];
  const dir = sessionDir(domain);
  return {
    round: normalizedRound,
    json: path.join(dir, fileNames.json),
    markdown: path.join(dir, fileNames.markdown),
  };
}

function gradeArtifactPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "grade.json"),
    markdown: path.join(dir, "grade.md"),
  };
}

function appendJsonlLine(filePath, document) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(document)}\n`, "utf8");
}

function writeMarkdownMirror(markdownPath, content, response) {
  try {
    writeFileAtomic(markdownPath, content);
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function appendMarkdownMirror(markdownPath, content, response) {
  try {
    fs.mkdirSync(path.dirname(markdownPath), { recursive: true });
    fs.appendFileSync(markdownPath, content, "utf8");
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function loadJsonDocumentStrict(filePath, label) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing ${label}: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed ${label}: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Malformed ${label}: ${filePath} (expected object)`);
  }

  return parsed;
}

function normalizeFindingRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "finding record must be an object"
      : `Malformed findings.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const finding = {
      id: parseFindingId(record.id, "id"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      title: assertRequiredText(record.title, "title"),
      severity: assertEnumValue(record.severity, SEVERITY_VALUES, "severity"),
      cwe: normalizeOptionalText(record.cwe, "cwe"),
      endpoint: assertRequiredText(record.endpoint, "endpoint"),
      description: assertRequiredText(record.description, "description"),
      proof_of_concept: assertRequiredText(record.proof_of_concept, "proof_of_concept"),
      response_evidence: normalizeOptionalText(record.response_evidence, "response_evidence"),
      impact: normalizeOptionalText(record.impact, "impact"),
      validated: assertBoolean(record.validated, "validated"),
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
    };

    if (expectedDomain != null && finding.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return finding;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readFindingsFromJsonl(domain) {
  const filePath = findingsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const findings = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed findings.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }

    findings.push(normalizeFindingRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }

  return findings;
}

function renderFindingMarkdownEntry(finding) {
  const waveAgent = finding.wave || finding.agent
    ? `\n- **Wave/Agent:** ${finding.wave || "?"}/${finding.agent || "?"}`
    : "";

  return [
    `## FINDING ${finding.id.slice(2)} (${finding.severity.toUpperCase()}): ${finding.title}`,
    `- **ID:** ${finding.id}`,
    `- **CWE:** ${finding.cwe || "N/A"}`,
    `- **Endpoint:** ${finding.endpoint}`,
    `- **Validated:** ${finding.validated ? "YES" : "NO"}`,
    `- **Description:** ${finding.description}`,
    `- **PoC:**`,
    "```",
    finding.proof_of_concept,
    "```",
    `- **Evidence:** ${finding.response_evidence || "See PoC"}`,
    `- **Impact:** ${finding.impact || "N/A"}`,
    waveAgent,
    "---\n\n",
  ].join("\n");
}

function normalizeVerificationResult(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("results entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  return {
    finding_id: findingId,
    disposition: assertEnumValue(result.disposition, VERIFICATION_DISPOSITION_VALUES, "disposition"),
    severity: result.severity == null ? null : assertEnumValue(result.severity, SEVERITY_VALUES, "severity"),
    reportable: assertBoolean(result.reportable, "reportable"),
    reasoning: assertRequiredText(result.reasoning, "reasoning"),
  };
}

function normalizeVerificationRoundDocument(document, { expectedDomain, expectedRound, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("verification round document must be an object");
  }

  const round = assertEnumValue(document.round, VERIFICATION_ROUND_VALUES, "round");
  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    round,
    notes: normalizeOptionalText(document.notes, "notes"),
    results: [],
  };

  if (!Array.isArray(document.results)) {
    throw new Error("results must be an array");
  }

  const seenIds = new Set();
  for (const result of document.results) {
    const normalizedResult = normalizeVerificationResult(
      result,
      findingIdSet ?? new Set([parseFindingId(result.finding_id)]),
    );
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    normalized.results.push(normalizedResult);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`verification round target_domain mismatch: expected ${expectedDomain}`);
  }
  if (expectedRound != null && normalized.round !== expectedRound) {
    throw new Error(`verification round mismatch: expected ${expectedRound}`);
  }

  return normalized;
}

function renderVerificationRoundMarkdown(document) {
  const lines = [
    `# Verification Round: ${document.round}`,
    `- Target: ${document.target_domain}`,
    `- Notes: ${document.notes || "N/A"}`,
    `- Results: ${document.results.length}`,
    "",
  ];

  if (document.results.length === 0) {
    lines.push("No verification results recorded.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const result of document.results) {
    lines.push(`## ${result.finding_id}`);
    lines.push(`- Disposition: ${result.disposition}`);
    lines.push(`- Severity: ${result.severity || "none"}`);
    lines.push(`- Reportable: ${result.reportable ? "YES" : "NO"}`);
    lines.push(`- Reasoning: ${result.reasoning}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function normalizeGradeFinding(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("findings entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    impact: assertInteger(result.impact, "impact", { min: 0, max: 30 }),
    proof_quality: assertInteger(result.proof_quality, "proof_quality", { min: 0, max: 25 }),
    severity_accuracy: assertInteger(result.severity_accuracy, "severity_accuracy", { min: 0, max: 15 }),
    chain_potential: assertInteger(result.chain_potential, "chain_potential", { min: 0, max: 15 }),
    report_quality: assertInteger(result.report_quality, "report_quality", { min: 0, max: 15 }),
    total_score: assertInteger(result.total_score, "total_score", { min: 0 }),
    feedback: normalizeOptionalText(result.feedback, "feedback"),
  };

  const expectedTotal = normalized.impact
    + normalized.proof_quality
    + normalized.severity_accuracy
    + normalized.chain_potential
    + normalized.report_quality;
  if (normalized.total_score !== expectedTotal) {
    throw new Error(`finding ${findingId} total_score must equal the sum of rubric scores`);
  }

  return normalized;
}

function normalizeGradeVerdictDocument(document, { expectedDomain = null, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("grade verdict document must be an object");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    verdict: assertEnumValue(document.verdict, GRADE_VERDICT_VALUES, "verdict"),
    total_score: assertInteger(document.total_score, "total_score", { min: 0 }),
    findings: [],
    feedback: normalizeOptionalText(document.feedback, "feedback"),
  };

  if (!Array.isArray(document.findings)) {
    throw new Error("findings must be an array");
  }

  const seenIds = new Set();
  for (const finding of document.findings) {
    const normalizedFinding = normalizeGradeFinding(
      finding,
      findingIdSet ?? new Set([parseFindingId(finding.finding_id)]),
    );
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    normalized.findings.push(normalizedFinding);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`grade verdict target_domain mismatch: expected ${expectedDomain}`);
  }

  return normalized;
}

function renderGradeVerdictMarkdown(document) {
  const lines = [
    "# Grade Verdict",
    `- Target: ${document.target_domain}`,
    `- Verdict: ${document.verdict}`,
    `- Total Score: ${document.total_score}`,
    `- Feedback: ${document.feedback || "N/A"}`,
    "",
  ];

  if (document.findings.length === 0) {
    lines.push("No graded findings.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of document.findings) {
    lines.push(`## ${finding.finding_id}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Proof Quality: ${finding.proof_quality}`);
    lines.push(`- Severity Accuracy: ${finding.severity_accuracy}`);
    lines.push(`- Chain Potential: ${finding.chain_potential}`);
    lines.push(`- Report Quality: ${finding.report_quality}`);
    lines.push(`- Total Score: ${finding.total_score}`);
    lines.push(`- Feedback: ${finding.feedback || "N/A"}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
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
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const structuredPath = findingsJsonlPath(domain);
  if (!findingCounters.has(structuredPath) || !fs.existsSync(structuredPath)) {
    findingCounters.set(structuredPath, readFindingsFromJsonl(domain).length);
  }

  const counter = findingCounters.get(structuredPath) + 1;
  const finding = normalizeFindingRecord({
    id: `F-${counter}`,
    target_domain: domain,
    title: args.title,
    severity: args.severity,
    cwe: args.cwe,
    endpoint: args.endpoint,
    description: args.description,
    proof_of_concept: args.proof_of_concept,
    response_evidence: args.response_evidence,
    impact: args.impact,
    validated: args.validated,
    wave: args.wave ?? null,
    agent: args.agent ?? null,
  }, { expectedDomain: domain });

  appendJsonlLine(structuredPath, finding);

  findingCounters.set(structuredPath, counter);

  const response = {
    recorded: true,
    finding_id: finding.id,
    total: counter,
    written_jsonl: structuredPath,
  };

  appendMarkdownMirror(findingsMarkdownPath(domain), renderFindingMarkdownEntry(finding), response);
  return JSON.stringify(response);
}

function readFindings(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: readFindingsFromJsonl(domain),
  });
}

function listFindings(args) {
  const findings = readFindingsFromJsonl(assertNonEmptyString(args.target_domain, "target_domain"));
  return JSON.stringify({
    count: findings.length,
    findings: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
    })),
  });
}

function waveStatus(args) {
  const findings = readFindingsFromJsonl(assertNonEmptyString(args.target_domain, "target_domain"));
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }

  return JSON.stringify({
    total: findings.length,
    by_severity: bySeverity,
    has_high_or_critical: bySeverity.critical + bySeverity.high > 0,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  });
}

function writeVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
  const notes = normalizeOptionalText(args.notes, "notes");
  if (!Array.isArray(args.results)) {
    throw new Error("results must be an array");
  }

  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  const results = args.results.map((result) => {
    const normalizedResult = normalizeVerificationResult(result, findingIdSet);
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    return normalizedResult;
  });

  // Completeness guard: balanced/final rounds must cover every finding from the prior round
  const PRIOR_ROUND = { balanced: "brutalist", final: "balanced" };
  if (PRIOR_ROUND[round]) {
    const priorPaths = verificationRoundPaths(domain, PRIOR_ROUND[round]);
    try {
      const priorDoc = JSON.parse(fs.readFileSync(priorPaths.json, "utf8"));
      const priorIds = new Set((priorDoc.results || []).map((r) => r.finding_id));
      const currentIds = new Set(results.map((r) => r.finding_id));
      const missing = [...priorIds].filter((id) => !currentIds.has(id));
      if (missing.length > 0) {
        throw new Error(
          `${round} round is missing ${missing.length} finding(s) from ${PRIOR_ROUND[round]} round: ${missing.join(", ")}. ` +
          `Include ALL findings from the prior round — pass through unchanged findings you did not re-test.`
        );
      }
    } catch (e) {
      if (e.message.includes("round is missing")) throw e;
      // Prior round file doesn't exist yet (e.g., brutalist hasn't run) — skip check
    }
  }

  const document = {
    version: 1,
    target_domain: domain,
    round,
    notes,
    results,
  };

  const paths = verificationRoundPaths(domain, round);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    round,
    results_count: results.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderVerificationRoundMarkdown(document), response);
  return JSON.stringify(response);
}

function readVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = verificationRoundPaths(domain, args.round);
  const document = loadJsonDocumentStrict(paths.json, `${paths.round} verification round JSON`);
  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  return JSON.stringify(normalizeVerificationRoundDocument(document, {
    expectedDomain: domain,
    expectedRound: paths.round,
    findingIdSet,
  }));
}

function writeGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const verdict = assertEnumValue(args.verdict, GRADE_VERDICT_VALUES, "verdict");
  const totalScore = assertInteger(args.total_score, "total_score", { min: 0 });
  const feedback = normalizeOptionalText(args.feedback, "feedback");
  if (!Array.isArray(args.findings)) {
    throw new Error("findings must be an array");
  }

  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  const findings = args.findings.map((finding) => {
    const normalizedFinding = normalizeGradeFinding(finding, findingIdSet);
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    return normalizedFinding;
  });

  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings,
    feedback,
  };

  const paths = gradeArtifactPaths(domain);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    verdict,
    findings_count: findings.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderGradeVerdictMarkdown(document), response);
  return JSON.stringify(response);
}

function readGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  return JSON.stringify(normalizeGradeVerdictDocument(document, {
    expectedDomain: domain,
    findingIdSet,
  }));
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

function logDeadEnds(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  // Validate against wave assignments — reject if wave/agent/surface_id not in assignments file
  const waveNumber = Number(wave.slice(1));
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
  }
  if (assignment.surface_id !== surfaceId) {
    throw new Error(`Agent ${agent} is assigned surface ${assignment.surface_id}, not ${surfaceId}`);
  }

  const deadEnds = normalizeStringArray(args.dead_ends, "dead_ends");
  const wafBlocked = normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints");

  if (deadEnds.length === 0 && wafBlocked.length === 0) {
    return JSON.stringify({ appended: 0, message: "Nothing to log" });
  }

  const dir = sessionDir(domain);
  const logPath = path.join(dir, `live-dead-ends-${wave}-${agent}.jsonl`);
  const record = {
    ts: new Date().toISOString(),
    surface_id: surfaceId,
    dead_ends: deadEnds,
    waf_blocked_endpoints: wafBlocked,
  };
  appendJsonlLine(logPath, record);

  return JSON.stringify({
    appended: deadEnds.length + wafBlocked.length,
    dead_ends: deadEnds.length,
    waf_blocked_endpoints: wafBlocked.length,
    log_path: logPath,
  });
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

  // Merge live dead-end logs (survive maxTurns kills even without a handoff)
  for (const assignment of assignments) {
    const logPath = path.join(dir, `live-dead-ends-${wave}-${assignment.agent}.jsonl`);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try { raw = fs.readFileSync(logPath, "utf8"); } catch { continue; }
    const lines = raw.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      try {
        const record = JSON.parse(line);
        if (record.surface_id !== assignment.surface_id) continue;
        pushUnique(deadEnds, deadEndSet, normalizeStringArray(record.dead_ends, "live_dead_ends"));
        pushUnique(wafBlockedEndpoints, wafSet, normalizeStringArray(record.waf_blocked_endpoints, "live_waf_blocked"));
      } catch {
        // Skip malformed line, keep processing remaining records
      }
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

  // Save to the target's session dir if provided, otherwise best-effort last session
  const sessionsDir = path.join(os.homedir(), "bounty-agent-sessions");
  try {
    const targetDir = args.target_domain
      ? path.join(sessionsDir, args.target_domain.trim())
      : null;

    if (targetDir && fs.existsSync(targetDir)) {
      fs.writeFileSync(path.join(targetDir, "auth.json"), JSON.stringify(profile, null, 2));
    } else {
      const dirs = fs.readdirSync(sessionsDir).sort();
      if (dirs.length > 0) {
        fs.writeFileSync(path.join(sessionsDir, dirs[dirs.length - 1], "auth.json"), JSON.stringify(profile, null, 2));
      }
    }
  } catch {}

  return JSON.stringify({ success: true, profile_name: name, keys: Object.keys(profile) });
}

// ── Tool dispatch ──
async function executeTool(name, args) {
  switch (name) {
    case "bounty_http_scan": return httpScan(args);
    case "bounty_record_finding": return recordFinding(args);
    case "bounty_read_findings": return readFindings(args);
    case "bounty_list_findings": return listFindings(args);
    case "bounty_write_verification_round": return writeVerificationRound(args);
    case "bounty_read_verification_round": return readVerificationRound(args);
    case "bounty_write_grade_verdict": return writeGradeVerdict(args);
    case "bounty_read_grade_verdict": return readGradeVerdict(args);
    case "bounty_write_handoff": return writeHandoff(args);
    case "bounty_log_dead_ends": return logDeadEnds(args);
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
  appendJsonlLine,
  gradeArtifactPaths,
  listFindings,
  mergeWaveHandoffs,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  sessionDir,
  findingsJsonlPath,
  findingsMarkdownPath,
  readFindings,
  readFindingsFromJsonl,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  normalizeStringArray,
  writeFileAtomic,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readSessionStateStrict,
} = require("./session-state.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  buildCoverageSummaryForSurface,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("./http-records.js");
const {
  summarizePublicIntelForSurface,
} = require("./public-intel.js");
const {
  summarizeStaticScanHints,
} = require("./static-artifacts.js");
const {
  filterExclusionsByHosts,
} = require("./scope.js");

// Bypass table tech-to-file map used by hunter brief generation.
const BYPASS_TABLE_MAP = {
  wordpress: "wordpress.txt",
  graphql: "graphql.txt",
  ssrf: "ssrf.txt",
  jwt: "jwt.txt",
  firebase: "firebase.txt",
  "next.js": "nextjs.txt",
  nextjs: "nextjs.txt",
  oauth: "oauth-oidc.txt",
  oidc: "oauth-oidc.txt",
};
const BYPASS_TABLE_DEFAULT = "rest-api.txt";
const HUNTER_KNOWLEDGE_FILE = path.join(".claude", "knowledge", "hunter-techniques.json");
const HUNTER_KNOWLEDGE_DEFAULT_ID = "generic-rest-api";
const HUNTER_KNOWLEDGE_MAX_ENTRIES = 4;
const HUNTER_KNOWLEDGE_MAX_CHARS = 4500;
const HUNTER_BRIEF_SURFACE_ARRAY_LIMITS = Object.freeze({
  hosts: 20,
  tech_stack: 20,
  endpoints: 80,
  interesting_params: 40,
  nuclei_hits: 30,
  bug_class_hints: 20,
  high_value_flows: 20,
  evidence: 25,
});
const HUNTER_BRIEF_SURFACE_SCALAR_LIMITS = Object.freeze({
  id: 120,
  priority: 40,
  original_priority: 40,
  surface_type: 80,
  name: 160,
  title: 160,
  description: 500,
});
const HUNTER_BRIEF_ARRAY_ITEM_MAX_CHARS = 500;
const HUNTER_BRIEF_RANKING_REASON_LIMIT = 10;
const HUNTER_BRIEF_RANKING_REASON_MAX_CHARS = 160;

function resolveBypassTable(techStack) {
  if (!Array.isArray(techStack)) return BYPASS_TABLE_DEFAULT;
  for (const tech of techStack) {
    const key = String(tech).toLowerCase();
    for (const [pattern, file] of Object.entries(BYPASS_TABLE_MAP)) {
      if (key.includes(pattern)) return file;
    }
  }
  return BYPASS_TABLE_DEFAULT;
}

function hunterKnowledgeCandidatePaths() {
  const candidates = [];
  if (process.env.CLAUDE_PROJECT_DIR) {
    candidates.push(path.join(process.env.CLAUDE_PROJECT_DIR, HUNTER_KNOWLEDGE_FILE));
  }
  candidates.push(path.join(__dirname, "..", "..", HUNTER_KNOWLEDGE_FILE));
  candidates.push(path.join(os.homedir(), HUNTER_KNOWLEDGE_FILE));
  return candidates;
}

function loadHunterKnowledge() {
  for (const candidate of hunterKnowledgeCandidatePaths()) {
    try {
      if (!candidate || !fs.existsSync(candidate)) continue;
      const parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
      if (parsed && typeof parsed === "object" && Array.isArray(parsed.entries)) {
        return {
          path: candidate,
          entries: parsed.entries.filter((entry) => entry && typeof entry === "object"),
        };
      }
    } catch {
      // Knowledge is read-only enrichment. A malformed optional file should not
      // block a hunter from receiving the deterministic assignment brief.
    }
  }
  return { path: null, entries: [] };
}

function lowerStringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item).toLowerCase());
}

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function surfaceFieldText(surface, fields) {
  const values = [];
  for (const field of fields) {
    values.push(...lowerStringArray(surface[field]));
  }
  return values.join("\n");
}

function countMatches(patterns, haystack, weight, label) {
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !haystack.includes(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function countExactMatches(patterns, values, weight, label) {
  const valueSet = new Set(lowerStringArray(values));
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !valueSet.has(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function scoreKnowledgeEntry(entry, surface) {
  const match = entry.match && typeof entry.match === "object" ? entry.match : {};
  const techText = surfaceFieldText(surface, [
    "tech_stack",
    "surface_type",
  ]);
  const endpointText = surfaceFieldText(surface, [
    "endpoints",
    "discovered_endpoints",
    "js_endpoints",
    "hosts",
    "high_value_flows",
    "evidence",
  ]);
  const paramValues = [
    ...lowerStringArray(surface.interesting_params),
    ...lowerStringArray(surface.params),
    ...lowerStringArray(surface.parameters),
  ];
  const hintText = surfaceFieldText(surface, [
    "nuclei_hits",
    "js_hints",
    "security_issues",
    "leaked_secrets",
    "auth_info",
    "surface_type",
    "bug_class_hints",
    "high_value_flows",
    "evidence",
  ]);

  const scored = [
    countMatches(match.tech, techText, 8, "tech"),
    countMatches(match.endpoints, endpointText, 5, "endpoint"),
    countExactMatches(match.params, paramValues, 3, "param"),
    countMatches(match.hints, hintText, 4, "hint"),
  ];

  return scored.reduce(
    (result, item) => ({
      score: result.score + item.score,
      matches: result.matches.concat(item.matches),
    }),
    { score: 0, matches: [] },
  );
}

function slimKnowledgeEntry(entry, matches) {
  return {
    id: assertNonEmptyString(entry.id || "knowledge-entry", "knowledge.id"),
    title: assertNonEmptyString(entry.title || entry.id || "Hunter guidance", "knowledge.title"),
    matched: matches.slice(0, 6),
    techniques: stringArray(entry.techniques)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 4),
    payload_hints: stringArray(entry.payload_hints)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 4),
  };
}

function fitKnowledgeEntries(entries, maxChars) {
  const selected = [];
  for (const entry of entries) {
    const candidate = selected.concat(entry);
    if (JSON.stringify(candidate).length > maxChars) break;
    selected.push(entry);
  }
  return selected;
}

function resolveHunterKnowledge(surface) {
  const knowledge = loadHunterKnowledge();
  if (knowledge.entries.length === 0) {
    return {
      techniques: [],
      payload_hints: [],
      knowledge_summary: {
        source: null,
        entries_returned: 0,
        capped: false,
        char_count: 0,
      },
    };
  }

  const scoredEntries = [];
  for (const entry of knowledge.entries) {
    const scored = scoreKnowledgeEntry(entry, surface);
    if (scored.score > 0) {
      scoredEntries.push({ entry, score: scored.score, matches: scored.matches });
    }
  }

  if (scoredEntries.length === 0) {
    const fallback = knowledge.entries.find((entry) => entry.id === HUNTER_KNOWLEDGE_DEFAULT_ID);
    if (fallback) {
      scoredEntries.push({ entry: fallback, score: 0, matches: ["fallback:generic-rest-api"] });
    }
  }

  scoredEntries.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return String(a.entry.id || "").localeCompare(String(b.entry.id || ""));
  });

  const slimEntries = scoredEntries
    .slice(0, HUNTER_KNOWLEDGE_MAX_ENTRIES)
    .map(({ entry, matches }) => slimKnowledgeEntry(entry, matches));
  const fittedEntries = fitKnowledgeEntries(slimEntries, HUNTER_KNOWLEDGE_MAX_CHARS);
  let techniques = [];
  let payloadHints = [];
  let charCount = 0;
  while (fittedEntries.length > 0) {
    techniques = fittedEntries.map((entry) => ({
      id: entry.id,
      title: entry.title,
      matched: entry.matched,
      guidance: entry.techniques,
    }));
    payloadHints = fittedEntries
      .filter((entry) => entry.payload_hints.length > 0)
      .map((entry) => ({
        id: entry.id,
        title: entry.title,
        hints: entry.payload_hints,
      }));
    charCount = JSON.stringify({ techniques, payload_hints: payloadHints }).length;
    if (charCount <= HUNTER_KNOWLEDGE_MAX_CHARS) break;
    fittedEntries.pop();
  }
  if (fittedEntries.length === 0) {
    techniques = [];
    payloadHints = [];
    charCount = 0;
  }

  return {
    techniques,
    payload_hints: payloadHints,
    knowledge_summary: {
      source: knowledge.path ? path.basename(knowledge.path) : null,
      entries_returned: fittedEntries.length,
      capped: slimEntries.length > fittedEntries.length,
      char_count: charCount,
      max_chars: HUNTER_KNOWLEDGE_MAX_CHARS,
    },
  };
}

function isBriefScalar(value) {
  return value == null || ["string", "number", "boolean"].includes(typeof value);
}

function capStringValue(value, maxChars) {
  if (typeof value !== "string" || value.length <= maxChars) {
    return { value, truncated: false, total_chars: typeof value === "string" ? value.length : null };
  }
  return {
    value: value.slice(0, maxChars),
    truncated: true,
    total_chars: value.length,
  };
}

function cappedSurfaceArray(value, limit) {
  const values = Array.isArray(value)
    ? value
    : value == null
      ? []
      : [value];
  let truncatedValues = 0;
  const shownValues = values.filter((item) => item != null).slice(0, limit).map((item) => {
    const capped = capStringValue(String(item), HUNTER_BRIEF_ARRAY_ITEM_MAX_CHARS);
    if (capped.truncated) truncatedValues += 1;
    return capped.value;
  });
  const limits = {
    shown: shownValues.length,
    total: values.length,
    omitted: Math.max(0, values.length - shownValues.length),
  };
  if (truncatedValues > 0) {
    limits.truncated_values = truncatedValues;
    limits.max_value_chars = HUNTER_BRIEF_ARRAY_ITEM_MAX_CHARS;
  }
  return {
    values: shownValues,
    limits,
  };
}

function slimRankingForBrief(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const ranking = {};
  if (Number.isFinite(value.version)) ranking.version = value.version;
  if (Number.isFinite(value.score)) ranking.score = value.score;
  if (isBriefScalar(value.priority)) {
    ranking.priority = capStringValue(String(value.priority), HUNTER_BRIEF_SURFACE_SCALAR_LIMITS.priority).value;
  }
  const cappedReasons = cappedSurfaceArray(value.reasons, HUNTER_BRIEF_RANKING_REASON_LIMIT);
  ranking.reasons = cappedReasons.values.map((reason) => {
    const capped = capStringValue(reason, HUNTER_BRIEF_RANKING_REASON_MAX_CHARS);
    return capped.value;
  });
  return ranking;
}

function slimSurfaceForBrief(surface) {
  const source = surface && typeof surface === "object" && !Array.isArray(surface) ? surface : {};
  const slimSurface = {};
  const surfaceLimits = {};

  for (const [field, maxChars] of Object.entries(HUNTER_BRIEF_SURFACE_SCALAR_LIMITS)) {
    const value = source[field];
    if (!isBriefScalar(value) || value == null) continue;
    const normalizedValue = typeof value === "string" ? value : String(value);
    const capped = capStringValue(normalizedValue, maxChars);
    slimSurface[field] = capped.value;
    if (capped.truncated) {
      surfaceLimits[field] = {
        shown_chars: capped.value.length,
        total_chars: capped.total_chars,
        omitted_chars: capped.total_chars - capped.value.length,
      };
    }
  }

  const ranking = slimRankingForBrief(source.ranking);
  if (ranking) {
    slimSurface.ranking = ranking;
  }

  for (const [field, limit] of Object.entries(HUNTER_BRIEF_SURFACE_ARRAY_LIMITS)) {
    const capped = cappedSurfaceArray(source[field], limit);
    slimSurface[field] = capped.values;
    surfaceLimits[field] = capped.limits;
  }

  return {
    surface: slimSurface,
    surface_limits: surfaceLimits,
  };
}

function readHunterBrief(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const waveNumber = Number(wave.slice(1));

  // 1. Load and validate assignment
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
  }

  // 2. Load attack surface and find assigned surface
  const attackSurface = readAttackSurfaceStrict(domain);
  let surfacesForBrief = attackSurface.document.surfaces;
  try {
    const ranked = rankAttackSurfaces(domain, { write: false });
    if (ranked && Array.isArray(ranked.surfaces)) {
      surfacesForBrief = ranked.surfaces;
    }
  } catch {}
  const surfaceObj = surfacesForBrief.find(
    (s) => s.id === assignment.surface_id,
  );
  if (!surfaceObj) {
    throw new Error(`Surface ${assignment.surface_id} not found in attack_surface.json`);
  }

  // 3. Read session state for exclusions
  const { state } = readSessionStateStrict(domain);

  // 4. Resolve bypass table
  const bypassFile = resolveBypassTable(surfaceObj.tech_stack);
  let bypassTable = "";
  try {
    // Look for bypass tables relative to project dir, install location, or global install
    const candidates = [
      path.join(process.env.CLAUDE_PROJECT_DIR || "", ".claude", "bypass-tables", bypassFile),
      path.join(__dirname, "..", "..", ".claude", "bypass-tables", bypassFile),
      path.join(os.homedir(), ".claude", "bypass-tables", bypassFile),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        bypassTable = fs.readFileSync(candidate, "utf8").trim();
        break;
      }
    }
  } catch {}

  const deadEndResult = filterExclusionsByHosts(state.dead_ends, surfaceObj.hosts);
  const wafResult = filterExclusionsByHosts(state.waf_blocked_endpoints, surfaceObj.hosts);
  const knowledge = resolveHunterKnowledge(surfaceObj);
  const coverageSummary = buildCoverageSummaryForSurface(
    readCoverageRecordsFromJsonl(domain),
    assignment.surface_id,
  );
  const trafficSummary = summarizeTrafficRecords(
    readTrafficRecordsFromJsonl(domain),
    { surface: surfaceObj },
  );
  const auditRecords = readHttpAuditRecordsFromJsonl(domain);
  const auditSummary = summarizeHttpAuditRecords(auditRecords, { surface: surfaceObj });
  const circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords, { surface: surfaceObj });
  const intelHints = summarizePublicIntelForSurface(domain, surfaceObj);
  const staticScanHints = summarizeStaticScanHints(domain, { surface: surfaceObj });
  const slimSurface = slimSurfaceForBrief(surfaceObj);

  return JSON.stringify({
    target_url: state.target_url,
    wave,
    agent,
    surface: slimSurface.surface,
    surface_limits: slimSurface.surface_limits,
    valid_surface_ids: attackSurface.surface_ids,
    dead_ends: deadEndResult.filtered,
    waf_blocked_endpoints: wafResult.filtered,
    exclusions_summary: {
      dead_ends_total: deadEndResult.total,
      dead_ends_shown: deadEndResult.filtered.length,
      dead_ends_omitted: deadEndResult.omitted,
      waf_blocked_total: wafResult.total,
      waf_blocked_shown: wafResult.filtered.length,
      waf_blocked_omitted: wafResult.omitted,
    },
    bypass_table: bypassTable || null,
    techniques: knowledge.techniques,
    payload_hints: knowledge.payload_hints,
    knowledge_summary: knowledge.knowledge_summary,
    coverage_summary: coverageSummary,
    traffic_summary: trafficSummary,
    audit_summary: auditSummary,
    circuit_breaker_summary: circuitBreakerSummary,
    ranking_summary: surfaceObj.ranking || null,
    intel_hints: intelHints,
    static_scan_hints: staticScanHints,
    auth_profiles_hint: "Call `bounty_list_auth_profiles`; pass the chosen profile name as `auth_profile` to `bounty_http_scan`.",
  }, null, 2);
}

module.exports = {
  readHunterBrief,
  resolveBypassTable,
  resolveHunterKnowledge,
  slimSurfaceForBrief,
};

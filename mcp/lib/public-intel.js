"use strict";

const fs = require("fs");
const {
  PUBLIC_INTEL_MAX_ITEMS,
  PUBLIC_INTEL_MAX_RESPONSE_BYTES,
} = require("./constants.js");
const {
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  publicIntelPath,
} = require("./paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("./storage.js");
const {
  hostnamesForSurface,
} = require("./url-surface.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  parseCveFeed,
} = require("./cve-feed-parser.js");
const {
  matchCveBatch,
} = require("./cve-scope-matcher.js");
const {
  querySchemaContracts,
} = require("./schema-contracts-store.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function readPublicIntelDocument(domain) {
  const filePath = publicIntelPath(domain);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    const parsed = readJsonFile(filePath, { label: "public-intel.json" });
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    if (parsed.target_domain !== domain) return null;
    return parsed;
  } catch {
    return null;
  }
}

function summarizePublicIntelForSurface(domain, surface, limit = PUBLIC_INTEL_MAX_ITEMS) {
  const intel = readPublicIntelDocument(domain);
  if (!intel) {
    return {
      available: false,
      reports: [],
      cve_matches: [],
      policy_summary: null,
      program_stats: null,
      errors: [],
    };
  }

  const surfaceTextValue = [
    surface && surface.id,
    ...hostnamesForSurface(surface || {}),
    ...stringArray(surface && surface.endpoints),
    ...stringArray(surface && surface.bug_class_hints),
    ...stringArray(surface && surface.high_value_flows),
    ...stringArray(surface && surface.surface_type),
  ].join(" ").toLowerCase();
  const reports = (Array.isArray(intel.disclosed_reports) ? intel.disclosed_reports : [])
    .filter((item) => item && typeof item === "object")
    .filter((report) => {
      const text = [report.title, report.url, report.query, ...(report.keywords || [])].join(" ").toLowerCase();
      if (!surfaceTextValue || !text) return true;
      return surfaceTextValue.split(/[^a-z0-9]+/).some((token) => token.length >= 4 && text.includes(token));
    })
    .slice(0, limit);
  const surfaceId = surface && typeof surface.id === "string" ? surface.id : null;
  const cveMatches = (Array.isArray(intel.cve_matches && intel.cve_matches.records)
    ? intel.cve_matches.records
    : [])
    .filter((record) => record && typeof record === "object")
    .map((record) => {
      if (!surfaceId) return record;
      // Scope matches to this assignment so one hunter's brief never exposes
      // CVE hints, surface IDs, or tech tokens belonging to other surfaces.
      const scoped = Array.isArray(record.matches)
        ? record.matches.filter((match) => match && match.surface_id === surfaceId)
        : [];
      if (scoped.length === 0) return null;
      return { ...record, matches: scoped, match_count: scoped.length };
    })
    .filter(Boolean)
    .slice(0, limit);

  return {
    available: true,
    reports,
    cve_matches: cveMatches,
    policy_summary: intel.policy_summary || null,
    program_stats: intel.program_stats || null,
    structured_scopes: Array.isArray(intel.structured_scopes) ? intel.structured_scopes.slice(0, limit) : [],
    errors: Array.isArray(intel.errors) ? intel.errors : [],
  };
}

function normalizeProgramHandle(program) {
  const value = normalizeOptionalText(program, "program");
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if (parsed.hostname.endsWith("hackerone.com")) {
      return parsed.pathname.split("/").filter(Boolean)[0] || null;
    }
  } catch {}
  return value.replace(/^@+/, "").replace(/^\/+|\/+$/g, "").split("/", 1)[0] || null;
}

function assertAllowedPublicIntelUrl(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || !["hackerone.com", "www.hackerone.com"].includes(parsed.hostname)) {
    throw new Error(`public intel URL is not allowlisted: ${parsed.hostname}`);
  }
  return parsed.toString();
}

function capUtf8Text(text, maxBytes) {
  const buffer = Buffer.from(String(text), "utf8");
  if (buffer.length <= maxBytes) {
    return { text: String(text), truncated: false };
  }
  return {
    text: buffer.subarray(0, maxBytes).toString("utf8"),
    truncated: true,
  };
}

async function readResponseTextCapped(resp, maxBytes) {
  if (!resp.body || typeof resp.body.getReader !== "function") {
    return capUtf8Text(await resp.text(), maxBytes);
  }

  const reader = resp.body.getReader();
  const chunks = [];
  let receivedBytes = 0;
  let truncated = false;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const buffer = Buffer.from(value);
      const remaining = maxBytes - receivedBytes;
      if (remaining > 0) {
        chunks.push(buffer.length > remaining ? buffer.subarray(0, remaining) : buffer);
      }
      receivedBytes += buffer.length;
      if (receivedBytes > maxBytes) {
        truncated = true;
        if (typeof reader.cancel === "function") {
          await reader.cancel();
        }
        break;
      }
    }
  } finally {
    if (typeof reader.releaseLock === "function") {
      reader.releaseLock();
    }
  }

  return {
    text: Buffer.concat(chunks).toString("utf8"),
    truncated,
  };
}

async function fetchTextWithTimeout(url, {
  timeoutMs = 8000,
  headers = {},
  maxBytes = PUBLIC_INTEL_MAX_RESPONSE_BYTES,
} = {}) {
  const safeUrl = assertAllowedPublicIntelUrl(url);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(safeUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; bountyagent-public-intel)",
        Accept: "application/json,text/html;q=0.9,*/*;q=0.8",
        ...headers,
      },
      signal: controller.signal,
    });
    const { text, truncated } = await readResponseTextCapped(resp, maxBytes);
    return {
      ok: resp.ok,
      status: resp.status,
      text,
      content_type: resp.headers.get("content-type") || "",
      truncated,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function compactPolicyText(value, maxChars = 1500) {
  const text = normalizeOptionalText(value, "policy") || null;
  if (!text) return null;
  return text.replace(/\s+/g, " ").trim().slice(0, maxChars);
}

function pickProgramStats(programJson) {
  const candidates = [
    programJson,
    programJson && programJson.program,
    programJson && programJson.profile,
  ].filter(Boolean);
  const stats = {};
  for (const candidate of candidates) {
    for (const key of [
      "handle",
      "name",
      "submission_state",
      "offers_bounties",
      "resolved_report_count",
      "triaged_report_count",
      "average_bounty_lower_amount",
      "average_bounty_upper_amount",
    ]) {
      if (candidate[key] != null && stats[key] == null) stats[key] = candidate[key];
    }
  }
  return Object.keys(stats).length > 0 ? stats : null;
}

function extractStructuredScopes(programJson, limit) {
  const scopes = programJson.structured_scopes ||
    programJson.program?.structured_scopes ||
    programJson.profile?.structured_scopes ||
    [];
  if (!Array.isArray(scopes)) return [];
  return scopes.slice(0, limit).map((scope) => ({
    asset_identifier: scope.asset_identifier || scope.identifier || scope.asset || null,
    asset_type: scope.asset_type || scope.type || null,
    eligible_for_bounty: scope.eligible_for_bounty ?? scope.eligible_for_submission ?? null,
    instruction: compactPolicyText(scope.instruction || scope.instructions, 300),
  }));
}

function parseHacktivityReportsFromJson(parsed, query, limit) {
  const containers = [
    parsed && parsed.reports,
    parsed && parsed.data,
    parsed && parsed.results,
    parsed && parsed.hacktivity_items,
  ].filter(Array.isArray);
  const reports = [];
  for (const container of containers) {
    for (const item of container) {
      const report = item.report || item;
      const id = report.id || report.databaseId || report.report_id || item.id;
      const title = report.title || report.summary || item.title || item.name;
      if (!id && !title) continue;
      reports.push({
        title: title ? String(title).slice(0, 160) : `Report ${id}`,
        url: id ? `https://hackerone.com/reports/${id}` : null,
        query,
      });
      if (reports.length >= limit) return reports;
    }
  }
  return reports;
}

function parseHacktivityReportsFromHtml(html, query, limit) {
  const reports = [];
  const seen = new Set();
  const reportRe = /href=["'](\/reports\/(\d+))["'][^>]*>([^<]{0,200})</gi;
  let match;
  while ((match = reportRe.exec(html)) && reports.length < limit) {
    const url = `https://hackerone.com${match[1]}`;
    if (seen.has(url)) continue;
    seen.add(url);
    const title = (match[3] || `Report ${match[2]}`).replace(/\s+/g, " ").trim();
    reports.push({ title: title || `Report ${match[2]}`, url, query });
  }
  return reports;
}

function cveSeverityRank(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return 0;
  if (value === "high") return 1;
  if (value === "medium") return 2;
  if (value === "low") return 3;
  if (value === "informational") return 4;
  return 5;
}

function compactText(value, maxChars) {
  if (typeof value !== "string") return null;
  const compact = value.replace(/\s+/g, " ").trim();
  if (!compact) return null;
  return compact.length > maxChars ? compact.slice(0, maxChars) : compact;
}

function compactCveRecord(record, matchResult) {
  const references = Array.isArray(record.references)
    ? record.references.slice(0, 3).map((reference) => ({
        url: typeof reference.url === "string" ? reference.url : null,
        tags: Array.isArray(reference.tags) ? reference.tags.slice(0, 5) : [],
      }))
    : [];
  // Keep the strongest match per distinct surface before truncating. matches
  // are already confidence-sorted, so the first row for a surface is its best.
  // Capping raw rows could drop whole surfaces (and their per-surface hint and
  // ranking boost) when one CVE matches many surfaces via repeated tokens.
  const matchedSurfaces = new Set();
  const distinctSurfaceMatches = [];
  const sourceMatches = Array.isArray(matchResult.matches) ? matchResult.matches : [];
  for (const match of sourceMatches) {
    if (matchedSurfaces.has(match.surface_id)) continue;
    matchedSurfaces.add(match.surface_id);
    distinctSurfaceMatches.push(match);
  }
  return {
    cve_id: record.cve_id,
    severity: record.severity || null,
    cvss_score: typeof record.cvss_score === "number" ? record.cvss_score : null,
    vulnerability_class: record.vulnerability_class || null,
    description: compactText(record.description, 600),
    published_at: record.published_at || null,
    references,
    match_count: matchResult.match_count,
    matched_surface_count: matchedSurfaces.size,
    match_hash: matchResult.match_hash,
    matches: distinctSurfaceMatches.slice(0, PUBLIC_INTEL_MAX_ITEMS).map((match) => ({
      surface_id: match.surface_id,
      confidence: match.confidence,
      surface_field: match.surface_field,
      surface_raw_token: match.surface_raw_token,
      token: match.token,
      cve_vendor: match.cve_vendor,
      cve_product: match.cve_product,
      cve_version: match.cve_version,
      cve_version_range: match.cve_version_range,
      notes: match.notes || null,
    })),
  };
}

function attackSurfaceFingerprint(domain) {
  // Stable hash of the surfaces that CVE matching reads from. Used as a
  // freshness key so preserved matches are dropped once the surface changes.
  try {
    const attackSurface = readAttackSurfaceStrict(domain);
    return hashCanonicalJson(attackSurface.document.surfaces);
  } catch {
    return null;
  }
}

function buildCveScopeMatches(domain, rawFeed, options = {}) {
  const feedText = assertRequiredText(rawFeed, "cve_feed_json");
  if (Buffer.byteLength(feedText, "utf8") > PUBLIC_INTEL_MAX_RESPONSE_BYTES) {
    throw new Error(`cve_feed_json exceeds read cap of ${PUBLIC_INTEL_MAX_RESPONSE_BYTES} bytes`);
  }
  const limit = options.limit == null
    ? PUBLIC_INTEL_MAX_ITEMS
    : assertInteger(options.limit, "cve_limit", { min: 1, max: PUBLIC_INTEL_MAX_ITEMS });
  const sourceUri = normalizeOptionalText(options.source_uri, "cve_source_uri");
  const parsed = parseCveFeed(feedText);
  const result = {
    version: 1,
    source_uri: sourceUri,
    schema_format: parsed.schema_format,
    total_records: parsed.records.length,
    total_with_matches: 0,
    parser_warnings: parsed.parser_warnings,
    errors: [],
    records: [],
  };
  if (parsed.records.length === 0) {
    return result;
  }

  let attackSurface;
  try {
    attackSurface = readAttackSurfaceStrict(domain);
  } catch (error) {
    result.errors.push(`attack_surface: ${error.message || String(error)}`);
    return result;
  }
  result.attack_surface_hash = hashCanonicalJson(attackSurface.document.surfaces);

  let schemaContracts = [];
  try {
    schemaContracts = querySchemaContracts({ target_domain: domain }).contracts;
  } catch (error) {
    result.errors.push(`schema_contracts: ${error.message || String(error)}`);
  }

  const byId = new Map(parsed.records.map((record) => [record.cve_id, record]));
  const batch = matchCveBatch({
    cve_records: parsed.records,
    surfaces: attackSurface.document.surfaces,
    schema_contracts: schemaContracts,
  });
  const matched = batch.records
    .filter((record) => record.match_count > 0)
    .sort((a, b) => {
      const ar = byId.get(a.cve_id) || {};
      const br = byId.get(b.cve_id) || {};
      const bySeverity = cveSeverityRank(ar.severity) - cveSeverityRank(br.severity);
      if (bySeverity !== 0) return bySeverity;
      const byCvss = (br.cvss_score || 0) - (ar.cvss_score || 0);
      if (byCvss !== 0) return byCvss;
      return a.cve_id.localeCompare(b.cve_id);
    });

  result.total_with_matches = matched.length;
  result.records = matched
    .slice(0, limit)
    .map((matchResult) => compactCveRecord(byId.get(matchResult.cve_id) || {}, matchResult));
  result.truncated = matched.length > limit;
  return result;
}

async function bountyPublicIntel(args, { rankAttackSurfaces = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const programHandle = normalizeProgramHandle(args.program);
  const existing = readPublicIntelDocument(domain);
  const limit = args.limit == null
    ? PUBLIC_INTEL_MAX_ITEMS
    : assertInteger(args.limit, "limit", { min: 1, max: PUBLIC_INTEL_MAX_ITEMS });
  const cveLimit = args.cve_limit == null
    ? limit
    : assertInteger(args.cve_limit, "cve_limit", { min: 1, max: PUBLIC_INTEL_MAX_ITEMS });
  const keywords = args.keywords == null
    ? []
    : (Array.isArray(args.keywords)
        ? normalizeStringArray(args.keywords, "keywords")
        : [assertNonEmptyString(args.keywords, "keywords")]);
  if (keywords.length === 0) keywords.push(domain);

  const result = {
    version: 1,
    target_domain: domain,
    generated_at: new Date().toISOString(),
    program: programHandle,
    keywords,
    program_stats: null,
    policy_summary: null,
    structured_scopes: [],
    disclosed_reports: [],
    cve_matches: null,
    errors: [],
  };

  if (typeof fetch !== "function") {
    result.errors.push("fetch is unavailable in this Node runtime");
  } else {
    if (programHandle) {
      try {
        const programUrl = `https://hackerone.com/${encodeURIComponent(programHandle)}.json`;
        const fetched = await fetchTextWithTimeout(programUrl);
        if (!fetched.ok) {
          result.errors.push(`program ${programHandle}: HTTP ${fetched.status}`);
        } else {
          const programJson = JSON.parse(fetched.text);
          result.program_stats = pickProgramStats(programJson);
          result.policy_summary = compactPolicyText(
            programJson.policy ||
            programJson.program?.policy ||
            programJson.profile?.policy ||
            programJson.policy_html,
          );
          result.structured_scopes = extractStructuredScopes(programJson, limit);
        }
      } catch (error) {
        result.errors.push(`program ${programHandle}: ${error.message || String(error)}`);
      }
    }

    for (const keyword of keywords) {
      if (result.disclosed_reports.length >= limit) break;
      try {
        const query = keyword || domain;
        const url = `https://hackerone.com/hacktivity?querystring=${encodeURIComponent(query)}`;
        const fetched = await fetchTextWithTimeout(url);
        if (!fetched.ok) {
          result.errors.push(`hacktivity ${query}: HTTP ${fetched.status}`);
          continue;
        }
        let reports = [];
        if (fetched.content_type.includes("json") || /^[\s{[]/.test(fetched.text)) {
          try {
            reports = parseHacktivityReportsFromJson(JSON.parse(fetched.text), query, limit - result.disclosed_reports.length);
          } catch {
            reports = parseHacktivityReportsFromHtml(fetched.text, query, limit - result.disclosed_reports.length);
          }
        } else {
          reports = parseHacktivityReportsFromHtml(fetched.text, query, limit - result.disclosed_reports.length);
        }
        const seen = new Set(result.disclosed_reports.map((report) => report.url || report.title));
        for (const report of reports) {
          const key = report.url || report.title;
          if (!key || seen.has(key)) continue;
          seen.add(key);
          result.disclosed_reports.push(report);
          if (result.disclosed_reports.length >= limit) break;
        }
      } catch (error) {
        result.errors.push(`hacktivity ${keyword}: ${error.message || String(error)}`);
      }
    }
  }

  if (args.cve_feed_json != null) {
    try {
      result.cve_matches = buildCveScopeMatches(domain, args.cve_feed_json, {
        limit: cveLimit,
        source_uri: args.cve_source_uri,
      });
    } catch (error) {
      result.errors.push(`cve_feed_json: ${error.message || String(error)}`);
    }
  } else if (existing && existing.cve_matches) {
    // Carry prior CVE matches forward only when the attack surface is unchanged
    // since they were computed; otherwise drop them so hunters never inherit
    // stale hints or ranking boosts after recon reroutes or reuses surface IDs.
    const stampedHash = existing.cve_matches.attack_surface_hash || null;
    const currentHash = attackSurfaceFingerprint(domain);
    if (stampedHash && currentHash && stampedHash === currentHash) {
      result.cve_matches = existing.cve_matches;
    } else {
      result.errors.push(
        "cve_matches: dropped stale prior matches (no cve_feed_json supplied and the attack surface changed or could not be verified); re-supply the feed to recompute",
      );
    }
  }

  writeFileAtomic(publicIntelPath(domain), `${JSON.stringify(result, null, 2)}\n`);
  if (rankAttackSurfaces) {
    try {
      rankAttackSurfaces(domain);
    } catch {}
  }
  return JSON.stringify(result, null, 2);
}

module.exports = {
  bountyPublicIntel,
  compactPolicyText,
  extractStructuredScopes,
  assertAllowedPublicIntelUrl,
  fetchTextWithTimeout,
  normalizeProgramHandle,
  parseHacktivityReportsFromHtml,
  parseHacktivityReportsFromJson,
  pickProgramStats,
  readPublicIntelDocument,
  readResponseTextCapped,
  buildCveScopeMatches,
  summarizePublicIntelForSurface,
};

"use strict";

const fs = require("fs");
const {
  PUBLIC_INTEL_MAX_ITEMS,
  PUBLIC_INTEL_MAX_RESPONSE_BYTES,
} = require("./constants.js");
const {
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  publicIntelPath,
} = require("./paths.js");
const {
  writeFileAtomic,
} = require("./storage.js");
const {
  hostnamesForSurface,
} = require("./url-surface.js");

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
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
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

  return {
    available: true,
    reports,
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

async function bountyPublicIntel(args, { rankAttackSurfaces = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const programHandle = normalizeProgramHandle(args.program);
  const limit = args.limit == null
    ? PUBLIC_INTEL_MAX_ITEMS
    : assertInteger(args.limit, "limit", { min: 1, max: PUBLIC_INTEL_MAX_ITEMS });
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
    errors: [],
  };

  if (typeof fetch !== "function") {
    result.errors.push("fetch is unavailable in this Node runtime");
    writeFileAtomic(publicIntelPath(domain), `${JSON.stringify(result, null, 2)}\n`);
    return JSON.stringify(result, null, 2);
  }

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
  summarizePublicIntelForSurface,
};

"use strict";

const fs = require("fs");
const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  CIRCUIT_BREAKER_THRESHOLD,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  HTTP_AUDIT_SUMMARY_MAX_ITEMS,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
  TRAFFIC_SUMMARY_MAX_ITEMS,
} = require("./constants.js");
const {
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalInteger,
  normalizeOptionalText,
  normalizeStringArray,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  httpAuditJsonlPath,
  trafficJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  appendJsonlLines,
  withSessionLock,
} = require("./storage.js");
const {
  isFirstPartyHost,
  recordMatchesSurface,
  safeUrlObject,
  stripUrlFragment,
  validateScanUrl,
  hostnameFromUrl,
} = require("./url-surface.js");

function normalizeHttpAuditRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "http audit record must be an object"
      : `Malformed http-audit.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const redactedUrl = redactUrlSensitiveValues(assertRequiredText(record.url, "url"));
    const redactedParsed = safeUrlObject(redactedUrl);
    const normalized = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      method: assertRequiredText(record.method, "method").toUpperCase(),
      url: redactedUrl,
      host: normalizeOptionalText(record.host, "host"),
      path: redactedParsed
        ? `${redactedParsed.pathname}${redactedParsed.search}`
        : normalizeOptionalText(record.path, "path"),
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      auth_profile: normalizeOptionalText(record.auth_profile, "auth_profile"),
      status: normalizeOptionalInteger(record.status, "status", { min: 100, max: 599 }),
      error: normalizeOptionalText(record.error, "error"),
      scope_decision: assertRequiredText(record.scope_decision, "scope_decision"),
      duration_ms: normalizeOptionalInteger(record.duration_ms, "duration_ms", { min: 0 }),
      final_url: record.final_url == null ? null : redactUrlSensitiveValues(record.final_url),
    };
    if (normalized.host) normalized.host = normalized.host.toLowerCase();

    if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return normalized;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed http-audit.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readHttpAuditRecordsFromJsonl(domain) {
  const filePath = httpAuditJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed http-audit.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeHttpAuditRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function appendHttpAuditRecord(record) {
  if (!record || !record.target_domain) return;
  const normalized = normalizeHttpAuditRecord(record, { expectedDomain: record.target_domain });
  withSessionLock(normalized.target_domain, () => {
    appendJsonlLine(httpAuditJsonlPath(normalized.target_domain), normalized, {
      maxRecords: HTTP_AUDIT_LOG_MAX_RECORDS,
    });
  });
}

function compactHttpAuditRecord(record) {
  const item = {
    ts: record.ts,
    method: record.method,
    url: record.url,
    status: record.status,
    scope_decision: record.scope_decision,
  };
  if (record.error) item.error = record.error;
  if (record.auth_profile) item.auth_profile = record.auth_profile;
  if (record.wave || record.agent) item.wave_agent = `${record.wave || "?"}/${record.agent || "?"}`;
  if (record.surface_id) item.surface_id = record.surface_id;
  return item;
}

function summarizeHttpAuditRecords(records, { surface = null, limit = HTTP_AUDIT_SUMMARY_MAX_ITEMS } = {}) {
  const filteredRecords = (surface ? records.filter((record) => recordMatchesSurface(record, surface)) : records)
    .slice()
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  const shownRecords = filteredRecords.slice(0, limit);

  const byStatusClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 };
  let errorCount = 0;
  let blockedByScope = 0;
  for (const record of filteredRecords) {
    if (record.error) errorCount += 1;
    if (record.scope_decision === "blocked") blockedByScope += 1;
    if (record.status == null) {
      byStatusClass.other += 1;
      continue;
    }
    const key = `${Math.floor(record.status / 100)}xx`;
    if (Object.prototype.hasOwnProperty.call(byStatusClass, key)) {
      byStatusClass[key] += 1;
    } else {
      byStatusClass.other += 1;
    }
  }

  return {
    total: filteredRecords.length,
    shown: shownRecords.length,
    omitted: Math.max(0, filteredRecords.length - shownRecords.length),
    cap: limit,
    by_status_class: byStatusClass,
    errors: errorCount,
    scope_blocked: blockedByScope,
    recent: shownRecords.map(compactHttpAuditRecord),
  };
}

function isCircuitBreakerFailure(record) {
  if (record.status === 403 || record.status === 429) return true;
  if (record.scope_decision === "request_error" && /timeout|abort/i.test(record.error || "")) return true;
  return false;
}

function buildCircuitBreakerSummary(records, { surface = null, threshold = CIRCUIT_BREAKER_THRESHOLD } = {}) {
  const relevantRecords = (surface ? records.filter((record) => recordMatchesSurface(record, surface)) : records)
    .filter(isCircuitBreakerFailure);
  const byHost = new Map();
  for (const record of relevantRecords) {
    const host = record.host || hostnameFromUrl(record.url) || "unknown";
    if (!byHost.has(host)) {
      byHost.set(host, { host, failures: 0, status_403: 0, status_429: 0, timeouts: 0, latest_ts: null });
    }
    const item = byHost.get(host);
    item.failures += 1;
    if (record.status === 403) item.status_403 += 1;
    if (record.status === 429) item.status_429 += 1;
    if (/timeout|abort/i.test(record.error || "")) item.timeouts += 1;
    if (!item.latest_ts || Date.parse(record.ts) > Date.parse(item.latest_ts)) {
      item.latest_ts = record.ts;
    }
  }

  const tripped = Array.from(byHost.values())
    .filter((item) => item.failures >= threshold)
    .sort((a, b) => {
      if (b.failures !== a.failures) return b.failures - a.failures;
      return a.host.localeCompare(b.host);
    });

  return {
    threshold,
    tripped_hosts: tripped,
    tripped_count: tripped.length,
    note: tripped.length
      ? "Repeated 403/429/timeout results on these hosts. Prefer fewer replay variants, authenticated traffic-derived requests, or a different surface."
      : null,
  };
}

function headerNamesFromInput(headers) {
  if (headers == null) return [];
  if (Array.isArray(headers)) {
    return headers
      .map((header) => header && (header.name || header.key))
      .filter((name) => typeof name === "string" && name.trim())
      .map((name) => name.trim().toLowerCase());
  }
  if (typeof headers === "object") {
    return Object.keys(headers).map((name) => name.trim().toLowerCase()).filter(Boolean);
  }
  return [];
}

function queryKeysFromUrl(urlValue) {
  const parsed = safeUrlObject(urlValue);
  if (!parsed) return [];
  return Array.from(new Set(Array.from(parsed.searchParams.keys()).filter(Boolean))).sort();
}

function normalizeTrafficRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "traffic record must be an object"
      : `Malformed traffic.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const redactedUrl = redactUrlSensitiveValues(assertRequiredText(record.url, "url"));
    const redactedParsed = safeUrlObject(redactedUrl);
    const normalized = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      source: assertRequiredText(record.source, "source"),
      method: assertRequiredText(record.method, "method").toUpperCase(),
      url: redactedUrl,
      host: assertRequiredText(record.host, "host").toLowerCase(),
      path: redactedParsed
        ? `${redactedParsed.pathname}${redactedParsed.search}`
        : assertRequiredText(record.path, "path"),
      status: normalizeOptionalInteger(record.status, "status", { min: 100, max: 599 }),
      auth_profile: normalizeOptionalText(record.auth_profile, "auth_profile"),
      has_auth: record.has_auth == null ? false : assertBoolean(record.has_auth, "has_auth"),
      header_names: normalizeStringArray(record.header_names, "header_names").map((name) => name.toLowerCase()),
      query_keys: normalizeStringArray(record.query_keys, "query_keys"),
    };

    if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return normalized;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed traffic.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readTrafficRecordsFromJsonl(domain) {
  const filePath = trafficJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed traffic.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeTrafficRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function trafficRecordKey(record) {
  return JSON.stringify([
    record.method,
    stripUrlFragment(record.url),
    record.status == null ? "" : record.status,
    record.has_auth ? "auth" : "anon",
  ]);
}

function normalizeTrafficImportEntries(args) {
  const entries = args.entries;
  if (entries == null) return [];
  if (Array.isArray(entries)) return entries;
  if (typeof entries === "string") {
    const parsed = JSON.parse(entries);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && parsed.log && Array.isArray(parsed.log.entries)) return parsed.log.entries;
  }
  if (entries && typeof entries === "object" && !Array.isArray(entries)) {
    if (entries.log && Array.isArray(entries.log.entries)) return entries.log.entries;
    if (Array.isArray(entries.entries)) return entries.entries;
  }
  throw new Error("entries must be an array or a HAR object with log.entries");
}

function normalizeImportedTrafficEntry(entry, index, { targetDomain, source, importedAt, blockInternalHosts = false }) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
    return { rejected: true, reason: `entries[${index}] must be an object` };
  }

  const request = entry.request && typeof entry.request === "object" ? entry.request : null;
  const response = entry.response && typeof entry.response === "object" ? entry.response : null;
  const method = String(entry.method || entry.request_method || request?.method || "GET").toUpperCase();
  let url = entry.url || entry.request_url || request?.url || null;
  if (!url && (entry.host || entry.hostname) && (entry.path || entry.url_path)) {
    const host = entry.host || entry.hostname;
    const pathValue = String(entry.path || entry.url_path || "/");
    url = `${entry.scheme || "https"}://${host}${pathValue.startsWith("/") ? pathValue : `/${pathValue}`}`;
  }
  if (typeof url !== "string" || !url.trim()) {
    return { rejected: true, reason: `entries[${index}] missing request URL` };
  }
  url = stripUrlFragment(url.trim());

  try {
    validateScanUrl(url, { blockInternalHosts });
  } catch (error) {
    return { rejected: true, reason: `entries[${index}] ${error.message || String(error)}` };
  }

  const parsed = safeUrlObject(url);
  if (!parsed) {
    return { rejected: true, reason: `entries[${index}] invalid URL` };
  }
  const host = parsed.hostname.toLowerCase();
  if (!isFirstPartyHost(host, targetDomain)) {
    return { rejected: true, reason: `entries[${index}] host ${host} is outside ${targetDomain}` };
  }
  const redactedUrl = redactUrlSensitiveValues(url);
  const redactedParsed = safeUrlObject(redactedUrl) || parsed;

  const statusValue = entry.status ?? entry.response_status ?? response?.status ?? null;
  const status = statusValue == null || statusValue === ""
    ? null
    : Number(statusValue);
  if (status != null && (!Number.isInteger(status) || status < 100 || status > 599)) {
    return { rejected: true, reason: `entries[${index}] invalid HTTP status` };
  }

  const headerNames = Array.from(new Set([
    ...headerNamesFromInput(entry.headers),
    ...headerNamesFromInput(entry.request_headers),
    ...headerNamesFromInput(request?.headers),
  ])).sort();
  const hasAuth = !!entry.has_auth ||
    !!entry.auth_profile ||
    headerNames.some((name) => ["authorization", "cookie", "x-csrf-token", "x-xsrf-token"].includes(name));

  return {
    rejected: false,
    record: normalizeTrafficRecord({
      version: 1,
      ts: normalizeOptionalText(entry.ts || entry.time || entry.startedDateTime || entry.started_at, "ts") || importedAt,
      target_domain: targetDomain,
      source,
      method,
      url: redactedUrl,
      host,
      path: `${redactedParsed.pathname}${redactedParsed.search}`,
      status,
      auth_profile: entry.auth_profile || null,
      has_auth: hasAuth,
      header_names: headerNames,
      query_keys: queryKeysFromUrl(url),
    }, { expectedDomain: targetDomain }),
  };
}

function compactTrafficRecord(record) {
  const item = {
    ts: record.ts,
    source: record.source,
    method: record.method,
    url: record.url,
    status: record.status,
    has_auth: record.has_auth,
  };
  if (record.auth_profile) item.auth_profile = record.auth_profile;
  if (record.query_keys.length) item.query_keys = record.query_keys;
  return item;
}

function summarizeTrafficRecords(records, { surface = null, limit = TRAFFIC_SUMMARY_MAX_ITEMS } = {}) {
  const filteredRecords = (surface ? records.filter((record) => recordMatchesSurface(record, surface)) : records)
    .slice()
    .sort((a, b) => {
      if (Number(b.has_auth) !== Number(a.has_auth)) return Number(b.has_auth) - Number(a.has_auth);
      const statusDelta = (a.status == null ? 999 : Math.floor(a.status / 100)) - (b.status == null ? 999 : Math.floor(b.status / 100));
      if (statusDelta !== 0) return statusDelta;
      return Date.parse(b.ts) - Date.parse(a.ts);
    });
  const shownRecords = filteredRecords.slice(0, limit);
  const byStatusClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 };
  for (const record of filteredRecords) {
    if (record.status == null) {
      byStatusClass.other += 1;
      continue;
    }
    const key = `${Math.floor(record.status / 100)}xx`;
    if (Object.prototype.hasOwnProperty.call(byStatusClass, key)) {
      byStatusClass[key] += 1;
    } else {
      byStatusClass.other += 1;
    }
  }
  return {
    total: filteredRecords.length,
    shown: shownRecords.length,
    omitted: Math.max(0, filteredRecords.length - shownRecords.length),
    cap: limit,
    authenticated_count: filteredRecords.filter((record) => record.has_auth).length,
    by_status_class: byStatusClass,
    recent: shownRecords.map(compactTrafficRecord),
  };
}

function importHttpTraffic(args, { rankAttackSurfaces = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const source = assertRequiredText(args.source, "source");
  const blockInternalHosts = args.block_internal_hosts === true;
  const inputEntries = normalizeTrafficImportEntries(args);
  const entries = inputEntries.slice(0, TRAFFIC_IMPORT_MAX_ENTRIES);
  const importedAt = new Date().toISOString();
  const normalizedRecords = [];
  const rejected = [];

  for (let index = 0; index < entries.length; index += 1) {
    const normalized = normalizeImportedTrafficEntry(entries[index], index, {
      targetDomain: domain,
      source,
      importedAt,
      blockInternalHosts,
    });
    if (normalized.rejected) {
      rejected.push(normalized.reason);
      continue;
    }

    normalizedRecords.push(normalized.record);
  }

  return withSessionLock(domain, () => {
    const existingRecords = readTrafficRecordsFromJsonl(domain);
    const seen = new Set(existingRecords.map(trafficRecordKey));
    const records = [];
    let duplicateCount = 0;

    for (const record of normalizedRecords) {
      const key = trafficRecordKey(record);
      if (seen.has(key)) {
        duplicateCount += 1;
        continue;
      }
      seen.add(key);
      records.push(record);
    }

    const logPath = trafficJsonlPath(domain);
    appendJsonlLines(logPath, records, { maxRecords: TRAFFIC_LOG_MAX_RECORDS });
    if (rankAttackSurfaces) {
      try {
        rankAttackSurfaces(domain);
      } catch {}
    }

    return JSON.stringify({
      version: 1,
      target_domain: domain,
      source,
      imported: records.length,
      duplicates: duplicateCount,
      rejected: rejected.length,
      rejected_reasons: rejected.slice(0, 20),
      capped_input: Math.max(0, inputEntries.length - entries.length),
      traffic_path: logPath,
    });
  });
}

function readHttpAudit(args, { readAttackSurfaceStrict = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const limit = args.limit == null
    ? HTTP_AUDIT_SUMMARY_MAX_ITEMS
    : assertInteger(args.limit, "limit", { min: 0, max: HTTP_AUDIT_SUMMARY_MAX_ITEMS });
  let surface = null;
  if (args.surface_id != null) {
    if (!readAttackSurfaceStrict) {
      throw new Error("readAttackSurfaceStrict callback is required when surface_id is provided");
    }
    const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
    const attackSurface = readAttackSurfaceStrict(domain);
    surface = attackSurface.document.surfaces.find((item) => item.id === surfaceId);
    if (!surface) {
      throw new Error(`Surface ${surfaceId} not found in attack_surface.json`);
    }
  }

  const records = readHttpAuditRecordsFromJsonl(domain);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    surface_id: surface ? surface.id : null,
    summary: summarizeHttpAuditRecords(records, { surface, limit }),
    circuit_breaker_summary: buildCircuitBreakerSummary(records, { surface }),
  }, null, 2);
}

module.exports = {
  appendHttpAuditRecord,
  buildCircuitBreakerSummary,
  compactHttpAuditRecord,
  compactTrafficRecord,
  headerNamesFromInput,
  importHttpTraffic,
  isCircuitBreakerFailure,
  normalizeHttpAuditRecord,
  normalizeImportedTrafficEntry,
  normalizeTrafficImportEntries,
  normalizeTrafficRecord,
  queryKeysFromUrl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
  trafficRecordKey,
};

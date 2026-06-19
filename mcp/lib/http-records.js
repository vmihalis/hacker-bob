"use strict";

const crypto = require("crypto");
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
  readFileUtf8,
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
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  blockInternalHostsRequestPolicy,
} = require("./session-state-store.js");
const {
  appendFrontierEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");

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
      checkpoint_mode: normalizeOptionalText(record.checkpoint_mode, "checkpoint_mode"),
      block_internal_hosts: record.block_internal_hosts == null
        ? false
        : assertBoolean(record.block_internal_hosts, "block_internal_hosts"),
      block_internal_hosts_source: normalizeOptionalText(
        record.block_internal_hosts_source,
        "block_internal_hosts_source",
      ),
      egress_profile: normalizeOptionalText(record.egress_profile, "egress_profile") || "default",
      egress_region: normalizeOptionalText(record.egress_region, "egress_region"),
      proxy_configured: record.proxy_configured == null
        ? false
        : assertBoolean(record.proxy_configured, "proxy_configured"),
      egress_profile_identity_hash: normalizeOptionalText(
        record.egress_profile_identity_hash,
        "egress_profile_identity_hash",
      ),
      egress_profile_identity_version: record.egress_profile_identity_version == null
        ? null
        : assertInteger(record.egress_profile_identity_version, "egress_profile_identity_version", { min: 1 }),
      status: normalizeOptionalInteger(record.status, "status", { min: 100, max: 599 }),
      error: normalizeOptionalText(record.error, "error"),
      scope_decision: assertRequiredText(record.scope_decision, "scope_decision"),
      registrable_domain: normalizeOptionalText(record.registrable_domain, "registrable_domain"),
      public_suffix: normalizeOptionalText(record.public_suffix, "public_suffix"),
      public_suffix_source: normalizeOptionalText(record.public_suffix_source, "public_suffix_source"),
      psl_overlay_file: normalizeOptionalText(record.psl_overlay_file, "psl_overlay_file"),
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

  const content = readFileUtf8(filePath, { label: "http-audit.jsonl" });
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
  if (record.checkpoint_mode) item.checkpoint_mode = record.checkpoint_mode;
  item.block_internal_hosts = record.block_internal_hosts === true;
  if (record.block_internal_hosts_source) {
    item.block_internal_hosts_source = record.block_internal_hosts_source;
  }
  if (record.egress_profile) item.egress_profile = record.egress_profile;
  if (record.egress_region) item.egress_region = record.egress_region;
  if (record.egress_profile_identity_hash) {
    item.egress_profile_identity_hash = record.egress_profile_identity_hash;
  }
  if (record.public_suffix_source) item.public_suffix_source = record.public_suffix_source;
  if (record.public_suffix) item.public_suffix = record.public_suffix;
  if (record.registrable_domain) item.registrable_domain = record.registrable_domain;
  if (record.psl_overlay_file) item.psl_overlay_file = record.psl_overlay_file;
  if (record.wave || record.agent) item.wave_agent = `${record.wave || "?"}/${record.agent || "?"}`;
  if (record.surface_id) item.surface_id = record.surface_id;
  return item;
}

function isNetworkUnreachableRecord(record) {
  if (!record || record.status != null) return false;
  if (record.scope_decision === "network_unreachable_target") return true;
  return /timeout|abort|econnreset|socket hang up|etimedout|enotfound|eai_again|econnrefused|network unreachable|connection reset/i
    .test(record.error || "");
}

function summarizeEgressProfiles(records) {
  const byProfile = {};
  const byRegion = {};
  const byIdentityHash = {};
  let unbound = 0;
  const identities = new Map();
  for (const record of records) {
    const profile = record.egress_profile || "default";
    byProfile[profile] = (byProfile[profile] || 0) + 1;
    if (record.egress_region) {
      byRegion[record.egress_region] = (byRegion[record.egress_region] || 0) + 1;
    }
    if (record.egress_profile_identity_hash) {
      byIdentityHash[record.egress_profile_identity_hash] = (
        byIdentityHash[record.egress_profile_identity_hash] || 0
      ) + 1;
      if (!identities.has(record.egress_profile_identity_hash)) {
        identities.set(record.egress_profile_identity_hash, {
          egress_profile_identity_hash: record.egress_profile_identity_hash,
          egress_profile_identity_version: record.egress_profile_identity_version,
          egress_profile: profile,
          egress_region: record.egress_region || null,
          proxy_configured: record.proxy_configured === true,
        });
      }
    } else {
      unbound += 1;
    }
  }
  return {
    by_profile: byProfile,
    by_region: byRegion,
    by_identity_hash: byIdentityHash,
    unbound,
    identities: Array.from(identities.values())
      .sort((a, b) => a.egress_profile.localeCompare(b.egress_profile)),
  };
}

function summarizeGeofenceWarnings(records, targetDomain, { threshold = CIRCUIT_BREAKER_THRESHOLD } = {}) {
  const byHost = new Map();
  for (const record of records) {
    const host = record.host || hostnameFromUrl(record.url) || "unknown";
    if (!isFirstPartyHost(host, targetDomain)) continue;
    if (!isNetworkUnreachableRecord(record)) continue;
    if (!byHost.has(host)) {
      byHost.set(host, {
        host,
        failures: 0,
        egress_profiles: new Set(),
        latest_ts: null,
      });
    }
    const item = byHost.get(host);
    item.failures += 1;
    item.egress_profiles.add(record.egress_profile || "default");
    if (!item.latest_ts || Date.parse(record.ts) > Date.parse(item.latest_ts)) {
      item.latest_ts = record.ts;
    }
  }

  const hosts = Array.from(byHost.values())
    .filter((item) => item.failures >= threshold)
    .sort((a, b) => b.failures - a.failures || a.host.localeCompare(b.host))
    .map((item) => ({
      host: item.host,
      failures: item.failures,
      egress_profiles: Array.from(item.egress_profiles).sort(),
      latest_ts: item.latest_ts,
    }));

  return {
    threshold,
    warning: hosts.length > 0,
    code: hosts.length > 0 ? "network_unreachable_target" : null,
    note: hosts.length > 0
      ? "Repeated first-party timeouts or connection failures may indicate a geofenced or unreachable target. Keep egress switching operator-controlled."
      : null,
    hosts,
  };
}

function summarizeHttpAuditRecords(records, { surface = null, limit = HTTP_AUDIT_SUMMARY_MAX_ITEMS, targetDomain = null } = {}) {
  const filteredRecords = (surface ? records.filter((record) => recordMatchesSurface(record, surface)) : records)
    .slice()
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  const shownRecords = filteredRecords.slice(0, limit);

  const byStatusClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 };
  let errorCount = 0;
  let blockedByScope = 0;
  let networkUnreachable = 0;
  let internalHostBlocking = 0;
  const internalHostBlockingBySource = {};
  for (const record of filteredRecords) {
    if (record.error) errorCount += 1;
    if (record.scope_decision === "blocked") blockedByScope += 1;
    if (isNetworkUnreachableRecord(record)) networkUnreachable += 1;
    if (record.block_internal_hosts === true) internalHostBlocking += 1;
    if (record.block_internal_hosts_source) {
      internalHostBlockingBySource[record.block_internal_hosts_source] = (
        internalHostBlockingBySource[record.block_internal_hosts_source] || 0
      ) + 1;
    }
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

  const summary = {
    total: filteredRecords.length,
    shown: shownRecords.length,
    omitted: Math.max(0, filteredRecords.length - shownRecords.length),
    cap: limit,
    by_status_class: byStatusClass,
    errors: errorCount,
    scope_blocked: blockedByScope,
    network_unreachable_target: networkUnreachable,
    egress: summarizeEgressProfiles(filteredRecords),
    geofence_warning: summarizeGeofenceWarnings(
      filteredRecords,
      targetDomain || (filteredRecords[0] && filteredRecords[0].target_domain) || null,
    ),
    recent: shownRecords.map(compactHttpAuditRecord),
  };
  if (filteredRecords.length > 0) {
    summary.block_internal_hosts = {
      true: internalHostBlocking,
      false: Math.max(0, filteredRecords.length - internalHostBlocking),
      by_source: internalHostBlockingBySource,
    };
  }
  return summary;
}

function normalizeHttpAuditSummaryLimit(value) {
  if (value == null) return HTTP_AUDIT_SUMMARY_MAX_ITEMS;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error("limit must be a finite number");
  }
  return Math.max(0, Math.min(HTTP_AUDIT_SUMMARY_MAX_ITEMS, Math.trunc(value)));
}

function isCircuitBreakerFailure(record) {
  if (record.status === 403 || record.status === 429) return true;
  if (["request_error", "network_unreachable_target"].includes(record.scope_decision) && /timeout|abort|econnreset|connection reset/i.test(record.error || "")) return true;
  return false;
}

function buildCircuitBreakerSummary(records, { surface = null, threshold = CIRCUIT_BREAKER_THRESHOLD } = {}) {
  const relevantRecords = (surface ? records.filter((record) => recordMatchesSurface(record, surface)) : records)
    .filter(isCircuitBreakerFailure);
  const byHost = new Map();
  for (const record of relevantRecords) {
    const host = record.host || hostnameFromUrl(record.url) || "unknown";
    if (!byHost.has(host)) {
      byHost.set(host, {
        host,
        failures: 0,
        status_403: 0,
        status_429: 0,
        timeouts: 0,
        connection_errors: 0,
        egress_profiles: new Set(),
        latest_ts: null,
      });
    }
    const item = byHost.get(host);
    item.failures += 1;
    if (record.status === 403) item.status_403 += 1;
    if (record.status === 429) item.status_429 += 1;
    if (/timeout|abort/i.test(record.error || "")) item.timeouts += 1;
    if (isNetworkUnreachableRecord(record)) item.connection_errors += 1;
    item.egress_profiles.add(record.egress_profile || "default");
    if (!item.latest_ts || Date.parse(record.ts) > Date.parse(item.latest_ts)) {
      item.latest_ts = record.ts;
    }
  }

  const sortedItems = Array.from(byHost.values())
    .map((item) => ({
      ...item,
      egress_profiles: Array.from(item.egress_profiles).sort(),
    }))
    .sort((a, b) => {
      if (b.failures !== a.failures) return b.failures - a.failures;
      return a.host.localeCompare(b.host);
    });
  const tripped = sortedItems.filter((item) => item.failures >= threshold);
  // Hosts with at least one failure but still below threshold. Operators
  // looking at a session that had errors but no warnings need to see this
  // — otherwise they cannot tell whether the threshold was reached and
  // suppressed, or never crossed. Threshold is the action gate; the
  // reporting gate sits at the first failure.
  const belowThreshold = sortedItems.filter(
    (item) => item.failures > 0 && item.failures < threshold,
  );

  return {
    threshold,
    tripped_hosts: tripped,
    tripped_count: tripped.length,
    below_threshold_hosts: belowThreshold,
    below_threshold_count: belowThreshold.length,
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

function normalizeSourceMeta(value) {
  // T.7: optional structured source metadata. For browser_capture this is
  // { kind: "browser_capture", session_id, [resource_type, frame_url] }; for
  // other sources callers can attach an arbitrary small object. Keep the
  // shape narrow: string values only, max ~10 keys, each value <= 200 chars.
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("source_meta must be an object");
  }
  const out = {};
  let keys = 0;
  for (const [key, raw] of Object.entries(value)) {
    if (keys >= 10) break;
    if (typeof key !== "string" || !key.trim()) continue;
    if (raw == null) continue;
    if (typeof raw === "string") {
      out[key] = raw.length > 200 ? `${raw.slice(0, 200)}…` : raw;
    } else if (typeof raw === "number" || typeof raw === "boolean") {
      out[key] = raw;
    } else {
      // Skip nested objects/arrays to keep the on-disk shape simple.
      continue;
    }
    keys += 1;
  }
  return Object.keys(out).length === 0 ? null : out;
}

// Plane X Cycle X.7 (X-P9 retrofit): every traffic record carries a
// deterministic `request_id`. The id is a sha256 fingerprint of the
// surface-shaping tuple `{method, url, status, has_auth, ts}` truncated
// to 16 hex chars. Two responses with identical surface keys collapse
// to the same id (matching the existing trafficRecordKey dedup). The
// id is the X-D12 `http_record:<request_id>` lookup key the X.7
// resolver uses.
function deriveTrafficRequestId(record) {
  const fingerprint = crypto.createHash("sha256").update(JSON.stringify([
    record.method,
    record.url,
    record.status == null ? "" : record.status,
    record.has_auth ? "auth" : "anon",
    record.ts,
  ])).digest("hex");
  return `R-${fingerprint.slice(0, 16)}`;
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

    const sourceMeta = normalizeSourceMeta(record.source_meta);
    if (sourceMeta) {
      normalized.source_meta = sourceMeta;
    }

    // X.7 retrofit: stamp the deterministic request_id so the X-D12
    // http_record resolver has a stable lookup key. We compute the id
    // AFTER URL redaction so two replays with the same redacted-url
    // tuple share the id (the redaction is deterministic by
    // construction).
    normalized.request_id = typeof record.request_id === "string" && record.request_id.trim()
      ? record.request_id
      : deriveTrafficRequestId(normalized);

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

  const content = readFileUtf8(filePath, { label: "traffic.jsonl" });
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

function normalizeImportedTrafficEntry(entry, index, { targetDomain, source, importedAt, blockInternalHosts = false, sourceMeta = null }) {
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

  // Per-entry source metadata wins over the batch default so callers can mix
  // captures from multiple sessions in one import; the browser flush tool
  // sets the same session_id on every entry so the per-entry override is a
  // no-op in that path.
  const perEntryMeta = entry.source_meta && typeof entry.source_meta === "object" && !Array.isArray(entry.source_meta)
    ? entry.source_meta
    : null;
  const effectiveMeta = perEntryMeta || sourceMeta || null;

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
      source_meta: effectiveMeta,
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

// Plane X Cycle X.7 (X-P9 retrofit): per-record distilled summary
// payload. The summary is the brief-inlinable form of an
// http_record:<request_id> artifact_ref. Bodies are pull-only via
// `bob_resolve_body`. The 2KB X-P9 hard cap is structurally honored
// because every field is a short scalar (or a 200-char preview); we do
// not inline header arrays or full body bytes.
const HTTP_RECORD_BODY_PREVIEW_MAX_CHARS = 200;

function deriveContentTypeFromHeaderNames(headerNames) {
  if (!Array.isArray(headerNames)) return null;
  // We don't carry header VALUES on traffic records (header_names only),
  // so content_type cannot be reconstructed from the record. Reserve the
  // field shape for the future cycle that wires per-record headers; for
  // now content_type is null when not present on the source record.
  return null;
}

function buildHttpRecordObservedPayload(record) {
  // The body_preview / body_hash / body_size fields are conditionally
  // populated when the record carries those fields (the X.7 retrofit
  // does not change the import path's body-capture behavior; HAR/Burp
  // entries without a response body land with body fields absent).
  const payload = {
    observation_kind: "http_record_observed",
    request_id: record.request_id,
    method: record.method,
    url: record.url,
    status: record.status,
    has_auth: record.has_auth === true,
    content_type: typeof record.content_type === "string" && record.content_type.trim()
      ? record.content_type.trim()
      : deriveContentTypeFromHeaderNames(record.header_names),
  };
  if (typeof record.body_hash === "string" && record.body_hash) {
    payload.body_hash = record.body_hash;
  }
  if (Number.isFinite(record.body_size_bytes)) {
    payload.body_size_bytes = record.body_size_bytes;
  }
  if (typeof record.body_preview === "string" && record.body_preview) {
    payload.body_preview = record.body_preview.length > HTTP_RECORD_BODY_PREVIEW_MAX_CHARS
      ? `${record.body_preview.slice(0, HTTP_RECORD_BODY_PREVIEW_MAX_CHARS)}…`
      : record.body_preview;
  }
  return payload;
}

function importHttpTraffic(args, { rankAttackSurfaces = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const source = assertRequiredText(args.source, "source");
  const sourceMeta = args.source_meta == null ? null : normalizeSourceMeta(args.source_meta);
  const internalHostPolicy = blockInternalHostsRequestPolicy(domain, args, {
    allowMissingSession: true,
  });
  const internalHostContext = blockInternalHostsPolicyFields(internalHostPolicy);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;
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
      sourceMeta,
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

    // LEGACY: removed in Plane D — traffic.jsonl remains during dual-write;
    // surface-index.json (F.2) and frontier-events.jsonl carry the authoritative
    // observation truth after Plane D ships.
    const logPath = trafficJsonlPath(domain);
    appendJsonlLines(logPath, records, { maxRecords: TRAFFIC_LOG_MAX_RECORDS });
    if (rankAttackSurfaces) {
      try {
        rankAttackSurfaces(domain);
      } catch {}
    }

    // Dual-write per Pact P2: imported traffic is a surface-shaping observation
    // event; emit one observation.recorded per batch import (not per row, to
    // keep the ledger bounded).
    if (records.length > 0) {
      try {
        const hosts = Array.from(new Set(records.map((record) => record.host).filter(Boolean))).slice(0, 20);
        const methods = Array.from(new Set(records.map((record) => record.method).filter(Boolean))).sort();
        appendFrontierEvent({
          target_domain: domain,
          kind: "observation.recorded",
          payload: {
            observation_kind: "http_traffic_imported",
            source,
            records: records.length,
            duplicates: duplicateCount,
            rejected: rejected.length,
            authenticated_records: records.filter((record) => record.has_auth).length,
            hosts,
            methods,
          },
          source: { artifact: "traffic.jsonl", tool: "bob_import_http_traffic" },
        });
        scheduleMaterialization(domain);
      } catch {
        // Frontier ledger is dual-write best-effort during the deprecation window.
      }

      // Plane X Cycle X.7 (X-P9 retrofit): per-record distilled summary
      // emission. The full body lives in traffic.jsonl; the per-record
      // summary becomes the brief-inlinable form. Agents pull the body
      // via `bob_resolve_body(http_record:<request_id>)`. Each emission
      // stays under the X-P9 2KB hard cap by construction — we carry
      // method/url/status/content_type/body_hash/body_size/body_preview/
      // request_id only, no full headers, no full body bytes.
      for (const record of records) {
        try {
          appendFrontierEvent({
            target_domain: domain,
            kind: "observation.recorded",
            payload: buildHttpRecordObservedPayload(record),
            source: { artifact: "traffic.jsonl", ref: record.request_id, tool: "bob_import_http_traffic" },
          });
        } catch {
          // Per-record summary emission is best-effort; the body stays
          // in traffic.jsonl regardless so the resolver still works.
        }
      }
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
      ...internalHostContext,
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane T Cycle T.5 — JWT-as-observation-kind
//
// When an HTTP response is ingested (after headers/body normalization in
// http-scan.js), we scan three locations for JWT-shaped tokens and emit one
// `observation.recorded` frontier event per distinct token. The full token is
// never written to the event payload — only a sha256 fingerprint, a short
// snippet (truncated header + payload + signature segments), and a sanitized
// projection of standard claims. `sub` is hashed (sha256) because it may be a
// raw user identifier; custom claims are dropped entirely.
//
// Dedup: an in-memory Set keyed by `${surface_id} ${token_fingerprint}`.
// Two scans of the same token under the same surface emit once. Across surfaces
// the same token emits once per surface (intentional — pack surfacing is per
// surface, so each surface needs its own jwt_observed event).
//
// Pact: T-P4 (observation-trigger architectural pattern). T-R3 (no secret
// leakage). The test suite contains a negative assertion that scans the emitted
// event JSON for the full token and fails if it appears.

const JWT_PAYLOAD_BODY_KEY_RE = /^(access_token|id_token|refresh_token|jwt|token)$/i;
const JWT_BODY_PARSE_MAX_BYTES = 1024 * 1024; // 1 MB — per T.5 spec.
const JWT_SEGMENT_RE = /^[A-Za-z0-9_-]+$/;
const JWT_TOKEN_RE = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

const jwtObservationDedupSet = new Set();

function jwtDedupKey(surfaceId, fingerprint) {
  return `${surfaceId == null ? "" : String(surfaceId)} ${fingerprint}`;
}

function _resetJwtObservationDedup() {
  // Test-only escape hatch. Production code path never calls this.
  jwtObservationDedupSet.clear();
}

function base64UrlDecodeToString(segment) {
  if (typeof segment !== "string" || !segment || !JWT_SEGMENT_RE.test(segment)) {
    return null;
  }
  try {
    return Buffer.from(segment, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

function safeParseJson(text) {
  if (typeof text !== "string" || !text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function looksLikeJwt(value) {
  return typeof value === "string" && JWT_TOKEN_RE.test(value);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function tokenSnippet(token) {
  // First 12 chars of header + "..." + first 12 chars of payload + "..." +
  // first 6 chars of signature. The full token is never reconstructable from
  // the snippet because each segment is truncated.
  const parts = String(token).split(".");
  const head = (parts[0] || "").slice(0, 12);
  const body = (parts[1] || "").slice(0, 12);
  const sig = (parts[2] || "").slice(0, 6);
  return `${head}...${body}...${sig}`;
}

function parseJwtHeaderAndPayload(token) {
  // Split, decode header (segment 0) + payload (segment 1). Signature is
  // never decoded or returned. Returns { header, payload } or null if the
  // token isn't decodable.
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const headerJson = base64UrlDecodeToString(parts[0]);
  const payloadJson = base64UrlDecodeToString(parts[1]);
  if (!headerJson || !payloadJson) return null;
  const header = safeParseJson(headerJson);
  const payload = safeParseJson(payloadJson);
  if (header == null || typeof header !== "object" || Array.isArray(header)) return null;
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) return null;
  return { header, payload };
}

function projectJwtClaims(parsed, token) {
  const header = parsed && parsed.header ? parsed.header : {};
  const payload = parsed && parsed.payload ? parsed.payload : {};
  const headerStr = (key) => (typeof header[key] === "string" && header[key].trim()
    ? header[key].trim()
    : null);
  const payloadStr = (key) => (typeof payload[key] === "string" && payload[key].trim()
    ? payload[key].trim()
    : null);
  const payloadNum = (key) => (Number.isFinite(payload[key]) ? Number(payload[key]) : null);
  // `aud` may be a string or an array of strings; we project to a stable
  // string by joining sorted entries. Either way, the raw token never appears.
  let claimAud = null;
  if (typeof payload.aud === "string" && payload.aud.trim()) {
    claimAud = payload.aud.trim();
  } else if (Array.isArray(payload.aud)) {
    const items = payload.aud
      .filter((entry) => typeof entry === "string" && entry.trim())
      .map((entry) => entry.trim())
      .sort();
    if (items.length > 0) claimAud = items.join(",");
  }
  // `sub` MUST be hashed — it is frequently a raw user id and leaking it
  // would violate T-R3.
  const subRaw = payloadStr("sub");
  const claimSubHash = subRaw == null ? null : sha256Hex(subRaw);
  return {
    header_alg: headerStr("alg"),
    header_kid: headerStr("kid"),
    header_typ: headerStr("typ"),
    claim_iss: payloadStr("iss"),
    claim_aud: claimAud,
    claim_sub_hash: claimSubHash,
    claim_exp: payloadNum("exp"),
    claim_iat: payloadNum("iat"),
    claim_nbf: payloadNum("nbf"),
    token_fingerprint: sha256Hex(token),
    token_snippet: tokenSnippet(token),
  };
}

function headerLookupAll(headers, lowerName) {
  // Returns array of header values for lowerName. Accepts:
  //   - WHATWG Headers (has .forEach + .get / .getSetCookie)
  //   - plain object  { name: string | string[] }
  if (headers == null) return [];
  if (typeof headers.forEach === "function" && typeof headers.get === "function") {
    if (lowerName === "set-cookie" && typeof headers.getSetCookie === "function") {
      try {
        const values = headers.getSetCookie();
        if (Array.isArray(values) && values.length > 0) return values.slice();
      } catch {
        // fall through
      }
    }
    const collected = [];
    headers.forEach((value, name) => {
      if (typeof name === "string" && name.toLowerCase() === lowerName) {
        collected.push(value);
      }
    });
    return collected;
  }
  if (typeof headers === "object" && !Array.isArray(headers)) {
    const out = [];
    for (const key of Object.keys(headers)) {
      if (typeof key !== "string" || key.toLowerCase() !== lowerName) continue;
      const value = headers[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === "string") out.push(item);
        }
      } else if (typeof value === "string") {
        out.push(value);
      }
    }
    return out;
  }
  return [];
}

function detectJwtInAuthorizationHeaders(headers) {
  const detections = [];
  const values = headerLookupAll(headers, "authorization");
  for (const value of values) {
    if (typeof value !== "string") continue;
    // `Bearer ` is case-insensitive in the scheme name per RFC 7235.
    const match = value.match(/^\s*bearer\s+(\S+)\s*$/i);
    if (!match) continue;
    const token = match[1];
    if (!looksLikeJwt(token)) continue;
    detections.push({
      token,
      token_location: "authorization_header",
      cookie_name: null,
      body_path: null,
    });
  }
  return detections;
}

function detectJwtInSetCookieHeaders(headers) {
  const detections = [];
  const values = headerLookupAll(headers, "set-cookie");
  for (const value of values) {
    if (typeof value !== "string" || !value) continue;
    // Set-Cookie can carry multiple cookies in a single header value when the
    // upstream stack concatenates them with comma + space. We split cautiously:
    // split on ", " only when followed by what looks like a cookie name=.
    const cookies = value.split(/,\s+(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)/);
    for (const cookie of cookies) {
      const firstSemi = cookie.indexOf(";");
      const pair = firstSemi === -1 ? cookie : cookie.slice(0, firstSemi);
      const eqIdx = pair.indexOf("=");
      if (eqIdx <= 0) continue;
      const name = pair.slice(0, eqIdx).trim();
      const rawValue = pair.slice(eqIdx + 1).trim();
      // Strip surrounding quotes if present.
      const tokenValue = rawValue.startsWith('"') && rawValue.endsWith('"')
        ? rawValue.slice(1, -1)
        : rawValue;
      if (!looksLikeJwt(tokenValue)) continue;
      detections.push({
        token: tokenValue,
        token_location: "set_cookie",
        cookie_name: name,
        body_path: null,
      });
    }
  }
  return detections;
}

function walkBodyForJwt(node, pathStack, detections) {
  if (node == null) return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      pathStack.push(`[${i}]`);
      walkBodyForJwt(node[i], pathStack, detections);
      pathStack.pop();
    }
    return;
  }
  if (typeof node !== "object") return;
  for (const key of Object.keys(node)) {
    pathStack.push(`.${key}`);
    const value = node[key];
    if (JWT_PAYLOAD_BODY_KEY_RE.test(key) && looksLikeJwt(value)) {
      detections.push({
        token: value,
        token_location: "response_body",
        cookie_name: null,
        body_path: `$${pathStack.join("")}`,
      });
    }
    walkBodyForJwt(value, pathStack, detections);
    pathStack.pop();
  }
}

function detectJwtInResponseBody(body) {
  if (body == null) return [];
  let text;
  if (typeof body === "string") {
    text = body;
  } else if (Buffer.isBuffer(body)) {
    text = body.toString("utf8");
  } else if (typeof body === "object") {
    // Pre-parsed object — walk it directly without re-encoding.
    const detections = [];
    walkBodyForJwt(body, [], detections);
    return detections;
  } else {
    return [];
  }
  if (Buffer.byteLength(text, "utf8") > JWT_BODY_PARSE_MAX_BYTES) return [];
  const parsed = safeParseJson(text);
  if (parsed == null) return [];
  if (typeof parsed !== "object") return [];
  const detections = [];
  walkBodyForJwt(parsed, [], detections);
  return detections;
}

function detectJwts({ response_headers = null, response_body = null } = {}) {
  return [
    ...detectJwtInAuthorizationHeaders(response_headers),
    ...detectJwtInSetCookieHeaders(response_headers),
    ...detectJwtInResponseBody(response_body),
  ];
}

function recordJwtObservations({
  target_domain,
  surface_id,
  response_headers = null,
  response_body = null,
  source_ref = null,
} = {}) {
  // Best-effort: any failure is silently swallowed (frontier ledger is dual-
  // write best-effort, per the importHttpTraffic precedent). Returns the list
  // of emitted event ids so http-scan / tests can introspect.
  if (target_domain == null) return [];
  if (surface_id == null) return [];
  const detections = detectJwts({ response_headers, response_body });
  if (detections.length === 0) return [];
  const emitted = [];
  const seenInThisCall = new Set();
  for (const detection of detections) {
    const parsed = parseJwtHeaderAndPayload(detection.token);
    if (!parsed) continue;
    const claims = projectJwtClaims(parsed, detection.token);
    const dedupKey = jwtDedupKey(surface_id, claims.token_fingerprint);
    if (jwtObservationDedupSet.has(dedupKey)) continue;
    // Two detections of the same token in the same response (e.g. body has the
    // same token under both `access_token` and `token`) — emit once.
    if (seenInThisCall.has(dedupKey)) continue;
    seenInThisCall.add(dedupKey);
    jwtObservationDedupSet.add(dedupKey);
    try {
      const event = appendFrontierEvent({
        target_domain,
        kind: "observation.recorded",
        surface_id,
        payload: {
          observation_kind: "jwt_observed",
          token_location: detection.token_location,
          cookie_name: detection.cookie_name,
          body_path: detection.body_path,
          header_alg: claims.header_alg,
          header_kid: claims.header_kid,
          header_typ: claims.header_typ,
          claim_iss: claims.claim_iss,
          claim_aud: claims.claim_aud,
          claim_sub_hash: claims.claim_sub_hash,
          claim_exp: claims.claim_exp,
          claim_iat: claims.claim_iat,
          claim_nbf: claims.claim_nbf,
          token_fingerprint: claims.token_fingerprint,
          token_snippet: claims.token_snippet,
        },
        source: {
          artifact: "http-records.jsonl",
          ref: source_ref == null ? null : String(source_ref),
        },
      });
      emitted.push(event.event_id);
      try {
        scheduleMaterialization(target_domain);
      } catch {
        // Materializer scheduling is best-effort.
      }
    } catch {
      // Removing the dedup entry on failure would invite an unbounded retry
      // loop. We accept "emit-once-or-not-at-all" for this slot.
    }
  }
  return emitted;
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane T Cycle T.6 — GraphQL / OpenAPI schema observation
//
// When an HTTP response is ingested we additionally scan for two schema
// shapes carried in the JSON body:
//
//   - GraphQL introspection: any response whose URL pathname matches
//     `/graphql`, `/api/graphql`, or `/__graphql`, OR any JSON body with a
//     top-level `data.__schema.types[]` array (canonical introspection
//     shape returned by `__schema` queries).
//   - OpenAPI 3.x / Swagger 2.0: JSON body with `openapi: "3.x.x"` or
//     `swagger: "2.0"` AND a `paths` object containing at least one path.
//
// Bodies larger than 1 MB are skipped (the size cap matches the JWT scan).
// Each detection emits one `observation.recorded` frontier event whose
// payload carries ONLY a sha256 fingerprint of the canonical schema JSON,
// plus a small set of summary fields (counts, root type names, security
// scheme names). The full schema document MUST NOT appear anywhere in the
// emitted event. The test suite contains a negative regression that scans
// the emitted JSON for the `types: [...]` array contents and fails if any
// type's field/value bytes leak.
//
// Dedup: in-memory Set keyed by `${surface_id} ${schema_fingerprint}`. The
// same schema observed twice on the same surface emits one event; the same
// schema on a different surface emits per surface (parallel to T.5).
//
// Pact: T-P4 (observation-trigger architectural pattern). T-R3 (no secret
// leakage, including no full schema body).

const SCHEMA_BODY_PARSE_MAX_BYTES = 1024 * 1024; // 1 MB — per T.6 spec.
const GRAPHQL_PATH_RE = /^(?:\/api)?\/__?graphql\/?$|^\/graphql\/?$|^\/api\/graphql\/?$/i;
const AUTH_DIRECTIVE_RE = /auth|jwt|require_login/i;
const OPENAPI_VERSION_RE = /^3\.\d+(?:\.\d+)?$/;
const SWAGGER_VERSION_RE = /^2\.0$/;

const schemaObservationDedupSet = new Set();

function schemaDedupKey(surfaceId, fingerprint) {
  return `${surfaceId == null ? "" : String(surfaceId)} ${fingerprint}`;
}

function _resetSchemaObservationDedup() {
  // Test-only escape hatch. Production code path never calls this.
  schemaObservationDedupSet.clear();
}

function canonicalJsonStringify(value) {
  // Deterministic stringification with sorted object keys. Two payloads with
  // the same logical content produce the same fingerprint regardless of key
  // ordering in transit.
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJsonStringify(entry)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJsonStringify(value[key])}`)
    .join(",")}}`;
}

function pathnameFromUrl(maybeUrl) {
  if (typeof maybeUrl !== "string" || !maybeUrl) return null;
  const parsed = safeUrlObject(maybeUrl);
  return parsed ? parsed.pathname : null;
}

function bodyAsText(body) {
  if (body == null) return null;
  if (typeof body === "string") return body;
  if (Buffer.isBuffer(body)) return body.toString("utf8");
  if (typeof body === "object") {
    try {
      return JSON.stringify(body);
    } catch {
      return null;
    }
  }
  return null;
}

function parseSchemaBodyJson(body) {
  if (body == null) return null;
  if (typeof body === "object" && !Buffer.isBuffer(body)) {
    return body;
  }
  const text = bodyAsText(body);
  if (text == null) return null;
  if (Buffer.byteLength(text, "utf8") > SCHEMA_BODY_PARSE_MAX_BYTES) return null;
  const parsed = safeParseJson(text);
  if (parsed == null) return null;
  if (typeof parsed !== "object" || Array.isArray(parsed)) return null;
  return parsed;
}

function looksLikeGraphqlPath(pathname) {
  if (typeof pathname !== "string" || !pathname) return false;
  return GRAPHQL_PATH_RE.test(pathname);
}

function extractGraphqlSchema(parsed) {
  // Canonical introspection shape: { data: { __schema: { types: [...] } } }.
  // We require types to be an array, not just present, so we don't fire on
  // unrelated `data.__schema` keys.
  if (parsed == null || typeof parsed !== "object") return null;
  const data = parsed.data;
  if (data == null || typeof data !== "object" || Array.isArray(data)) return null;
  const schema = data.__schema;
  if (schema == null || typeof schema !== "object" || Array.isArray(schema)) return null;
  if (!Array.isArray(schema.types)) return null;
  return schema;
}

function rootTypeName(schema, key) {
  const entry = schema && typeof schema === "object" ? schema[key] : null;
  if (entry && typeof entry === "object" && typeof entry.name === "string" && entry.name.trim()) {
    return entry.name.trim();
  }
  return null;
}

function schemaHasAuthDirective(schema) {
  // Look for any directive name or any type/field directive matching
  // /auth|jwt|require_login/i. We never copy the directive arguments — only
  // a boolean flag escapes into the payload.
  if (schema == null || typeof schema !== "object") return false;
  const directives = Array.isArray(schema.directives) ? schema.directives : [];
  for (const directive of directives) {
    if (directive && typeof directive === "object"
      && typeof directive.name === "string"
      && AUTH_DIRECTIVE_RE.test(directive.name)) {
      return true;
    }
  }
  const types = Array.isArray(schema.types) ? schema.types : [];
  for (const type of types) {
    if (type == null || typeof type !== "object") continue;
    if (Array.isArray(type.appliedDirectives)) {
      for (const applied of type.appliedDirectives) {
        if (applied && typeof applied === "object"
          && typeof applied.name === "string"
          && AUTH_DIRECTIVE_RE.test(applied.name)) {
          return true;
        }
      }
    }
    const fields = Array.isArray(type.fields) ? type.fields : [];
    for (const field of fields) {
      if (field == null || typeof field !== "object") continue;
      if (!Array.isArray(field.appliedDirectives)) continue;
      for (const applied of field.appliedDirectives) {
        if (applied && typeof applied === "object"
          && typeof applied.name === "string"
          && AUTH_DIRECTIVE_RE.test(applied.name)) {
          return true;
        }
      }
    }
  }
  return false;
}

function detectIntrospectionDisabled(schema) {
  // Heuristic: introspection responded (we have a __schema object) but the
  // types array is empty or sparse enough that downstream tools will need
  // schema-reconstruction. Sparse threshold = fewer than 4 entries (the four
  // built-in scalars plus root types normally land well above this).
  if (schema == null || typeof schema !== "object") return false;
  const types = Array.isArray(schema.types) ? schema.types : [];
  return types.length < 4;
}

function buildGraphqlObservationPayload({ schema, requestUrl, pathname }) {
  // schema_fingerprint is the sha256 of the canonical JSON of the __schema
  // sub-document. We deliberately fingerprint the schema only — not the
  // ambient response — so the same schema served twice through different
  // wrappers fingerprints identically.
  const canonical = canonicalJsonStringify(schema);
  return {
    observation_kind: "graphql_schema_observed",
    schema_url: requestUrl,
    endpoint_path: pathname,
    type_count: Array.isArray(schema.types) ? schema.types.length : 0,
    query_root: rootTypeName(schema, "queryType"),
    mutation_root: rootTypeName(schema, "mutationType"),
    subscription_root: rootTypeName(schema, "subscriptionType"),
    has_auth_directive: schemaHasAuthDirective(schema),
    has_introspection_disabled: detectIntrospectionDisabled(schema),
    schema_fingerprint: sha256Hex(canonical),
  };
}

function extractOpenApiSpec(parsed) {
  // Returns { kind: "openapi" | "swagger", version: string, document } when
  // the parsed JSON satisfies the OpenAPI / Swagger 2.0 shape AND carries a
  // paths object with >= 1 entry. Returns null otherwise.
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const paths = parsed.paths;
  if (paths == null || typeof paths !== "object" || Array.isArray(paths)) return null;
  const pathKeys = Object.keys(paths).filter((key) => key.startsWith("/"));
  if (pathKeys.length === 0) return null;
  if (typeof parsed.openapi === "string" && OPENAPI_VERSION_RE.test(parsed.openapi)) {
    return { kind: "openapi", version: parsed.openapi, document: parsed };
  }
  if (typeof parsed.swagger === "string" && SWAGGER_VERSION_RE.test(parsed.swagger)) {
    return { kind: "swagger", version: parsed.swagger, document: parsed };
  }
  return null;
}

const OPENAPI_METHODS = ["get", "put", "post", "delete", "patch", "options", "head", "trace"];

function summarizeOpenApiPaths(document) {
  const paths = document && typeof document.paths === "object" && !Array.isArray(document.paths)
    ? document.paths
    : {};
  const pathKeys = Object.keys(paths).filter((key) => key.startsWith("/"));
  let methods = 0;
  for (const key of pathKeys) {
    const pathItem = paths[key];
    if (pathItem == null || typeof pathItem !== "object" || Array.isArray(pathItem)) continue;
    for (const method of OPENAPI_METHODS) {
      if (pathItem[method] && typeof pathItem[method] === "object") methods += 1;
    }
  }
  return { endpoint_count: pathKeys.length, methods_count: methods };
}

function collectSecuritySchemeNames(document, kind) {
  // OpenAPI 3.x: components.securitySchemes. Swagger 2.0: securityDefinitions.
  // We return only the scheme NAMES (the keys), never the contents — scheme
  // values can contain `flows.*.tokenUrl` and `name` (header name) fields
  // that are safe enough on their own but we intentionally don't carry them.
  if (document == null || typeof document !== "object") {
    return { names: [], types: [] };
  }
  let bucket = null;
  if (kind === "openapi"
    && document.components
    && typeof document.components === "object"
    && !Array.isArray(document.components)
    && document.components.securitySchemes
    && typeof document.components.securitySchemes === "object"
    && !Array.isArray(document.components.securitySchemes)) {
    bucket = document.components.securitySchemes;
  } else if (kind === "swagger"
    && document.securityDefinitions
    && typeof document.securityDefinitions === "object"
    && !Array.isArray(document.securityDefinitions)) {
    bucket = document.securityDefinitions;
  }
  if (bucket == null) return { names: [], types: [] };
  const names = [];
  const types = [];
  for (const key of Object.keys(bucket).sort()) {
    if (typeof key !== "string" || !key.trim()) continue;
    names.push(key);
    const entry = bucket[key];
    if (entry && typeof entry === "object" && typeof entry.type === "string") {
      types.push(entry.type.toLowerCase());
    }
  }
  return { names, types };
}

function buildOpenApiObservationPayload({ spec, requestUrl }) {
  const { kind, version, document } = spec;
  const { endpoint_count, methods_count } = summarizeOpenApiPaths(document);
  const { names: securityNames, types: securityTypes } = collectSecuritySchemeNames(document, kind);
  const canonical = canonicalJsonStringify(document);
  return {
    observation_kind: "openapi_schema_observed",
    schema_url: requestUrl,
    spec_version: `${kind} ${version}`,
    endpoint_count,
    methods_count,
    security_schemes: securityNames,
    has_oauth: securityTypes.includes("oauth2"),
    has_apikey: securityTypes.includes("apikey"),
    spec_fingerprint: sha256Hex(canonical),
  };
}

function detectSchemas({ request_url = null, response_body = null } = {}) {
  // Returns a list of "detection" objects: { kind, fingerprint, payload }.
  // Caller is responsible for dedup + emission.
  const text = bodyAsText(response_body);
  if (text == null) return [];
  if (Buffer.byteLength(text, "utf8") > SCHEMA_BODY_PARSE_MAX_BYTES) return [];
  const parsed = safeParseJson(text);
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const detections = [];
  const pathname = pathnameFromUrl(request_url);
  const isGraphqlPath = looksLikeGraphqlPath(pathname);
  const schema = extractGraphqlSchema(parsed);
  if (schema && (isGraphqlPath || Array.isArray(schema.types))) {
    const payload = buildGraphqlObservationPayload({ schema, requestUrl: request_url, pathname });
    detections.push({
      observation_kind: "graphql_schema_observed",
      fingerprint: payload.schema_fingerprint,
      payload,
    });
  }
  const spec = extractOpenApiSpec(parsed);
  if (spec) {
    const payload = buildOpenApiObservationPayload({ spec, requestUrl: request_url });
    detections.push({
      observation_kind: "openapi_schema_observed",
      fingerprint: payload.spec_fingerprint,
      payload,
    });
  }
  return detections;
}

function recordSchemaObservations({
  target_domain,
  surface_id,
  request_url = null,
  response_body = null,
  source_ref = null,
} = {}) {
  // Best-effort, mirrors recordJwtObservations. Returns the list of emitted
  // event ids so http-scan / tests can introspect.
  if (target_domain == null) return [];
  if (surface_id == null) return [];
  const detections = detectSchemas({ request_url, response_body });
  if (detections.length === 0) return [];
  const emitted = [];
  const seenInThisCall = new Set();
  for (const detection of detections) {
    const dedupKey = schemaDedupKey(surface_id, detection.fingerprint);
    if (schemaObservationDedupSet.has(dedupKey)) continue;
    if (seenInThisCall.has(dedupKey)) continue;
    seenInThisCall.add(dedupKey);
    schemaObservationDedupSet.add(dedupKey);
    try {
      const event = appendFrontierEvent({
        target_domain,
        kind: "observation.recorded",
        surface_id,
        payload: detection.payload,
        source: {
          artifact: "http-records.jsonl",
          ref: source_ref == null ? null : String(source_ref),
        },
      });
      emitted.push(event.event_id);
      try {
        scheduleMaterialization(target_domain);
      } catch {
        // Materializer scheduling is best-effort.
      }
    } catch {
      // Emit-once-or-not-at-all (mirrors the JWT path).
    }
  }
  return emitted;
}

function readHttpAudit(args, { readAttackSurfaceStrict = null } = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const limit = normalizeHttpAuditSummaryLimit(args.limit);
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
    summary: summarizeHttpAuditRecords(records, { surface, limit, targetDomain: domain }),
    circuit_breaker_summary: buildCircuitBreakerSummary(records, { surface }),
  }, null, 2);
}

module.exports = {
  _resetJwtObservationDedup,
  _resetSchemaObservationDedup,
  appendHttpAuditRecord,
  buildCircuitBreakerSummary,
  buildHttpRecordObservedPayload,
  compactHttpAuditRecord,
  compactTrafficRecord,
  deriveTrafficRequestId,
  detectJwts,
  detectSchemas,
  headerNamesFromInput,
  importHttpTraffic,
  isCircuitBreakerFailure,
  isNetworkUnreachableRecord,
  normalizeHttpAuditRecord,
  normalizeImportedTrafficEntry,
  normalizeTrafficImportEntries,
  normalizeHttpAuditSummaryLimit,
  normalizeTrafficRecord,
  parseJwtHeaderAndPayload,
  queryKeysFromUrl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  recordJwtObservations,
  recordSchemaObservations,
  summarizeHttpAuditRecords,
  summarizeGeofenceWarnings,
  summarizeTrafficRecords,
  trafficRecordKey,
  HTTP_RECORD_BODY_PREVIEW_MAX_CHARS,
};

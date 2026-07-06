"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  assertSafeDomain,
  sessionDir,
  sessionsRoot,
} = require("./paths.js");
const {
  readJsonFile,
  withSessionLock,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  isFirstPartyHost,
  safeUrlObject,
} = require("./url-surface.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

const authProfiles = new Map();

function authCacheKey(domain, profileName) {
  const authPath = resolveAuthJsonPath(domain);
  return `${authPath || domain}:${profileName}`;
}

function buildHeaderProfile(headers, cookies, storage) {
  const profile = {};
  Object.assign(profile, headers);
  if (Object.keys(cookies).length) {
    profile["Cookie"] = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
    // STRUCTURED cookie jar — Bob-LOCAL metadata (in PROFILE_METADATA_KEYS, never emitted as a header).
    // A consumer that re-issues cookies individually (the mass-read producer's browser transport) uses
    // this verbatim so a cookie VALUE containing ';' stays ONE cookie and can never be re-split into a
    // FORGED extra cookie out of the flattened "Cookie" header. A copy of the original {name: value} map.
    profile["cookie_jar"] = { ...cookies };
  }
  for (const [k, v] of Object.entries(storage)) {
    if (typeof v === "string" && v.startsWith("eyJ") && !profile["Authorization"]) {
      profile["Authorization"] = `Bearer ${v}`;
    }
  }
  return profile;
}

// The canonical set of profile keys that are Bob-LOCAL metadata, NEVER HTTP request
// headers: credentials + browser storage + the PR-PROV synthetic-identity provenance
// flags and synthetic mailbox + expiry hints. SINGLE source of truth for every consumer
// that reads a raw profile from resolveAuthProfile and must not emit/surface these: the
// outbound-header merge (applyAuthProfileHeaders, used by bob_http_scan), the
// bob_list_auth_profiles summary (summarizeAuthProfile), and the IDOR producer's outbound
// strip (offensive-idor-producer.js imports this). One set means a future provenance key
// cannot leak through a reader that forgot to add it.
const PROFILE_METADATA_KEYS = Object.freeze(new Set([
  "credentials", "local_storage", "session_storage",
  "synthetic", "email_origin", "provisioned_via", "email",
  "expires_at", "expiresAt", "expiry", "expires",
  "cookie_jar",
]));

// Build an outbound header map from a base header set plus a resolved auth profile's HEADER
// fields, skipping the Bob-local metadata above so the synthetic mailbox + provenance
// fingerprint (and credentials/storage) never reach the TARGET as request headers.
// resolveAuthProfile returns the RAW profile, so this is the required chokepoint for any
// outbound consumer. PURE: returns a NEW object and never mutates the caller's `headers`.
// A caller-supplied key is preserved by PRESENCE (so an intentional empty-string header is
// NOT overwritten from the profile), not by truthiness.
function applyAuthProfileHeaders(headers, profile) {
  const merged = headers && typeof headers === "object" ? { ...headers } : {};
  if (!profile || typeof profile !== "object") return merged;
  for (const [k, v] of Object.entries(profile)) {
    if (PROFILE_METADATA_KEYS.has(k)) continue;
    if (!(k in merged)) merged[k] = v;
  }
  return merged;
}

function resolveAuthJsonPath(targetDomain, { allowLegacyFallback = false } = {}) {
  // When no target_domain is supplied, `allowLegacyFallback` enables a
  // no-target discovery path that picks the most-recently-modified session
  // under the canonical `~/hacker-bob-sessions/` root. This is unrelated to the
  // retired legacy session root; it never reads `~/bounty-agent-sessions/`.
  const sessionsDir = sessionsRoot();
  if (targetDomain) {
    assertSafeDomain(targetDomain);
    return path.join(sessionDir(targetDomain), "auth.json");
  }
  if (!allowLegacyFallback) {
    return null;
  }
  try {
    const entries = fs.readdirSync(sessionsDir)
      .map((d) => {
        const full = path.join(sessionsDir, d);
        try {
          const stat = fs.statSync(full);
          return stat.isDirectory() ? { name: d, mtimeMs: stat.mtimeMs } : null;
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => b.mtimeMs - a.mtimeMs);
    if (entries.length > 0) return path.join(sessionsDir, entries[0].name, "auth.json");
  } catch {}
  return null;
}

function readAuthJson(filePath) {
  try {
    return readJsonFile(filePath, { label: "auth.json" });
  } catch {
    return null;
  }
}

function migrateAuthJson(existing) {
  if (!existing || typeof existing !== "object") return { version: 2, profiles: {} };
  if (existing.version === 2) return existing;
  return { version: 2, profiles: { attacker: existing } };
}

function writeAuthFile(authPath, content) {
  fs.mkdirSync(path.dirname(authPath), { recursive: true });
  const tempPath = path.join(
    path.dirname(authPath),
    `.${path.basename(authPath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );

  let fd = null;
  try {
    fd = fs.openSync(tempPath, "wx", 0o600);
    fs.writeFileSync(fd, content, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(tempPath, authPath);
    fs.chmodSync(authPath, 0o600);
  } catch (error) {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
    try { fs.rmSync(tempPath, { force: true }); } catch {}
    throw error;
  }
}

function persistAuthProfiles(domain, profilesByName) {
  const authPath = resolveAuthJsonPath(domain);
  const result = withSessionLock(domain, () => {
    const existing = readAuthJson(authPath);
    const doc = migrateAuthJson(existing);
    for (const [profileName, profile] of Object.entries(profilesByName)) {
      doc.profiles[profileName] = { ...profile };
    }
    writeAuthFile(authPath, JSON.stringify(doc, null, 2) + "\n");

    const saved = readAuthJson(authPath);
    if (!saved || saved.version !== 2 || !saved.profiles) {
      throw new Error("persisted auth profile verification failed");
    }

    return {
      authPath,
      saved,
      hasAttacker: !!saved.profiles.attacker,
      hasVictim: !!saved.profiles.victim,
    };
  });

  for (const [profileName, profile] of Object.entries(profilesByName)) {
    authProfiles.set(authCacheKey(domain, profileName), profile);
  }

  return result;
}

function authStore(args, options = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  assertSafeDomain(domain);
  const profileName = assertNonEmptyString(args.profile_name, "profile_name");
  const headers = args.headers || {};
  const cookies = args.cookies || {};
  const storage = args.local_storage || {};
  const credentials = args.credentials || null;

  const profile = buildHeaderProfile(headers, cookies, storage);
  if (credentials) profile.credentials = credentials;

  // PR-PROV: stamp the synthetic-identity provenance the IDOR signed-row producer
  // (bob_http_idor_confirm, mint condition #18) requires before it will sign. This is
  // accepted ONLY from the second positional argument, which the MCP tool dispatcher
  // never supplies — dispatch.js and tool-registry.js both invoke tool.handler(args)
  // with ONE argument, the identical seam the producer itself uses (idorConfirm(args),
  // "dispatcher always calls with NO second argument"). So the public bob_auth_store
  // tool (operator-supplied, possibly a real victim's pasted cookie/JWT) can NEVER
  // stamp provenance; only the in-process bob_auto_signup success path — downstream of
  // assertSignupEmailAllowed (tempMailboxIsKnown + operator-denylist) — passes it. Each
  // field is copied only on an exact match to the frozen REQUIRED_PROVENANCE contract
  // (offensive-idor-producer.js:140-144), so even the trusted caller cannot persist an
  // arbitrary provenance value. PR-PROV adds NO key isolation: the same-UID in-process
  // forge boundary (BEDROCK) remains open until the deferred offensive-SANDBOX PR.
  const provenance = options && typeof options === "object" && options.provenance
    && typeof options.provenance === "object"
    ? options.provenance
    : null;
  if (provenance) {
    if (provenance.synthetic === true) profile.synthetic = true;
    if (provenance.email_origin === "temp_email") profile.email_origin = "temp_email";
    if (provenance.provisioned_via === "bob_auto_signup") profile.provisioned_via = "bob_auto_signup";
    if (typeof provenance.email === "string" && provenance.email) profile.email = provenance.email;
  }

  const authPath = resolveAuthJsonPath(domain);
  let persisted = null;
  if (authPath) {
    try {
      persisted = persistAuthProfiles(domain, { [profileName]: profile });
    } catch (error) {
      throw new ToolError(ERROR_CODES.INTERNAL_ERROR, `failed to persist auth profile: ${error.message || String(error)}`, {
        success: false,
        profile_name: profileName,
        auth_path: authPath,
      });
    }
  }

  return JSON.stringify({
    success: true,
    profile_name: profileName,
    keys: Object.keys(profile).filter((k) => k !== "credentials"),
    persisted: !!authPath,
    has_attacker: !!persisted?.hasAttacker,
    has_victim: !!persisted?.hasVictim,
  });
}

function candidateAuthDomains(targetDomain, urlValue) {
  const normalizedTarget = targetDomain
    ? String(targetDomain).toLowerCase().replace(/\.+$/, "")
    : null;
  const candidates = [];
  const seen = new Set();
  const add = (domain) => {
    const value = String(domain || "").toLowerCase().replace(/\.+$/, "");
    if (!value || seen.has(value)) return;
    seen.add(value);
    candidates.push(value);
  };

  const parsed = safeUrlObject(urlValue);
  const urlHost = parsed ? parsed.hostname.toLowerCase().replace(/\.+$/, "") : null;

  if (normalizedTarget && (!urlHost || isFirstPartyHost(urlHost, normalizedTarget))) {
    add(normalizedTarget);
  }

  return candidates;
}

function resolveAuthProfile(authProfile, urlValue, targetDomain) {
  const profileName = assertNonEmptyString(authProfile, "auth_profile");
  const domains = candidateAuthDomains(targetDomain, urlValue);

  for (const domain of domains) {
    const cacheKey = authCacheKey(domain, profileName);
    if (authProfiles.has(cacheKey)) {
      return authProfiles.get(cacheKey);
    }
  }

  for (const domain of domains) {
    const authPath = resolveAuthJsonPath(domain);
    const doc = authPath ? readAuthJson(authPath) : null;
    if (doc && doc.version === 2 && doc.profiles && doc.profiles[profileName]) {
      authProfiles.set(authCacheKey(domain, profileName), doc.profiles[profileName]);
      return doc.profiles[profileName];
    }
    if (doc && !doc.version && ["attacker", "default", "legacy"].includes(profileName)) {
      authProfiles.set(authCacheKey(domain, profileName), doc);
      return doc;
    }
  }

  return null;
}

function parseCookieNames(cookieHeader) {
  if (typeof cookieHeader !== "string") return [];
  return cookieHeader
    .split(";")
    .map((part) => part.split("=", 1)[0].trim())
    .filter(Boolean)
    .sort();
}

function profileExpiryHint(profile, mtimeMs) {
  const expiryCandidate = profile.expires_at || profile.expiresAt || profile.expiry || profile.expires;
  let expiresAt = null;
  try {
    if (expiryCandidate) {
      const parsed = new Date(expiryCandidate);
      if (!Number.isNaN(parsed.getTime())) {
        expiresAt = parsed.toISOString();
      }
    }
  } catch {}

  const staleAfterMs = 7 * 24 * 60 * 60 * 1000;
  const ageMs = Number.isFinite(mtimeMs) ? Date.now() - mtimeMs : null;

  return {
    expires_at: expiresAt,
    is_expired: expiresAt == null ? null : Date.parse(expiresAt) <= Date.now(),
    last_updated: Number.isFinite(mtimeMs) ? new Date(mtimeMs).toISOString() : null,
    stale_after_days: 7,
    is_stale: ageMs == null ? null : ageMs > staleAfterMs,
  };
}

// bob_list_auth_profiles must not surface the Bob-local metadata keys (credentials/
// storage + the PR-PROV provenance flags + synthetic mailbox) as bogus `header_keys` or
// leak the mailbox into the summary JSON. Uses the canonical PROFILE_METADATA_KEYS so it
// can never drift from the outbound-header merge + the producer strip. The producer reads
// the RAW profile, not this summary, so this is operator-visibility hygiene only.
// A NON-SECRET, non-reversible fingerprint of a profile's OUTBOUND auth material
// (the header/cookie/credential/storage VALUES that actually reach the target),
// mirroring the egress-identity-hash pattern. Two profile names bound to the same
// session material produce the same fingerprint, so a completion gate can require
// >=2 DISTINCT principals for an auth-differential sweep — a 2-name/1-token sweep
// (distinct names, same principal, zero real cross-tenant test) can no longer be
// counted as executed cross-tenant coverage. Returns null when a profile carries
// no outbound auth material (an unauthenticated principal).
// Extract a STABLE identity (iss+sub) from a Bearer JWT so the SAME account presented
// across two sessions (different token strings) fingerprints identically — distinctness
// then means distinct ACCOUNT identity, not distinct per-session credential material, so
// one tenant re-authenticated twice cannot forge distinct_principal_count>=2.
function jwtIdentityClaims(profile) {
  try {
    const authHeader = typeof profile.Authorization === "string" ? profile.Authorization
      : (typeof profile.authorization === "string" ? profile.authorization : "");
    const m = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(authHeader.trim());
    if (!m) return null;
    const json = Buffer.from(m[2].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const claims = JSON.parse(json);
    const sub = claims && claims.sub != null ? String(claims.sub) : "";
    if (!sub) return null;
    return { iss: claims && claims.iss != null ? String(claims.iss) : "", sub };
  } catch {
    return null;
  }
}

function principalFingerprint(profile) {
  const normalizedProfile = profile && typeof profile === "object" ? profile : {};
  // Prefer a stable identity claim over the raw credential blob when available.
  const identity = jwtIdentityClaims(normalizedProfile);
  if (identity) return hashCanonicalJson({ __principal_identity: identity }).slice(0, 32);
  const material = {};
  for (const key of Object.keys(normalizedProfile).filter((k) => !PROFILE_METADATA_KEYS.has(k)).sort()) {
    material[key] = normalizedProfile[key];
  }
  if (normalizedProfile.credentials && typeof normalizedProfile.credentials === "object") {
    material.__credentials = normalizedProfile.credentials;
  }
  if (normalizedProfile.local_storage && typeof normalizedProfile.local_storage === "object") {
    material.__local_storage = normalizedProfile.local_storage;
  }
  if (Object.keys(material).length === 0) return null;
  return hashCanonicalJson(material).slice(0, 32);
}

function summarizeAuthProfile(name, profile, fileStats) {
  const normalizedProfile = profile && typeof profile === "object" ? profile : {};
  const headerKeys = Object.keys(normalizedProfile)
    .filter((key) => !PROFILE_METADATA_KEYS.has(key))
    .sort();
  const credentials = normalizedProfile.credentials && typeof normalizedProfile.credentials === "object"
    ? normalizedProfile.credentials
    : null;

  return {
    profile_name: name,
    header_keys: headerKeys,
    cookie_names: parseCookieNames(normalizedProfile.Cookie),
    local_storage_keys: normalizedProfile.local_storage && typeof normalizedProfile.local_storage === "object"
      ? Object.keys(normalizedProfile.local_storage).sort()
      : [],
    has_credentials: !!credentials,
    credential_fields: credentials ? Object.keys(credentials).sort() : [],
    principal_fingerprint: principalFingerprint(normalizedProfile),
    expiry: profileExpiryHint(normalizedProfile, fileStats ? fileStats.mtimeMs : null),
  };
}

function listAuthProfiles(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  assertSafeDomain(domain);
  const profilesByName = new Map();
  for (const candidateDomain of candidateAuthDomains(domain, `https://${domain}/`)) {
    const authPath = resolveAuthJsonPath(candidateDomain);
    let doc = null;
    let stats = null;
    try {
      stats = fs.statSync(authPath);
      doc = readAuthJson(authPath);
    } catch {
      doc = null;
    }

    const migrated = migrateAuthJson(doc);
    for (const [name, profile] of Object.entries(migrated.profiles || {})) {
      if (profilesByName.has(name) || !profile || typeof profile !== "object") continue;
      profilesByName.set(name, summarizeAuthProfile(name, profile, stats));
    }
  }

  const profiles = Array.from(profilesByName.values());

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    profiles,
    has_attacker: profiles.some((profile) => profile.profile_name === "attacker"),
    has_victim: profiles.some((profile) => profile.profile_name === "victim"),
  });
}

// The outbound SESSION-CREDENTIAL header names (lowercased) that mark a profile as carrying
// usable authentication material. buildHeaderProfile flattens a stored cookie jar into a
// "Cookie" header and a stored JWT into "Authorization: Bearer …", so these two are the
// canonical signal that a profile authenticates a request. This is a POSITIVE allowlist — the
// inverse of PROFILE_METADATA_KEYS — so hasUsableAuthProfile never treats an unrecognized key
// as a credential (see below).
const CREDENTIAL_HEADER_NAMES = Object.freeze(new Set(["authorization", "cookie"]));

// True iff auth.json carries at least one stored profile (any name) for the session domain
// or a candidate auth domain whose body holds usable credential material. Lets advanceSession
// derive auth_status from the PRESENCE of usable credentials without coupling the session
// lifecycle to a specific profile name.
//
// NAME-AGNOSTIC BY DESIGN (Codex PR#138 review): a profile named `victim`, `admin`, or `idor_target`
// — stored to replay captured credentials for access-control / IDOR testing — also satisfies this.
// That is intentional: the operator plan advances auth_status when an attacker OR victim profile is
// persisted, and `auth_status` is an advisory session MILESTONE meaning "this session holds at least
// one usable credential profile (any principal)", NOT a claim that a specific principal authenticated.
// It grants no capability (a stale/unintended credential 401s on use), so the name-agnostic read is
// the SAFE simplification; coupling the milestone to caller-chosen profile names would be fragile
// (names are free-form: attacker/victim/admin/tenant_b/...) for no security gain.
function hasUsableAuthProfile(domain) {
  assertSafeDomain(domain);
  for (const candidateDomain of candidateAuthDomains(domain, `https://${domain}/`)) {
    let doc = null;
    try { doc = readAuthJson(resolveAuthJsonPath(candidateDomain)); } catch { doc = null; }
    const migrated = migrateAuthJson(doc);
    for (const profile of Object.values(migrated.profiles || {})) {
      // POSITIVE-INCLUSION: a profile is "usable" only when it carries an outbound session
      // credential (Authorization or Cookie) with a non-empty string value. An ALLOWLIST — not
      // "any key not in PROFILE_METADATA_KEYS" — so a future profile field added for telemetry/
      // annotation can never SILENTLY promote a session to "authenticated" (the exclusion-list
      // form would, and the carry-forward rule never auto-downgrades, so one false upgrade would
      // stick for the session lifetime). An empty or metadata-only profile (bob_auth_store called
      // with just a profile_name) has no credential header → not authenticated. A profile whose
      // ONLY credential is a bespoke header (e.g. X-Api-Key) also reads as not-yet-authenticated;
      // that false-negative is the SAFE direction for a trust signal (the session stays "pending"
      // and auth tasks still run, rather than over-claiming credential provenance).
      if (profile && typeof profile === "object"
        && Object.entries(profile).some(([key, value]) =>
          CREDENTIAL_HEADER_NAMES.has(key.toLowerCase())
          && typeof value === "string" && value.trim() !== "")) {
        return true;
      }
    }
  }
  return false;
}

module.exports = {
  applyAuthProfileHeaders,
  authStore,
  buildHeaderProfile,
  candidateAuthDomains,
  hasUsableAuthProfile,
  listAuthProfiles,
  migrateAuthJson,
  PROFILE_METADATA_KEYS,
  readAuthJson,
  resolveAuthJsonPath,
  resolveAuthProfile,
  writeAuthFile,
};

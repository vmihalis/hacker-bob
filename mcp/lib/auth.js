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
  }
  for (const [k, v] of Object.entries(storage)) {
    if (typeof v === "string" && v.startsWith("eyJ") && !profile["Authorization"]) {
      profile["Authorization"] = `Bearer ${v}`;
    }
  }
  return profile;
}

function resolveAuthJsonPath(targetDomain, { allowLegacyFallback = false } = {}) {
  // Cycle P.2: scan the canonical `~/hacker-bob-sessions/` root for the
  // legacy-fallback discovery path. Sessions copied from
  // `~/bounty-agent-sessions/` by the migration shim land here.
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

// Keys excluded from the bob_list_auth_profiles `header_keys` summary: the existing
// non-header metadata (credentials/storage) PLUS the PR-PROV synthetic-identity
// provenance flags + synthetic mailbox that bob_auto_signup stamps. Mirrors the
// producer's outbound-strip set (offensive-idor-producer.js PROFILE_METADATA_KEYS,
// :154-158) — keep in sync. Without this, a signup-stamped profile would surface
// synthetic/email_origin/provisioned_via as bogus "header_keys" and leak the synthetic
// mailbox into the summary JSON. The producer reads the RAW profile, not this summary,
// so excluding them here is operator-visibility hygiene only, never a gate change.
const SUMMARY_EXCLUDED_KEYS = new Set([
  "credentials", "local_storage", "session_storage",
  "synthetic", "email_origin", "provisioned_via", "email",
]);

function summarizeAuthProfile(name, profile, fileStats) {
  const normalizedProfile = profile && typeof profile === "object" ? profile : {};
  const headerKeys = Object.keys(normalizedProfile)
    .filter((key) => !SUMMARY_EXCLUDED_KEYS.has(key))
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

module.exports = {
  authStore,
  buildHeaderProfile,
  candidateAuthDomains,
  listAuthProfiles,
  migrateAuthJson,
  readAuthJson,
  resolveAuthJsonPath,
  resolveAuthProfile,
  writeAuthFile,
};

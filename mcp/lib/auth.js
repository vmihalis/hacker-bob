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
} = require("./paths.js");
const {
  writeFileAtomic,
} = require("./storage.js");

const authProfiles = new Map();

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

function resolveAuthJsonPath(targetDomain) {
  const sessionsDir = path.join(os.homedir(), "bounty-agent-sessions");
  if (targetDomain) {
    const targetDir = sessionDir(targetDomain);
    if (fs.existsSync(targetDir)) return path.join(targetDir, "auth.json");
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
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function migrateAuthJson(existing) {
  if (!existing || typeof existing !== "object") return { version: 2, profiles: {} };
  if (existing.version === 2) return existing;
  return { version: 2, profiles: { attacker: existing } };
}

function authStore(args) {
  const domain = args.target_domain == null
    ? null
    : assertNonEmptyString(args.target_domain, "target_domain");
  if (domain) assertSafeDomain(domain);
  const role = args.role;
  const headers = args.headers || {};
  const cookies = args.cookies || {};
  const storage = args.local_storage || {};
  const credentials = args.credentials || null;

  const profile = buildHeaderProfile(headers, cookies, storage);
  if (credentials) profile.credentials = credentials;

  const cacheKey = domain ? `${domain}:${role}` : role;
  authProfiles.set(cacheKey, profile);

  const authPath = resolveAuthJsonPath(domain);
  if (authPath) {
    try {
      const existing = readAuthJson(authPath);
      const doc = migrateAuthJson(existing);
      const profileForDisk = Object.assign({}, profile);
      doc.profiles[role] = profileForDisk;
      writeFileAtomic(authPath, JSON.stringify(doc, null, 2) + "\n");
    } catch {}
  }

  let hasAttacker = false;
  let hasVictim = false;
  if (authPath) {
    try {
      const saved = readAuthJson(authPath);
      if (saved && saved.version === 2 && saved.profiles) {
        hasAttacker = !!saved.profiles.attacker;
        hasVictim = !!saved.profiles.victim;
      }
    } catch {}
  }

  return JSON.stringify({
    success: true,
    role,
    keys: Object.keys(profile).filter((k) => k !== "credentials"),
    has_attacker: hasAttacker,
    has_victim: hasVictim,
  });
}

function authManual(args) {
  const result = authStore({
    target_domain: args.target_domain,
    role: "attacker",
    cookies: args.cookies,
    headers: args.headers,
    local_storage: args.local_storage,
  });
  if (args.profile_name) {
    const headers = args.headers || {};
    const cookies = args.cookies || {};
    const storage = args.local_storage || {};
    const profile = buildHeaderProfile(headers, cookies, storage);
    authProfiles.set(args.profile_name, profile);
  }
  return result;
}

function resolveAuthProfile(authProfile, urlValue) {
  if (authProfiles.has(authProfile)) {
    return authProfiles.get(authProfile);
  }

  try {
    const urlHost = new URL(urlValue).hostname;
    const domainKey = `${urlHost}:${authProfile}`;
    if (authProfiles.has(domainKey)) return authProfiles.get(domainKey);
  } catch {}

  try {
    const urlHost = new URL(urlValue).hostname;
    const authPath = resolveAuthJsonPath(urlHost);
    if (authPath) {
      const doc = readAuthJson(authPath);
      if (doc && doc.version === 2 && doc.profiles && doc.profiles[authProfile]) {
        return doc.profiles[authProfile];
      }
      if (doc && !doc.version) {
        return doc;
      }
    }
  } catch {}

  return null;
}

module.exports = {
  authManual,
  authStore,
  buildHeaderProfile,
  migrateAuthJson,
  readAuthJson,
  resolveAuthJsonPath,
  resolveAuthProfile,
};

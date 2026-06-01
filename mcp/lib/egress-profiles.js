"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  readJsonFile,
} = require("./storage.js");

const EGRESS_PROFILES_VERSION = 1;
const EGRESS_PROFILE_IDENTITY_VERSION = 1;
const EGRESS_PROFILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENV_REF_RE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;
const SUPPORTED_PROXY_PROTOCOLS = Object.freeze(["http:", "https:", "socks5:", "socks5h:"]);
const EGRESS_PROFILES_FILE = path.join(".claude", "bob", "egress-profiles.json");
const EGRESS_PROFILES_EXAMPLE_FILE = path.join(".claude", "bob", "egress-profiles.example.json");

function projectRootFromMcp() {
  return path.resolve(__dirname, "..", "..");
}

function egressProfilesPath(projectRoot = projectRootFromMcp()) {
  return path.join(projectRoot, EGRESS_PROFILES_FILE);
}

function egressProfilesExamplePath(projectRoot = projectRootFromMcp()) {
  return path.join(projectRoot, EGRESS_PROFILES_EXAMPLE_FILE);
}

function defaultEgressProfile() {
  return {
    name: "default",
    proxy_url: null,
    region: null,
    description: "Direct connection from this machine.",
    enabled: true,
  };
}

function defaultEgressProfilesDocument() {
  return {
    version: EGRESS_PROFILES_VERSION,
    profiles: [defaultEgressProfile()],
  };
}

function exampleEgressProfilesDocument() {
  return {
    version: EGRESS_PROFILES_VERSION,
    profiles: [
      defaultEgressProfile(),
      {
        name: "gr-residential",
        proxy_url: "${BOB_EGRESS_GR_RESIDENTIAL_PROXY}",
        region: "GR",
        description: "Example operator-managed profile for Greece. Set the env var before use.",
        enabled: false,
      },
    ],
  };
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function normalizeProfileName(name, fieldName = "profile name") {
  const value = String(name == null ? "" : name).trim();
  if (!EGRESS_PROFILE_NAME_RE.test(value)) {
    throw new Error(`${fieldName} must match ${EGRESS_PROFILE_NAME_RE.source}`);
  }
  return value;
}

function redactProxyUrl(proxyUrl) {
  if (proxyUrl == null) return null;
  const text = String(proxyUrl);
  if (ENV_REF_RE.test(text)) return text;
  const redacted = redactUrlSensitiveValues(text);
  if (redacted !== text) return redacted;
  return text.replace(/:\/\/([^:@/\s]+):([^@/\s]+)@/g, "://REDACTED:REDACTED@");
}

function normalizeNullableString(value, fieldName) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string or null`);
  }
  const text = value.trim();
  return text || null;
}

function hasInlineProxyCredentials(proxyUrl) {
  if (proxyUrl == null || ENV_REF_RE.test(proxyUrl)) return false;
  try {
    const parsed = new URL(proxyUrl);
    return parsed.username.length > 0 || parsed.password.length > 0;
  } catch {
    return false;
  }
}

function hasInlineProxyQueryOrFragment(proxyUrl) {
  if (proxyUrl == null || ENV_REF_RE.test(proxyUrl)) return false;
  try {
    const parsed = new URL(proxyUrl);
    return parsed.search.length > 0 || parsed.hash.length > 0;
  } catch {
    return false;
  }
}

function normalizeProfile(profile, index) {
  if (!isPlainObject(profile)) {
    throw new Error(`profiles[${index}] must be an object`);
  }
  const name = normalizeProfileName(profile.name, `profiles[${index}].name`);
  const proxyUrl = normalizeNullableString(profile.proxy_url, `profiles[${index}].proxy_url`);
  if (hasInlineProxyCredentials(proxyUrl)) {
    throw new Error(`profiles[${index}].proxy_url credentials must use an environment reference such as \${BOB_EGRESS_PROXY_URL}`);
  }
  if (hasInlineProxyQueryOrFragment(proxyUrl)) {
    throw new Error(`profiles[${index}].proxy_url query strings or fragments must use an environment reference such as \${BOB_EGRESS_PROXY_URL}`);
  }
  const region = normalizeNullableString(profile.region, `profiles[${index}].region`);
  const description = normalizeNullableString(profile.description, `profiles[${index}].description`);
  const enabled = profile.enabled == null ? true : profile.enabled;
  if (typeof enabled !== "boolean") {
    throw new Error(`profiles[${index}].enabled must be boolean`);
  }
  return {
    name,
    proxy_url: proxyUrl,
    region,
    description,
    enabled,
  };
}

function normalizeEgressProfilesDocument(document) {
  if (!isPlainObject(document)) {
    throw new Error("egress profiles config must be an object");
  }
  const version = document.version == null ? EGRESS_PROFILES_VERSION : document.version;
  if (version !== EGRESS_PROFILES_VERSION) {
    throw new Error(`egress profiles version must be ${EGRESS_PROFILES_VERSION}`);
  }
  if (!Array.isArray(document.profiles)) {
    throw new Error("egress profiles config must contain profiles[]");
  }

  const profiles = [];
  const names = new Set();
  for (let index = 0; index < document.profiles.length; index += 1) {
    const profile = normalizeProfile(document.profiles[index], index);
    if (names.has(profile.name)) {
      throw new Error(`duplicate egress profile: ${profile.name}`);
    }
    names.add(profile.name);
    profiles.push(profile);
  }

  const defaultProfile = profiles.find((profile) => profile.name === "default");
  if (!defaultProfile) {
    throw new Error('egress profiles config must include an enabled "default" profile');
  }
  if (defaultProfile.enabled !== true) {
    throw new Error('egress profile "default" must be enabled');
  }
  if (defaultProfile.proxy_url !== null) {
    throw new Error('egress profile "default" must use proxy_url: null');
  }

  return {
    version: EGRESS_PROFILES_VERSION,
    profiles,
  };
}

function readEgressProfilesDocument(projectRoot = projectRootFromMcp()) {
  const filePath = egressProfilesPath(projectRoot);
  if (!fs.existsSync(filePath)) {
    return defaultEgressProfilesDocument();
  }
  const parsed = readJsonFile(filePath, { label: EGRESS_PROFILES_FILE });
  return normalizeEgressProfilesDocument(parsed);
}

function writeEgressProfilesDocument(projectRoot, document, options = {}) {
  const normalized = normalizeEgressProfilesDocument(document);
  const filePath = egressProfilesPath(projectRoot);
  if (options.installFs) {
    options.installFs.writeJson(filePath, normalized, {
      kind: EGRESS_PROFILES_FILE,
      rejectExistingSymlink: true,
    });
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
  }
  return normalized;
}

function ensureEgressProfilesConfig(projectRoot = projectRootFromMcp(), options = {}) {
  const filePath = egressProfilesPath(projectRoot);
  if (options.installFs) {
    const existing = options.installFs.readJsonIfExists(filePath, null, {
      kind: EGRESS_PROFILES_FILE,
      symlink: "reject",
    });
    if (existing == null) {
      writeEgressProfilesDocument(projectRoot, defaultEgressProfilesDocument(), options);
      return { created: true, path: filePath };
    }
    normalizeEgressProfilesDocument(existing);
    return { created: false, path: filePath };
  }
  if (!fs.existsSync(filePath)) {
    writeEgressProfilesDocument(projectRoot, defaultEgressProfilesDocument(), options);
    return { created: true, path: filePath };
  }
  normalizeEgressProfilesDocument(readJsonFile(filePath, { label: EGRESS_PROFILES_FILE }));
  return { created: false, path: filePath };
}

function ensureEgressProfilesExample(projectRoot = projectRootFromMcp(), options = {}) {
  const filePath = egressProfilesExamplePath(projectRoot);
  if (options.installFs) {
    options.installFs.writeJson(filePath, exampleEgressProfilesDocument(), {
      kind: EGRESS_PROFILES_EXAMPLE_FILE,
      rejectExistingSymlink: true,
    });
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(exampleEgressProfilesDocument(), null, 2)}\n`, "utf8");
  }
  return filePath;
}

function resolveProxyUrl(proxyUrl, env = process.env) {
  if (proxyUrl == null) return null;
  const envRef = proxyUrl.match(ENV_REF_RE);
  if (envRef) {
    const value = env[envRef[1]];
    if (typeof value !== "string" || !value.trim()) {
      throw new Error(`egress proxy env var ${envRef[1]} is not set`);
    }
    return value.trim();
  }
  return proxyUrl;
}

function envRefName(proxyUrl) {
  if (proxyUrl == null) return null;
  const envRef = String(proxyUrl).match(ENV_REF_RE);
  return envRef ? envRef[1] : null;
}

function validateProxyUrl(proxyUrl) {
  if (proxyUrl == null) return null;
  let parsed;
  try {
    parsed = new URL(proxyUrl);
  } catch {
    throw new Error(`egress proxy URL is malformed: ${redactProxyUrl(proxyUrl)}`);
  }
  if (!SUPPORTED_PROXY_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error(`unsupported egress proxy protocol: ${parsed.protocol}`);
  }
  if (!parsed.hostname) {
    throw new Error(`egress proxy URL is missing a host: ${redactProxyUrl(proxyUrl)}`);
  }
  if (parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new Error("egress proxy URL query strings or fragments are not supported");
  }
  return parsed;
}

function defaultProxyPort(protocol) {
  if (protocol === "http:") return "80";
  if (protocol === "https:") return "443";
  if (protocol === "socks5:" || protocol === "socks5h:") return "1080";
  return "";
}

function resolvedProxyIdentity(proxyUrl) {
  if (proxyUrl == null) return null;
  const parsed = validateProxyUrl(proxyUrl);
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port || defaultProxyPort(parsed.protocol),
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}

function stableIdentityHash(input) {
  return crypto
    .createHash("sha256")
    .update(canonicalJson(input))
    .digest("hex");
}

function buildEgressProfileIdentity(profile, resolvedProxyUrl) {
  const proxyConfigured = resolvedProxyUrl != null;
  const envRef = envRefName(profile.proxy_url);
  const resolvedProxy = resolvedProxyIdentity(resolvedProxyUrl);
  const source = {
    proxy_url_source: envRef ? "env" : profile.proxy_url == null ? "none" : "inline",
    proxy_env_var: envRef,
    proxy_url_redacted: resolvedProxyUrl == null ? null : redactProxyUrl(resolvedProxyUrl),
    resolved_proxy: resolvedProxy,
  };
  const hashInput = {
    identity_version: EGRESS_PROFILE_IDENTITY_VERSION,
    profile_name: profile.name,
    region: profile.region,
    proxy_configured: proxyConfigured,
    proxy_source: {
      proxy_url_source: source.proxy_url_source,
      proxy_env_var: source.proxy_env_var,
    },
    resolved_proxy: resolvedProxy,
  };
  return {
    egress_profile_identity_hash: stableIdentityHash(hashInput),
    egress_profile_identity_version: EGRESS_PROFILE_IDENTITY_VERSION,
    egress_profile_identity_source: source,
  };
}

function egressProfileIdentityFields(profile) {
  return {
    egress_profile: profile.name,
    egress_region: profile.region,
    proxy_configured: profile.proxy_configured === true,
    egress_profile_identity_hash: profile.egress_profile_identity_hash,
    egress_profile_identity_version: profile.egress_profile_identity_version,
    egress_profile_identity_source: profile.egress_profile_identity_source,
  };
}

function profilePublicView(profile) {
  return {
    name: profile.name,
    enabled: profile.enabled,
    region: profile.region,
    description: profile.description,
    proxy_configured: profile.proxy_url != null,
  };
}

function listEgressProfiles(projectRoot = projectRootFromMcp()) {
  return readEgressProfilesDocument(projectRoot).profiles.map(profilePublicView);
}

function resolveEgressProfile(name = "default", {
  projectRoot = projectRootFromMcp(),
  env = process.env,
} = {}) {
  const requestedName = normalizeProfileName(name || "default", "egress_profile");
  const document = readEgressProfilesDocument(projectRoot);
  const profile = document.profiles.find((item) => item.name === requestedName);
  if (!profile) {
    throw new Error(`egress profile "${requestedName}" was not found`);
  }
  if (!profile.enabled) {
    throw new Error(`egress profile "${requestedName}" is disabled`);
  }
  const proxyUrl = resolveProxyUrl(profile.proxy_url, env);
  validateProxyUrl(proxyUrl);
  const identity = buildEgressProfileIdentity(profile, proxyUrl);
  return {
    name: profile.name,
    region: profile.region,
    description: profile.description,
    proxy_url: proxyUrl,
    proxy_url_redacted: redactProxyUrl(proxyUrl),
    proxy_configured: proxyUrl != null,
    ...identity,
  };
}

function createProxyAgent(proxyUrl) {
  if (proxyUrl == null) return null;
  const { ProxyAgent } = require("proxy-agent");
  return new ProxyAgent(proxyUrl);
}

function addOrUpdateEgressProfile(projectRoot, profile) {
  const document = readEgressProfilesDocument(projectRoot);
  const normalized = normalizeProfile(profile, document.profiles.length);
  if (normalized.name === "default") {
    normalized.enabled = true;
    normalized.proxy_url = null;
  }
  const existingIndex = document.profiles.findIndex((item) => item.name === normalized.name);
  if (existingIndex >= 0) {
    document.profiles[existingIndex] = normalized;
  } else {
    document.profiles.push(normalized);
  }
  return writeEgressProfilesDocument(projectRoot, document);
}

function setEgressProfileEnabled(projectRoot, name, enabled) {
  const normalizedName = normalizeProfileName(name);
  if (normalizedName === "default" && enabled === false) {
    throw new Error('egress profile "default" cannot be disabled');
  }
  const document = readEgressProfilesDocument(projectRoot);
  const profile = document.profiles.find((item) => item.name === normalizedName);
  if (!profile) throw new Error(`egress profile "${normalizedName}" was not found`);
  profile.enabled = enabled;
  return writeEgressProfilesDocument(projectRoot, document);
}

function removeEgressProfile(projectRoot, name) {
  const normalizedName = normalizeProfileName(name);
  if (normalizedName === "default") {
    throw new Error('egress profile "default" cannot be removed');
  }
  const document = readEgressProfilesDocument(projectRoot);
  const nextProfiles = document.profiles.filter((profile) => profile.name !== normalizedName);
  if (nextProfiles.length === document.profiles.length) {
    throw new Error(`egress profile "${normalizedName}" was not found`);
  }
  return writeEgressProfilesDocument(projectRoot, {
    ...document,
    profiles: nextProfiles,
  });
}

function isUntouchedGeneratedEgressConfig(projectRoot = projectRootFromMcp()) {
  const filePath = egressProfilesPath(projectRoot);
  if (!fs.existsSync(filePath)) return false;
  try {
    const current = normalizeEgressProfilesDocument(readJsonFile(filePath, { label: EGRESS_PROFILES_FILE }));
    return JSON.stringify(current) === JSON.stringify(defaultEgressProfilesDocument());
  } catch {
    return false;
  }
}

module.exports = {
  EGRESS_PROFILES_EXAMPLE_FILE,
  EGRESS_PROFILES_FILE,
  EGRESS_PROFILE_IDENTITY_VERSION,
  EGRESS_PROFILES_VERSION,
  EGRESS_PROFILE_NAME_RE,
  SUPPORTED_PROXY_PROTOCOLS,
  addOrUpdateEgressProfile,
  createProxyAgent,
  defaultEgressProfile,
  defaultEgressProfilesDocument,
  egressProfileIdentityFields,
  egressProfilesExamplePath,
  egressProfilesPath,
  ensureEgressProfilesConfig,
  ensureEgressProfilesExample,
  exampleEgressProfilesDocument,
  isUntouchedGeneratedEgressConfig,
  listEgressProfiles,
  normalizeEgressProfilesDocument,
  projectRootFromMcp,
  profilePublicView,
  readEgressProfilesDocument,
  redactProxyUrl,
  removeEgressProfile,
  resolveEgressProfile,
  setEgressProfileEnabled,
  writeEgressProfilesDocument,
};

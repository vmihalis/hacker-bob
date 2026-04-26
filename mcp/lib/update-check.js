#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PACKAGE_NAME = "hacker-bob";
const PACKAGE_URL = `https://www.npmjs.com/package/${PACKAGE_NAME}`;
const DEFAULT_CHANGELOG_URL = "https://raw.githubusercontent.com/vmihalis/hacker-bob/main/CHANGELOG.md";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function packageName() {
  return process.env.HACKER_BOB_PACKAGE_NAME || PACKAGE_NAME;
}

function cleanError(error) {
  const message = error && error.message ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 300);
}

function nowMs(options = {}) {
  return Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
}

function projectHash(projectDir) {
  return crypto.createHash("sha256").update(path.resolve(projectDir)).digest("hex").slice(0, 24);
}

function cacheDir(options = {}) {
  return path.join(options.homeDir || os.homedir(), ".cache", "hacker-bob", "update-checks");
}

function cachePath(projectDir, options = {}) {
  return path.join(cacheDir(options), `${projectHash(projectDir)}.json`);
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readUpdateCache(projectDir, options = {}) {
  const filePath = cachePath(projectDir, options);
  try {
    return readJsonFile(filePath);
  } catch {
    return null;
  }
}

function writeUpdateCache(projectDir, value, options = {}) {
  const filePath = cachePath(projectDir, options);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return filePath;
}

function clearUpdateCache(projectDir, options = {}) {
  fs.rmSync(cachePath(projectDir, options), { force: true });
}

function isCacheFresh(cache, options = {}) {
  if (!cache || !Number.isFinite(cache.checked_at_ms)) return false;
  const ttlMs = Number.isFinite(options.ttlMs) ? options.ttlMs : CACHE_TTL_MS;
  return nowMs(options) - cache.checked_at_ms < ttlMs;
}

function isCacheStale(projectDir, options = {}) {
  return !isCacheFresh(readUpdateCache(projectDir, options), options);
}

function installedVersionPaths(projectDir, options = {}) {
  if (options.installedVersionPath) return [options.installedVersionPath];
  if (Array.isArray(options.installedVersionPaths) && options.installedVersionPaths.length > 0) {
    return options.installedVersionPaths;
  }
  return [
    path.join(projectDir, ".hacker-bob", "VERSION"),
    path.join(projectDir, ".claude", "bob", "VERSION"),
  ];
}

function readInstalledVersion(projectDir, options = {}) {
  for (const versionPath of installedVersionPaths(projectDir, options)) {
    try {
      const version = fs.readFileSync(versionPath, "utf8").trim();
      if (version) return version;
    } catch {
      // Try the next configured version path.
    }
  }
  return null;
}

function parseSemver(version) {
  const match = String(version || "").trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] || "",
  };
}

function compareIdentifiers(a, b) {
  if (a === b) return 0;
  const aNum = /^\d+$/.test(a) ? Number(a) : null;
  const bNum = /^\d+$/.test(b) ? Number(b) : null;
  if (aNum != null && bNum != null) return Math.sign(aNum - bNum);
  if (aNum != null) return -1;
  if (bNum != null) return 1;
  return a < b ? -1 : 1;
}

function compareSemver(a, b) {
  const left = parseSemver(a);
  const right = parseSemver(b);
  if (!left || !right) return String(a || "").localeCompare(String(b || ""));
  for (const key of ["major", "minor", "patch"]) {
    if (left[key] !== right[key]) return Math.sign(left[key] - right[key]);
  }
  if (!left.prerelease && right.prerelease) return 1;
  if (left.prerelease && !right.prerelease) return -1;
  if (!left.prerelease && !right.prerelease) return 0;
  const leftParts = left.prerelease.split(".");
  const rightParts = right.prerelease.split(".");
  const count = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < count; index += 1) {
    if (leftParts[index] == null) return -1;
    if (rightParts[index] == null) return 1;
    const compared = compareIdentifiers(leftParts[index], rightParts[index]);
    if (compared !== 0) return compared;
  }
  return 0;
}

function metadataUrlForPackage(name) {
  if (process.env.HACKER_BOB_REGISTRY_METADATA_URL) return process.env.HACKER_BOB_REGISTRY_METADATA_URL;
  const registry = (process.env.HACKER_BOB_NPM_REGISTRY_URL || "https://registry.npmjs.org").replace(/\/+$/, "");
  return `${registry}/${encodeURIComponent(name).replace(/^%40/, "@").replace(/%2F/g, "/")}`;
}

function changelogUrl() {
  return process.env.HACKER_BOB_CHANGELOG_URL || DEFAULT_CHANGELOG_URL;
}

function readFileUrl(url) {
  return fs.readFileSync(new URL(url), "utf8");
}

async function fetchText(url, options = {}) {
  if (url.startsWith("file:")) return readFileUrl(url);
  const fetchImpl = options.fetchImpl || fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 8000);
  try {
    const response = await fetchImpl(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
    return await response.text();
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJson(url, options = {}) {
  if (url.startsWith("file:")) return JSON.parse(readFileUrl(url));
  const text = await fetchText(url, options);
  return JSON.parse(text);
}

async function fetchLatestVersion(options = {}) {
  if (process.env.HACKER_BOB_LATEST_VERSION) return process.env.HACKER_BOB_LATEST_VERSION;
  const name = options.packageName || packageName();
  const metadata = await fetchJson(metadataUrlForPackage(name), options);
  const latest = metadata && metadata["dist-tags"] && metadata["dist-tags"].latest;
  if (!latest) throw new Error(`npm metadata for ${name} does not include dist-tags.latest`);
  return latest;
}

async function fetchChangelog(options = {}) {
  return fetchText(options.changelogUrl || changelogUrl(), options);
}

function changelogSections(markdown) {
  const headingPattern = /^##\s+(?:\[?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?)(?:\s+-\s+.*)?$/gm;
  const headings = [];
  let match;
  while ((match = headingPattern.exec(markdown)) !== null) {
    headings.push({
      version: match[1],
      start: match.index,
      bodyStart: headingPattern.lastIndex,
    });
  }
  return headings.map((heading, index) => ({
    version: heading.version,
    content: markdown.slice(heading.start, headings[index + 1] ? headings[index + 1].start : markdown.length).trim(),
  }));
}

function extractChangelogEntries(markdown, installedVersion, latestVersion) {
  const sections = changelogSections(markdown);
  const selected = sections.filter((section, index) => {
    if (latestVersion && compareSemver(section.version, latestVersion) > 0) return false;
    if (!installedVersion) return latestVersion ? compareSemver(section.version, latestVersion) === 0 : index === 0;
    return compareSemver(section.version, installedVersion) > 0;
  });
  return selected.map((section) => section.content).join("\n\n").trim();
}

async function checkForUpdate(projectDir, options = {}) {
  const checkedAtMs = nowMs(options);
  const checkedAt = new Date(checkedAtMs).toISOString();
  const installedVersion = readInstalledVersion(projectDir, options);
  const name = options.packageName || packageName();
  const base = {
    schema_version: 1,
    package_name: name,
    package_url: PACKAGE_URL,
    install_target: path.resolve(projectDir),
    installed_version: installedVersion,
    latest_version: null,
    update_available: false,
    legacy_install: !installedVersion,
    checked_at: checkedAt,
    checked_at_ms: checkedAtMs,
    error: null,
  };

  let latestVersion;
  try {
    latestVersion = await fetchLatestVersion({ ...options, packageName: name });
  } catch (error) {
    return {
      ...base,
      error: {
        type: "registry",
        message: cleanError(error),
      },
    };
  }

  const updateAvailable = !installedVersion || compareSemver(latestVersion, installedVersion) > 0;
  const result = {
    ...base,
    latest_version: latestVersion,
    update_available: updateAvailable,
  };

  if (updateAvailable && options.includeChangelog !== false) {
    try {
      const markdown = await fetchChangelog(options);
      result.changelog = extractChangelogEntries(markdown, installedVersion, latestVersion);
    } catch (error) {
      result.changelog = "";
      result.changelog_error = cleanError(error);
    }
  }

  return result;
}

async function refreshUpdateCache(projectDir, options = {}) {
  const existing = readUpdateCache(projectDir, options);
  if (!options.force && isCacheFresh(existing, options)) {
    return { cache: existing, refreshed: false, path: cachePath(projectDir, options) };
  }
  const result = await checkForUpdate(projectDir, { ...options, includeChangelog: false });
  const filePath = writeUpdateCache(projectDir, result, options);
  return { cache: result, refreshed: true, path: filePath };
}

function defaultInstallCommand(result) {
  const name = (result && result.package_name) || PACKAGE_NAME;
  const target = result && result.install_target ? JSON.stringify(result.install_target) : ".";
  return `npx -y ${name}@latest install ${target}`;
}

function installCommandForResult(result, options = {}) {
  if (options.installCommand) return options.installCommand;
  if (typeof options.installCommandForResult === "function") {
    const command = options.installCommandForResult(result);
    if (command) return command;
  }
  return defaultInstallCommand(result);
}

function renderUpdateSummary(result, options = {}) {
  if (!result) return "No Hacker Bob update cache is available yet.\n";
  if (result.error) {
    return [
      "Hacker Bob update check could not reach npm.",
      `Installed: ${result.installed_version || "legacy/unknown"}`,
      `Manual update command: ${installCommandForResult(result, options)}`,
      `Reason: ${result.error.message}`,
      "",
    ].join("\n");
  }
  if (!result.update_available) {
    return `Hacker Bob is up to date (${result.installed_version || result.latest_version}).\n`;
  }
  const installed = result.installed_version || "legacy/unknown";
  return `Hacker Bob ${result.latest_version} is available (installed: ${installed}). Run /bob:update.\n`;
}

function renderUpdatePlan(result, options = {}) {
  const lines = [];
  if (result.error) {
    lines.push("Hacker Bob update check could not reach npm.");
    lines.push("");
    lines.push(`Installed: ${result.installed_version || "legacy/unknown"}`);
    lines.push(`Manual update command: \`${installCommandForResult(result, options)}\``);
    lines.push(`Reason: ${result.error.message}`);
    lines.push("");
    lines.push("Try again when online, or run the manual command from the project root.");
    return `${lines.join("\n")}\n`;
  }

  lines.push("# Hacker Bob Update");
  lines.push("");
  lines.push(`Installed: ${result.installed_version || "legacy install (missing install version metadata)"}`);
  lines.push(`Latest: ${result.latest_version}`);
  lines.push("");

  if (!result.update_available) {
    lines.push("Hacker Bob is already up to date.");
    return `${lines.join("\n")}\n`;
  }

  if (result.legacy_install) {
    lines.push("This looks like a legacy install. A fresh npm install will add version metadata and the update hooks.");
    lines.push("");
  }

  if (result.changelog) {
    const preview = result.changelog.length > 4000
      ? `${result.changelog.slice(0, 4000).trimEnd()}\n\n[Changelog preview truncated]`
      : result.changelog;
    lines.push("## Changelog Preview");
    lines.push("");
    lines.push(preview);
    lines.push("");
  } else if (result.changelog_error) {
    lines.push(`Changelog preview unavailable: ${result.changelog_error}`);
    lines.push("");
  }

  lines.push(`Install command: \`${installCommandForResult(result, options)}\``);
  lines.push("Ask the operator: Update now?");
  return `${lines.join("\n")}\n`;
}

module.exports = {
  CACHE_TTL_MS,
  PACKAGE_NAME,
  cachePath,
  checkForUpdate,
  clearUpdateCache,
  compareSemver,
  extractChangelogEntries,
  fetchLatestVersion,
  installCommandForResult,
  installedVersionPaths,
  isCacheFresh,
  isCacheStale,
  readInstalledVersion,
  readUpdateCache,
  refreshUpdateCache,
  renderUpdatePlan,
  renderUpdateSummary,
  writeUpdateCache,
};

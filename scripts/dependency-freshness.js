#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const NPM_CACHE = process.env.HACKER_BOB_RELEASE_NPM_CACHE ||
  path.join(os.tmpdir(), "hacker-bob-dependency-freshness-npm-cache");

const CHECKS = Object.freeze([
  Object.freeze({
    name: "psl",
    reason: "Public Suffix List scope ownership",
    warnAfterDays: 180,
  }),
]);

let failures = 0;
let warnings = 0;

function log(status, message) {
  console.log(`${status} ${message}`);
}

function pass(message) {
  log("OK", message);
}

function info(message) {
  log("INFO", message);
}

function warn(message) {
  warnings += 1;
  log("WARN", message);
}

function fail(message) {
  failures += 1;
  log("FAIL", message);
}

function parseArgs(argv) {
  const options = {
    metadataFile: null,
    now: new Date(),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--metadata-file") {
      index += 1;
      if (!argv[index]) throw new Error("--metadata-file requires a path");
      options.metadataFile = argv[index];
    } else if (arg === "--now") {
      index += 1;
      if (!argv[index]) throw new Error("--now requires an ISO timestamp");
      const parsed = new Date(argv[index]);
      if (Number.isNaN(parsed.getTime())) throw new Error(`invalid --now timestamp: ${argv[index]}`);
      options.now = parsed;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function packageLockVersion(packageLock, name) {
  const lockPath = `node_modules/${name}`;
  const entry = packageLock.packages && packageLock.packages[lockPath];
  return entry && entry.version;
}

function declaredDependencyRange(packageJson, name) {
  return (packageJson.dependencies && packageJson.dependencies[name]) ||
    (packageJson.optionalDependencies && packageJson.optionalDependencies[name]) ||
    null;
}

function npmViewPackageMetadata(name) {
  const result = spawnSync("npm", ["view", name, "version", "time", "dist-tags", "--json"], {
    cwd: ROOT,
    env: {
      ...process.env,
      npm_config_cache: NPM_CACHE,
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    fail(`${name} registry metadata lookup failed; release freshness cannot be proven offline: ${String(result.stderr || result.stdout).trim()}`);
    return null;
  }
  try {
    return JSON.parse(String(result.stdout || "").trim());
  } catch (error) {
    fail(`${name} registry metadata was not parseable JSON: ${error.message}`);
    return null;
  }
}

function metadataFromFile(metadataFile, name) {
  const raw = readJson(metadataFile);
  return raw[name] || raw;
}

function packageMetadata(name, options) {
  if (options.metadataFile) return metadataFromFile(options.metadataFile, name);
  return npmViewPackageMetadata(name);
}

function daysBetween(later, earlier) {
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function checkOverlayEscapeHatch() {
  const scopeSource = fs.readFileSync(path.join(ROOT, "mcp", "lib", "scope.js"), "utf8");
  const hasEnv = scopeSource.includes("BOB_PSL_OVERLAY_FILE");
  const hasSource = scopeSource.includes("operator_overlay");
  const hasUnlistedFallback = scopeSource.includes("psl_unlisted");
  if (hasEnv && hasSource && hasUnlistedFallback) {
    pass("PSL overlay escape hatch remains implemented without runtime network refresh");
  } else {
    fail("PSL overlay escape hatch is missing expected BOB_PSL_OVERLAY_FILE/operator_overlay/psl_unlisted markers");
  }
}

function checkDependency(check, options, packageJson, packageLock) {
  const range = declaredDependencyRange(packageJson, check.name);
  const lockedVersion = packageLockVersion(packageLock, check.name);
  if (!range) {
    fail(`${check.name} is missing from package.json dependencies`);
    return;
  }
  if (!lockedVersion) {
    fail(`${check.name} is missing from package-lock.json`);
    return;
  }
  pass(`${check.name} is declared as ${range} and locked at ${lockedVersion}`);

  const metadata = packageMetadata(check.name, options);
  if (!metadata) return;

  const latest = (metadata["dist-tags"] && metadata["dist-tags"].latest) || metadata.version;
  if (!latest) {
    fail(`${check.name} registry metadata has no latest version`);
    return;
  }

  if (latest === lockedVersion) {
    pass(`${check.name} lockfile version matches npm latest ${latest}`);
  } else {
    fail(`${check.name} lockfile version ${lockedVersion} is behind npm latest ${latest}`);
  }

  const publishedAt = metadata.time && (metadata.time[latest] || metadata.time.modified);
  if (!publishedAt) {
    fail(`${check.name}@${latest} registry metadata has no publish timestamp`);
    return;
  }
  const publishedDate = new Date(publishedAt);
  if (Number.isNaN(publishedDate.getTime())) {
    fail(`${check.name}@${latest} publish timestamp is invalid: ${publishedAt}`);
    return;
  }

  const ageDays = daysBetween(options.now, publishedDate);
  const ageText = ageDays.toFixed(1);
  if (ageDays > check.warnAfterDays) {
    const latestText = latest === lockedVersion ? "; lockfile is still npm latest" : "";
    warn(`${check.name}@${latest} latest publish age ${ageText} days exceeds warning threshold ${check.warnAfterDays} days${latestText}`);
  } else {
    pass(`${check.name}@${latest} latest publish age ${ageText} days is within ${check.warnAfterDays} day warning threshold`);
  }
  info(`${check.name} freshness owner: ${check.reason}`);
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Dependency freshness check failed: ${error.message}`);
    process.exit(1);
  }

  console.log("Hacker Bob dependency freshness check");
  console.log(`INFO now=${options.now.toISOString()}`);
  if (options.metadataFile) info(`using registry metadata fixture ${path.relative(ROOT, path.resolve(options.metadataFile))}`);

  const packageJson = readJson(path.join(ROOT, "package.json"));
  const packageLock = readJson(path.join(ROOT, "package-lock.json"));

  checkOverlayEscapeHatch();
  for (const check of CHECKS) {
    checkDependency(check, options, packageJson, packageLock);
  }

  if (failures > 0) {
    console.error(`Dependency freshness check failed with ${failures} failure(s) and ${warnings} warning(s).`);
    process.exit(1);
  }
  console.log(`Dependency freshness check passed with ${warnings} warning(s).`);
}

main();

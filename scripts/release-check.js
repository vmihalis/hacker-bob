#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  DISALLOWED_PACKED_FILE_PATTERNS,
  DISALLOWED_PACKED_TEXT_PATTERNS,
  EXCLUDED_CANONICAL_PACKAGE_FILES,
  LOCAL_INSTALL_METADATA_FILES,
  REQUIRED_SUPPORT_SURFACES,
  expectedCanonicalFiles,
  isInternalRefactorDoc,
  isPackableBin,
  isPackableBobResource,
  isPackableScript,
  isPackedTextFile,
  wrapperPackages,
} = require("./lib/package-policy.js");

const ROOT = path.join(__dirname, "..");
const WRAPPER_PACKAGES = wrapperPackages(ROOT);
const NPM_CACHE = process.env.HACKER_BOB_RELEASE_NPM_CACHE || path.join(os.tmpdir(), "hacker-bob-release-check-npm-cache");
const args = new Set(process.argv.slice(2));
const registryMode = args.has("--registry");
const allowPublished = args.has("--allow-published");

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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function exists(filePath) {
  return fs.existsSync(filePath);
}

function run(command, commandArgs, options = {}) {
  return spawnSync(command, commandArgs, {
    cwd: options.cwd || ROOT,
    env: {
      ...process.env,
      npm_config_cache: NPM_CACHE,
      ...(options.env || {}),
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function npm(commandArgs, options = {}) {
  return run("npm", commandArgs, options);
}

function parseJsonOutput(result, description) {
  const output = String(result.stdout || "").trim();
  try {
    return JSON.parse(output);
  } catch (error) {
    fail(`${description} did not return parseable JSON: ${error.message}`);
    if (output) info(`${description} stdout: ${output.slice(0, 500)}`);
    if (result.stderr) info(`${description} stderr: ${String(result.stderr).trim().slice(0, 500)}`);
    return null;
  }
}

function pack(cwd, label) {
  const result = npm(["pack", "--dry-run", "--json"], { cwd });
  if (result.status !== 0) {
    fail(`${label} npm pack failed: ${String(result.stderr || result.stdout).trim()}`);
    return null;
  }
  const packs = parseJsonOutput(result, `${label} npm pack`);
  if (!Array.isArray(packs) || packs.length !== 1) {
    fail(`${label} npm pack returned an unexpected result`);
    return null;
  }
  return packs[0];
}

function fileSet(packResult) {
  return new Set((packResult.files || []).map((file) => file.path));
}

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    pass(message);
  } else {
    fail(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertFile(filePath, message) {
  if (exists(filePath)) {
    pass(message);
  } else {
    fail(`${message}: missing ${path.relative(ROOT, filePath)}`);
  }
}

function checkManifest() {
  const rootPackage = readJson(path.join(ROOT, "package.json"));
  assertEqual(rootPackage.name, "hacker-bob", "canonical package name is hacker-bob");
  const codexPluginManifest = readJson(path.join(ROOT, "adapters", "codex", "hacker-bob", ".codex-plugin", "plugin.json"));
  assertEqual(
    codexPluginManifest.version,
    rootPackage.version,
    "Codex plugin manifest version matches canonical version",
  );

  const wrapperPackages = WRAPPER_PACKAGES.map((spec) => {
    const wrapperPackage = readJson(path.join(spec.root, "package.json"));
    assertEqual(wrapperPackage.name, spec.name, `${spec.label} package name is ${spec.name}`);
    assertEqual(wrapperPackage.version, rootPackage.version, `${spec.label} version matches canonical version`);
    assertEqual(
      wrapperPackage.dependencies && wrapperPackage.dependencies["hacker-bob"],
      rootPackage.version,
      `${spec.label} dependency pins the canonical package version`,
    );
    const declaredBin = wrapperPackage.bin && wrapperPackage.bin[spec.name];
    assertEqual(declaredBin, spec.bin, `${spec.label} declares bin ${spec.name} -> ${spec.bin}`);
    return { spec, wrapperPackage };
  });

  assertFile(path.join(ROOT, "CHANGELOG.md"), "CHANGELOG.md exists");
  const changelog = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  if (changelog.includes(`## [${rootPackage.version}]`)) {
    pass(`CHANGELOG.md has a ${rootPackage.version} section`);
  } else {
    fail(`CHANGELOG.md is missing a ${rootPackage.version} section`);
  }

  assertFile(
    path.join(ROOT, "docs", "releases", `v${rootPackage.version}.md`),
    `release notes exist for v${rootPackage.version}`,
  );

  return { rootPackage, wrapperPackages };
}

function checkCanonicalPack(rootPackage) {
  const canonical = pack(ROOT, "canonical package");
  if (!canonical) return;
  const files = fileSet(canonical);

  assertEqual(canonical.name, "hacker-bob", "canonical pack name is hacker-bob");
  assertEqual(canonical.version, rootPackage.version, "canonical pack version matches package.json");

  for (const expected of expectedCanonicalFiles(ROOT)) {
    if (files.has(expected)) {
      pass(`canonical pack includes ${expected}`);
    } else {
      fail(`canonical pack is missing ${expected}`);
    }
  }
  for (const expected of REQUIRED_SUPPORT_SURFACES) {
    if (files.has(expected)) {
      pass(`canonical pack intentionally includes support surface ${expected}`);
    } else {
      fail(`canonical pack is missing intentional support surface ${expected}`);
    }
  }
  for (const excluded of EXCLUDED_CANONICAL_PACKAGE_FILES) {
    if (files.has(excluded)) {
      fail(`canonical pack includes excluded file ${excluded}`);
    } else {
      pass(`canonical pack excludes ${excluded}`);
    }
  }

  // Pack-size budget raised to 3.1 MB to accommodate the kimi adapter family
  // (adapters/kimi/*, scripts/lib/kimi-role-renderer.js, scripts/lib/install-fs.js,
  // packages/hacker-bob-kimi/*) absorbed from PR #58 alongside the existing
  // Y.3 Stage c substrate growth, plus packable Plane-Delta graph JSON docs.
  // Mirrors the test/package.test.js ceiling.
  if (canonical.size < 3100000) {
    pass(`canonical pack size ${canonical.size} bytes is under 3.1 MB`);
  } else {
    fail(`canonical pack size ${canonical.size} bytes exceeds 3.1 MB`);
  }

  let foundDisallowed = false;
  for (const file of files) {
    if (file.startsWith("test/") || file.startsWith("tests/")) {
      foundDisallowed = true;
      fail(`canonical pack includes test artifact ${file}`);
    }
    if (isInternalRefactorDoc(file)) {
      foundDisallowed = true;
      fail(`canonical pack includes internal refactor tracker ${file}`);
    }
    if (file.startsWith("scripts/replay-prompts/")) {
      foundDisallowed = true;
      fail(`canonical pack includes deprecated replay prompt ${file}`);
    }
    if (DISALLOWED_PACKED_FILE_PATTERNS.some((pattern) => pattern.test(file))) {
      foundDisallowed = true;
      fail(`canonical pack includes local/temp artifact ${file}`);
    }
    if (file.startsWith("scripts/") && !isPackableScript(file)) {
      foundDisallowed = true;
      fail(`canonical pack includes unsupported scripts/ file ${file}`);
    }
    if (file.startsWith("bin/") && !isPackableBin(file)) {
      foundDisallowed = true;
      fail(`canonical pack includes unsupported bin/ file ${file}`);
    }
    if (file.startsWith(".hacker-bob/") && !isPackableBobResource(file)) {
      foundDisallowed = true;
      fail(`canonical pack includes unsupported .hacker-bob resource ${file}`);
    }
    if (file.startsWith("packages/")) {
      foundDisallowed = true;
      fail(`canonical pack includes nested package artifact ${file}`);
    }
    if (file.startsWith(".github/")) {
      foundDisallowed = true;
      fail(`canonical pack includes GitHub metadata ${file}`);
    }
    if (file.startsWith(".cache/") || file.startsWith("cache/") || file.includes("/.cache/")) {
      foundDisallowed = true;
      fail(`canonical pack includes cache artifact ${file}`);
    }
    if (file === ".claude/hooks/bob-update-lib.js") {
      foundDisallowed = true;
      fail("canonical pack includes deprecated hook-local update library");
    }
    if (LOCAL_INSTALL_METADATA_FILES.has(file)) {
      foundDisallowed = true;
      fail(`canonical pack includes local install metadata ${file}`);
    }
    if (file.includes("bounty-agent-sessions") || file.includes("hacker-bob-sessions")) {
      foundDisallowed = true;
      fail(`canonical pack includes session artifact ${file}`);
    }
    if (isPackedTextFile(file)) {
      const sourcePath = path.join(ROOT, file);
      if (exists(sourcePath)) {
        const content = fs.readFileSync(sourcePath, "utf8");
        for (const pattern of DISALLOWED_PACKED_TEXT_PATTERNS) {
          if (pattern.test(content)) {
            foundDisallowed = true;
            fail(`canonical pack text file includes local absolute path ${file}`);
          }
        }
      }
    }
  }
  if (!foundDisallowed) {
    pass("canonical pack excludes tests, cache files, nested packages, and session artifacts");
  }
}

function checkWrapperPack(spec, rootPackage) {
  const result = pack(spec.root, spec.label);
  if (!result) return;
  const files = Array.from(fileSet(result)).sort();

  assertEqual(result.name, spec.name, `${spec.label} pack name is ${spec.name}`);
  assertEqual(result.version, rootPackage.version, `${spec.label} pack version matches canonical version`);

  const expected = [spec.bin, "README.md", "package.json"].sort();
  if (JSON.stringify(files) === JSON.stringify(expected)) {
    pass(`${spec.label} pack contains only wrapper, README, and manifest`);
  } else {
    fail(`${spec.label} pack contents mismatch: ${files.join(", ")}`);
  }

  if (result.size < 5000) {
    pass(`${spec.label} pack size ${result.size} bytes is under 5 KB`);
  } else {
    fail(`${spec.label} pack size ${result.size} bytes exceeds 5 KB`);
  }

  // Verify the bin script injects the adapter default. Catches a renamed
  // wrapper that lost its adapter pin.
  const binSource = fs.readFileSync(path.join(spec.root, spec.bin), "utf8");
  if (binSource.includes(`"${spec.adapter}"`)) {
    pass(`${spec.label} bin script pins --adapter ${spec.adapter}`);
  } else {
    fail(`${spec.label} bin script does not pin --adapter ${spec.adapter}`);
  }
}

function npmJson(commandArgs, description, options = {}) {
  const result = npm([...commandArgs, "--json"], options);
  if (result.status !== 0) {
    if (options.allowFailure) return { ok: false, result };
    fail(`${description} failed: ${String(result.stderr || result.stdout).trim()}`);
    return { ok: false, result };
  }
  return { ok: true, value: parseJsonOutput(result, description), result };
}

function isNpmNotFound(result) {
  const text = `${String(result && result.stderr || "")}\n${String(result && result.stdout || "")}`;
  return /\bE404\b/.test(text) || /404 Not Found/.test(text);
}

function checkPackageRegistry(name, version) {
  const metadata = npmJson(
    ["view", name, "name", "version", "dist-tags"],
    `npm view ${name}`,
    { allowFailure: true },
  );
  if (!metadata.ok || !metadata.value) {
    if (isNpmNotFound(metadata.result)) {
      pass(`${name} is not published yet`);
      pass(`${name}@${version} is not published yet`);
      info(`${name} has no latest dist-tag yet; it should become ${version} after first publish`);
      return;
    }
    fail(`${name} registry metadata lookup failed: ${String(metadata.result.stderr || metadata.result.stdout).trim()}`);
    return;
  }

  pass(`${name} resolves on npm`);
  const latest = metadata.value.version || (metadata.value["dist-tags"] && metadata.value["dist-tags"].latest);
  const localVersion = npmJson(
    ["view", `${name}@${version}`, "version"],
    `npm view ${name}@${version}`,
    { allowFailure: true },
  );
  const isPublished = localVersion.ok && localVersion.value === version;

  if (isPublished) {
    if (allowPublished) {
      pass(`${name}@${version} is already published and allowed for this check`);
    } else {
      fail(`${name}@${version} is already published; pass --allow-published when checking an existing release`);
    }
  } else {
    pass(`${name}@${version} is not published yet`);
  }

  if (latest === version) {
    pass(`${name} latest dist-tag matches ${version}`);
  } else if (isPublished) {
    fail(`${name} latest dist-tag is ${latest}; expected ${version}`);
  } else {
    info(`${name} latest dist-tag is ${latest}; it should become ${version} after publish`);
  }
}

function permissionText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(",");
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function hasReadWrite(value) {
  const text = permissionText(value);
  return text.includes("read-write") || (text.includes("read") && text.includes("write"));
}

function checkRegistry(rootPackage, wrapperPackages) {
  const whoami = npm(["whoami"]);
  if (whoami.status === 0 && String(whoami.stdout).trim()) {
    pass(`npm whoami succeeds as ${String(whoami.stdout).trim()}`);
  } else {
    fail(`npm whoami failed: ${String(whoami.stderr || whoami.stdout).trim()}`);
  }

  checkPackageRegistry(rootPackage.name, rootPackage.version);
  for (const { wrapperPackage } of wrapperPackages) {
    checkPackageRegistry(wrapperPackage.name, wrapperPackage.version);
  }

  const access = npm(["access", "list", "packages", "--json"]);
  if (access.status !== 0) {
    const allNames = [rootPackage.name, ...wrapperPackages.map(({ wrapperPackage }) => wrapperPackage.name)].join(", ");
    warn(`Could not verify npm read-write package access. Ensure the token can read and write ${allNames}.`);
    if (access.stderr) info(`npm access stderr: ${String(access.stderr).trim().slice(0, 500)}`);
    return;
  }

  const accessMap = parseJsonOutput(access, "npm access list packages");
  if (!accessMap) return;
  const names = [rootPackage.name, ...wrapperPackages.map(({ wrapperPackage }) => wrapperPackage.name)];
  for (const name of names) {
    if (hasReadWrite(accessMap[name])) {
      pass(`npm access lists ${name} as read-write`);
    } else {
      fail(`npm access does not list ${name} as read-write`);
    }
  }
}

function main() {
  console.log("Hacker Bob release check");
  if (registryMode) info("registry checks enabled");

  const { rootPackage, wrapperPackages } = checkManifest();
  checkCanonicalPack(rootPackage);
  for (const { spec } of wrapperPackages) {
    checkWrapperPack(spec, rootPackage);
  }

  if (registryMode) checkRegistry(rootPackage, wrapperPackages);

  if (failures > 0) {
    console.error(`Release check failed with ${failures} failure(s) and ${warnings} warning(s).`);
    process.exit(1);
  }
  console.log(`Release check passed with ${warnings} warning(s).`);
}

main();

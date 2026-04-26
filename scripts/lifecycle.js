"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  BOB_RESOURCE_DIR,
  NEUTRAL_INSTALL_SCHEMA_VERSION,
  RESOURCE_SETS,
  commandExists,
  detectInstalledAdapterIds,
  installedAdapterIds,
  neutralInstallMetadataPath,
  neutralVersionPath,
  patchrightAvailable,
} = require("./install.js");
const {
  adapterIdsForSelection,
  getAdapter,
} = require("../adapters/index.js");

const LEGACY_CLAUDE_RESOURCE_DIR = ".claude";
const ROOT_MCP_ADAPTER_IDS = Object.freeze(["claude", "generic-mcp"]);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function relativeDisplay(targetAbs, filePath) {
  const relative = path.relative(targetAbs, filePath);
  return relative && !relative.startsWith("..") ? relative : filePath;
}

function addCheck(checks, status, id, message, detail) {
  const check = { id, status, message };
  if (detail !== undefined) check.detail = detail;
  checks.push(check);
  return check;
}

function nodeMajor(version) {
  const major = String(version || "").split(".")[0];
  const parsed = Number.parseInt(major, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function fileExists(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function dirExists(dirPath) {
  try {
    return fs.statSync(dirPath).isDirectory();
  } catch {
    return false;
  }
}

function jsonReadCheck(checks, filePath, id, targetAbs) {
  if (!fileExists(filePath)) {
    addCheck(checks, "error", id, `${relativeDisplay(targetAbs, filePath)} is missing`);
    return null;
  }
  try {
    const value = readJson(filePath);
    addCheck(checks, "ok", id, `${relativeDisplay(targetAbs, filePath)} is valid JSON`);
    return value;
  } catch (error) {
    addCheck(
      checks,
      "error",
      id,
      `${relativeDisplay(targetAbs, filePath)} is not valid JSON`,
      { error: error.message || String(error) },
    );
    return null;
  }
}

function readVersionFile(filePath) {
  try {
    const value = fs.readFileSync(filePath, "utf8").trim();
    return value || null;
  } catch {
    return null;
  }
}

function addNeutralInstallChecks(checks, targetAbs, adapterIds) {
  const versionPath = neutralVersionPath(targetAbs);
  const legacyVersionPath = path.join(targetAbs, ".claude", "bob", "VERSION");
  const neutralVersion = readVersionFile(versionPath);
  const legacyVersion = readVersionFile(legacyVersionPath);
  let installedVersion = neutralVersion;

  if (neutralVersion) {
    addCheck(checks, "ok", "install_version", `Installed Bob version is ${neutralVersion}`, {
      installed_version: neutralVersion,
      path: relativeDisplay(targetAbs, versionPath),
    });
  } else if (fileExists(versionPath)) {
    addCheck(checks, "error", "install_version", `${relativeDisplay(targetAbs, versionPath)} is empty`);
  } else if (legacyVersion) {
    installedVersion = legacyVersion;
    addCheck(
      checks,
      "warn",
      "install_version",
      `Neutral install version is missing; using legacy ${relativeDisplay(targetAbs, legacyVersionPath)} fallback`,
      {
        installed_version: legacyVersion,
        expected: relativeDisplay(targetAbs, versionPath),
        legacy: relativeDisplay(targetAbs, legacyVersionPath),
      },
    );
  } else {
    addCheck(checks, "error", "install_version", `${relativeDisplay(targetAbs, versionPath)} is missing`);
  }

  const metadataPath = neutralInstallMetadataPath(targetAbs);
  const legacyMetadataPath = path.join(targetAbs, ".claude", "bob", "install.json");
  let metadata = null;
  if (fileExists(metadataPath)) {
    metadata = jsonReadCheck(checks, metadataPath, "install_metadata_json", targetAbs);
  } else if (fileExists(legacyMetadataPath)) {
    addCheck(
      checks,
      "warn",
      "install_metadata_json",
      `Neutral install metadata is missing; legacy ${relativeDisplay(targetAbs, legacyMetadataPath)} exists`,
      {
        expected: relativeDisplay(targetAbs, metadataPath),
        legacy: relativeDisplay(targetAbs, legacyMetadataPath),
      },
    );
    addCheck(checks, "warn", "install_metadata", "Install metadata is legacy; reinstall to write neutral adapter metadata");
  } else {
    addCheck(checks, "error", "install_metadata_json", `${relativeDisplay(targetAbs, metadataPath)} is missing`);
  }

  if (!metadata) return;

  const metadataErrors = [];
  if (metadata.schema_version !== NEUTRAL_INSTALL_SCHEMA_VERSION) {
    metadataErrors.push(`schema_version must be ${NEUTRAL_INSTALL_SCHEMA_VERSION}`);
  }
  if (!metadata.bob_version) metadataErrors.push("bob_version is missing");
  if (installedVersion && metadata.bob_version !== installedVersion) {
    metadataErrors.push("bob_version does not match VERSION");
  }
  if (metadata.install_target !== targetAbs) metadataErrors.push("install_target does not match this project");
  if (!metadata.package_name) metadataErrors.push("package_name is missing");
  let metadataAdapters = [];
  try {
    metadataAdapters = adapterIdsForSelection(metadata.installed_adapters || [], { defaultIds: [] });
  } catch (error) {
    metadataErrors.push(error.message || String(error));
  }
  if (metadataAdapters.length === 0) metadataErrors.push("installed_adapters is missing or empty");
  const missingAdapters = adapterIds.filter((id) => !metadataAdapters.includes(id));
  if (missingAdapters.length > 0) {
    metadataErrors.push(`installed_adapters is missing ${missingAdapters.join(", ")}`);
  }

  if (metadataErrors.length === 0) {
    addCheck(checks, "ok", "install_metadata", "Neutral install metadata matches this project", {
      installed_adapters: metadataAdapters,
    });
  } else {
    addCheck(checks, "error", "install_metadata", "Neutral install metadata is incomplete or mismatched", {
      errors: metadataErrors,
    });
  }
}

function expectedMcpServer(targetAbs) {
  return {
    command: "node",
    args: [path.join(targetAbs, "mcp", "server.js")],
  };
}

function loadServerCheck(serverPath) {
  const script = [
    "const server = require(process.argv[1]);",
    "if (!Array.isArray(server.TOOLS) || server.TOOLS.length === 0) process.exit(2);",
  ].join(" ");
  return spawnSync(process.execPath, ["-e", script, serverPath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function fileNamesInDir(targetAbs, relativeDir, predicate) {
  const dir = path.join(targetAbs, relativeDir);
  if (!dirExists(dir)) return [];
  return fs.readdirSync(dir)
    .sort()
    .filter((name) => fileExists(path.join(dir, name)))
    .filter((name) => !predicate || predicate(name));
}

function legacyResourceDir(resourceSet) {
  return path.join(LEGACY_CLAUDE_RESOURCE_DIR, path.basename(resourceSet.destination));
}

function resourceCheckId(resourceSet) {
  return `resource_${path.basename(resourceSet.destination).replace(/-/g, "_")}`;
}

function resourceLabel(resourceSet) {
  return path.basename(resourceSet.destination) === "knowledge" ? "hunter knowledge" : "bypass tables";
}

function addRuntimeResourceChecks(checks, targetAbs) {
  for (const resourceSet of RESOURCE_SETS) {
    const canonical = fileNamesInDir(targetAbs, resourceSet.destination, resourceSet.predicate);
    const legacyDir = legacyResourceDir(resourceSet);
    const legacy = fileNamesInDir(targetAbs, legacyDir, resourceSet.predicate);
    const id = resourceCheckId(resourceSet);
    const label = resourceLabel(resourceSet);
    if (canonical.length > 0) {
      addCheck(
        checks,
        "ok",
        id,
        `${resourceSet.destination} contains ${canonical.length} Bob ${label} file${canonical.length === 1 ? "" : "s"}`,
      );
    } else if (legacy.length > 0) {
      addCheck(
        checks,
        "warn",
        id,
        `Only legacy ${legacyDir} ${label} files were found; runtime fallback still works, but reinstall to write ${resourceSet.destination}`,
        {
          legacy: legacy.map((name) => path.join(legacyDir, name)),
          expected: resourceSet.destination,
        },
      );
    } else {
      addCheck(
        checks,
        "error",
        id,
        `Bob ${label} files are missing from ${resourceSet.destination}`,
      );
    }
  }
}

function httpxAvailable() {
  return commandExists("httpx") || fileExists(path.join(os.homedir(), "go", "bin", "httpx"));
}

function doctorProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const adapterIds = adapterIdsForSelection(options.adapter || options.adapters);
  const checks = [];

  if (nodeMajor(process.versions.node) >= 20) {
    addCheck(checks, "ok", "node_version", `Node.js ${process.versions.node} satisfies >=20`);
  } else {
    addCheck(checks, "error", "node_version", `Node.js ${process.versions.node} is below required >=20`);
  }

  if (!dirExists(targetAbs)) {
    addCheck(checks, "error", "target_directory", `${targetAbs} is not a directory`);
    return {
      ok: false,
      target: targetAbs,
      adapters: adapterIds,
      checks,
    };
  }
  addCheck(checks, "ok", "target_directory", `${targetAbs} is a directory`);

  for (const tool of ["curl", "python3"]) {
    if (commandExists(tool)) {
      addCheck(checks, "ok", `required_tool_${tool}`, `${tool} is available`);
    } else {
      addCheck(checks, "error", `required_tool_${tool}`, `${tool} is missing`);
    }
  }

  addNeutralInstallChecks(checks, targetAbs, adapterIds);

  for (const adapterId of adapterIds) {
    const adapter = getAdapter(adapterId);
    if (adapterId === "claude") {
      adapter.doctor({
        targetAbs,
        checks,
        addCheck,
        fileExists,
        idPrefix: "claude_",
        jsonReadCheck,
        relativeDisplay,
      });
    } else {
      const adapterResult = adapter.doctor({ targetAbs });
      checks.push(...adapterResult.checks);
    }
  }

  const serverPath = path.join(targetAbs, "mcp", "server.js");
  if (!fileExists(serverPath)) {
    addCheck(checks, "error", "mcp_server_file", "mcp/server.js is missing");
  } else {
    addCheck(checks, "ok", "mcp_server_file", "mcp/server.js is installed");
    const loadResult = loadServerCheck(serverPath);
    if (loadResult.status === 0) {
      addCheck(checks, "ok", "mcp_server_loadable", "mcp/server.js loads successfully");
    } else {
      addCheck(checks, "error", "mcp_server_loadable", "mcp/server.js failed to load", {
        exit_status: loadResult.status,
        stderr: (loadResult.stderr || "").trim(),
      });
    }
  }

  addRuntimeResourceChecks(checks, targetAbs);

  for (const tool of ["subfinder", "nuclei"]) {
    if (commandExists(tool)) {
      addCheck(checks, "ok", `optional_tool_${tool}`, `${tool} is available`);
    } else {
      addCheck(checks, "warn", `optional_tool_${tool}`, `${tool} is missing; related recon steps will be skipped`);
    }
  }

  if (httpxAvailable()) {
    addCheck(checks, "ok", "optional_tool_httpx", "httpx is available");
  } else {
    addCheck(checks, "warn", "optional_tool_httpx", "httpx is missing; related recon steps will be skipped");
  }

  if (patchrightAvailable(targetAbs, sourceRoot)) {
    addCheck(checks, "ok", "optional_patchright", "patchright is available");
  } else {
    addCheck(checks, "warn", "optional_patchright", "patchright is missing; Tier 2 auto-signup is disabled");
  }

  if (process.env.CAPSOLVER_API_KEY) {
    addCheck(checks, "ok", "optional_capsolver", "CAPSOLVER_API_KEY is set");
  } else {
    addCheck(checks, "warn", "optional_capsolver", "CAPSOLVER_API_KEY is not set; CAPTCHA solving is disabled");
  }

  return {
    ok: checks.every((check) => check.status !== "error"),
    target: targetAbs,
    adapters: adapterIds,
    checks,
  };
}

function printDoctorReport(result, stream = process.stdout) {
  stream.write(`Hacker Bob doctor: ${result.target}\n\n`);
  for (const check of result.checks) {
    stream.write(`${check.status.toUpperCase()}: ${check.id} - ${check.message}\n`);
    if (check.detail && check.detail.missing && check.detail.missing.length) {
      for (const missing of check.detail.missing) {
        stream.write(`  missing: ${missing}\n`);
      }
    }
    if (check.detail && check.detail.errors && check.detail.errors.length) {
      for (const error of check.detail.errors) {
        stream.write(`  error: ${error}\n`);
      }
    }
  }
  stream.write(`\n${result.ok ? "No required problems found." : "Required problems found."}\n`);
}

function sourceDirFiles(sourceRoot, relativeDir, predicate) {
  const dir = path.join(sourceRoot, relativeDir);
  if (!dirExists(dir)) return [];
  return fs.readdirSync(dir)
    .sort()
    .filter((name) => fileExists(path.join(dir, name)))
    .filter((name) => !predicate || predicate(name))
    .map((name) => path.join(relativeDir, name));
}

function sourceTreeFiles(sourceRoot, relativeDir) {
  const root = path.join(sourceRoot, relativeDir);
  if (!dirExists(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(sourceRoot, full));
      }
    }
  };
  visit(root);
  return files.sort();
}

function managedNeutralResourceFiles(sourceRoot) {
  return [
    path.join(BOB_RESOURCE_DIR, "VERSION"),
    path.join(BOB_RESOURCE_DIR, "install.json"),
    ...RESOURCE_SETS.flatMap((resourceSet) => sourceDirFiles(
      sourceRoot,
      resourceSet.source,
      resourceSet.predicate,
    )),
  ];
}

function managedLegacyResourceFiles(sourceRoot) {
  const files = [];
  for (const resourceSet of RESOURCE_SETS) {
    const legacyDir = legacyResourceDir(resourceSet);
    for (const relative of sourceDirFiles(sourceRoot, resourceSet.source, resourceSet.predicate)) {
      files.push(path.join(legacyDir, path.basename(relative)));
    }
    for (const relative of sourceDirFiles(sourceRoot, legacyDir, resourceSet.predicate)) {
      files.push(relative);
    }
  }
  return Array.from(new Set(files)).sort();
}

function managedRuntimeFiles(sourceRoot) {
  return sourceTreeFiles(sourceRoot, "mcp");
}

function maybeRemoveFile(targetAbs, relativePath, result) {
  const filePath = path.join(targetAbs, relativePath);
  if (!fs.existsSync(filePath)) return;
  const stat = fs.lstatSync(filePath);
  if (stat.isDirectory()) {
    result.skipped.push({ type: "file", path: relativePath, reason: "expected file but found directory" });
    return;
  }
  result.actions.push({ type: "remove_file", path: relativePath });
  if (!result.dry_run) fs.rmSync(filePath, { force: true });
}

function maybeRemoveEmptyDir(targetAbs, relativePath, result) {
  const dirPath = path.join(targetAbs, relativePath);
  if (!dirExists(dirPath)) return;
  if (fs.readdirSync(dirPath).length !== 0) return;
  result.actions.push({ type: "remove_empty_dir", path: relativePath });
  if (!result.dry_run) fs.rmdirSync(dirPath);
}

function appendAdapterUninstallResult(result, adapterResult) {
  if (!adapterResult) return;
  result.actions.push(...(adapterResult.actions || []));
  result.skipped.push(...(adapterResult.skipped || []));
  if (adapterResult.ok === false) result.ok = false;
}

function remainingAdapterIds(installedIds, selectedIds) {
  return installedIds.filter((id) => !selectedIds.includes(id));
}

function shouldPreserveRootMcpConfig(adapterId, remainingIds) {
  return ROOT_MCP_ADAPTER_IDS.includes(adapterId) &&
    remainingIds.some((id) => ROOT_MCP_ADAPTER_IDS.includes(id));
}

function updateNeutralMetadataAfterUninstall(targetAbs, remainingIds, result) {
  const metadataPath = neutralInstallMetadataPath(targetAbs);
  if (!fileExists(metadataPath)) return;
  let metadata;
  try {
    metadata = readJson(metadataPath);
  } catch (error) {
    result.skipped.push({
      type: "config",
      path: path.join(BOB_RESOURCE_DIR, "install.json"),
      reason: `invalid JSON: ${error.message || String(error)}`,
    });
    return;
  }

  const next = {
    ...metadata,
    updated_at: new Date().toISOString(),
    installed_adapters: adapterIdsForSelection(remainingIds, { defaultIds: [] }),
  };
  result.actions.push({ type: "update_config", path: path.join(BOB_RESOURCE_DIR, "install.json") });
  if (!result.dry_run) writeJson(metadataPath, next);
}

function pruneManagedDirs(targetAbs, result, { adapterIds, removeShared }) {
  const dirs = [];
  for (const adapterId of adapterIds) {
    const adapter = getAdapter(adapterId);
    if (typeof adapter.managedDirs === "function") dirs.push(...adapter.managedDirs());
  }
  if (removeShared) {
    dirs.push(
      path.join(BOB_RESOURCE_DIR, "bypass-tables"),
      path.join(BOB_RESOURCE_DIR, "knowledge"),
      BOB_RESOURCE_DIR,
      path.join("mcp", "lib", "tools"),
      path.join("mcp", "lib"),
      "mcp",
    );
  }

  for (const relativePath of dirs) {
    maybeRemoveEmptyDir(targetAbs, relativePath, result);
  }
}

function uninstallProject(projectDir, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot || path.join(__dirname, ".."));
  const targetAbs = path.resolve(projectDir || ".");
  const adapterIds = adapterIdsForSelection(options.adapter || options.adapters);
  if (!dirExists(targetAbs)) {
    throw new Error(`Uninstall target does not exist or is not a directory: ${targetAbs}`);
  }
  const installedBefore = adapterIdsForSelection([
    ...installedAdapterIds(targetAbs),
    ...detectInstalledAdapterIds(targetAbs),
    ...adapterIds,
  ], { defaultIds: [] });
  const remainingIds = remainingAdapterIds(installedBefore, adapterIds);
  const removeShared = remainingIds.length === 0;
  const result = {
    ok: true,
    dry_run: options.dryRun !== false,
    target: targetAbs,
    adapters: adapterIds,
    remaining_adapters: remainingIds,
    remove_shared: removeShared,
    actions: [],
    skipped: [],
  };

  for (const adapterId of adapterIds) {
    const adapter = getAdapter(adapterId);
    const preserveMcpConfig = shouldPreserveRootMcpConfig(adapterId, remainingIds);
    if (adapterId === "claude") {
      adapter.uninstall({
        sourceRoot,
        targetAbs,
        result,
        helpers: {
          fileExists,
          maybeRemoveFile,
          readJson,
          writeJson,
        },
        preserveMcpConfig,
      });
    } else if (adapterId === "generic-mcp") {
      appendAdapterUninstallResult(result, adapter.uninstall({
        targetAbs,
        dryRun: result.dry_run,
        preserveMcpConfig,
      }));
    } else {
      appendAdapterUninstallResult(result, adapter.uninstall({
        sourceRoot,
        targetAbs,
        dryRun: result.dry_run,
      }));
    }
  }

  if (removeShared) {
    for (const relativePath of [
      ...managedNeutralResourceFiles(sourceRoot),
      ...managedRuntimeFiles(sourceRoot),
    ]) {
      maybeRemoveFile(targetAbs, relativePath, result);
    }
  } else {
    updateNeutralMetadataAfterUninstall(targetAbs, remainingIds, result);
  }
  if (removeShared || adapterIds.includes("claude")) {
    for (const relativePath of managedLegacyResourceFiles(sourceRoot)) {
      maybeRemoveFile(targetAbs, relativePath, result);
    }
  }

  pruneManagedDirs(targetAbs, result, { adapterIds, removeShared });
  return result;
}

function printUninstallReport(result, stream = process.stdout) {
  stream.write(`Hacker Bob uninstall: ${result.target}\n`);
  stream.write(result.dry_run ? "Mode: dry-run (pass --yes to remove)\n\n" : "Mode: remove\n\n");
  if (result.actions.length === 0) {
    stream.write("No Bob-managed files or config entries found.\n");
  } else {
    for (const action of result.actions) {
      stream.write(`${result.dry_run ? "WOULD " : ""}${action.type}: ${action.path}\n`);
    }
  }
  if (result.skipped.length > 0) {
    stream.write("\nSkipped:\n");
    for (const skipped of result.skipped) {
      stream.write(`SKIP ${skipped.type}: ${skipped.path} (${skipped.reason})\n`);
    }
  }
}

module.exports = {
  doctorProject,
  expectedMcpServer,
  managedLegacyResourceFiles,
  managedNeutralResourceFiles,
  managedRuntimeFiles,
  printDoctorReport,
  printUninstallReport,
  uninstallProject,
};

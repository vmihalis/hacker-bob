"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const vm = require("node:vm");

const INSPECTION_MODE = "static_manifest_digest_commonjs_syntax_v1";
const BOB_OWNED_RUNTIME_INSPECTION_MODE = "static_bob_owned_runtime_manifest_v1";
const MAX_SERVER_BYTES = 2 * 1024 * 1024;
const MAX_RUNTIME_MANIFEST_ENTRIES = 1024;
const MAX_RUNTIME_TREE_ENTRIES = 2048;
const MAX_RUNTIME_PATH_BYTES = 512;
const MAX_RUNTIME_PATH_DEPTH = 24;
const MAX_RUNTIME_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_RUNTIME_DIAGNOSTICS = 64;
const RUNTIME_PATH_COMPONENT_PATTERN = /^[A-Za-z0-9._@+-]+$/u;

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function readStableRegularFile(filePath) {
  let before;
  try {
    before = fs.lstatSync(filePath, { bigint: true });
  } catch {
    return { ok: false, reason_code: "file_unreadable" };
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    return { ok: false, reason_code: "file_type_rejected" };
  }
  if (before.size < 1n || before.size > BigInt(MAX_SERVER_BYTES)) {
    return { ok: false, reason_code: "file_size_rejected" };
  }

  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(before, opened)) {
      return { ok: false, reason_code: "file_identity_changed" };
    }
    const contents = fs.readFileSync(descriptor);
    const afterDescriptor = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filePath, { bigint: true });
    if (!sameIdentity(opened, afterDescriptor)
        || !sameIdentity(afterDescriptor, afterPath)
        || BigInt(contents.length) !== opened.size) {
      return { ok: false, reason_code: "file_identity_changed" };
    }
    return {
      ok: true,
      contents,
      mode: Number(opened.mode & 0o777n),
      size: Number(opened.size),
    };
  } catch {
    return { ok: false, reason_code: "file_unreadable" };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function commonJsSyntaxValid(contents, filename) {
  let source = contents.toString("utf8");
  if (source.charCodeAt(0) === 0xFEFF) source = source.slice(1);
  if (source.startsWith("#!")) source = `//${source.slice(2)}`;
  try {
    // Compile the CommonJS wrapper only. vm.Script does not evaluate the body,
    // resolve imports, initialize globals, or run any installed target code.
    new vm.Script(Module.wrap(source), { filename, displayErrors: false });
    return true;
  } catch {
    return false;
  }
}

function result(fields) {
  return {
    ok: false,
    validation_mode: INSPECTION_MODE,
    manifest_valid: false,
    digest_valid: false,
    syntax_valid: false,
    ...fields,
  };
}

function inspectMcpServerStatically({ sourceRoot, serverPath, runtimeManifest }) {
  const manifest = Array.isArray(runtimeManifest) ? [...runtimeManifest] : [];
  const manifestValid = typeof sourceRoot === "string"
    && typeof serverPath === "string"
    && manifest.every((entry) => (
      typeof entry === "string"
      && /^[a-z0-9][a-z0-9.-]*\.js$/u.test(entry)
      && path.basename(entry) === entry
    ))
    && new Set(manifest).size === manifest.length
    && manifest.filter((entry) => entry === "server.js").length === 1;
  const manifestSha256 = sha256(Buffer.from(JSON.stringify(manifest), "utf8"));
  if (!manifestValid) {
    return result({
      reason_code: "runtime_manifest_rejected",
      manifest_sha256: manifestSha256,
    });
  }

  const expectedPath = path.join(path.resolve(sourceRoot), "mcp", "server.js");
  const expected = readStableRegularFile(expectedPath);
  if (!expected.ok) {
    return result({
      reason_code: "trusted_source_server_rejected",
      manifest_valid: true,
      manifest_sha256: manifestSha256,
    });
  }
  const installed = readStableRegularFile(serverPath);
  if (!installed.ok) {
    return result({
      reason_code: `installed_server_${installed.reason_code}`,
      manifest_valid: true,
      manifest_sha256: manifestSha256,
      expected_sha256: sha256(expected.contents),
    });
  }

  const expectedSha256 = sha256(expected.contents);
  const observedSha256 = sha256(installed.contents);
  const syntaxValid = commonJsSyntaxValid(installed.contents, serverPath);
  const digestValid = observedSha256 === expectedSha256;
  if (!syntaxValid) {
    return result({
      reason_code: "installed_server_syntax_rejected",
      manifest_valid: true,
      digest_valid: digestValid,
      syntax_valid: false,
      manifest_sha256: manifestSha256,
      expected_sha256: expectedSha256,
      observed_sha256: observedSha256,
      byte_size: installed.contents.length,
    });
  }
  if (!digestValid) {
    return result({
      reason_code: "installed_server_digest_mismatch",
      manifest_valid: true,
      digest_valid: false,
      syntax_valid: true,
      manifest_sha256: manifestSha256,
      expected_sha256: expectedSha256,
      observed_sha256: observedSha256,
      byte_size: installed.contents.length,
    });
  }
  return result({
    ok: true,
    reason_code: "static_validation_complete",
    manifest_valid: true,
    digest_valid: true,
    syntax_valid: true,
    manifest_sha256: manifestSha256,
    expected_sha256: expectedSha256,
    observed_sha256: observedSha256,
    byte_size: installed.contents.length,
  });
}

function normalizeRelativeRuntimePath(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_RUNTIME_PATH_BYTES
      || value.startsWith("/") || value.includes("\\") || value.includes("\0")
      || value.includes("//")) return null;
  const components = value.split("/");
  if (components.length < 2 || components.length > MAX_RUNTIME_PATH_DEPTH) return null;
  for (const component of components) {
    if (component === "." || component === ".."
        || !RUNTIME_PATH_COMPONENT_PATTERN.test(component)) return null;
  }
  return components.join("/");
}

function runtimeAbsolutePath(root, relativePath) {
  return path.join(path.resolve(root), ...relativePath.split("/"));
}

function runtimeFileProjection(relativePath, stable) {
  return Object.freeze({
    path: relativePath,
    type: "file",
    mode: stable.mode,
    byte_size: stable.size,
    sha256: sha256(stable.contents),
  });
}

function manifestDigest(entries) {
  return sha256(Buffer.from(JSON.stringify({
    schema_version: 1,
    coverage: "bob_owned_runtime_only",
    entries,
  }), "utf8"));
}

function expectedRuntimeDirectories(runtimeFiles, ownedRoots) {
  const directories = new Set();
  for (const file of runtimeFiles) {
    for (const root of ownedRoots) {
      if (!file.startsWith(`${root}/`)) continue;
      const components = file.split("/");
      const rootDepth = root.split("/").length;
      for (let depth = rootDepth + 1; depth < components.length; depth += 1) {
        directories.add(components.slice(0, depth).join("/"));
      }
    }
  }
  return directories;
}

function statType(stat) {
  if (stat.isSymbolicLink()) return "symlink";
  if (stat.isDirectory()) return "directory";
  if (stat.isFile()) return "file";
  if (stat.isSocket()) return "socket";
  if (stat.isFIFO()) return "fifo";
  if (stat.isCharacterDevice()) return "character_device";
  if (stat.isBlockDevice()) return "block_device";
  return "unknown";
}

function inspectOwnedTree(targetRoot, relativeRoot, budget) {
  const files = new Set();
  const directories = new Set();
  const nonRegular = new Map();
  const absoluteRoot = runtimeAbsolutePath(targetRoot, relativeRoot);

  let rootBefore;
  try {
    rootBefore = fs.lstatSync(absoluteRoot, { bigint: true });
  } catch (error) {
    nonRegular.set(relativeRoot, error && error.code === "ENOENT" ? "missing" : "unreadable");
    return { files, directories, nonRegular };
  }
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink()) {
    nonRegular.set(relativeRoot, statType(rootBefore));
    return { files, directories, nonRegular };
  }

  const visit = (absoluteDirectory, relativeDirectory, depth) => {
    if (depth > MAX_RUNTIME_PATH_DEPTH) throw new Error("runtime_tree_depth_rejected");
    let before;
    let names;
    try {
      before = fs.lstatSync(absoluteDirectory, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink()) {
        nonRegular.set(relativeDirectory, statType(before));
        return;
      }
      names = fs.readdirSync(absoluteDirectory).sort();
    } catch {
      throw new Error("runtime_tree_probe_rejected");
    }
    for (const name of names) {
      budget.entries += 1;
      if (budget.entries > MAX_RUNTIME_TREE_ENTRIES) {
        throw new Error("runtime_tree_entry_bound_exceeded");
      }
      if (!RUNTIME_PATH_COMPONENT_PATTERN.test(name) || name === "." || name === "..") {
        throw new Error("runtime_tree_path_rejected");
      }
      const absolute = path.join(absoluteDirectory, name);
      const relative = `${relativeDirectory}/${name}`;
      let stat;
      try {
        stat = fs.lstatSync(absolute, { bigint: true });
      } catch {
        throw new Error("runtime_tree_probe_rejected");
      }
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        directories.add(relative);
        visit(absolute, relative, depth + 1);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        files.add(relative);
      } else {
        nonRegular.set(relative, statType(stat));
      }
    }
    let after;
    try {
      after = fs.lstatSync(absoluteDirectory, { bigint: true });
    } catch {
      throw new Error("runtime_tree_probe_rejected");
    }
    if (!sameIdentity(before, after)) throw new Error("runtime_tree_identity_changed");
  };

  visit(absoluteRoot, relativeRoot, relativeRoot.split("/").length);
  let rootAfter;
  try {
    rootAfter = fs.lstatSync(absoluteRoot, { bigint: true });
  } catch {
    throw new Error("runtime_tree_probe_rejected");
  }
  if (!sameIdentity(rootBefore, rootAfter)) throw new Error("runtime_tree_identity_changed");
  return { files, directories, nonRegular };
}

function bobOwnedRuntimeResult(fields = {}) {
  return {
    ok: false,
    validation_mode: BOB_OWNED_RUNTIME_INSPECTION_MODE,
    coverage: "bob_owned_runtime_only",
    manifest_valid: false,
    manifest_sha256: null,
    entry_count: 0,
    owned_root_count: 0,
    issue_counts: Object.freeze({}),
    ...fields,
  };
}

function inspectBobOwnedRuntimeStatically({
  sourceRoot,
  targetRoot,
  runtimeFiles,
  ownedRoots,
}) {
  if (typeof sourceRoot !== "string" || typeof targetRoot !== "string"
      || !Array.isArray(runtimeFiles) || !Array.isArray(ownedRoots)
      || runtimeFiles.length < 1 || runtimeFiles.length > MAX_RUNTIME_MANIFEST_ENTRIES
      || ownedRoots.length < 1 || ownedRoots.length > 32) {
    return bobOwnedRuntimeResult({ reason_code: "runtime_manifest_rejected" });
  }

  const normalizedFiles = runtimeFiles.map(normalizeRelativeRuntimePath);
  const normalizedRoots = ownedRoots.map(normalizeRelativeRuntimePath);
  if (normalizedFiles.some((entry) => entry == null)
      || normalizedRoots.some((entry) => entry == null)
      || new Set(normalizedFiles).size !== normalizedFiles.length
      || new Set(normalizedRoots).size !== normalizedRoots.length) {
    return bobOwnedRuntimeResult({ reason_code: "runtime_manifest_rejected" });
  }
  normalizedFiles.sort();
  normalizedRoots.sort();
  for (let left = 0; left < normalizedRoots.length; left += 1) {
    for (let right = left + 1; right < normalizedRoots.length; right += 1) {
      if (normalizedRoots[right].startsWith(`${normalizedRoots[left]}/`)) {
        return bobOwnedRuntimeResult({ reason_code: "runtime_manifest_rejected" });
      }
    }
  }
  for (const root of normalizedRoots) {
    if (!normalizedFiles.some((file) => file.startsWith(`${root}/`))) {
      return bobOwnedRuntimeResult({ reason_code: "runtime_manifest_rejected" });
    }
  }

  const entries = [];
  let totalBytes = 0;
  for (const relativePath of normalizedFiles) {
    const source = readStableRegularFile(runtimeAbsolutePath(sourceRoot, relativePath));
    if (!source.ok) {
      return bobOwnedRuntimeResult({
        reason_code: "trusted_source_runtime_rejected",
        source_issue: Object.freeze({ path: relativePath, reason_code: source.reason_code }),
      });
    }
    totalBytes += source.size;
    if (totalBytes > MAX_RUNTIME_TOTAL_BYTES) {
      return bobOwnedRuntimeResult({ reason_code: "runtime_manifest_byte_bound_exceeded" });
    }
    if (relativePath.endsWith(".js")
        && !commonJsSyntaxValid(source.contents, relativePath)) {
      return bobOwnedRuntimeResult({
        reason_code: "trusted_source_runtime_syntax_rejected",
        source_issue: Object.freeze({ path: relativePath, reason_code: "commonjs_syntax_invalid" }),
      });
    }
    entries.push(runtimeFileProjection(relativePath, source));
  }
  Object.freeze(entries);
  const expectedFileSet = new Set(normalizedFiles);
  const expectedDirectorySet = expectedRuntimeDirectories(normalizedFiles, normalizedRoots);
  const digest = manifestDigest(entries);

  const issueNames = [
    "missing",
    "extra",
    "non_regular",
    "mode_mismatch",
    "size_mismatch",
    "digest_mismatch",
    "syntax_invalid",
  ];
  const diagnostics = Object.fromEntries(issueNames.map((name) => [name, []]));
  const issueCounts = Object.fromEntries(issueNames.map((name) => [name, 0]));
  const addIssue = (name, value) => {
    issueCounts[name] += 1;
    if (diagnostics[name].length < MAX_RUNTIME_DIAGNOSTICS) diagnostics[name].push(value);
  };

  let observedFiles = new Set();
  let observedDirectories = new Set();
  const treeBudget = { entries: 0 };
  try {
    for (const relativeRoot of normalizedRoots) {
      const observed = inspectOwnedTree(targetRoot, relativeRoot, treeBudget);
      observedFiles = new Set([...observedFiles, ...observed.files]);
      observedDirectories = new Set([...observedDirectories, ...observed.directories]);
      for (const [relativePath, type] of observed.nonRegular) {
        addIssue("non_regular", Object.freeze({ path: relativePath, observed_type: type }));
      }
    }
  } catch (error) {
    return bobOwnedRuntimeResult({
      reason_code: error && error.message ? error.message : "runtime_tree_probe_rejected",
      manifest_valid: true,
      manifest_sha256: digest,
      entry_count: entries.length,
      owned_root_count: normalizedRoots.length,
    });
  }

  for (const observed of observedFiles) {
    if (!expectedFileSet.has(observed)) addIssue("extra", observed);
  }
  for (const observed of observedDirectories) {
    if (!expectedDirectorySet.has(observed)) addIssue("extra", observed);
  }
  for (const entry of entries) {
    if (!normalizedRoots.some((root) => entry.path.startsWith(`${root}/`))) continue;
    if (!observedFiles.has(entry.path)) {
      addIssue("missing", entry.path);
      continue;
    }
    const installed = readStableRegularFile(runtimeAbsolutePath(targetRoot, entry.path));
    if (!installed.ok) {
      addIssue("non_regular", Object.freeze({
        path: entry.path,
        observed_type: installed.reason_code,
      }));
      continue;
    }
    if (installed.mode !== entry.mode) {
      addIssue("mode_mismatch", Object.freeze({
        path: entry.path,
        expected_mode: entry.mode.toString(8).padStart(3, "0"),
        observed_mode: installed.mode.toString(8).padStart(3, "0"),
      }));
    }
    if (installed.size !== entry.byte_size) {
      addIssue("size_mismatch", entry.path);
    }
    if (sha256(installed.contents) !== entry.sha256) {
      addIssue("digest_mismatch", entry.path);
    }
    if (entry.path.endsWith(".js")
        && !commonJsSyntaxValid(installed.contents, entry.path)) {
      addIssue("syntax_invalid", entry.path);
    }
  }
  for (const file of normalizedFiles) {
    if (normalizedRoots.some((root) => file.startsWith(`${root}/`))) continue;
    const installed = readStableRegularFile(runtimeAbsolutePath(targetRoot, file));
    if (!installed.ok) {
      addIssue(installed.reason_code === "file_type_rejected" ? "non_regular" : "missing",
        installed.reason_code === "file_type_rejected"
          ? Object.freeze({ path: file, observed_type: installed.reason_code })
          : file);
      continue;
    }
    const entry = entries.find((candidate) => candidate.path === file);
    if (installed.mode !== entry.mode) {
      addIssue("mode_mismatch", Object.freeze({
        path: file,
        expected_mode: entry.mode.toString(8).padStart(3, "0"),
        observed_mode: installed.mode.toString(8).padStart(3, "0"),
      }));
    }
    if (installed.size !== entry.byte_size) addIssue("size_mismatch", file);
    if (sha256(installed.contents) !== entry.sha256) addIssue("digest_mismatch", file);
    if (file.endsWith(".js") && !commonJsSyntaxValid(installed.contents, file)) {
      addIssue("syntax_invalid", file);
    }
  }

  const issueCount = Object.values(issueCounts).reduce((sum, count) => sum + count, 0);
  for (const values of Object.values(diagnostics)) Object.freeze(values);
  Object.freeze(diagnostics);
  Object.freeze(issueCounts);
  return bobOwnedRuntimeResult({
    ok: issueCount === 0,
    reason_code: issueCount === 0
      ? "static_bob_owned_runtime_validation_complete"
      : "installed_bob_owned_runtime_rejected",
    manifest_valid: true,
    manifest_sha256: digest,
    entry_count: entries.length,
    owned_root_count: normalizedRoots.length,
    total_source_bytes: totalBytes,
    issue_counts: issueCounts,
    diagnostics,
    diagnostic_limit: MAX_RUNTIME_DIAGNOSTICS,
  });
}

module.exports = {
  BOB_OWNED_RUNTIME_INSPECTION_MODE,
  INSPECTION_MODE,
  inspectBobOwnedRuntimeStatically,
  inspectMcpServerStatically,
};

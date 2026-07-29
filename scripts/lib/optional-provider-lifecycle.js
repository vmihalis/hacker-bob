"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  analyzeClosedCommonjsSource,
} = require("./closed-commonjs-loader.js");

const {
  evaluateNativePrebuildDoctorV2,
  verifyReleaseEnvelopeV2,
} = require("../../packages/bob-instrument-native-prebuild-trust/lib/index.js");
const {
  verifyJavascriptWorkerClosureEnvelope,
} = require("../../packages/bob-instrument-native-prebuild-trust/lib/javascript-worker-closure.js");
const {
  OPTIONAL_PROVIDER_REGISTRY,
  OPTIONAL_PROVIDER_REGISTRY_VERSION,
  getOptionalProviderPackage,
} = require("./optional-provider-registry.js");
const {
  executeLifecycleMutation,
  lifecycleCustodianTargetSnapshot,
  withLifecycleCustodianTarget,
} = require("./lifecycle-custodian.js");

const OPTIONAL_PACKAGE_METADATA_FILE = ".bob-optional-package.json";
const OPTIONAL_PACKAGE_METADATA_VERSION = 3;
const MAX_PACKAGE_FILES = 128;
const MAX_PACKAGE_BYTES = 512 * 1024 * 1024;
const MAX_WORKER_FILE_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 256 * 1024;
const INSTALL_MODE_READ_ONLY = 0o444;
const INSTALL_MODE_EXECUTABLE = 0o555;
const LIFECYCLE_SCRIPT_NAMES = Object.freeze([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
]);
const METADATA_FIELDS = Object.freeze([
  "schema_version",
  "registry_version",
  "provider_id",
  "package_id",
  "package_name",
  "package_version",
  "surface_policy",
  "content_digest",
  "release_manifest_digest",
  "release_id",
  "release_epoch",
  "release_envelope_digest",
  "release_trust_policy_digest",
  "release_key_id",
  "release_public_key_digest",
  "release_trust_epoch",
  "release_revocation_epoch",
  "files",
  "installed_at",
]);
const FILE_RECORD_FIELDS = Object.freeze(["path", "byte_size", "sha256", "mode"]);
const PACKAGE_NAME_PATTERN = /^@hacker-bob\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const POSIX_COMPONENT_PATTERN = /^(?:@[A-Za-z0-9][A-Za-z0-9._+-]{0,127}|[A-Za-z0-9][A-Za-z0-9._@+-]{0,127})$/u;
const WORKER_PACKAGE_ROOT = "worker";
const WORKER_CLOSURE_BUILTIN_IDS = Object.freeze([
  "node:crypto", "node:fs", "node:path", "node:util",
]);
const WORKER_CLOSURE_BUILTINS = Object.freeze(new Set(
  WORKER_CLOSURE_BUILTIN_IDS.map((value) => value.slice(5)),
));

const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpTest = RegExp.prototype.test;
const cryptoCreateHash = crypto.createHash;
const hashPrototype = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;

function lifecycleError(reasonCode = "package_rejected") {
  const error = new Error("Optional provider package lifecycle was rejected");
  Object.defineProperty(error, "code", {
    value: "optional_provider_package_rejected",
    enumerable: false,
  });
  Object.defineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw lifecycleError(reasonCode);
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  for (const key of reflectOwnKeys(value)) {
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      return false;
    }
  }
  return true;
}

function assertExactObject(value, fields, reasonCode = "schema_invalid") {
  if (!isPlainDataObject(value) || reflectOwnKeys(value).length !== fields.length) {
    reject(reasonCode);
  }
  for (const field of fields) {
    if (!reflectApply(objectHasOwnProperty, value, [field])) reject(reasonCode);
  }
  return value;
}

function own(value, field, reasonCode = "schema_invalid") {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
    reject(reasonCode);
  }
  return descriptor.value;
}

function assertString(value, pattern, reasonCode) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512
      || (pattern && !reflectApply(regexpTest, pattern, [value]))) reject(reasonCode);
  return value;
}

function assertDigest(value, reasonCode = "metadata_invalid") {
  return assertString(value, DIGEST_PATTERN, reasonCode);
}

function normalizeRelativePath(value, reasonCode = "package_surface_invalid") {
  assertString(value, null, reasonCode);
  if (value.startsWith("/") || value.includes("\\") || value.includes("//")
      || value.includes("\0")) reject(reasonCode);
  const components = value.split("/");
  if (components.length < 1 || components.length > 16) reject(reasonCode);
  for (const component of components) {
    if (component === "." || component === ".."
        || !reflectApply(regexpTest, POSIX_COMPONENT_PATTERN, [component])) reject(reasonCode);
  }
  return components.join("/");
}

function sha256Buffer(value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [value]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function nodeMajor(version) {
  const match = /^(\d+)\./u.exec(String(version || ""));
  return match ? Number.parseInt(match[1], 10) : 0;
}

function defaultHost() {
  return Object.freeze({
    os: process.platform,
    architecture: process.arch,
    node_major: nodeMajor(process.versions.node),
    napi_version: Number.parseInt(process.versions.napi || "0", 10) || 0,
  });
}

function normalizeHost(input) {
  if (input == null) return defaultHost();
  assertExactObject(input, ["os", "architecture", "node_major", "napi_version"],
    "host_invalid");
  const host = {
    os: assertString(own(input, "os", "host_invalid"), /^[a-z0-9_-]{1,32}$/u,
      "host_invalid"),
    architecture: assertString(own(input, "architecture", "host_invalid"),
      /^[a-z0-9_-]{1,32}$/u, "host_invalid"),
    node_major: own(input, "node_major", "host_invalid"),
    napi_version: own(input, "napi_version", "host_invalid"),
  };
  if (!Number.isSafeInteger(host.node_major) || !Number.isSafeInteger(host.napi_version)
      || host.node_major < 1 || host.napi_version < 0) reject("host_invalid");
  return Object.freeze(host);
}

function hostCompatibility(packageRecord, host) {
  const diagnostics = Object.freeze({
    platform: packageRecord.target_os === "any" || packageRecord.target_os === host.os,
    architecture: packageRecord.target_architecture === "any"
      || packageRecord.target_architecture === host.architecture,
    node_major: packageRecord.node_major === host.node_major,
    napi: packageRecord.napi_version === null
      || packageRecord.napi_version === host.napi_version,
  });
  let reasonCode = "host_supported";
  if (!diagnostics.platform) reasonCode = "platform_unsupported";
  else if (!diagnostics.architecture) reasonCode = "architecture_unsupported";
  else if (!diagnostics.node_major) reasonCode = "node_major_unsupported";
  else if (!diagnostics.napi) reasonCode = "napi_version_unsupported";
  return Object.freeze({
    supported: diagnostics.platform && diagnostics.architecture
      && diagnostics.node_major && diagnostics.napi,
    reason_code: reasonCode,
    diagnostics,
    expected: Object.freeze({
      os: packageRecord.target_os,
      architecture: packageRecord.target_architecture,
      node_major: packageRecord.node_major,
      napi_version: packageRecord.napi_version,
    }),
    actual: host,
  });
}

function packagePaths(targetAbs, provider, packageRecord) {
  const providerRoot = path.join(targetAbs, ...provider.owned_root.split("/"));
  const transactionStem = packageRecord.package_id;
  return {
    providerRoot,
    packageRoot: path.join(providerRoot, packageRecord.owned_subdirectory),
    stagingRoot: path.join(providerRoot, `.staging-${transactionStem}`),
    backupRoot: path.join(providerRoot, `.backup-${transactionStem}`),
    transactionFile: path.join(providerRoot, `.transaction-${transactionStem}.json`),
    transactionTempFile: path.join(providerRoot, `.transaction-${transactionStem}.json.tmp`),
  };
}

function safeLstat(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    reject("filesystem_probe_failed");
  }
}

function sameFilesystemIdentity(left, right) {
  return left != null && right != null && left.dev === right.dev && left.ino === right.ino;
}

function retainDirectoryAncestry(
  directoryPath,
  reasonCode = "directory_ancestry_rejected",
  options = {},
) {
  const records = [];
  const retained = new Set();
  const expectedRootIdentity = options.expectedRootIdentity || null;
  const rootPath = path.resolve(directoryPath);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
    | (fs.constants.O_NOFOLLOW || 0);
  let closed = false;

  const revalidate = () => {
    if (closed) reject(reasonCode);
    for (const record of records) {
      let descriptorStat;
      let pathStat;
      try {
        descriptorStat = fs.fstatSync(record.descriptor);
        pathStat = fs.lstatSync(record.path);
      } catch {
        reject(reasonCode);
      }
      if (!descriptorStat.isDirectory() || !pathStat.isDirectory()
          || pathStat.isSymbolicLink()
          || !sameFilesystemIdentity(descriptorStat, record.identity)
          || !sameFilesystemIdentity(pathStat, record.identity)) reject(reasonCode);
    }
  };

  const add = (candidate) => {
    const absolute = path.resolve(candidate);
    if (retained.has(absolute)) return;
    const before = safeLstat(absolute);
    if (!before || !before.isDirectory() || before.isSymbolicLink()) reject(reasonCode);
    let descriptor;
    try {
      descriptor = fs.openSync(absolute, flags);
      const opened = fs.fstatSync(descriptor);
      const after = fs.lstatSync(absolute);
      if (!opened.isDirectory() || !after.isDirectory() || after.isSymbolicLink()
          || !sameFilesystemIdentity(before, opened)
          || !sameFilesystemIdentity(opened, after)
          || (absolute === rootPath && expectedRootIdentity != null
            && !sameFilesystemIdentity(opened, expectedRootIdentity))) reject(reasonCode);
      records.push({
        path: absolute,
        descriptor,
        identity: Object.freeze({ dev: opened.dev, ino: opened.ino }),
      });
      retained.add(absolute);
      descriptor = undefined;
    } catch (error) {
      if (error && error.code === "optional_provider_package_rejected") throw error;
      reject(reasonCode);
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    revalidate();
  };

  const close = () => {
    if (closed) return;
    closed = true;
    for (let index = records.length - 1; index >= 0; index -= 1) {
      try {
        fs.closeSync(records[index].descriptor);
      } catch {
        // The operation already failed closed; descriptor cleanup is best effort.
      }
    }
  };

  const sync = () => {
    revalidate();
    try {
      const start = Math.max(0, records.length - 2);
      for (let index = start; index < records.length; index += 1) {
        fs.fsyncSync(records[index].descriptor);
      }
    } catch {
      reject(reasonCode);
    }
    revalidate();
  };

  try {
    // The caller supplies the trusted operation anchor (project target, source
    // package root, or retained Bob-owned parent). Track that anchor and every
    // descendant directory touched by the operation. System-level ancestors
    // such as macOS /var -> /private/var remain outside Bob's ownership scope.
    add(path.resolve(directoryPath));
    return Object.freeze({ add, close, revalidate, sync });
  } catch (error) {
    close();
    throw error;
  }
}

function readRegularFileNoFollow(filePath, maximumBytes) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    const pathBefore = fs.lstatSync(filePath);
    if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) reject("package_file_invalid");
    descriptor = fs.openSync(filePath, flags);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameFilesystemIdentity(pathBefore, before)
        || before.size < 0 || before.size > maximumBytes) {
      reject("package_file_invalid");
    }
    const contents = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const pathAfter = fs.lstatSync(filePath);
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino
        || after.size !== before.size || after.mtimeMs !== before.mtimeMs
        || after.mode !== before.mode || after.ctimeMs !== before.ctimeMs
        || !pathAfter.isFile() || pathAfter.isSymbolicLink()
        || !sameFilesystemIdentity(after, pathAfter)
        || pathAfter.mode !== before.mode
        || contents.length !== before.size) reject("package_file_unstable");
    return contents;
  } catch (error) {
    if (error && error.code === "optional_provider_package_rejected") throw error;
    reject("package_file_invalid");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function collectPackageFiles(root, options = {}) {
  const guard = retainDirectoryAncestry(root, "package_ancestry_rejected");
  const files = [];
  let totalBytes = 0;
  const visit = (current, relativeParent) => {
    guard.add(current);
    guard.revalidate();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true }).sort((left, right) =>
        left.name.localeCompare(right.name));
    } catch {
      reject("package_walk_failed");
    }
    guard.revalidate();
    for (const entry of entries) {
      const relative = relativeParent ? `${relativeParent}/${entry.name}` : entry.name;
      if (relative !== OPTIONAL_PACKAGE_METADATA_FILE) normalizeRelativePath(relative);
      const absolute = path.join(current, entry.name);
      guard.revalidate();
      const stat = safeLstat(absolute);
      if (!stat || stat.isSymbolicLink()) reject("package_symlink_rejected");
      if (stat.isDirectory()) {
        guard.add(absolute);
        visit(absolute, relative);
        continue;
      }
      if (!stat.isFile()) reject("package_file_invalid");
      if (relative === OPTIONAL_PACKAGE_METADATA_FILE && options.allowMetadata !== true) {
        reject("injected_metadata_rejected");
      }
      const maximum = options.maximumFileBytes || 256 * 1024 * 1024;
      const contents = readRegularFileNoFollow(absolute, maximum);
      const stableStat = safeLstat(absolute);
      if (!stableStat || !sameFilesystemIdentity(stat, stableStat)
          || stableStat.mode !== stat.mode || stableStat.size !== stat.size
          || stableStat.mtimeMs !== stat.mtimeMs) reject("package_file_unstable");
      guard.revalidate();
      totalBytes += contents.length;
      if (files.length >= MAX_PACKAGE_FILES || totalBytes > MAX_PACKAGE_BYTES) {
        reject("package_size_rejected");
      }
      files.push({
        path: relative,
        contents,
        byte_size: contents.length,
        sha256: sha256Buffer(contents),
        mode: stat.mode & 0o777,
      });
    }
  };
  try {
    visit(root, "");
    guard.revalidate();
    return files;
  } finally {
    guard.close();
  }
}

function parseJsonBuffer(contents, reasonCode) {
  if (!Buffer.isBuffer(contents) || contents.length > MAX_MANIFEST_BYTES) reject(reasonCode);
  try {
    const value = JSON.parse(contents.toString("utf8"));
    if (!isPlainDataObject(value)) reject(reasonCode);
    return value;
  } catch (error) {
    if (error && error.code === "optional_provider_package_rejected") throw error;
    reject(reasonCode);
  }
}

function packageManifestFromFiles(files) {
  const entry = files.find((file) => file.path === "package.json");
  if (!entry) reject("package_manifest_missing");
  return parseJsonBuffer(entry.contents, "package_manifest_invalid");
}

function assertNoInstallScripts(manifest) {
  const scripts = manifest.scripts;
  if (scripts == null) return;
  if (!isPlainDataObject(scripts)) reject("package_scripts_invalid");
  for (const name of LIFECYCLE_SCRIPT_NAMES) {
    if (reflectApply(objectHasOwnProperty, scripts, [name])) reject("install_script_rejected");
  }
}

function equalStringMap(actual, expected) {
  if (!isPlainDataObject(actual)) return false;
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (actualKeys.length !== expectedKeys.length) return false;
  for (let index = 0; index < actualKeys.length; index += 1) {
    if (actualKeys[index] !== expectedKeys[index]
        || actual[actualKeys[index]] !== expected[expectedKeys[index]]) return false;
  }
  return true;
}

function equalStringArray(actual, expected) {
  if (!Array.isArray(actual) || utilTypes.isProxy(actual)
      || Object.getPrototypeOf(actual) !== Array.prototype
      || actual.length !== expected.length) return false;
  return actual.every((value, index) => value === expected[index]);
}

function assertAllowedManifestFields(manifest, allowed, reasonCode) {
  const allowedSet = new Set(allowed);
  if (Object.keys(manifest).some((field) => !allowedSet.has(field))) reject(reasonCode);
}

function parsePackageManifestAt(filesByPath, manifestPath) {
  const record = filesByPath.get(manifestPath);
  if (!record) reject("worker_package_manifest_missing");
  return parseJsonBuffer(record.contents, "worker_package_manifest_invalid");
}

function assertClosurePackageManifest(packageSpec, manifest) {
  const mismatchReason = packageSpec.package_id === "worker"
    ? "worker_manifest_mismatch" : "worker_dependency_manifest_mismatch";
  assertAllowedManifestFields(manifest, [
    "name", "version", "private", "description", "license", "type", "engines",
    "main", "files", "exports", "scripts", "dependencies",
  ], "worker_dependency_manifest_surface_rejected");
  if (manifest.name !== packageSpec.package_name
      || manifest.version !== packageSpec.package_version
      || manifest.private !== true
      || typeof manifest.description !== "string" || manifest.description.length === 0
      || manifest.license !== "Apache-2.0"
      || manifest.type !== "commonjs"
      || manifest.main !== packageSpec.expected_main
      || !equalStringArray(manifest.files, packageSpec.expected_files)
      || !equalStringMap(manifest.engines, { node: ">=20 <21" })
      || !equalStringMap(manifest.exports, packageSpec.expected_exports)
      || !equalStringMap(manifest.dependencies, packageSpec.expected_dependencies)) {
    reject(mismatchReason);
  }
  assertNoInstallScripts(manifest);
  if (!isPlainDataObject(manifest.scripts)
      || typeof manifest.scripts.test !== "string" || manifest.scripts.test.length === 0
      || Object.values(manifest.scripts).some((value) =>
        typeof value !== "string" || value.length === 0)) {
    reject("worker_dependency_manifest_surface_rejected");
  }
  if (manifest.bin != null || manifest.optionalDependencies != null
      || manifest.bundleDependencies != null || manifest.bundledDependencies != null
      || manifest.peerDependencies != null || manifest.devDependencies != null
      || manifest.peerDependenciesMeta != null || manifest.gypfile === true) {
    reject("worker_dependency_manifest_surface_rejected");
  }
}

function fileMediaType(filePath) {
  if (filePath.endsWith(".js")) return "application/javascript";
  if (filePath.endsWith(".json")) return "application/json";
  if (filePath.endsWith(".md")) return "text/markdown";
  reject("worker_surface_rejected");
}

function declaredPackageFileMatches(pattern, relativePath) {
  if (pattern === "lib/**/*.js") {
    return relativePath.startsWith("lib/")
      && relativePath.length > "lib/.js".length
      && relativePath.endsWith(".js");
  }
  return relativePath === pattern;
}

function assertDeclaredPackageFileSurfaces(files, packageContexts) {
  const matchedPatterns = new Map(packageContexts.map((context) => [
    context.package_id,
    new Set(),
  ]));
  for (const file of files) {
    const context = closurePackageForPath(packageContexts, file.path);
    const relative = file.path.slice(context.package_root.length + 1);
    if (relative === "package.json") continue;
    const pattern = context.manifest.files.find((candidate) =>
      declaredPackageFileMatches(candidate, relative));
    if (pattern == null) reject("worker_undeclared_package_file_rejected");
    matchedPatterns.get(context.package_id).add(pattern);
  }
  for (const context of packageContexts) {
    const matched = matchedPatterns.get(context.package_id);
    if (context.manifest.files.some((pattern) => !matched.has(pattern))) {
      reject("worker_declared_package_file_missing");
    }
  }
}

function extractLiteralRequires(source, sourcePath) {
  try {
    return analyzeClosedCommonjsSource(source, sourcePath)
      .map((specifier) => ({ sourcePath, specifier }));
  } catch (error) {
    if (error && error.reason_code === "javascript_syntax_rejected") {
      reject("worker_javascript_syntax_rejected");
    }
    if (error && error.reason_code === "duplicate_module_edge_rejected") {
      reject("worker_duplicate_module_edge_rejected");
    }
    reject("worker_dynamic_loader_rejected");
  }
}

function closurePackageForPath(packageContexts, filePath) {
  const matches = packageContexts.filter((context) =>
    filePath === context.package_root || filePath.startsWith(`${context.package_root}/`));
  matches.sort((left, right) => right.package_root.length - left.package_root.length);
  if (matches.length === 0) reject("worker_package_boundary_rejected");
  return matches[0];
}

function closurePackageSpecifier(specifier) {
  if (!specifier.startsWith("@")) return null;
  const components = specifier.split("/");
  if (components.length < 2 || components[0].length < 2 || components[1].length < 1) {
    return null;
  }
  return {
    packageName: `${components[0]}/${components[1]}`,
    subpath: components.length === 2 ? "." : `./${components.slice(2).join("/")}`,
  };
}

function resolveClosureModuleEdge(sourcePath, specifier, filesByPath, packageContexts) {
  const sourceDirectory = path.posix.dirname(sourcePath);
  const sourcePackage = closurePackageForPath(packageContexts, sourcePath);
  if (specifier.startsWith("node:") || WORKER_CLOSURE_BUILTINS.has(specifier)) {
    const builtin = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
    if (!WORKER_CLOSURE_BUILTINS.has(builtin)) reject("worker_builtin_rejected");
    return {
      source_path: sourcePath,
      specifier,
      resolution_kind: "builtin",
      resolved_path: `node:${builtin}`,
    };
  }
  if (specifier.startsWith(".")) {
    const resolved = path.posix.normalize(path.posix.join(sourceDirectory, specifier));
    if (resolved.startsWith("../") || resolved === ".." || path.posix.isAbsolute(resolved)
        || !filesByPath.has(resolved)) reject("worker_relative_resolution_rejected");
    const targetPackage = closurePackageForPath(packageContexts, resolved);
    if (targetPackage.package_id !== sourcePackage.package_id) {
      reject("worker_cross_package_relative_edge_rejected");
    }
    return {
      source_path: sourcePath,
      specifier,
      resolution_kind: "relative",
      resolved_path: resolved,
    };
  }
  const parsed = closurePackageSpecifier(specifier);
  if (parsed == null) reject("worker_undeclared_dependency_rejected");
  const dependencyVersion = sourcePackage.manifest.dependencies[parsed.packageName];
  if (typeof dependencyVersion !== "string") reject("worker_undeclared_dependency_rejected");
  const targetPackage = packageContexts.find((context) =>
    context.manifest.name === parsed.packageName);
  if (!targetPackage || targetPackage.manifest.version !== dependencyVersion) {
    reject("worker_dependency_binding_rejected");
  }
  const target = targetPackage.manifest.exports[parsed.subpath];
  if (typeof target !== "string") reject("worker_package_export_rejected");
  if (!target.startsWith("./")) reject("worker_package_export_rejected");
  const resolved = path.posix.normalize(
    path.posix.join(targetPackage.package_root, target.slice(2)),
  );
  if (!resolved.startsWith(`${targetPackage.package_root}/`)) {
    reject("worker_package_export_rejected");
  }
  if (!filesByPath.has(resolved)) reject("worker_package_export_rejected");
  return {
    source_path: sourcePath,
    specifier,
    resolution_kind: "package_export",
    resolved_path: resolved,
  };
}

function edgeIdentity(edge) {
  return `${edge.source_path}\0${edge.specifier}\0${edge.resolved_path}`;
}

function deriveWorkerClosureEdges(files, filesByPath, packageContexts) {
  const actualEdges = [];
  for (const file of files) {
    if (fileMediaType(file.path) !== "application/javascript") continue;
    const source = file.contents.toString("utf8");
    for (const input of extractLiteralRequires(source, file.path)) {
      actualEdges.push(resolveClosureModuleEdge(
        input.sourcePath,
        input.specifier,
        filesByPath,
        packageContexts,
      ));
    }
  }
  actualEdges.sort((left, right) => {
    const leftIdentity = edgeIdentity(left);
    const rightIdentity = edgeIdentity(right);
    return leftIdentity < rightIdentity ? -1 : (leftIdentity > rightIdentity ? 1 : 0);
  });
  return actualEdges;
}

function assertWorkerClosureReachability(files, edges, entrypoint) {
  const adjacency = new Map();
  for (const edge of edges) {
    if (edge.resolution_kind === "builtin") continue;
    if (!adjacency.has(edge.source_path)) adjacency.set(edge.source_path, []);
    adjacency.get(edge.source_path).push(edge.resolved_path);
  }
  const reachable = new Set();
  const pending = [entrypoint];
  while (pending.length > 0) {
    const current = pending.pop();
    if (reachable.has(current)) continue;
    reachable.add(current);
    for (const dependency of adjacency.get(current) || []) pending.push(dependency);
  }
  for (const file of files) {
    if (fileMediaType(file.path) === "application/javascript" && !reachable.has(file.path)) {
      reject("worker_unreachable_javascript_rejected");
    }
  }
}

function deriveInstalledWorkerClosure(packageRecord, files) {
  const sortedFiles = [...files].sort((left, right) => (
    left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)
  ));
  const filesByPath = new Map(sortedFiles.map((file) => [file.path, file]));
  if (filesByPath.size !== sortedFiles.length) reject("installed_worker_surface_rejected");
  for (const file of sortedFiles) {
    if (file.byte_size > MAX_WORKER_FILE_BYTES || file.mode !== INSTALL_MODE_READ_ONLY) {
      reject("installed_worker_mode_rejected");
    }
    fileMediaType(file.path);
  }
  const packageContexts = packageRecord.expected_closure_packages.map((packageSpec) => {
    const manifestPath = `${packageSpec.package_root}/package.json`;
    const manifest = parsePackageManifestAt(filesByPath, manifestPath);
    assertClosurePackageManifest(packageSpec, manifest);
    return Object.freeze({
      ...packageSpec,
      manifest_path: manifestPath,
      manifest,
    });
  });
  assertDeclaredPackageFileSurfaces(sortedFiles, packageContexts);
  for (const context of packageContexts) {
    for (const target of Object.values(context.manifest.exports)) {
      if (typeof target !== "string" || !target.startsWith("./")) {
        reject("worker_package_export_rejected");
      }
      const resolved = path.posix.normalize(
        path.posix.join(context.package_root, target.slice(2)),
      );
      if (!resolved.startsWith(`${context.package_root}/`) || !filesByPath.has(resolved)) {
        reject("worker_package_export_rejected");
      }
    }
    for (const [dependencyName, dependencyVersion] of
      Object.entries(context.manifest.dependencies)) {
      const dependency = packageContexts.find((candidate) =>
        candidate.manifest.name === dependencyName);
      if (!dependency || dependency.manifest.version !== dependencyVersion) {
        reject("worker_dependency_binding_rejected");
      }
    }
  }
  const workerContext = packageContexts.find((context) => context.package_id === "worker");
  if (!workerContext) reject("worker_package_binding_rejected");
  const edges = deriveWorkerClosureEdges(sortedFiles, filesByPath, packageContexts);
  assertWorkerClosureReachability(sortedFiles, edges, packageRecord.expected_closure_entrypoint);
  return {
    sortedFiles,
    filesByPath,
    packageContexts,
    workerManifest: workerContext.manifest,
    edges,
  };
}

function validateWorkerClosureGraph(packageRecord, files, closureManifest) {
  for (const file of files) {
    if ((file.mode & 0o111) !== 0) reject("worker_source_mode_rejected");
  }
  const derived = deriveInstalledWorkerClosure(packageRecord, files.map((file) => ({
    ...file,
    mode: INSTALL_MODE_READ_ONLY,
  })));
  const {
    sortedFiles: normalizedFiles,
    filesByPath,
    workerManifest,
    packageContexts,
    edges: actualEdges,
  } = derived;
  if (closureManifest.entrypoint !== packageRecord.expected_closure_entrypoint
      || closureManifest.node_major !== packageRecord.node_major
      || closureManifest.provider_id !== "chameleon_ultra"
      || closureManifest.package_name !== packageRecord.package_name
      || closureManifest.package_version !== packageRecord.package_version) {
    reject("worker_closure_binding_rejected");
  }
  if (closureManifest.resolution_policy.allowed_builtins.length
        !== WORKER_CLOSURE_BUILTIN_IDS.length
      || closureManifest.resolution_policy.allowed_builtins.some((value, index) =>
        value !== WORKER_CLOSURE_BUILTIN_IDS[index])) {
    reject("worker_closure_builtin_policy_rejected");
  }
  const packageIds = closureManifest.packages.map((record) => record.package_id);
  if (packageIds.length !== packageRecord.expected_closure_package_ids.length
      || packageIds.some((value, index) =>
        value !== packageRecord.expected_closure_package_ids[index])) {
    reject("worker_closure_package_set_rejected");
  }
  const packageBindings = new Map(closureManifest.packages.map((record) => [record.package_id, record]));
  for (const context of packageContexts) {
    const binding = packageBindings.get(context.package_id);
    if (!binding || binding.package_root !== context.package_root
        || binding.manifest_path !== context.manifest_path
        || binding.package_name !== context.package_name
        || binding.package_version !== context.package_version) {
      reject("worker_closure_package_binding_rejected");
    }
  }
  const signedFiles = closureManifest.files;
  if (signedFiles.length !== files.length) reject("worker_closure_file_set_rejected");
  for (let index = 0; index < signedFiles.length; index += 1) {
    const expected = signedFiles[index];
    const actual = normalizedFiles[index];
    if (actual && (actual.mode & 0o111) !== 0) reject("worker_source_mode_rejected");
    if (!actual || actual.path !== expected.path || actual.byte_size !== expected.byte_size
        || actual.sha256 !== expected.sha256 || expected.install_mode !== INSTALL_MODE_READ_ONLY
        || expected.media_type !== fileMediaType(expected.path)
        || actual.byte_size > MAX_WORKER_FILE_BYTES) {
      reject("worker_closure_file_binding_rejected");
    }
  }
  for (const context of packageContexts) {
    const binding = packageBindings.get(context.package_id);
    const manifestFile = filesByPath.get(context.manifest_path);
    if (!binding || !manifestFile || binding.manifest_sha256 !== manifestFile.sha256) {
      reject("worker_closure_manifest_digest_rejected");
    }
  }
  if (actualEdges.length !== closureManifest.module_edges.length) {
    reject("worker_closure_module_graph_rejected");
  }
  for (let index = 0; index < actualEdges.length; index += 1) {
    const actual = actualEdges[index];
    const expected = closureManifest.module_edges[index];
    if (actual.source_path !== expected.source_path || actual.specifier !== expected.specifier
        || actual.resolution_kind !== expected.resolution_kind
        || actual.resolved_path !== expected.resolved_path) {
      reject("worker_closure_module_graph_rejected");
    }
  }
  assertWorkerClosureReachability(normalizedFiles, actualEdges, closureManifest.entrypoint);
  return { workerManifest };
}

function validateWorkerSource(packageRecord, files, releaseVerification) {
  if (releaseVerification == null || !isPlainDataObject(releaseVerification)) {
    reject("signed_release_required");
  }
  let verified;
  try {
    verified = verifyJavascriptWorkerClosureEnvelope(releaseVerification);
  } catch {
    reject("signed_worker_closure_rejected");
  }
  const sortedFiles = [...files].sort((left, right) => (
    left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)
  ));
  const validated = validateWorkerClosureGraph(packageRecord, sortedFiles, verified.manifest);
  return {
    selected: sortedFiles.map((file) => ({ ...file, install_mode: INSTALL_MODE_READ_ONLY })),
    packageVersion: validated.workerManifest.version,
    releaseManifestDigest: verified.manifest_digest,
    verifiedRelease: verified,
    manifest: validated.workerManifest,
  };
}

const COMPONENT_SCHEMA_FIELDS = Object.freeze([
  "request_schema",
  "result_schema",
  "effect_journal_schema",
  "receipt_schema",
]);
const DURABLE_EXCHANGE_SCHEMA_FIELDS = Object.freeze([
  "grant_record_schema",
  "go_record_schema",
  "receipt_record_schema",
  "outbox_record_schema",
]);

function nativeReleaseArtifacts(packageRecord, releaseManifest) {
  const artifacts = new Map();
  let schemaCount = 0;

  function addArtifact(input, installMode, kind) {
    const artifactPath = normalizeRelativePath(input.artifact_path);
    if (artifacts.has(artifactPath)) reject("native_artifact_set_rejected");
    artifacts.set(artifactPath, Object.freeze({
      path: artifactPath,
      byte_size: input.byte_size,
      sha256: input.sha256,
      install_mode: installMode,
      kind,
    }));
  }

  for (const component of releaseManifest.components) {
    const installMode = packageRecord.required_component_install_modes[component.component_id];
    if (installMode !== INSTALL_MODE_READ_ONLY && installMode !== INSTALL_MODE_EXECUTABLE) {
      reject("native_component_set_rejected");
    }
    addArtifact(component, installMode, "component");
    for (const field of COMPONENT_SCHEMA_FIELDS) {
      addArtifact(component.capability_abi[field], INSTALL_MODE_READ_ONLY, "schema");
      schemaCount += 1;
    }
  }
  const durablePolicy = releaseManifest.authority_handoff_policy.durable_exchange_policy;
  for (const field of DURABLE_EXCHANGE_SCHEMA_FIELDS) {
    addArtifact(durablePolicy[field], INSTALL_MODE_READ_ONLY, "schema");
    schemaCount += 1;
  }
  if (schemaCount !== packageRecord.required_signed_schema_artifact_count
      || artifacts.size !== packageRecord.required_component_ids.length + schemaCount) {
    reject("native_artifact_set_rejected");
  }
  return artifacts;
}

function validateNativePrebuild(packageRecord, files, manifest, releaseVerification) {
  if (releaseVerification == null || !isPlainDataObject(releaseVerification)) {
    reject("signed_release_required");
  }
  let verified;
  try {
    verified = verifyReleaseEnvelopeV2(releaseVerification);
  } catch {
    reject("signed_release_rejected");
  }
  const releaseManifest = verified.manifest;
  if (releaseManifest.package_name !== packageRecord.package_name
      || manifest.name !== packageRecord.package_name
      || manifest.version !== releaseManifest.package_version
      || releaseManifest.target.os !== packageRecord.target_os
      || releaseManifest.target.architecture !== packageRecord.target_architecture
      || releaseManifest.target.node_major !== packageRecord.node_major
      || releaseManifest.target.napi_version !== packageRecord.napi_version) {
    reject("signed_release_binding_rejected");
  }
  assertNoInstallScripts(manifest);
  if (manifest.bin != null || manifest.dependencies != null || manifest.optionalDependencies != null
      || manifest.bundleDependencies != null || manifest.bundledDependencies != null
      || manifest.peerDependencies != null || manifest.devDependencies != null
      || manifest.gypfile === true) reject("native_manifest_surface_rejected");
  const componentIds = releaseManifest.components.map((component) => component.component_id);
  if (componentIds.length !== packageRecord.required_component_ids.length
      || componentIds.some((value, index) => value !== packageRecord.required_component_ids[index])) {
    reject("native_component_set_rejected");
  }
  const artifacts = nativeReleaseArtifacts(packageRecord, releaseManifest);
  const selected = [];
  const seenArtifacts = new Set();
  for (const file of files) {
    const artifact = artifacts.get(file.path);
    if (artifact) {
      if (file.byte_size !== artifact.byte_size || file.sha256 !== artifact.sha256) {
        reject("native_artifact_digest_rejected");
      }
      const installMode = artifact.install_mode;
      if ((installMode !== INSTALL_MODE_READ_ONLY && installMode !== INSTALL_MODE_EXECUTABLE)
          || (installMode === INSTALL_MODE_EXECUTABLE
            ? (file.mode & 0o111) === 0
            : (file.mode & 0o111) !== 0)) {
        reject("native_source_mode_rejected");
      }
      seenArtifacts.add(file.path);
      selected.push({
        ...file,
        install_mode: installMode,
      });
      continue;
    }
    if (file.path === "package.json" || file.path === "README.md"
        || file.path === "LICENSE" || file.path === "NOTICE") {
      if ((file.mode & 0o111) !== 0) reject("native_source_mode_rejected");
      selected.push({ ...file, install_mode: INSTALL_MODE_READ_ONLY });
      continue;
    }
    reject("native_surface_rejected");
  }
  if (seenArtifacts.size !== artifacts.size) {
    reject("native_artifact_set_rejected");
  }
  return {
    selected,
    packageVersion: manifest.version,
    releaseManifestDigest: verified.manifest_digest,
    verifiedRelease: verified,
  };
}

function normalizedFileRecords(files) {
  return files.map((file) => Object.freeze({
    path: file.path,
    byte_size: file.byte_size,
    sha256: file.sha256,
    mode: file.install_mode == null ? file.mode : file.install_mode,
  })).sort((left, right) => (left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)));
}

function contentDigest(
  selection,
  packageVersion,
  releaseManifestDigest,
  releaseIdentity,
  fileRecords,
) {
  return sha256Buffer(Buffer.from(JSON.stringify({
    domain: "hacker-bob/optional-provider-installed-package/v3",
    provider_id: selection.provider.provider_id,
    package_id: selection.package.package_id,
    package_name: selection.package.package_name,
    package_version: packageVersion,
    surface_policy: selection.package.surface_policy,
    release_manifest_digest: releaseManifestDigest,
    release_id: releaseIdentity.release_id,
    release_epoch: releaseIdentity.release_epoch,
    release_envelope_digest: releaseIdentity.release_envelope_digest,
    release_trust_policy_digest: releaseIdentity.release_trust_policy_digest,
    release_key_id: releaseIdentity.release_key_id,
    release_public_key_digest: releaseIdentity.release_public_key_digest,
    release_trust_epoch: releaseIdentity.release_trust_epoch,
    release_revocation_epoch: releaseIdentity.release_revocation_epoch,
    files: fileRecords,
  }), "utf8"));
}

function releaseIdentityForValidated(selection, validated) {
  if (selection.package.surface_policy !== "signed_javascript_worker_closure_v1") {
    return Object.freeze({
      release_id: null,
      release_epoch: null,
      release_envelope_digest: null,
      release_trust_policy_digest: null,
      release_key_id: null,
      release_public_key_digest: null,
      release_trust_epoch: null,
      release_revocation_epoch: null,
    });
  }
  const verified = validated.verifiedRelease;
  return Object.freeze({
    release_id: verified.manifest.release_id,
    release_epoch: verified.manifest.release_epoch,
    release_envelope_digest: verified.envelope_digest,
    release_trust_policy_digest: verified.trust_policy_digest,
    release_key_id: verified.key_id,
    release_public_key_digest: verified.public_key_digest,
    release_trust_epoch: verified.trust_epoch,
    release_revocation_epoch: verified.revocation_epoch,
  });
}

function validateSourcePackage(selection, sourceRoot, releaseVerification) {
  const files = collectPackageFiles(sourceRoot);
  const workerClosure = selection.package.surface_policy
    === "signed_javascript_worker_closure_v1";
  const manifest = workerClosure ? null : packageManifestFromFiles(files);
  const validated = workerClosure
    ? validateWorkerSource(selection.package, files, releaseVerification)
    : validateNativePrebuild(selection.package, files, manifest, releaseVerification);
  const fileRecords = normalizedFileRecords(validated.selected);
  const releaseIdentity = releaseIdentityForValidated(selection, validated);
  return {
    ...validated,
    manifest: validated.manifest || manifest,
    fileRecords,
    releaseIdentity,
    contentDigest: contentDigest(
      selection,
      validated.packageVersion,
      validated.releaseManifestDigest,
      releaseIdentity,
      fileRecords,
    ),
  };
}

function validateInstalledNativeSurface(selection, files, manifest) {
  if (manifest.name !== selection.package.package_name) {
    reject("installed_manifest_drift");
  }
  assertNoInstallScripts(manifest);
  if (manifest.bin != null || manifest.dependencies != null || manifest.optionalDependencies != null
      || manifest.bundleDependencies != null || manifest.bundledDependencies != null
      || manifest.peerDependencies != null || manifest.devDependencies != null
      || manifest.gypfile === true) reject("installed_native_surface_rejected");
  let artifactCount = 0;
  let executableCount = 0;
  for (const file of files) {
    if (file.path === "package.json" || file.path === "README.md"
        || file.path === "LICENSE" || file.path === "NOTICE") {
      if (file.mode !== INSTALL_MODE_READ_ONLY) reject("installed_native_mode_rejected");
      continue;
    }
    if (file.mode !== INSTALL_MODE_READ_ONLY && file.mode !== INSTALL_MODE_EXECUTABLE) {
      reject("installed_native_mode_rejected");
    }
    if (file.mode === INSTALL_MODE_EXECUTABLE) executableCount += 1;
    artifactCount += 1;
  }
  const expectedExecutableCount = Object.values(
    selection.package.required_component_install_modes,
  ).filter((mode) => mode === INSTALL_MODE_EXECUTABLE).length;
  if (artifactCount !== selection.package.required_component_ids.length
        + selection.package.required_signed_schema_artifact_count
      || executableCount !== expectedExecutableCount) {
    reject("installed_native_surface_rejected");
  }
}

function metadataForInstall(selection, validated, installedAt) {
  return {
    schema_version: OPTIONAL_PACKAGE_METADATA_VERSION,
    registry_version: OPTIONAL_PROVIDER_REGISTRY_VERSION,
    provider_id: selection.provider.provider_id,
    package_id: selection.package.package_id,
    package_name: selection.package.package_name,
    package_version: validated.packageVersion,
    surface_policy: selection.package.surface_policy,
    content_digest: validated.contentDigest,
    release_manifest_digest: validated.releaseManifestDigest,
    release_id: validated.releaseIdentity.release_id,
    release_epoch: validated.releaseIdentity.release_epoch,
    release_envelope_digest: validated.releaseIdentity.release_envelope_digest,
    release_trust_policy_digest: validated.releaseIdentity.release_trust_policy_digest,
    release_key_id: validated.releaseIdentity.release_key_id,
    release_public_key_digest: validated.releaseIdentity.release_public_key_digest,
    release_trust_epoch: validated.releaseIdentity.release_trust_epoch,
    release_revocation_epoch: validated.releaseIdentity.release_revocation_epoch,
    files: validated.fileRecords,
    installed_at: installedAt,
  };
}

function normalizeMetadata(value, selection) {
  assertExactObject(value, METADATA_FIELDS, "metadata_invalid");
  if (own(value, "schema_version", "metadata_invalid") !== OPTIONAL_PACKAGE_METADATA_VERSION
      || own(value, "registry_version", "metadata_invalid")
        !== OPTIONAL_PROVIDER_REGISTRY_VERSION
      || own(value, "provider_id", "metadata_invalid") !== selection.provider.provider_id
      || own(value, "package_id", "metadata_invalid") !== selection.package.package_id
      || own(value, "package_name", "metadata_invalid") !== selection.package.package_name
      || own(value, "surface_policy", "metadata_invalid") !== selection.package.surface_policy) {
    reject("metadata_invalid");
  }
  const packageVersion = assertString(own(value, "package_version", "metadata_invalid"),
    VERSION_PATTERN, "metadata_invalid");
  if (selection.package.version_policy === "registry_exact"
      && packageVersion !== selection.package.package_version) reject("metadata_invalid");
  const releaseManifestDigest = own(value, "release_manifest_digest", "metadata_invalid");
  if (selection.package.signed_release_required) {
    assertDigest(releaseManifestDigest, "metadata_invalid");
  } else if (releaseManifestDigest !== null) reject("metadata_invalid");
  const releaseIdentity = {
    release_id: own(value, "release_id", "metadata_invalid"),
    release_epoch: own(value, "release_epoch", "metadata_invalid"),
    release_envelope_digest: own(value, "release_envelope_digest", "metadata_invalid"),
    release_trust_policy_digest: own(
      value,
      "release_trust_policy_digest",
      "metadata_invalid",
    ),
    release_key_id: own(value, "release_key_id", "metadata_invalid"),
    release_public_key_digest: own(value, "release_public_key_digest", "metadata_invalid"),
    release_trust_epoch: own(value, "release_trust_epoch", "metadata_invalid"),
    release_revocation_epoch: own(value, "release_revocation_epoch", "metadata_invalid"),
  };
  if (selection.package.surface_policy === "signed_javascript_worker_closure_v1") {
    assertString(releaseIdentity.release_id, /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,190}$/u,
      "metadata_invalid");
    if (!Number.isSafeInteger(releaseIdentity.release_epoch)
        || releaseIdentity.release_epoch < 1) reject("metadata_invalid");
    assertDigest(releaseIdentity.release_envelope_digest, "metadata_invalid");
    assertDigest(releaseIdentity.release_trust_policy_digest, "metadata_invalid");
    assertString(releaseIdentity.release_key_id, /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,190}$/u,
      "metadata_invalid");
    assertDigest(releaseIdentity.release_public_key_digest, "metadata_invalid");
    if (!Number.isSafeInteger(releaseIdentity.release_trust_epoch)
        || releaseIdentity.release_trust_epoch < 1
        || !Number.isSafeInteger(releaseIdentity.release_revocation_epoch)
        || releaseIdentity.release_revocation_epoch < 1) reject("metadata_invalid");
  } else if (Object.values(releaseIdentity).some((field) => field !== null)) {
    reject("metadata_invalid");
  }
  const installedAt = own(value, "installed_at", "metadata_invalid");
  assertString(installedAt, TIMESTAMP_PATTERN, "metadata_invalid");
  const fileInputs = own(value, "files", "metadata_invalid");
  if (!Array.isArray(fileInputs) || utilTypes.isProxy(fileInputs)
      || fileInputs.length < 1 || fileInputs.length > MAX_PACKAGE_FILES) reject("metadata_invalid");
  const files = [];
  let previous = null;
  for (let index = 0; index < fileInputs.length; index += 1) {
    const file = fileInputs[index];
    assertExactObject(file, FILE_RECORD_FIELDS, "metadata_invalid");
    const filePath = normalizeRelativePath(own(file, "path", "metadata_invalid"),
      "metadata_invalid");
    const byteSize = own(file, "byte_size", "metadata_invalid");
    const mode = own(file, "mode", "metadata_invalid");
    if (!Number.isSafeInteger(byteSize) || byteSize < 0 || byteSize > MAX_PACKAGE_BYTES
        || (mode !== INSTALL_MODE_READ_ONLY && mode !== INSTALL_MODE_EXECUTABLE)
        || (previous != null && filePath <= previous)) reject("metadata_invalid");
    files.push(Object.freeze({
      path: filePath,
      byte_size: byteSize,
      sha256: assertDigest(own(file, "sha256", "metadata_invalid"), "metadata_invalid"),
      mode,
    }));
    previous = filePath;
  }
  return Object.freeze({
    package_version: packageVersion,
    content_digest: assertDigest(own(value, "content_digest", "metadata_invalid"),
      "metadata_invalid"),
    release_manifest_digest: releaseManifestDigest,
    ...releaseIdentity,
    files: Object.freeze(files),
    installed_at: installedAt,
  });
}

function inspectInstalled(selection, targetAbs, options = {}) {
  const paths = packagePaths(targetAbs, selection.provider, selection.package);
  let ancestryGuard;
  let recoverableMetadata = null;
  let transactionPresent = false;
  try {
    ancestryGuard = retainDirectoryAncestry(targetAbs, "installed_ancestry_rejected", {
      expectedRootIdentity: options.expectedRootIdentity || null,
    });
    const relativeProviderRoot = path.relative(targetAbs, paths.providerRoot);
    if (!relativeProviderRoot || relativeProviderRoot.startsWith("..")
        || path.isAbsolute(relativeProviderRoot)) reject("installed_ancestry_rejected");
    let current = targetAbs;
    for (const component of relativeProviderRoot.split(path.sep)) {
      current = path.join(current, component);
      const stat = safeLstat(current);
      if (!stat) return { present: false, paths };
      if (!stat.isDirectory() || stat.isSymbolicLink()) reject("installed_ancestry_rejected");
      ancestryGuard.add(current);
    }
    transactionPresent = [paths.stagingRoot, paths.backupRoot, paths.transactionFile,
      paths.transactionTempFile].some((candidate) => safeLstat(candidate) != null);
    if (options.allowTransaction !== true && transactionPresent) {
      reject("transaction_recovery_required");
    }
    const packageStat = safeLstat(paths.packageRoot);
    if (!packageStat) return { present: false, paths };
    if (!packageStat.isDirectory() || packageStat.isSymbolicLink()) {
      reject("installed_root_invalid");
    }
    ancestryGuard.add(paths.packageRoot);
    const files = collectPackageFiles(paths.packageRoot, { allowMetadata: true });
    ancestryGuard.revalidate();
    const metadataFile = files.find((file) => file.path === OPTIONAL_PACKAGE_METADATA_FILE);
    if (!metadataFile) reject("metadata_missing");
    if (metadataFile.mode !== INSTALL_MODE_READ_ONLY) reject("metadata_mode_rejected");
    const metadata = normalizeMetadata(
      parseJsonBuffer(metadataFile.contents, "metadata_invalid"),
      selection,
    );
    recoverableMetadata = metadata;
    const payloadFiles = files.filter((file) => file.path !== OPTIONAL_PACKAGE_METADATA_FILE);
    const fileRecords = normalizedFileRecords(payloadFiles);
    if (fileRecords.length !== metadata.files.length) reject("installed_surface_drift");
    for (let index = 0; index < fileRecords.length; index += 1) {
      const actual = fileRecords[index];
      const expected = metadata.files[index];
      if (actual.path !== expected.path || actual.byte_size !== expected.byte_size
          || actual.sha256 !== expected.sha256 || actual.mode !== expected.mode) {
        reject("installed_surface_drift");
      }
    }
    const digest = contentDigest(
      selection,
      metadata.package_version,
      metadata.release_manifest_digest,
      metadata,
      fileRecords,
    );
    if (digest !== metadata.content_digest) reject("installed_content_drift");
    let manifest;
    if (selection.package.surface_policy === "signed_javascript_worker_closure_v1") {
      const worker = deriveInstalledWorkerClosure(selection.package, payloadFiles);
      manifest = worker.workerManifest;
    } else {
      manifest = packageManifestFromFiles(payloadFiles);
      validateInstalledNativeSurface(selection, payloadFiles, manifest);
    }
    if (manifest.name !== selection.package.package_name
        || manifest.version !== metadata.package_version) reject("installed_manifest_drift");
    return {
      present: true,
      blocked: false,
      paths,
      metadata,
      files: payloadFiles,
      fileRecords,
      manifest,
      transactionPresent,
    };
  } catch (error) {
    return {
      present: true,
      blocked: true,
      reasonCode: error && error.reason_code ? error.reason_code : "installed_package_rejected",
      metadata: recoverableMetadata,
      transactionPresent,
      paths,
    };
  } finally {
    if (ancestryGuard) ancestryGuard.close();
  }
}

function projection(selection, status, reasonCode, compatibility, options = {}) {
  const severity = status === "blocked" ? "error"
    : (status === "installed_unqualified" || status === "unsupported_host" ? "warn" : "info");
  const workerClosure = selection.package.surface_policy
    === "signed_javascript_worker_closure_v1";
  return Object.freeze({
    version: OPTIONAL_PROVIDER_REGISTRY_VERSION,
    provider_id: selection.provider.provider_id,
    package_id: selection.package.package_id,
    status,
    severity,
    reason_code: reasonCode,
    installed: options.installed === true,
    supported_host: options.supportedHost === true,
    host_compatibility: compatibility,
    release_signature_valid: options.releaseSignatureValid === true,
    evidence_cross_bound: options.evidenceCrossBound === true,
    package_provenance_only: workerClosure,
    external_immutable_release_keyring_observed: false,
    probe_to_exec_closure_identity_bound: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
    activation_performed: false,
    host_inspection_performed: false,
    hardware_probe_performed: false,
  });
}

function qualificationForInstalled(selection, installed, qualificationInput) {
  if (!selection.package.signed_release_required || qualificationInput == null) return null;
  if (!isPlainDataObject(qualificationInput)) return { blocked: true };
  if (selection.package.surface_policy === "signed_javascript_worker_closure_v1") {
    let verified;
    try {
      verified = verifyJavascriptWorkerClosureEnvelope(qualificationInput);
      validateWorkerClosureGraph(selection.package, installed.files, verified.manifest);
    } catch {
      return { blocked: true };
    }
    if (verified.manifest_digest !== installed.metadata.release_manifest_digest
        || verified.envelope_digest !== installed.metadata.release_envelope_digest
        || verified.trust_policy_digest !== installed.metadata.release_trust_policy_digest
        || verified.key_id !== installed.metadata.release_key_id
        || verified.public_key_digest !== installed.metadata.release_public_key_digest
        || verified.manifest.release_id !== installed.metadata.release_id
        || verified.manifest.release_epoch !== installed.metadata.release_epoch
        || verified.trust_epoch !== installed.metadata.release_trust_epoch
        || verified.revocation_epoch !== installed.metadata.release_revocation_epoch
        || verified.manifest.package_name !== installed.manifest.name
        || verified.manifest.package_version !== installed.manifest.version
        || verified.manifest.files.length !== installed.fileRecords.length) {
      return { blocked: true };
    }
    for (let index = 0; index < verified.manifest.files.length; index += 1) {
      const expected = verified.manifest.files[index];
      const actual = installed.fileRecords[index];
      if (expected.path !== actual.path || expected.byte_size !== actual.byte_size
          || expected.sha256 !== actual.sha256 || expected.install_mode !== actual.mode) {
        return { blocked: true };
      }
    }
    return { blocked: false, kind: "signed_worker_closure" };
  }
  let verified;
  let doctor;
  try {
    const context = own(qualificationInput, "evaluation_context", "qualification_input_invalid");
    verified = verifyReleaseEnvelopeV2({
      envelope: own(qualificationInput, "envelope", "qualification_input_invalid"),
      trust_policy: own(qualificationInput, "trust_policy", "qualification_input_invalid"),
      now: context == null ? null : own(context, "now", "qualification_input_invalid"),
    });
    doctor = evaluateNativePrebuildDoctorV2(qualificationInput);
  } catch {
    return { blocked: true };
  }
  if (doctor.status !== "diagnostic_complete_non_authorizing"
      || verified.manifest_digest !== installed.metadata.release_manifest_digest
      || doctor.manifest_digest !== installed.metadata.release_manifest_digest
      || verified.manifest.package_name !== installed.manifest.name
      || verified.manifest.package_version !== installed.manifest.version) {
    return { blocked: true };
  }
  try {
    validateInstalledNativeSurface(selection, installed.files, installed.manifest);
  } catch {
    return { blocked: true };
  }
  let expectedArtifacts;
  try {
    expectedArtifacts = nativeReleaseArtifacts(selection.package, verified.manifest);
  } catch {
    return { blocked: true };
  }
  const artifacts = new Map();
  for (const file of installed.fileRecords) {
    if (expectedArtifacts.has(file.path)) {
      artifacts.set(file.path, file);
      continue;
    }
    if (file.path !== "package.json" && file.path !== "README.md"
        && file.path !== "LICENSE" && file.path !== "NOTICE") return { blocked: true };
  }
  if (artifacts.size !== expectedArtifacts.size) return { blocked: true };
  for (const expected of expectedArtifacts.values()) {
    const file = artifacts.get(expected.path);
    if (!file || file.byte_size !== expected.byte_size || file.sha256 !== expected.sha256
        || file.mode !== expected.install_mode) {
      return { blocked: true };
    }
  }
  return { blocked: false, kind: "signed_native_prebuild" };
}

function probeOptionalProviderPackage(input) {
  assertExactObject(input, [
    "target_abs",
    "provider_id",
    "package_id",
    "host",
    "qualification_input",
  ], "probe_input_invalid");
  const targetAbs = path.resolve(assertString(own(input, "target_abs", "probe_input_invalid"),
    null, "probe_input_invalid"));
  const selection = getOptionalProviderPackage(
    own(input, "provider_id", "probe_input_invalid"),
    own(input, "package_id", "probe_input_invalid"),
  );
  const host = normalizeHost(own(input, "host", "probe_input_invalid"));
  const compatibility = hostCompatibility(selection.package, host);
  const supported = compatibility.supported;
  const installed = inspectInstalled(selection, targetAbs);
  if (!installed.present) {
    return projection(selection, supported ? "absent" : "unsupported_host",
      supported ? "optional_package_absent" : compatibility.reason_code, compatibility, {
        installed: false,
        supportedHost: supported,
      });
  }
  if (installed.blocked) {
    return projection(selection, "blocked", installed.reasonCode || "installed_package_rejected",
      compatibility, {
      installed: true,
      supportedHost: supported,
    });
  }
  if (!supported) {
    return projection(selection, "unsupported_host", compatibility.reason_code, compatibility, {
      installed: true,
      supportedHost: false,
    });
  }
  const qualification = qualificationForInstalled(
    selection,
    installed,
    own(input, "qualification_input", "probe_input_invalid"),
  );
  if (qualification && qualification.blocked) {
    return projection(selection, "blocked", "qualification_evidence_rejected", compatibility, {
      installed: true,
      supportedHost: true,
    });
  }
  if (qualification) {
    const reasonCode = qualification.kind === "signed_worker_closure"
      ? "signed_worker_closure_reverified_non_authorizing"
      : "caller_evidence_cross_bound";
    return projection(selection, "qualified_diagnostic", reasonCode,
      compatibility, {
      installed: true,
      supportedHost: true,
      releaseSignatureValid: true,
      evidenceCrossBound: true,
    });
  }
  return projection(selection, "installed_unqualified", "qualification_evidence_absent",
    compatibility, {
    installed: true,
    supportedHost: true,
    releaseSignatureValid: false,
  });
}

function probeOptionalProviders(input) {
  assertExactObject(input, ["target_abs", "host", "qualification_inputs"],
    "probe_input_invalid");
  const qualificationInputs = own(input, "qualification_inputs", "probe_input_invalid");
  if (qualificationInputs != null && !isPlainDataObject(qualificationInputs)) {
    reject("probe_input_invalid");
  }
  const results = [];
  for (const provider of OPTIONAL_PROVIDER_REGISTRY) {
    for (const packageRecord of provider.packages) {
      const key = `${provider.provider_id}:${packageRecord.package_id}`;
      const qualification = qualificationInputs == null ? null : qualificationInputs[key] || null;
      results.push(probeOptionalProviderPackage({
        target_abs: own(input, "target_abs", "probe_input_invalid"),
        provider_id: provider.provider_id,
        package_id: packageRecord.package_id,
        host: own(input, "host", "probe_input_invalid"),
        qualification_input: qualification,
      }));
    }
  }
  return Object.freeze(results);
}

function assertReleaseHighWater(selection, existing, validated) {
  if (selection.package.surface_policy !== "signed_javascript_worker_closure_v1"
      || !existing.present) return;
  const prior = existing.metadata;
  if (!prior && existing.transactionPresent === true) {
    // A fresh install can crash after its staged tree becomes the package leaf,
    // before any prior high-water record exists. Only the custodian's exact
    // journal/plan/identity recovery may decide that state.
    return;
  }
  if (!prior) reject(existing.reasonCode || "release_high_water_unavailable");
  const candidate = validated.releaseIdentity;
  if (candidate.release_epoch < prior.release_epoch
      || candidate.release_trust_epoch < prior.release_trust_epoch
      || candidate.release_revocation_epoch < prior.release_revocation_epoch) {
    reject("release_high_water_rollback_rejected");
  }
  if (candidate.release_epoch === prior.release_epoch
      && (candidate.release_id !== prior.release_id
        || validated.releaseManifestDigest !== prior.release_manifest_digest)) {
    reject("release_epoch_equivocation_rejected");
  }
  if (candidate.release_trust_epoch === prior.release_trust_epoch
      && candidate.release_revocation_epoch === prior.release_revocation_epoch
      && candidate.release_trust_policy_digest !== prior.release_trust_policy_digest) {
    reject("release_policy_epoch_equivocation_rejected");
  }
}

function installOrUpdateOptionalProviderPackage(input, operation) {
  assertExactObject(input, [
    "target_abs",
    "provider_id",
    "package_id",
    "source_root",
    "release_verification",
    "now",
  ], "install_input_invalid");
  const targetAbs = path.resolve(assertString(own(input, "target_abs", "install_input_invalid"),
    null, "install_input_invalid"));
  const sourceRoot = path.resolve(assertString(own(input, "source_root", "install_input_invalid"),
    null, "install_input_invalid"));
  const selection = getOptionalProviderPackage(
    own(input, "provider_id", "install_input_invalid"),
    own(input, "package_id", "install_input_invalid"),
  );
  const releaseVerification = own(input, "release_verification", "install_input_invalid");
  const installedAtInput = own(input, "now", "install_input_invalid");
  const paths = packagePaths(targetAbs, selection.provider, selection.package);
  const sourceWithinOwnedRoot = path.relative(paths.providerRoot, sourceRoot);
  if (sourceWithinOwnedRoot === "" || (!sourceWithinOwnedRoot.startsWith("..")
      && !path.isAbsolute(sourceWithinOwnedRoot))) reject("source_inside_owned_root_rejected");
  const installedAt = installedAtInput == null ? new Date().toISOString()
    : assertString(installedAtInput, TIMESTAMP_PATTERN, "install_input_invalid");
  return withLifecycleCustodianTarget(targetAbs, (targetAuthority) => {
    const targetSnapshot = lifecycleCustodianTargetSnapshot(targetAuthority);
    const validated = validateSourcePackage(selection, sourceRoot, releaseVerification);
    const inspectionOptions = {
      expectedRootIdentity: targetSnapshot,
      // The custodian owns transaction recovery. Read the still-installed
      // high-water record without treating its own journal as ambient state,
      // then let the exact plan digest decide whether recovery may proceed.
      allowTransaction: true,
    };
    const existing = inspectInstalled(selection, targetAbs, inspectionOptions);
    assertReleaseHighWater(selection, existing, validated);
    const metadata = metadataForInstall(selection, validated, installedAt);
    if (existing.present && !existing.blocked
        && existing.transactionPresent !== true
        && existing.metadata.content_digest === validated.contentDigest
        && existing.metadata.release_manifest_digest === validated.releaseManifestDigest) {
      return Object.freeze({
        provider_id: selection.provider.provider_id,
        package_id: selection.package.package_id,
        operation: "unchanged",
        status: "installed_unqualified",
        production_ready: false,
        hardware_access_authorized: false,
        activation_performed: false,
      });
    }
    const metadataContents = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, "utf8");
    executeLifecycleMutation(targetAuthority, {
      operation: "replace",
      selection: `optional:${selection.provider.provider_id}:${selection.package.package_id}`,
      files: [
        ...validated.selected.map((file) => ({
          path: file.path,
          contents: file.contents,
          mode: file.install_mode,
        })),
        {
          path: OPTIONAL_PACKAGE_METADATA_FILE,
          contents: metadataContents,
          mode: INSTALL_MODE_READ_ONLY,
        },
      ],
    });
    const installed = inspectInstalled(selection, targetAbs, inspectionOptions);
    if (!installed.present || installed.blocked
        || installed.metadata.content_digest !== validated.contentDigest
        || installed.metadata.release_manifest_digest !== validated.releaseManifestDigest) {
      reject("install_verification_failed");
    }
    return Object.freeze({
      provider_id: selection.provider.provider_id,
      package_id: selection.package.package_id,
      operation: existing.present ? "updated" : operation,
      status: "installed_unqualified",
      production_ready: false,
      hardware_access_authorized: false,
      activation_performed: false,
    });
  });
}

function installOptionalProviderPackage(input) {
  return installOrUpdateOptionalProviderPackage(input, "installed");
}

function updateOptionalProviderPackage(input) {
  return installOrUpdateOptionalProviderPackage(input, "updated");
}

function safeRemovePackageRoot(selection, targetAbs, dryRun, targetAuthority = null) {
  const paths = packagePaths(targetAbs, selection.provider, selection.package);
  if (dryRun) {
    const ownedEntries = [
      paths.packageRoot,
      paths.stagingRoot,
      paths.backupRoot,
      paths.transactionFile,
      paths.transactionTempFile,
    ];
    let present;
    try {
      present = ownedEntries.some((candidate) => safeLstat(candidate) != null);
    } catch {
      return Object.freeze({
        provider_id: selection.provider.provider_id,
        package_id: selection.package.package_id,
        operation: "blocked",
        removed: false,
        reason_code: "owned_ancestry_rejected",
      });
    }
    if (!present) {
      return Object.freeze({
        provider_id: selection.provider.provider_id,
        package_id: selection.package.package_id,
        operation: "absent",
        removed: false,
        reason_code: "optional_package_absent",
      });
    }
  }
  let mutation = null;
  if (!dryRun) {
    mutation = executeLifecycleMutation(targetAuthority, {
      operation: "remove",
      selection: `optional:${selection.provider.provider_id}:${selection.package.package_id}`,
      files: [],
    });
    if (mutation.status === "absent") {
      return Object.freeze({
        provider_id: selection.provider.provider_id,
        package_id: selection.package.package_id,
        operation: "absent",
        removed: false,
        reason_code: "optional_package_absent",
      });
    }
  }
  return Object.freeze({
    provider_id: selection.provider.provider_id,
    package_id: selection.package.package_id,
    operation: dryRun ? "would_remove" : "removed",
    removed: !dryRun,
    reason_code: "bob_owned_package_removed",
  });
}

function uninstallOptionalProviderPackage(input, targetAuthority = null) {
  assertExactObject(input, ["target_abs", "provider_id", "package_id", "dry_run"],
    "uninstall_input_invalid");
  const targetAbs = path.resolve(assertString(own(input, "target_abs", "uninstall_input_invalid"),
    null, "uninstall_input_invalid"));
  const dryRun = own(input, "dry_run", "uninstall_input_invalid");
  if (dryRun !== true && dryRun !== false) reject("uninstall_input_invalid");
  const selection = getOptionalProviderPackage(
    own(input, "provider_id", "uninstall_input_invalid"),
    own(input, "package_id", "uninstall_input_invalid"),
  );
  if (dryRun || targetAuthority != null) {
    return safeRemovePackageRoot(selection, targetAbs, dryRun, targetAuthority);
  }
  return withLifecycleCustodianTarget(targetAbs, (retainedTargetAuthority) =>
    safeRemovePackageRoot(selection, targetAbs, false, retainedTargetAuthority));
}

function uninstallAllOptionalProviders(input, targetAuthority = null) {
  assertExactObject(input, ["target_abs", "dry_run"], "uninstall_input_invalid");
  const targetAbs = path.resolve(assertString(own(input, "target_abs", "uninstall_input_invalid"),
    null, "uninstall_input_invalid"));
  const dryRun = own(input, "dry_run", "uninstall_input_invalid");
  if (dryRun !== true && dryRun !== false) reject("uninstall_input_invalid");
  const removeAll = (retainedTargetAuthority) => {
    const results = [];
    for (const provider of OPTIONAL_PROVIDER_REGISTRY) {
      for (const packageRecord of provider.packages) {
        const selection = getOptionalProviderPackage(provider.provider_id, packageRecord.package_id);
        results.push(safeRemovePackageRoot(
          selection,
          targetAbs,
          dryRun,
          retainedTargetAuthority,
        ));
      }
    }
    return Object.freeze(results);
  };
  if (dryRun || targetAuthority != null) return removeAll(targetAuthority);
  return withLifecycleCustodianTarget(targetAbs, removeAll);
}

function optionalProviderDoctorChecks(input) {
  const projections = probeOptionalProviders(input);
  return Object.freeze(projections.map((projectionValue) => Object.freeze({
    id: `optional_provider_${projectionValue.provider_id}_${projectionValue.package_id}`,
    status: projectionValue.severity,
    message: projectionValue.reason_code,
    detail: Object.freeze({
      provider_id: projectionValue.provider_id,
      package_id: projectionValue.package_id,
      lifecycle_status: projectionValue.status,
      installed: projectionValue.installed,
      supported_host: projectionValue.supported_host,
      host_compatibility: projectionValue.host_compatibility,
      production_ready: false,
      hardware_access_authorized: false,
      activation_performed: false,
    }),
  })));
}

module.exports = {
  OPTIONAL_PACKAGE_METADATA_FILE,
  OPTIONAL_PACKAGE_METADATA_VERSION,
  installOptionalProviderPackage,
  optionalProviderDoctorChecks,
  probeOptionalProviderPackage,
  probeOptionalProviders,
  retainDirectoryAncestry,
  sameFilesystemIdentity,
  uninstallAllOptionalProviders,
  uninstallOptionalProviderPackage,
  updateOptionalProviderPackage,
};

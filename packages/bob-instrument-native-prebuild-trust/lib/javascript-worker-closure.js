"use strict";

// Provider-neutral, non-authorizing signature contract for a closed CommonJS
// worker release. This deliberately does not extend or reinterpret the native
// prebuild v2 schema: JavaScript package provenance and native running-code
// identity are distinct claims with distinct trust epochs and revocation sets.

const crypto = require("node:crypto");
const {
  assertBoolean,
  assertDenseArray,
  assertDigest,
  assertExactObject,
  assertIdentifier,
  assertInteger,
  assertOpaqueToken,
  assertString,
  assertTimestamp,
  domainDigest,
  makeArray,
  makeRecord: makeIndexedRecord,
  ownValue,
  reject,
  setArrayIndex,
  timestampMilliseconds,
} = require("./data-contract.js");

const cryptoCreateHash = crypto.createHash;
const cryptoCreatePublicKey = crypto.createPublicKey;
const cryptoVerify = crypto.verify;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const reflectApply = Reflect.apply;
const regexpTest = RegExp.prototype.test;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;
const SafeSet = Set;
const setAdd = Set.prototype.add;
const setHas = Set.prototype.has;

const JAVASCRIPT_WORKER_CLOSURE_VERSION = 1;
const JAVASCRIPT_WORKER_CLOSURE_MANIFEST_DOMAIN =
  "hacker-bob/javascript-worker-release-closure-manifest/v1";
const JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN =
  "hacker-bob/javascript-worker-release-closure-signature/v1";
const JAVASCRIPT_WORKER_CLOSURE_ENVELOPE_DOMAIN =
  "hacker-bob/javascript-worker-release-closure-envelope/v1";
const JAVASCRIPT_WORKER_CLOSURE_KEY_USAGE =
  "javascript_worker_release_closure_v1";

const JAVASCRIPT_WORKER_CLOSURE_BLOCKERS = objectFreeze([
  "external_immutable_worker_release_keyring_port_absent",
  "probe_to_exec_closure_identity_binding_absent",
  "javascript_signature_is_not_native_running_code_identity",
  "native_component_identity_and_hil_remain_required",
  "verification_result_is_package_provenance_only_non_authorizing",
]);

const MANIFEST_FIELDS = objectFreeze([
  "version", "kind", "release_id", "release_epoch", "provider_id",
  "package_name", "package_version", "node_major", "entrypoint", "packages",
  "files", "module_edges", "resolution_policy", "issued_at", "expires_at",
]);
const PACKAGE_FIELDS = objectFreeze([
  "package_id", "package_name", "package_version", "package_root",
  "manifest_path", "manifest_sha256",
]);
const FILE_FIELDS = objectFreeze([
  "path", "byte_size", "sha256", "install_mode", "media_type",
]);
const EDGE_FIELDS = objectFreeze([
  "source_path", "specifier", "resolution_kind", "resolved_path",
]);
const RESOLUTION_POLICY_FIELDS = objectFreeze([
  "scheme", "commonjs_only", "literal_require_only", "ambient_node_modules_allowed",
  "dynamic_import_allowed", "eval_loader_allowed", "undeclared_dependency_allowed",
  "closure_local_package_resolution_required", "all_javascript_reachable_from_entrypoint",
  "allowed_builtins",
]);
const ENVELOPE_FIELDS = objectFreeze([
  "version", "kind", "signature_domain", "manifest", "manifest_digest",
  "authentication",
]);
const AUTHENTICATION_FIELDS = objectFreeze([
  "scheme", "key_usage", "key_id", "public_key_digest", "trust_epoch",
  "revocation_epoch", "signed_manifest_digest", "signature",
]);
const TRUST_POLICY_FIELDS = objectFreeze([
  "version", "kind", "current_trust_epoch", "current_revocation_epoch",
  "minimum_release_epoch", "revoked_release_ids", "revoked_manifest_digests", "keys",
]);
const TRUST_KEY_FIELDS = objectFreeze([
  "key_id", "public_key_spki_der", "public_key_digest", "trust_epoch",
  "not_before", "not_after", "revoked", "revocation_epoch",
  "allowed_provider_ids", "allowed_package_names",
]);
const CLAIM_FIELDS = objectFreeze([
  "manifest_digest", "key_id", "public_key_digest", "trust_epoch", "revocation_epoch",
]);

const PACKAGE_PATTERN = /^@(?:hacker-bob|bobnetsec)\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const REQUIRE_SPECIFIER_PATTERN = /^(?:node:[a-z0-9._/-]+|[a-z][a-z0-9._/-]*|\.{1,2}\/[A-Za-z0-9._@+/-]+|@[a-z0-9._-]+\/[a-z0-9._-]+(?:\/[a-z0-9._-]+)*)$/u;
const MEDIA_TYPE_VALUES = objectFreeze([
  "application/javascript", "application/json", "text/markdown",
]);
const RESOLUTION_KIND_VALUES = objectFreeze(["builtin", "relative", "package_export"]);
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const ED25519_SPKI_HEX_PATTERN = /^302a300506032b6570032100[a-f0-9]{64}$/u;
const CLOSURE_PATH_COMPONENT_PATTERN = /^(?:@[A-Za-z0-9][A-Za-z0-9._+-]{0,127}|[A-Za-z0-9][A-Za-z0-9._@+-]{0,127})$/u;

function makeRecord(fields, values) {
  const ordered = [];
  for (let index = 0; index < fields.length; index += 1) {
    setArrayIndex(ordered, ordered.length, values[fields[index]]);
  }
  return makeIndexedRecord(fields, ordered);
}

function assertClosurePath(value, label, code) {
  assertString(value, label, { maximumBytes: 512, code });
  if (value.startsWith("/") || value.includes("\\") || value.includes("//")
      || value.includes("\0")) reject(code, `${label} is not a closure-relative path`);
  const components = value.split("/");
  if (components.length < 1 || components.length > 16
      || components.some((component) => component === "." || component === ".."
        || !reflectApply(regexpTest, CLOSURE_PATH_COMPONENT_PATTERN, [component]))) {
    reject(code, `${label} contains a forbidden path component`);
  }
  return value;
}

function exactString(input, field, label, expected, code) {
  const value = assertString(ownValue(input, field, label, code), `${label}.${field}`, {
    maximumBytes: 512,
    code,
  });
  if (value !== expected) reject(code, `${label}.${field} is unsupported`);
  return value;
}

function exactBoolean(input, field, label, expected, code) {
  const value = ownValue(input, field, label, code);
  if (value !== expected) reject(code, `${label}.${field} must be ${expected}`);
  return value;
}

function normalizeSortedStrings(input, label, validator, maximum = 64, code = "schema_invalid") {
  assertDenseArray(input, label, maximum, code);
  const output = [];
  let previous = null;
  for (let index = 0; index < input.length; index += 1) {
    const value = validator(ownValue(input, `${index}`, label, code), `${label}[${index}]`, code);
    if (previous != null && value <= previous) reject(code, `${label} must be unique and sorted`);
    setArrayIndex(output, output.length, value);
    previous = value;
  }
  return makeArray(output);
}

function assertPackageName(value, label, code = "package_invalid") {
  return assertString(value, label, { pattern: PACKAGE_PATTERN, maximumBytes: 191, code });
}

function assertVersion(value, label, code = "package_invalid") {
  return assertString(value, label, { pattern: VERSION_PATTERN, maximumBytes: 128, code });
}

function normalizePackage(input, index) {
  const label = `manifest.packages[${index}]`;
  const code = "closure_package_invalid";
  assertExactObject(input, PACKAGE_FIELDS, label, code);
  return makeRecord(PACKAGE_FIELDS, {
    package_id: assertIdentifier(ownValue(input, "package_id", label, code),
      `${label}.package_id`, code),
    package_name: assertPackageName(ownValue(input, "package_name", label, code),
      `${label}.package_name`, code),
    package_version: assertVersion(ownValue(input, "package_version", label, code),
      `${label}.package_version`, code),
    package_root: assertClosurePath(ownValue(input, "package_root", label, code),
      `${label}.package_root`, code),
    manifest_path: assertClosurePath(ownValue(input, "manifest_path", label, code),
      `${label}.manifest_path`, code),
    manifest_sha256: assertDigest(ownValue(input, "manifest_sha256", label, code),
      `${label}.manifest_sha256`, code),
  });
}

function normalizeFile(input, index) {
  const label = `manifest.files[${index}]`;
  const code = "closure_file_invalid";
  assertExactObject(input, FILE_FIELDS, label, code);
  const mediaType = assertString(ownValue(input, "media_type", label, code),
    `${label}.media_type`, { maximumBytes: 64, code });
  if (!MEDIA_TYPE_VALUES.includes(mediaType)) reject(code, `${label}.media_type is unsupported`);
  const installMode = assertInteger(ownValue(input, "install_mode", label, code),
    `${label}.install_mode`, 0, 0o777, code);
  if (installMode !== 0o444) reject(code, `${label}.install_mode must be read-only`);
  return makeRecord(FILE_FIELDS, {
    path: assertClosurePath(ownValue(input, "path", label, code),
      `${label}.path`, code),
    byte_size: assertInteger(ownValue(input, "byte_size", label, code),
      `${label}.byte_size`, 1, 4 * 1024 * 1024, code),
    sha256: assertDigest(ownValue(input, "sha256", label, code),
      `${label}.sha256`, code),
    install_mode: installMode,
    media_type: mediaType,
  });
}

function normalizeEdge(input, index) {
  const label = `manifest.module_edges[${index}]`;
  const code = "closure_module_graph_invalid";
  assertExactObject(input, EDGE_FIELDS, label, code);
  const resolutionKind = assertString(ownValue(input, "resolution_kind", label, code),
    `${label}.resolution_kind`, { maximumBytes: 32, code });
  if (!RESOLUTION_KIND_VALUES.includes(resolutionKind)) {
    reject(code, `${label}.resolution_kind is unsupported`);
  }
  const specifier = assertString(ownValue(input, "specifier", label, code),
    `${label}.specifier`, { pattern: REQUIRE_SPECIFIER_PATTERN, maximumBytes: 256, code });
  const resolvedPath = assertString(ownValue(input, "resolved_path", label, code),
    `${label}.resolved_path`, { maximumBytes: 512, code });
  if (resolutionKind === "builtin") {
    const expectedBuiltin = specifier.startsWith("node:") ? specifier : `node:${specifier}`;
    if (resolvedPath !== expectedBuiltin) {
      reject(code, `${label} builtin binding is invalid`);
    }
  } else {
    assertClosurePath(resolvedPath, `${label}.resolved_path`, code);
    if (resolutionKind === "relative" && !specifier.startsWith(".")) {
      reject(code, `${label} relative binding is invalid`);
    }
    if (resolutionKind === "package_export" && !specifier.startsWith("@")) {
      reject(code, `${label} package binding is invalid`);
    }
  }
  return makeRecord(EDGE_FIELDS, {
    source_path: assertClosurePath(ownValue(input, "source_path", label, code),
      `${label}.source_path`, code),
    specifier,
    resolution_kind: resolutionKind,
    resolved_path: resolvedPath,
  });
}

function normalizeResolutionPolicy(input) {
  const label = "manifest.resolution_policy";
  const code = "closure_resolution_policy_invalid";
  assertExactObject(input, RESOLUTION_POLICY_FIELDS, label, code);
  return makeRecord(RESOLUTION_POLICY_FIELDS, {
    scheme: exactString(input, "scheme", label,
      "closed_commonjs_literal_resolution_v1", code),
    commonjs_only: exactBoolean(input, "commonjs_only", label, true, code),
    literal_require_only: exactBoolean(input, "literal_require_only", label, true, code),
    ambient_node_modules_allowed: exactBoolean(
      input, "ambient_node_modules_allowed", label, false, code,
    ),
    dynamic_import_allowed: exactBoolean(input, "dynamic_import_allowed", label, false, code),
    eval_loader_allowed: exactBoolean(input, "eval_loader_allowed", label, false, code),
    undeclared_dependency_allowed: exactBoolean(
      input, "undeclared_dependency_allowed", label, false, code,
    ),
    closure_local_package_resolution_required: exactBoolean(
      input, "closure_local_package_resolution_required", label, true, code,
    ),
    all_javascript_reachable_from_entrypoint: exactBoolean(
      input, "all_javascript_reachable_from_entrypoint", label, true, code,
    ),
    allowed_builtins: normalizeSortedStrings(
      ownValue(input, "allowed_builtins", label, code),
      `${label}.allowed_builtins`,
      (value, valueLabel, valueCode) => assertString(value, valueLabel, {
        pattern: /^node:[a-z][a-z0-9._/-]{0,127}$/u,
        maximumBytes: 133,
        code: valueCode,
      }),
      32,
      code,
    ),
  });
}

function normalizeManifest(input) {
  const label = "javascript worker closure manifest";
  const code = "closure_manifest_invalid";
  assertExactObject(input, MANIFEST_FIELDS, label, code);
  if (ownValue(input, "version", label, code) !== JAVASCRIPT_WORKER_CLOSURE_VERSION) {
    reject(code, "closure manifest version is unsupported");
  }
  exactString(input, "kind", label, "javascript_worker_release_closure_manifest", code);
  const packageInputs = ownValue(input, "packages", label, code);
  assertDenseArray(packageInputs, "manifest.packages", 8, code);
  if (packageInputs.length < 1) reject(code, "closure must bind at least one package");
  const packages = [];
  let previousPackage = null;
  for (let index = 0; index < packageInputs.length; index += 1) {
    const value = normalizePackage(ownValue(packageInputs, `${index}`, "manifest.packages", code),
      index);
    if (previousPackage != null && value.package_id <= previousPackage) {
      reject(code, "closure packages must be unique and sorted");
    }
    setArrayIndex(packages, packages.length, value);
    previousPackage = value.package_id;
  }
  const fileInputs = ownValue(input, "files", label, code);
  assertDenseArray(fileInputs, "manifest.files", 128, code);
  if (fileInputs.length < 4) reject(code, "closure file set is incomplete");
  const files = [];
  let previousFile = null;
  for (let index = 0; index < fileInputs.length; index += 1) {
    const value = normalizeFile(ownValue(fileInputs, `${index}`, "manifest.files", code), index);
    if (previousFile != null && value.path <= previousFile) {
      reject(code, "closure files must be unique and sorted");
    }
    setArrayIndex(files, files.length, value);
    previousFile = value.path;
  }
  const edgeInputs = ownValue(input, "module_edges", label, code);
  assertDenseArray(edgeInputs, "manifest.module_edges", 256, code);
  if (edgeInputs.length < 2) reject(code, "closure module graph is incomplete");
  const edges = [];
  let previousEdge = null;
  for (let index = 0; index < edgeInputs.length; index += 1) {
    const value = normalizeEdge(ownValue(edgeInputs, `${index}`, "manifest.module_edges", code),
      index);
    const identity = `${value.source_path}\0${value.specifier}\0${value.resolved_path}`;
    if (previousEdge != null && identity <= previousEdge) {
      reject(code, "closure module edges must be unique and sorted");
    }
    setArrayIndex(edges, edges.length, value);
    previousEdge = identity;
  }
  const packageName = assertPackageName(ownValue(input, "package_name", label, code),
    "manifest.package_name", code);
  const packageVersion = assertVersion(ownValue(input, "package_version", label, code),
    "manifest.package_version", code);
  const workerPackage = packages.find((record) => record.package_id === "worker");
  if (!workerPackage || workerPackage.package_name !== packageName
      || workerPackage.package_version !== packageVersion) {
    reject(code, "worker package identity is not bound by the closure");
  }
  const entrypoint = assertClosurePath(ownValue(input, "entrypoint", label, code),
    "manifest.entrypoint", code);
  if (!files.some((file) => file.path === entrypoint
      && file.media_type === "application/javascript")) {
    reject(code, "closure entrypoint is absent from the file set");
  }
  const resolutionPolicy = normalizeResolutionPolicy(
    ownValue(input, "resolution_policy", label, code),
  );
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  for (const packageRecord of packages) {
    const manifestFile = filesByPath.get(packageRecord.manifest_path);
    if (!packageRecord.manifest_path.startsWith(`${packageRecord.package_root}/`)
        || !manifestFile || manifestFile.media_type !== "application/json"
        || manifestFile.sha256 !== packageRecord.manifest_sha256) {
      reject(code, "closure package manifest is not bound to its package root and file record");
    }
  }
  const adjacency = new Map();
  for (const edge of edges) {
    const sourceFile = filesByPath.get(edge.source_path);
    if (!sourceFile || sourceFile.media_type !== "application/javascript") {
      reject(code, "closure module edge source is not a signed JavaScript file");
    }
    if (edge.resolution_kind === "builtin") {
      if (!resolutionPolicy.allowed_builtins.includes(edge.resolved_path)) {
        reject(code, "closure module edge uses a builtin outside the signed allowlist");
      }
      continue;
    }
    const targetFile = filesByPath.get(edge.resolved_path);
    if (!targetFile || targetFile.media_type !== "application/javascript") {
      reject(code, "closure module edge target is not a signed JavaScript file");
    }
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
    if (file.media_type === "application/javascript" && !reachable.has(file.path)) {
      reject(code, "closure contains JavaScript outside the signed entrypoint graph");
    }
  }
  return makeRecord(MANIFEST_FIELDS, {
    version: JAVASCRIPT_WORKER_CLOSURE_VERSION,
    kind: "javascript_worker_release_closure_manifest",
    release_id: assertOpaqueToken(ownValue(input, "release_id", label, code),
      "manifest.release_id", code),
    release_epoch: assertInteger(ownValue(input, "release_epoch", label, code),
      "manifest.release_epoch", 1, Number.MAX_SAFE_INTEGER, code),
    provider_id: assertIdentifier(ownValue(input, "provider_id", label, code),
      "manifest.provider_id", code),
    package_name: packageName,
    package_version: packageVersion,
    node_major: assertInteger(ownValue(input, "node_major", label, code),
      "manifest.node_major", 20, 20, code),
    entrypoint,
    packages: makeArray(packages),
    files: makeArray(files),
    module_edges: makeArray(edges),
    resolution_policy: resolutionPolicy,
    issued_at: assertTimestamp(ownValue(input, "issued_at", label, code),
      "manifest.issued_at", code),
    expires_at: assertTimestamp(ownValue(input, "expires_at", label, code),
      "manifest.expires_at", code),
  });
}

function digestJavascriptWorkerClosureManifest(input) {
  return domainDigest(JAVASCRIPT_WORKER_CLOSURE_MANIFEST_DOMAIN, normalizeManifest(input));
}

function normalizeClaim(input) {
  const label = "javascript worker closure signature claim";
  const code = "closure_signature_claim_invalid";
  assertExactObject(input, CLAIM_FIELDS, label, code);
  return makeRecord(CLAIM_FIELDS, {
    manifest_digest: assertDigest(ownValue(input, "manifest_digest", label, code),
      `${label}.manifest_digest`, code),
    key_id: assertOpaqueToken(ownValue(input, "key_id", label, code),
      `${label}.key_id`, code),
    public_key_digest: assertDigest(ownValue(input, "public_key_digest", label, code),
      `${label}.public_key_digest`, code),
    trust_epoch: assertInteger(ownValue(input, "trust_epoch", label, code),
      `${label}.trust_epoch`, 1, Number.MAX_SAFE_INTEGER, code),
    revocation_epoch: assertInteger(ownValue(input, "revocation_epoch", label, code),
      `${label}.revocation_epoch`, 1, Number.MAX_SAFE_INTEGER, code),
  });
}

function javascriptWorkerClosureSignatureMessage(input) {
  const digest = domainDigest(JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN, normalizeClaim(input));
  return bufferFrom(`${JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN}\0${digest}`, "utf8");
}

function normalizeAuthentication(input) {
  const label = "closure envelope.authentication";
  const code = "closure_authentication_invalid";
  assertExactObject(input, AUTHENTICATION_FIELDS, label, code);
  const signature = assertString(ownValue(input, "signature", label, code), `${label}.signature`, {
    pattern: SIGNATURE_PATTERN,
    minimumBytes: 86,
    maximumBytes: 86,
    code,
  });
  const signatureBytes = bufferFrom(signature, "base64url");
  if (signatureBytes.length !== 64
      || reflectApply(bufferToString, signatureBytes, ["base64url"]) !== signature) {
    reject(code, `${label}.signature is not canonical Ed25519 base64url`);
  }
  return makeRecord(AUTHENTICATION_FIELDS, {
    scheme: exactString(input, "scheme", label, "ed25519", code),
    key_usage: exactString(input, "key_usage", label,
      JAVASCRIPT_WORKER_CLOSURE_KEY_USAGE, code),
    key_id: assertOpaqueToken(ownValue(input, "key_id", label, code), `${label}.key_id`, code),
    public_key_digest: assertDigest(ownValue(input, "public_key_digest", label, code),
      `${label}.public_key_digest`, code),
    trust_epoch: assertInteger(ownValue(input, "trust_epoch", label, code),
      `${label}.trust_epoch`, 1, Number.MAX_SAFE_INTEGER, code),
    revocation_epoch: assertInteger(ownValue(input, "revocation_epoch", label, code),
      `${label}.revocation_epoch`, 1, Number.MAX_SAFE_INTEGER, code),
    signed_manifest_digest: assertDigest(
      ownValue(input, "signed_manifest_digest", label, code),
      `${label}.signed_manifest_digest`, code,
    ),
    signature,
  });
}

function normalizeEnvelope(input) {
  const label = "javascript worker closure envelope";
  const code = "closure_envelope_invalid";
  assertExactObject(input, ENVELOPE_FIELDS, label, code);
  if (ownValue(input, "version", label, code) !== JAVASCRIPT_WORKER_CLOSURE_VERSION) {
    reject(code, "closure envelope version is unsupported");
  }
  exactString(input, "kind", label, "signed_javascript_worker_release_closure", code);
  exactString(input, "signature_domain", label,
    JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN, code);
  const manifest = normalizeManifest(ownValue(input, "manifest", label, code));
  const manifestDigest = assertDigest(ownValue(input, "manifest_digest", label, code),
    "envelope.manifest_digest", code);
  if (manifestDigest !== domainDigest(JAVASCRIPT_WORKER_CLOSURE_MANIFEST_DOMAIN, manifest)) {
    reject(code, "closure manifest digest does not match canonical manifest");
  }
  const authentication = normalizeAuthentication(
    ownValue(input, "authentication", label, code),
  );
  if (authentication.signed_manifest_digest !== manifestDigest) {
    reject(code, "closure authentication does not bind the manifest digest");
  }
  return makeRecord(ENVELOPE_FIELDS, {
    version: JAVASCRIPT_WORKER_CLOSURE_VERSION,
    kind: "signed_javascript_worker_release_closure",
    signature_domain: JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN,
    manifest,
    manifest_digest: manifestDigest,
    authentication,
  });
}

function normalizeTrustKey(input, index) {
  const label = `closure trust policy.keys[${index}]`;
  const code = "closure_trust_key_invalid";
  assertExactObject(input, TRUST_KEY_FIELDS, label, code);
  const encoded = assertString(ownValue(input, "public_key_spki_der", label, code),
    `${label}.public_key_spki_der`, { pattern: BASE64URL_PATTERN, maximumBytes: 128, code });
  let der;
  let runtimeKey;
  try {
    der = bufferFrom(encoded, "base64url");
    if (encoded !== reflectApply(bufferToString, der, ["base64url"])
        || !reflectApply(regexpTest, ED25519_SPKI_HEX_PATTERN, [
          reflectApply(bufferToString, der, ["hex"]),
        ])) {
      reject(code, `${label}.public_key_spki_der is not an Ed25519 SPKI key`);
    }
    runtimeKey = reflectApply(cryptoCreatePublicKey, crypto, [{
      key: der,
      format: "der",
      type: "spki",
    }]);
  } catch {
    reject(code, `${label}.public_key_spki_der is not an Ed25519 SPKI key`);
  }
  const publicKeyDigest = assertDigest(ownValue(input, "public_key_digest", label, code),
    `${label}.public_key_digest`, code);
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [der]);
  const observedDigest = reflectApply(hashDigest, hash, ["hex"]);
  if (observedDigest !== publicKeyDigest) reject(code, `${label} public key digest mismatch`);
  return {
    normalized: makeRecord(TRUST_KEY_FIELDS, {
      key_id: assertOpaqueToken(ownValue(input, "key_id", label, code),
        `${label}.key_id`, code),
      public_key_spki_der: encoded,
      public_key_digest: publicKeyDigest,
      trust_epoch: assertInteger(ownValue(input, "trust_epoch", label, code),
        `${label}.trust_epoch`, 1, Number.MAX_SAFE_INTEGER, code),
      not_before: assertTimestamp(ownValue(input, "not_before", label, code),
        `${label}.not_before`, code),
      not_after: assertTimestamp(ownValue(input, "not_after", label, code),
        `${label}.not_after`, code),
      revoked: assertBoolean(ownValue(input, "revoked", label, code),
        `${label}.revoked`, code),
      revocation_epoch: assertInteger(ownValue(input, "revocation_epoch", label, code),
        `${label}.revocation_epoch`, 0, Number.MAX_SAFE_INTEGER, code),
      allowed_provider_ids: normalizeSortedStrings(
        ownValue(input, "allowed_provider_ids", label, code),
        `${label}.allowed_provider_ids`, assertIdentifier, 16, code,
      ),
      allowed_package_names: normalizeSortedStrings(
        ownValue(input, "allowed_package_names", label, code),
        `${label}.allowed_package_names`, assertPackageName, 16, code,
      ),
    }),
    runtimeKey,
  };
}

function normalizeTrustPolicy(input) {
  const label = "javascript worker closure trust policy";
  const code = "closure_trust_policy_invalid";
  assertExactObject(input, TRUST_POLICY_FIELDS, label, code);
  if (ownValue(input, "version", label, code) !== JAVASCRIPT_WORKER_CLOSURE_VERSION) {
    reject(code, "closure trust policy version is unsupported");
  }
  exactString(input, "kind", label, "javascript_worker_closure_trust_policy", code);
  const keyInputs = ownValue(input, "keys", label, code);
  assertDenseArray(keyInputs, "closure trust policy.keys", 32, code);
  if (keyInputs.length < 1) reject(code, "closure trust policy keyring is empty");
  const keys = [];
  const runtimeKeys = [];
  const publicKeySpkis = new SafeSet();
  const publicKeyDigests = new SafeSet();
  let previous = null;
  for (let index = 0; index < keyInputs.length; index += 1) {
    const key = normalizeTrustKey(ownValue(keyInputs, `${index}`, "trust policy.keys", code), index);
    if (previous != null && key.normalized.key_id <= previous) {
      reject(code, "closure trust keys must be unique and sorted");
    }
    if (reflectApply(setHas, publicKeySpkis, [key.normalized.public_key_spki_der])
        || reflectApply(setHas, publicKeyDigests, [key.normalized.public_key_digest])) {
      reject(code, "closure trust keys cannot alias Ed25519 key material across key IDs");
    }
    reflectApply(setAdd, publicKeySpkis, [key.normalized.public_key_spki_der]);
    reflectApply(setAdd, publicKeyDigests, [key.normalized.public_key_digest]);
    setArrayIndex(keys, keys.length, key.normalized);
    setArrayIndex(runtimeKeys, runtimeKeys.length, key.runtimeKey);
    previous = key.normalized.key_id;
  }
  const normalized = makeRecord(TRUST_POLICY_FIELDS, {
    version: JAVASCRIPT_WORKER_CLOSURE_VERSION,
    kind: "javascript_worker_closure_trust_policy",
    current_trust_epoch: assertInteger(ownValue(input, "current_trust_epoch", label, code),
      "trust_policy.current_trust_epoch", 1, Number.MAX_SAFE_INTEGER, code),
    current_revocation_epoch: assertInteger(
      ownValue(input, "current_revocation_epoch", label, code),
      "trust_policy.current_revocation_epoch", 1, Number.MAX_SAFE_INTEGER, code,
    ),
    minimum_release_epoch: assertInteger(ownValue(input, "minimum_release_epoch", label, code),
      "trust_policy.minimum_release_epoch", 1, Number.MAX_SAFE_INTEGER, code),
    revoked_release_ids: normalizeSortedStrings(
      ownValue(input, "revoked_release_ids", label, code),
      "trust_policy.revoked_release_ids", assertOpaqueToken, 128, code,
    ),
    revoked_manifest_digests: normalizeSortedStrings(
      ownValue(input, "revoked_manifest_digests", label, code),
      "trust_policy.revoked_manifest_digests", assertDigest, 128, code,
    ),
    keys: makeArray(keys),
  });
  return { normalized, runtimeKeys };
}

function verifyJavascriptWorkerClosureEnvelope(input) {
  const label = "javascript worker closure verification";
  const code = "closure_verification_input_invalid";
  assertExactObject(input, ["envelope", "trust_policy", "now"], label, code);
  const envelope = normalizeEnvelope(ownValue(input, "envelope", label, code));
  const trust = normalizeTrustPolicy(ownValue(input, "trust_policy", label, code));
  const now = assertTimestamp(ownValue(input, "now", label, code), "verification.now", code);
  const nowMs = timestampMilliseconds(now, "verification.now", code);
  const manifest = envelope.manifest;
  const auth = envelope.authentication;
  if (manifest.release_epoch < trust.normalized.minimum_release_epoch) {
    reject("closure_release_rollback", "closure release epoch is below the policy floor");
  }
  if (trust.normalized.revoked_release_ids.includes(manifest.release_id)) {
    reject("closure_release_revoked", "closure release ID is revoked");
  }
  if (trust.normalized.revoked_manifest_digests.includes(envelope.manifest_digest)) {
    reject("closure_manifest_revoked", "closure manifest digest is revoked");
  }
  if (nowMs < timestampMilliseconds(manifest.issued_at, "manifest.issued_at")
      || nowMs >= timestampMilliseconds(manifest.expires_at, "manifest.expires_at")) {
    reject("closure_release_time_rejected", "closure release is outside its validity window");
  }
  let keyIndex = -1;
  for (let index = 0; index < trust.normalized.keys.length; index += 1) {
    if (trust.normalized.keys[index].key_id === auth.key_id) keyIndex = index;
  }
  if (keyIndex < 0) reject("closure_untrusted_key", "closure key is not trusted");
  const key = trust.normalized.keys[keyIndex];
  if (key.revoked) reject("closure_revoked_key", "closure key is revoked");
  if (key.trust_epoch !== trust.normalized.current_trust_epoch
      || auth.trust_epoch !== trust.normalized.current_trust_epoch
      || key.trust_epoch !== auth.trust_epoch
      || key.revocation_epoch !== trust.normalized.current_revocation_epoch
      || auth.revocation_epoch !== trust.normalized.current_revocation_epoch
      || key.public_key_digest !== auth.public_key_digest) {
    reject("closure_trust_binding_rejected", "closure trust or revocation epoch is stale");
  }
  if (!key.allowed_provider_ids.includes(manifest.provider_id)
      || !key.allowed_package_names.includes(manifest.package_name)) {
    reject("closure_key_scope_rejected", "closure package is outside release key scope");
  }
  if (nowMs < timestampMilliseconds(key.not_before, "key.not_before")
      || nowMs >= timestampMilliseconds(key.not_after, "key.not_after")) {
    reject("closure_key_time_rejected", "closure key is outside its validity window");
  }
  const claim = {
    manifest_digest: envelope.manifest_digest,
    key_id: auth.key_id,
    public_key_digest: auth.public_key_digest,
    trust_epoch: auth.trust_epoch,
    revocation_epoch: auth.revocation_epoch,
  };
  let valid = false;
  try {
    valid = reflectApply(cryptoVerify, crypto, [
      null,
      javascriptWorkerClosureSignatureMessage(claim),
      trust.runtimeKeys[keyIndex],
      bufferFrom(auth.signature, "base64url"),
    ]);
  } catch {
    valid = false;
  }
  if (!valid) reject("closure_signature_invalid", "closure Ed25519 signature failed");
  return objectFreeze({
    version: JAVASCRIPT_WORKER_CLOSURE_VERSION,
    kind: "verified_javascript_worker_release_closure_non_authorizing",
    manifest,
    manifest_digest: envelope.manifest_digest,
    envelope_digest: domainDigest(JAVASCRIPT_WORKER_CLOSURE_ENVELOPE_DOMAIN, envelope),
    trust_policy_digest: domainDigest(
      "hacker-bob/javascript-worker-closure-trust-policy/v1",
      trust.normalized,
    ),
    key_id: key.key_id,
    public_key_digest: key.public_key_digest,
    trust_epoch: key.trust_epoch,
    revocation_epoch: key.revocation_epoch,
    release_signature_valid: true,
    closure_bytes_bound: true,
    external_immutable_keyring_observed: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
    blockers: JAVASCRIPT_WORKER_CLOSURE_BLOCKERS,
  });
}

module.exports = {
  JAVASCRIPT_WORKER_CLOSURE_BLOCKERS,
  JAVASCRIPT_WORKER_CLOSURE_ENVELOPE_DOMAIN,
  JAVASCRIPT_WORKER_CLOSURE_KEY_USAGE,
  JAVASCRIPT_WORKER_CLOSURE_MANIFEST_DOMAIN,
  JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN,
  JAVASCRIPT_WORKER_CLOSURE_VERSION,
  digestJavascriptWorkerClosureManifest,
  javascriptWorkerClosureSignatureMessage,
  verifyJavascriptWorkerClosureEnvelope,
};

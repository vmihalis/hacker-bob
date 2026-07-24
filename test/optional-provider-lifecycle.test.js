"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const {
  installLifecycleCustodianTestDouble,
} = require("./fixtures/lifecycle-custodian-test-port.js");

const lifecycleCustodianTest = installLifecycleCustodianTestDouble();

const {
  OPTIONAL_PROVIDER_REGISTRY,
  OPTIONAL_PROVIDER_STATUS_VALUES,
} = require("../scripts/lib/optional-provider-registry.js");
const lifecycle = require("../scripts/lib/optional-provider-lifecycle.js");
const {
  analyzeClosedCommonjsSource,
  createClosedCommonjsLoader,
} = require("../scripts/lib/closed-commonjs-loader.js");
const { copyCanonicalRuntimePackages } = require("../scripts/install.js");
const { doctorProject, uninstallProject } = require("../scripts/lifecycle.js");
const {
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
  MCP_TOP_LEVEL_RUNTIME_FILES,
} = require("../scripts/lib/package-policy.js");
const {
  inspectBobOwnedRuntimeStatically,
  inspectMcpServerStatically,
} = require("../scripts/lib/static-runtime-inspection.js");
const {
  LIFECYCLE_CUSTODIAN_SELECTIONS,
} = require("../scripts/lib/lifecycle-custodian-contract.js");
const {
  createNativePrebuildV2ReleaseSource,
} = require("./helpers/native-prebuild-v2-release.js");
const trust = require("../packages/bob-instrument-native-prebuild-trust/lib/index.js");
const workerClosureTrust = require(
  "../packages/bob-instrument-native-prebuild-trust/lib/javascript-worker-closure.js"
);

const ROOT = path.resolve(__dirname, "..");
const NOW = "2026-07-19T12:00:00.000Z";
const WORKER_HOST = Object.freeze({
  os: "darwin",
  architecture: "arm64",
  node_major: 20,
  napi_version: 9,
});

function temporaryDirectory(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function workerManifest(overrides = {}) {
  return {
    ...JSON.parse(fs.readFileSync(
      path.join(ROOT, "packages/bob-instrument-chameleon-worker/package.json"),
      "utf8",
    )),
    ...overrides,
  };
}

const WORKER_RELEASES = new Map();
const WORKER_RELEASE_PRIVATE_KEYS = new Map();
const WORKER_CLOSURE_JS_FILES = Object.freeze([
  [
    "packages/bob-instrument-chameleon-worker/lib/serialport-usb-cdc-driver.js",
    "worker/lib/serialport-usb-cdc-driver.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/usb-cdc-custody.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/usb-cdc-custody.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/hf14a-probe-compiler.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/hf14a-probe-compiler.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/rf-off-usb-execution-port.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/rf-off-usb-execution-port.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/compiled-provider-command.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/compiled-provider-command.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/codec.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/codec.js",
  ],
  [
    "packages/bob-instrument-chameleon-worker-runtime/lib/closed-runtime-contracts.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/closed-runtime-contracts.js",
  ],
]);

function writeWorkerClosureFile(root, relative, contents) {
  const destination = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, contents);
}

function workerClosureFiles(root) {
  const output = [];
  const visit = (directory, parent = "") => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const relative = parent ? `${parent}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute, relative);
      else {
        const contents = fs.readFileSync(absolute);
        output.push({
          path: relative,
          byte_size: contents.length,
          sha256: digest(contents),
          install_mode: 0o444,
          media_type: relative.endsWith(".js") ? "application/javascript"
            : (relative.endsWith(".json") ? "application/json" : "text/markdown"),
        });
      }
    }
  };
  visit(root);
  return output.sort((left, right) => (
    left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)
  ));
}

function resolveFixtureWorkerEdge(sourcePath, specifier) {
  if (specifier.startsWith("node:") || ["crypto", "fs", "path", "util"].includes(specifier)) {
    return {
      source_path: sourcePath,
      specifier,
      resolution_kind: "builtin",
      resolved_path: specifier.startsWith("node:") ? specifier : `node:${specifier}`,
    };
  }
  if (specifier.startsWith(".")) {
    return {
      source_path: sourcePath,
      specifier,
      resolution_kind: "relative",
      resolved_path: path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), specifier)),
    };
  }
  const packageExports = {
    "@hacker-bob/instrument-chameleon-worker-runtime": {
      root: "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime",
      exports: {
        ".": "lib/codec.js",
        "./codec": "lib/codec.js",
        "./compiled-provider-command": "lib/compiled-provider-command.js",
        "./hf14a-probe-compiler": "lib/hf14a-probe-compiler.js",
        "./rf-off-usb-execution-port": "lib/rf-off-usb-execution-port.js",
        "./usb-cdc-custody": "lib/usb-cdc-custody.js",
      },
    },
  };
  const packageName = Object.keys(packageExports).find((candidate) =>
    specifier === candidate || specifier.startsWith(`${candidate}/`));
  if (!packageName) throw new Error(`unexpected fixture dependency ${specifier}`);
  const subpath = specifier === packageName ? "." : `./${specifier.slice(packageName.length + 1)}`;
  const target = packageExports[packageName].exports[subpath];
  if (!target) throw new Error(`unexpected fixture dependency ${specifier}`);
  return {
    source_path: sourcePath,
    specifier,
    resolution_kind: "package_export",
    resolved_path: `${packageExports[packageName].root}/${target}`,
  };
}

function workerClosureEdges(root, files) {
  const edges = [];
  for (const file of files.filter((record) => record.media_type === "application/javascript")) {
    const source = fs.readFileSync(path.join(root, ...file.path.split("/")), "utf8");
    for (const specifier of analyzeClosedCommonjsSource(source, file.path)) {
      edges.push(resolveFixtureWorkerEdge(file.path, specifier));
    }
  }
  return edges.sort((left, right) => {
    const leftIdentity = `${left.source_path}\0${left.specifier}\0${left.resolved_path}`;
    const rightIdentity = `${right.source_path}\0${right.specifier}\0${right.resolved_path}`;
    return leftIdentity < rightIdentity ? -1 : (leftIdentity > rightIdentity ? 1 : 0);
  });
}

function makeWorkerSource(root, overrides = {}, options = {}) {
  if (options.resign_only !== true) {
    const workerRoot = path.join(root, "worker");
    fs.mkdirSync(workerRoot, { recursive: true });
    writeJson(path.join(workerRoot, "package.json"), workerManifest(overrides));
    writeWorkerClosureFile(root, "worker/README.md", "# inert signed worker closure\n");
    for (const [sourceRelative, destinationRelative] of WORKER_CLOSURE_JS_FILES) {
      writeWorkerClosureFile(
        root,
        destinationRelative,
        fs.readFileSync(path.join(ROOT, sourceRelative)),
      );
    }
    for (const packageDirectory of ["bob-instrument-chameleon-worker-runtime"]) {
      const manifest = JSON.parse(fs.readFileSync(
        path.join(ROOT, "packages", packageDirectory, "package.json"),
        "utf8",
      ));
      writeJson(path.join(
        root,
        "worker",
        "node_modules",
        "@hacker-bob",
        manifest.name.slice("@hacker-bob/".length),
        "package.json",
      ), manifest);
    }
  }
  const files = workerClosureFiles(root);
  const packages = [
    {
      package_id: "chameleon_worker_runtime",
      package_name: "@hacker-bob/instrument-chameleon-worker-runtime",
      package_version: "0.0.0-development",
      package_root: "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime",
      manifest_path: "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/package.json",
      manifest_sha256: files.find((record) =>
        record.path === "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/package.json").sha256,
    },
    {
      package_id: "worker",
      package_name: "@hacker-bob/instrument-chameleon-worker",
      package_version: "0.0.0-development",
      package_root: "worker",
      manifest_path: "worker/package.json",
      manifest_sha256: files.find((record) => record.path === "worker/package.json").sha256,
    },
  ];
  const moduleEdges = workerClosureEdges(root, files);
  const signedJavascriptPaths = new Set(files
    .filter((record) => record.media_type === "application/javascript")
    .map((record) => record.path));
  const missingEdge = moduleEdges.find((edge) => (
    edge.resolution_kind !== "builtin" && !signedJavascriptPaths.has(edge.resolved_path)
  ));
  if (missingEdge) {
    throw new Error(`fixture worker edge target is absent: ${JSON.stringify(missingEdge)}`);
  }
  const manifest = {
    version: 1,
    kind: "javascript_worker_release_closure_manifest",
    release_id: "worker-closure:2026.07.19.lifecycle-test",
    release_epoch: 11,
    provider_id: "chameleon_ultra",
    package_name: "@hacker-bob/instrument-chameleon-worker",
    package_version: "0.0.0-development",
    node_major: 20,
    entrypoint: "worker/lib/serialport-usb-cdc-driver.js",
    packages,
    files,
    module_edges: moduleEdges,
    resolution_policy: {
      scheme: "closed_commonjs_literal_resolution_v1",
      commonjs_only: true,
      literal_require_only: true,
      ambient_node_modules_allowed: false,
      dynamic_import_allowed: false,
      eval_loader_allowed: false,
      undeclared_dependency_allowed: false,
      closure_local_package_resolution_required: true,
      all_javascript_reachable_from_entrypoint: true,
      allowed_builtins: ["node:crypto", "node:fs", "node:path", "node:util"],
    },
    issued_at: "2026-07-19T00:00:00.000Z",
    expires_at: "2026-07-20T00:00:00.000Z",
  };
  if (options.resign_only === true) {
    const existing = cloneWorkerVerification(root);
    manifest.release_epoch = existing.envelope.manifest.release_epoch + 1;
    manifest.release_id = `worker-closure:2026.07.19.lifecycle-test-r${manifest.release_epoch}`;
    existing.envelope.manifest = manifest;
    resignWorkerVerification(root, existing);
    WORKER_RELEASES.set(path.resolve(root), existing);
    return;
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyDigest = digest(publicDer);
  const manifestDigest = workerClosureTrust.digestJavascriptWorkerClosureManifest(manifest);
  const claim = {
    manifest_digest: manifestDigest,
    key_id: "worker-release-key:lifecycle-test",
    public_key_digest: publicKeyDigest,
    trust_epoch: 11,
    revocation_epoch: 11,
  };
  const envelope = {
    version: 1,
    kind: "signed_javascript_worker_release_closure",
    signature_domain: workerClosureTrust.JAVASCRIPT_WORKER_CLOSURE_SIGNATURE_DOMAIN,
    manifest,
    manifest_digest: manifestDigest,
    authentication: {
      scheme: "ed25519",
      key_usage: workerClosureTrust.JAVASCRIPT_WORKER_CLOSURE_KEY_USAGE,
      key_id: claim.key_id,
      public_key_digest: publicKeyDigest,
      trust_epoch: 11,
      revocation_epoch: 11,
      signed_manifest_digest: manifestDigest,
      signature: crypto.sign(
        null,
        workerClosureTrust.javascriptWorkerClosureSignatureMessage(claim),
        privateKey,
      ).toString("base64url"),
    },
  };
  const trustPolicy = {
    version: 1,
    kind: "javascript_worker_closure_trust_policy",
    current_trust_epoch: 11,
    current_revocation_epoch: 11,
    minimum_release_epoch: 11,
    revoked_release_ids: [],
    revoked_manifest_digests: [],
    keys: [{
      key_id: claim.key_id,
      public_key_spki_der: publicDer.toString("base64url"),
      public_key_digest: publicKeyDigest,
      trust_epoch: 11,
      not_before: "2026-07-18T00:00:00.000Z",
      not_after: "2026-07-21T00:00:00.000Z",
      revoked: false,
      revocation_epoch: 11,
      allowed_provider_ids: ["chameleon_ultra"],
      allowed_package_names: ["@hacker-bob/instrument-chameleon-worker"],
    }],
  };
  WORKER_RELEASES.set(path.resolve(root), {
    envelope,
    trust_policy: trustPolicy,
    now: NOW,
  });
  WORKER_RELEASE_PRIVATE_KEYS.set(path.resolve(root), privateKey);
}

function resignWorkerSource(root) {
  makeWorkerSource(root, {}, { resign_only: true });
}

function signWorkerFilesWithoutRebuildingGraph(root) {
  const verification = cloneWorkerVerification(root);
  const files = workerClosureFiles(root);
  verification.envelope.manifest.files = files;
  for (const packageRecord of verification.envelope.manifest.packages) {
    packageRecord.manifest_sha256 = files.find((record) =>
      record.path === packageRecord.manifest_path).sha256;
  }
  return resignWorkerVerification(root, verification);
}

function cloneWorkerVerification(root) {
  return JSON.parse(JSON.stringify(WORKER_RELEASES.get(path.resolve(root))));
}

function resignWorkerVerification(root, verification) {
  const privateKey = WORKER_RELEASE_PRIVATE_KEYS.get(path.resolve(root));
  const manifestDigest = workerClosureTrust.digestJavascriptWorkerClosureManifest(
    verification.envelope.manifest,
  );
  verification.envelope.manifest_digest = manifestDigest;
  verification.envelope.authentication.signed_manifest_digest = manifestDigest;
  verification.envelope.authentication.signature = crypto.sign(
    null,
    workerClosureTrust.javascriptWorkerClosureSignatureMessage({
      manifest_digest: manifestDigest,
      key_id: verification.envelope.authentication.key_id,
      public_key_digest: verification.envelope.authentication.public_key_digest,
      trust_epoch: verification.envelope.authentication.trust_epoch,
      revocation_epoch: verification.envelope.authentication.revocation_epoch,
    }),
    privateKey,
  ).toString("base64url");
  return verification;
}

function workerVerificationAtEpochs(root, overrides = {}) {
  const verification = cloneWorkerVerification(root);
  const authentication = verification.envelope.authentication;
  const key = verification.trust_policy.keys.find((record) =>
    record.key_id === authentication.key_id);
  const releaseEpoch = overrides.release_epoch == null
    ? verification.envelope.manifest.release_epoch : overrides.release_epoch;
  const trustEpoch = overrides.trust_epoch == null
    ? authentication.trust_epoch : overrides.trust_epoch;
  const revocationEpoch = overrides.revocation_epoch == null
    ? authentication.revocation_epoch : overrides.revocation_epoch;
  verification.envelope.manifest.release_epoch = releaseEpoch;
  verification.envelope.manifest.release_id = overrides.release_id
    || verification.envelope.manifest.release_id;
  authentication.trust_epoch = trustEpoch;
  authentication.revocation_epoch = revocationEpoch;
  verification.trust_policy.current_trust_epoch = trustEpoch;
  verification.trust_policy.current_revocation_epoch = revocationEpoch;
  verification.trust_policy.minimum_release_epoch = Math.min(
    verification.trust_policy.minimum_release_epoch,
    releaseEpoch,
  );
  key.trust_epoch = trustEpoch;
  key.revocation_epoch = revocationEpoch;
  if (overrides.policy_equivocation === true) {
    verification.trust_policy.revoked_release_ids = ["worker-closure:unrelated"];
  }
  return resignWorkerVerification(root, verification);
}

function workerLifecycleInput(target, source, extra = {}) {
  return {
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    source_root: source,
    release_verification: WORKER_RELEASES.get(path.resolve(source)) || null,
    now: NOW,
    ...extra,
  };
}

function workerProbe(target, extra = {}) {
  return lifecycle.probeOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    host: WORKER_HOST,
    qualification_input: null,
    ...extra,
  });
}

function transactionPaths(target) {
  const providerRoot = path.join(
    target,
    ".hacker-bob",
    "optional-providers",
    "chameleon-ultra",
  );
  return {
    providerRoot,
    packageRoot: path.join(providerRoot, "worker-source"),
    stagingRoot: path.join(providerRoot, ".staging-worker_source"),
    backupRoot: path.join(providerRoot, ".backup-worker_source"),
    journal: path.join(providerRoot, ".transaction-worker_source.json"),
  };
}

function countExactDirectoryOpens(directory, callback) {
  const expected = path.resolve(directory);
  const originalOpenSync = fs.openSync;
  let count = 0;
  fs.openSync = function instrumentedOpenSync(filePath, flags, ...args) {
    if (typeof filePath === "string" && path.resolve(filePath) === expected
        && typeof flags === "number"
        && (flags & fs.constants.O_DIRECTORY) === fs.constants.O_DIRECTORY) count += 1;
    return Reflect.apply(originalOpenSync, this, [filePath, flags, ...args]);
  };
  try {
    return Object.freeze({ result: callback(), count });
  } finally {
    fs.openSync = originalOpenSync;
  }
}

function digest(value) {
  return require("node:crypto").createHash("sha256").update(value).digest("hex");
}

function makeLegacyNativeReleaseSource(root) {
  const crypto = require("node:crypto");
  const packageName = "@hacker-bob/instrument-native-prebuild-darwin-arm64";
  const packageVersion = "1.2.3";
  const artifactPaths = [
    "native/ipc-acceptor.node",
    "native/chameleon-cdc-custody.node",
    "bin/bob-safety-watchdog",
    "bin/bob-privileged-launcher",
  ];
  const artifactKinds = [
    "node_native_addon",
    "node_native_addon",
    "mach_o_executable",
    "mach_o_executable",
  ];
  const codeTypes = ["bundle", "bundle", "executable", "executable"];
  const artifacts = artifactPaths.map((artifactPath, index) => ({
    path: artifactPath,
    contents: Buffer.from(`inert-signed-artifact-${index}-${"x".repeat(index + 1)}`, "utf8"),
  }));
  const manifest = {
    version: 1,
    kind: "native_prebuild_release_manifest",
    package_name: packageName,
    package_version: packageVersion,
    release_id: "native-prebuild:2026.07.19.lifecycle-test",
    release_epoch: 7,
    target: {
      os: "darwin",
      architecture: "arm64",
      node_major: 20,
      napi_version: 9,
      node_api_only: true,
      deployment_format: "signed_immutable_prebuild_set",
    },
    components: trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS.map((componentId, index) => ({
      component_id: componentId,
      artifact_path: artifactPaths[index],
      artifact_kind: artifactKinds[index],
      byte_size: artifacts[index].contents.length,
      sha256: digest(artifacts[index].contents),
      source_digest: digest(`source-${index}`),
      builder_digest: digest(`builder-${index}`),
      toolchain_digest: digest(`toolchain-${index}`),
      provenance_digest: digest(`provenance-${index}`),
      dynamic_dependency_policy: {
        exact_dependencies: ["/usr/lib/libSystem.B.dylib"],
        weak_dependencies_allowed: false,
        upward_dependencies_allowed: false,
        rpaths_allowed: false,
      },
      macho_signing_policy: {
        signature_kind: "developer_id",
        code_type: codeTypes[index],
        team_identifier: "ABCDEF1234",
        signing_identifier: `org.hackerbob.lifecycle.${componentId.replaceAll("_", "-")}`,
        cdhash_algorithm: "sha256",
        hardened_runtime_required: true,
        notarization_required: true,
        adhoc_allowed: false,
        designated_requirement_digest: digest(`requirement-${index}`),
        entitlements_digest: digest(`entitlements-${index}`),
      },
    })),
    source_tree_digest: digest("source-tree"),
    builder_identity_digest: digest("builder-identity"),
    toolchain_manifest_digest: digest("toolchain-manifest"),
    provenance_statement_digest: digest("provenance-statement"),
    principal_acl_policy_digest: digest("principal-acl-policy"),
    filesystem_policy: {
      install_root_owner_uid: 0,
      install_root_owner_gid: 0,
      artifact_owner_uid: 0,
      artifact_owner_gid: 0,
      install_root_path_digest: digest("install-root"),
      required_open_scheme: "openat_no_follow_descriptor_walk_v1",
      max_static_inspection_age_ms: 30 * 60 * 1000,
      required_immutability_evidence_scheme:
        "read_only_mount_or_darwin_system_immutable_flags_v1",
      require_root_owned_ancestry: true,
      require_no_symlinks: true,
      require_regular_files: true,
      require_single_link: true,
      require_stable_file_identity: true,
      require_retained_artifact_fds: true,
      require_root_immutable: true,
      require_artifact_immutable: true,
      require_read_only_mount_or_system_immutable: true,
      require_mapped_image_binding: true,
    },
    native_attestation_policy: {
      scheme: "darwin_loaded_image_identity_v1",
      attestor_implementation_digest: digest("attestor-implementation"),
      attestor_source_digest: digest("attestor-source"),
      attestor_loaded_image_digest: digest("attestor-loaded-image"),
      component_identity_binding_scheme: "darwin_fd_codesign_loaded_mapped_cross_binding_v1",
      max_attestation_age_ms: 20 * 60 * 1000,
      require_kernel_originated_identity: true,
      require_on_disk_fd_binding: true,
      require_loaded_or_exec_image_binding: true,
      require_mapped_process_image_binding: true,
      require_component_host_or_equivalent_validation: true,
      require_pre_post_identity_match: true,
      require_live_double_read: true,
      require_principal_acl_binding: true,
    },
    hil_policy: {
      suite_id: "plane_ph_native_prebuild_hil",
      suite_digest: digest("hil-suite"),
      authority_scope_digest: digest("hil-authority-scope"),
      device_qualification_policy_digest: digest("hil-device-policy"),
      fixture_manifest_digest: digest("hil-fixture-manifest"),
      operator_witness_policy_digest: digest("hil-witness-policy"),
      max_evidence_age_ms: 10 * 60 * 1000,
      required_gate_ids: [...trust.NATIVE_PREBUILD_REQUIRED_HIL_GATES],
    },
    issued_at: "2026-07-19T00:00:00.000Z",
    expires_at: "2026-07-20T00:00:00.000Z",
  };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyDigest = digest(publicDer);
  const manifestDigest = trust.digestReleaseManifest(manifest);
  const claim = {
    manifest_digest: manifestDigest,
    key_id: "native-release-key:lifecycle-test",
    public_key_digest: publicKeyDigest,
    trust_epoch: 7,
  };
  const envelope = {
    version: 1,
    kind: "signed_native_prebuild_release",
    signature_domain: trust.NATIVE_PREBUILD_SIGNATURE_DOMAIN,
    manifest,
    manifest_digest: manifestDigest,
    authentication: {
      scheme: "ed25519",
      key_usage: trust.NATIVE_PREBUILD_KEY_USAGE,
      key_id: claim.key_id,
      public_key_digest: publicKeyDigest,
      trust_epoch: 7,
      signed_manifest_digest: manifestDigest,
      signature: crypto.sign(null, trust.releaseSignatureMessage(claim), privateKey)
        .toString("base64url"),
    },
  };
  const trustPolicy = {
    version: 1,
    kind: "native_prebuild_trust_policy",
    current_trust_epoch: 7,
    minimum_release_epoch: 7,
    revoked_release_ids: [],
    revoked_manifest_digests: [],
    keys: [{
      key_id: claim.key_id,
      public_key_spki_der: publicDer.toString("base64url"),
      public_key_digest: publicKeyDigest,
      trust_epoch: 7,
      not_before: "2026-07-18T00:00:00.000Z",
      not_after: "2026-07-21T00:00:00.000Z",
      revoked: false,
      revocation_epoch: 0,
      allowed_package_names: [packageName],
      allowed_component_ids: [...trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS],
    }],
  };
  fs.mkdirSync(root, { recursive: true });
  writeJson(path.join(root, "package.json"), {
    name: packageName,
    version: packageVersion,
    private: true,
    type: "commonjs",
  });
  for (let index = 0; index < artifacts.length; index += 1) {
    const artifact = artifacts[index];
    const destination = path.join(root, ...artifact.path.split("/"));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, artifact.contents);
    fs.chmodSync(destination, artifactKinds[index] === "mach_o_executable" ? 0o755 : 0o644);
  }
  return {
    artifacts,
    manifest,
    releaseVerification: { envelope, trust_policy: trustPolicy, now: NOW },
  };
}

function makeNativeReleaseSource(root) {
  return createNativePrebuildV2ReleaseSource(root);
}

function nativeInput(target, source, releaseVerification) {
  return {
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "darwin_arm64_native_prebuild",
    source_root: source,
    release_verification: releaseVerification,
    now: NOW,
  };
}

test("optional provider registry is frozen, registry-driven, and native component exact", () => {
  assert.ok(Object.isFrozen(OPTIONAL_PROVIDER_REGISTRY));
  assert.deepEqual(OPTIONAL_PROVIDER_STATUS_VALUES, [
    "absent",
    "unsupported_host",
    "installed_unqualified",
    "qualified_diagnostic",
    "blocked",
  ]);
  const provider = OPTIONAL_PROVIDER_REGISTRY[0];
  assert.equal(provider.activation_policy, "never_automatic");
  assert.equal(provider.installation_policy, "explicit_operator_only");
  assert.ok(Object.isFrozen(provider));
  assert.ok(Object.isFrozen(provider.packages));
  const worker = provider.packages.find((entry) => entry.package_id === "worker_source");
  assert.equal(worker.surface_policy, "signed_javascript_worker_closure_v1");
  assert.equal(worker.signed_release_required, true);
  assert.deepEqual(worker.expected_closure_package_ids, [
    "chameleon_worker_runtime",
    "worker",
  ]);
  assert.deepEqual(worker.expected_dependencies, {
    "@hacker-bob/instrument-chameleon-worker-runtime": "0.0.0-development",
  });
  assert.equal(Object.prototype.hasOwnProperty.call(
    worker.expected_dependencies,
    "serialport",
  ), false);
  const native = provider.packages.find((entry) =>
    entry.package_id === "darwin_arm64_native_prebuild");
  assert.deepEqual(native.required_component_ids, trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2);
  assert.equal(native.surface_policy, "signed_native_prebuild_v2");
  assert.equal(native.signed_release_required, true);
});

test("custodian selections exactly mirror optional registry packages and canonical roots", () => {
  const expected = [
    ...OPTIONAL_PROVIDER_REGISTRY.flatMap((provider) => provider.packages.map((packageRecord) =>
      `optional:${provider.provider_id}:${packageRecord.package_id}`)),
    ...CANONICAL_RUNTIME_PACKAGE_ROOTS.map((relativeRoot) => `canonical:${relativeRoot}`),
  ].sort();
  assert.deepEqual(Object.keys(LIFECYCLE_CUSTODIAN_SELECTIONS).sort(), expected);
  assert.equal(new Set(Object.values(LIFECYCLE_CUSTODIAN_SELECTIONS)).size, expected.length);
});

test("lazy absence and unsupported-host probes are bounded and non-authorizing", (t) => {
  const root = temporaryDirectory(t, "bob-optional-probe-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);
  const absent = workerProbe(target);
  assert.equal(absent.status, "absent");
  assert.equal(absent.severity, "info");
  assert.equal(absent.installed, false);
  assert.equal(absent.production_ready, false);
  assert.equal(absent.hardware_access_authorized, false);
  assert.equal(absent.activation_performed, false);
  assert.equal(absent.hardware_probe_performed, false);

  const unsupported = lifecycle.probeOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "darwin_arm64_native_prebuild",
    host: { os: "linux", architecture: "x64", node_major: 22, napi_version: 10 },
    qualification_input: null,
  });
  assert.equal(unsupported.status, "unsupported_host");
  assert.equal(unsupported.reason_code, "platform_unsupported");
  assert.deepEqual(unsupported.host_compatibility.diagnostics, {
    platform: false,
    architecture: false,
    node_major: false,
    napi: false,
  });
  assert.equal(unsupported.production_ready, false);
});

test("imports, status, doctor, and dry-run paths never capture mutation authority", (t) => {
  const root = temporaryDirectory(t, "bob-optional-read-only-authority-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, "sentinel"), "preserve", "utf8");
  const opensBefore = lifecycleCustodianTest.targetOpenCount();

  const custodian = require("../scripts/lib/lifecycle-custodian.js");
  assert.equal(custodian.lifecycleCustodianStatus().mutation_authorized, true);
  assert.equal(workerProbe(target).status, "absent");
  assert.equal(lifecycle.optionalProviderDoctorChecks({
    target_abs: target,
    host: WORKER_HOST,
    qualification_inputs: null,
  }).length, 2);
  assert.equal(lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: true,
  }).operation, "absent");
  assert.equal(lifecycle.uninstallAllOptionalProviders({
    target_abs: target,
    dry_run: true,
  }).length, 2);
  const dryUninstall = uninstallProject(target, {
    adapter: "generic-mcp",
    dryRun: true,
    onAdapterResolution: () => {},
    sourceRoot: ROOT,
  });
  assert.equal(dryUninstall.dry_run, true);
  doctorProject(target, {
    adapter: "generic-mcp",
    onAdapterResolution: () => {},
    sourceRoot: ROOT,
  });

  assert.equal(lifecycleCustodianTest.targetOpenCount(), opensBefore);
  assert.equal(fs.readFileSync(path.join(target, "sentinel"), "utf8"), "preserve");
});

test("imports, status, doctor, and dry-run never execute an installed mcp/server.js", (t) => {
  const root = temporaryDirectory(t, "bob-lifecycle-hostile-server-");
  const target = path.join(root, "workspace");
  const marker = path.join(root, "target-code-executed");
  fs.mkdirSync(path.join(target, "mcp"), { recursive: true });
  const hostileServer = [
    "\"use strict\";",
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");`,
    "module.exports = { TOOLS: [{ name: \"hostile\" }] };",
    "",
  ].join("\n");
  const serverPath = path.join(target, "mcp", "server.js");
  fs.writeFileSync(serverPath, hostileServer, "utf8");

  const probe = String.raw`
    "use strict";
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const target = process.argv[1];
    const marker = process.argv[2];
    const sourceRoot = process.argv[3];
    const lifecyclePath = process.argv[4];
    const optionalPath = process.argv[5];
    const custodianPath = process.argv[6];

    const lifecycle = require(lifecyclePath);
    assert.equal(fs.existsSync(marker), false, "lifecycle import executed target code");

    const custodian = require(custodianPath);
    custodian.lifecycleCustodianStatus();
    assert.equal(fs.existsSync(marker), false, "status executed target code");

    const optional = require(optionalPath);
    optional.probeOptionalProviderPackage({
      target_abs: target,
      provider_id: "chameleon_ultra",
      package_id: "worker_source",
      host: { os: "darwin", architecture: "arm64", node_major: 20, napi_version: 9 },
      qualification_input: null,
    });
    assert.equal(fs.existsSync(marker), false, "provider status executed target code");

    const doctor = lifecycle.doctorProject(target, {
      adapter: "generic-mcp",
      onAdapterResolution: () => {},
      sourceRoot,
    });
    assert.equal(fs.existsSync(marker), false, "doctor executed target code");
    for (const id of ["generic_mcp_server", "mcp_server_loadable"]) {
      const check = doctor.checks.find((candidate) => candidate.id === id);
      assert.equal(check.status, "error");
      assert.equal(check.detail.validation_mode, "static_manifest_digest_commonjs_syntax_v1");
      assert.equal(check.detail.reason_code, "installed_server_digest_mismatch");
      assert.equal(check.detail.syntax_valid, true);
      assert.equal(check.detail.digest_valid, false);
    }

    const dryRun = lifecycle.uninstallProject(target, {
      adapter: "generic-mcp",
      dryRun: true,
      onAdapterResolution: () => {},
      sourceRoot,
    });
    assert.equal(dryRun.dry_run, true);
    assert.equal(fs.existsSync(marker), false, "dry-run executed target code");
  `;
  const execution = spawnSync(process.execPath, [
    "-e",
    probe,
    target,
    marker,
    ROOT,
    path.join(ROOT, "scripts", "lifecycle.js"),
    path.join(ROOT, "scripts", "lib", "optional-provider-lifecycle.js"),
    path.join(ROOT, "scripts", "lib", "lifecycle-custodian.js"),
  ], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(execution.status, 0, execution.stderr || execution.stdout);
  assert.equal(fs.existsSync(marker), false);
  assert.equal(fs.readFileSync(serverPath, "utf8"), hostileServer);
  assert.deepEqual(fs.readdirSync(target), ["mcp"]);
});

test("static server inspection enforces manifest, digest, and CommonJS syntax without evaluation", (t) => {
  const root = temporaryDirectory(t, "bob-static-server-inspection-");
  const sourceRoot = path.join(root, "trusted-source");
  const target = path.join(root, "workspace");
  const marker = path.join(root, "evaluated");
  const expectedPath = path.join(sourceRoot, "mcp", "server.js");
  const installedPath = path.join(target, "mcp", "server.js");
  fs.mkdirSync(path.dirname(expectedPath), { recursive: true });
  fs.mkdirSync(path.dirname(installedPath), { recursive: true });
  const validButEffectful = [
    "\"use strict\";",
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");`,
    "module.exports = { TOOLS: [{ name: \"fixture\" }] };",
    "",
  ].join("\n");
  fs.writeFileSync(expectedPath, validButEffectful, "utf8");
  fs.writeFileSync(installedPath, validButEffectful, "utf8");

  const exact = inspectMcpServerStatically({
    sourceRoot,
    serverPath: installedPath,
    runtimeManifest: MCP_TOP_LEVEL_RUNTIME_FILES,
  });
  assert.equal(exact.ok, true);
  assert.equal(exact.manifest_valid, true);
  assert.equal(exact.digest_valid, true);
  assert.equal(exact.syntax_valid, true);
  assert.equal(fs.existsSync(marker), false, "syntax compilation evaluated target code");

  fs.writeFileSync(installedPath, "module.exports = {\n", "utf8");
  const malformed = inspectMcpServerStatically({
    sourceRoot,
    serverPath: installedPath,
    runtimeManifest: MCP_TOP_LEVEL_RUNTIME_FILES,
  });
  assert.equal(malformed.ok, false);
  assert.equal(malformed.reason_code, "installed_server_syntax_rejected");
  assert.equal(malformed.syntax_valid, false);
  assert.equal(malformed.digest_valid, false);

  const unmanifested = inspectMcpServerStatically({
    sourceRoot,
    serverPath: installedPath,
    runtimeManifest: ["auto-signup.js"],
  });
  assert.equal(unmanifested.ok, false);
  assert.equal(unmanifested.reason_code, "runtime_manifest_rejected");
  assert.equal(unmanifested.manifest_valid, false);
  assert.equal(fs.existsSync(marker), false);
});

test("static Bob-owned runtime inspection is bounded, traversal-closed, and non-evaluating", (t) => {
  const root = temporaryDirectory(t, "bob-static-runtime-inspection-");
  const sourceRoot = path.join(root, "trusted-source");
  const targetRoot = path.join(root, "workspace");
  const marker = path.join(root, "evaluated");
  const relativeFile = "mcp/lib/runtime.js";
  const effectfulSource = [
    "\"use strict\";",
    `require(\"node:fs\").writeFileSync(${JSON.stringify(marker)}, \"executed\");`,
    "module.exports = {};",
    "",
  ].join("\n");
  for (const directory of [sourceRoot, targetRoot]) {
    const filePath = path.join(directory, "mcp", "lib", "runtime.js");
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, effectfulSource, "utf8");
  }

  const exact = inspectBobOwnedRuntimeStatically({
    sourceRoot,
    targetRoot,
    runtimeFiles: [relativeFile],
    ownedRoots: ["mcp/lib"],
  });
  assert.equal(exact.ok, true);
  assert.equal(exact.coverage, "bob_owned_runtime_only");
  assert.equal(exact.entry_count, 1);
  assert.equal(fs.existsSync(marker), false, "runtime inspection evaluated target code");

  const traversal = inspectBobOwnedRuntimeStatically({
    sourceRoot,
    targetRoot,
    runtimeFiles: ["mcp/lib/../outside.js"],
    ownedRoots: ["mcp/lib"],
  });
  assert.equal(traversal.ok, false);
  assert.equal(traversal.reason_code, "runtime_manifest_rejected");

  const oversized = inspectBobOwnedRuntimeStatically({
    sourceRoot,
    targetRoot,
    runtimeFiles: Array.from({ length: 1025 }, (_, index) => `mcp/lib/f${index}.js`),
    ownedRoots: ["mcp/lib"],
  });
  assert.equal(oversized.ok, false);
  assert.equal(oversized.reason_code, "runtime_manifest_rejected");
  assert.equal(fs.existsSync(marker), false);
});

test("loading and probing lifecycle cannot load provider/native/network/process surfaces or mutate", (t) => {
  const root = temporaryDirectory(t, "bob-optional-inert-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);
  const script = String.raw`
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const Module = require("node:module");
    const target = process.argv[1];
    const modulePath = process.argv[2];
    const before = fs.readdirSync(target);
    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
      if (/serialport|chameleon-worker|native-darwin|child_process|node:(?:net|http|https)|(?:^|\/)usb(?:$|\/)/u.test(request)) {
        throw new Error("forbidden load: " + request);
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    process.dlopen = () => { throw new Error("native load forbidden"); };
    const lifecycle = require(modulePath);
    const result = lifecycle.probeOptionalProviderPackage({
      target_abs: target,
      provider_id: "chameleon_ultra",
      package_id: "worker_source",
      host: { os: "darwin", architecture: "arm64", node_major: 20, napi_version: 9 },
      qualification_input: null,
    });
    assert.equal(result.status, "absent");
    assert.deepEqual(fs.readdirSync(target), before);
  `;
  const result = spawnSync(process.execPath, [
    "-e",
    script,
    target,
    path.join(ROOT, "scripts", "lib", "optional-provider-lifecycle.js"),
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("explicit worker install/update is inert, idempotent, unqualified, and secret-free", (t) => {
  const root = temporaryDirectory(t, "bob-optional-install-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source-DO_NOT_LEAK-local-secret");
  fs.mkdirSync(target);
  makeWorkerSource(source);

  const installed = lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
  assert.deepEqual(installed, {
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    operation: "installed",
    status: "installed_unqualified",
    production_ready: false,
    hardware_access_authorized: false,
    activation_performed: false,
  });
  const paths = transactionPaths(target);
  const metadataPath = path.join(paths.packageRoot, lifecycle.OPTIONAL_PACKAGE_METADATA_FILE);
  const metadataBefore = fs.readFileSync(metadataPath, "utf8");
  const statBefore = fs.statSync(metadataPath);
  assert.ok(!metadataBefore.includes(source));
  assert.ok(!metadataBefore.includes("DO_NOT_LEAK"));
  assert.ok(!metadataBefore.includes("release_verification"));
  assert.equal(fs.existsSync(paths.stagingRoot), false);
  assert.equal(fs.existsSync(paths.backupRoot), false);
  assert.equal(fs.existsSync(paths.journal), false);
  for (const relative of [
    "worker/package.json",
    "worker/README.md",
    "worker/lib/serialport-usb-cdc-driver.js",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/package.json",
    "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/closed-runtime-contracts.js",
  ]) {
    assert.equal(fs.statSync(path.join(paths.packageRoot, ...relative.split("/"))).mode & 0o777,
      0o444, relative);
  }

  const projection = workerProbe(target);
  assert.equal(projection.status, "installed_unqualified", JSON.stringify(projection));
  assert.equal(projection.release_signature_valid, false);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.hardware_access_authorized, false);

  const unchangedInstall = lifecycle.installOptionalProviderPackage({
    ...workerLifecycleInput(target, source),
    now: "2026-07-19T12:30:00.000Z",
  });
  const unchangedUpdate = lifecycle.updateOptionalProviderPackage({
    ...workerLifecycleInput(target, source),
    now: "2026-07-19T13:00:00.000Z",
  });
  assert.equal(unchangedInstall.operation, "unchanged");
  assert.equal(unchangedUpdate.operation, "unchanged");
  assert.equal(fs.readFileSync(metadataPath, "utf8"), metadataBefore);
  assert.equal(fs.statSync(metadataPath).mtimeMs, statBefore.mtimeMs);
});

test("worker updates preserve release, trust, and revocation epoch high-water marks", (t) => {
  const root = temporaryDirectory(t, "bob-worker-high-water-");
  const source = path.join(root, "source");
  const target = path.join(root, "target");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  const current = cloneWorkerVerification(source);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source, {
    release_verification: current,
  }));
  const metadataPath = path.join(
    transactionPaths(target).packageRoot,
    lifecycle.OPTIONAL_PACKAGE_METADATA_FILE,
  );
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  assert.equal(metadata.release_id, current.envelope.manifest.release_id);
  assert.equal(metadata.release_epoch, 11);
  assert.equal(metadata.release_trust_epoch, 11);
  assert.equal(metadata.release_revocation_epoch, 11);
  const installedBytes = fs.readFileSync(metadataPath);

  for (const [label, verification, reasonCode] of [
    ["release", workerVerificationAtEpochs(source, { release_epoch: 10 }),
      "release_high_water_rollback_rejected"],
    ["trust", workerVerificationAtEpochs(source, { trust_epoch: 10 }),
      "release_high_water_rollback_rejected"],
    ["revocation", workerVerificationAtEpochs(source, { revocation_epoch: 10 }),
      "release_high_water_rollback_rejected"],
    ["release identity", workerVerificationAtEpochs(source, {
      release_id: "worker-closure:2026.07.19.equivocated",
    }), "release_epoch_equivocation_rejected"],
    ["policy", workerVerificationAtEpochs(source, { policy_equivocation: true }),
      "release_policy_epoch_equivocation_rejected"],
  ]) {
    assert.throws(
      () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source, {
        release_verification: verification,
      })),
      (error) => error && error.code === "optional_provider_package_rejected"
        && error.reason_code === reasonCode,
      label,
    );
    assert.deepEqual(fs.readFileSync(metadataPath), installedBytes, label);
  }
});

test("signed worker closure rejects hostile signature, key, revocation, rollback, and schema inputs", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-trust-");
  const source = path.join(root, "source");
  makeWorkerSource(source);
  const exact = cloneWorkerVerification(source);
  const verified = workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(exact);
  assert.equal(verified.release_signature_valid, true);
  assert.equal(verified.closure_bytes_bound, true);
  assert.equal(verified.external_immutable_keyring_observed, false);
  assert.equal(verified.production_ready, false);
  assert.equal(verified.authoritative, false);
  assert.ok(verified.blockers.includes("external_immutable_worker_release_keyring_port_absent"));
  assert.ok(verified.blockers.includes("probe_to_exec_closure_identity_binding_absent"));

  const badSignature = cloneWorkerVerification(source);
  const signature = badSignature.envelope.authentication.signature;
  badSignature.envelope.authentication.signature = `${
    signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(badSignature),
    (error) => error && error.code === "closure_signature_invalid",
  );

  const untrusted = cloneWorkerVerification(source);
  untrusted.trust_policy.keys[0].key_id = "worker-release-key:substituted";
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(untrusted),
    (error) => error && error.code === "closure_untrusted_key",
  );

  const revokedKey = cloneWorkerVerification(source);
  revokedKey.trust_policy.keys[0].revoked = true;
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(revokedKey),
    (error) => error && error.code === "closure_revoked_key",
  );

  const revokedRelease = cloneWorkerVerification(source);
  revokedRelease.trust_policy.revoked_release_ids = [
    revokedRelease.envelope.manifest.release_id,
  ];
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(revokedRelease),
    (error) => error && error.code === "closure_release_revoked",
  );

  const revokedManifest = cloneWorkerVerification(source);
  revokedManifest.trust_policy.revoked_manifest_digests = [
    revokedManifest.envelope.manifest_digest,
  ];
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(revokedManifest),
    (error) => error && error.code === "closure_manifest_revoked",
  );

  const rollback = cloneWorkerVerification(source);
  rollback.trust_policy.minimum_release_epoch =
    rollback.envelope.manifest.release_epoch + 1;
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(rollback),
    (error) => error && error.code === "closure_release_rollback",
  );

  const staleRevocation = cloneWorkerVerification(source);
  staleRevocation.trust_policy.current_revocation_epoch += 1;
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(staleRevocation),
    (error) => error && error.code === "closure_trust_binding_rejected",
  );

  const traversal = cloneWorkerVerification(source);
  traversal.envelope.manifest.files[0].path = "../outside.js";
  assert.throws(
    () => resignWorkerVerification(source, traversal),
    (error) => error && error.code === "closure_file_invalid",
  );

  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(new Proxy(exact, {})),
    (error) => error && error.code === "closure_verification_input_invalid",
  );
});

test("signed worker closure survives hostile same-process crypto and key-encoding intrinsics", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-intrinsics-");
  const source = path.join(root, "source");
  makeWorkerSource(source);
  const payload = Buffer.from(JSON.stringify(cloneWorkerVerification(source)), "utf8")
    .toString("base64url");
  const closureModule = path.join(
    ROOT,
    "packages",
    "bob-instrument-native-prebuild-trust",
    "lib",
    "javascript-worker-closure.js",
  );
  const script = `
    "use strict";
    const crypto = require("node:crypto");
    const api = require(${JSON.stringify(closureModule)});
    const encoded = ${JSON.stringify(payload)};
    const valid = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    const forged = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    const attacker = crypto.generateKeyPairSync("ed25519");
    const attackerDer = attacker.publicKey.export({ type: "spki", format: "der" });
    forged.trust_policy.keys[0].public_key_spki_der = attackerDer.toString("base64url");
    const auth = forged.envelope.authentication;
    auth.signature = crypto.sign(null, api.javascriptWorkerClosureSignatureMessage({
      manifest_digest: auth.signed_manifest_digest,
      key_id: auth.key_id,
      public_key_digest: auth.public_key_digest,
      trust_epoch: auth.trust_epoch,
      revocation_epoch: auth.revocation_epoch,
    }), attacker.privateKey).toString("base64url");

    let ordinaryRejection = null;
    try {
      api.verifyJavascriptWorkerClosureEnvelope(forged);
    } catch (error) {
      ordinaryRejection = error.code;
    }
    if (ordinaryRejection !== "closure_trust_key_invalid") process.exit(41);

    const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
    crypto.createHash = () => ({
      update() { return this; },
      digest() { return auth.public_key_digest; },
    });
    crypto.createPublicKey = () => { throw new Error("poisoned crypto.createPublicKey"); };
    crypto.verify = () => false;
    Buffer.from = () => { throw new Error("poisoned Buffer.from"); };
    Buffer.prototype.toString = () => { throw new Error("poisoned Buffer.toString"); };
    RegExp.prototype.test = () => { throw new Error("poisoned RegExp.test"); };
    hashPrototype.update = () => { throw new Error("poisoned Hash.update"); };
    hashPrototype.digest = () => { throw new Error("poisoned Hash.digest"); };

    const verified = api.verifyJavascriptWorkerClosureEnvelope(valid);
    if (verified.release_signature_valid !== true) process.exit(42);
    let poisonedRejection = null;
    try {
      api.verifyJavascriptWorkerClosureEnvelope(forged);
    } catch (error) {
      poisonedRejection = error.code;
    }
    if (poisonedRejection !== "closure_trust_key_invalid") process.exit(43);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("signed worker trust policy rejects duplicate canonical SPKI and digest aliases", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-key-alias-");
  const source = path.join(root, "source");
  makeWorkerSource(source);
  const verification = cloneWorkerVerification(source);
  const alias = {
    ...verification.trust_policy.keys[0],
    key_id: "worker-release-key:active-alias",
  };
  verification.trust_policy.keys = [alias, verification.trust_policy.keys[0]]
    .sort((left, right) => left.key_id.localeCompare(right.key_id));
  assert.throws(
    () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(verification),
    (error) => error && error.code === "closure_trust_policy_invalid"
      && /cannot alias Ed25519 key material/u.test(error.message),
  );
});

test("revoked signed worker key material cannot survive under another key ID", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-revoked-key-alias-");
  for (const aliasKeyId of [
    "worker-release-key:aaa-active-alias",
    "worker-release-key:zzz-active-alias",
  ]) {
    const source = path.join(root, aliasKeyId.endsWith("aaa-active-alias") ? "before" : "after");
    makeWorkerSource(source);
    const verification = cloneWorkerVerification(source);
    const revoked = verification.trust_policy.keys[0];
    revoked.revoked = true;
    const activeAlias = {
      ...revoked,
      key_id: aliasKeyId,
      revoked: false,
    };
    verification.trust_policy.keys = [revoked, activeAlias]
      .sort((left, right) => left.key_id.localeCompare(right.key_id));
    verification.envelope.authentication.key_id = activeAlias.key_id;
    resignWorkerVerification(source, verification);
    assert.throws(
      () => workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(verification),
      (error) => error && error.code === "closure_trust_policy_invalid"
        && /cannot alias Ed25519 key material/u.test(error.message),
      aliasKeyId,
    );
  }
});

test("signed worker closure admits only the exact reachable package and dependency graph", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-surface-");
  let index = 0;
  const rejectInstall = (source, releaseVerification, expectedReason = null) => {
    const target = path.join(root, `target-${index += 1}`);
    fs.mkdirSync(target);
    const before = fs.readdirSync(target);
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source, {
        release_verification: releaseVerification,
      })),
      (error) => error && error.code === "optional_provider_package_rejected"
        && (expectedReason == null || error.reason_code === expectedReason),
    );
    assert.deepEqual(fs.readdirSync(target), before);
  };

  const omitted = path.join(root, "omitted");
  makeWorkerSource(omitted);
  fs.unlinkSync(path.join(omitted, "worker", "README.md"));
  rejectInstall(omitted, cloneWorkerVerification(omitted), "worker_declared_package_file_missing");

  const extra = path.join(root, "extra");
  makeWorkerSource(extra);
  writeWorkerClosureFile(extra, "worker/lib/ambient-extra.js", "\"use strict\";\n");
  rejectInstall(extra, cloneWorkerVerification(extra), "worker_unreachable_javascript_rejected");

  const undeclaredData = path.join(root, "undeclared-data");
  makeWorkerSource(undeclaredData);
  writeWorkerClosureFile(undeclaredData, "worker/ambient.json", "{}\n");
  rejectInstall(
    undeclaredData,
    cloneWorkerVerification(undeclaredData),
    "worker_undeclared_package_file_rejected",
  );

  const dependency = path.join(root, "dependency");
  makeWorkerSource(dependency);
  const dependencyManifestPath = path.join(dependency, "worker", "package.json");
  const dependencyManifest = JSON.parse(fs.readFileSync(dependencyManifestPath, "utf8"));
  dependencyManifest.dependencies.serialport = "13.0.0";
  writeJson(dependencyManifestPath, dependencyManifest);
  resignWorkerSource(dependency);
  rejectInstall(dependency, cloneWorkerVerification(dependency), "worker_manifest_mismatch");

  const exportDrift = path.join(root, "export-drift");
  makeWorkerSource(exportDrift);
  const chameleonManifestPath = path.join(
    exportDrift,
    "worker",
    "node_modules",
    "@hacker-bob",
    "instrument-chameleon-worker-runtime",
    "package.json",
  );
  const chameleonManifest = JSON.parse(fs.readFileSync(chameleonManifestPath, "utf8"));
  chameleonManifest.exports["./raw"] = "./lib/codec.js";
  writeJson(chameleonManifestPath, chameleonManifest);
  resignWorkerSource(exportDrift);
  rejectInstall(
    exportDrift,
    cloneWorkerVerification(exportDrift),
    "worker_dependency_manifest_mismatch",
  );

  const crossPackageRelative = path.join(root, "cross-package-relative");
  makeWorkerSource(crossPackageRelative);
  const crossPackageDriverPath = path.join(
    crossPackageRelative,
    "worker",
    "lib",
    "serialport-usb-cdc-driver.js",
  );
  const driverSource = fs.readFileSync(crossPackageDriverPath, "utf8").replace(
    "@hacker-bob/instrument-chameleon-worker-runtime/rf-off-usb-execution-port",
    "../node_modules/@hacker-bob/instrument-chameleon-worker-runtime/lib/rf-off-usb-execution-port.js",
  );
  fs.writeFileSync(crossPackageDriverPath, driverSource, "utf8");
  resignWorkerSource(crossPackageRelative);
  rejectInstall(
    crossPackageRelative,
    cloneWorkerVerification(crossPackageRelative),
    "worker_cross_package_relative_edge_rejected",
  );

  const versionDrift = path.join(root, "version-drift");
  makeWorkerSource(versionDrift);
  const versionManifestPath = path.join(versionDrift, "worker", "package.json");
  const versionManifest = JSON.parse(fs.readFileSync(versionManifestPath, "utf8"));
  versionManifest.version = "0.0.1";
  writeJson(versionManifestPath, versionManifest);
  resignWorkerSource(versionDrift);
  rejectInstall(versionDrift, cloneWorkerVerification(versionDrift), "worker_manifest_mismatch");

  const omittedEdge = path.join(root, "omitted-edge");
  makeWorkerSource(omittedEdge);
  const omittedEdgeVerification = cloneWorkerVerification(omittedEdge);
  omittedEdgeVerification.envelope.manifest.module_edges.splice(3, 1);
  resignWorkerVerification(omittedEdge, omittedEdgeVerification);
  rejectInstall(
    omittedEdge,
    omittedEdgeVerification,
    "worker_closure_module_graph_rejected",
  );

  const ambientRequire = path.join(root, "ambient-require");
  makeWorkerSource(ambientRequire);
  const driverPath = path.join(
    ambientRequire,
    "worker",
    "lib",
    "serialport-usb-cdc-driver.js",
  );
  fs.appendFileSync(driverPath, "\nrequire(\"serialport\");\n", "utf8");
  const ambientVerification = cloneWorkerVerification(ambientRequire);
  const driverRecord = ambientVerification.envelope.manifest.files.find((record) =>
    record.path === "worker/lib/serialport-usb-cdc-driver.js");
  const driverBytes = fs.readFileSync(driverPath);
  driverRecord.byte_size = driverBytes.length;
  driverRecord.sha256 = digest(driverBytes);
  ambientVerification.envelope.manifest.module_edges.push({
    source_path: "worker/lib/serialport-usb-cdc-driver.js",
    specifier: "serialport",
    resolution_kind: "builtin",
    resolved_path: "node:serialport",
  });
  ambientVerification.envelope.manifest.module_edges.sort((left, right) => {
    const leftIdentity = `${left.source_path}\0${left.specifier}\0${left.resolved_path}`;
    const rightIdentity = `${right.source_path}\0${right.specifier}\0${right.resolved_path}`;
    return leftIdentity < rightIdentity ? -1 : (leftIdentity > rightIdentity ? 1 : 0);
  });
  assert.throws(
    () => resignWorkerVerification(ambientRequire, ambientVerification),
    (error) => error && error.code === "closure_manifest_invalid",
  );

  const escapedRequire = path.join(root, "escaped-require");
  makeWorkerSource(escapedRequire);
  fs.appendFileSync(path.join(
    escapedRequire,
    "worker",
    "lib",
    "serialport-usb-cdc-driver.js",
  ), "\n\\u0072equire(\"serialport\");\n", "utf8");
  rejectInstall(
    escapedRequire,
    signWorkerFilesWithoutRebuildingGraph(escapedRequire),
    "worker_undeclared_dependency_rejected",
  );

  for (const [name, hostileSource] of [
    ["computed-module-require", "module[\"require\"](\"node:child_process\");"],
    ["optional-require", "require?.(\"node:child_process\");"],
    ["computed-process-loader", "process[\"getBuiltinModule\"](\"node:child_process\");"],
    ["require-alias", "const hostileLoader = require; hostileLoader(\"node:child_process\");"],
    ["require-object-alias", "const hostileHolder = { loader: require }; hostileHolder.loader(\"node:child_process\");"],
    ["commented-import", "import /* loader boundary */ (\"node:child_process\");"],
    ["commented-eval", "eval /* loader boundary */ (\"require('node:child_process')\");"],
  ]) {
    const hostile = path.join(root, name);
    makeWorkerSource(hostile);
    fs.appendFileSync(path.join(
      hostile,
      "worker",
      "lib",
      "serialport-usb-cdc-driver.js",
    ), `\n${hostileSource}\n`, "utf8");
    rejectInstall(
      hostile,
      signWorkerFilesWithoutRebuildingGraph(hostile),
      "worker_dynamic_loader_rejected",
    );
  }

  const hardlinked = path.join(root, "hardlinked");
  makeWorkerSource(hardlinked);
  const hardlinkWitness = path.join(root, "hardlink-witness");
  fs.linkSync(path.join(hardlinked, "worker", "README.md"), hardlinkWitness);
  rejectInstall(hardlinked, cloneWorkerVerification(hardlinked), "package_file_invalid");
});

test("closed CommonJS loader executes only the verified in-memory edge graph", () => {
  const sources = new Map([
    ["worker/index.js", "\"use strict\"; module.exports = require(\"./value.js\");"],
    ["worker/value.js", "\"use strict\"; module.exports = Object.freeze({ value: 42 });"],
  ]);
  const loader = createClosedCommonjsLoader({
    sources,
    module_edges: [{
      source_path: "worker/index.js",
      specifier: "./value.js",
      resolution_kind: "relative",
      resolved_path: "worker/value.js",
    }],
    builtin_modules: new Map(),
  });
  assert.equal(loader.loadEntrypoint("worker/index.js").value, 42);

  assert.throws(
    () => createClosedCommonjsLoader({
      sources: new Map([["worker/index.js",
        "module[\"require\"](\"node:child_process\");"]]),
      module_edges: [],
      builtin_modules: new Map(),
    }),
    (error) => error && error.code === "closed_commonjs_loader_rejected"
      && error.reason_code === "module_capability_rejected",
  );
});

test("the signed worker assembly loads through its exact closed graph without hardware", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closed-loader-");
  const source = path.join(root, "source");
  makeWorkerSource(source);
  const verification = cloneWorkerVerification(source);
  const sources = new Map(verification.envelope.manifest.files
    .filter((record) => record.media_type === "application/javascript"
      || record.media_type === "application/json")
    .map((record) => [
      record.path,
      fs.readFileSync(path.join(source, ...record.path.split("/"))),
    ]));
  const loader = createClosedCommonjsLoader({
    sources,
    module_edges: verification.envelope.manifest.module_edges,
    builtin_modules: new Map([
      ["node:crypto", require("node:crypto")],
      ["node:fs", require("node:fs")],
      ["node:path", require("node:path")],
      ["node:util", require("node:util")],
    ]),
  });
  const worker = loader.loadEntrypoint(verification.envelope.manifest.entrypoint);
  assert.equal(typeof worker.createSerialPortUsbCdcDriverPort, "function");
  assert.equal(fs.existsSync(path.join(root, "hardware-probe")), false);
});

test("checked-in worker runtime assembly loads outside the checkout without ambient node_modules", (t) => {
  const root = temporaryDirectory(t, "bob-worker-clean-assembly-");
  const source = path.join(root, "signed-source");
  makeWorkerSource(source);
  assert.equal(fs.existsSync(path.join(root, "node_modules")), false);
  const script = `
    "use strict";
    const worker = require(process.argv[1]);
    if (typeof worker.createSerialPortUsbCdcDriverPort !== "function") process.exit(2);
    process.stdout.write(JSON.stringify(Object.keys(worker).sort()));
  `;
  const result = spawnSync(process.execPath, ["-e", script, path.join(source, "worker")], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, NODE_PATH: "" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /createSerialPortUsbCdcDriverPort/u);
  assert.equal(fs.existsSync(path.join(root, "node_modules")), false);
});

test("worker closure probe re-verifies signature and repairs, rather than masks, reinstall drift", (t) => {
  const root = temporaryDirectory(t, "bob-worker-closure-probe-");
  const source = path.join(root, "source");
  const target = path.join(root, "target");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  const verification = cloneWorkerVerification(source);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source, {
    release_verification: verification,
  }));
  const qualified = workerProbe(target, { qualification_input: verification });
  assert.equal(qualified.status, "qualified_diagnostic");
  assert.equal(qualified.reason_code, "signed_worker_closure_reverified_non_authorizing");
  assert.equal(qualified.release_signature_valid, true);
  assert.equal(qualified.production_ready, false);
  assert.equal(qualified.authoritative, false);

  // A second valid signer over identical bytes is not silently substituted for
  // the key/trust/revocation lineage recorded by installation.
  resignWorkerSource(source);
  const alternateValidLineage = cloneWorkerVerification(source);
  assert.equal(workerClosureTrust.verifyJavascriptWorkerClosureEnvelope(
    alternateValidLineage,
  ).release_signature_valid, true);
  assert.equal(workerProbe(target, {
    qualification_input: alternateValidLineage,
  }).status, "blocked");

  const tamperedEvidence = cloneWorkerVerification(source);
  tamperedEvidence.envelope.authentication.signature = "A".repeat(86);
  assert.equal(workerProbe(target, { qualification_input: tamperedEvidence }).status, "blocked");

  const installedReadme = path.join(
    transactionPaths(target).packageRoot,
    "worker",
    "README.md",
  );
  fs.chmodSync(installedReadme, 0o644);
  fs.writeFileSync(installedReadme, "# installed drift\n", "utf8");
  fs.chmodSync(installedReadme, 0o444);
  assert.equal(workerProbe(target, { qualification_input: verification }).status, "blocked");
  const repaired = lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source, {
    release_verification: verification,
  }));
  assert.equal(repaired.operation, "updated");
  assert.equal(workerProbe(target, { qualification_input: verification }).status,
    "qualified_diagnostic");

  const hardlinkWitness = path.join(root, "installed-hardlink-witness");
  fs.linkSync(installedReadme, hardlinkWitness);
  assert.equal(workerProbe(target, { qualification_input: verification }).status, "blocked");
  fs.unlinkSync(hardlinkWitness);
  assert.equal(workerProbe(target, { qualification_input: verification }).status,
    "qualified_diagnostic");

  const outside = path.join(root, "outside-readme");
  fs.writeFileSync(outside, "# outside\n", "utf8");
  fs.chmodSync(installedReadme, 0o644);
  fs.unlinkSync(installedReadme);
  fs.symlinkSync(outside, installedReadme);
  assert.equal(workerProbe(target, { qualification_input: verification }).status, "blocked");
});

test("worker install rejects lifecycle scripts, native payloads, source symlinks, and owned-ancestor symlinks", (t) => {
  const root = temporaryDirectory(t, "bob-optional-malicious-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);

  const scripted = path.join(root, "scripted");
  makeWorkerSource(scripted, { scripts: { preinstall: "touch escaped" } });
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, scripted)),
    (error) => error && error.reason_code === "install_script_rejected",
  );

  const nativePayload = path.join(root, "native-payload");
  makeWorkerSource(nativePayload);
  fs.writeFileSync(path.join(nativePayload, "evil.node"), "not native", "utf8");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, nativePayload)),
    (error) => error && error.reason_code === "worker_surface_rejected",
  );

  const linked = path.join(root, "linked");
  makeWorkerSource(linked);
  fs.symlinkSync(
    path.join(linked, "worker", "README.md"),
    path.join(linked, "worker", "lib", "linked.js"),
  );
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, linked)),
    (error) => error && error.reason_code === "package_symlink_rejected",
  );

  const executableWorker = path.join(root, "executable-worker");
  makeWorkerSource(executableWorker);
  fs.chmodSync(
    path.join(executableWorker, "worker", "lib", "serialport-usb-cdc-driver.js"),
    0o755,
  );
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, executableWorker)),
    (error) => error && error.reason_code === "worker_source_mode_rejected",
  );

  const outside = path.join(root, "outside");
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "sentinel"), "preserve", "utf8");
  fs.mkdirSync(path.join(target, ".hacker-bob"));
  fs.symlinkSync(outside, path.join(target, ".hacker-bob", "optional-providers"));
  const clean = path.join(root, "clean");
  makeWorkerSource(clean);
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, clean)),
    (error) => error && error.reason_code === "installed_ancestry_rejected",
  );
  assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");
});

test("source ancestor identity swap is rejected before destination mutation", (t) => {
  const root = temporaryDirectory(t, "bob-optional-race-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  const outside = path.join(root, "outside");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "serialport-usb-cdc-driver.js"), "evil\n", "utf8");
  const sourceLib = path.join(source, "worker", "lib");
  const heldLib = path.join(source, "worker", "lib-held");
  const originalReaddir = fs.readdirSync;
  let swapped = false;
  fs.readdirSync = function guardedRace(candidate, ...args) {
    if (!swapped && path.resolve(String(candidate)) === path.resolve(sourceLib)) {
      swapped = true;
      fs.renameSync(sourceLib, heldLib);
      fs.symlinkSync(outside, sourceLib);
    }
    return originalReaddir.call(this, candidate, ...args);
  };
  try {
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "package_ancestry_rejected",
    );
  } finally {
    fs.readdirSync = originalReaddir;
    if (fs.lstatSync(sourceLib).isSymbolicLink()) fs.unlinkSync(sourceLib);
    fs.renameSync(heldLib, sourceLib);
  }
  assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false);
});

test("native prepared input rejects hardlinks, symlinks, mode drift, hash drift, and request tamper", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-input-");
  const cases = [
    {
      name: "source-hardlink",
      mutate(context, outside) {
        const prepared = path.join(context.source_root, "worker", "README.md");
        const outsideFile = path.join(outside, "hardlink-source");
        fs.writeFileSync(outsideFile, fs.readFileSync(prepared));
        fs.chmodSync(outsideFile, 0o444);
        fs.unlinkSync(prepared);
        fs.linkSync(outsideFile, prepared);
      },
    },
    {
      name: "source-symlink",
      mutate(context, outside) {
        const prepared = path.join(context.source_root, "worker", "README.md");
        const outsideFile = path.join(outside, "symlink-source");
        fs.writeFileSync(outsideFile, "# inert worker source\n", "utf8");
        fs.unlinkSync(prepared);
        fs.symlinkSync(outsideFile, prepared);
      },
    },
    {
      name: "source-mode",
      mutate(context) {
        fs.chmodSync(path.join(context.source_root, "worker", "README.md"), 0o644);
      },
    },
    {
      name: "source-hash",
      mutate(context) {
        const prepared = path.join(context.source_root, "worker", "README.md");
        fs.chmodSync(prepared, 0o644);
        fs.writeFileSync(prepared, "# tampered worker src\n", "utf8");
        fs.chmodSync(prepared, 0o444);
      },
    },
    {
      name: "request-hardlink",
      mutate(context) {
        fs.linkSync(context.request_path, `${context.request_path}.second-link`);
      },
    },
    {
      name: "request-mode",
      mutate(context) {
        fs.chmodSync(context.request_path, 0o644);
      },
    },
    {
      name: "request-hash",
      mutate(context) {
        const request = fs.readFileSync(context.request_path);
        request[request.length - 1] ^= 1;
        fs.chmodSync(context.request_path, 0o644);
        fs.writeFileSync(context.request_path, request);
        fs.chmodSync(context.request_path, 0o444);
      },
    },
  ];
  for (const hostileCase of cases) {
    const target = path.join(root, `target-${hostileCase.name}`);
    const source = path.join(root, `source-${hostileCase.name}`);
    const outside = path.join(root, `outside-${hostileCase.name}`);
    fs.mkdirSync(target);
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "sentinel"), `preserve-${hostileCase.name}`, "utf8");
    makeWorkerSource(source);
    lifecycleCustodianTest.beforeNextNative((context) => hostileCase.mutate(context, outside));
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "native_mutation_rejected",
      hostileCase.name,
    );
    assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false, hostileCase.name);
    assert.equal(
      fs.readFileSync(path.join(outside, "sentinel"), "utf8"),
      `preserve-${hostileCase.name}`,
    );
  }
});

test("invalid result descriptors cannot mutate the target or receive custodian bytes", (t) => {
  const root = temporaryDirectory(t, "bob-lifecycle-result-fd-");
  for (const kind of ["regular-file", "directory"]) {
    const target = path.join(root, `target-${kind}`);
    const source = path.join(root, `source-${kind}`);
    const resultPath = path.join(root, `result-${kind}`);
    fs.mkdirSync(target);
    makeWorkerSource(source);
    if (kind === "regular-file") fs.writeFileSync(resultPath, "preserve-result-bytes", "utf8");
    else fs.mkdirSync(resultPath);
    const descriptor = fs.openSync(
      resultPath,
      kind === "regular-file"
        ? fs.constants.O_WRONLY
        : fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
          | (fs.constants.O_NOFOLLOW || 0),
    );
    try {
      lifecycleCustodianTest.useNextResultDescriptor(descriptor);
      assert.throws(
        () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
        (error) => error && error.reason_code === "native_mutation_rejected",
        kind,
      );
    } finally {
      fs.closeSync(descriptor);
    }
    assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false, kind);
    if (kind === "regular-file") {
      assert.equal(fs.readFileSync(resultPath, "utf8"), "preserve-result-bytes");
    } else {
      assert.deepEqual(fs.readdirSync(resultPath), []);
    }
  }
});

test("plan-digest replay rejects source drift until the exact crashed request resumes", (t) => {
  const root = temporaryDirectory(t, "bob-optional-plan-replay-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
  const firstPlan = "# exact recovery plan A\n";
  fs.writeFileSync(path.join(source, "worker", "README.md"), firstPlan, "utf8");
  resignWorkerSource(source);
  const firstPlanVerification = cloneWorkerVerification(source);
  lifecycleCustodianTest.crashNextAt("building");
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
    (error) => error && error.reason_code === "injected_native_crash",
  );
  fs.writeFileSync(path.join(source, "worker", "README.md"), "# different plan B\n", "utf8");
  resignWorkerSource(source);
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  fs.writeFileSync(path.join(source, "worker", "README.md"), firstPlan, "utf8");
  WORKER_RELEASES.set(path.resolve(source), firstPlanVerification);
  const recovered = lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source));
  assert.equal(recovered.operation, "updated");
  assert.equal(
    fs.readFileSync(
      path.join(transactionPaths(target).packageRoot, "worker", "README.md"),
      "utf8",
    ),
    firstPlan,
  );
});

test("helper tamper blocks optional mutation while the canonical core remains installable", (t) => {
  const root = temporaryDirectory(t, "bob-lifecycle-helper-admission-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  const binary = lifecycleCustodianTest.test_binary;
  const originalMode = fs.statSync(binary).mode & 0o777;
  fs.chmodSync(binary, 0o644);
  try {
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "test_binary_unavailable",
    );
  } finally {
    fs.chmodSync(binary, originalMode);
  }
  assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false);

  const productionTarget = path.join(root, "production-target");
  fs.mkdirSync(productionTarget);
  const productionWrapper = path.join(ROOT, "scripts", "lib", "lifecycle-custodian.js");
  const isolated = spawnSync(process.execPath, ["-e", `
    const custodian = require(${JSON.stringify(productionWrapper)});
    try {
      custodian.withLifecycleCustodianTarget(process.argv[1], (targetAuthority) =>
        custodian.executeLifecycleMutation(targetAuthority, {
          operation: "remove",
          selection: "canonical:packages/bob-artifact-vault",
          files: [],
        }));
      process.exit(9);
    } catch (error) {
      process.stdout.write(JSON.stringify({ code: error.code, reason: error.reason_code }));
    }
  `, productionTarget], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
  });
  assert.equal(isolated.status, 0, isolated.stderr);
  assert.deepEqual(JSON.parse(isolated.stdout), {
    code: "lifecycle_custodian_unavailable",
    reason: "openat_to_exec_or_mapped_image_binding_missing",
  });
  assert.deepEqual(fs.readdirSync(productionTarget), []);
  const productionHome = path.join(root, "production-home");
  fs.mkdirSync(productionHome);
  const install = spawnSync(process.execPath, [
    path.join(ROOT, "bin", "hacker-bob.js"),
    "install",
    productionTarget,
    "--adapter",
    "generic-mcp",
  ], {
    cwd: ROOT,
    encoding: "utf8",
    env: { HOME: productionHome, PATH: "/usr/bin:/bin" },
  });
  assert.equal(install.status, 0, install.stderr);
  assert.equal(fs.existsSync(path.join(productionTarget, "mcp", "server.js")), true);
  assert.equal(
    fs.existsSync(path.join(productionTarget, "packages", "bob-artifact-vault", "package.json")),
    true,
  );
  fs.writeFileSync(path.join(productionTarget, "sentinel"), "preserve", "utf8");
  const uninstall = spawnSync(process.execPath, [
    path.join(ROOT, "bin", "hacker-bob.js"),
    "uninstall",
    productionTarget,
    "--adapter",
    "generic-mcp",
    "--yes",
  ], {
    cwd: ROOT,
    encoding: "utf8",
    env: { HOME: productionHome, PATH: "/usr/bin:/bin" },
  });
  assert.equal(uninstall.status, 0, uninstall.stderr);
  assert.equal(fs.existsSync(path.join(productionTarget, "mcp", "server.js")), false);
  assert.equal(fs.existsSync(path.join(productionTarget, "packages", "bob-artifact-vault")), false);
  assert.equal(fs.readFileSync(path.join(productionTarget, "sentinel"), "utf8"), "preserve");
});

test("optional install retains one target authority across a real-directory replacement", (t) => {
  const root = temporaryDirectory(t, "bob-optional-destination-race-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  const outside = path.join(root, "outside");
  fs.mkdirSync(target);
  const outsidePaths = transactionPaths(outside);
  fs.mkdirSync(outsidePaths.packageRoot, { recursive: true });
  fs.mkdirSync(outsidePaths.stagingRoot);
  fs.writeFileSync(path.join(outside, "sentinel"), "preserve", "utf8");
  makeWorkerSource(source);
  fs.writeFileSync(path.join(outsidePaths.packageRoot, "sentinel"), "leaf-preserve", "utf8");
  fs.writeFileSync(
    path.join(outsidePaths.stagingRoot, "sentinel"),
    "staging-preserve",
    "utf8",
  );
  const heldTarget = `${target}-held`;
  const opensBefore = lifecycleCustodianTest.targetOpenCount();
  lifecycleCustodianTest.beforeNextNative(() => {
    fs.renameSync(target, heldTarget);
    fs.renameSync(outside, target);
  });
  try {
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "install_verification_failed",
    );
  } finally {
    if (fs.existsSync(heldTarget)) {
      fs.renameSync(target, outside);
      fs.renameSync(heldTarget, target);
    }
  }
  assert.equal(lifecycleCustodianTest.targetOpenCount() - opensBefore, 1);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");
  assert.equal(
    fs.readFileSync(path.join(outsidePaths.packageRoot, "sentinel"), "utf8"),
    "leaf-preserve",
  );
  assert.equal(
    fs.readFileSync(path.join(outsidePaths.stagingRoot, "sentinel"), "utf8"),
    "staging-preserve",
  );
  assert.equal(fs.existsSync(transactionPaths(target).packageRoot), true);
  const cleanup = lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: false,
  });
  assert.equal(cleanup.operation, "removed");
});

test("optional uninstall retains one target authority across a real-directory replacement", (t) => {
  const root = temporaryDirectory(t, "bob-optional-uninstall-destination-race-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  const outside = path.join(root, "outside");
  const heldTarget = `${target}-held`;
  fs.mkdirSync(target);
  makeWorkerSource(source);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
  const intendedPaths = transactionPaths(target);
  const outsidePaths = transactionPaths(outside);
  fs.mkdirSync(outsidePaths.packageRoot, { recursive: true });
  fs.writeFileSync(path.join(outside, "sentinel"), "preserve", "utf8");
  fs.writeFileSync(path.join(outsidePaths.packageRoot, "sentinel"), "leaf-preserve", "utf8");

  const opensBefore = lifecycleCustodianTest.targetOpenCount();
  lifecycleCustodianTest.beforeNextNative(() => {
    fs.renameSync(target, heldTarget);
    fs.renameSync(outside, target);
  });
  let removed;
  try {
    removed = lifecycle.uninstallOptionalProviderPackage({
      target_abs: target,
      provider_id: "chameleon_ultra",
      package_id: "worker_source",
      dry_run: false,
    });
  } finally {
    if (fs.existsSync(heldTarget)) {
      fs.renameSync(target, outside);
      fs.renameSync(heldTarget, target);
    }
  }
  assert.equal(removed.operation, "removed");
  assert.equal(lifecycleCustodianTest.targetOpenCount() - opensBefore, 1);
  assert.equal(fs.existsSync(intendedPaths.packageRoot), false);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");
  assert.equal(
    fs.readFileSync(path.join(outsidePaths.packageRoot, "sentinel"), "utf8"),
    "leaf-preserve",
  );
});

test("native journal recovery is bounded across every replace crash phase", (t) => {
  const root = temporaryDirectory(t, "bob-optional-recovery-");
  for (const phase of ["building", "prepared", "backup_renamed", "installed", "committed"]) {
    const target = path.join(root, `workspace-${phase}`);
    const source = path.join(root, `source-${phase}`);
    fs.mkdirSync(target);
    makeWorkerSource(source);
    lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
    fs.writeFileSync(path.join(source, "worker", "README.md"), `# changed at ${phase}\n`, "utf8");
    resignWorkerSource(source);
    lifecycleCustodianTest.crashNextAt(phase);
    assert.throws(
      () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    const recovered = lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source));
    assert.equal(recovered.operation, "updated");
    const paths = transactionPaths(target);
    assert.equal(fs.existsSync(paths.packageRoot), true, phase);
    assert.equal(fs.existsSync(paths.backupRoot), false, phase);
    assert.equal(fs.existsSync(paths.stagingRoot), false, phase);
    assert.equal(fs.existsSync(paths.journal), false, phase);
  }
});

test("journal identity rollback closes backup and install rename microphases", (t) => {
  const root = temporaryDirectory(t, "bob-optional-microphase-recovery-");
  for (const phase of ["after_backup_rename", "after_install_rename"]) {
    const target = path.join(root, `existing-${phase}`);
    const source = path.join(root, `existing-source-${phase}`);
    fs.mkdirSync(target);
    makeWorkerSource(source);
    lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
    const original = fs.readFileSync(
      path.join(transactionPaths(target).packageRoot, "worker", "README.md"),
    );
    fs.writeFileSync(path.join(source, "worker", "README.md"), `# replacement ${phase}\n`, "utf8");
    resignWorkerSource(source);
    lifecycleCustodianTest.crashNextAt(phase);
    assert.throws(
      () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    lifecycleCustodianTest.crashNextAt("after_recovery");
    assert.throws(
      () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    const paths = transactionPaths(target);
    assert.deepEqual(
      fs.readFileSync(path.join(paths.packageRoot, "worker", "README.md")),
      original,
      phase,
    );
    assert.equal(fs.existsSync(paths.stagingRoot), false, phase);
    assert.equal(fs.existsSync(paths.backupRoot), false, phase);
    assert.equal(fs.existsSync(paths.journal), false, phase);
  }

  for (const phase of ["after_backup_rename", "after_install_rename"]) {
    const target = path.join(root, `fresh-${phase}`);
    const source = path.join(root, `fresh-source-${phase}`);
    fs.mkdirSync(target);
    makeWorkerSource(source);
    lifecycleCustodianTest.crashNextAt(phase);
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    lifecycleCustodianTest.crashNextAt("after_recovery");
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    const paths = transactionPaths(target);
    assert.equal(fs.existsSync(paths.packageRoot), false, phase);
    assert.equal(fs.existsSync(paths.stagingRoot), false, phase);
    assert.equal(fs.existsSync(paths.backupRoot), false, phase);
    assert.equal(fs.existsSync(paths.journal), false, phase);
  }
});

test("recovery preserves substituted foreign leaf and backup identities", (t) => {
  const root = temporaryDirectory(t, "bob-optional-recovery-substitution-");

  const freshTarget = path.join(root, "fresh-target");
  const freshSource = path.join(root, "fresh-source");
  fs.mkdirSync(freshTarget);
  makeWorkerSource(freshSource);
  lifecycleCustodianTest.crashNextAt("after_install_rename");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(freshTarget, freshSource)),
    (error) => error && error.reason_code === "injected_native_crash",
  );
  const freshPaths = transactionPaths(freshTarget);
  fs.renameSync(freshPaths.packageRoot, path.join(freshPaths.providerRoot, "held-staged-leaf"));
  fs.mkdirSync(freshPaths.packageRoot);
  fs.writeFileSync(path.join(freshPaths.packageRoot, "foreign-sentinel"), "preserve-leaf", "utf8");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(freshTarget, freshSource)),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  assert.equal(
    fs.readFileSync(path.join(freshPaths.packageRoot, "foreign-sentinel"), "utf8"),
    "preserve-leaf",
  );

  const updateTarget = path.join(root, "update-target");
  const updateSource = path.join(root, "update-source");
  fs.mkdirSync(updateTarget);
  makeWorkerSource(updateSource);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(updateTarget, updateSource));
  fs.writeFileSync(
    path.join(updateSource, "worker", "README.md"),
    "# replacement with held backup\n",
    "utf8",
  );
  resignWorkerSource(updateSource);
  lifecycleCustodianTest.crashNextAt("after_backup_rename");
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(updateTarget, updateSource)),
    (error) => error && error.reason_code === "injected_native_crash",
  );
  const updatePaths = transactionPaths(updateTarget);
  fs.renameSync(updatePaths.backupRoot, path.join(updatePaths.providerRoot, "held-original-backup"));
  fs.mkdirSync(updatePaths.backupRoot);
  fs.writeFileSync(path.join(updatePaths.backupRoot, "foreign-sentinel"), "preserve-backup", "utf8");
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(updateTarget, updateSource)),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  assert.equal(
    fs.readFileSync(path.join(updatePaths.backupRoot, "foreign-sentinel"), "utf8"),
    "preserve-backup",
  );
});

test("checksum-valid journal identity and reserved-field tamper fail closed", (t) => {
  const crypto = require("node:crypto");
  const root = temporaryDirectory(t, "bob-optional-journal-tamper-");
  const cases = [
    {
      name: "staged-generation",
      mutate(bytes) {
        bytes.writeBigUInt64BE(bytes.readBigUInt64BE(128) + 1n, 128);
      },
    },
    {
      name: "header-reserved",
      mutate(bytes) {
        bytes.writeUInt32BE(1, 28);
      },
    },
    {
      name: "original-reserved",
      mutate(bytes) {
        bytes.writeUInt32BE(1, 108);
      },
    },
    {
      name: "staged-reserved",
      mutate(bytes) {
        bytes.writeUInt32BE(1, 156);
      },
    },
  ];
  for (const hostileCase of cases) {
    const target = path.join(root, `target-${hostileCase.name}`);
    const source = path.join(root, `source-${hostileCase.name}`);
    fs.mkdirSync(target);
    makeWorkerSource(source);
    lifecycleCustodianTest.crashNextAt("prepared");
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "injected_native_crash",
    );
    const paths = transactionPaths(target);
    const journal = fs.readFileSync(paths.journal);
    assert.equal(journal.length, 192);
    hostileCase.mutate(journal);
    crypto.createHash("sha256").update(journal.subarray(0, 160)).digest().copy(journal, 160);
    fs.chmodSync(paths.journal, 0o600);
    fs.writeFileSync(paths.journal, journal);
    fs.chmodSync(paths.journal, 0o400);
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source)),
      (error) => error && error.reason_code === "native_mutation_rejected",
      hostileCase.name,
    );
    assert.equal(fs.existsSync(paths.stagingRoot), true, hostileCase.name);
    assert.equal(fs.existsSync(paths.packageRoot), false, hostileCase.name);
  }
});

test("replace recovery preserves foreign bytes added inside a bound staged tree", (t) => {
  const root = temporaryDirectory(t, "bob-optional-staged-tree-tamper-");

  const preparedTarget = path.join(root, "prepared-target");
  const preparedSource = path.join(root, "prepared-source");
  fs.mkdirSync(preparedTarget);
  makeWorkerSource(preparedSource);
  lifecycleCustodianTest.crashNextAt("prepared");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(
      preparedTarget, preparedSource,
    )),
    (error) => error && error.reason_code === "injected_native_crash",
  );
  const preparedPaths = transactionPaths(preparedTarget);
  fs.writeFileSync(path.join(preparedPaths.stagingRoot, "foreign-sentinel"), "preserve", "utf8");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(workerLifecycleInput(
      preparedTarget, preparedSource,
    )),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  assert.equal(
    fs.readFileSync(path.join(preparedPaths.stagingRoot, "foreign-sentinel"), "utf8"),
    "preserve",
  );

  const installedTarget = path.join(root, "installed-target");
  const installedSource = path.join(root, "installed-source");
  fs.mkdirSync(installedTarget);
  makeWorkerSource(installedSource);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(installedTarget, installedSource));
  fs.writeFileSync(
    path.join(installedSource, "worker", "README.md"),
    "# replacement before installed crash\n",
  );
  resignWorkerSource(installedSource);
  lifecycleCustodianTest.crashNextAt("installed");
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(
      installedTarget, installedSource,
    )),
    (error) => error && error.reason_code === "injected_native_crash",
  );
  const installedPaths = transactionPaths(installedTarget);
  fs.writeFileSync(path.join(installedPaths.packageRoot, "foreign-sentinel"), "preserve", "utf8");
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(
      installedTarget, installedSource,
    )),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  assert.equal(
    fs.readFileSync(path.join(installedPaths.packageRoot, "foreign-sentinel"), "utf8"),
    "preserve",
  );
  assert.equal(fs.existsSync(installedPaths.backupRoot), true);
});

test("orphan transaction state fails closed and uninstall removes every Bob-owned transaction path", (t) => {
  const root = temporaryDirectory(t, "bob-optional-orphan-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  lifecycle.installOptionalProviderPackage(workerLifecycleInput(target, source));
  const paths = transactionPaths(target);
  fs.mkdirSync(paths.backupRoot);
  assert.throws(
    () => lifecycle.updateOptionalProviderPackage(workerLifecycleInput(target, source)),
    (error) => error && error.reason_code === "native_mutation_rejected",
  );
  assert.equal(workerProbe(target).status, "blocked");

  const dry = lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: true,
  });
  assert.equal(dry.operation, "would_remove");
  assert.equal(fs.existsSync(paths.packageRoot), true);
  const removed = lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: false,
  });
  assert.equal(removed.operation, "removed");
  for (const candidate of [paths.packageRoot, paths.stagingRoot, paths.backupRoot, paths.journal]) {
    assert.equal(fs.existsSync(candidate), false);
  }
  const absent = lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: false,
  });
  assert.equal(absent.operation, "absent");
});

test("descriptor-relative uninstall unlinks target hardlinks without changing outside bytes", (t) => {
  const root = temporaryDirectory(t, "bob-optional-hardlink-uninstall-");
  const target = path.join(root, "workspace");
  const outside = path.join(root, "outside");
  fs.mkdirSync(target);
  fs.mkdirSync(outside);
  const paths = transactionPaths(target);
  fs.mkdirSync(paths.packageRoot, { recursive: true });
  const outsideFile = path.join(outside, "sentinel");
  fs.writeFileSync(outsideFile, "outside-bytes-survive", "utf8");
  fs.linkSync(outsideFile, path.join(paths.packageRoot, "linked-sentinel"));
  const removed = lifecycle.uninstallOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "worker_source",
    dry_run: false,
  });
  assert.equal(removed.operation, "removed");
  assert.equal(fs.existsSync(paths.packageRoot), false);
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "outside-bytes-survive");
  assert.equal(fs.statSync(outsideFile).nlink, 1);
});

test("native prebuild requires a fresh signed envelope and remains unqualified after install", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "native-release");
  fs.mkdirSync(target);
  const fixture = makeNativeReleaseSource(source);

  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(target, source, null)),
    (error) => error && error.reason_code === "signed_release_required",
  );
  const installed = lifecycle.installOptionalProviderPackage(nativeInput(
    target,
    source,
    fixture.releaseVerification,
  ));
  assert.equal(installed.status, "installed_unqualified");
  assert.equal(installed.production_ready, false);
  assert.equal(installed.hardware_access_authorized, false);

  const projection = lifecycle.probeOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "darwin_arm64_native_prebuild",
    host: WORKER_HOST,
    qualification_input: null,
  });
  assert.equal(projection.status, "installed_unqualified", JSON.stringify(projection));
  assert.equal(projection.release_signature_valid, false);
  assert.equal(projection.evidence_cross_bound, false);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.hardware_access_authorized, false);

  const packageRoot = path.join(
    target,
    ".hacker-bob",
    "optional-providers",
    "chameleon-ultra",
    "darwin-arm64-native-prebuild",
  );
  const metadataText = fs.readFileSync(
    path.join(packageRoot, lifecycle.OPTIONAL_PACKAGE_METADATA_FILE),
    "utf8",
  );
  assert.ok(metadataText.includes(fixture.releaseVerification.envelope.manifest_digest));
  assert.ok(!metadataText.includes(fixture.releaseVerification.envelope.authentication.signature));
  assert.ok(!metadataText.includes("public_key_spki_der"));
  const metadata = JSON.parse(metadataText);
  const expectedModes = new Map([
    ["native/ipc-acceptor.node", 0o444],
    ["native/chameleon-cdc-custody.node", 0o444],
    ["bin/bob-safety-watchdog", 0o555],
    ["bin/bob-privileged-launcher", 0o555],
    ["bin/bob-lifecycle-custodian", 0o555],
    ["bin/bob-native-dispatch-custodian", 0o555],
    ["package.json", 0o444],
  ]);
  assert.equal(fixture.schemaArtifacts.length, 28);
  for (const schema of fixture.schemaArtifacts) expectedModes.set(schema.path, 0o444);
  for (const [relative, expectedMode] of expectedModes) {
    assert.equal(fs.statSync(path.join(packageRoot, ...relative.split("/"))).mode & 0o777,
      expectedMode, relative);
    assert.equal(metadata.files.find((file) => file.path === relative).mode, expectedMode);
  }
  const unchanged = lifecycle.updateOptionalProviderPackage(nativeInput(
    target,
    source,
    fixture.releaseVerification,
  ));
  assert.equal(unchanged.operation, "unchanged");
});

test("signed native source rejects every ambient dependency manifest surface", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-dependencies-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);

  for (const [field, value] of [
    ["dependencies", { serialport: "13.0.0" }],
    ["optionalDependencies", { serialport: "13.0.0" }],
    ["peerDependencies", { serialport: "13.0.0" }],
    ["devDependencies", { serialport: "13.0.0" }],
    ["bundleDependencies", ["serialport"]],
    ["bundledDependencies", ["serialport"]],
  ]) {
    const source = path.join(root, field);
    const fixture = makeNativeReleaseSource(source);
    const manifestPath = path.join(source, "package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest[field] = value;
    writeJson(manifestPath, manifest);
    assert.throws(
      () => lifecycle.installOptionalProviderPackage(nativeInput(
        target,
        source,
        fixture.releaseVerification,
      )),
      (error) => error && error.reason_code === "native_manifest_surface_rejected",
      field,
    );
  }
  assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false);
});

test("optional native lifecycle rejects legacy v1 topology before installation", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-v1-rejected-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "legacy-native-release");
  fs.mkdirSync(target);
  const fixture = makeLegacyNativeReleaseSource(source);

  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      source,
      fixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "signed_release_rejected",
  );
  assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false);
});

test("native source and installed mode drift fail closed without executing components", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-mode-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);

  const addonExecSource = path.join(root, "addon-exec");
  const addonFixture = makeNativeReleaseSource(addonExecSource);
  fs.chmodSync(path.join(addonExecSource, "native", "ipc-acceptor.node"), 0o755);
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      addonExecSource,
      addonFixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "native_source_mode_rejected",
  );

  const executableNoExecSource = path.join(root, "executable-no-exec");
  const executableFixture = makeNativeReleaseSource(executableNoExecSource);
  fs.chmodSync(path.join(executableNoExecSource, "bin", "bob-safety-watchdog"), 0o644);
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      executableNoExecSource,
      executableFixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "native_source_mode_rejected",
  );

  const schemaExecSource = path.join(root, "schema-exec");
  const schemaFixture = makeNativeReleaseSource(schemaExecSource);
  fs.chmodSync(
    path.join(schemaExecSource, ...schemaFixture.schemaArtifacts[0].path.split("/")),
    0o755,
  );
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      schemaExecSource,
      schemaFixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "native_source_mode_rejected",
  );

  const missingSchemaSource = path.join(root, "missing-schema");
  const missingSchemaFixture = makeNativeReleaseSource(missingSchemaSource);
  fs.unlinkSync(path.join(
    missingSchemaSource,
    ...missingSchemaFixture.schemaArtifacts[0].path.split("/"),
  ));
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      missingSchemaSource,
      missingSchemaFixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "native_artifact_set_rejected",
  );

  const cleanSource = path.join(root, "clean");
  const cleanFixture = makeNativeReleaseSource(cleanSource);
  lifecycle.installOptionalProviderPackage(nativeInput(
    target,
    cleanSource,
    cleanFixture.releaseVerification,
  ));
  const packageRoot = path.join(
    target,
    ".hacker-bob",
    "optional-providers",
    "chameleon-ultra",
    "darwin-arm64-native-prebuild",
  );
  const probe = () => lifecycle.probeOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "darwin_arm64_native_prebuild",
    host: WORKER_HOST,
    qualification_input: null,
  });
  const addon = path.join(packageRoot, "native", "ipc-acceptor.node");
  fs.chmodSync(addon, 0o555);
  assert.equal(probe().status, "blocked");
  fs.chmodSync(addon, 0o444);
  assert.equal(probe().status, "installed_unqualified");

  const executable = path.join(packageRoot, "bin", "bob-safety-watchdog");
  fs.chmodSync(executable, 0o444);
  assert.equal(probe().status, "blocked");
  fs.chmodSync(executable, 0o555);
  assert.equal(probe().status, "installed_unqualified");

  const schema = path.join(packageRoot, ...cleanFixture.schemaArtifacts[0].path.split("/"));
  fs.chmodSync(schema, 0o555);
  assert.equal(probe().status, "blocked");
  fs.chmodSync(schema, 0o444);
  assert.equal(probe().status, "installed_unqualified");

  const metadataPath = path.join(packageRoot, lifecycle.OPTIONAL_PACKAGE_METADATA_FILE);
  fs.chmodSync(metadataPath, 0o644);
  assert.equal(probe().reason_code, "metadata_mode_rejected");
});

test("signed native install admits six v2 components plus every bound schema and rejects extras", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-extra-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "native-release");
  fs.mkdirSync(target);
  const fixture = makeNativeReleaseSource(source);
  fs.writeFileSync(path.join(source, "evil.node"), "unmanifested", "utf8");
  assert.throws(
    () => lifecycle.installOptionalProviderPackage(nativeInput(
      target,
      source,
      fixture.releaseVerification,
    )),
    (error) => error && error.reason_code === "native_surface_rejected",
  );
  assert.equal(fs.existsSync(path.join(target, ".hacker-bob")), false);
});

test("forged installed metadata cannot turn an extra native payload into a qualified surface", (t) => {
  const root = temporaryDirectory(t, "bob-optional-native-forge-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "native-release");
  fs.mkdirSync(target);
  const fixture = makeNativeReleaseSource(source);
  lifecycle.installOptionalProviderPackage(nativeInput(
    target,
    source,
    fixture.releaseVerification,
  ));
  const packageRoot = path.join(
    target,
    ".hacker-bob",
    "optional-providers",
    "chameleon-ultra",
    "darwin-arm64-native-prebuild",
  );
  const metadataPath = path.join(packageRoot, lifecycle.OPTIONAL_PACKAGE_METADATA_FILE);
  const extraContents = Buffer.from("untrusted-extra-native-payload", "utf8");
  const extraPath = "native/evil.node";
  fs.writeFileSync(path.join(packageRoot, ...extraPath.split("/")), extraContents);
  fs.chmodSync(path.join(packageRoot, ...extraPath.split("/")), 0o444);
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.files.push({
    path: extraPath,
    byte_size: extraContents.length,
    sha256: digest(extraContents),
    mode: 0o444,
  });
  metadata.files.sort((left, right) =>
    (left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)));
  metadata.content_digest = digest(Buffer.from(JSON.stringify({
    domain: "hacker-bob/optional-provider-installed-package/v1",
    provider_id: metadata.provider_id,
    package_id: metadata.package_id,
    package_name: metadata.package_name,
    package_version: metadata.package_version,
    surface_policy: metadata.surface_policy,
    release_manifest_digest: metadata.release_manifest_digest,
    files: metadata.files,
  }), "utf8"));
  fs.chmodSync(metadataPath, 0o644);
  writeJson(metadataPath, metadata);

  const projection = lifecycle.probeOptionalProviderPackage({
    target_abs: target,
    provider_id: "chameleon_ultra",
    package_id: "darwin_arm64_native_prebuild",
    host: WORKER_HOST,
    qualification_input: {
      envelope: fixture.releaseVerification.envelope,
      trust_policy: fixture.releaseVerification.trust_policy,
      evaluation_context: { now: NOW },
    },
  });
  assert.equal(projection.status, "blocked");
  assert.equal(projection.release_signature_valid, false);
  assert.equal(projection.evidence_cross_bound, false);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.hardware_access_authorized, false);
});

test("canonical install blocks symlinked ancestry and replaces a leaf symlink without following it", (t) => {
  const root = temporaryDirectory(t, "bob-canonical-symlink-");
  const outside = path.join(root, "outside");
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "sentinel"), "preserve", "utf8");

  const ancestorTarget = path.join(root, "ancestor-target");
  fs.mkdirSync(ancestorTarget);
  fs.symlinkSync(outside, path.join(ancestorTarget, "packages"));
  assert.throws(
    () => copyCanonicalRuntimePackages(ROOT, ancestorTarget),
    /native mutation rejected|test fixture was rejected|ancestry was rejected/u,
  );
  assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);

  const leafTarget = path.join(root, "leaf-target");
  fs.mkdirSync(path.join(leafTarget, "packages"), { recursive: true });
  fs.symlinkSync(outside, path.join(leafTarget, "packages", "bob-artifact-vault"));
  const copied = copyCanonicalRuntimePackages(ROOT, leafTarget);
  assert.ok(copied.includes("packages/bob-artifact-vault/package.json"));
  assert.equal(
    fs.lstatSync(path.join(leafTarget, "packages", "bob-artifact-vault")).isDirectory(),
    true,
  );
  assert.deepEqual(fs.readdirSync(outside), ["sentinel"]);

  const fakeSource = path.join(root, "fake-source");
  const sourceTarget = path.join(root, "source-target");
  fs.mkdirSync(path.join(fakeSource, "packages"), { recursive: true });
  fs.mkdirSync(sourceTarget);
  fs.symlinkSync(outside, path.join(fakeSource, "packages", "bob-artifact-vault"));
  assert.throws(
    () => copyCanonicalRuntimePackages(fakeSource, sourceTarget),
    (error) => error && error.reason_code === "canonical_source_ancestry_rejected",
  );
  assert.equal(fs.existsSync(path.join(sourceTarget, "packages")), false);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");
});

test("canonical replace retains one direct target guard and rejects a root swap", (t) => {
  const root = temporaryDirectory(t, "bob-canonical-anchor-swap-");
  const target = path.join(root, "workspace");
  const heldTarget = `${target}-held`;
  const outside = path.join(root, "outside");
  fs.mkdirSync(target);
  fs.mkdirSync(path.join(outside, "packages", "bob-artifact-vault"), { recursive: true });
  fs.mkdirSync(path.join(outside, "packages", ".staging-bob-artifact-vault"));
  const outsideLeaf = path.join(outside, "packages", "bob-artifact-vault", "sentinel");
  const outsideStaging = path.join(
    outside,
    "packages",
    ".staging-bob-artifact-vault",
    "sentinel",
  );
  fs.writeFileSync(outsideLeaf, "leaf-preserve", "utf8");
  fs.writeFileSync(outsideStaging, "staging-preserve", "utf8");
  fs.writeFileSync(path.join(outside, "sentinel"), "root-preserve", "utf8");
  const authorityOpensBefore = lifecycleCustodianTest.targetOpenCount();
  const originalRandomBytes = crypto.randomBytes;
  let swapped = false;
  crypto.randomBytes = function swapAtFirstStagingToken(...args) {
    if (!swapped) {
      swapped = true;
      fs.renameSync(target, heldTarget);
      fs.renameSync(outside, target);
    }
    return Reflect.apply(originalRandomBytes, this, args);
  };
  let copyObservation;
  try {
    copyObservation = countExactDirectoryOpens(target, () =>
      assert.throws(
        () => copyCanonicalRuntimePackages(ROOT, target),
        (error) => error && error.reason_code === "canonical_target_ancestry_rejected",
      ));
  } finally {
    crypto.randomBytes = originalRandomBytes;
    if (fs.existsSync(heldTarget)) {
      fs.renameSync(target, outside);
      fs.renameSync(heldTarget, target);
    }
  }
  assert.equal(copyObservation.count, 1);
  assert.equal(lifecycleCustodianTest.targetOpenCount() - authorityOpensBefore, 0);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "root-preserve");
  assert.equal(fs.readFileSync(outsideLeaf, "utf8"), "leaf-preserve");
  assert.equal(fs.readFileSync(outsideStaging, "utf8"), "staging-preserve");
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    assert.equal(fs.existsSync(path.join(target, relativeRoot)), false, relativeRoot);
    assert.equal(fs.existsSync(path.join(outside, relativeRoot)),
      relativeRoot === CANONICAL_RUNTIME_PACKAGE_ROOTS[0], relativeRoot);
  }
});

test("full uninstall removes every canonical/transaction root while preserving unrelated packages", (t) => {
  const root = temporaryDirectory(t, "bob-canonical-uninstall-");
  const target = path.join(root, "workspace");
  fs.mkdirSync(target);
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const packageRoot = path.join(target, relativeRoot);
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, "orphan.js"), "Bob-owned stale file\n", "utf8");
  }
  const unrelated = path.join(target, "packages", "operator-owned", "keep.txt");
  fs.mkdirSync(path.dirname(unrelated), { recursive: true });
  fs.writeFileSync(unrelated, "preserve", "utf8");
  const optional = transactionPaths(target);
  fs.mkdirSync(optional.packageRoot, { recursive: true });
  fs.mkdirSync(optional.stagingRoot);
  fs.mkdirSync(optional.backupRoot);

  const result = uninstallProject(target, {
    adapter: "generic-mcp",
    dryRun: false,
    onAdapterResolution: () => {},
    sourceRoot: ROOT,
  });
  assert.equal(result.ok, true, JSON.stringify(result.skipped));
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    assert.equal(fs.existsSync(path.join(target, relativeRoot)), false, relativeRoot);
  }
  assert.equal(fs.readFileSync(unrelated, "utf8"), "preserve");
  for (const candidate of [
    optional.packageRoot,
    optional.stagingRoot,
    optional.backupRoot,
    optional.journal,
  ]) assert.equal(fs.existsSync(candidate), false, candidate);
});

test("full uninstall retains one target authority across six canonical and two optional roots", (t) => {
  const root = temporaryDirectory(t, "bob-full-uninstall-anchor-swap-");
  const target = path.join(root, "workspace");
  const heldTarget = `${target}-held`;
  const outside = path.join(root, "outside");
  fs.mkdirSync(target);

  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const packageRoot = path.join(target, relativeRoot);
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, "orphan.js"), "Bob-owned stale file\n", "utf8");
  }
  const optionalRoots = [];
  for (const provider of OPTIONAL_PROVIDER_REGISTRY) {
    const providerRoot = path.join(target, ...provider.owned_root.split("/"));
    for (const packageRecord of provider.packages) {
      const roots = {
        packageRoot: path.join(providerRoot, packageRecord.owned_subdirectory),
        stagingRoot: path.join(providerRoot, `.staging-${packageRecord.package_id}`),
        backupRoot: path.join(providerRoot, `.backup-${packageRecord.package_id}`),
      };
      for (const candidate of Object.values(roots)) fs.mkdirSync(candidate, { recursive: true });
      fs.writeFileSync(path.join(roots.packageRoot, "orphan"), "Bob-owned stale file\n", "utf8");
      optionalRoots.push(roots);
    }
  }

  const outsideCanonical = path.join(outside, CANONICAL_RUNTIME_PACKAGE_ROOTS[0]);
  const outsideCanonicalStaging = path.join(
    path.dirname(outsideCanonical),
    `.staging-${path.basename(outsideCanonical)}`,
  );
  fs.mkdirSync(outsideCanonical, { recursive: true });
  fs.mkdirSync(outsideCanonicalStaging);
  fs.writeFileSync(path.join(outsideCanonical, "sentinel"), "canonical-preserve", "utf8");
  fs.writeFileSync(path.join(outsideCanonicalStaging, "sentinel"),
    "canonical-staging-preserve", "utf8");
  const outsideOptionalRoots = [];
  for (const provider of OPTIONAL_PROVIDER_REGISTRY) {
    const providerRoot = path.join(outside, ...provider.owned_root.split("/"));
    for (const packageRecord of provider.packages) {
      const packageRoot = path.join(providerRoot, packageRecord.owned_subdirectory);
      const stagingRoot = path.join(providerRoot, `.staging-${packageRecord.package_id}`);
      fs.mkdirSync(packageRoot, { recursive: true });
      fs.mkdirSync(stagingRoot);
      fs.writeFileSync(path.join(packageRoot, "sentinel"), "optional-preserve", "utf8");
      fs.writeFileSync(path.join(stagingRoot, "sentinel"), "optional-staging-preserve", "utf8");
      outsideOptionalRoots.push({ packageRoot, stagingRoot });
    }
  }
  fs.writeFileSync(path.join(outside, "sentinel"), "root-preserve", "utf8");

  const authorityOpensBefore = lifecycleCustodianTest.targetOpenCount();
  lifecycleCustodianTest.beforeNextNative(() => {
    fs.renameSync(target, heldTarget);
    fs.renameSync(outside, target);
  });
  let uninstallObservation;
  try {
    uninstallObservation = countExactDirectoryOpens(target, () => uninstallProject(target, {
      adapter: "generic-mcp",
      dryRun: false,
      onAdapterResolution: () => {},
      sourceRoot: ROOT,
    }));
  } finally {
    if (fs.existsSync(heldTarget)) {
      fs.renameSync(target, outside);
      fs.renameSync(heldTarget, target);
    }
  }
  assert.equal(uninstallObservation.count, 1);
  assert.equal(lifecycleCustodianTest.targetOpenCount() - authorityOpensBefore, 1);
  assert.equal(uninstallObservation.result.ok, true,
    JSON.stringify(uninstallObservation.result.skipped));
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    assert.equal(fs.existsSync(path.join(target, relativeRoot)), false, relativeRoot);
  }
  for (const roots of optionalRoots) {
    for (const candidate of Object.values(roots)) assert.equal(fs.existsSync(candidate), false);
  }
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "root-preserve");
  assert.equal(fs.readFileSync(path.join(outsideCanonical, "sentinel"), "utf8"),
    "canonical-preserve");
  assert.equal(fs.readFileSync(path.join(outsideCanonicalStaging, "sentinel"), "utf8"),
    "canonical-staging-preserve");
  for (const roots of outsideOptionalRoots) {
    assert.equal(fs.readFileSync(path.join(roots.packageRoot, "sentinel"), "utf8"),
      "optional-preserve");
    assert.equal(fs.readFileSync(path.join(roots.stagingRoot, "sentinel"), "utf8"),
      "optional-staging-preserve");
  }
});

test("canonical uninstall removes a leaf symlink only and blocks a symlinked packages ancestor", (t) => {
  const root = temporaryDirectory(t, "bob-canonical-uninstall-symlink-");
  const outside = path.join(root, "outside");
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "sentinel"), "preserve", "utf8");

  const leafTarget = path.join(root, "leaf-target");
  fs.mkdirSync(path.join(leafTarget, "packages"), { recursive: true });
  const leaf = path.join(leafTarget, CANONICAL_RUNTIME_PACKAGE_ROOTS[0]);
  fs.symlinkSync(outside, leaf);
  const leafResult = uninstallProject(leafTarget, {
    adapter: "generic-mcp",
    dryRun: false,
    onAdapterResolution: () => {},
    sourceRoot: ROOT,
  });
  assert.equal(leafResult.ok, true, JSON.stringify(leafResult.skipped));
  assert.equal(fs.existsSync(leaf), false);
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");

  const ancestorTarget = path.join(root, "ancestor-target");
  fs.mkdirSync(ancestorTarget);
  fs.symlinkSync(outside, path.join(ancestorTarget, "packages"));
  const ancestorResult = uninstallProject(ancestorTarget, {
    adapter: "generic-mcp",
    dryRun: false,
    onAdapterResolution: () => {},
    sourceRoot: ROOT,
  });
  assert.equal(ancestorResult.ok, false);
  assert.ok(ancestorResult.skipped.some((entry) =>
    /canonical_target_ancestry_rejected|native_mutation_rejected|Bob-owned ancestry rejected/u
      .test(entry.reason)));
  assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "preserve");
});

test("optional-provider CLI fails closed for mutation while status stays inert and read-only", (t) => {
  const root = temporaryDirectory(t, "bob-optional-cli-");
  const target = path.join(root, "workspace");
  const source = path.join(root, "source");
  fs.mkdirSync(target);
  makeWorkerSource(source);
  const cli = path.join(ROOT, "bin", "hacker-bob.js");
  const run = (operation, extra = []) => spawnSync(process.execPath, [
    cli,
    "optional-provider",
    operation,
    target,
    "--provider",
    "chameleon_ultra",
    "--package",
    "worker_source",
    ...extra,
    "--json",
  ], { cwd: ROOT, encoding: "utf8" });

  const installResult = run("install", ["--source", source]);
  assert.notEqual(installResult.status, 0);
  assert.match(installResult.stderr, /Qualified lifecycle custodian is unavailable/u);
  const statusResult = run("status");
  assert.equal(statusResult.status, 0, statusResult.stderr);
  const status = JSON.parse(statusResult.stdout);
  assert.equal(status.status, "absent");
  assert.equal(status.activation_performed, false);
  assert.equal(status.hardware_probe_performed, false);
  assert.equal(status.hardware_access_authorized, false);
  const updateResult = run("update", ["--source", source]);
  assert.notEqual(updateResult.status, 0);
  assert.match(updateResult.stderr, /Qualified lifecycle custodian is unavailable/u);
  const dryUninstall = run("uninstall");
  assert.equal(dryUninstall.status, 0, dryUninstall.stderr);
  assert.equal(JSON.parse(dryUninstall.stdout).operation, "absent");
  assert.equal(fs.existsSync(transactionPaths(target).packageRoot), false);
  const removed = run("uninstall", ["--yes"]);
  assert.notEqual(removed.status, 0);
  assert.match(removed.stderr, /Qualified lifecycle custodian is unavailable/u);
  assert.equal(fs.existsSync(transactionPaths(target).packageRoot), false);
});

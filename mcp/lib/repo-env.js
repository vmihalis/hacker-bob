"use strict";

// Cycle O.3 of Plane O: repo-env preparation + Dockerfile.bob generation.
//
// `prepareRepoEnv` is the OSS-axis companion to `bob_init_repo_session`.
// It owns the per-session `Dockerfile.bob`, `repo-env.json`, and the
// `recommended_commands[]` shape that the orchestrator hands to evaluator
// agents. The default mode is `dry_run: true` — we never invoke docker
// unless the operator opts in via `build_image: true` AND docker is
// actually installed.
//
// Plane O invariants enforced here:
//   O-P3  Sandbox flags are emitted in EVERY generated docker argv. Per-flag
//         positive assertions live in the test suite; this module is the
//         producer of those argvs and never strips a sandbox flag.
//   O-D6  Per-session docker image with cache busting. The generated
//         Dockerfile includes `ARG SESSION_ID=<target_domain>` as the FIRST
//         instruction so cross-session BuildKit layer-cache reuse can't
//         smuggle a poisoned layer.
//   O-D7  `recommended_commands[]` has the shape
//         `{id, description, command: string[], role, seed_path?}` where `role ∈
//         {build, test, fuzz, lint, compose}` and `seed_path` is a repo-relative
//         path for seed-corpus commands.
//   O-P7  Every persisted JSONL/JSON write routes through
//         `validateNoSensitiveMaterial` before append. The generated
//         Dockerfile is the only artefact that can carry a proxy reference,
//         and we explicitly forbid `ENV.*PROXY` lines (proxy creds flow via
//         `--build-arg` + `--env` at run time, never via baked image ENV).
//
// Cycle O.3 does NOT exec `docker run`; that is O.4's `repo_docker_run`.
// Cycle O.3 owns the build-image path only, which exec's `docker build`
// when the operator explicitly sets `build_image: true`.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");

const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
  assertInteger,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  repoCommandRunsJsonlPath,
  repoCheckoutDir,
  repoInventoryPath,
  repoRunsDir,
  repoWorkDir,
  sessionDir,
} = require("./paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  writeJsonDocument,
  hashDocumentExcluding,
} = require("./fabric-common.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  assertHistoryAvailableForRef,
  normalizeHistoryRef,
  readRepoSession,
} = require("./repo-target.js");

const execFilePromise = promisify(execFile);

const REPO_ENV_VERSION = 1;

// Default + max timeout for `docker build` invocations. The MVP guidance was
// "5 minutes is enough for almost every base image"; we keep that and let
// operators bump per-invocation if a slow base needs longer.
const DEFAULT_DOCKER_BUILD_TIMEOUT_MS = 300_000;
const MAX_DOCKER_BUILD_TIMEOUT_MS = 600_000;

// Per O.3 §2 — language → base image mapping. Keys are manifest filenames or
// well-known build files; the first match wins. Order matters: we look for
// stronger signals (Cargo.toml, go.mod, etc.) before the catch-all native
// build files because a C-extension Rust crate should still resolve to
// `rust:1.79` rather than the C/C++ base.
const LANGUAGE_DETECTION_ORDER = Object.freeze([
  { name: "node", marker: "package.json", base_image: "node:20" },
  { name: "rust", marker: "Cargo.toml", base_image: "rust:1.79" },
  { name: "go", marker: "go.mod", base_image: "golang:1.22" },
  {
    name: "python",
    markers: ["pyproject.toml", "requirements.txt", "setup.py"],
    base_image: "python:3.12",
  },
  { name: "ruby", marker: "Gemfile", base_image: "ruby:3.3" },
  { name: "php", marker: "composer.json", base_image: "php:8.3-cli" },
  {
    name: "java",
    markers: ["pom.xml", "build.gradle", "build.gradle.kts"],
    base_image: "eclipse-temurin:21-jdk",
  },
]);

const NATIVE_BUILD_MARKERS = Object.freeze([
  "CMakeLists.txt",
  "configure.ac",
  "Makefile.am",
  "Makefile",
  "meson.build",
]);

const DEFAULT_BASE_IMAGE = "ubuntu:24.04";
const C_BASE_IMAGE = "ubuntu:24.04";
const C_DEFAULT_APT_PACKAGES = Object.freeze([
  "build-essential",
  "cmake",
  "ninja-build",
  "clang",
  "gdb",
  "valgrind",
]);
// Extra packages preloaded when O.2 detected NFS/XDR shape. Mirrors the
// MVP carry-back: libtirpc/libnfs/libkrb5/libssl give parsers and DVN
// stubs enough surface to repro from packets in fuzz runs.
const NFS_EXTRA_APT_PACKAGES = Object.freeze([
  "libssl-dev",
  "libkrb5-dev",
  "libtirpc-dev",
]);

const RECOMMENDED_COMMAND_ROLES = Object.freeze([
  "build",
  "test",
  "fuzz",
  "lint",
  "compose",
]);

function dockerfileBobPath(domain) {
  return path.join(sessionDir(domain), "Dockerfile.bob");
}

function repoEnvJsonPath(domain) {
  return path.join(sessionDir(domain), "repo-env.json");
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function hasFile(repoRoot, name) {
  try {
    return fs.statSync(path.join(repoRoot, name)).isFile();
  } catch {
    return false;
  }
}

function detectLanguageProfile(repoRoot) {
  for (const entry of LANGUAGE_DETECTION_ORDER) {
    const markers = entry.markers || [entry.marker];
    for (const marker of markers) {
      if (hasFile(repoRoot, marker)) {
        return {
          language: entry.name,
          base_image: entry.base_image,
          marker,
        };
      }
    }
  }
  // Native build files? Promote to C/C++ profile.
  for (const marker of NATIVE_BUILD_MARKERS) {
    if (hasFile(repoRoot, marker)) {
      return {
        language: "c",
        base_image: C_BASE_IMAGE,
        marker,
      };
    }
  }
  return {
    language: "default",
    base_image: DEFAULT_BASE_IMAGE,
    marker: null,
  };
}

// Build the recommended command list for a detected language. Each entry
// follows O-D7's shape: `{id, description, command: string[], role}`.
//
// Node:    `npm ci --ignore-scripts` (security carry-back; lifecycle scripts
//          run arbitrary code with whatever creds happen to be in scope).
// Python:  `pip install --no-build-isolation` (static-friendly install; lets
//          the static-scan lens read the resolved dependency tree without a
//          PEP 517 build invoking arbitrary setup.py code).
// C/C++:   uses the `compose` role to stage `/src` into `/work/repo` before
//          building, because the repo mount stays read-only and CMake wants
//          to write into the source tree's parent.
function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function firstSeedCorpusRel(seedCorpus) {
  if (!Array.isArray(seedCorpus)) return null;
  for (const entry of seedCorpus) {
    if (entry && typeof entry.rel_path === "string" && entry.rel_path.trim()) {
      return entry.rel_path.trim();
    }
  }
  return null;
}

function recommendedCommandsFor(language, { nfsXdrShape = false, seedCorpus = [] } = {}) {
  if (language === "node") {
    return [
      {
        id: "install",
        description: "Install dependencies without running lifecycle scripts.",
        command: ["npm", "ci", "--ignore-scripts"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the package's npm test script.",
        command: ["npm", "test", "--", "--silent"],
        role: "test",
      },
    ];
  }
  if (language === "python") {
    return [
      {
        id: "install",
        description: "Install dependencies without running PEP 517 build hooks.",
        command: ["pip", "install", "--no-build-isolation", "-r", "requirements.txt"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the pytest suite.",
        command: ["pytest", "-q"],
        role: "test",
      },
    ];
  }
  if (language === "go") {
    return [
      {
        id: "build",
        description: "Compile every Go module under ./...",
        command: ["go", "build", "./..."],
        role: "build",
      },
      {
        id: "test",
        description: "Run the Go test suite.",
        command: ["go", "test", "./..."],
        role: "test",
      },
    ];
  }
  if (language === "rust") {
    return [
      {
        id: "build",
        description: "Build the workspace in release mode.",
        command: ["cargo", "build", "--release", "--locked"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the cargo test suite.",
        command: ["cargo", "test", "--locked"],
        role: "test",
      },
    ];
  }
  if (language === "ruby") {
    return [
      {
        id: "install",
        description: "Install Gemfile dependencies.",
        command: ["bundle", "install", "--frozen"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the rake test target.",
        command: ["bundle", "exec", "rake", "test"],
        role: "test",
      },
    ];
  }
  if (language === "php") {
    return [
      {
        id: "install",
        description: "Install composer dependencies without dev plugins.",
        command: ["composer", "install", "--no-scripts", "--no-plugins"],
        role: "build",
      },
      {
        id: "test",
        description: "Run the PHPUnit suite.",
        command: ["vendor/bin/phpunit"],
        role: "test",
      },
    ];
  }
  if (language === "java") {
    return [
      {
        id: "build",
        description: "Build via maven without spawning network downloads where possible.",
        command: ["mvn", "-B", "-DskipTests=false", "verify"],
        role: "build",
      },
    ];
  }
  if (language === "c") {
    // The C/C++ recipe uses the `compose` role: copy `/src` into `/work/repo`
    // (writable), then cmake+ctest from there. This is the MVP carry-back
    // for read-only-mount staging.
    const staging =
      "cp -a /src/. /work/repo/ && cd /work/repo && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure";
    const sanitizerNote = nfsXdrShape ? " (NFS/XDR shape detected — preload libtirpc/libssl/libkrb5)" : "";
    const commands = [
      {
        id: "build_and_test",
        description: `Stage /src into /work/repo, build with cmake, run ctest.${sanitizerNote}`,
        command: ["sh", "-lc", staging],
        role: "compose",
      },
    ];
    const seedRel = firstSeedCorpusRel(seedCorpus);
    if (seedRel) {
      const quotedSeedRel = shellQuote(seedRel);
      commands.push({
        id: "fuzz_seed_probe",
        description: `Seed corpus discovered at ${seedRel}; adapt it to the repo's existing fuzz harness before non-dry-run replay.`,
        seed_path: seedRel,
        command: [
          "sh",
          "-lc",
          `cp -a /src/. /work/repo/ && cd /work/repo && find ${quotedSeedRel} -maxdepth 2 -type f | head -20`,
        ],
        role: "fuzz",
      });
    }
    return commands;
  }
  return [];
}

// Compose the generated Dockerfile.bob. Plane O reasons:
//
// - `ARG SESSION_ID=<target_domain>` is the FIRST `ARG` instruction. Per O-D6
//   this busts BuildKit's cross-session layer cache so a poisoned layer
//   from another OSS session can't be smuggled into this one.
// - `USER 1000:1000` lands AFTER any apt-get install layer; otherwise the
//   non-root user can't write into /var/lib/apt during install.
// - No `ENV` carries a proxy or credential. Proxy values flow through
//   `--build-arg` (for build-time) and `--env` (for run-time) so they never
//   land in `docker history`.
// - When `allow_network: false`, the generated Dockerfile MUST NOT contain
//   any `apt-get install` / `cargo install` / `npm install` lines so the
//   subsequent `docker build --network none` actually succeeds.
function buildDockerfileBob({
  language,
  baseImage,
  targetDomain,
  nfsXdrShape,
  allowNetwork,
}) {
  const lines = [];
  lines.push(`# Generated by bob_repo_prepare_env for ${targetDomain}`);
  lines.push("# Plane O invariants: O-D6 (ARG SESSION_ID cache-bust), O-P3 (USER 1000:1000),");
  lines.push("# O-P3 (no ENV credentials — proxy threaded via --build-arg / --env at run time).");
  lines.push("");
  lines.push(`ARG SESSION_ID=${targetDomain}`);
  lines.push(`FROM ${baseImage}`);
  lines.push("ARG SESSION_ID");
  lines.push("LABEL bob.session_id=\"${SESSION_ID}\"");
  if (allowNetwork) {
    // ARG declarations for proxy values — populated via --build-arg at build
    // time. These are intentionally NOT promoted to ENV (which would land in
    // `docker history`). The build-time recipe references them locally where
    // an install layer needs them; at run time, --env supplies them again.
    lines.push("ARG HTTP_PROXY=");
    lines.push("ARG HTTPS_PROXY=");
    lines.push("ARG NO_PROXY=");
  }
  if (language === "c") {
    const packages = nfsXdrShape
      ? [...C_DEFAULT_APT_PACKAGES, ...NFS_EXTRA_APT_PACKAGES]
      : [...C_DEFAULT_APT_PACKAGES];
    if (allowNetwork) {
      lines.push("RUN apt-get update \\");
      lines.push(`    && apt-get install -y --no-install-recommends ${packages.join(" ")} \\`);
      lines.push("    && rm -rf /var/lib/apt/lists/*");
    } else {
      lines.push(`# apt-get install skipped (allow_network=false). Packages would be: ${packages.join(" ")}`);
    }
  }
  // Writable staging dir owned by the non-root user. /src remains read-only
  // (mounted at run time by repo_docker_run); /work is the per-session
  // writable area.
  lines.push("RUN mkdir -p /work/repo /work/out && chown -R 1000:1000 /work");
  lines.push("USER 1000:1000");
  lines.push("WORKDIR /src");
  lines.push("");
  return lines.join("\n") + "\n";
}

// Compose the docker build argv for `build_image: true`. Returns an
// `{command, args, env}` triple that the runtime executor consumes. Tests
// inject a fake `execFile` runtime to assert each flag without invoking
// docker.
function buildDockerBuildArgv({
  dockerfilePath,
  contextPath,
  imageTag,
  allowNetwork,
  targetDomain,
  egressProfile,
  env = {},
}) {
  const args = ["build"];
  args.push("--network", allowNetwork ? "default" : "none");
  args.push("--build-arg", `SESSION_ID=${targetDomain}`);
  if (allowNetwork) {
    // Proxy via --build-arg, never ENV in the image. Operators see this as
    // O-R2's mitigation: when the network is open, the proxy stays scoped
    // to build time and never leaks into the resulting image layer.
    const proxyUrl = egressProfile && egressProfile.proxy_url
      ? egressProfile.proxy_url
      : null;
    if (proxyUrl) {
      args.push("--build-arg", `HTTP_PROXY=${proxyUrl}`);
      args.push("--build-arg", `HTTPS_PROXY=${proxyUrl}`);
    }
  }
  args.push("--tag", imageTag);
  args.push("--file", dockerfilePath);
  args.push(contextPath);
  return {
    command: "docker",
    args,
    env: { ...env },
  };
}

// Reject any generated Dockerfile that bakes a proxy/secret into the image
// via `ENV`. The check is intentionally narrow — `ARG HTTP_PROXY=` is fine
// (it's a build-time-only parameter) but `ENV HTTP_PROXY=` would land in
// `docker history`. Per O-P3 / O-R2.
const ENV_SECRET_LEAK_RE = /^\s*ENV\s+[A-Z0-9_]*(PROXY|SECRET|TOKEN|PASSWORD|API[_-]?KEY)\b/m;

function assertNoEnvSecretLeak(dockerfileContent) {
  if (ENV_SECRET_LEAK_RE.test(dockerfileContent)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "generated Dockerfile.bob would bake a proxy or secret into the image via ENV (forbidden by O-P3)",
      { violated_invariant: "O-P3", env_secret_leak: true },
    );
  }
}

async function dockerIsAvailable(runtime) {
  const runner = runtime && typeof runtime.execFile === "function"
    ? runtime.execFile
    : execFilePromise;
  try {
    await runner("docker", ["--version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function buildImageTag(targetDomain, repoHash) {
  // Per O-D6: image tag binds `target_domain` + the pinned `repo_hash` from
  // SessionNucleus. The hash is intentionally already capped to 8-64 hex
  // chars by `initRepoSession`; we trim to 16 for the tag so we stay under
  // docker's 128-char tag limit while still scoping per repo state.
  const tag = `bob-oss-${targetDomain}:${repoHash.slice(0, 16)}`;
  return tag;
}

// Build the repo-env.json document. The document is the operator-visible
// summary of what would happen on docker build — it captures the detected
// language, the chosen base image, the recommended command list, the
// derived image tag, and (when applicable) the resolved egress profile
// identity so reviewers can confirm proxy routing without re-reading the
// session nucleus.
function buildRepoEnvDocument({
  targetDomain,
  repoSession,
  repoRoot,
  detection,
  recommendedCommands,
  imageTag,
  baseImage,
  buildImage,
  dryRun,
  allowNetwork,
  egressProfileSummary,
  generatedAt,
  nfsXdrShape,
  seedCorpus,
  seedCorpusCount,
}) {
  const normalizedSeedCorpusCount = Number.isInteger(seedCorpusCount) && seedCorpusCount >= 0
    ? seedCorpusCount
    : Array.isArray(seedCorpus) ? seedCorpus.length : 0;
  const doc = {
    version: REPO_ENV_VERSION,
    target_domain: targetDomain,
    repo_path: repoRoot,
    repo_hash: repoSession.repo_hash,
    generated_at: generatedAt,
    detection: {
      language: detection.language,
      marker: detection.marker,
      nfs_xdr_shape: nfsXdrShape,
      seed_corpus_count: normalizedSeedCorpusCount,
    },
    base_image: baseImage,
    image_tag: imageTag,
    dry_run: dryRun,
    build_image: buildImage,
    allow_network: allowNetwork,
    egress_profile: egressProfileSummary,
    dockerfile_path: dockerfileBobPath(targetDomain),
    seed_corpus: Array.isArray(seedCorpus) ? seedCorpus : [],
    recommended_commands: recommendedCommands,
  };
  return doc;
}

// Read `nfs_xdr_shape` flag from repo-inventory.json if present. The
// inventory is the authoritative source — prepare_env should reuse the
// O.2 detection rather than re-scanning. When the inventory isn't present
// yet (operator skipped `bob_repo_inventory`), fall back to `false`.
function loadNfsXdrShape(targetDomain) {
  const invPath = repoInventoryPath(targetDomain);
  if (!fs.existsSync(invPath)) return false;
  try {
    const raw = fs.readFileSync(invPath, "utf8");
    const doc = JSON.parse(raw);
    return Boolean(doc && doc.nfs_xdr_shape);
  } catch {
    return false;
  }
}

function loadSeedCorpus(targetDomain) {
  const invPath = repoInventoryPath(targetDomain);
  if (!fs.existsSync(invPath)) return [];
  try {
    const raw = fs.readFileSync(invPath, "utf8");
    const doc = JSON.parse(raw);
    return Array.isArray(doc && doc.seed_corpus) ? doc.seed_corpus : [];
  } catch {
    return [];
  }
}

function loadSeedCorpusCount(targetDomain) {
  const invPath = repoInventoryPath(targetDomain);
  if (!fs.existsSync(invPath)) return 0;
  try {
    const raw = fs.readFileSync(invPath, "utf8");
    const doc = JSON.parse(raw);
    if (
      doc
      && doc.counts
      && Number.isInteger(doc.counts.seed_corpus)
      && doc.counts.seed_corpus >= 0
    ) {
      return doc.counts.seed_corpus;
    }
    return Array.isArray(doc && doc.seed_corpus) ? doc.seed_corpus.length : 0;
  } catch {
    return 0;
  }
}

async function prepareRepoEnv({
  target_domain: targetDomain,
  base_image: baseImageOverride = null,
  build_image: buildImage = false,
  dry_run: dryRun = true,
  allow_network: allowNetwork = false,
  image_tag: imageTagOverride = null,
  timeout_ms: timeoutMsOverride = null,
  egress_profile: egressProfileNameOverride = null,
  runtime = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const repoRoot = repoSession.target_repo.root_path;
  if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `bound repo path is no longer a directory: ${repoRoot}`,
      { repo_error_code: "repo_path_not_directory" },
    );
  }

  const normalizedDryRun = dryRun == null ? true : assertBoolean(dryRun, "dry_run");
  const normalizedBuildImage = buildImage == null ? false : assertBoolean(buildImage, "build_image");
  const normalizedAllowNetwork = allowNetwork == null ? false : assertBoolean(allowNetwork, "allow_network");
  if (normalizedDryRun && normalizedBuildImage) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "dry_run and build_image are mutually exclusive; set dry_run: false to build",
    );
  }
  const timeoutMs = timeoutMsOverride == null
    ? DEFAULT_DOCKER_BUILD_TIMEOUT_MS
    : assertInteger(timeoutMsOverride, "timeout_ms", { min: 1000, max: MAX_DOCKER_BUILD_TIMEOUT_MS });

  const detection = detectLanguageProfile(repoRoot);
  const baseImage = baseImageOverride
    ? assertNonEmptyString(baseImageOverride, "base_image")
    : detection.base_image;
  const nfsXdrShape = loadNfsXdrShape(domain);
  const seedCorpus = loadSeedCorpus(domain);
  const seedCorpusCount = loadSeedCorpusCount(domain);
  const recommendedCommands = recommendedCommandsFor(detection.language, { nfsXdrShape, seedCorpus });
  for (const command of recommendedCommands) {
    assertEnumValue(command.role, RECOMMENDED_COMMAND_ROLES, `recommended_commands[${command.id}].role`);
  }

  const imageTag = imageTagOverride
    ? assertNonEmptyString(imageTagOverride, "image_tag")
    : buildImageTag(domain, repoSession.repo_hash);

  // Resolve egress profile early so build-time proxy routing is deterministic
  // and visible in repo-env.json. We do NOT short-circuit when the profile
  // name override is null — the session's bound egress profile (from
  // state.json) is the default. When `allow_network: false`, we still
  // record the profile name for provenance, but its proxy_url is not
  // injected into the build args.
  let egressProfileResolved = null;
  try {
    const { state } = readSessionStateStrict(domain);
    const profileName = egressProfileNameOverride || state.egress_profile || "default";
    egressProfileResolved = resolveEgressProfile(profileName);
  } catch (error) {
    if (normalizedAllowNetwork) {
      // We need a usable proxy resolution if the operator opened network
      // access. Surface the error explicitly.
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `failed to resolve egress profile for repo build: ${error.message || error}`,
        { repo_error_code: "egress_profile_unresolved" },
      );
    }
  }

  const egressProfileSummary = egressProfileResolved
    ? {
        name: egressProfileResolved.name,
        region: egressProfileResolved.region,
        proxy_configured: egressProfileResolved.proxy_configured,
        proxy_url_redacted: egressProfileResolved.proxy_url_redacted,
        egress_profile_identity_hash: egressProfileResolved.egress_profile_identity_hash,
      }
    : null;

  const dockerfileContent = buildDockerfileBob({
    language: detection.language,
    baseImage,
    targetDomain: domain,
    nfsXdrShape,
    allowNetwork: normalizedAllowNetwork,
  });
  assertNoEnvSecretLeak(dockerfileContent);

  const generatedAt = new Date().toISOString();
  const document = buildRepoEnvDocument({
    targetDomain: domain,
    repoSession,
    repoRoot,
    detection,
    recommendedCommands,
    imageTag,
    baseImage,
    buildImage: normalizedBuildImage,
    dryRun: normalizedDryRun,
    allowNetwork: normalizedAllowNetwork,
    egressProfileSummary,
    generatedAt,
    nfsXdrShape,
    seedCorpus,
    seedCorpusCount,
  });
  // O-P7: scrub-validate before persistence. The recommended_commands carry
  // shell strings; the validator already catches inline tokens like
  // "PASSWORD=hunter2" via SENSITIVE_VALUE_RE so a future operator override
  // can't smuggle credentials into the recipe.
  validateNoSensitiveMaterial(document, "repo_env");
  document.repo_env_hash = hashDocumentExcluding(document, ["generated_at", "repo_env_hash"]);

  // Phase 1: synchronous persistence under the session lock. The lock helper
  // refuses async callbacks (storage.js: "withSessionLock callback must be
  // synchronous"), so docker build — which is inherently async — happens in
  // phase 2 below, after the lock is released. That ordering also matches
  // the contract that artefacts are durable on disk before any out-of-process
  // side effect fires.
  const persisted = withSessionLock(domain, () => {
    const dockerfilePath = dockerfileBobPath(domain);
    const repoEnvPath = repoEnvJsonPath(domain);
    fs.writeFileSync(dockerfilePath, dockerfileContent, "utf8");
    writeJsonDocument(repoEnvPath, document);
    return { dockerfilePath, repoEnvPath };
  });
  const dockerfilePath = persisted.dockerfilePath;
  const repoEnvPath = persisted.repoEnvPath;

  if (normalizedBuildImage) {
    const dockerAvailable = await dockerIsAvailable(runtime);
    if (!dockerAvailable) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "docker is not installed or not in PATH; rerun with dry_run: true",
        { repo_error_code: "docker_unavailable" },
      );
    }
    const argv = buildDockerBuildArgv({
      dockerfilePath,
      contextPath: repoRoot,
      imageTag,
      allowNetwork: normalizedAllowNetwork,
      targetDomain: domain,
      egressProfile: egressProfileResolved,
    });
    const runner = runtime && typeof runtime.execFile === "function"
      ? runtime.execFile
      : execFilePromise;
    try {
      await runner(argv.command, argv.args, { timeout: timeoutMs, env: { ...process.env, ...(argv.env || {}) } });
    } catch (error) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `docker build failed: ${error.message || error}`,
        { repo_error_code: "docker_build_failed" },
      );
    }
  }

  return {
    created: true,
    target_domain: domain,
    repo_path: repoRoot,
    dockerfile_path: dockerfilePath,
    repo_env_path: repoEnvPath,
    image_tag: imageTag,
    base_image: baseImage,
    language: detection.language,
    nfs_xdr_shape: nfsXdrShape,
    seed_corpus: seedCorpus,
    seed_corpus_count: seedCorpusCount,
    dry_run: normalizedDryRun,
    build_image: normalizedBuildImage,
    allow_network: normalizedAllowNetwork,
    recommended_commands: recommendedCommands,
    repo_env_hash: document.repo_env_hash,
    egress_profile: egressProfileSummary,
  };
}

// =====================================================================
// Cycle O.4 — sandboxed docker execution via bob_repo_docker_run
// =====================================================================
//
// `repoDockerRun` is the OSS-axis evaluator entrypoint that runs an
// operator-vetted command inside the per-session image built in O.3.
//
// Plane O invariants enforced here:
//
//   O-P3  Every constructed argv carries the FULL sandbox flag set:
//         --cap-drop ALL, --security-opt no-new-privileges,
//         --user 1000:1000, --cpus 2, --memory 4g, --pids-limit 1024,
//         --read-only-tmpfs, --tmpfs /tmp:size=512m, and
//         --network none by default (or --network bridge when the
//         operator explicitly sets allow_network: true). Tests assert
//         each flag individually so a regression that drops one shows
//         up as a single specific failure.
//
//   O-D6  Refuses to run when image_tag doesn't match the session's
//         derived tag (computed from the SessionNucleus-pinned
//         repo_hash). This blocks an evaluator from sneaking a
//         cross-session image into the run path.
//
//   O-P7  Persistence routes the JSONL entry through
//         validateNoSensitiveMaterial. The JSONL NEVER carries raw
//         stdout/stderr — only the path + sha256 of the capture file.
//         Raw stdout/stderr files in repo-runs/ are protected by
//         session-read-guard.sh extensions in O.7.
//
//   O.4-§9 Allowed role-bundles: evaluator-shared, verifier, evidence.
//         The orchestrator dispatches; it does NOT execute docker.
//
// Defaults: dry_run: true, allow_network: false,
// repo_mount_mode: "read_only", timeout_ms: 300_000 (max 600_000).
//
// Dry-run shape: still validates inputs, constructs the argv, records
// {dry_run: true, planned_argv, ...} to repo-command-runs.jsonl, and
// returns the run plan. No docker invocation, no capture files.

const REPO_DOCKER_RUN_VERSION = 1;
const REPO_DOCKER_RUN_DEFAULT_TIMEOUT_MS = 300_000;
const REPO_DOCKER_RUN_MAX_TIMEOUT_MS = 600_000;
const DIFFERENTIAL_MATERIALIZER_TIMEOUT_MS = 30_000;
const REPO_DOCKER_RUN_MAX_OUTPUT_BYTES = 16 * 1024 * 1024; // 16 MB per stream
const REPO_DOCKER_RUN_MAX_COMMAND_TOKENS = 64;
const REPO_DOCKER_RUN_MAX_TOKEN_LENGTH = 2048;
const REPO_WORK_MOUNT_MODE = "read_write";
// Plane X Cycle X.7 (X-P9 retrofit): stdout/stderr first-line previews
// cap. 200 chars matches the http_record body_preview discipline; the
// per-stream first line is captured at completion time so the JSONL
// row becomes brief-inlinable without resolving the full capture file.
const REPO_DOCKER_RUN_FIRST_LINE_MAX_CHARS = 200;
// Bound the bytes we read from each capture file when probing for the
// first line so a degenerate stream that emits a multi-MB first line
// does not pull 16 MB into RAM just to compute a 200-char preview.
const REPO_DOCKER_RUN_FIRST_LINE_PROBE_BYTES = 4096;
const REPO_MOUNT_MODE_VALUES = Object.freeze(["read_only", "read_write"]);
const DIFFERENTIAL_CHECKOUT_KIND_VALUES = Object.freeze([
  "upstream_fix",
  "pre_introduction",
  "self_patch",
]);
const REPO_DOCKER_RUN_DNS = "1.1.1.1";
const REPO_DOCKER_RUN_PROXY_ARG = Object.freeze({
  http: "HTTP_PROXY",
  https: "HTTPS_PROXY",
  no: "NO_PROXY",
});

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function generateRunId() {
  // 8-hex prefix from the ISO timestamp keeps run ids loosely
  // chronological (helps when scanning repo-runs/ by name) without
  // depending on a global counter that would need locking.
  const stamp = Date.now().toString(16).padStart(12, "0");
  const noise = crypto.randomBytes(4).toString("hex");
  return `run-${stamp}-${noise}`;
}

function assertCommandArray(command) {
  if (!Array.isArray(command) || command.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "command must be a non-empty array of string tokens",
    );
  }
  if (command.length > REPO_DOCKER_RUN_MAX_COMMAND_TOKENS) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `command must have at most ${REPO_DOCKER_RUN_MAX_COMMAND_TOKENS} tokens`,
    );
  }
  const normalized = [];
  for (let i = 0; i < command.length; i++) {
    const raw = command[i];
    if (typeof raw !== "string" || raw.length === 0) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `command[${i}] must be a non-empty string`,
      );
    }
    if (raw.length > REPO_DOCKER_RUN_MAX_TOKEN_LENGTH) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `command[${i}] must be at most ${REPO_DOCKER_RUN_MAX_TOKEN_LENGTH} characters`,
      );
    }
    normalized.push(raw);
  }
  return normalized;
}

function assertCheckoutRef(value, fieldName) {
  return normalizeHistoryRef(value, fieldName);
}

function normalizeDifferentialCheckout(checkout) {
  if (checkout == null) return null;
  if (typeof checkout !== "object" || Array.isArray(checkout)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "checkout must be an object when provided",
    );
  }
  return {
    ref: assertCheckoutRef(checkout.ref, "checkout.ref"),
    kind: assertEnumValue(checkout.kind, DIFFERENTIAL_CHECKOUT_KIND_VALUES, "checkout.kind"),
  };
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function assertWorkPath(value, fieldName) {
  const normalized = assertNonEmptyString(value, fieldName);
  if (!normalized.startsWith("/work/")
      || normalized.includes("..")
      || normalized.includes("//")
      || !/^\/work\/[A-Za-z0-9._/-]+$/.test(normalized)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be a safe path under /work`,
      { repo_error_code: "invalid_differential_dest" },
    );
  }
  return normalized;
}

function assertWorkDest(dest) {
  return assertWorkPath(dest, "dest");
}

function assertContainerCheckoutDest(dest) {
  const normalized = assertNonEmptyString(dest, "dest");
  // S14 control replay intentionally runs from /src: repoDockerRun binds
  // /src to a run-scoped checkout under repo-checkouts/, outside writable
  // /work. Other container paths must stay under /work.
  if (normalized === "/src") return normalized;
  return assertWorkDest(normalized);
}

function hostPathContains(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!!relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}

function realpathIfPossible(filePath) {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

function assertRunScopedPathBoundary(base, candidate) {
  const baseReal = realpathIfPossible(base);
  const relative = path.relative(base, candidate);
  if (!relative) return;
  let cursor = base;
  for (const part of relative.split(path.sep)) {
    if (!part || part === ".") continue;
    cursor = path.join(cursor, part);
    let lstat = null;
    try {
      lstat = fs.lstatSync(cursor);
    } catch (error) {
      if (error && error.code === "ENOENT") break;
      throw error;
    }
    if (lstat.isSymbolicLink()) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "differential checkout run path must not include symlinks",
        { repo_error_code: "differential_checkout_symlink_escape" },
      );
    }
    const cursorReal = realpathIfPossible(cursor);
    if (!hostPathContains(baseReal, cursorReal)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "differential checkout run path escaped the repo work directory",
        { repo_error_code: "differential_checkout_symlink_escape" },
      );
    }
  }
}

function assertRepoWorkDirBoundary(workDir, sessionRoot) {
  const base = path.resolve(workDir);
  const sessionReal = realpathIfPossible(sessionRoot);
  const parent = path.dirname(base);
  if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "repo work directory parent is missing",
      { repo_error_code: "repo_work_path_invalid" },
    );
  }
  const parentReal = realpathIfPossible(parent);
  if (!hostPathContains(sessionReal, parentReal)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "repo work directory parent escaped the session directory",
      { repo_error_code: "repo_work_symlink_escape" },
    );
  }
  let baseLstat = null;
  try {
    baseLstat = fs.lstatSync(base);
  } catch (error) {
    if (!error || error.code !== "ENOENT") throw error;
  }
  if (baseLstat) {
    const lstat = baseLstat;
    if (lstat.isSymbolicLink()) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "repo work directory must not be a symlink",
        { repo_error_code: "repo_work_symlink_escape" },
      );
    }
    if (!fs.statSync(base).isDirectory()) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "repo work path is not a directory",
        { repo_error_code: "repo_work_path_invalid" },
      );
    }
    const baseReal = realpathIfPossible(base);
    if (!hostPathContains(sessionReal, baseReal)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        "repo work directory escaped the session directory",
        { repo_error_code: "repo_work_symlink_escape" },
      );
    }
  }
  return base;
}

function runScopedHostPath(workDir, sessionRoot, runId, ...parts) {
  const base = assertRepoWorkDirBoundary(workDir, sessionRoot);
  const candidate = path.resolve(base, runId, ...parts);
  if (!hostPathContains(base, candidate)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "differential checkout run path escaped the repo work directory",
      { repo_error_code: "invalid_differential_dest" },
    );
  }
  assertRunScopedPathBoundary(base, candidate);
  return candidate;
}

function mkdirDifferentialRunDirectory(dirPath, mode) {
  try {
    fs.mkdirSync(dirPath, { mode });
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `differential checkout run path could not be created safely: ${error.message || error}`,
      { repo_error_code: "differential_checkout_symlink_escape" },
    );
  }
  const lstat = fs.lstatSync(dirPath);
  if (lstat.isSymbolicLink() || !fs.statSync(dirPath).isDirectory()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "differential checkout run path must be a directory and must not be a symlink",
      { repo_error_code: "differential_checkout_symlink_escape" },
    );
  }
  fs.chmodSync(dirPath, mode);
}

async function execDifferentialMaterializer(command, args, stage) {
  try {
    await execFilePromise(command, args, {
      timeout: DIFFERENTIAL_MATERIALIZER_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `differential checkout materialization failed during ${stage}: ${error.message || error}`,
      { repo_error_code: "differential_checkout_materialization_failed" },
    );
  }
}

async function materializeDifferentialCheckoutTree({
  repoRoot,
  checkoutRoot,
  workDir,
  sessionRoot,
  runId,
  checkoutRef,
  checkoutObject,
  checkoutKind,
  expectedPatchHash = null,
}) {
  assertCheckoutRef(checkoutRef, "checkout_ref");
  const archiveRef = assertCheckoutRef(checkoutObject || checkoutRef, "checkout_object");
  const kind = assertEnumValue(checkoutKind, DIFFERENTIAL_CHECKOUT_KIND_VALUES, "checkout_kind");
  const runWorkDir = runScopedHostPath(checkoutRoot, sessionRoot, runId);
  const checkoutDir = runScopedHostPath(checkoutRoot, sessionRoot, runId, "repo");
  const checkoutTar = runScopedHostPath(checkoutRoot, sessionRoot, runId, "checkout.tar");
  fs.rmSync(runWorkDir, { recursive: true, force: true });
  fs.mkdirSync(checkoutRoot, { recursive: true, mode: 0o755 });
  assertRepoWorkDirBoundary(checkoutRoot, sessionRoot);
  fs.mkdirSync(workDir, { recursive: true, mode: 0o755 });
  assertRepoWorkDirBoundary(workDir, sessionRoot);
  mkdirDifferentialRunDirectory(runWorkDir, 0o755);
  assertRunScopedPathBoundary(path.resolve(checkoutRoot), runWorkDir);
  mkdirDifferentialRunDirectory(checkoutDir, 0o755);
  assertRunScopedPathBoundary(path.resolve(checkoutRoot), checkoutDir);

  if (kind !== "self_patch") {
    try {
      await execDifferentialMaterializer(
        "git",
        ["-C", repoRoot, "archive", "--format=tar", `--output=${checkoutTar}`, archiveRef],
        "git archive",
      );
      await execDifferentialMaterializer("tar", ["-x", "-f", checkoutTar, "-C", checkoutDir], "tar extract");
    } finally {
      fs.rmSync(checkoutTar, { force: true });
    }
    return { checkout_path: checkoutDir };
  }

  const patchBuffer = readSelfPatchBuffer(workDir, sessionRoot);
  const observedPatchHash = patchBuffer ? sha256Hex(patchBuffer) : null;
  if (!observedPatchHash) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "self_patch checkout requires /work/patch.diff before bob_repo_docker_run",
      { repo_error_code: "missing_differential_patch" },
    );
  }
  if (expectedPatchHash && observedPatchHash !== expectedPatchHash) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "self_patch checkout patch changed during differential materialization",
      { repo_error_code: "differential_patch_changed" },
    );
  }

  const tempRoot = runScopedHostPath(checkoutRoot, sessionRoot, runId, "host-materialize");
  const patchSnapshot = path.join(tempRoot, "patch.diff");
  const baseTar = runScopedHostPath(checkoutRoot, sessionRoot, runId, "base.tar");
  fs.mkdirSync(tempRoot, { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(patchSnapshot, patchBuffer, { mode: 0o600 });
    await execDifferentialMaterializer(
      "git",
      ["-C", repoRoot, "archive", "--format=tar", `--output=${baseTar}`, archiveRef],
      "git archive",
    );
    await execDifferentialMaterializer("tar", ["-x", "-f", baseTar, "-C", checkoutDir], "tar extract");
    await execDifferentialMaterializer("git", ["-C", checkoutDir, "apply", patchSnapshot], "git apply");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(baseTar, { force: true });
    fs.rmSync(checkoutTar, { force: true });
  }
  return { checkout_path: checkoutDir };
}

function buildDifferentialCheckoutCommand({
  checkout_ref: checkoutRef,
  checkout_kind: checkoutKind,
  dest = "/src",
  after_command: afterCommand = null,
} = {}) {
  assertCheckoutRef(checkoutRef, "checkout_ref");
  assertEnumValue(checkoutKind, DIFFERENTIAL_CHECKOUT_KIND_VALUES, "checkout_kind");
  const checkoutDest = assertContainerCheckoutDest(dest);
  const normalizedAfterCommand = afterCommand == null ? null : assertCommandArray(afterCommand);
  const script = [
    "set -eu",
    `test -d ${shellQuote(checkoutDest)}`,
  ];
  if (normalizedAfterCommand) {
    script.push(`cd ${shellQuote(checkoutDest)}`);
    script.push(normalizedAfterCommand.map(shellQuote).join(" "));
  }
  return assertCommandArray(["sh", "-c", script.join(" && ")]);
}

// Build the docker run argv. Each O-P3 sandbox flag is emitted in
// fixed order so the test suite can assert per-flag presence by
// indexOf. The function is pure (no I/O) so tests exercise it
// directly without a temp session.
function buildDockerRunArgv({
  repoRoot,
  workDir,
  imageTag,
  command,
  allowNetwork,
  repoMountMode,
  egressProfile,
}) {
  if (!repoRoot || !workDir || !imageTag || !Array.isArray(command) || command.length === 0) {
    throw new Error("buildDockerRunArgv requires repoRoot, workDir, imageTag, command");
  }
  const args = ["run", "--rm"];
  // Network: --network none by default. When allow_network is true we
  // attach the standard bridge network and pin DNS to 1.1.1.1 so the
  // host's resolver (which may carry secret tokens via /etc/hosts
  // shadowing or local stub resolvers) is bypassed.
  args.push("--network", allowNetwork ? "bridge" : "none");
  if (allowNetwork) {
    args.push("--dns", REPO_DOCKER_RUN_DNS);
  }
  // O-P3 mandatory sandbox flags — order is the doc's order so reviewers
  // can scan the argv and the spec block side-by-side.
  args.push("--cap-drop", "ALL");
  args.push("--security-opt", "no-new-privileges");
  args.push("--user", "1000:1000");
  args.push("--cpus", "2");
  args.push("--memory", "4g");
  args.push("--pids-limit", "1024");
  args.push("--read-only");
  args.push("--tmpfs", "/tmp:size=512m");
  // Mounts: /src is the bound repo (read-only by default), /work is
  // session-scoped writable space for build artefacts.
  const mountSuffix = repoMountMode === "read_write" ? "rw" : "ro";
  args.push("-v", `${repoRoot}:/src:${mountSuffix}`);
  args.push("-v", `${workDir}:/work:rw`);
  // Proxy: --env (run-time), NEVER ENV in the image. Skipping these
  // when allow_network=false keeps the offline path airtight.
  if (allowNetwork) {
    const proxyUrl = egressProfile && egressProfile.proxy_url
      ? egressProfile.proxy_url
      : null;
    if (proxyUrl) {
      args.push("--env", `${REPO_DOCKER_RUN_PROXY_ARG.http}=${proxyUrl}`);
      args.push("--env", `${REPO_DOCKER_RUN_PROXY_ARG.https}=${proxyUrl}`);
    }
  }
  args.push(imageTag);
  for (const token of command) {
    args.push(token);
  }
  return {
    command: "docker",
    args,
    env: {},
  };
}

// Default spawn-based runtime. The runtime contract is:
//   await runtime.run({command, args, timeout_ms, stdoutPath, stderrPath})
// returns {exit_code, signal, duration_ms, timed_out, stdout_bytes,
//          stderr_bytes, stdout_truncated, stderr_truncated}.
//
// Stdout/stderr are streamed to disk (capped at 16 MB each) — never
// held in process memory. Tests inject a stub so they can assert the
// constructed argv and synthesize an exit code without actually
// invoking docker.
function defaultDockerRuntime() {
  return {
    async run({ command, args, timeoutMs, stdoutPath, stderrPath }) {
      const { spawn } = require("child_process");
      return new Promise((resolve, reject) => {
        let child;
        try {
          child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
        } catch (error) {
          reject(error);
          return;
        }
        const stdoutFd = fs.openSync(stdoutPath, "w");
        const stderrFd = fs.openSync(stderrPath, "w");
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let stdoutTruncated = false;
        let stderrTruncated = false;
        let timedOut = false;
        const startedAt = Date.now();
        const timer = setTimeout(() => {
          timedOut = true;
          try { child.kill("SIGTERM"); } catch {}
          setTimeout(() => {
            try { child.kill("SIGKILL"); } catch {}
          }, 5000);
        }, timeoutMs);
        child.stdout.on("data", (chunk) => {
          const remaining = REPO_DOCKER_RUN_MAX_OUTPUT_BYTES - stdoutBytes;
          if (remaining > 0) {
            const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
            fs.writeSync(stdoutFd, slice, 0, slice.length);
          } else {
            stdoutTruncated = true;
          }
          stdoutBytes += chunk.length;
          if (stdoutBytes > REPO_DOCKER_RUN_MAX_OUTPUT_BYTES) stdoutTruncated = true;
        });
        child.stderr.on("data", (chunk) => {
          const remaining = REPO_DOCKER_RUN_MAX_OUTPUT_BYTES - stderrBytes;
          if (remaining > 0) {
            const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
            fs.writeSync(stderrFd, slice, 0, slice.length);
          } else {
            stderrTruncated = true;
          }
          stderrBytes += chunk.length;
          if (stderrBytes > REPO_DOCKER_RUN_MAX_OUTPUT_BYTES) stderrTruncated = true;
        });
        child.on("error", (error) => {
          clearTimeout(timer);
          try { fs.closeSync(stdoutFd); } catch {}
          try { fs.closeSync(stderrFd); } catch {}
          reject(error);
        });
        child.on("close", (code, signal) => {
          clearTimeout(timer);
          try { fs.closeSync(stdoutFd); } catch {}
          try { fs.closeSync(stderrFd); } catch {}
          resolve({
            exit_code: code,
            signal,
            duration_ms: Date.now() - startedAt,
            timed_out: timedOut,
            stdout_bytes: stdoutBytes,
            stderr_bytes: stderrBytes,
            stdout_truncated: stdoutTruncated,
            stderr_truncated: stderrTruncated,
          });
        });
      });
    },
    async execFile(command, args, options = {}) {
      // Used for `docker --version` probes. The default falls through to
      // the same execFilePromise used by prepareRepoEnv.
      return execFilePromise(command, args, options);
    },
  };
}

async function dockerCliAvailable(runtime) {
  const runner = runtime && typeof runtime.execFile === "function"
    ? runtime.execFile
    : execFilePromise;
  try {
    await runner("docker", ["--version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

// Hash the stdout/stderr file for use in the JSONL row. The hash is
// what callers verify against the EvidenceReference in O.8.
function hashFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const data = fs.readFileSync(filePath);
    return sha256Hex(data);
  } catch {
    return null;
  }
}

function readSelfPatchBuffer(workDir, sessionRoot) {
  const base = assertRepoWorkDirBoundary(workDir, sessionRoot);
  const patchPath = path.join(base, "patch.diff");
  let lstat = null;
  try {
    lstat = fs.lstatSync(patchPath);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
  if (!lstat.isFile()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "self_patch checkout requires /work/patch.diff to be a regular Bob-owned file",
      { repo_error_code: "invalid_differential_patch" },
    );
  }
  const baseReal = realpathIfPossible(base);
  const patchReal = realpathIfPossible(patchPath);
  if (!hostPathContains(baseReal, patchReal)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "self_patch checkout patch escaped the repo work directory",
      { repo_error_code: "differential_patch_symlink_escape" },
    );
  }
  return fs.readFileSync(patchPath);
}

function hashSelfPatchFile(workDir, sessionRoot) {
  const patchBuffer = readSelfPatchBuffer(workDir, sessionRoot);
  return patchBuffer ? sha256Hex(patchBuffer) : null;
}

// Plane X Cycle X.7 (X-P9 retrofit): read the first line of a capture
// file for the brief-inlinable summary. Bounded by a 4KB probe so a
// degenerate single-line capture file does not pull 16MB into memory
// just to compute a 200-char preview. Returns null on missing file,
// empty file, or read error; the JSONL row's `null` is then a stable
// signal that there was no usable first line.
function readFirstLine(filePath, maxChars) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const stat = fs.statSync(filePath);
    if (stat.size === 0) return null;
    const probeLen = Math.min(stat.size, REPO_DOCKER_RUN_FIRST_LINE_PROBE_BYTES);
    const fd = fs.openSync(filePath, "r");
    try {
      const buf = Buffer.alloc(probeLen);
      const bytesRead = fs.readSync(fd, buf, 0, probeLen, 0);
      if (bytesRead <= 0) return null;
      const text = buf.subarray(0, bytesRead).toString("utf8");
      const newlineIdx = text.indexOf("\n");
      const firstLine = newlineIdx === -1 ? text : text.slice(0, newlineIdx);
      // Strip trailing CR for CRLF-emitting platforms.
      const stripped = firstLine.endsWith("\r") ? firstLine.slice(0, -1) : firstLine;
      if (!stripped) return null;
      return stripped.length > maxChars
        ? `${stripped.slice(0, maxChars)}…`
        : stripped;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

// Normalize replay_context. Operators pass {wave, agent, surface_id?, ...}
// so we can correlate runs back to their evaluator dispatch. The shape
// must not carry secrets (sensitive-material scan catches that).
function normalizeReplayContext(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "replay_context must be an object when provided",
    );
  }
  const allowedKeys = new Set([
    "wave",
    "agent",
    "surface_id",
    "finding_id",
    "task_lens",
    "technique_pack_id",
    "purpose",
    "operator_note",
  ]);
  const out = {};
  for (const [key, raw] of Object.entries(value)) {
    if (!allowedKeys.has(key)) continue;
    if (raw == null) continue;
    if (typeof raw === "number") {
      out[key] = raw;
      continue;
    }
    if (typeof raw === "string") {
      const trimmed = raw.trim();
      if (trimmed.length > 256) {
        throw new ToolError(
          ERROR_CODES.INVALID_ARGUMENTS,
          `replay_context.${key} must be at most 256 characters`,
        );
      }
      if (trimmed) out[key] = trimmed;
      continue;
    }
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `replay_context.${key} must be a string or number`,
    );
  }
  return Object.keys(out).length > 0 ? out : null;
}

async function repoDockerRun({
  target_domain: targetDomain,
  command,
  checkout = null,
  dry_run: dryRun = true,
  allow_network: allowNetwork = false,
  repo_mount_mode: repoMountMode = "read_only",
  image_tag: imageTagOverride = null,
  timeout_ms: timeoutMsOverride = null,
  replay_context: replayContextRaw = null,
  blocked_harness_run_id: blockedHarnessRunIdRaw = null,
  egress_profile: egressProfileNameOverride = null,
  runtime = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const repoSession = readRepoSession(domain);
  const repoRoot = repoSession.target_repo.root_path;
  const sessionRoot = sessionDir(domain);
  const workDir = repoWorkDir(domain);
  const checkoutRoot = repoCheckoutDir(domain);
  if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `bound repo path is no longer a directory: ${repoRoot}`,
      { repo_error_code: "repo_path_not_directory" },
    );
  }

  const runId = generateRunId();
  const normalizedCheckout = normalizeDifferentialCheckout(checkout);
  const normalizedInputCommand = assertCommandArray(command);
  let checkoutHistory = null;
  if (normalizedCheckout) {
    checkoutHistory = assertHistoryAvailableForRef(repoRoot, normalizedCheckout.ref);
  }
  const checkoutSrcRoot = normalizedCheckout
    ? runScopedHostPath(checkoutRoot, sessionRoot, runId, "repo")
    : repoRoot;
  const effectiveCommand = normalizedCheckout
    ? buildDifferentialCheckoutCommand({
        checkout_ref: normalizedCheckout.ref,
        checkout_kind: normalizedCheckout.kind,
        dest: "/src",
        after_command: normalizedInputCommand,
      })
    : normalizedInputCommand;
  const normalizedCommand = assertCommandArray(effectiveCommand);
  const normalizedDryRun = dryRun == null ? true : assertBoolean(dryRun, "dry_run");
  const normalizedAllowNetwork = allowNetwork == null ? false : assertBoolean(allowNetwork, "allow_network");
  const normalizedMountMode = assertEnumValue(
    repoMountMode == null ? "read_only" : repoMountMode,
    REPO_MOUNT_MODE_VALUES,
    "repo_mount_mode",
  );
  if (normalizedCheckout && normalizedMountMode !== "read_only") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "differential checkout runs require repo_mount_mode read_only",
      { repo_error_code: "differential_checkout_requires_read_only_mount" },
    );
  }
  const normalizedTimeoutMs = timeoutMsOverride == null
    ? REPO_DOCKER_RUN_DEFAULT_TIMEOUT_MS
    : assertInteger(timeoutMsOverride, "timeout_ms", {
      min: 1000,
      max: REPO_DOCKER_RUN_MAX_TIMEOUT_MS,
    });
  const normalizedReplayContext = normalizeReplayContext(replayContextRaw);
  const normalizedBlockedHarnessRunId = blockedHarnessRunIdRaw == null
    ? null
    : assertNonEmptyString(blockedHarnessRunIdRaw, "blocked_harness_run_id");

  // Image tag is bound to the session's pinned repo_hash. An explicit
  // override is allowed but only when it matches the derived tag — O-D6
  // refuses cross-session images so we never accidentally run a poisoned
  // layer from a previous session.
  const expectedImageTag = buildImageTag(domain, repoSession.repo_hash);
  let imageTag = expectedImageTag;
  if (imageTagOverride != null) {
    const provided = assertNonEmptyString(imageTagOverride, "image_tag");
    if (provided !== expectedImageTag) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `image_tag does not match the session's derived tag; got ${provided}, expected ${expectedImageTag}`,
        {
          repo_error_code: "image_tag_mismatch",
          provided_image_tag: provided,
          expected_image_tag: expectedImageTag,
          violated_invariant: "O-D6",
        },
      );
    }
    imageTag = provided;
  }

  // Resolve egress profile if the operator opened the network. We
  // surface the profile summary in the JSONL row for provenance and
  // thread the proxy_url into the run-time --env flags.
  let egressProfileResolved = null;
  try {
    const { state } = readSessionStateStrict(domain);
    const profileName = egressProfileNameOverride || state.egress_profile || "default";
    egressProfileResolved = resolveEgressProfile(profileName);
  } catch (error) {
    if (normalizedAllowNetwork) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `failed to resolve egress profile for repo docker run: ${error.message || error}`,
        { repo_error_code: "egress_profile_unresolved" },
      );
    }
  }
  const egressProfileSummary = egressProfileResolved
    ? {
        name: egressProfileResolved.name,
        region: egressProfileResolved.region,
        proxy_configured: egressProfileResolved.proxy_configured,
        proxy_url_redacted: egressProfileResolved.proxy_url_redacted,
        egress_profile_identity_hash: egressProfileResolved.egress_profile_identity_hash,
      }
    : null;

  // Build the argv deterministically before any I/O so dry-run and
  // live-run paths share the exact same flags.
  const argv = buildDockerRunArgv({
    repoRoot: checkoutSrcRoot,
    workDir,
    imageTag,
    command: normalizedCommand,
    allowNetwork: normalizedAllowNetwork,
    repoMountMode: normalizedMountMode,
    egressProfile: egressProfileResolved,
  });
  const commandHash = sha256Hex(JSON.stringify(normalizedCommand));
  const replayCommandHash = normalizedInputCommand
    ? sha256Hex(JSON.stringify(normalizedInputCommand))
    : null;
  const argvHash = sha256Hex(JSON.stringify(argv.args));
  const runsDir = repoRunsDir(domain);
  const stdoutPath = path.join(runsDir, `${runId}.stdout`);
  const stderrPath = path.join(runsDir, `${runId}.stderr`);
  if (normalizedCheckout && normalizedCheckout.kind === "self_patch") {
    assertRepoWorkDirBoundary(workDir, sessionRoot);
  }
  const checkoutPatchHash = normalizedCheckout && normalizedCheckout.kind === "self_patch"
    ? hashSelfPatchFile(workDir, sessionRoot)
    : null;
  if (normalizedCheckout && normalizedCheckout.kind === "self_patch" && !checkoutPatchHash) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "self_patch checkout requires /work/patch.diff before bob_repo_docker_run",
      { repo_error_code: "missing_differential_patch" },
    );
  }
  const startedAt = new Date().toISOString();

  // Network mode is the value we'd hand to docker --network. We capture
  // it in the JSONL row so a reviewer can confirm the mode at-a-glance.
  const networkMode = normalizedAllowNetwork ? "bridge" : "none";

  // Phase 1: persist the plan. dry_run records a plan row and returns.
  if (normalizedDryRun) {
    const planRow = {
      version: REPO_DOCKER_RUN_VERSION,
      run_id: runId,
      target_domain: domain,
      dry_run: true,
      command_hash: commandHash,
      argv_hash: argvHash,
      network_mode: networkMode,
      mount_mode: normalizedMountMode,
      work_mount_mode: REPO_WORK_MOUNT_MODE,
      image_tag: imageTag,
      timeout_ms: normalizedTimeoutMs,
      planned_at: startedAt,
      planned_argv: argv.args,
      egress_profile: egressProfileSummary,
    };
    if (replayCommandHash) planRow.replay_command_hash = replayCommandHash;
    if (normalizedCheckout) {
      planRow.checkout_ref = normalizedCheckout.ref;
      planRow.checkout_kind = normalizedCheckout.kind;
      if (normalizedCheckout.kind === "self_patch") {
        planRow.checkout_patch_hash = checkoutPatchHash;
      }
      if (checkoutHistory) {
        planRow.checkout_object = checkoutHistory.checkout_object;
        planRow.checkout_object_format = checkoutHistory.checkout_object_format;
      }
    }
    if (normalizedReplayContext) planRow.replay_context = normalizedReplayContext;
    if (normalizedBlockedHarnessRunId) planRow.blocked_harness_run_id = normalizedBlockedHarnessRunId;
    // O-P7: scrub-validate before persistence. planned_argv carries the
    // command tokens; if a future caller smuggles a token like
    // "Authorization: Bearer ..." the validator catches it.
    validateNoSensitiveMaterial(planRow, "repo_command_runs");
    withSessionLock(domain, () => {
      fs.mkdirSync(runsDir, { recursive: true });
      fs.mkdirSync(workDir, { recursive: true });
      appendJsonlLine(repoCommandRunsJsonlPath(domain), planRow);
    });
    return {
      created: true,
      target_domain: domain,
      run_id: runId,
      dry_run: true,
      image_tag: imageTag,
      network_mode: networkMode,
      mount_mode: normalizedMountMode,
      work_mount_mode: REPO_WORK_MOUNT_MODE,
      command_hash: commandHash,
      replay_command_hash: replayCommandHash,
      argv_hash: argvHash,
      planned_argv: argv.args,
      stdout_path: null,
      stderr_path: null,
      stdout_hash: null,
      stderr_hash: null,
      exit_code: null,
      duration_ms: null,
      timed_out: false,
      egress_profile: egressProfileSummary,
      replay_context: normalizedReplayContext,
      blocked_harness_run_id: normalizedBlockedHarnessRunId,
      ...(normalizedCheckout ? {
        checkout_ref: normalizedCheckout.ref,
        checkout_kind: normalizedCheckout.kind,
        ...(checkoutHistory ? {
          checkout_object: checkoutHistory.checkout_object,
          checkout_object_format: checkoutHistory.checkout_object_format,
        } : {}),
        ...(normalizedCheckout.kind === "self_patch" ? { checkout_patch_hash: checkoutPatchHash } : {}),
      } : {}),
    };
  }

  // Live mode: ensure docker is available, prepare capture files, exec
  // via the runtime, hash the captures, then persist the JSONL row.
  const runtimeImpl = runtime || defaultDockerRuntime();
  const dockerAvailable = await dockerCliAvailable(runtimeImpl);
  if (!dockerAvailable) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "docker is not installed or not in PATH; rerun with dry_run: true",
      { repo_error_code: "docker_unavailable" },
    );
  }
  if (normalizedCheckout) {
    await materializeDifferentialCheckoutTree({
      repoRoot,
      checkoutRoot,
      workDir,
      sessionRoot,
      runId,
      checkoutRef: normalizedCheckout.ref,
      checkoutObject: checkoutHistory && checkoutHistory.checkout_object,
      checkoutKind: normalizedCheckout.kind,
      expectedPatchHash: checkoutPatchHash,
    });
  }
  withSessionLock(domain, () => {
    fs.mkdirSync(runsDir, { recursive: true });
    fs.mkdirSync(workDir, { recursive: true });
    // Touch the capture files so the runtime always writes to a path
    // owned by the session (avoids races where a stub runtime returns
    // without creating the file).
    fs.writeFileSync(stdoutPath, "");
    fs.writeFileSync(stderrPath, "");
  });
  let runResult;
  try {
    runResult = await runtimeImpl.run({
      command: argv.command,
      args: argv.args,
      timeoutMs: normalizedTimeoutMs,
      stdoutPath,
      stderrPath,
    });
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `docker run failed to start: ${error.message || error}`,
      { repo_error_code: "docker_run_spawn_failed", run_id: runId },
    );
  }
  if (!runResult || typeof runResult !== "object") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "runtime.run must return a result object",
      { repo_error_code: "docker_run_runtime_invalid" },
    );
  }
  const exitCode = typeof runResult.exit_code === "number" ? runResult.exit_code : null;
  const signal = typeof runResult.signal === "string" ? runResult.signal : null;
  const durationMs = typeof runResult.duration_ms === "number" ? runResult.duration_ms : null;
  const timedOut = runResult.timed_out === true;
  const stdoutBytes = typeof runResult.stdout_bytes === "number" ? runResult.stdout_bytes : 0;
  const stderrBytes = typeof runResult.stderr_bytes === "number" ? runResult.stderr_bytes : 0;
  const stdoutTruncated = runResult.stdout_truncated === true;
  const stderrTruncated = runResult.stderr_truncated === true;
  const stdoutHash = hashFile(stdoutPath);
  const stderrHash = hashFile(stderrPath);
  const stdoutFirstLine = readFirstLine(stdoutPath, REPO_DOCKER_RUN_FIRST_LINE_MAX_CHARS);
  const stderrFirstLine = readFirstLine(stderrPath, REPO_DOCKER_RUN_FIRST_LINE_MAX_CHARS);
  const completedAt = new Date().toISOString();

  const liveRow = {
    version: REPO_DOCKER_RUN_VERSION,
    run_id: runId,
    target_domain: domain,
    dry_run: false,
    command_hash: commandHash,
    argv_hash: argvHash,
    network_mode: networkMode,
    mount_mode: normalizedMountMode,
    work_mount_mode: REPO_WORK_MOUNT_MODE,
    image_tag: imageTag,
    timeout_ms: normalizedTimeoutMs,
    started_at: startedAt,
    completed_at: completedAt,
    exit_code: exitCode,
    signal,
    duration_ms: durationMs,
    timed_out: timedOut,
    stdout_path: stdoutPath,
    stderr_path: stderrPath,
    stdout_bytes: stdoutBytes,
    stderr_bytes: stderrBytes,
    stdout_truncated: stdoutTruncated,
    stderr_truncated: stderrTruncated,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    // Plane X Cycle X.7 (X-P9 retrofit): distilled summary fields.
    // stdout/stderr capture files stay on disk (path + hash unchanged
    // so the C.7 5-hash binding is preserved); the JSONL record becomes
    // the brief-inlinable form via these scalars. Per X-P9 the bounds
    // are structural (200-char first-line, integer counters) so the
    // 2KB hard cap is honored by construction.
    stdout_first_line: stdoutFirstLine,
    stderr_first_line: stderrFirstLine,
    stdout_size_bytes: stdoutBytes,
    stderr_size_bytes: stderrBytes,
    egress_profile: egressProfileSummary,
  };
  if (replayCommandHash) liveRow.replay_command_hash = replayCommandHash;
  if (normalizedCheckout) {
    liveRow.checkout_ref = normalizedCheckout.ref;
    liveRow.checkout_kind = normalizedCheckout.kind;
    if (checkoutHistory) {
      liveRow.checkout_object = checkoutHistory.checkout_object;
      liveRow.checkout_object_format = checkoutHistory.checkout_object_format;
    }
    if (normalizedCheckout.kind === "self_patch") {
      liveRow.checkout_patch_hash = checkoutPatchHash;
    }
  }
  if (normalizedReplayContext) liveRow.replay_context = normalizedReplayContext;
  if (normalizedBlockedHarnessRunId) liveRow.blocked_harness_run_id = normalizedBlockedHarnessRunId;
  // O-P7: pre-flight before persistence. The validator catches both the
  // forbidden key shape (e.g. a stray "authorization" sub-field) and
  // value shape (e.g. a JWT-shaped path). Raw stdout/stderr never lands
  // here — only the path + hash — so the regression is purely guarding
  // against future producer slips.
  validateNoSensitiveMaterial(liveRow, "repo_command_runs");
  withSessionLock(domain, () => {
    appendJsonlLine(repoCommandRunsJsonlPath(domain), liveRow);
  });

  return {
    created: true,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    image_tag: imageTag,
    network_mode: networkMode,
    mount_mode: normalizedMountMode,
    work_mount_mode: REPO_WORK_MOUNT_MODE,
    command_hash: commandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: argvHash,
    planned_argv: argv.args,
    stdout_path: stdoutPath,
    stderr_path: stderrPath,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    stdout_bytes: stdoutBytes,
    stderr_bytes: stderrBytes,
    stdout_size_bytes: stdoutBytes,
    stderr_size_bytes: stderrBytes,
    stdout_first_line: stdoutFirstLine,
    stderr_first_line: stderrFirstLine,
    stdout_truncated: stdoutTruncated,
    stderr_truncated: stderrTruncated,
    exit_code: exitCode,
    signal,
    duration_ms: durationMs,
    timed_out: timedOut,
    egress_profile: egressProfileSummary,
    replay_context: normalizedReplayContext,
    blocked_harness_run_id: normalizedBlockedHarnessRunId,
    ...(normalizedCheckout ? {
      checkout_ref: normalizedCheckout.ref,
      checkout_kind: normalizedCheckout.kind,
      ...(checkoutHistory ? {
        checkout_object: checkoutHistory.checkout_object,
        checkout_object_format: checkoutHistory.checkout_object_format,
      } : {}),
      ...(normalizedCheckout.kind === "self_patch" ? { checkout_patch_hash: checkoutPatchHash } : {}),
    } : {}),
  };
}

module.exports = {
  // Public API
  prepareRepoEnv,
  repoDockerRun,
  // Helpers exposed for cross-module reuse / tests
  buildDockerfileBob,
  buildDockerBuildArgv,
  buildDifferentialCheckoutCommand,
  buildDockerRunArgv,
  buildImageTag,
  runScopedHostPath,
  detectLanguageProfile,
  recommendedCommandsFor,
  loadSeedCorpus,
  loadSeedCorpusCount,
  assertNoEnvSecretLeak,
  dockerfileBobPath,
  readFirstLine,
  repoEnvJsonPath,
  loadNfsXdrShape,
  // Constants
  DEFAULT_DOCKER_BUILD_TIMEOUT_MS,
  DIFFERENTIAL_CHECKOUT_KIND_VALUES,
  DIFFERENTIAL_MATERIALIZER_TIMEOUT_MS,
  MAX_DOCKER_BUILD_TIMEOUT_MS,
  RECOMMENDED_COMMAND_ROLES,
  REPO_DOCKER_RUN_DEFAULT_TIMEOUT_MS,
  REPO_DOCKER_RUN_FIRST_LINE_MAX_CHARS,
  REPO_DOCKER_RUN_MAX_OUTPUT_BYTES,
  REPO_DOCKER_RUN_MAX_TIMEOUT_MS,
  REPO_DOCKER_RUN_VERSION,
  REPO_ENV_VERSION,
  REPO_MOUNT_MODE_VALUES,
  C_DEFAULT_APT_PACKAGES,
  NFS_EXTRA_APT_PACKAGES,
  ENV_SECRET_LEAK_RE,
};

// Quiet imports for parity with sibling repo-target.js. These are kept so
// future expansions (e.g., normalizing operator-provided base_image text)
// don't need to re-import.
// eslint-disable-next-line no-unused-vars
const _unusedNormalizeOptionalText = normalizeOptionalText;

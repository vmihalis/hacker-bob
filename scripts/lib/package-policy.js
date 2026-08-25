"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

// Single source of truth for the npm pack-size tripwire. Imported by BOTH
// test/package.test.js and scripts/release-check.js so the ceiling cannot drift
// between them (no duplicated magic number). The 921 KB docs/hacker-bob-social.png is
// excluded from the pack (EXCLUDED_CANONICAL_PACKAGE_FILES). On this (core) line the lean
// pack is larger than the public line because core ships the full
// offensive arsenal (XSS/IDOR/CORS/OOB/nuclei producers + tools, ed25519/keyed-ledger MAC)
// and the offensive-sandbox isolation arc (attestation + verdict gate + sc-container-exec +
// the seven SC container runners) the public line does not. The provider-neutral physical
// contract runtime plus the provider-neutral nested Plane-PH packages are kept within the ceiling
// by excluding internal competitive analysis, roadmap authoring/review workbooks, and unreferenced
// documentation screenshots along with the social-preview asset. The deliberate 3.70 MB ceiling
// still fires early on a surprising regression (a re-added asset or vendored dependency). Bump it
// deliberately (and only here) when a real runtime growth stream warrants it.
// The 2026-07 Plane-PH transaction ledger added the broker-owned durable store,
// compatibility alias, and intrinsic-poisoning defenses while retaining one
// implementation in the tarball; that reviewed runtime growth warrants this
// 50 KB increment and leaves less than 1.4% headroom.
//
// Raised to 3.85 MB for the install drift guard. Two things forced this, and the
// docs were NOT one of them -- both engineering surveys written for that work
// (docs/install-ownership.md 43,213 B and docs/report-md-format-facts.md 31,443 B)
// are denied pack budget in EXCLUDED_CANONICAL_PACKAGE_FILES below rather than
// shipped. Excluding them was measured, not assumed: it recovers only 24,723
// compressed bytes, because ~75 KB of markdown gzips roughly 3x. What remains is:
//   1. A PRE-EXISTING breach. The tarball was already 3,734,856 B at the branch
//      point -- 34,856 B over the old 3.70 MB ceiling before this branch added a
//      single byte, so `npm run test:package` was already red on main. The ceiling
//      had been outgrown by earlier merges and the tripwire went unaddressed.
//   2. Genuine shipped runtime growth: scripts/lib/install-drift.js (the guard
//      itself, 27,458 B) plus the report-format contract, which by design is
//      replicated into all four role surfaces it governs -- .claude/agents/
//      report-writer.md, prompts/roles/reporter.md, and the codex and kimi
//      bob-evaluate SKILL.md bundles -- at 17,911 B each.
// Post-exclusion the lean tarball measured 3,795,479 B, so 3.85 MB left ~54 KB
// (1.4%) of headroom. The authority-unit-of-work, exclusive storage receipts,
// repo-host boundary, belief contract compiler, validity/lease kernel, and web
// instrument plane are all shipped runtime rather than authoring artifacts. With
// those surfaces present the measured lean tarball is 3,920,688 B. A deliberate
// 4.00 MB ceiling retains ~79 KB (2.0%) of headroom while still catching a
// re-added asset or vendored dependency.
const CANONICAL_PACKAGE_MAX_BYTES = 4_000_000;

// Explicit deny-by-default manifest for the JavaScript files installed at the
// top level of mcp/. It is shared by install, doctor, and package tests so the
// static lifecycle diagnostic is bound to the same shipping contract as the
// installer rather than a second list that can drift.
const MCP_TOP_LEVEL_RUNTIME_FILES = Object.freeze([
  "server.js",
  "auto-signup.js",
  "redaction.js",
  "browser-driver.js",
  "finalization-receipt.js",
  "finding-artifact.js",
  "projection-client.js",
  "projection-payload.js",
]);

const WRAPPER_PACKAGE_SPECS = Object.freeze([
  Object.freeze({
    name: "hacker-bob-cc",
    relativeRoot: path.join("packages", "hacker-bob-cc"),
    bin: "bin/hacker-bob-cc.js",
    adapter: "claude",
    label: "Claude Code wrapper",
  }),
  Object.freeze({
    name: "hacker-bob-codex",
    relativeRoot: path.join("packages", "hacker-bob-codex"),
    bin: "bin/hacker-bob-codex.js",
    adapter: "codex",
    label: "Codex wrapper",
  }),
  Object.freeze({
    name: "hacker-bob-kimi",
    relativeRoot: path.join("packages", "hacker-bob-kimi"),
    bin: "bin/hacker-bob-kimi.js",
    adapter: "kimi",
    label: "Kimi CLI wrapper",
  }),
]);

// Plane-PH core and pure qualification-contract packages are deliberately
// nested under canonical Bob. Legacy packages may still resolve root-owned MCP
// compatibility surfaces; the signed worker closure instead follows declared
// package exports and dependencies. Only package metadata, declared root
// entrypoints, and flat lib/*.js runtime source are admitted; tests, fixtures,
// node_modules, and unrelated workspaces remain excluded.
const CANONICAL_RUNTIME_PACKAGE_ROOTS = Object.freeze([
  "packages/bob-artifact-vault",
  "packages/bob-instrument-broker",
  "packages/bob-instrument-contracts",
  "packages/bob-instrument-chameleon",
  "packages/bob-instrument-chameleon-worker-runtime",
  "packages/bob-instrument-deterministic",
  "packages/bob-instrument-native-prebuild-trust",
  "packages/bob-instrument-principal-acl-darwin",
]);
const CANONICAL_RUNTIME_OWNED_ROOTS = Object.freeze([
  "mcp",
  ...CANONICAL_RUNTIME_PACKAGE_ROOTS,
]);
const CANONICAL_RUNTIME_PACKAGE_ROOT_SET = new Set(CANONICAL_RUNTIME_PACKAGE_ROOTS);
const CANONICAL_RUNTIME_ROOT_ENTRYPOINTS = new Set([
  "packages/bob-artifact-vault/index.js",
  "packages/bob-artifact-vault/worker.js",
  "packages/bob-artifact-vault/operator.js",
]);

function isCanonicalRuntimePackageFile(file) {
  if (typeof file !== "string") return false;
  const segments = file.split("/");
  if (segments.length < 3) return false;
  const root = segments.slice(0, 2).join("/");
  if (!CANONICAL_RUNTIME_PACKAGE_ROOT_SET.has(root)) return false;
  const relative = segments.slice(2).join("/");
  return relative === "package.json"
    || CANONICAL_RUNTIME_ROOT_ENTRYPOINTS.has(file)
    || /^lib\/[^/]+\.js$/.test(relative);
}

const LOCAL_INSTALL_METADATA_FILES = new Set([
  ".hacker-bob/VERSION",
  ".hacker-bob/install.json",
  ".claude/bob/VERSION",
  ".claude/bob/install.json",
  ".claude/bob/egress-profiles.json",
  ".kimi/bob/VERSION",
  ".kimi/bob/install.json",
  // Operator-local Claude Code session overrides; excluded from package.json's
  // files glob (only settings.json ships) so npm pack never includes it. The
  // expectedCanonicalFiles walker should not require it either.
  ".claude/settings.local.json",
  // Cron scheduler runtime lock file. Present only while a Claude Code session
  // owns scheduled jobs; never persisted to disk by the installer.
  ".claude/scheduled_tasks.lock",
]);

const REQUIRED_SUPPORT_SURFACES = Object.freeze([
  ".hacker-bob/knowledge/evaluator-techniques.json",
  ".hacker-bob/bypass-tables/graphql.txt",
  ".hacker-bob/bypass-tables/oauth-oidc.txt",
  "bin/hacker-bob.js",
  "mcp/server.js",
  "mcp/core/bob-export.js",
  "mcp/domains/repo/cve-feed-parser.js",
  "mcp/domains/repo/cve-scope-matcher.js",
  "mcp/core/egress-profiles.js",
  "mcp/core/update-check.js",
  "docs/provider-authoring.md",
  "prompts/playbooks/C2_doc_vs_behavior.md",
  "prompts/playbooks/C4_multi_account_differential.md",
  "testing/policy-replay/replay.mjs",
  "testing/policy-replay/tune.mjs",
  "testing/policy-replay/bench.mjs",
  "testing/policy-replay/cases/sample-evaluator-refusal.json",
  "testing/policy-replay/prompts/00-baseline.md",
  "testing/policy-replay/prompts/01-scope-anchor.md",
]);

// Operator-facing support files that must survive the project-local install,
// not merely exist beside the npm package. Source and destination are explicit
// so lifecycle ownership never expands to an operator's whole docs/ tree.
const CANONICAL_INSTALL_SUPPORT_FILES = Object.freeze([
  Object.freeze({
    id: "finding_artifact_schema",
    source: "infra/aws/hacker-bob-stack/finding-artifact.schema.json",
    destination: "infra/aws/hacker-bob-stack/finding-artifact.schema.json",
  }),
  Object.freeze({
    id: "physical_provider_authoring",
    source: "docs/provider-authoring.md",
    destination: ".hacker-bob/docs/provider-authoring.md",
  }),
]);

const STALE_HOOK_SCRIPT_NAMES = Object.freeze([
  "bob-update-lib.js",
  "scope-guard.sh",
  "scope-guard-mcp.sh",
]);

// Native/provider implementation packages are distributed only through the
// explicit optional-provider lifecycle. Canonical Bob ships provider-neutral
// core plus pure trust/principal contract sources; it never vendors a worker,
// native source tree, fixture executable, or unsigned prebuild.
const OPTIONAL_PROVIDER_EXCLUDED_PACKAGE_ROOTS = Object.freeze([
  "packages/bob-instrument-chameleon-worker",
  "packages/bob-instrument-chameleon-native-darwin",
  "packages/bob-instrument-native-darwin",
  "packages/bob-instrument-trusted-clock-native-darwin",
  "packages/bob-instrument-native-prebuild-darwin-arm64",
  "packages/bob-instrument-launcher-native-darwin",
  "packages/bob-instrument-safety-native-darwin",
  "packages/bob-lifecycle-custodian-native-darwin",
]);

const EXCLUDED_CANONICAL_PACKAGE_FILES = Object.freeze([
  ...STALE_HOOK_SCRIPT_NAMES.map((name) => `.claude/hooks/${name}`),
  // Internal analysis is useful in the source tree but is not runtime or end-user package
  // documentation. README presentation media remains available in the source repository and on
  // GitHub, but is not runtime material and must not consume canonical-package budget. The offline
  // guide is retained in the source tree as an explicitly labelled v1.3.5/pre-v2 historical
  // snapshot, but does not describe the installed v2 runtime.
  "docs/COMPETITOR_ANALYSIS.md",
  "docs/COMPETITOR_ANALYSIS_APPENDIX.md",
  "docs/LLM_AGENT_SECURITY_LANDSCAPE_2026.md",
  "docs/ISSUE_111_SURFACE_BINDING_PLAN.md",
  // Engineering surveys written while building the install ownership/drift guard and the
  // report.md format contract. They record how the in-tree copy families and report layer
  // were mapped; they are development artifacts, not runtime or end-user documentation, and
  // nothing in the installed runtime reads them. Kept in the source tree, denied pack budget.
  "docs/install-ownership.md",
  "docs/report-md-format-facts.md",
  "docs/BOB_OSS_BENCHMARK_PLAN.md",
  "docs/hacker-bob-offline-guide.md",
  "docs/bob-architecture-event.html",
  "docs/media/doctor-ok.png",
  "docs/media/evaluate-start.png",
  "docs/media/status-fresh.png",
  "docs/media/hacker-bob-demo.gif",
  "docs/media/hacker-bob-demo.tape",
  "docs/media/hacker-bob-doctor-demo.gif",
  "docs/media/hacker-bob-doctor-demo.tape",
  "docs/media/hacker-bob-receipts-demo.gif",
  "docs/media/hacker-bob-receipts-demo.sh",
  "docs/media/hacker-bob-receipts-demo.tape",
  "docs/media/readme-chapter-deploy.svg",
  "docs/media/readme-chapter-operate.svg",
  "docs/media/readme-chapter-proof.svg",
  "docs/media/readme-community-header.svg",
  "docs/media/readme-contributing-header.svg",
  "docs/media/readme-footer.svg",
  "docs/media/readme-hero.png",
  "docs/media/readme-security-header.svg",
  "docs/media/readme-signal-deck.svg",
  "docs/hacker-bob-offline-guide.pdf",
  // The 921 KB social-preview card is a web/marketing asset (referenced only by the
  // non-packed site/ and GitHub's social-preview, never by the installed runtime). It
  // dominated the tarball at ~27% of pack size; excluding it reclaims the budget headroom
  // the comment in test/package.test.js long flagged as the obvious trim target.
  "docs/hacker-bob-social.png",
  "scripts/authority-inventory.js",
  "scripts/check-plane-physical.js",
  "scripts/replay-refusal.js",
  "scripts/bench-prompts.sh",
  "scripts/replay-prompts/00-baseline.md",
  "scripts/replay-prompts/01-scope-anchor.md",
  "scripts/replay-prompts/README.md",
]);
const EXCLUDED_CANONICAL_PACKAGE_FILE_SET = new Set(EXCLUDED_CANONICAL_PACKAGE_FILES);

const PACKED_TEXT_EXTENSIONS = new Set([
  ".Dockerfile",
  ".css",
  ".html",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".py",
  ".sh",
  ".txt",
]);

const DISALLOWED_PACKED_FILE_PATTERNS = Object.freeze([
  /(^|\/)\.env(?:\.|$)/,
  /(^|\/)[^/]+\.local\.[^/]+$/,
  /(^|\/)[^/]+\.(?:bak|old|orig|tmp)$/,
  /~$/,
  /\.(?:node|dylib|so|a|o)$/,
  /^packages\/(?:bob-instrument-(?:chameleon-worker|chameleon-native-darwin|native-darwin|trusted-clock-native-darwin|native-prebuild-darwin-arm64|launcher-native-darwin|safety-native-darwin)|bob-lifecycle-custodian-native-darwin)\//,
]);

const DISALLOWED_PACKED_TEXT_PATTERNS = Object.freeze([
  /\/Users\/[A-Za-z0-9._-]+/,
  /\/dev\/(?:cu|tty)\.[A-Za-z0-9._-]+/i,
  /\b(?:artifact|vault):v1:[A-Za-z0-9_-]{43}\b/,
  /\bbob-evidence:sha256:[a-f0-9]{64}\b/,
  /\bgate-evidence-replay-receipt:v1:[a-f0-9]{64}\b/,
  /"(?:engineering_evidence_refs|hil_evidence_refs|review_evidence)"\s*:\s*\[\s*(?:"|\{)/,
  /\b(?:card|tag|hf|lf)[ _-]?(?:uid|id)\s*[:=]\s*(?:0x)?[0-9a-f][0-9a-f:\- ]{5,}\b/i,
  /\btrack[ _-]?2\s*[:=]\s*;?[0-9]{12,19}[=dD][0-9]{4,}/i,
]);

function wrapperPackages(root = DEFAULT_ROOT) {
  return Object.freeze(WRAPPER_PACKAGE_SPECS.map((spec) => Object.freeze({
    ...spec,
    root: path.join(root, spec.relativeRoot),
  })));
}

function isInternalRefactorDoc(file) {
  return /^docs\/refactor-[^/]+\.md$/.test(file);
}

// Plane-B is a mutable /goal authoring ledger (including per-node work notes),
// not installed product documentation. Keep its source-tree specification and
// machine state together rather than publishing a partial graph with broken
// detail links.
function isInternalPlaneBeliefRoadmapDoc(file) {
  return file === "docs/causal-belief-hypergraph.md"
    || file.startsWith("docs/plane-belief/");
}

function isInternalPlaneDeltaDetailDoc(file) {
  return /^docs\/plane-delta\/detail\/[^/]+\.md$/.test(file);
}

// The Plane-Delta README is an implementation-order guide and verification/
// contains the adversarial review workbook. The high-level topology and graph
// JSON remain packable support material; these source-only review artifacts do
// not participate in runtime, install, or a declared package surface.
function isInternalPlaneDeltaVerificationDoc(file) {
  return file === "docs/plane-delta/README.md"
    || file.startsWith("docs/plane-delta/verification/");
}

function isInternalPlanePhysicalDoc(file) {
  return file.startsWith("docs/plane-physical/");
}

// This is a deferred CI/OAuth design memo. The installed policy-replay README,
// runners, prompts, and fixture remain shipped support surfaces.
function isInternalPolicyReplayPlanningDoc(file) {
  return file === "testing/policy-replay/LIVE_SMOKE_DESIGN.md";
}

function isInternalRefactorScratch(file) {
  return file === "tmp" || file.startsWith("tmp/");
}

function isPackableScript(file) {
  return /^scripts\/.+\.(?:js|mjs|sh)$/.test(file);
}

function isPackableBin(file) {
  return /^bin\/.+\.js$/.test(file);
}

function isPackableBobResource(file) {
  return /^\.hacker-bob\/bypass-tables\/[^/]+\.txt$/.test(file) ||
    /^\.hacker-bob\/knowledge\/[^/]+\.json$/.test(file);
}

function isPackableMcpRuntimeFile(file) {
  if (typeof file !== "string") return false;
  if (/^mcp\/[^/]+\.js$/.test(file)) return true;
  if (/^mcp\/(?:core|domains|tools|fuzz)\/(?:[^/]+\/)*[^/]+\.js$/.test(file)) return true;
  if (/^mcp\/lib\/[^/]+\.js$/.test(file)) return true;
  return file === "mcp/fuzz/bob-multitu-build.sh"
    || file === "mcp/offensive-image.json";
}

function isPackedTextFile(file) {
  return PACKED_TEXT_EXTENSIONS.has(path.extname(file));
}

function isExcludedCanonicalPackageFile(file) {
  return EXCLUDED_CANONICAL_PACKAGE_FILE_SET.has(file);
}

function sourceTreeFiles(root, relativeDir) {
  const absoluteRoot = path.join(root, relativeDir);
  if (!fs.existsSync(absoluteRoot)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(root, full).split(path.sep).join("/"));
      }
    }
  };
  visit(absoluteRoot);
  return files.sort();
}

function expectedCanonicalFiles(root = DEFAULT_ROOT) {
  return Array.from(new Set([
    "package.json",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "DISCLAIMER.md",
    "SECURITY.md",
    "install.sh",
    ...sourceTreeFiles(root, ".hacker-bob").filter((file) => !LOCAL_INSTALL_METADATA_FILES.has(file)),
    ...sourceTreeFiles(root, ".claude").filter((file) => !LOCAL_INSTALL_METADATA_FILES.has(file)),
    ...sourceTreeFiles(root, "adapters"),
    ...sourceTreeFiles(root, "bin").filter(isPackableBin),
    ...sourceTreeFiles(root, "docs").filter((file) =>
      !isInternalRefactorDoc(file) &&
      !isInternalPlaneBeliefRoadmapDoc(file) &&
      !isInternalPlaneDeltaDetailDoc(file) &&
      !isInternalPlaneDeltaVerificationDoc(file) &&
      !isInternalPlanePhysicalDoc(file)),
    ...sourceTreeFiles(root, "mcp").filter(isPackableMcpRuntimeFile),
    ...CANONICAL_RUNTIME_PACKAGE_ROOTS.flatMap((relativeRoot) => (
      sourceTreeFiles(root, relativeRoot).filter(isCanonicalRuntimePackageFile)
    )),
    ...sourceTreeFiles(root, "prompts"),
    ...sourceTreeFiles(root, "scripts").filter(isPackableScript),
    ...sourceTreeFiles(root, "testing/policy-replay")
      .filter((file) => !isInternalPolicyReplayPlanningDoc(file)),
  ])).filter((file) => !isExcludedCanonicalPackageFile(file)).sort();
}

function canonicalInstalledRuntimeFiles(root = DEFAULT_ROOT) {
  return Object.freeze(Array.from(new Set([
    ...MCP_TOP_LEVEL_RUNTIME_FILES.map((name) => `mcp/${name}`),
    ...sourceTreeFiles(root, "mcp").filter(isPackableMcpRuntimeFile),
    ...CANONICAL_RUNTIME_PACKAGE_ROOTS.flatMap((relativeRoot) => (
      sourceTreeFiles(root, relativeRoot).filter(isCanonicalRuntimePackageFile)
    )),
  ])).sort());
}

module.exports = {
  CANONICAL_INSTALL_SUPPORT_FILES,
  CANONICAL_RUNTIME_OWNED_ROOTS,
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
  CANONICAL_PACKAGE_MAX_BYTES,
  DISALLOWED_PACKED_FILE_PATTERNS,
  DISALLOWED_PACKED_TEXT_PATTERNS,
  EXCLUDED_CANONICAL_PACKAGE_FILES,
  LOCAL_INSTALL_METADATA_FILES,
  MCP_TOP_LEVEL_RUNTIME_FILES,
  OPTIONAL_PROVIDER_EXCLUDED_PACKAGE_ROOTS,
  PACKED_TEXT_EXTENSIONS,
  REQUIRED_SUPPORT_SURFACES,
  STALE_HOOK_SCRIPT_NAMES,
  WRAPPER_PACKAGE_SPECS,
  canonicalInstalledRuntimeFiles,
  expectedCanonicalFiles,
  isCanonicalRuntimePackageFile,
  isInternalRefactorScratch,
  isInternalRefactorDoc,
  isInternalPlaneBeliefRoadmapDoc,
  isInternalPlaneDeltaDetailDoc,
  isInternalPlaneDeltaVerificationDoc,
  isInternalPlanePhysicalDoc,
  isInternalPolicyReplayPlanningDoc,
  isExcludedCanonicalPackageFile,
  isPackableBin,
  isPackableBobResource,
  isPackableMcpRuntimeFile,
  isPackableScript,
  isPackedTextFile,
  sourceTreeFiles,
  wrapperPackages,
};

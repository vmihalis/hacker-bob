"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

// Single source of truth for the npm pack-size tripwire. Imported by BOTH
// test/package.test.js and scripts/release-check.js so the ceiling cannot drift
// between them (no duplicated magic number). The 921 KB docs/hacker-bob-social.png is
// excluded from the pack (EXCLUDED_CANONICAL_PACKAGE_FILES). On this (core) line the lean
// pack measures ~2.96 MB — larger than the public line because core ships the full
// offensive arsenal (XSS/IDOR/CORS/OOB/nuclei producers + tools, ed25519/keyed-ledger MAC)
// and the offensive-sandbox isolation arc (attestation + verdict gate + sc-container-exec +
// the seven SC container runners) the public line does not. This snug 3.2 MB ceiling keeps
// ~240 KB of operating headroom — enough to absorb the ~3 KB pack-size non-determinism plus
// a couple PRs of normal source growth, while still firing early on a surprising regression
// (a re-added asset, a vendored dep). Bump it deliberately (and only here) when a real
// growth stream warrants it.
const CANONICAL_PACKAGE_MAX_BYTES = 3_200_000;

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
  "mcp/lib/bob-export.js",
  "mcp/lib/cve-feed-parser.js",
  "mcp/lib/cve-scope-matcher.js",
  "mcp/lib/egress-profiles.js",
  "mcp/lib/update-check.js",
  "prompts/playbooks/C2_doc_vs_behavior.md",
  "prompts/playbooks/C4_multi_account_differential.md",
  "testing/policy-replay/replay.mjs",
  "testing/policy-replay/tune.mjs",
  "testing/policy-replay/bench.mjs",
  "testing/policy-replay/cases/sample-evaluator-refusal.json",
  "testing/policy-replay/prompts/00-baseline.md",
  "testing/policy-replay/prompts/01-scope-anchor.md",
]);

const STALE_HOOK_SCRIPT_NAMES = Object.freeze([
  "bob-update-lib.js",
  "scope-guard.sh",
  "scope-guard-mcp.sh",
]);

const EXCLUDED_CANONICAL_PACKAGE_FILES = Object.freeze([
  ...STALE_HOOK_SCRIPT_NAMES.map((name) => `.claude/hooks/${name}`),
  "docs/hacker-bob-offline-guide.pdf",
  // The 921 KB social-preview card is a web/marketing asset (referenced only by the
  // non-packed site/ and GitHub's social-preview, never by the installed runtime). It
  // dominated the tarball at ~27% of pack size; excluding it reclaims the budget headroom
  // the comment in test/package.test.js long flagged as the obvious trim target.
  "docs/hacker-bob-social.png",
  "scripts/authority-inventory.js",
  "scripts/replay-refusal.js",
  "scripts/bench-prompts.sh",
  "scripts/replay-prompts/00-baseline.md",
  "scripts/replay-prompts/01-scope-anchor.md",
  "scripts/replay-prompts/README.md",
]);
const EXCLUDED_CANONICAL_PACKAGE_FILE_SET = new Set(EXCLUDED_CANONICAL_PACKAGE_FILES);

const PACKED_TEXT_EXTENSIONS = new Set([
  ".css",
  ".html",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".sh",
  ".txt",
]);

const DISALLOWED_PACKED_FILE_PATTERNS = Object.freeze([
  /(^|\/)\.env(?:\.|$)/,
  /(^|\/)[^/]+\.local\.[^/]+$/,
  /(^|\/)[^/]+\.(?:bak|old|orig|tmp)$/,
  /~$/,
]);

const DISALLOWED_PACKED_TEXT_PATTERNS = Object.freeze([
  /\/Users\/[A-Za-z0-9._-]+/,
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

function isInternalPlaneDeltaDetailDoc(file) {
  return /^docs\/plane-delta\/detail\/[^/]+\.md$/.test(file);
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
    ...sourceTreeFiles(root, "docs").filter((file) => !isInternalRefactorDoc(file) && !isInternalPlaneDeltaDetailDoc(file)),
    ...sourceTreeFiles(root, "mcp").filter((file) => !file.startsWith("mcp/node_modules/")),
    ...sourceTreeFiles(root, "prompts"),
    ...sourceTreeFiles(root, "scripts").filter(isPackableScript),
    ...sourceTreeFiles(root, "testing/policy-replay"),
  ])).filter((file) => !isExcludedCanonicalPackageFile(file)).sort();
}

module.exports = {
  CANONICAL_PACKAGE_MAX_BYTES,
  DISALLOWED_PACKED_FILE_PATTERNS,
  DISALLOWED_PACKED_TEXT_PATTERNS,
  EXCLUDED_CANONICAL_PACKAGE_FILES,
  LOCAL_INSTALL_METADATA_FILES,
  PACKED_TEXT_EXTENSIONS,
  REQUIRED_SUPPORT_SURFACES,
  STALE_HOOK_SCRIPT_NAMES,
  WRAPPER_PACKAGE_SPECS,
  expectedCanonicalFiles,
  isInternalRefactorScratch,
  isInternalRefactorDoc,
  isInternalPlaneDeltaDetailDoc,
  isExcludedCanonicalPackageFile,
  isPackableBin,
  isPackableBobResource,
  isPackableScript,
  isPackedTextFile,
  sourceTreeFiles,
  wrapperPackages,
};

"use strict";
// Y-P13 (T4) GROUND-TRUTH closure leg. Independently derives the set of
// wrapWriteTool callers that ACTUALLY write an audit-graded artifact, and
// asserts it equals AUDIT_GRADED_WRITER_TOOLS.
//
// This is the leg that makes the whitelist NON-tautological. The FLAG↔WHITELIST
// bijection in _write-base.js only proves the whitelist agrees with itself (a
// spec that sets the flag). It does NOT prove the whitelist equals the set of
// composers that actually emit an isAuditGradedPath() path. A future
// wrapWriteTool caller that writes report.md but forgets BOTH the flag and the
// whitelist entry is invisible to the bijection — that is exactly the I2 class.
//
// GROUND TRUTH used here: each tool spec self-declares `session_artifacts_written`
// — the literal artifact basenames it writes. That manifest is authored
// independently of the `writes_audit_graded` flag and the whitelist, so
// classifying those declared artifacts through isAuditGradedPath() yields a
// writer set derived from a DIFFERENT source than the flag. A new composer that
// declares `report.md` in its manifest but forgets the flag+whitelist is caught:
// its declared artifact classifies audit-graded, so it joins the ground-truth
// set, so `missing` is non-empty, so this guard fails.
//
// Scope: wrapWriteTool callers only — the whitelist is the wrapWriteTool
// composer whitelist. Tools that emit pipeline events without wrapping a
// write composer are a separate surface and out of this registry's closure
// guarantee.

const fs = require("fs");
const path = require("path");
const { AUDIT_GRADED_WRITER_TOOLS, isAuditGradedPath, sessionDir } = require("../mcp/lib/paths.js");

const TOOLS_DIR = path.resolve(__dirname, "../mcp/lib/tools");
const PROBE_DOMAIN = "example.com";

// session_artifacts_written entries use placeholder tokens for per-wave/agent
// files (handoff-wN-aN.json) and indexed assignments (wave-N-assignments.json).
// Normalize them to a concrete instance so isAuditGradedPath's filename pattern
// (^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.(json|md)$) matches.
function normalizeArtifact(artifact) {
  return artifact
    .replace(/wN/g, "w1")
    .replace(/aN/g, "a3")
    .replace(/-N-/g, "-1-");
}

function declaredArtifactIsAuditGraded(artifact) {
  // Directory-style declarations (trailing slash) and templated contract paths
  // (e.g. "contracts/<chain_id>/...") are classified by their normalized
  // session-relative form.
  const normalized = normalizeArtifact(artifact).replace(/\/$/, "");
  const abs = path.join(sessionDir(PROBE_DOMAIN), normalized);
  return isAuditGradedPath(abs, PROBE_DOMAIN);
}

// Enumerate every wrapWriteTool caller, loading its (side-effect-free) spec to
// read the authoritative session_artifacts_written manifest. Loading a writer
// module only constructs the spec object; no handler runs.
function enumerateWriters() {
  const out = [];
  for (const f of fs.readdirSync(TOOLS_DIR)) {
    if (!f.endsWith(".js") || f.startsWith("_")) continue;
    const file = path.join(TOOLS_DIR, f);
    const src = fs.readFileSync(file, "utf8");
    if (!/wrapWriteTool\s*\(/.test(src)) continue;
    const spec = require(file);
    if (!spec || typeof spec.name !== "string") continue;
    const artifacts = Array.isArray(spec.session_artifacts_written)
      ? spec.session_artifacts_written
      : [];
    out.push({ name: spec.name, artifacts });
  }
  return out;
}

function main() {
  const writers = enumerateWriters();
  for (const w of writers) {
    if (w.artifacts.length === 0) {
      throw new Error(
        `ground-truth derivation: wrapWriteTool caller '${w.name}' declares an empty ` +
        `session_artifacts_written manifest — cannot classify it independently`,
      );
    }
  }

  const groundTruth = writers
    .filter((w) => w.artifacts.some(declaredArtifactIsAuditGraded))
    .map((w) => w.name)
    .sort();
  const whitelist = [...AUDIT_GRADED_WRITER_TOOLS].sort();

  // writes audit-graded but NOT whitelisted (the I2 class):
  const missing = groundTruth.filter((n) => !whitelist.includes(n));
  // whitelisted but no declared audit-graded artifact found:
  const extra = whitelist.filter((n) => !groundTruth.includes(n));

  if (missing.length || extra.length) {
    throw new Error(
      `Y-P13 ground-truth closure violation: ` +
      `audit-graded-writers-not-whitelisted=[${missing.join(",")}] ` +
      `whitelisted-with-no-audit-graded-write=[${extra.join(",")}]`,
    );
  }
  console.log(`Y-P13 ground-truth closure OK: ${groundTruth.length} writers anchored`);
}

main();

#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const {
  REGISTRY, TAG_GRAMMAR, ALLOWLIST_UNDOCUMENTED, SELF_FILES,
  knownTags, enforcingSites,
} = require("../mcp/core/invariant-registry.js");

// Files that legitimately embed every REGISTRY key as a string (the registry
// itself, this driver, and the test). They are excluded from the tag-scan to
// avoid a self-reference loop. SELF_FILES is owned by the registry module so
// the registry, driver, and test agree on exactly one list.
const SELF = new Set(SELF_FILES);

function trackedFiles() {
  const out = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" });
  return out.split("\n").map((s) => s.trim()).filter(Boolean)
    .filter((f) => !f.startsWith("node_modules/") && !f.endsWith(".min.js"))
    .filter((f) => /\.(js|md|sh|json|ts)$/.test(f));
}

function scannableFiles() {
  return trackedFiles().filter((f) => !SELF.has(f));
}

function extractTags(text) {
  const found = new Set();
  for (const re of TAG_GRAMMAR.uniquePatterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) found.add(m[0]);
  }
  // S/C/I only in anchored comment form; capture group 1 is the tag.
  const sci = TAG_GRAMMAR.sciCommentPattern;
  sci.lastIndex = 0;
  let m;
  while ((m = sci.exec(text)) !== null) found.add(m[1]);
  return found;
}

function scanTree() {
  const byTag = new Map(); // tag -> Set(file)
  for (const f of scannableFiles()) {
    let text;
    try { text = fs.readFileSync(path.join(ROOT, f), "utf8"); } catch { continue; }
    for (const tag of extractTags(text)) {
      if (!byTag.has(tag)) byTag.set(tag, new Set());
      byTag.get(tag).add(f);
    }
  }
  return byTag;
}

function fileHasSymbol(file, symbol) {
  let text;
  try { text = fs.readFileSync(path.join(ROOT, file), "utf8"); } catch { return false; }
  return text.includes(symbol);
}

// Prove SELF_FILES is COMPLETE. Every file (other than SELF_FILES) that
// contains a registry key as a verbatim string would mask orphans if it were
// unlisted — so a registry key appearing as a bare string OUTSIDE its expected
// tag form in an unlisted file is suspicious. The concrete, decidable check: no
// tracked file OUTSIDE SELF_FILES may contain ALL of the registry's keys as
// substrings (only the registry/driver/test enumerate the full key set). If one
// did, it is an un-listed mirror of the registry and must be added to
// SELF_FILES. This catches an incomplete SELF_FILES that would let a future
// "registry mirror" file silently satisfy tag->registry for every key.
function assertSelfFilesComplete() {
  const keys = Object.keys(REGISTRY);
  const offenders = [];
  for (const f of trackedFiles()) {
    if (SELF.has(f)) continue;
    let text;
    try { text = fs.readFileSync(path.join(ROOT, f), "utf8"); } catch { continue; }
    if (keys.every((k) => text.includes(k))) offenders.push(f);
  }
  return offenders;
}

function run() {
  const known = knownTags();
  const byTag = scanTree();
  const errors = [];

  // (a) tag -> registry: every found tag is known OR allowlisted.
  const orphanTags = [];
  for (const tag of byTag.keys()) {
    if (known.has(tag)) continue;
    if (ALLOWLIST_UNDOCUMENTED.has(tag)) continue;
    orphanTags.push(tag);
  }
  for (const tag of orphanTags.sort()) {
    errors.push(`orphan tag (no registry entry, not allowlisted): ${tag} `
      + `@ ${[...byTag.get(tag)].sort().slice(0, 5).join(", ")}`);
  }

  // (b) registry -> site: every invariant entry's enforcing symbol is live.
  for (const site of enforcingSites()) {
    if (!fs.existsSync(path.join(ROOT, site.file))) {
      errors.push(`dangling enforced_by for ${site.tag}: file missing ${site.file}`);
      continue;
    }
    if (!fileHasSymbol(site.file, site.symbol)) {
      errors.push(`dangling enforced_by for ${site.tag}: `
        + `${site.file} has no symbol "${site.symbol}"`);
    }
  }

  // (c) allowlist hygiene: every allowlisted tag must actually still appear in
  // the tree (a stale allowlist hides nothing and should shrink).
  for (const tag of ALLOWLIST_UNDOCUMENTED) {
    if (!byTag.has(tag)) {
      errors.push(`stale allowlist entry (tag no longer in tree): ${tag}`);
    }
  }

  // (d) self-closure: SELF_FILES must cover every registry mirror.
  for (const f of assertSelfFilesComplete()) {
    errors.push(`SELF_FILES incomplete: ${f} mirrors all registry keys but is `
      + `not listed; it would mask orphans. Add it to SELF_FILES.`);
  }

  return { errors, byTag, known };
}

function main() {
  const seed = process.argv.includes("--seed-allowlist");
  const { errors, byTag, known } = run();
  if (seed) {
    const backlog = [...byTag.keys()].filter((t) => !known.has(t)).sort();
    process.stdout.write(JSON.stringify(backlog, null, 2) + "\n");
    return;
  }
  if (errors.length) {
    console.error("invariant-registry orphan-check FAILED:");
    for (const e of errors) console.error("  - " + e);
    process.exit(1);
  }
  console.log(`invariant-registry orphan-check OK `
    + `(${known.size} entries, ${byTag.size} tags scanned)`);
}

if (require.main === module) main();
module.exports = { run, extractTags, assertSelfFilesComplete, scannableFiles };

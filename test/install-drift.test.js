"use strict";

// drf-020-drift-guard — never overwrite (or delete) a locally-modified
// installed file without saying so.
//
// Every collection assertion in this file carries an explicit counter and a
// HARDCODED FLOOR. A loop over an empty collection passes vacuously, so a
// bare `for (…) assert(…)` would be indistinguishable from a broken fixture.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const {
  installProject,
  printInstallSummary,
} = require(path.join(ROOT, "scripts", "install.js"));
const { createSafeInstallFs } = require(path.join(ROOT, "scripts", "lib", "install-fs.js"));
const {
  INSTALLED_FILE_OWNERSHIP_KEY,
  INSTALLED_FILE_OWNERSHIP_VERSION,
  PRESERVED_LOCAL_SUFFIX,
  PRESERVE_REASON_MODIFIED,
  PRESERVE_REASON_SYMLINK,
  PRESERVE_REASON_UNRECORDED,
  beginInstallDriftGuard,
  createInstallDriftGuard,
  declaredInstalledFileOwnershipCount,
  formatPreservedSummary,
  normalizeInstalledFileOwnership,
} = require(path.join(ROOT, "scripts", "lib", "install-drift.js"));

// The files this node owns. Several assertions below scan exactly this set.
const NODE_FILES = Object.freeze([
  path.join("scripts", "install.js"),
  path.join("scripts", "lib", "install-fs.js"),
  path.join("scripts", "lib", "install-drift.js"),
  path.join("test", "install-drift.test.js"),
]);

// A file the Claude adapter installs through FAMILY A (scripts/install.js
// copyFile, injected into adapters/claude/index.js). This is the exact file
// the observed defect destroyed.
const VICTIM_REL = path.join(".claude", "agents", "report-writer.md");
const LOCAL_EDIT = "\n<!-- OPERATOR LOCAL EDIT — must survive a reinstall -->\n";

const TEMP_ROOTS = [];

// INVARIANT 4: every install in this file targets a THROWAWAY directory under
// os.tmpdir(). Nothing here may ever be pointed at a real workspace.
function throwawayDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bob-drift-${prefix}-`));
  TEMP_ROOTS.push(dir);
  return dir;
}

test.after(() => {
  for (const dir of TEMP_ROOTS) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
});

// Installs write into $HOME (codex/kimi adapters, session roots, session-cap),
// so each workspace gets its own throwaway HOME too.
function install(workspace, home, adapters = null) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return installProject(workspace, {
      sourceRoot: ROOT,
      installerSource: "install.sh",
      onAdapterResolution() {},
      ...(adapters ? { adapters } : {}),
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

// Every `.bob-local` path anywhere under `root`. Used as a positive-control
// counter so a "no strays" assertion cannot pass because the walk found nothing.
function sidecarsUnder(root) {
  const found = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules") continue;
        walk(abs);
        continue;
      }
      if (abs.includes(PRESERVED_LOCAL_SUFFIX)) found.push(path.relative(root, abs));
    }
  };
  if (fs.existsSync(root)) walk(root);
  return found.sort();
}

function freshWorkspace(prefix) {
  return { workspace: throwawayDir(prefix), home: throwawayDir(`${prefix}-home`) };
}

// Mirrors `src` into a NEW directory: regular files are copied, subdirectories
// are symlinked back at the original. Cheap enough to build a whole alternate
// source root (the repo's node_modules trees are 700MB and are never copied),
// and every real file the installer reads still resolves.
function mirrorSourceTree(src, dest, skip) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (skip && skip(entry.name)) continue;
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) fs.symlinkSync(from, to);
    else if (entry.isFile()) fs.copyFileSync(from, to);
  }
}

// Turns `relative` (and every ancestor of it) from a symlink-back-at-the-repo
// into a REAL directory of copies, so a test can mutate it without ever writing
// through to /Users/noot/Documents/hacker-bob. fs.unlinkSync on a symlink
// removes the link and can never touch its target.
function materializeSourceDir(root, relative) {
  let current = "";
  for (const part of relative.split("/")) {
    current = current ? `${current}/${part}` : part;
    const abs = path.join(root, current);
    const stat = fs.lstatSync(abs, { throwIfNoEntry: false });
    if (!stat || !stat.isSymbolicLink()) continue;
    const original = fs.readlinkSync(abs);
    fs.unlinkSync(abs);
    mirrorSourceTree(original, abs, (name) => name === "node_modules");
  }
  assert.ok(fs.realpathSync(path.join(root, relative)).startsWith(fs.realpathSync(root)),
    `refusing to hand a test a path that still resolves into the repo: ${relative}`);
}

// An alternate SOURCE ROOT: byte-identical to the repo except for whatever
// `mutate` changes. `dependencies` are stripped from its package.json so the
// runtime-dependency graph has zero edges and never has to walk node_modules —
// the installer's dependency machinery rejects symlinked package trees, and
// copying 700MB per test is not an option.
function alternateSourceRoot(prefix, { realDirs = [], mutate = null } = {}) {
  const root = throwawayDir(prefix);
  mirrorSourceTree(ROOT, root, (name) => name === ".git" || name === "node_modules");
  for (const relative of realDirs) {
    materializeSourceDir(root, relative);
  }
  const manifestPath = path.join(root, "package.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  delete manifest.dependencies;
  delete manifest.peerDependencies;
  delete manifest.optionalDependencies;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  if (mutate) mutate(root);
  return root;
}

function installFrom(workspace, home, sourceRoot, adapters = ["claude"]) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return installProject(workspace, {
      sourceRoot,
      installerSource: "install.sh",
      onAdapterResolution() {},
      adapters,
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function readMeta(workspace) {
  return JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
}

// Digest every regular file under `root`, skipping the dependency tree (copied
// by a different, unguarded mechanism) and the two metadata receipts whose
// timestamps intentionally move on every run.
const IDEMPOTENCE_EXEMPT = Object.freeze([
  path.join(".hacker-bob", "install.json"),
  path.join(".claude", "bob", "install.json"),
]);

function snapshotTree(root) {
  const snapshot = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules") continue;
        walk(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      if (IDEMPOTENCE_EXEMPT.includes(rel)) continue;
      snapshot.set(rel, sha256(fs.readFileSync(abs)));
    }
  };
  walk(root);
  return snapshot;
}

function captureStdout(fn) {
  const lines = [];
  const original = console.log;
  console.log = (...args) => { lines.push(args.join(" ")); };
  try {
    fn();
  } finally {
    console.log = original;
  }
  return lines;
}

// ---------------------------------------------------------------------------
// 1. THE DEFECT ITSELF, on the copy family that actually bit.
// ---------------------------------------------------------------------------

test("family A: a locally modified installed agent file is preserved, not silently destroyed", () => {
  const { workspace, home } = freshWorkspace("familyA");

  const first = install(workspace, home);
  const victim = path.join(workspace, VICTIM_REL);
  assert.ok(fs.existsSync(victim), `fixture broken: install did not write ${VICTIM_REL}`);

  // Counter + hardcoded floor: prove the adapter really populated the agents
  // directory, so a later "all agents survived" style claim cannot pass on an
  // empty directory.
  const agentFiles = fs.readdirSync(path.join(workspace, ".claude", "agents"))
    .filter((name) => name.endsWith(".md"));
  assert.ok(agentFiles.length >= 5,
    `expected >= 5 installed agent files, saw ${agentFiles.length}`);

  // Clean first install says nothing.
  assert.equal(first.preservedLocalFiles.length, 0);

  const pristine = fs.readFileSync(victim);
  const edited = Buffer.concat([pristine, Buffer.from(LOCAL_EDIT, "utf8")]);
  fs.writeFileSync(victim, edited);

  const second = install(workspace, home);

  // The new version landed...
  assert.equal(sha256(fs.readFileSync(victim)), sha256(pristine),
    "destination should hold the freshly installed version");

  // ...and the operator's bytes survived VERBATIM beside it.
  const sidecar = `${victim}${PRESERVED_LOCAL_SUFFIX}`;
  assert.ok(fs.existsSync(sidecar), `local work was destroyed: no ${PRESERVED_LOCAL_SUFFIX} beside ${VICTIM_REL}`);
  assert.equal(sha256(fs.readFileSync(sidecar)), sha256(edited),
    "preserved copy must be byte-identical to what the operator had");

  // The sidecar must NOT be loadable as an agent definition.
  assert.ok(!sidecar.endsWith(".md"), "preserved copy must not keep the .md extension");

  // Counter + floor on the report itself.
  assert.ok(second.preservedLocalFiles.length >= 1,
    `expected >= 1 preserved path, saw ${second.preservedLocalFiles.length}`);
  const reported = second.preservedLocalFiles
    .filter((entry) => entry.original_path === VICTIM_REL.split(path.sep).join("/"));
  assert.equal(reported.length, 1, "the modified agent must be named in the run summary exactly once");
  assert.equal(reported[0].reason, PRESERVE_REASON_MODIFIED);
  assert.equal(reported[0].preserved_path, `${VICTIM_REL.split(path.sep).join("/")}${PRESERVED_LOCAL_SUFFIX}`);
});

test("the preservation notice is the LAST thing printed, after Done.", () => {
  const { workspace, home } = freshWorkspace("notice");
  install(workspace, home);
  const victim = path.join(workspace, VICTIM_REL);
  fs.appendFileSync(victim, LOCAL_EDIT);
  const summary = install(workspace, home);
  assert.ok(summary.preservedLocalFiles.length >= 1,
    `fixture broken: nothing was preserved (${summary.preservedLocalFiles.length})`);

  const lines = captureStdout(() => printInstallSummary(summary));
  assert.ok(lines.length >= 20, `expected a real summary, saw ${lines.length} lines`);

  const doneIndex = lines.findIndex((line) => line.startsWith("Done."));
  assert.ok(doneIndex >= 0, "summary must contain a Done. line");

  const namedIndexes = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].includes(`${VICTIM_REL.split(path.sep).join("/")}${PRESERVED_LOCAL_SUFFIX}`)) {
      namedIndexes.push(index);
    }
  }
  assert.ok(namedIndexes.length >= 1,
    `preserved path was never printed (${namedIndexes.length} mentions)`);
  for (const index of namedIndexes) {
    assert.ok(index > doneIndex,
      `preserved path printed at line ${index}, before Done. at ${doneIndex} — operator will scroll past it`);
  }

  // Every preserved entry must be named, not summarized as a count.
  let named = 0;
  for (const entry of summary.preservedLocalFiles) {
    assert.ok(lines.some((line) => line.includes(entry.preserved_path)),
      `preserved path not named in the summary: ${entry.preserved_path}`);
    named += 1;
  }
  assert.ok(named >= 1, `expected >= 1 named preserved path, saw ${named}`);
});

// ---------------------------------------------------------------------------
// 2. IDEMPOTENCE + NO REGRESSION ON THE CLEAN PATH.
// ---------------------------------------------------------------------------

test("two consecutive installs with no local edits are byte-identical and silent", () => {
  const { workspace, home } = freshWorkspace("idem");

  const first = install(workspace, home);
  const before = snapshotTree(workspace);
  // Counter + hardcoded floor: a byte-identical comparison of an EMPTY
  // snapshot would pass vacuously.
  assert.ok(before.size >= 300,
    `expected >= 300 installed files in the snapshot, saw ${before.size}`);

  const second = install(workspace, home);
  const after = snapshotTree(workspace);

  assert.equal(second.preservedLocalFiles.length, 0,
    `clean reinstall preserved ${second.preservedLocalFiles.length} files; it must preserve none`);
  assert.equal(after.size, before.size, "reinstall changed the installed file count");

  let compared = 0;
  for (const [rel, digest] of before) {
    assert.equal(after.get(rel), digest, `reinstall changed ${rel}`);
    compared += 1;
  }
  assert.ok(compared >= 300, `expected >= 300 files compared, compared ${compared}`);

  // No stray preservation sidecars anywhere in the tree.
  const strays = [...after.keys()].filter((rel) => rel.includes(PRESERVED_LOCAL_SUFFIX));
  assert.deepEqual(strays, [], `clean reinstall left preservation sidecars: ${strays.join(", ")}`);

  // The receipt itself is stable apart from the intentional timestamp.
  const firstMeta = readMeta(workspace);
  assert.equal(firstMeta.schema_version, 2, "schema_version must stay 2 (additive extension)");
  assert.equal(firstMeta[INSTALLED_FILE_OWNERSHIP_KEY].version, INSTALLED_FILE_OWNERSHIP_VERSION);
  assert.equal(first.installedFileOwnershipCount, second.installedFileOwnershipCount);
  assert.ok(firstMeta[INSTALLED_FILE_OWNERSHIP_KEY].files.length >= 300,
    `expected >= 300 ownership records, saw ${firstMeta[INSTALLED_FILE_OWNERSHIP_KEY].files.length}`);

  // The READ side of the receipt, floored. A receipt that silently normalizes
  // to zero would leave this at 0 while every other assertion above still
  // passed, because an identical-bytes reinstall never reaches the recorded
  // digest comparison at all.
  assert.equal(first.driftGuardRecordedCount, 0, "a first install has no previous receipt");
  assert.ok(second.driftGuardRecordedCount >= 300,
    `the second install read only ${second.driftGuardRecordedCount} records from the receipt`);
  assert.equal(second.driftGuardWarnings.length, 0,
    `a clean reinstall raised warnings: ${second.driftGuardWarnings.join(" | ")}`);
  assert.equal(second.driftGuardOwnershipOverflowed, false,
    "the ownership receipt overflowed on a normal install");
});

test("the ownership receipt records the files the copy families actually wrote", () => {
  const { workspace, home } = freshWorkspace("receipt");
  install(workspace, home);
  const receipt = readMeta(workspace)[INSTALLED_FILE_OWNERSHIP_KEY];

  const byPath = new Map(receipt.files.map((record) => [record.path, record]));
  // Representative destinations from BOTH the adapter surface and the neutral
  // runtime surface. Each is asserted individually; the counter proves the
  // loop ran.
  const expected = [
    VICTIM_REL.split(path.sep).join("/"),
    ".claude/rules/reporting.md",
    "mcp/server.js",
  ];
  let checked = 0;
  for (const rel of expected) {
    const record = byPath.get(rel);
    assert.ok(record, `ownership receipt is missing ${rel}`);
    assert.deepEqual(Object.keys(record).sort(), ["byte_size", "mode", "path", "sha256"],
      `record shape drifted for ${rel}`);
    const onDisk = fs.readFileSync(path.join(workspace, ...rel.split("/")));
    assert.equal(record.sha256, sha256(onDisk), `recorded digest does not match disk for ${rel}`);
    assert.equal(record.byte_size, onDisk.length);
    checked += 1;
  }
  assert.equal(checked, expected.length);
  assert.ok(checked >= 3, `expected >= 3 spot-checked records, checked ${checked}`);

  // Round-trips through the tolerant reader.
  const normalized = normalizeInstalledFileOwnership(readMeta(workspace));
  assert.ok(normalized.size >= 300, `receipt did not round-trip, saw ${normalized.size} records`);
});

// ---------------------------------------------------------------------------
// 3. THE GATE IS DRIFT, NOT MERE EXISTENCE (negative control).
// ---------------------------------------------------------------------------

test("a destination already equal to the incoming bytes is overwritten silently", () => {
  const { workspace, home } = freshWorkspace("nodrift");
  install(workspace, home);
  const victim = path.join(workspace, VICTIM_REL);
  const pristine = fs.readFileSync(victim);

  // Same bytes, but a NEW inode and a mtime the installer cannot have set.
  // Nothing can be destroyed by rewriting identical content, so the guard must
  // stay quiet — this is the clean-path regression control.
  fs.rmSync(victim);
  fs.writeFileSync(victim, pristine);

  const summary = install(workspace, home);
  assert.equal(summary.preservedLocalFiles.length, 0,
    "identical content must not trigger preservation");
  assert.ok(!fs.existsSync(`${victim}${PRESERVED_LOCAL_SUFFIX}`));
});

test("upgrading from an install.json with no ownership receipt fails safe and preserves", () => {
  const { workspace, home } = freshWorkspace("upgrade");
  install(workspace, home);

  // Simulate an install performed by a Bob that predates this receipt.
  const metaPath = path.join(workspace, ".hacker-bob", "install.json");
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  assert.ok(meta[INSTALLED_FILE_OWNERSHIP_KEY], "fixture broken: receipt was never written");
  delete meta[INSTALLED_FILE_OWNERSHIP_KEY];
  fs.writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`, "utf8");
  assert.equal(normalizeInstalledFileOwnership(meta).size, 0,
    "an install.json without the key must normalize to zero records, not throw");

  const victim = path.join(workspace, VICTIM_REL);
  fs.appendFileSync(victim, LOCAL_EDIT);

  const summary = install(workspace, home);
  const reported = summary.preservedLocalFiles
    .filter((entry) => entry.original_path === VICTIM_REL.split(path.sep).join("/"));
  assert.equal(reported.length, 1,
    "an unrecorded, drifted file must be preserved rather than assumed disposable");
  assert.equal(reported[0].reason, PRESERVE_REASON_UNRECORDED);
  assert.ok(fs.existsSync(`${victim}${PRESERVED_LOCAL_SUFFIX}`));

  // And the upgraded install re-establishes the receipt.
  assert.ok(readMeta(workspace)[INSTALLED_FILE_OWNERSHIP_KEY].files.length >= 300);
});

// ---------------------------------------------------------------------------
// 4. THE DELETE PATHS. Deleting an edited file is the same destruction.
// ---------------------------------------------------------------------------

test("removeIfExists preserves an edited legacy file instead of deleting it", () => {
  const { workspace, home } = freshWorkspace("delete");
  install(workspace, home);

  // adapters/claude/index.js sweeps LEGACY_AGENT_FILES through the installer's
  // removeIfExists. Plant one carrying operator content.
  const legacy = path.join(workspace, ".claude", "agents", "hunter-agent.md");
  const operatorContent = "# operator's own notes, never installed by Bob\n";
  fs.writeFileSync(legacy, operatorContent, "utf8");

  const summary = install(workspace, home);

  const sidecar = `${legacy}${PRESERVED_LOCAL_SUFFIX}`;
  assert.ok(fs.existsSync(sidecar), "an edited legacy file was deleted outright");
  assert.equal(fs.readFileSync(sidecar, "utf8"), operatorContent);
  assert.ok(!fs.existsSync(legacy), "the legacy path itself must still be swept clear");

  const reported = summary.preservedLocalFiles
    .filter((entry) => entry.original_path === ".claude/agents/hunter-agent.md");
  assert.equal(reported.length, 1, "the preserved legacy file must be named in the summary");

  // Idempotent: a second run has nothing left to preserve at that path.
  const third = install(workspace, home);
  const again = third.preservedLocalFiles
    .filter((entry) => entry.original_path === ".claude/agents/hunter-agent.md");
  assert.equal(again.length, 0, "delete-path preservation must not repeat on a clean rerun");
});

test("a legacy file Bob itself installed is deleted silently", () => {
  // Unit-level: the recorded digest matches, so there is no local work to save.
  const root = throwawayDir("delete-unit");
  const doomed = path.join(root, "doomed.md");
  fs.writeFileSync(doomed, "bob content\n", "utf8");

  const session = beginInstallDriftGuard({ targetAbs: root, previousMetadata: null });
  session.guard.recordWrite(doomed);
  const ownership = session.end().ownership;
  assert.equal(ownership.files.length, 1, "fixture broken: nothing was recorded");

  const guard = createInstallDriftGuard({
    targetAbs: root,
    previousMetadata: { [INSTALLED_FILE_OWNERSHIP_KEY]: ownership },
  });
  assert.equal(guard.beforeDelete(doomed), false,
    "an untouched Bob-owned file must be deletable without preservation");
  assert.equal(guard.preservedFiles().length, 0);

  fs.writeFileSync(doomed, "operator content\n", "utf8");
  const drifted = createInstallDriftGuard({
    targetAbs: root,
    previousMetadata: { [INSTALLED_FILE_OWNERSHIP_KEY]: ownership },
  });
  assert.equal(drifted.beforeDelete(doomed), true,
    "a drifted file must be preserved instead of deleted");
  assert.equal(drifted.preservedFiles().length, 1);
  assert.equal(fs.readFileSync(`${doomed}${PRESERVED_LOCAL_SUFFIX}`, "utf8"), "operator content\n");
});

// ---------------------------------------------------------------------------
// 5. BOTH COPY FAMILIES ARE GUARDED.
//
// GROUND TRUTH: adapters/claude/index.js never requires install-fs.js — it
// receives copyDirFiles/copyFile injected from scripts/install.js. A guard in
// createSafeInstallFs alone would not have prevented the observed defect, so
// both families must be wired and both are asserted here.
// ---------------------------------------------------------------------------

test("family B: createSafeInstallFs copyFile is guarded by the SAME implementation", () => {
  const root = throwawayDir("familyB");
  const sourceDir = throwawayDir("familyB-src");
  const sourceFile = path.join(sourceDir, "skill.md");
  const destination = path.join(root, "skills", "skill.md");

  fs.writeFileSync(sourceFile, "v1\n", "utf8");
  const safeFs = createSafeInstallFs(root, { label: "test root" });

  // Install #1 — destination absent, silent, recorded.
  const s1 = beginInstallDriftGuard({ targetAbs: root, previousMetadata: null });
  safeFs.copyFile(sourceFile, destination);
  const ownership = s1.end();
  assert.equal(ownership.preserved.length, 0, "a fresh write must not preserve anything");
  assert.equal(ownership.ownership.files.length, 1,
    `expected exactly 1 recorded family-B file, saw ${ownership.ownership.files.length}`);

  const previousMetadata = { [INSTALLED_FILE_OWNERSHIP_KEY]: ownership.ownership };

  // Install #2 — clean upgrade: Bob's bytes untouched on disk, source moved on.
  fs.writeFileSync(sourceFile, "v2\n", "utf8");
  const s2 = beginInstallDriftGuard({ targetAbs: root, previousMetadata });
  safeFs.copyFile(sourceFile, destination);
  const clean = s2.end();
  assert.equal(clean.preserved.length, 0,
    "an untouched destination must be upgraded silently");
  assert.equal(fs.readFileSync(destination, "utf8"), "v2\n");

  // Install #3 — the operator edited it. Preserve.
  fs.writeFileSync(destination, "operator v2 + notes\n", "utf8");
  fs.writeFileSync(sourceFile, "v3\n", "utf8");
  const s3 = beginInstallDriftGuard({
    targetAbs: root,
    previousMetadata: { [INSTALLED_FILE_OWNERSHIP_KEY]: clean.ownership },
  });
  safeFs.copyFile(sourceFile, destination);
  const drifted = s3.end();
  assert.equal(drifted.preserved.length, 1,
    `family B must preserve the operator's edit, preserved ${drifted.preserved.length}`);
  assert.equal(drifted.preserved[0].original_path, "skills/skill.md");
  assert.equal(drifted.preserved[0].reason, PRESERVE_REASON_MODIFIED);
  assert.equal(fs.readFileSync(destination, "utf8"), "v3\n");
  assert.equal(fs.readFileSync(`${destination}${PRESERVED_LOCAL_SUFFIX}`, "utf8"),
    "operator v2 + notes\n");
});

test("the guard is inert when no install is in flight", () => {
  const root = throwawayDir("inert");
  const sourceDir = throwawayDir("inert-src");
  const sourceFile = path.join(sourceDir, "f.txt");
  const destination = path.join(root, "f.txt");
  fs.writeFileSync(sourceFile, "new\n", "utf8");
  fs.writeFileSync(destination, "operator\n", "utf8");

  // No beginInstallDriftGuard: createSafeInstallFs must behave exactly as before.
  createSafeInstallFs(root, { label: "test root" }).copyFile(sourceFile, destination);
  assert.equal(fs.readFileSync(destination, "utf8"), "new\n");
  assert.ok(!fs.existsSync(`${destination}${PRESERVED_LOCAL_SUFFIX}`),
    "an unarmed guard must not create sidecars");
});

test("both copy families require the one shared guard implementation", () => {
  // A NEGATIVE GREP IS NOT EVIDENCE. Each assertion below is paired with a
  // POSITIVE CONTROL from the same read, proving the file was really loaded.
  const installJs = fs.readFileSync(path.join(ROOT, "scripts", "install.js"), "utf8");
  const installFsJs = fs.readFileSync(path.join(ROOT, "scripts", "lib", "install-fs.js"), "utf8");
  const claudeAdapterJs = fs.readFileSync(path.join(ROOT, "adapters", "claude", "index.js"), "utf8");

  // Positive controls.
  assert.ok(installJs.includes("function copyDirFiles("),
    "positive control failed: scripts/install.js was not read as expected");
  assert.ok(installFsJs.includes("function createSafeInstallFs("),
    "positive control failed: scripts/lib/install-fs.js was not read as expected");
  assert.ok(claudeAdapterJs.includes("copyDirFiles"),
    "positive control failed: adapters/claude/index.js was not read as expected");

  // FAMILY A and FAMILY B both require the shared module — not two copies.
  assert.ok(installJs.includes('require("./lib/install-drift.js")'),
    "FAMILY A (scripts/install.js) does not require the shared drift guard");
  assert.ok(installFsJs.includes('require("./install-drift.js")'),
    "FAMILY B (scripts/lib/install-fs.js) does not require the shared drift guard");

  // The corrected ground truth that makes FAMILY A load-bearing: the Claude
  // adapter, which wrote the destroyed file, does NOT go through install-fs.
  assert.ok(!claudeAdapterJs.includes("install-fs"),
    "ground truth changed: adapters/claude/index.js now references install-fs.js");

  // And there is exactly one implementation of the preserve step. The copy
  // families may IMPORT the suffix constant, but neither may spell the literal
  // or reimplement the move — two divergent guards is the defect this graph
  // exists to fix.
  const guardJs = fs.readFileSync(path.join(ROOT, "scripts", "lib", "install-drift.js"), "utf8");
  assert.ok(guardJs.includes("function preserveLocalFile("),
    "positive control failed: install-drift.js was not read as expected");
  assert.ok(guardJs.includes('".bob-local"'),
    "positive control failed: the suffix literal does not live in the shared module");
  let literalSites = 0;
  for (const file of [installJs, installFsJs]) {
    literalSites += (file.match(/"\.bob-local"/gu) || []).length;
  }
  assert.equal(literalSites, 0,
    "a copy family spells the preservation suffix itself instead of importing it");
});

test("the mcp/lib wholesale replace preserves local work outside the wiped root", () => {
  const { workspace, home } = freshWorkspace("treewipe");
  install(workspace, home);

  // scripts/install.js rmSync's the whole mcp/lib root before re-copying it,
  // so a local edit there dies before any copyFile guard sees the destination.
  const libDir = path.join(workspace, "mcp", "lib");
  const libFiles = fs.readdirSync(libDir).filter((name) => name.endsWith(".js"));
  assert.ok(libFiles.length >= 50,
    `expected >= 50 installed mcp/lib modules, saw ${libFiles.length}`);

  const edited = path.join(libDir, libFiles[0]);
  const operatorBytes = `${fs.readFileSync(edited, "utf8")}\n// operator debug hook\n`;
  fs.writeFileSync(edited, operatorBytes, "utf8");

  // A module Bob never installed, sitting inside the wiped root.
  const orphan = path.join(libDir, "operator-only-module.js");
  fs.writeFileSync(orphan, "module.exports = {};\n", "utf8");

  const summary = install(workspace, home);

  const preservedRoot = `${libDir}${PRESERVED_LOCAL_SUFFIX}`;
  assert.ok(fs.existsSync(preservedRoot),
    "mcp/lib was wiped without preserving local work");
  assert.ok(!preservedRoot.startsWith(`${libDir}${path.sep}`),
    "the preserved tree must live OUTSIDE the wiped root");

  const editedPreserved = path.join(preservedRoot, libFiles[0]);
  assert.ok(fs.existsSync(editedPreserved), `local edit to mcp/lib/${libFiles[0]} was destroyed`);
  assert.equal(fs.readFileSync(editedPreserved, "utf8"), operatorBytes);
  assert.ok(fs.existsSync(path.join(preservedRoot, "operator-only-module.js")),
    "an operator-authored module inside mcp/lib was destroyed");

  // Both are named in the run summary.
  let named = 0;
  for (const rel of [`mcp/lib/${libFiles[0]}`, "mcp/lib/operator-only-module.js"]) {
    assert.ok(summary.preservedLocalFiles.some((entry) => entry.original_path === rel),
      `preserved path missing from summary: ${rel}`);
    named += 1;
  }
  assert.equal(named, 2);

  // The wipe still did its job: mcp/lib holds the fresh runtime.
  assert.equal(
    sha256(fs.readFileSync(edited)),
    sha256(fs.readFileSync(path.join(ROOT, "mcp", "lib", libFiles[0]))),
    "mcp/lib must still be replaced with the shipped runtime",
  );
  assert.ok(!fs.existsSync(orphan), "the wholesale replace must still clear the root");

  // Quiet on a clean rerun. NOT a bare empty-array equality: the third install
  // must be proven to have actually run the tree replace, or "zero preserved"
  // would pass vacuously on a no-op.
  const third = install(workspace, home);
  const libAgain = third.preservedLocalFiles.filter((entry) => entry.original_path.startsWith("mcp/lib/"));
  const rewritten = fs.readdirSync(libDir).filter((name) => name.endsWith(".js"));
  assert.ok(rewritten.length >= 50,
    `positive control failed: the third install left only ${rewritten.length} mcp/lib modules`);
  assert.ok(third.installedFileOwnershipCount >= 300,
    `positive control failed: the third install recorded only ${third.installedFileOwnershipCount} files`);
  assert.equal(libAgain.length, 0,
    `the tree replace must be silent once nothing has drifted, preserved ${libAgain.length}: `
    + libAgain.map((entry) => entry.original_path).join(", "));
});

test("a SECOND drift event at the same tree path keeps BOTH preserved copies", () => {
  // The regression that made this necessary: the tree-replace sweep used a bare
  // rename to a fixed destination, so the second drift event at one path ate
  // the copy the first one had saved — the guard silently destroying local work
  // in its own preservation path.
  const { workspace, home } = freshWorkspace("treewipe2");
  install(workspace, home);

  const libDir = path.join(workspace, "mcp", "lib");
  const libFiles = fs.readdirSync(libDir).filter((name) => name.endsWith(".js")).sort();
  assert.ok(libFiles.length >= 50,
    `expected >= 50 installed mcp/lib modules, saw ${libFiles.length}`);
  const victim = path.join(libDir, libFiles[0]);
  const preservedRoot = `${libDir}${PRESERVED_LOCAL_SUFFIX}`;

  const EDIT_ONE = "\n// OPERATOR EDIT ONE\n";
  const EDIT_TWO = "\n// OPERATOR EDIT TWO — a different debug hook\n";

  fs.appendFileSync(victim, EDIT_ONE);
  const editOneBytes = fs.readFileSync(victim, "utf8");
  const second = install(workspace, home);

  // The replace restored Bob's version, so the second edit is applied to a
  // fresh file and its content genuinely differs from the first.
  fs.appendFileSync(victim, EDIT_TWO);
  const editTwoBytes = fs.readFileSync(victim, "utf8");
  assert.notEqual(editOneBytes, editTwoBytes, "fixture broken: the two edits are identical");
  const third = install(workspace, home);

  // Counter + hardcoded floor: BOTH copies must be on disk.
  const siblings = fs.readdirSync(preservedRoot).filter((name) => name.startsWith(libFiles[0])).sort();
  assert.ok(siblings.length >= 2,
    `the second drift event overwrote the first preserved copy: only ${siblings.length} copies `
    + `beside ${preservedRoot} (${siblings.join(", ")})`);

  const bodies = siblings.map((name) => fs.readFileSync(path.join(preservedRoot, name), "utf8"));
  assert.ok(bodies.includes(editOneBytes), "EDIT ONE was destroyed by the second drift event");
  assert.ok(bodies.includes(editTwoBytes), "EDIT TWO was not preserved");
  assert.equal(new Set(bodies).size, bodies.length,
    "the preserved copies must be distinct, not the same bytes twice");

  // ...and the two runs must report DIFFERENT preserved paths, or the operator
  // cannot tell that two separate copies exist.
  const p2 = second.preservedLocalFiles.filter((entry) => entry.original_path === `mcp/lib/${libFiles[0]}`);
  const p3 = third.preservedLocalFiles.filter((entry) => entry.original_path === `mcp/lib/${libFiles[0]}`);
  assert.equal(p2.length, 1, `run 2 must name the preserved path once, named ${p2.length}`);
  assert.equal(p3.length, 1, `run 3 must name the preserved path once, named ${p3.length}`);
  assert.notEqual(p2[0].preserved_path, p3[0].preserved_path,
    `both runs reported the same preserved_path (${p3[0].preserved_path}) — one copy was clobbered`);
});

// ---------------------------------------------------------------------------
// 6. THE OTHER DELETE PATH: the pre-v2 legacy resource sweep.
// ---------------------------------------------------------------------------

test("the legacy resource sweep preserves an edited legacy copy instead of deleting it", () => {
  const { workspace, home } = freshWorkspace("legacyres");
  install(workspace, home);

  // removeLegacyResourceCopies deletes .claude/{bypass-tables,knowledge}/<name>
  // for every name the shipped resource set carries. On a modern tree those
  // directories do not exist, so the loop runs ZERO times and an unguarded
  // rmSync there is invisible. Plant the directory so the loop actually runs.
  const sourceNames = fs.readdirSync(path.join(ROOT, ".hacker-bob", "bypass-tables"))
    .filter((name) => name.endsWith(".txt"))
    .sort();
  assert.ok(sourceNames.length >= 3,
    `fixture broken: expected >= 3 shipped bypass tables, saw ${sourceNames.length}`);

  const legacyDir = path.join(workspace, ".claude", "bypass-tables");
  fs.mkdirSync(legacyDir, { recursive: true });
  const planted = [];
  for (const name of sourceNames.slice(0, 3)) {
    const legacyPath = path.join(legacyDir, name);
    fs.writeFileSync(legacyPath, `# operator content for ${name}\n`, "utf8");
    planted.push({ name, legacyPath, body: `# operator content for ${name}\n` });
  }
  assert.equal(planted.length, 3);

  const summary = install(workspace, home);

  let survived = 0;
  for (const entry of planted) {
    assert.ok(!fs.existsSync(entry.legacyPath),
      `the legacy path must still be swept clear: ${entry.name}`);
    const sidecar = `${entry.legacyPath}${PRESERVED_LOCAL_SUFFIX}`;
    assert.ok(fs.existsSync(sidecar),
      `an edited legacy resource copy was deleted outright: .claude/bypass-tables/${entry.name}`);
    assert.equal(fs.readFileSync(sidecar, "utf8"), entry.body);
    assert.ok(summary.preservedLocalFiles.some(
      (item) => item.original_path === `.claude/bypass-tables/${entry.name}`,
    ), `preserved legacy resource not named in the summary: ${entry.name}`);
    survived += 1;
  }
  assert.equal(survived, 3, `expected 3 preserved legacy copies, saw ${survived}`);

  // Idempotent: a rerun has nothing left at those paths to preserve again.
  const again = install(workspace, home);
  const repeats = again.preservedLocalFiles
    .filter((entry) => entry.original_path.startsWith(".claude/bypass-tables/"));
  assert.equal(repeats.length, 0,
    `the legacy sweep repeated its preservation: ${repeats.map((r) => r.original_path).join(", ")}`);
});

// ---------------------------------------------------------------------------
// 7. FAMILY B's NON-COPY WRITES. copyFile is not the only way family B lands a
// wholesale file: the codex adapter renders six command wrappers through
// installFs.writeTextFile with no merge semantics at all.
// ---------------------------------------------------------------------------

test("family B: locally modified codex command wrappers are preserved, not silently destroyed", () => {
  const { workspace, home } = freshWorkspace("codexcmd");
  install(workspace, home, ["codex"]);

  const commandDir = path.join(workspace, ".codex", "plugins", "hacker-bob", "commands");
  const commands = fs.readdirSync(commandDir).filter((name) => name.endsWith(".md")).sort();
  // Counter + hardcoded floor: without this, "every wrapper survived" would
  // pass on an empty command directory.
  assert.ok(commands.length >= 6,
    `expected >= 6 rendered codex command wrappers, saw ${commands.length}`);

  const edited = new Map();
  for (const name of commands) {
    const abs = path.join(commandDir, name);
    fs.appendFileSync(abs, `\n<!-- OPERATOR EDIT ${name} -->\n`);
    edited.set(name, fs.readFileSync(abs, "utf8"));
  }

  const summary = install(workspace, home, ["codex"]);

  let preservedCount = 0;
  for (const name of commands) {
    const abs = path.join(commandDir, name);
    const sidecar = `${abs}${PRESERVED_LOCAL_SUFFIX}`;
    assert.ok(fs.existsSync(sidecar),
      `codex command wrapper was silently destroyed: ${name}`);
    assert.equal(fs.readFileSync(sidecar, "utf8"), edited.get(name),
      `preserved copy is not byte-identical to the operator's version: ${name}`);
    assert.ok(!fs.readFileSync(abs, "utf8").includes("OPERATOR EDIT"),
      `the freshly rendered wrapper should have replaced the edit: ${name}`);
    assert.ok(summary.preservedLocalFiles.some(
      (entry) => entry.preserved_path.endsWith(`commands/${name}${PRESERVED_LOCAL_SUFFIX}`),
    ), `preserved codex wrapper not named in the summary: ${name}`);
    preservedCount += 1;
  }
  assert.ok(preservedCount >= 6,
    `expected >= 6 preserved codex wrappers, saw ${preservedCount}`);
});

test("three consecutive codex installs with no local edits preserve nothing", () => {
  // The codex adapter writes .codex/plugins/hacker-bob/.mcp.json TWICE in one
  // run — copyTree lands the template, then writeJson renders the real config
  // over it. If the receipt only remembers the first of those, every later
  // install sees permanent drift and cries wolf on a completely clean tree.
  const { workspace, home } = freshWorkspace("codexidem");

  const runs = [
    install(workspace, home, ["codex"]),
    install(workspace, home, ["codex"]),
    install(workspace, home, ["codex"]),
  ];

  // Positive control: the installs really did write the codex surface.
  const pluginDir = path.join(workspace, ".codex", "plugins", "hacker-bob");
  assert.ok(fs.existsSync(path.join(pluginDir, ".mcp.json")),
    "fixture broken: the codex adapter never wrote .mcp.json");
  assert.ok(runs[2].installedFileOwnershipCount >= 300,
    `positive control failed: only ${runs[2].installedFileOwnershipCount} files recorded`);

  let checked = 0;
  for (const [index, run] of runs.entries()) {
    assert.equal(run.preservedLocalFiles.length, 0,
      `codex install #${index + 1} preserved ${run.preservedLocalFiles.length} files on a clean tree: `
      + run.preservedLocalFiles.map((entry) => `${entry.original_path}:${entry.reason}`).join(", "));
    assert.equal(run.driftGuardWarnings.length, 0,
      `codex install #${index + 1} raised drift-guard warnings: ${run.driftGuardWarnings.join(" | ")}`);
    checked += 1;
  }
  assert.equal(checked, 3);

  // BOTH regions. Half the guarded family-B writes land under $HOME
  // (adapters/codex/index.js installDirectSkills copies through
  // createSafeInstallFs(home)), so a workspace-only scan cannot see them.
  // sidecarsUnder is proven to return non-empty under $HOME by the test in
  // section 12, so a zero here is a real zero.
  let regions = 0;
  for (const [label, region] of [["workspace", workspace], ["$HOME", home]]) {
    const strays = sidecarsUnder(region);
    assert.equal(strays.length, 0,
      `clean codex installs left preservation sidecars under ${label}: ${strays.join(", ")}`);
    regions += 1;
  }
  assert.equal(regions, 2);
});

// ---------------------------------------------------------------------------
// 8. NO SILENT CAPS. Both bounds must reach the operator's screen.
// ---------------------------------------------------------------------------

test("both guard bounds print instead of firing silently", () => {
  const root = throwawayDir("caps");

  // (a) The ownership receipt cap. Recording past it drops the record, which
  // makes the NEXT install treat those files as unrecorded local work.
  const a = path.join(root, "a.txt");
  const b = path.join(root, "b.txt");
  fs.writeFileSync(a, "a\n", "utf8");
  fs.writeFileSync(b, "b\n", "utf8");
  const capped = createInstallDriftGuard({ targetAbs: root, maxOwnershipFiles: 1 });
  capped.recordWrite(a);
  capped.recordWrite(b);
  assert.equal(capped.writtenFileCount(), 1, "fixture broken: the cap did not bite");
  assert.equal(capped.ownershipOverflowed(), true);
  const overflowWarnings = capped.warnings();
  assert.ok(overflowWarnings.length >= 1,
    `the ownership cap fired silently: ${overflowWarnings.length} warnings`);
  assert.ok(overflowWarnings.some((line) => line.includes("b.txt")),
    `the warning must name the dropped file: ${overflowWarnings.join(" | ")}`);

  // (b) The tree-sweep cap. The caller wipes the tree the instant the sweep
  // returns, so anything the walk did not reach is destroyed.
  const tree = path.join(root, "tree");
  fs.mkdirSync(tree, { recursive: true });
  let planted = 0;
  for (const name of ["one.js", "two.js", "three.js"]) {
    fs.writeFileSync(path.join(tree, name), `// local ${name}\n`, "utf8");
    planted += 1;
  }
  assert.equal(planted, 3);
  const sweeper = createInstallDriftGuard({ targetAbs: root, maxOwnershipFiles: 2 });
  const moved = sweeper.preserveBeforeTreeReplace({
    targetTree: tree,
    sourceTree: null,
    preservedTree: path.join(root, "tree.preserved"),
  });
  assert.ok(moved.length >= 1 && moved.length < planted,
    `fixture broken: expected a truncated sweep, moved ${moved.length} of ${planted}`);
  const sweepWarnings = sweeper.warnings();
  assert.ok(sweepWarnings.length >= 1,
    `the tree-sweep cap fired silently: ${sweepWarnings.length} warnings`);
  assert.ok(sweepWarnings.some((line) => line.includes("stopped after")),
    `the warning must say the sweep stopped early: ${sweepWarnings.join(" | ")}`);

  // Both must actually reach the printed summary, even with nothing preserved.
  const printed = formatPreservedSummary([], overflowWarnings.concat(sweepWarnings));
  assert.ok(printed.length >= 3, `warnings were not printed, got ${printed.length} lines`);
  let namedWarnings = 0;
  for (const warning of overflowWarnings.concat(sweepWarnings)) {
    assert.ok(printed.some((line) => line.includes(warning)),
      `warning never printed: ${warning}`);
    namedWarnings += 1;
  }
  assert.ok(namedWarnings >= 2, `expected >= 2 printed warnings, saw ${namedWarnings}`);

  // POSITIVE CONTROL: the same call with no warnings and nothing preserved
  // prints NOTHING, so the clean path stays quiet.
  assert.deepEqual(formatPreservedSummary([], []), [],
    "positive control failed: the clean path is no longer silent");
  const clean = createInstallDriftGuard({ targetAbs: root });
  clean.recordWrite(a);
  clean.recordWrite(b);
  assert.equal(clean.writtenFileCount(), 2, "positive control failed: default cap should not bite");
  assert.equal(clean.warnings().length, 0,
    `positive control failed: an uncapped guard warned anyway: ${clean.warnings().join(" | ")}`);
});

test("a malformed or foreign ownership receipt yields zero records, never a throw", () => {
  const cases = [
    undefined,
    null,
    {},
    { [INSTALLED_FILE_OWNERSHIP_KEY]: null },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: [] },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: 99, files: [] } },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: 1, files: [{ path: "a", byte_size: 1, sha256: "zz", mode: 420 }] } },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: 1, files: [{ path: "a", byte_size: -1, sha256: "a".repeat(64), mode: 420 }] } },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: 1, files: [{ path: "a", sha256: "a".repeat(64), mode: 420 }] } },
    { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: 1, files: [{ path: "a", byte_size: 1, sha256: "a".repeat(64), mode: 420 }, { path: "a", byte_size: 1, sha256: "a".repeat(64), mode: 420 }] } },
  ];
  let checked = 0;
  for (const metadata of cases) {
    assert.equal(normalizeInstalledFileOwnership(metadata).size, 0,
      `malformed receipt was accepted: ${JSON.stringify(metadata)}`);
    checked += 1;
  }
  assert.ok(checked >= 10, `expected >= 10 malformed-receipt cases, checked ${checked}`);

  // Positive control: a WELL-FORMED receipt must still be accepted, or the
  // assertions above would pass because the reader rejects everything.
  const good = {
    [INSTALLED_FILE_OWNERSHIP_KEY]: {
      version: INSTALLED_FILE_OWNERSHIP_VERSION,
      files: [{ path: "a/b.md", byte_size: 3, sha256: "b".repeat(64), mode: 0o644 }],
    },
  };
  assert.equal(normalizeInstalledFileOwnership(good).size, 1,
    "positive control failed: the reader rejects a valid receipt");
});

test("a receipt that silently normalizes to zero says so out loud", () => {
  // One malformed record among hundreds rejects the WHOLE map. That direction
  // is right, but it used to happen in silence: every recorded.get() then
  // missed, the entire tree took the preserve branch, and the operator was told
  // their edits were saved for files they had never touched.
  const files = [];
  for (let index = 0; index < 600; index += 1) {
    files.push({ path: `mcp/lib/mod-${index}.js`, byte_size: 10, sha256: "c".repeat(64), mode: 0o644 });
  }
  assert.equal(files.length, 600, "fixture broken: the receipt is not populated");

  const healthy = { [INSTALLED_FILE_OWNERSHIP_KEY]: { version: INSTALLED_FILE_OWNERSHIP_VERSION, files } };
  // POSITIVE CONTROL: the same receipt without the poison is read in full and
  // raises NOTHING, so the warning below is caused by the bad record alone.
  assert.equal(declaredInstalledFileOwnershipCount(healthy), 600);
  const clean = createInstallDriftGuard({ targetAbs: throwawayDir("recept-ok"), previousMetadata: healthy });
  assert.equal(clean.recordedFileCount(), 600,
    `positive control failed: a valid 600-record receipt yielded ${clean.recordedFileCount()}`);
  assert.equal(clean.warnings().length, 0,
    `positive control failed: a valid receipt warned anyway: ${clean.warnings().join(" | ")}`);

  const poisoned = {
    [INSTALLED_FILE_OWNERSHIP_KEY]: {
      version: INSTALLED_FILE_OWNERSHIP_VERSION,
      files: [...files, { path: "mcp/lib/bad.js", byte_size: 10, sha256: "c".repeat(64), mode: 99999 }],
    },
  };
  assert.equal(declaredInstalledFileOwnershipCount(poisoned), 601);
  assert.equal(normalizeInstalledFileOwnership(poisoned).size, 0,
    "fixture broken: the poisoned receipt was accepted");

  const guard = createInstallDriftGuard({ targetAbs: throwawayDir("recept-bad"), previousMetadata: poisoned });
  assert.equal(guard.recordedFileCount(), 0);
  const warnings = guard.warnings();
  assert.ok(warnings.length >= 1,
    `a receipt that normalized to zero was accepted in silence: ${warnings.length} warnings`);
  assert.ok(warnings.some((line) => line.includes("601")),
    `the warning must say how many records were declared: ${warnings.join(" | ")}`);
  assert.ok(formatPreservedSummary([], warnings).length >= 2,
    "the warning must reach the printed summary");
});

test("every recordWrite bound warns instead of dropping a record in silence", () => {
  // Four early returns leave a path unrecorded, which makes the NEXT install
  // preserve Bob's own bytes as if they were the operator's. Each must print.
  const root = throwawayDir("recordbounds");
  const guard = createInstallDriftGuard({ targetAbs: root, maxOwnershipFiles: 2 });

  // (a) not a regular file
  const asDirectory = path.join(root, "a-directory");
  fs.mkdirSync(asDirectory);
  assert.equal(guard.recordWrite(asDirectory), null);

  // (b) past the per-record byte limit. Sparse: truncate reports the size
  // without ever writing 257MB, and the bound returns before any hashing.
  const huge = path.join(root, "huge.bin");
  fs.writeFileSync(huge, "");
  fs.truncateSync(huge, (256 * 1024 * 1024) + 1);
  assert.ok(fs.lstatSync(huge).size > 256 * 1024 * 1024, "fixture broken: the file is not oversized");
  assert.equal(guard.recordWrite(huge), null);

  // (c) the receipt-full cap.
  const one = path.join(root, "one.txt");
  const two = path.join(root, "two.txt");
  const three = path.join(root, "three.txt");
  for (const file of [one, two, three]) fs.writeFileSync(file, "x\n", "utf8");
  guard.recordWrite(one);
  guard.recordWrite(two);
  assert.equal(guard.recordWrite(three), null, "fixture broken: the cap did not bite");
  assert.equal(guard.writtenFileCount(), 2, "only the two in-bounds files may be recorded");

  // (d) a path that cannot serve as a receipt key. macOS caps a real path at
  // PATH_MAX (1024), the same order as the key bound, so it is driven through
  // the same injection seam the receipt cap uses rather than left unproven.
  const keyBound = createInstallDriftGuard({ targetAbs: root, maxOwnershipPathLength: 8 });
  const overlongKey = path.join(root, "past-the-key-bound.txt");
  fs.writeFileSync(overlongKey, "x\n", "utf8");
  assert.equal(keyBound.recordWrite(overlongKey), null);
  assert.equal(keyBound.writtenFileCount(), 0, "an unusable key must not be recorded");

  const warnings = guard.warnings().concat(keyBound.warnings());
  assert.ok(warnings.length >= 4,
    `expected >= 4 distinct bound warnings, saw ${warnings.length}: ${warnings.join(" | ")}`);
  let matched = 0;
  for (const needle of ["a-directory", "huge.bin", "three.txt", "past-the-key-bound.txt"]) {
    assert.ok(warnings.some((line) => line.includes(needle)),
      `no warning names ${needle}: ${warnings.join(" | ")}`);
    matched += 1;
  }
  assert.equal(matched, 4);

  // POSITIVE CONTROL: an in-bounds record is silent, so the warnings above are
  // caused by the bounds and not by recordWrite warning unconditionally.
  const quiet = createInstallDriftGuard({ targetAbs: root });
  quiet.recordWrite(one);
  assert.equal(quiet.writtenFileCount(), 1);
  assert.equal(quiet.warnings().length, 0,
    `positive control failed: an in-bounds record warned: ${quiet.warnings().join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 9. FAMILY A's OTHER WRITE: the renderer-driven command files.
//
// adapters/claude/index.js renders bob-evaluate.md, bob-update.md and
// bob-export.md from renderCommand() with NO merge semantics, and used to land
// them through its own bare fs.writeFileSync. Only the fourth command file
// (bob-egress.md, a real copyFile) was guarded — 3 of 4 were silently
// destroyed. scripts/install.js now injects the guarded writeTextFile.
// ---------------------------------------------------------------------------

test("family A: locally modified .claude/commands files are ALL preserved", () => {
  const { workspace, home } = freshWorkspace("claudecmd");
  install(workspace, home, ["claude"]);

  const commandDir = path.join(workspace, ".claude", "commands");
  const commands = fs.readdirSync(commandDir).filter((name) => name.endsWith(".md")).sort();
  // The counter + hardcoded floor that would have caught this: .claude/agents
  // was enumerated with a floor and .claude/commands never was, which is
  // precisely why the third write family stayed invisible.
  assert.ok(commands.length >= 4,
    `expected >= 4 installed .claude/commands files, saw ${commands.length}`);
  for (const renderer of ["bob-evaluate.md", "bob-update.md", "bob-export.md"]) {
    assert.ok(commands.includes(renderer), `fixture broken: ${renderer} was not installed`);
  }

  const edited = new Map();
  for (const name of commands) {
    const abs = path.join(commandDir, name);
    fs.appendFileSync(abs, `\n<!-- OPERATOR EDIT ${name} -->\n`);
    edited.set(name, fs.readFileSync(abs, "utf8"));
  }

  const summary = install(workspace, home, ["claude"]);

  let preserved = 0;
  for (const name of commands) {
    const abs = path.join(commandDir, name);
    const sidecar = `${abs}${PRESERVED_LOCAL_SUFFIX}`;
    assert.ok(fs.existsSync(sidecar), `command file was silently destroyed: ${name}`);
    assert.equal(fs.readFileSync(sidecar, "utf8"), edited.get(name),
      `preserved copy is not byte-identical to the operator's version: ${name}`);
    assert.ok(!fs.readFileSync(abs, "utf8").includes("OPERATOR EDIT"),
      `the freshly rendered command should have replaced the edit: ${name}`);
    assert.ok(summary.preservedLocalFiles.some(
      (entry) => entry.original_path === `.claude/commands/${name}`,
    ), `preserved command not named in the summary: ${name}`);
    preserved += 1;
  }
  assert.ok(preserved >= 4, `expected >= 4 preserved command files, saw ${preserved}`);

  // The injection is what makes the three renderer-driven files reachable.
  // Read both ends with positive controls; a zero-hit search proves nothing.
  const installJs = fs.readFileSync(path.join(ROOT, "scripts", "install.js"), "utf8");
  const adapterJs = fs.readFileSync(path.join(ROOT, "adapters", "claude", "index.js"), "utf8");
  assert.ok(installJs.includes("function writeTextFile("),
    "positive control failed: scripts/install.js has no writeTextFile");
  assert.ok(adapterJs.includes("for (const commandId of commandIds()) {"),
    "positive control failed: the adapter's command loop was not read");
  assert.ok(adapterJs.includes("writeGeneratedFile("),
    "the adapter no longer routes its rendered commands through the injected writer");

  // Idempotent: a clean rerun preserves nothing under .claude/commands.
  const again = install(workspace, home, ["claude"]);
  const repeats = again.preservedLocalFiles
    .filter((entry) => entry.original_path.startsWith(".claude/commands/"));
  assert.equal(repeats.length, 0,
    `the command writes repeated their preservation: ${repeats.map((r) => r.original_path).join(", ")}`);
});

test("family A: a SYMLINKED destination is preserved, not written through", () => {
  // FAMILY A has no leaf checks at all — copyFile is mkdir -> guard ->
  // fs.copyFileSync -> chmod — and copyFileSync FOLLOWS a symlink, rewriting
  // whatever the operator pointed it at. rename() moves the link itself.
  const { workspace, home } = freshWorkspace("symlink");
  install(workspace, home, ["claude"]);

  const victim = path.join(workspace, VICTIM_REL);
  const operatorFile = path.join(workspace, "operator-notes.md");
  const operatorBody = "# operator's own file, reached only through the symlink\n";
  fs.writeFileSync(operatorFile, operatorBody, "utf8");
  fs.rmSync(victim);
  fs.symlinkSync(operatorFile, victim);
  assert.ok(fs.lstatSync(victim).isSymbolicLink(), "fixture broken: the destination is not a symlink");

  const summary = install(workspace, home, ["claude"]);

  // The operator's target file is untouched...
  assert.equal(fs.readFileSync(operatorFile, "utf8"), operatorBody,
    "the install wrote THROUGH the symlink and destroyed the operator's file");
  // ...the link itself was moved aside, still a link...
  const sidecar = `${victim}${PRESERVED_LOCAL_SUFFIX}`;
  assert.ok(fs.lstatSync(sidecar).isSymbolicLink(), "the preserved copy must still be the symlink");
  assert.equal(fs.readlinkSync(sidecar), operatorFile);
  // ...and the destination is a fresh regular file holding Bob's version.
  assert.ok(fs.lstatSync(victim).isFile(), "the destination must be a real file again");
  assert.equal(
    sha256(fs.readFileSync(victim)),
    sha256(fs.readFileSync(path.join(ROOT, VICTIM_REL))),
    "the destination must hold the shipped version",
  );

  const reported = summary.preservedLocalFiles
    .filter((entry) => entry.original_path === VICTIM_REL.split(path.sep).join("/"));
  assert.equal(reported.length, 1, "the symlinked destination must be named in the summary");
  assert.equal(reported[0].reason, PRESERVE_REASON_SYMLINK);
});

// ---------------------------------------------------------------------------
// 10. THE WHOLESALE mcp/lib REPLACE MUST REFUSE A GUTTED SOURCE.
// ---------------------------------------------------------------------------

test("the mcp/lib replace refuses a source below the runtime-module floor", () => {
  const { workspace, home } = freshWorkspace("libfloor");
  install(workspace, home, ["claude"]);

  const libDir = path.join(workspace, "mcp", "lib");
  const before = fs.readdirSync(libDir).filter((name) => name.endsWith(".js"));
  assert.ok(before.length >= 50,
    `fixture broken: expected >= 50 installed mcp/lib modules, saw ${before.length}`);

  // A source root identical to the repo except that mcp/lib ships one module:
  // an empty extraction, a partial tarball, or a packaging change that moved
  // the modules off the .js/.sh copy predicate. The preservation sweep CANNOT
  // rescue this — it skips every file still matching its recorded digest — so
  // without a floor this wiped 305 modules, preserved 0, warned 0, and
  // reported success.
  const gutted = alternateSourceRoot("libfloor-src", {
    realDirs: ["mcp"],
    mutate(root) {
      const lib = path.join(root, "mcp", "lib");
      fs.unlinkSync(lib);
      fs.mkdirSync(lib);
      fs.writeFileSync(path.join(lib, "only-module.js"), "module.exports = {};\n", "utf8");
    },
  });
  assert.equal(fs.readdirSync(path.join(gutted, "mcp", "lib")).length, 1,
    "fixture broken: the gutted source is not gutted");

  let message = null;
  try {
    installFrom(workspace, home, gutted);
  } catch (error) {
    message = error.message;
  }
  assert.ok(message, "a gutted mcp/lib source was accepted and the installed runtime was wiped");
  assert.ok(message.includes("mcp/lib"), `the refusal must name the tree: ${message}`);
  assert.ok(/\b50\b/u.test(message), `the refusal must name the floor: ${message}`);

  // And it refused BEFORE the destination was destroyed.
  const after = fs.readdirSync(libDir).filter((name) => name.endsWith(".js"));
  assert.equal(after.length, before.length,
    `the installed runtime lost ${before.length - after.length} modules despite the refusal`);

  // POSITIVE CONTROL: the same alternate-source machinery with mcp/lib INTACT
  // installs cleanly, so the throw above is caused by the gutting alone.
  const healthy = alternateSourceRoot("libfloor-ok", { realDirs: ["mcp"] });
  const summary = installFrom(workspace, home, healthy);
  assert.ok(summary.installedFileOwnershipCount >= 300,
    `positive control failed: only ${summary.installedFileOwnershipCount} files recorded`);
  assert.equal(summary.preservedLocalFiles.length, 0,
    `positive control failed: a healthy alternate source preserved ${summary.preservedLocalFiles.length} files`);
});

// ---------------------------------------------------------------------------
// 11. A GENUINE VERSION UPGRADE. Every other integration test here reinstalls
// IDENTICAL bytes and short-circuits before the recorded-digest comparison is
// ever reached, so the receipt is not load-bearing for them. This one changes
// the shipped content and proves the receipt is what keeps the upgrade quiet.
// ---------------------------------------------------------------------------

test("an upgrade whose shipped content changed preserves nothing", () => {
  const { workspace, home } = freshWorkspace("realupgrade");
  const first = install(workspace, home, ["claude"]);
  assert.equal(first.driftGuardRecordedCount, 0,
    "a first install has no previous receipt to read");

  const changed = [];
  const upgraded = alternateSourceRoot("realupgrade-src", {
    realDirs: [".claude/agents", ".claude/rules"],
    mutate(root) {
      for (const relativeDir of [".claude/agents", ".claude/rules"]) {
        const dir = path.join(root, ...relativeDir.split("/"));
        for (const name of fs.readdirSync(dir).filter((entry) => entry.endsWith(".md")).sort().slice(0, 4)) {
          const abs = path.join(dir, name);
          fs.appendFileSync(abs, "\n<!-- shipped in the next release -->\n");
          changed.push(`${relativeDir}/${name}`);
        }
      }
    },
  });
  // Counter + hardcoded floor on the files that ACTUALLY differ, measured from
  // disk rather than from the mutate callback's own bookkeeping.
  let differing = 0;
  for (const relative of changed) {
    const shipped = fs.readFileSync(path.join(upgraded, ...relative.split("/")));
    const installed = fs.readFileSync(path.join(workspace, ...relative.split("/")));
    assert.notEqual(sha256(shipped), sha256(installed), `fixture broken: ${relative} did not change`);
    differing += 1;
  }
  assert.ok(differing >= 5, `expected >= 5 genuinely changed files, saw ${differing}`);

  const second = installFrom(workspace, home, upgraded);

  // The receipt is load-bearing here: the destination matches neither the
  // incoming bytes nor nothing-at-all, so the ONLY thing that keeps the upgrade
  // quiet is the recorded digest from the previous run.
  assert.ok(second.driftGuardRecordedCount >= 300,
    `the previous receipt yielded only ${second.driftGuardRecordedCount} records`);
  assert.equal(second.preservedLocalFiles.length, 0,
    "a real upgrade of untouched files must be silent, preserved: "
    + second.preservedLocalFiles.map((entry) => `${entry.original_path}:${entry.reason}`).join(", "));
  assert.equal(second.driftGuardWarnings.length, 0,
    `the upgrade raised warnings: ${second.driftGuardWarnings.join(" | ")}`);

  let upgradedFiles = 0;
  for (const relative of changed) {
    assert.equal(
      sha256(fs.readFileSync(path.join(workspace, ...relative.split("/")))),
      sha256(fs.readFileSync(path.join(upgraded, ...relative.split("/")))),
      `the new version did not land for ${relative}`,
    );
    assert.ok(!fs.existsSync(path.join(workspace, `${relative}${PRESERVED_LOCAL_SUFFIX}`)),
      `an untouched file was preserved as if it were local work: ${relative}`);
    upgradedFiles += 1;
  }
  assert.ok(upgradedFiles >= 5, `expected >= 5 upgraded files, saw ${upgradedFiles}`);

  // NEGATIVE CONTROL on the same upgrade: edit one of them and the SAME run
  // shape now preserves it, so "zero preserved" above is a real result.
  const victim = path.join(workspace, VICTIM_REL);
  fs.appendFileSync(victim, LOCAL_EDIT);
  const third = installFrom(workspace, home, upgraded);
  assert.equal(third.preservedLocalFiles.length, 1,
    `the negative control preserved ${third.preservedLocalFiles.length} files, expected exactly 1`);
  assert.equal(third.preservedLocalFiles[0].original_path, VICTIM_REL.split(path.sep).join("/"));
});

// ---------------------------------------------------------------------------
// 12. THE TEST FILE'S OWN DISCIPLINE.
// ---------------------------------------------------------------------------

test("sidecarsUnder finds guarded family-B writes under $HOME", () => {
  // Half the guarded family-B writes land under $HOME, not the workspace:
  // adapters/codex/index.js installDirectSkills copies through
  // createSafeInstallFs(home). The stray-sidecar assertion elsewhere scans the
  // workspace only, so this is where sidecarsUnder is exercised in the case it
  // MUST return non-empty — otherwise a broken walk would pass in silence.
  const { workspace, home } = freshWorkspace("homeskills");
  install(workspace, home, ["codex"]);

  const skillsDir = path.join(home, ".codex", "skills");
  const skills = fs.readdirSync(skillsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.ok(skills.length >= 6,
    `expected >= 6 codex skills under $HOME, saw ${skills.length}`);

  // POSITIVE CONTROL for the walker: nothing preserved yet, so it must be empty
  // here and non-empty below. Both directions are asserted.
  assert.equal(sidecarsUnder(home).length, 0,
    "fixture broken: a clean install already left sidecars under $HOME");

  let editedSkills = 0;
  for (const skill of skills) {
    const abs = path.join(skillsDir, skill, "SKILL.md");
    if (!fs.existsSync(abs)) continue;
    fs.appendFileSync(abs, `\n<!-- OPERATOR EDIT ${skill} -->\n`);
    editedSkills += 1;
  }
  assert.ok(editedSkills >= 6, `expected >= 6 editable SKILL.md files, edited ${editedSkills}`);

  const summary = install(workspace, home, ["codex"]);

  const found = sidecarsUnder(home);
  assert.ok(found.length >= editedSkills,
    `sidecarsUnder found ${found.length} preserved copies under $HOME, expected >= ${editedSkills}`);
  let named = 0;
  for (const entry of summary.preservedLocalFiles.filter((item) => item.original_path.includes("/.codex/skills/"))) {
    assert.ok(path.isAbsolute(entry.original_path),
      `a $HOME write must be keyed by absolute path: ${entry.original_path}`);
    named += 1;
  }
  assert.ok(named >= 6, `expected >= 6 preserved $HOME skills in the summary, saw ${named}`);

  // The workspace, meanwhile, holds none of them.
  assert.equal(sidecarsUnder(workspace).length, 0,
    "the $HOME preservation leaked sidecars into the workspace");
});

test("this node's files carry no raw control bytes", () => {
  // A raw NUL landed inside a string literal in install-drift.js in an earlier
  // round. It rendered as a space, made git report the module as `Bin 0 -> 21180
  // bytes` (unreviewable), made BSD grep skip the file entirely while exiting 1
  // (every search over it a false negative), and made the line LIE about what it
  // checked. Control bytes are never legitimate in these files.
  let scanned = 0;
  for (const relative of NODE_FILES) {
    const abs = path.join(ROOT, relative);
    const bytes = fs.readFileSync(abs);
    // Positive control: the file was really read and is really source.
    assert.ok(bytes.length > 1000, `positive control failed: ${relative} is ${bytes.length} bytes`);
    assert.ok(bytes.includes("use strict"), `positive control failed: ${relative} is not source`);
    const offenders = [];
    for (let index = 0; index < bytes.length; index += 1) {
      const byte = bytes[index];
      const printable = byte === 0x09 || byte === 0x0a || byte === 0x0d || byte >= 0x20;
      if (!printable) offenders.push(`${relative}@${index}=0x${byte.toString(16)}`);
    }
    assert.deepEqual(offenders, [],
      `raw control byte(s) in ${relative}: ${offenders.join(", ")}`);
    scanned += 1;
  }
  assert.equal(scanned, NODE_FILES.length);
  assert.ok(scanned >= 4, `expected >= 4 scanned files, scanned ${scanned}`);
});

// ---------------------------------------------------------------------------
// 13. THE MOTIVATING DIRECTORY GETS THE SAME NON-VACUITY FLOOR AS mcp/lib.
// `.claude/agents/**/*` and `.claude/rules/**/*` are package.json globs of the
// same shape as `mcp/lib/**/*.js`, but copyDirFiles has no empty guard and the
// Claude adapter adds none. Before these floors an emptied source installed
// 0 agents, printed "  0 Claude agent definitions", printed "Done." and
// reported success — in the directory report-writer.md lives in.
// ---------------------------------------------------------------------------

// Shared body: empty one globbed Claude resource dir in an alternate source
// root and prove the install REFUSES rather than shipping a hollow Bob.
function assertClaudeResourceFloorRefuses({
  prefix,
  relativeDir,
  repoFloor,
  installFloor,
  messageNeedle,
}) {
  const { workspace, home } = freshWorkspace(prefix);
  install(workspace, home, ["claude"]);

  const parts = relativeDir.split("/");
  // Positive control on the REPO, so a broken glob cannot make this vacuous.
  const repoFiles = fs.readdirSync(path.join(ROOT, ...parts)).filter((n) => n.endsWith(".md"));
  assert.ok(repoFiles.length >= repoFloor,
    `fixture broken: the repo ships ${repoFiles.length} ${relativeDir} files, expected >= ${repoFloor}`);
  // ...and on the freshly installed TARGET.
  const installedDir = path.join(workspace, ...parts);
  const before = fs.readdirSync(installedDir).filter((n) => n.endsWith(".md"));
  assert.ok(before.length >= repoFloor,
    `fixture broken: the install landed ${before.length} ${relativeDir} files, expected >= ${repoFloor}`);

  const emptied = alternateSourceRoot(`${prefix}-src`, {
    realDirs: [relativeDir],
    mutate(root) {
      const dir = path.join(root, ...parts);
      let removed = 0;
      for (const name of fs.readdirSync(dir)) {
        fs.rmSync(path.join(dir, name), { recursive: true, force: true });
        removed += 1;
      }
      assert.ok(removed >= repoFloor,
        `fixture broken: emptying ${relativeDir} removed only ${removed} entries`);
    },
  });
  assert.equal(fs.readdirSync(path.join(emptied, ...parts)).length, 0,
    `fixture broken: ${relativeDir} in the alternate source is not empty`);

  let message = null;
  try {
    installFrom(workspace, home, emptied);
  } catch (error) {
    message = error.message;
  }
  assert.ok(message,
    `an emptied ${relativeDir} source was ACCEPTED: the install shipped a Bob without them and said nothing`);
  assert.ok(message.includes(messageNeedle),
    `the refusal must name the tree: ${message}`);
  // The refusal names the INSTALL floor, which is deliberately BELOW the count
  // the repo ships (see MIN_CLAUDE_AGENT_FILES in scripts/install.js: a floor
  // pinned at the live count turns a legitimate deletion — commit 933df67
  // removed .claude/rules/hunting.md — into a hard install failure). Asserting
  // repoFloor here conflated the two and would silently re-pin them together.
  assert.ok(new RegExp(`\\b${installFloor}\\b`, "u").test(message),
    `the refusal must name the floor ${installFloor}: ${message}`);
  assert.ok(installFloor < repoFloor,
    `the install floor ${installFloor} for ${relativeDir} must sit BELOW the ${repoFloor} files the repo `
    + "ships, or a legitimate removal becomes a misdiagnosed install failure");

  // POSITIVE CONTROL: the same alternate-source machinery with the directory
  // INTACT installs cleanly, so the throw above is caused by the emptying alone.
  const healthy = alternateSourceRoot(`${prefix}-ok`, { realDirs: [relativeDir] });
  const summary = installFrom(workspace, home, healthy);
  assert.ok(summary.agents >= MIN_AGENTS_SHIPPED,
    `positive control failed: only ${summary.agents} agents installed`);
  assert.ok(summary.rules >= MIN_RULES_SHIPPED,
    `positive control failed: only ${summary.rules} rules installed`);
  assert.equal(summary.preservedLocalFiles.length, 0,
    `positive control failed: a healthy alternate source preserved ${summary.preservedLocalFiles.length} files`);
}

// What the REPO ships today. Used as the fixture positive control, so a broken
// glob or a half-extracted checkout cannot make these tests vacuous.
const MIN_AGENTS_SHIPPED = 21;
const MIN_RULES_SHIPPED = 2;
// The floors scripts/install.js hardcodes — deliberately BELOW the shipped
// counts above so a legitimate removal is not a hard install failure. Restated
// here rather than imported so a silent lowering of the constant cannot
// silently lower the test.
const MIN_AGENTS_INSTALL_FLOOR = 15;
const MIN_RULES_INSTALL_FLOOR = 1;

test("the install refuses an emptied .claude/agents source", () => {
  assertClaudeResourceFloorRefuses({
    prefix: "agentfloor",
    relativeDir: ".claude/agents",
    repoFloor: MIN_AGENTS_SHIPPED,
    installFloor: MIN_AGENTS_INSTALL_FLOOR,
    messageNeedle: ".claude/agents",
  });
});

test("the install refuses an emptied .claude/rules source", () => {
  assertClaudeResourceFloorRefuses({
    prefix: "rulefloor",
    relativeDir: ".claude/rules",
    repoFloor: MIN_RULES_SHIPPED,
    installFloor: MIN_RULES_INSTALL_FLOOR,
    messageNeedle: ".claude/rules",
  });
});

// ---------------------------------------------------------------------------
// 14. THE UNGUARDED-ADAPTER-WRITE INVENTORY MUST PIN THINGS THAT STILL EXIST.
// scripts/install.js documents, in a comment above copyFile, which Claude
// adapter writes this file never sees and therefore cannot guard. That comment
// previously cited FIVE line numbers, all of which rotted by exactly +8 the
// moment this node inserted its own writeTextFile seam into the adapter — a
// comment aiming five readers at the wrong line is a false justification in
// source. The citations are now SYMBOLS, and this test is what keeps them true.
//
// ★ THIS TEST ONCE ENSHRINED A HOLE AS A FEATURE. The legacy-skill sweep's raw
// `fs.rmSync(path.join(claudeDir, "skills", legacySkill), {recursive:true})`
// was in the CITED list below, so the one genuinely destructive INSTALL-path
// delete in the adapter was asserted to be intentionally unguarded — while
// every neighbouring delete in the same function already went through the
// guarded removeIfExists. An operator marker in
// .claude/skills/bob-evaluate/SKILL.md was destroyed with no preserved copy
// and no summary line, and this test defended that. It is now guarded through
// the injected removeDirIfExists (proved end-to-end in
// test/install-claude-sweep.test.js), so the inventory must NOT list it — and
// the FORBIDDEN block below keeps it from creeping back in.
//
// What legitimately remains: three UNINSTALL-path deletes of Bob-generated
// config, and the VERSION stamp Bob owns outright. None is an install-path
// write over content an operator can edit and expect to keep.
// ---------------------------------------------------------------------------

test("the unguarded-adapter-write inventory pins symbols that still exist", () => {
  const installJs = fs.readFileSync(path.join(ROOT, "scripts", "install.js"), "utf8");
  const adapterJs = fs.readFileSync(path.join(ROOT, "adapters", "claude", "index.js"), "utf8");
  // Positive controls: both files were really read and are really source.
  assert.ok(installJs.includes("function copyFile("),
    "positive control failed: scripts/install.js has no copyFile");
  assert.ok(adapterJs.includes("function install("),
    "positive control failed: adapters/claude/index.js has no install()");

  // Each entry: the substring the comment cites, which must occur in BOTH the
  // inventory comment and the adapter it describes.
  const CITED = [
    'fs.writeFileSync(path.join(claudeDir, "bob", "VERSION")',
    "fs.rmSync(mcpPath, { force: true });",
    "fs.rmSync(settingsPath, { force: true });",
    "fs.rmSync(configPath, { force: true });",
  ];
  let pinned = 0;
  for (const symbol of CITED) {
    assert.ok(installJs.includes(symbol),
      `the inventory in scripts/install.js no longer cites: ${symbol}`);
    assert.ok(adapterJs.includes(symbol),
      `the inventory cites a symbol that no longer exists in adapters/claude/index.js: ${symbol}`);
    pinned += 1;
  }
  assert.equal(pinned, CITED.length);
  assert.ok(pinned >= 4, `expected >= 4 pinned symbols, pinned ${pinned}`);

  // FORBIDDEN. These are now GUARDED, so listing them again would re-assert a
  // destructive hole as intentional. Each negative is paired with the positive
  // control that proves the guarded replacement is really present — a missing
  // string otherwise cannot distinguish "guarded" from "the whole sweep was
  // deleted" or "my substring was wrong".
  const FORBIDDEN = [
    {
      symbol: 'fs.rmSync(path.join(claudeDir, "skills", legacySkill)',
      replacement: 'removeDirIfExists(path.join(claudeDir, "skills", legacySkill))',
      what: "the LEGACY_BOB_SKILLS sweep",
    },
  ];
  let forbiddenChecked = 0;
  for (const entry of FORBIDDEN) {
    assert.ok(adapterJs.includes(entry.replacement),
      `positive control failed: ${entry.what} does not use its guarded replacement `
      + `(${entry.replacement})`);
    assert.ok(!adapterJs.includes(entry.symbol),
      `${entry.what} is unguarded again in adapters/claude/index.js: ${entry.symbol}`);
    assert.ok(!installJs.includes(entry.symbol),
      `the inventory in scripts/install.js lists a now-GUARDED write as unguarded: ${entry.symbol}`);
    forbiddenChecked += 1;
  }
  assert.ok(forbiddenChecked >= 1, `only ${forbiddenChecked} forbidden symbols were checked`);
  // The guarded remover has to exist and be injected, or the replacement above
  // is a call to nothing.
  assert.ok(installJs.includes("function removeDirIfExists("),
    "scripts/install.js has no removeDirIfExists to inject");
  assert.ok(/\n\s*removeDirIfExists,\n/u.test(installJs),
    "scripts/install.js never injects removeDirIfExists into the Claude adapter");

  // And the enclosing functions the comment names are real.
  let named = 0;
  for (const fn of ["removeMcpConfig", "removeSettingsConfig", "removeGeneratedEgressConfig"]) {
    assert.ok(adapterJs.includes(`function ${fn}(`),
      `the inventory names a function that does not exist: ${fn}`);
    assert.ok(installJs.includes(fn),
      `scripts/install.js's inventory no longer names ${fn}`);
    named += 1;
  }
  assert.ok(named >= 3, `expected >= 3 named functions, saw ${named}`);

  // The inventory must NOT go back to citing adapters/claude/index.js by line
  // number: that is precisely the form that rotted. POSITIVE CONTROL FIRST —
  // a zero-hit search proves nothing unless the same pattern minus the line
  // number does hit, which is what distinguishes "no stale citations" from
  // "my regex was wrong".
  const mentions = [...installJs.matchAll(/adapters\/claude\/index\.js/gu)];
  assert.ok(mentions.length >= 2,
    `positive control failed: the inventory mentions adapters/claude/index.js ${mentions.length} times`);
  const stale = [...installJs.matchAll(/adapters\/claude\/index\.js:(\d+)/gu)].map((m) => m[0]);
  assert.deepEqual(stale, [],
    `scripts/install.js cites adapters/claude/index.js by LINE NUMBER again: ${stale.join(", ")}`);
  // The same rot check, run against the live adapter: every line number the
  // inventory used to carry pointed at a real statement, and after the +8 shift
  // three of them pointed at blank lines. Symbol pinning is what fixes that,
  // so assert the comment actually adopted it.
  assert.ok(installJs.includes("Pinned by SYMBOL"),
    "the inventory no longer states that it pins by symbol");
});

"use strict";

// fix-082-first-upgrade — the drift guard's DEBUT must not be a false alarm.
//
// THE DEFECT, MEASURED BEFORE IT WAS FIXED. No released Bob writes the
// `installed_file_ownership` receipt, so on the first upgrade `recorded` is
// empty and EVERY installed file whose shipped bytes changed in the release
// takes the "no recorded digest -> preserve" branch at once. Against a real
// v2.0.1 -> 2.1.0 upgrade of a throwaway workspace that was:
//
//     273 preserved files      (1 of them an actual operator edit)
//     551 summary lines
//     2.32 MB mcp/lib.bob-local/   holding the PREVIOUS release's modules
//       0 warnings               -- the one warning that could have explained
//                                   it is gated on `declaredRecords > 0`, and
//                                   the no-receipt case is declaredRecords === 0
//
// and the operator was told "Bob did NOT overwrite your changes" about files
// nobody touched, then "Re-apply anything you still want, then delete the
// preserved copies." Followed literally on that 2.32 MB tree, that reinstalls
// the previous release's runtime over the new one.
//
// Preserving all 273 is still correct: with no receipt there is genuinely no
// evidence separating an operator edit from a file the release rewrote, and
// guessing would silently destroy real work. What this node changes is the
// REPORT. The fix must satisfy all three of:
//
//   1. first upgrade, NO operator edits      -> bounded, and never claims the
//                                               operator authored anything
//   2. first upgrade, ONE real edit          -> that file preserved AND named
//   3. the install after the migration       -> completely silent
//
// WHY THE FIXTURE SYNTHESIZES THE RELEASE DELTA. The numbers above came from
// rewinding a source copy to `git archive v2.0.1`, which needs the tag and a
// `.git` directory to exist. This file instead mutates a source copy directly,
// which is deterministic, needs no git, and reproduces the same structural
// situation: N shipped files differ between two installs of a workspace whose
// install.json carries no ownership receipt. The counts are FLOORED below, so a
// fixture that silently failed to produce a release-sized delta cannot let
// these tests pass vacuously.
//
// INVARIANT 4: every install here targets a throwaway directory under
// os.tmpdir(). Nothing in this file may ever be pointed at a real workspace.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const { installProject } = require(path.join(ROOT, "scripts", "install.js"));
const {
  INSTALLED_FILE_OWNERSHIP_KEY,
  MAX_MIGRATION_NAMED_FILES,
  MAX_MIGRATION_NAMED_TREES,
  PRESERVED_LOCAL_SUFFIX,
  createInstallDriftGuard,
  formatPreservedSummary,
  looksLikePreviousInstall,
} = require(path.join(ROOT, "scripts", "lib", "install-drift.js"));

// The file the observed defect actually destroyed, written by FAMILY A
// (scripts/install.js copyFile, injected into adapters/claude/index.js).
const VICTIM = ".claude/agents/report-writer.md";
const OPERATOR_MARK = "<!-- OPERATOR LOCAL EDIT fix-082 -- must survive and be NAMED -->";
const SHIPPED_MARK = "<!-- SHIPPED BY THE NEXT RELEASE -->";

// NON-VACUITY FLOORS. Invariant 6: a check that iterates a collection is
// satisfied by an empty one, so every count below has a hardcoded floor.
const MIN_RELEASE_DELTA = 200;      // shipped files the fixture must change
const MIN_MIGRATION_PRESERVES = 150; // files the first upgrade must preserve
const MIN_RECEIPT_RECORDS = 300;     // records the migration run must write

// The whole point of the fix: the notice is bounded. 551 lines was the defect;
// the fixed run measures 42. The ceiling is deliberately loose so it fails on a
// regression to per-file listing, not on ordinary wording changes.
const MAX_MIGRATION_LINES = 90;

// Sentences the migration notice must NEVER contain: both assert an authorship
// Bob cannot establish, and the second actively instructs a downgrade.
const FALSE_AUTHORSHIP = "Bob did NOT overwrite your changes";
const FALSE_INSTRUCTION = "Re-apply anything you still want";

const TEMP_ROOTS = [];
test.after(() => {
  for (const dir of TEMP_ROOTS) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
});

function throwaway(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bob-first-upgrade-${prefix}-`));
  TEMP_ROOTS.push(dir);
  return dir;
}

function install(workspace, home, sourceRoot) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return installProject(workspace, {
      sourceRoot,
      installerSource: "install.sh",
      adapters: ["claude"],
      onAdapterResolution() {},
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

function readMeta(workspace) {
  return JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
}

// Simulate an install performed by a Bob that predates the ownership receipt.
// Only the installer's own metadata is touched, and only by removing a key an
// older release simply never wrote.
function stripOwnershipReceipt(workspace) {
  const metaPath = path.join(workspace, ".hacker-bob", "install.json");
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  assert.ok(meta[INSTALLED_FILE_OWNERSHIP_KEY], "fixture broken: the install wrote no ownership receipt to strip");
  delete meta[INSTALLED_FILE_OWNERSHIP_KEY];
  fs.writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`, "utf8");
  return meta;
}

function walkFiles(dir, onFile) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      walkFiles(abs, onFile);
    } else if (entry.isFile()) {
      onFile(abs);
    }
  }
}

// ---------------------------------------------------------------------------
// ONE shared sequence, run once, observed by every test below. Five installs
// against two workspaces:
//
//   A: install(old) -> strip receipt -> install(new) -> install(new)
//   B: install(old) -> strip receipt -> EDIT one file -> install(new)
//
// Each test asserts on the recorded observations, so none depends on the order
// the runner happens to pick.
// ---------------------------------------------------------------------------
let SHARED = null;

function migrationRun() {
  if (SHARED) return SHARED;
  const tempRoot = throwaway("run");
  const source = path.join(tempRoot, "source");

  // A REAL source tree. The top-level node_modules must be a real directory
  // (the runtime dependency copier rejects a symlinked ancestry); nested
  // node_modules are never read by the installer, so they are skipped.
  let copied = 0;
  fs.cpSync(ROOT, source, {
    recursive: true,
    dereference: false,
    filter(src) {
      const base = path.basename(src);
      if (base === ".git") return false;
      if (base === "node_modules" && path.dirname(src) !== ROOT) return false;
      copied += 1;
      return true;
    },
  });
  assert.ok(copied >= 2000, `fixture broken: the source copy saw only ${copied} entries`);
  assert.ok(
    fs.statSync(path.join(source, "node_modules")).isDirectory(),
    "fixture broken: the copied source needs a real node_modules directory",
  );

  const workspaceA = path.join(tempRoot, "workspace-a");
  const workspaceB = path.join(tempRoot, "workspace-b");
  const homeA = path.join(tempRoot, "home-a");
  const homeB = path.join(tempRoot, "home-b");
  for (const dir of [workspaceA, workspaceB, homeA, homeB]) fs.mkdirSync(dir, { recursive: true });

  // 1. Both workspaces get "the previous release".
  const seedA = install(workspaceA, homeA, source);
  const seedB = install(workspaceB, homeB, source);
  assert.equal(seedA.preservedLocalFiles.length, 0, "fixture broken: a first install preserved something");
  assert.equal(seedB.preservedLocalFiles.length, 0, "fixture broken: a first install preserved something");

  // 2. Both look like they were installed by a Bob with no ownership receipt.
  const strippedMetaA = stripOwnershipReceipt(workspaceA);
  stripOwnershipReceipt(workspaceB);

  // 3. Exactly ONE genuine operator edit, in workspace B only.
  const victimAbs = path.join(workspaceB, ...VICTIM.split("/"));
  assert.ok(fs.existsSync(victimAbs), `fixture broken: the install never landed ${VICTIM}`);
  fs.appendFileSync(victimAbs, `\n${OPERATOR_MARK}\n`, "utf8");

  // 4. THE NEXT RELEASE. Change the shipped bytes of a release-sized set of
  //    files: every runtime module under mcp/lib and every Claude agent
  //    definition. Appending a comment line is syntactically inert in both.
  let mutated = 0;
  walkFiles(path.join(source, "mcp", "lib"), (abs) => {
    if (!abs.endsWith(".js")) return;
    fs.appendFileSync(abs, `\n// ${SHIPPED_MARK}\n`, "utf8");
    mutated += 1;
  });
  walkFiles(path.join(source, ".claude", "agents"), (abs) => {
    if (!abs.endsWith(".md")) return;
    fs.appendFileSync(abs, `\n${SHIPPED_MARK}\n`, "utf8");
    mutated += 1;
  });
  assert.ok(
    mutated >= MIN_RELEASE_DELTA,
    `fixture broken: the synthetic release changed only ${mutated} files (floor ${MIN_RELEASE_DELTA}); `
    + "without a release-sized delta the assertions below would pass vacuously",
  );

  // 5. THE FIRST UPGRADE, on both workspaces.
  const cleanUpgrade = install(workspaceA, homeA, source);
  const editedUpgrade = install(workspaceB, homeB, source);

  // 6. And the install AFTER the migration.
  const secondInstall = install(workspaceA, homeA, source);

  SHARED = {
    source,
    workspaceA,
    workspaceB,
    mutated,
    strippedMetaA,
    cleanUpgrade,
    editedUpgrade,
    secondInstall,
    cleanLines: formatPreservedSummary(cleanUpgrade.preservedLocalFiles, cleanUpgrade.driftGuardWarnings),
    editedLines: formatPreservedSummary(editedUpgrade.preservedLocalFiles, editedUpgrade.driftGuardWarnings),
    secondLines: formatPreservedSummary(secondInstall.preservedLocalFiles, secondInstall.driftGuardWarnings),
  };
  return SHARED;
}

// ---------------------------------------------------------------------------
// 1. FIRST UPGRADE, NO OPERATOR EDITS. Every preserved file here is one the
//    release rewrote. The run must stay bounded and must not claim otherwise.
// ---------------------------------------------------------------------------

test("a first upgrade with no local edits is bounded and never claims the operator's authorship", () => {
  const run = migrationRun();
  const preserved = run.cleanUpgrade.preservedLocalFiles;
  const lines = run.cleanLines;
  const text = lines.join("\n");

  // POSITIVE CONTROLS. Without these a fix that preserved nothing at all, or a
  // fixture whose receipt was never stripped, would sail through.
  assert.equal(
    run.cleanUpgrade.driftGuardRecordedCount,
    0,
    "fixture broken: the upgrade still read an ownership receipt, so this is not a first upgrade",
  );
  assert.ok(
    preserved.length >= MIN_MIGRATION_PRESERVES,
    `only ${preserved.length} files were preserved (floor ${MIN_MIGRATION_PRESERVES}); `
    + "the release delta did not reach the guard, so nothing below is being tested",
  );
  assert.ok(lines.length > 0, "the migration preserved files and printed nothing at all");

  // THE FIX. 273 preserved files produced 551 lines before this node.
  assert.ok(
    lines.length <= MAX_MIGRATION_LINES,
    `the first-upgrade notice is ${lines.length} lines for ${preserved.length} files `
    + `(ceiling ${MAX_MIGRATION_LINES}). That is the false alarm this node exists to remove.`
    + `\n--- notice ---\n${text}`,
  );
  // The property that actually scales: strictly fewer lines than files.
  assert.ok(
    lines.length < preserved.length,
    `the notice spends ${lines.length} lines on ${preserved.length} files; it is still listing per-file`,
  );

  // Every one of these is unattributable, and every one says so.
  let flagged = 0;
  for (const entry of preserved) {
    assert.equal(
      entry.first_upgrade,
      true,
      `${entry.original_path} was preserved during a first upgrade but not marked as unattributable`,
    );
    flagged += 1;
  }
  assert.equal(flagged, preserved.length);
  assert.ok(flagged >= MIN_MIGRATION_PRESERVES);

  // The two claims that were false. POSITIVE CONTROL FIRST: a zero-hit search
  // proves nothing unless the same haystack demonstrably contains the banner.
  assert.match(
    text,
    /^LOCAL EDITS PRESERVED \(\d+\): FIRST UPGRADE/mu,
    `the notice carries no first-upgrade banner\n--- notice ---\n${text}`,
  );
  assert.ok(
    !text.includes(FALSE_AUTHORSHIP),
    `the notice still claims authorship it cannot establish: ${FALSE_AUTHORSHIP}\n--- notice ---\n${text}`,
  );
  assert.ok(
    !text.includes(FALSE_INSTRUCTION),
    `the notice still tells the operator to re-apply changes they never made: ${FALSE_INSTRUCTION}`
    + `\n--- notice ---\n${text}`,
  );

  // The wholesale-replaced runtime tree is SUMMARIZED, not enumerated, and the
  // notice warns against restoring it.
  const swept = preserved.filter((entry) => entry.preserved_path.includes(`${PRESERVED_LOCAL_SUFFIX}/`));
  assert.ok(
    swept.length >= 100,
    `only ${swept.length} files came from the wholesale mcp/lib replace; the bulk case is not covered`,
  );
  const groupLines = lines.filter((line) => line.includes("diff -rq "));
  assert.ok(
    groupLines.length >= 1,
    `positive control failed: the notice never summarizes a replaced tree\n--- notice ---\n${text}`,
  );
  assert.ok(
    groupLines.length <= MAX_MIGRATION_NAMED_TREES,
    `the notice spends ${groupLines.length} group lines on ${swept.length} swept files`,
  );
  assert.ok(
    groupLines.some((line) => line.includes(`mcp/lib${PRESERVED_LOCAL_SUFFIX}`)),
    `the notice never names the tree it moved the runtime into\n--- notice ---\n${text}`,
  );
  // THE BOUND THAT MATTERS: not one of the swept files is listed individually.
  let namedSwept = 0;
  for (const entry of swept) {
    if (text.includes(entry.preserved_path)) namedSwept += 1;
  }
  assert.equal(
    namedSwept,
    0,
    `${namedSwept} of ${swept.length} wholesale-replaced files were listed one by one`,
  );
  assert.match(text, /do NOT copy one back/u, "the notice does not warn against restoring the previous runtime");
});

// ---------------------------------------------------------------------------
// 2. FIRST UPGRADE, ONE REAL EDIT. Fail-safe is not enough: the operator has to
//    be able to FIND it among the release noise.
// ---------------------------------------------------------------------------

test("a genuinely edited file survives the migration, keeps its bytes, and is named by path", () => {
  const run = migrationRun();
  const text = run.editedLines.join("\n");

  const entries = run.editedUpgrade.preservedLocalFiles.filter((entry) => entry.original_path === VICTIM);
  assert.equal(entries.length, 1, `expected exactly one preserved copy of ${VICTIM}, got ${entries.length}`);
  const entry = entries[0];

  // The bytes are really on disk, at the path the run printed.
  const preservedAbs = path.join(run.workspaceB, ...entry.preserved_path.split("/"));
  assert.ok(fs.existsSync(preservedAbs), `the run named ${entry.preserved_path} but nothing is there`);
  const preservedBody = fs.readFileSync(preservedAbs, "utf8");
  assert.ok(
    preservedBody.includes(OPERATOR_MARK),
    "the preserved copy lost the operator's edit",
  );

  // BOTH paths are printed: without the destination the notice is a hiding
  // place, and without the source the operator cannot tell what was moved.
  assert.ok(text.includes(VICTIM), `the run never named ${VICTIM}\n--- notice ---\n${text}`);
  assert.ok(
    text.includes(entry.preserved_path),
    `the run never said where it put ${VICTIM}\n--- notice ---\n${text}`,
  );

  // ...and the operator still gets the new release at the installed path.
  const installedBody = fs.readFileSync(path.join(run.workspaceB, ...VICTIM.split("/")), "utf8");
  assert.ok(installedBody.includes(SHIPPED_MARK), "the upgrade did not land the new shipped bytes");
  assert.ok(!installedBody.includes(OPERATOR_MARK), "the installed path still holds the operator's edit");
});

// ---------------------------------------------------------------------------
// 3. THE SECOND INSTALL. The migration writes the receipt, so the run after it
//    has evidence for every file and must say nothing at all.
// ---------------------------------------------------------------------------

test("the install after the migration is completely silent", () => {
  const run = migrationRun();

  // POSITIVE CONTROL: silence must come from having evidence, not from having
  // installed nothing.
  const receipt = readMeta(run.workspaceA)[INSTALLED_FILE_OWNERSHIP_KEY];
  assert.ok(receipt, "the migration run wrote no ownership receipt, so the next install cannot be silent");
  assert.ok(
    receipt.files.length >= MIN_RECEIPT_RECORDS,
    `the receipt carries only ${receipt.files.length} records (floor ${MIN_RECEIPT_RECORDS})`,
  );
  assert.ok(
    run.secondInstall.driftGuardRecordedCount >= MIN_RECEIPT_RECORDS,
    `the second install read only ${run.secondInstall.driftGuardRecordedCount} recorded digests `
    + `(floor ${MIN_RECEIPT_RECORDS}); it was not consulting the receipt`,
  );

  assert.deepEqual(
    run.secondInstall.preservedLocalFiles,
    [],
    "the second install preserved something on a clean path",
  );
  assert.deepEqual(
    run.secondInstall.driftGuardWarnings,
    [],
    "the second install reported a drift-guard limit on a clean path",
  );
  assert.deepEqual(run.secondLines, [], `the second install printed: ${run.secondLines.join("\n")}`);

  // Nothing new was set aside on disk either.
  const strays = [];
  walkFiles(run.workspaceA, (abs) => {
    if (abs.includes(PRESERVED_LOCAL_SUFFIX)) strays.push(path.relative(run.workspaceA, abs));
  });
  // The MIGRATION's copies are still there on purpose -- the operator deletes
  // them. What must not grow is the set: the second install adds none, so every
  // stray is one the first upgrade already reported.
  const reported = new Set(run.cleanUpgrade.preservedLocalFiles.map((e) => e.preserved_path));
  const unreported = strays.filter((rel) => !reported.has(rel.split(path.sep).join("/")));
  assert.ok(strays.length >= 1, "positive control failed: the walk found no preserved copies at all");
  assert.deepEqual(
    unreported,
    [],
    `the second install left preserved copies nobody reported: ${unreported.slice(0, 10).join(", ")}`,
  );
});

// ---------------------------------------------------------------------------
// 4. THE TRIGGER ITSELF. "First upgrade" is claimed from a POSITIVE marker of a
//    prior install, not from the absence of the ownership key -- otherwise a
//    fresh install into an empty directory would wear the migration wording.
// ---------------------------------------------------------------------------

test("first-upgrade mode is keyed on a real prior install, not on a missing receipt", () => {
  const run = migrationRun();
  const target = throwaway("trigger");

  // The real thing: an install.json a real install wrote, minus the key an
  // older release never wrote. Pinned against real metadata, not a fixture.
  assert.ok(
    looksLikePreviousInstall(run.strippedMetaA),
    "a real install.json is not recognized as a previous install; the marker fields were renamed",
  );
  assert.equal(
    createInstallDriftGuard({ targetAbs: target, previousMetadata: run.strippedMetaA }).firstUpgrade(),
    true,
    "an install.json from a pre-receipt Bob did not engage first-upgrade mode",
  );

  // A fresh target. scripts/install.js passes null when there is no install.json.
  assert.equal(looksLikePreviousInstall(null), false);
  assert.equal(
    createInstallDriftGuard({ targetAbs: target, previousMetadata: null }).firstUpgrade(),
    false,
    "a fresh install was treated as a migration",
  );

  // Junk that happens to lack the key is not a previous install either.
  let rejected = 0;
  for (const junk of [{}, [], "install.json", 7, { installed_file_ownership: null }, { schema_version: 2 }]) {
    assert.equal(looksLikePreviousInstall(junk), false, `accepted as a previous install: ${JSON.stringify(junk)}`);
    rejected += 1;
  }
  assert.equal(rejected, 6);

  // And a receipt-bearing install is never a migration, however many records.
  assert.equal(
    createInstallDriftGuard({
      targetAbs: target,
      previousMetadata: readMeta(run.workspaceA),
    }).firstUpgrade(),
    false,
    "a workspace that already carries an ownership receipt was treated as a migration",
  );
});

// ---------------------------------------------------------------------------
// 5. THE LISTING BOUND ANNOUNCES ITSELF. The real fixture preserves 24 sidecar
//    copies, under the cap, so the elision branch would otherwise never run --
//    and an unexercised bound is exactly the kind of quiet cap this module
//    forbids. Drive it directly.
// ---------------------------------------------------------------------------

test("the first-upgrade listing bound states what it left out instead of dropping it", () => {
  const OVERFLOW = 7;
  const total = MAX_MIGRATION_NAMED_FILES + OVERFLOW;
  const entries = [];
  for (let index = 0; index < total; index += 1) {
    const original = `.claude/agents/agent-${String(index).padStart(3, "0")}.md`;
    entries.push({
      original_path: original,
      preserved_path: `${original}${PRESERVED_LOCAL_SUFFIX}`,
      reason: "no_recorded_digest",
      first_upgrade: true,
    });
  }
  const lines = formatPreservedSummary(entries, []);
  const text = lines.join("\n");

  const named = entries.filter((entry) => text.includes(entry.preserved_path));
  assert.equal(
    named.length,
    MAX_MIGRATION_NAMED_FILES,
    `the bound named ${named.length} of ${total} files, expected exactly ${MAX_MIGRATION_NAMED_FILES}`,
  );
  assert.ok(
    text.includes(`and ${OVERFLOW} more`),
    `the bound dropped ${OVERFLOW} files without saying so\n--- notice ---\n${text}`,
  );
  assert.match(
    text,
    new RegExp(`find \\. -name '\\*\\${PRESERVED_LOCAL_SUFFIX}\\*'`, "u"),
    "the notice does not give the operator a way to enumerate what it elided",
  );
  assert.ok(!text.includes(FALSE_AUTHORSHIP));
  assert.ok(!text.includes(FALSE_INSTRUCTION));
});

// The same gap on the other axis. A real install replaces exactly one tree
// wholesale (mcp/lib), so the group bound never fires against the live fixture
// either -- and an unexercised bound is how a silent cap gets shipped.
test("the first-upgrade group bound states how many trees it left out", () => {
  const OVERFLOW = 3;
  const total = MAX_MIGRATION_NAMED_TREES + OVERFLOW;
  const entries = [];
  for (let index = 0; index < total; index += 1) {
    const tree = `pkg/tree-${String(index).padStart(3, "0")}`;
    entries.push({
      original_path: `${tree}/module.js`,
      preserved_path: `${tree}${PRESERVED_LOCAL_SUFFIX}/module.js`,
      reason: "no_recorded_digest",
      first_upgrade: true,
    });
  }
  const text = formatPreservedSummary(entries, []).join("\n");

  const named = entries.filter((entry) => text.includes(`${entry.original_path.split("/module.js")[0]}`
    + `${PRESERVED_LOCAL_SUFFIX} `));
  assert.equal(
    named.length,
    MAX_MIGRATION_NAMED_TREES,
    `the bound named ${named.length} of ${total} trees, expected exactly ${MAX_MIGRATION_NAMED_TREES}`,
  );
  assert.ok(
    text.includes(`and ${OVERFLOW} more replaced directories`),
    `the bound dropped ${OVERFLOW} trees without saying so\n--- notice ---\n${text}`,
  );
  // Grouped means grouped: no member file of any tree is listed on its own.
  let individually = 0;
  for (const entry of entries) {
    if (text.includes(entry.preserved_path)) individually += 1;
  }
  assert.equal(individually, 0, `${individually} swept files were listed individually`);
});

// ---------------------------------------------------------------------------
// 6. AN ATTRIBUTABLE PRESERVE IS UNTOUCHED BY ANY OF THIS. The ordinary notice
//    is the one an operator sees on every run after the migration, and it still
//    says exactly what it said.
// ---------------------------------------------------------------------------

test("an attributable preserve keeps the original notice, even alongside a migration", () => {
  const attributed = {
    original_path: ".claude/agents/report-writer.md",
    preserved_path: `.claude/agents/report-writer.md${PRESERVED_LOCAL_SUFFIX}`,
    reason: "locally_modified",
    first_upgrade: false,
  };
  const migrated = {
    original_path: "mcp/lib/waves/wave-scheduler.js",
    preserved_path: `mcp/lib${PRESERVED_LOCAL_SUFFIX}/waves/wave-scheduler.js`,
    reason: "no_recorded_digest",
    first_upgrade: true,
  };

  const aloneText = formatPreservedSummary([attributed], []).join("\n");
  assert.ok(aloneText.includes(FALSE_AUTHORSHIP), "the ordinary notice lost its authorship statement");
  assert.ok(aloneText.includes(FALSE_INSTRUCTION), "the ordinary notice lost its closing advice");
  assert.ok(aloneText.includes(attributed.preserved_path), "the ordinary notice stopped naming the destination");

  // Both sections can coexist: a symlink at an installed path is operator work
  // receipt or no receipt, so a migration run can still produce an attributable
  // preserve. The attributable one comes FIRST so its advice is not buried.
  const bothLines = formatPreservedSummary([attributed, migrated], []);
  const bothText = bothLines.join("\n");
  const ordinaryAt = bothLines.findIndex((line) => line.startsWith("LOCAL EDITS PRESERVED (1): Bob did NOT"));
  const migrationAt = bothLines.findIndex((line) => /^LOCAL EDITS PRESERVED \(1\): FIRST UPGRADE/u.test(line));
  assert.ok(ordinaryAt >= 0, `the ordinary banner is missing\n--- notice ---\n${bothText}`);
  assert.ok(migrationAt >= 0, `the migration banner is missing\n--- notice ---\n${bothText}`);
  assert.ok(ordinaryAt < migrationAt, "the migration section was printed before the attributable one");

  // The counts are per-section, not the combined total: an operator reading
  // "LOCAL EDITS PRESERVED (2): Bob did NOT overwrite your changes" would be
  // told the migration files were theirs.
  assert.ok(!bothText.includes("LOCAL EDITS PRESERVED (2)"), "the two sections were counted as one");

  // And nothing at all when there is nothing to say.
  assert.deepEqual(formatPreservedSummary([], []), []);
});

// ---------------------------------------------------------------------------
// 7. THE OPERATOR HAS TO BE ABLE TO LOOK THIS UP. `.bob-local` files appear on
//    a machine that has never seen them before; a release note is where an
//    operator goes next.
// ---------------------------------------------------------------------------

test("CHANGELOG documents the drift guard and the one-time first upgrade", () => {
  const changelog = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
  // POSITIVE CONTROL: the file was really read and really is the changelog.
  assert.ok(changelog.length > 10000, `positive control failed: CHANGELOG.md is ${changelog.length} bytes`);
  const headings = [...changelog.matchAll(/^## \[[^\]]+\]/gmu)].map((match) => match[0]);
  assert.ok(headings.length >= 4, `positive control failed: found ${headings.length} release headings`);

  // The entry has to live in THIS release's section, not somewhere below it.
  const start = changelog.indexOf("## [2.1.0]");
  assert.ok(start >= 0, "CHANGELOG.md has no 2.1.0 section");
  const next = changelog.indexOf("\n## [", start + 1);
  const section = next === -1 ? changelog.slice(start) : changelog.slice(start, next);
  assert.ok(section.length > 500, `positive control failed: the 2.1.0 section is ${section.length} bytes`);

  let documented = 0;
  for (const needle of [PRESERVED_LOCAL_SUFFIX, "LOCAL EDITS PRESERVED", "installed_file_ownership", "First upgrade"]) {
    assert.ok(section.includes(needle), `the 2.1.0 section never mentions ${needle}`);
    documented += 1;
  }
  assert.equal(documented, 4);
  assert.ok(
    /do not copy a[^\n]*\.bob-local\/[^\n]*tree back/iu.test(section),
    "the changelog does not warn against restoring a preserved runtime tree",
  );
});

"use strict";

// fix-081-claude-legacy-sweep — the TWO destructive paths that survived the
// drift-guard change set, both reproduced live against a throwaway install
// before a line was changed:
//
//   1. adapters/claude/index.js swept LEGACY_BOB_SKILLS with a RAW recursive
//      fs.rmSync while every neighbouring delete in the same function
//      (STALE_HOOK_FILES, LEGACY_AGENT_FILES, LEGACY_HOOK_FILES,
//      LEGACY_BOB_COMMAND_FILES) already went through the guarded
//      removeIfExists. `bob-evaluate` is in that list and was the LIVE skill
//      directory name until the bob-evaluate-runner rename, so real upgraders
//      hit it. An operator marker planted in
//      .claude/skills/bob-evaluate/SKILL.md was GONE after a reinstall: no
//      preserved copy, no summary line, exit 0.
//
//   2. The eight packages/bob-* canonical runtime roots are replaced
//      WHOLESALE (rename the installed root into a backup slot, promote a
//      staged copy, rmSync the backup). 75 marked files across all eight —
//      67 lib/*.js plus a new NOTES.md per package — vanished silently.
//      package-policy.js defines CANONICAL_RUNTIME_OWNED_ROOTS as
//      ["mcp/lib", ...CANONICAL_RUNTIME_PACKAGE_ROOTS]: ONE class of nine, of
//      which only mcp/lib had a sweep.
//
// NON-VACUITY (invariant 6). Every legacy directory below is created PRESENT
// and non-empty before the sweep runs; every collection assertion carries an
// explicit counter and a HARDCODED floor; and test 3 is the deliberate control
// that runs the identical machinery with the directory ABSENT and proves it
// then preserves nothing. A zero-hit search or an empty loop proves nothing.
//
// INVARIANT 4. Every path this file writes to lives under os.tmpdir(). The
// installer is never pointed at a real workspace.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const {
  copyCanonicalRuntimePackages,
  installProject,
  removeDirIfExists,
} = require(path.join(ROOT, "scripts", "install.js"));
const {
  INSTALLED_FILE_OWNERSHIP_KEY,
  PRESERVED_LOCAL_SUFFIX,
  PRESERVE_REASON_MODIFIED,
  PRESERVE_REASON_UNRECORDED,
  formatPreservedSummary,
} = require(path.join(ROOT, "scripts", "lib", "install-drift.js"));
const {
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
} = require(path.join(ROOT, "scripts", "lib", "package-policy.js"));
const { LEGACY_BOB_SKILLS } = require(path.join(ROOT, "adapters", "claude", "index.js"));

// Read from the shipping source, then floored, so a rename or a deletion in
// the adapter cannot quietly empty these tests.
const MIN_LEGACY_CLAUDE_SKILLS = 2;
const MIN_CANONICAL_PACKAGE_ROOTS = 8;
assert.ok(LEGACY_BOB_SKILLS.length >= MIN_LEGACY_CLAUDE_SKILLS,
  `fixture broken: the Claude adapter names ${LEGACY_BOB_SKILLS.length} legacy skills`);
assert.ok(CANONICAL_RUNTIME_PACKAGE_ROOTS.length >= MIN_CANONICAL_PACKAGE_ROOTS,
  `fixture broken: package-policy names ${CANONICAL_RUNTIME_PACKAGE_ROOTS.length} canonical package roots`);
// The specific name the defect report named: LIVE until the recent rename, so
// upgraders really do have this directory on disk.
assert.ok(LEGACY_BOB_SKILLS.includes("bob-evaluate"),
  "fixture broken: bob-evaluate is no longer a swept legacy Claude skill");

const OPERATOR_EDIT = "# OPERATOR LOCAL EDIT — must survive an install sweep\n";

const TEMP_ROOTS = [];

function throwawayDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bob-claudesweep-${prefix}-`));
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

function writeFile(abs, contents) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents, "utf8");
  return abs;
}

// The real installer against a throwaway workspace AND a throwaway HOME.
function install(workspace, home) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return installProject(workspace, {
      sourceRoot: ROOT,
      installerSource: "install.sh",
      onAdapterResolution() {},
      adapters: ["claude"],
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

// A fresh installed workspace, plus its throwaway HOME. Returns the FIRST
// install's summary too, so callers can assert the clean path was clean before
// they perturb it.
function freshInstall(prefix) {
  const workspace = throwawayDir(`${prefix}-ws`);
  const home = throwawayDir(`${prefix}-home`);
  const summary = install(workspace, home);
  assert.deepEqual(summary.preservedLocalFiles, [],
    "the FIRST install into an empty workspace preserved something");
  return { workspace, home, summary };
}

// Every file under `root` whose path carries the preserved marker, with the
// number of files actually visited. An absence claim needs a walk that
// demonstrably ran; `visited` is that positive control.
function scanPreserved(root) {
  const hits = [];
  let visited = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules") continue;
        walk(abs);
        continue;
      }
      visited += 1;
      if (abs.includes(PRESERVED_LOCAL_SUFFIX)) hits.push(path.relative(root, abs));
    }
  };
  if (fs.existsSync(root)) walk(root);
  return { hits: hits.sort(), visited };
}

function countFilesUnder(dir) {
  if (!fs.existsSync(dir)) return 0;
  let total = 0;
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else total += 1;
    }
  };
  walk(dir);
  return total;
}

// ---------------------------------------------------------------------------
// 1. THE CLAUDE LEGACY-SKILL SWEEP. Directory PRESENT and holding operator work.
// ---------------------------------------------------------------------------

test("the Claude legacy-skill sweep preserves an operator-edited skill tree", () => {
  const { workspace, home } = freshInstall("legacyskill");
  const legacyDir = path.join(workspace, ".claude", "skills", "bob-evaluate");

  // PRESENT and non-empty. A sweep of an absent directory proves nothing —
  // which is exactly how the unguarded rmSync survived review.
  const seeded = [
    writeFile(path.join(legacyDir, "SKILL.md"), `${OPERATOR_EDIT}legacy orchestrator body\n`),
    writeFile(path.join(legacyDir, "notes.md"), `${OPERATOR_EDIT}notes\n`),
    writeFile(path.join(legacyDir, "reference", "guide.md"), `${OPERATOR_EDIT}guide\n`),
  ];
  const MIN_SEEDED = 3;
  assert.ok(seeded.length >= MIN_SEEDED,
    `fixture broken: seeded ${seeded.length} files, floor ${MIN_SEEDED}`);
  assert.equal(countFilesUnder(legacyDir), seeded.length,
    "fixture broken: the legacy tree on disk does not match what was seeded");

  const summary = install(workspace, home);

  // The sweep still does its job: the stale skill is GONE from the directory
  // Claude Code scans.
  assert.equal(fs.existsSync(legacyDir), false,
    "the legacy skill directory survived the sweep");

  // ...and every byte the operator wrote is still on disk, and SAID SO.
  const preserved = summary.preservedLocalFiles
    .filter((entry) => entry.original_path.includes(path.join(".claude", "skills", "bob-evaluate")));
  assert.ok(preserved.length >= MIN_SEEDED,
    `only ${preserved.length} of ${seeded.length} legacy-skill files were preserved`);
  let checked = 0;
  for (const entry of preserved) {
    assert.equal(entry.reason, PRESERVE_REASON_UNRECORDED,
      `unexpected preserve reason for ${entry.original_path}: ${entry.reason}`);
    const abs = path.join(workspace, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy is missing: ${entry.preserved_path}`);
    assert.ok(fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `preserved copy lost the operator's bytes: ${entry.preserved_path}`);
    checked += 1;
  }
  assert.ok(checked >= MIN_SEEDED, `only ${checked} preserved copies were verified`);

  // LOUD is the requirement (invariant 1): the operator must be told.
  const lines = formatPreservedSummary(summary.preservedLocalFiles, summary.driftGuardWarnings);
  assert.ok(lines.some((line) => line.includes("LOCAL EDITS PRESERVED")),
    "the install printed no LOCAL EDITS PRESERVED notice");
  assert.ok(lines.some((line) => line.includes(path.join(".claude", "skills", "bob-evaluate"))),
    "the summary never names the legacy skill path it preserved");
  assert.deepEqual(summary.driftGuardWarnings, [],
    `the guard reported limits: ${summary.driftGuardWarnings.join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 2. THE QUARANTINE MUST NOT RESURRECT THE SWEPT SKILL.
// A sibling `.claude/skills/bob-evaluate.bob-local/SKILL.md` is still inside
// the directory Claude Code scans for skills, so it would reinstate the exact
// stale skill the sweep exists to retire under a new name. Family B reached
// this conclusion for $CODEX_HOME/skills; family A must match it.
// ---------------------------------------------------------------------------

test("a preserved legacy Claude skill tree lands outside every scanned directory", () => {
  const { workspace, home } = freshInstall("quarantine");
  const skillsRoot = path.join(workspace, ".claude", "skills");
  const legacyDir = path.join(skillsRoot, "bob-evaluate");
  writeFile(path.join(legacyDir, "SKILL.md"), `${OPERATOR_EDIT}legacy body\n`);
  writeFile(path.join(legacyDir, "reference", "guide.md"), `${OPERATOR_EDIT}guide\n`);
  assert.equal(countFilesUnder(legacyDir), 2, "fixture broken: legacy tree is not 2 files");

  const summary = install(workspace, home);
  assert.ok(summary.preservedLocalFiles.length >= 2,
    `positive control failed: only ${summary.preservedLocalFiles.length} files preserved`);

  // Nothing carrying the preserved marker may sit under the scanned skills
  // root. The walk's `visited` count is the positive control that this is a
  // real absence and not an empty directory.
  const scan = scanPreserved(skillsRoot);
  assert.ok(scan.visited >= 4,
    `positive control failed: the scan of ${skillsRoot} visited only ${scan.visited} files`);
  assert.deepEqual(scan.hits, [],
    `a preserved copy is loadable from the scanned skills root: ${scan.hits.join(", ")}`);

  // No directory under .claude/skills may hold a SKILL.md that is not a
  // currently-shipped skill.
  let scannedSkillDirs = 0;
  for (const entry of fs.readdirSync(skillsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    scannedSkillDirs += 1;
    assert.ok(!entry.name.includes(PRESERVED_LOCAL_SUFFIX),
      `a quarantine directory is inside the scanned skills root: ${entry.name}`);
  }
  assert.ok(scannedSkillDirs >= 3,
    `positive control failed: only ${scannedSkillDirs} skill directories were scanned`);

  // And the copies really are on disk, outside that root, under ONE quarantine.
  let outside = 0;
  for (const entry of summary.preservedLocalFiles) {
    const abs = path.join(workspace, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy missing: ${entry.preserved_path}`);
    assert.ok(!abs.startsWith(`${skillsRoot}${path.sep}`),
      `preserved copy landed inside the scanned skills root: ${entry.preserved_path}`);
    assert.ok(entry.preserved_path.startsWith(PRESERVED_LOCAL_SUFFIX),
      `preserved copy is not under the ${PRESERVED_LOCAL_SUFFIX} quarantine: ${entry.preserved_path}`);
    outside += 1;
  }
  assert.ok(outside >= 2, `only ${outside} preserved copies were located`);
});

// ---------------------------------------------------------------------------
// 3. THE CONTROL. Same machinery, directory ABSENT (the modern tree) and the
// clean path untouched. Invariants 2 and 3: a second install with no local
// edits changes nothing and says nothing.
// ---------------------------------------------------------------------------

test("a clean reinstall with no legacy skill directory preserves nothing and says nothing", () => {
  const { workspace, home } = freshInstall("control");
  const skillsRoot = path.join(workspace, ".claude", "skills");

  // The precondition that makes this a CONTROL and not a duplicate of test 1.
  let absent = 0;
  for (const legacySkill of LEGACY_BOB_SKILLS) {
    assert.equal(fs.existsSync(path.join(skillsRoot, legacySkill)), false,
      `fixture broken: a modern install shipped legacy skill ${legacySkill}`);
    absent += 1;
  }
  assert.ok(absent >= MIN_LEGACY_CLAUDE_SKILLS,
    `positive control failed: checked only ${absent} legacy skill names`);

  const before = countFilesUnder(workspace);
  assert.ok(before >= 300, `positive control failed: the install left only ${before} files`);

  const summary = install(workspace, home);

  assert.deepEqual(summary.preservedLocalFiles, [],
    `a clean reinstall preserved ${summary.preservedLocalFiles.length} files`);
  assert.deepEqual(summary.driftGuardWarnings, [],
    `a clean reinstall warned: ${summary.driftGuardWarnings.join(" | ")}`);
  assert.deepEqual(formatPreservedSummary(summary.preservedLocalFiles, summary.driftGuardWarnings), [],
    "a clean reinstall printed a preservation notice");
  // The receipt was really read — a silently-rejected receipt would make every
  // destination look local, and this test would pass for the wrong reason if
  // the guard simply never ran.
  assert.ok(summary.driftGuardRecordedCount >= 300,
    `the reinstall read only ${summary.driftGuardRecordedCount} records from the previous receipt`);
  const scan = scanPreserved(workspace);
  assert.ok(scan.visited >= 300, `positive control failed: scan visited ${scan.visited} files`);
  assert.deepEqual(scan.hits, [],
    `a clean reinstall left preserved copies on disk: ${scan.hits.slice(0, 5).join(", ")}`);
  assert.equal(countFilesUnder(workspace), before,
    "a clean reinstall changed the installed file count");
});

// ---------------------------------------------------------------------------
// 4. THE CALL SITE ITSELF. The raw recursive rmSync must be GONE from the
// adapter, and the guarded twin must be a REQUIRED injection — a defaulted one
// could only fall back to the unguarded rmSync this test exists to forbid.
// Every negative assertion below is paired with a positive control proving the
// file was really read.
// ---------------------------------------------------------------------------

test("the Claude adapter routes its legacy-skill sweep through the guarded directory remover", () => {
  const adapterJs = fs.readFileSync(path.join(ROOT, "adapters", "claude", "index.js"), "utf8");
  const installJs = fs.readFileSync(path.join(ROOT, "scripts", "install.js"), "utf8");
  // POSITIVE CONTROLS: both files were really read and really are the source.
  assert.ok(adapterJs.includes("function install("),
    "positive control failed: adapters/claude/index.js has no install()");
  assert.ok(adapterJs.includes("for (const legacySkill of LEGACY_BOB_SKILLS) {"),
    "positive control failed: the adapter has no LEGACY_BOB_SKILLS sweep at all");
  assert.ok(installJs.includes("function removeDirIfExists("),
    "positive control failed: scripts/install.js has no removeDirIfExists");

  // The defect, verbatim.
  assert.ok(!adapterJs.includes('fs.rmSync(path.join(claudeDir, "skills", legacySkill)'),
    "adapters/claude/index.js still sweeps legacy skills with a raw recursive fs.rmSync");
  // ...and the replacement is really there.
  assert.ok(adapterJs.includes('removeDirIfExists(path.join(claudeDir, "skills", legacySkill))'),
    "the legacy-skill sweep does not call removeDirIfExists");

  // REQUIRED injection, not a defaulted fallback. `removeDirIfExists,` in the
  // destructured parameter list with no `=` is what makes a missing injection
  // a loud TypeError instead of a silent unguarded delete.
  assert.ok(/\n\s*removeDirIfExists,\n/u.test(adapterJs),
    "removeDirIfExists is not a required (undefaulted) install() parameter");
  assert.ok(!/removeDirIfExists\s*=/u.test(adapterJs),
    "removeDirIfExists has a fallback default, which would be an unguarded rmSync");
  // scripts/install.js must actually pass it.
  assert.ok(/\n\s*removeDirIfExists,\n/u.test(installJs),
    "scripts/install.js never injects removeDirIfExists into the Claude adapter");

  // The guard is load-bearing, not decorative: with no install in flight the
  // recursive remove REFUSES rather than deleting unprotected.
  const root = throwawayDir("disarmed");
  const doomed = path.join(root, ".claude", "skills", "bob-evaluate");
  writeFile(path.join(doomed, "SKILL.md"), OPERATOR_EDIT);
  assert.throws(
    () => removeDirIfExists(doomed),
    /drift guard disarmed/u,
    "removeDirIfExists deleted a directory tree with no guard armed",
  );
  assert.equal(fs.existsSync(path.join(doomed, "SKILL.md")), true,
    "the refused remove destroyed the tree anyway");
});

// ---------------------------------------------------------------------------
// 5. THE EIGHT CANONICAL RUNTIME PACKAGE ROOTS. Replaced wholesale, guarded by
// exactly nothing before this change. Marked lib/*.js in EVERY root plus a new
// file with no source counterpart at all.
// ---------------------------------------------------------------------------

test("the canonical runtime package replace preserves operator work in every root", () => {
  const { workspace, home } = freshInstall("packages");
  const packagesDir = path.join(workspace, "packages");

  const marked = [];
  const newFiles = [];
  let rootsTouched = 0;
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const installedRoot = path.join(workspace, relativeRoot);
    assert.equal(fs.existsSync(installedRoot), true,
      `fixture broken: the install did not create ${relativeRoot}`);
    const libDir = path.join(installedRoot, "lib");
    if (fs.existsSync(libDir)) {
      for (const name of fs.readdirSync(libDir).filter((n) => n.endsWith(".js")).sort()) {
        const abs = path.join(libDir, name);
        fs.writeFileSync(abs, OPERATOR_EDIT + fs.readFileSync(abs, "utf8"), "utf8");
        marked.push(abs);
      }
    }
    // A file with NO source counterpart and NO ownership record: pure operator
    // work, the case a source-identity comparison alone can never rescue.
    newFiles.push(writeFile(path.join(installedRoot, "NOTES.md"), `${OPERATOR_EDIT}operator notes\n`));
    rootsTouched += 1;
  }
  const MIN_MARKED = 8;
  assert.ok(rootsTouched >= MIN_CANONICAL_PACKAGE_ROOTS,
    `fixture broken: only ${rootsTouched} canonical roots were seeded`);
  assert.ok(marked.length >= MIN_MARKED,
    `fixture broken: only ${marked.length} lib modules were marked`);
  assert.equal(newFiles.length, rootsTouched, "fixture broken: one NOTES.md per root");

  const summary = install(workspace, home);

  // Every marked path was replaced with Bob's version (the install still works)...
  let replaced = 0;
  for (const abs of marked) {
    assert.equal(fs.existsSync(abs), true, `the replace dropped a runtime module: ${abs}`);
    assert.ok(!fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `the replace never actually ran for ${abs}`);
    replaced += 1;
  }
  assert.ok(replaced >= MIN_MARKED, `only ${replaced} modules were replaced`);

  // ...and every byte of operator work is preserved, named, and readable.
  const preserved = summary.preservedLocalFiles
    .filter((entry) => entry.original_path.startsWith("packages/")
      || entry.original_path.startsWith(`packages${path.sep}`));
  assert.ok(preserved.length >= marked.length + newFiles.length,
    `preserved ${preserved.length} package files, expected at least ${marked.length + newFiles.length}`);
  let verified = 0;
  let modifiedReason = 0;
  let unrecordedReason = 0;
  for (const entry of preserved) {
    const abs = path.join(workspace, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy missing: ${entry.preserved_path}`);
    assert.ok(fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `preserved copy lost the operator's bytes: ${entry.preserved_path}`);
    if (entry.reason === PRESERVE_REASON_MODIFIED) modifiedReason += 1;
    else if (entry.reason === PRESERVE_REASON_UNRECORDED) unrecordedReason += 1;
    else assert.fail(`unexpected preserve reason ${entry.reason} for ${entry.original_path}`);
    verified += 1;
  }
  assert.ok(verified >= MIN_MARKED, `only ${verified} preserved package copies were verified`);
  // The marked lib modules were RECORDED by the first install, so they come
  // back as locally_modified, not as unrecorded. That distinction is the proof
  // the ownership receipt covers these roots at all.
  assert.ok(modifiedReason >= MIN_MARKED,
    `only ${modifiedReason} preserved package files were flagged locally_modified`);
  assert.ok(unrecordedReason >= rootsTouched,
    `only ${unrecordedReason} preserved package files were flagged no_recorded_digest`);

  // Loud, and pointing at packages/.
  const lines = formatPreservedSummary(summary.preservedLocalFiles, summary.driftGuardWarnings);
  assert.ok(lines.some((line) => line.includes("LOCAL EDITS PRESERVED")),
    "the install printed no LOCAL EDITS PRESERVED notice for the package replace");
  assert.ok(lines.some((line) => line.includes("packages/") || line.includes(`packages${path.sep}`)),
    "the summary never names a packages/ path it preserved");
  assert.deepEqual(summary.driftGuardWarnings, [],
    `the guard reported limits: ${summary.driftGuardWarnings.join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 6. THE RECEIPT. Without ownership records for the promoted package files,
// the sweep in test 5 has nothing to compare against and the FIRST upgrade
// that legitimately changes a lib module would preserve it as local work — a
// sidecar for work the operator never did, on every release. So assert the
// records exist and match the bytes on disk.
// ---------------------------------------------------------------------------

test("the canonical runtime package promotion records its files in the ownership receipt", () => {
  const { workspace, summary } = freshInstall("receipt");
  // The NEUTRAL receipt, not the adapter-local .claude/bob/install.json stamp:
  // installed_file_ownership lives with the adapter-agnostic install metadata.
  const metadataPath = path.join(workspace, ".hacker-bob", "install.json");
  assert.equal(fs.existsSync(metadataPath), true, "the install wrote no neutral install.json");
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  const ownership = metadata[INSTALLED_FILE_OWNERSHIP_KEY];
  assert.ok(ownership && Array.isArray(ownership.files),
    `install.json carries no ${INSTALLED_FILE_OWNERSHIP_KEY}.files array`);
  assert.ok(ownership.files.length >= 300,
    `positive control failed: the receipt holds only ${ownership.files.length} records`);

  const crypto = require("node:crypto");
  const byPath = new Map(ownership.files.map((record) => [record.path, record]));
  let rootsCovered = 0;
  let filesChecked = 0;
  for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
    const key = `${relativeRoot.split(path.sep).join("/")}/package.json`;
    const record = byPath.get(key);
    assert.ok(record, `the receipt has no record for ${key}`);
    const abs = path.join(workspace, ...key.split("/"));
    const digest = crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
    assert.equal(record.sha256, digest, `the receipt digest for ${key} does not match the file on disk`);
    assert.equal(record.byte_size, fs.statSync(abs).size, `the receipt size for ${key} is wrong`);
    filesChecked += 1;
    rootsCovered += 1;
  }
  assert.ok(rootsCovered >= MIN_CANONICAL_PACKAGE_ROOTS,
    `only ${rootsCovered} canonical roots are covered by the receipt`);

  // At least one lib module per shipped root, so the receipt is not just
  // package.json manifests.
  let libRecords = 0;
  for (const record of ownership.files) {
    if (/^packages\/bob-[^/]+\/lib\/[^/]+\.js$/u.test(record.path)) libRecords += 1;
  }
  assert.ok(libRecords >= MIN_CANONICAL_PACKAGE_ROOTS,
    `the receipt holds only ${libRecords} packages/bob-*/lib/*.js records`);
  assert.ok(filesChecked >= MIN_CANONICAL_PACKAGE_ROOTS, `only ${filesChecked} receipt records were checked`);
  assert.ok(summary.installedFileOwnershipCount >= ownership.files.length,
    "the summary's ownership count disagrees with the receipt on disk");
});

// ---------------------------------------------------------------------------
// 7. THE DISARMED REFUSAL ON THE PACKAGE PATH. Same positive control as the
// mcp/lib replace: guardBeforeTreeReplace returns [] both when it preserved
// nothing and when no guard is armed, and the next statement destroys a tree.
// ---------------------------------------------------------------------------

test("the canonical runtime package replace refuses to run with the drift guard disarmed", () => {
  const { workspace } = freshInstall("disarmedpkg");
  const probeRoot = CANONICAL_RUNTIME_PACKAGE_ROOTS[0];
  const marker = path.join(workspace, probeRoot, "NOTES.md");
  writeFile(marker, `${OPERATOR_EDIT}operator notes\n`);
  assert.equal(fs.existsSync(path.join(workspace, probeRoot)), true,
    "fixture broken: the probe package root is absent");

  // Called OUTSIDE installProject, so no ambient guard is armed.
  assert.throws(
    () => copyCanonicalRuntimePackages(ROOT, workspace, null),
    /drift guard disarmed/u,
    "the canonical package replace ran with no guard armed",
  );
  assert.equal(fs.existsSync(marker), true,
    "the refused replace destroyed the operator's file anyway");
  assert.ok(fs.readFileSync(marker, "utf8").startsWith(OPERATOR_EDIT),
    "the refused replace rewrote the operator's file");
});

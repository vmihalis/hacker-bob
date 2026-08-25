"use strict";

// drf-025-delete-guard — FAMILY B's delete surface.
//
// drf-020 guarded the WRITE surface of both copy families and the DELETE
// surface of family A (scripts/install.js removeIfExists :1959, and the
// wholesale mcp/lib replace :2141). Family B — scripts/lib/install-fs.js,
// used by the codex, kimi and generic-mcp adapters — kept deleting straight
// through to fs.rmSync. A delete destroys local work exactly like an
// overwrite, so this file proves the SAME guard now covers both shapes:
//
//   removePath(file)                 -> guardBeforeDelete       (sidecar)
//   removePath(dir, {recursive:true}) -> guardBeforeTreeReplace (quarantine)
//   removeDirContents(dir)            -> the recursive path, per child
//
// NON-VACUITY. The failure this graph has hit at every layer is a loop that
// runs zero times and reports success — scripts/install.js:1931-1935 names the
// exact trap for this very sweep. So every collection assertion below carries
// an explicit COUNTER and a HARDCODED FLOOR, every legacy directory is created
// PRESENT and non-empty before the sweep runs, and test 7 is the deliberate
// control that runs the identical machinery with the directory ABSENT and
// proves it then preserves nothing.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const { installProject } = require(path.join(ROOT, "scripts", "install.js"));
const { createSafeInstallFs } = require(path.join(ROOT, "scripts", "lib", "install-fs.js"));
const {
  PRESERVED_LOCAL_SUFFIX,
  PRESERVE_REASON_UNRECORDED,
  beginInstallDriftGuard,
} = require(path.join(ROOT, "scripts", "lib", "install-drift.js"));
const { LEGACY_SKILL_DIRS } = require(path.join(ROOT, "adapters", "codex", "index.js"));
const { STALE_HOOK_FILES } = require(path.join(ROOT, "adapters", "kimi", "index.js"));
const { LEGACY_BOB_SKILLS } = require(path.join(ROOT, "adapters", "kimi", "config.js"));

// The exact legacy names the real adapters sweep. Read from the adapters, then
// floored, so a rename in the adapter cannot quietly empty these tests.
const MIN_CODEX_LEGACY_SKILL_DIRS = 5;
const MIN_KIMI_LEGACY_SKILLS = 1;
const MIN_KIMI_STALE_HOOKS = 1;
assert.ok(LEGACY_SKILL_DIRS.length >= MIN_CODEX_LEGACY_SKILL_DIRS,
  `fixture broken: the codex adapter names ${LEGACY_SKILL_DIRS.length} legacy skill dirs`);
assert.ok(LEGACY_BOB_SKILLS.length >= MIN_KIMI_LEGACY_SKILLS,
  `fixture broken: the kimi adapter names ${LEGACY_BOB_SKILLS.length} legacy skills`);
assert.ok(STALE_HOOK_FILES.length >= MIN_KIMI_STALE_HOOKS,
  `fixture broken: the kimi adapter names ${STALE_HOOK_FILES.length} stale hooks`);

const CODEX_LEGACY_SKILL = LEGACY_SKILL_DIRS[LEGACY_SKILL_DIRS.length - 1];
const KIMI_LEGACY_SKILL = LEGACY_BOB_SKILLS[LEGACY_BOB_SKILLS.length - 1];
const KIMI_STALE_HOOK = STALE_HOOK_FILES[0];

const OPERATOR_EDIT = "# OPERATOR LOCAL EDIT — must survive an install sweep\n";

const TEMP_ROOTS = [];

// INVARIANT 4: every path this file writes to lives under os.tmpdir(). Nothing
// here may ever be pointed at a real workspace.
function throwawayDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bob-delguard-${prefix}-`));
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

// Every path under `root` whose name carries the preserved marker, with a
// counter the caller floors. Also the tool used to prove the ABSENCE of strays
// on the clean path — an absence claim needs a walk that demonstrably ran, so
// this returns the total number of files visited alongside the hits.
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

// Arm the ambient guard, run `body`, always disarm. The guard is process-scoped,
// so a test that threw while armed would poison every test after it.
//
// The `return` deliberately sits OUTSIDE the finally. Returning from a finally
// block SWALLOWS whatever the try threw, which would hand every caller
// `preserved: []` — indistinguishable from a clean run, and a silent pass for
// exactly the assertions test 4 makes. Disarm in the finally; return after it.
function withArmedGuard(targetAbs, body) {
  const session = beginInstallDriftGuard({ targetAbs, previousMetadata: null });
  let result;
  let ended;
  try {
    result = body();
  } finally {
    ended = session.end();
  }
  return { result, ...ended };
}

// The real installer, against a throwaway workspace AND a throwaway HOME (the
// codex adapter writes under $CODEX_HOME, which resolves through os.homedir()).
function install(workspace, home, adapters) {
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    return installProject(workspace, {
      sourceRoot: ROOT,
      installerSource: "install.sh",
      onAdapterResolution() {},
      adapters,
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

// ---------------------------------------------------------------------------
// 1. RECURSIVE DELETE. The legacy directory is PRESENT and holds operator work.
// ---------------------------------------------------------------------------

test("a family-B recursive delete preserves an operator-edited legacy skill tree", () => {
  const root = throwawayDir("recursive");
  const skillsRoot = path.join(root, "skills");
  const legacyDir = path.join(skillsRoot, CODEX_LEGACY_SKILL);

  // PRESENT and non-empty. A sweep of an absent directory proves nothing.
  const seeded = [
    writeFile(path.join(legacyDir, "SKILL.md"), OPERATOR_EDIT),
    writeFile(path.join(legacyDir, "notes.md"), `${OPERATOR_EDIT}notes\n`),
    writeFile(path.join(legacyDir, "nested", "helper.sh"), `${OPERATOR_EDIT}helper\n`),
  ];
  const MIN_SEEDED = 3;
  assert.ok(seeded.length >= MIN_SEEDED,
    `fixture broken: seeded ${seeded.length} files, floor ${MIN_SEEDED}`);
  assert.equal(countFilesUnder(legacyDir), seeded.length,
    "fixture broken: the legacy tree on disk does not match what was seeded");

  const { preserved, warnings } = withArmedGuard(root, () => {
    createSafeInstallFs(root, { label: "delete-guard root" })
      .removePath(legacyDir, { recursive: true });
  });

  // The sweep still did its job: the stale skill is GONE from the scanned root.
  assert.equal(fs.existsSync(legacyDir), false,
    "the legacy skill directory survived the sweep");
  assert.equal(countFilesUnder(skillsRoot), 0,
    `the scanned skills root still holds ${countFilesUnder(skillsRoot)} files after the sweep`);

  // ...and every byte of the operator's work is still on disk.
  assert.ok(preserved.length >= MIN_SEEDED,
    `only ${preserved.length} of ${seeded.length} files were preserved`);
  let checked = 0;
  for (const entry of preserved) {
    assert.equal(entry.reason, PRESERVE_REASON_UNRECORDED,
      `unexpected preserve reason for ${entry.original_path}: ${entry.reason}`);
    const abs = path.join(root, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy is missing: ${entry.preserved_path}`);
    assert.ok(fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `preserved copy lost the operator's bytes: ${entry.preserved_path}`);
    checked += 1;
  }
  assert.ok(checked >= MIN_SEEDED, `only ${checked} preserved copies were verified`);
  assert.deepEqual(warnings, [], `the guard reported limits: ${warnings.join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 2. THE QUARANTINE MUST NOT RESURRECT THE SWEPT SKILL.
// A sibling `<dir>.bob-local` would leave a loadable SKILL.md inside the
// directory the host scans, reinstating the exact stale skill the sweep exists
// to retire. This is the directory-shaped twin of the `.md` reasoning at
// scripts/lib/install-drift.js:52-55.
// ---------------------------------------------------------------------------

test("a preserved legacy skill tree lands outside every scanned directory", () => {
  const root = throwawayDir("quarantine");
  const skillsRoot = path.join(root, "skills");
  const legacyDir = path.join(skillsRoot, CODEX_LEGACY_SKILL);
  writeFile(path.join(legacyDir, "SKILL.md"), OPERATOR_EDIT);
  writeFile(path.join(legacyDir, "reference", "guide.md"), OPERATOR_EDIT);

  const { preserved } = withArmedGuard(root, () => {
    createSafeInstallFs(root, { label: "delete-guard root" })
      .removePath(legacyDir, { recursive: true });
  });

  const MIN_PRESERVED = 2;
  assert.ok(preserved.length >= MIN_PRESERVED,
    `only ${preserved.length} files preserved, floor ${MIN_PRESERVED}`);

  const quarantine = path.join(root, PRESERVED_LOCAL_SUFFIX);
  let inQuarantine = 0;
  for (const entry of preserved) {
    const abs = path.resolve(root, entry.preserved_path);
    assert.ok(abs.startsWith(`${quarantine}${path.sep}`),
      `preserved copy is not in the quarantine root: ${entry.preserved_path}`);
    assert.equal(abs.startsWith(`${skillsRoot}${path.sep}`), false,
      `preserved copy was left inside the SCANNED skills root and would load as a live skill: ${entry.preserved_path}`);
    inQuarantine += 1;
  }
  assert.ok(inQuarantine >= MIN_PRESERVED,
    `only ${inQuarantine} preserved paths were location-checked`);

  // The scanned root must hold nothing loadable at all — not the original
  // directory, and not a `.bob-local`-suffixed sibling of it.
  const survivors = fs.existsSync(skillsRoot) ? fs.readdirSync(skillsRoot) : [];
  assert.deepEqual(survivors, [],
    `the scanned skills root still holds ${survivors.length} entries: ${survivors.join(", ")}`);
});

// ---------------------------------------------------------------------------
// 3. SINGLE-FILE DELETE — the kimi stale-hook / codex stale-command shape.
// ---------------------------------------------------------------------------

test("a family-B single-file delete preserves an operator-authored file", () => {
  const root = throwawayDir("singlefile");
  const hooksDir = path.join(root, "hooks");
  const targets = [KIMI_STALE_HOOK, "another-stale.sh"];
  const MIN_TARGETS = 2;
  assert.ok(targets.length >= MIN_TARGETS,
    `fixture broken: ${targets.length} targets, floor ${MIN_TARGETS}`);
  for (const name of targets) writeFile(path.join(hooksDir, name), `${OPERATOR_EDIT}${name}\n`);

  const { preserved, warnings } = withArmedGuard(root, () => {
    const installFs = createSafeInstallFs(root, { label: "delete-guard root" });
    for (const name of targets) installFs.removePath(path.join(hooksDir, name));
  });

  assert.ok(preserved.length >= MIN_TARGETS,
    `only ${preserved.length} of ${targets.length} single-file deletes were preserved`);
  let checked = 0;
  for (const name of targets) {
    assert.equal(fs.existsSync(path.join(hooksDir, name)), false,
      `the stale hook survived at its live path: ${name}`);
    // The sidecar keeps the operator's bytes but NOT a name any loader matches:
    // the suffix lands after the extension, so `*.sh` no longer selects it.
    const sidecar = path.join(hooksDir, `${name}${PRESERVED_LOCAL_SUFFIX}`);
    assert.equal(fs.existsSync(sidecar), true, `no preserved sidecar for ${name}`);
    assert.equal(fs.readFileSync(sidecar, "utf8"), `${OPERATOR_EDIT}${name}\n`,
      `the preserved sidecar for ${name} does not hold the operator's bytes`);
    assert.equal(path.extname(sidecar), PRESERVED_LOCAL_SUFFIX,
      `the sidecar still ends in a loadable extension: ${sidecar}`);
    checked += 1;
  }
  assert.ok(checked >= MIN_TARGETS, `only ${checked} sidecars were verified`);
  assert.deepEqual(warnings, [], `the guard reported limits: ${warnings.join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 4. NO REGRESSION ON THE CLEAN PATH (invariants 2 and 3). Bytes this run wrote,
// and a cache whose contents still match the tree it was copied from, are
// deleted in silence. The `childSourceTree` hint is what makes the second case
// quiet, so its absence is asserted to be the ONLY difference.
// ---------------------------------------------------------------------------

test("the clean path deletes silently: same-run bytes and a cache matching its source", () => {
  const root = throwawayDir("clean");
  const source = path.join(root, "src");
  const MIN_CACHE_FILES = 3;
  const cacheFiles = ["plugin.json", path.join("commands", "one.md"), path.join("commands", "two.md")];
  assert.ok(cacheFiles.length >= MIN_CACHE_FILES,
    `fixture broken: ${cacheFiles.length} cache files, floor ${MIN_CACHE_FILES}`);
  for (const relative of cacheFiles) writeFile(path.join(source, relative), `bob owns ${relative}\n`);

  // (a) A file THIS RUN copied through the guarded family-B copyFile is Bob's
  // own, whatever any receipt says, so deleting it must be silent.
  const sameRun = withArmedGuard(root, () => {
    const installFs = createSafeInstallFs(root, { label: "delete-guard root" });
    installFs.copyFile(path.join(source, "plugin.json"), path.join(root, "live", "plugin.json"));
    installFs.removePath(path.join(root, "live", "plugin.json"));
  });
  assert.deepEqual(sameRun.preserved, [],
    `deleting bytes this run wrote preserved ${sameRun.preserved.length} files`);
  assert.equal(fs.existsSync(path.join(root, "live", "plugin.json")), false,
    "the same-run file was not actually deleted");

  // (b) The codex cache shape: cacheBase/<version>/ is a verbatim copy of
  // pluginDir, so wiping it ahead of the re-copy destroys nothing.
  const cacheBase = path.join(root, "cache");
  const versionDir = path.join(cacheBase, "1.2.3");
  for (const relative of cacheFiles) {
    writeFile(path.join(versionDir, relative), fs.readFileSync(path.join(source, relative), "utf8"));
  }
  assert.equal(countFilesUnder(versionDir), cacheFiles.length,
    "fixture broken: the cache copy is not complete");

  const quiet = withArmedGuard(root, () => {
    createSafeInstallFs(root, { label: "delete-guard root" })
      .removeDirContents(cacheBase, { childSourceTree: source });
  });
  assert.deepEqual(quiet.preserved, [],
    `a cache still matching its source preserved ${quiet.preserved.length} files`);
  assert.equal(countFilesUnder(cacheBase), 0, "the cache was not cleared");
  const strays = scanPreserved(root);
  assert.ok(strays.visited >= MIN_CACHE_FILES,
    `stray scan is vacuous: it visited only ${strays.visited} files`);
  assert.deepEqual(strays.hits, [],
    `the clean path left ${strays.hits.length} preserved copies: ${strays.hits.join(", ")}`);

  // NEGATIVE CONTROL for the hint: the same wipe WITHOUT childSourceTree has no
  // way to know the bytes are Bob's, so it preserves. This proves the quiet
  // result above is caused by the hint and not by an empty directory.
  for (const relative of cacheFiles) {
    writeFile(path.join(versionDir, relative), fs.readFileSync(path.join(source, relative), "utf8"));
  }
  const noisy = withArmedGuard(root, () => {
    createSafeInstallFs(root, { label: "delete-guard root" }).removeDirContents(cacheBase);
  });
  assert.ok(noisy.preserved.length >= MIN_CACHE_FILES,
    `without the source hint only ${noisy.preserved.length} files were preserved, floor ${MIN_CACHE_FILES}`);
});

// ---------------------------------------------------------------------------
// 5. THE REAL CODEX INSTALL. Not a hand-built call — installProject drives
// adapters/codex/index.js:313 with the legacy directory PRESENT.
// ---------------------------------------------------------------------------

test("the real codex install preserves an operator edit in a legacy skill dir", () => {
  const workspace = throwawayDir("codex");
  const home = throwawayDir("codex-home");
  const codexSkills = path.join(home, ".codex", "skills");
  const legacyDir = path.join(codexSkills, CODEX_LEGACY_SKILL);
  const seeded = [
    writeFile(path.join(legacyDir, "SKILL.md"), OPERATOR_EDIT),
    writeFile(path.join(legacyDir, "reference", "playbook.md"), `${OPERATOR_EDIT}playbook\n`),
  ];
  const MIN_SEEDED = 2;
  assert.equal(countFilesUnder(legacyDir), seeded.length,
    `fixture broken: seeded ${seeded.length} files but ${countFilesUnder(legacyDir)} are on disk`);
  assert.ok(seeded.length >= MIN_SEEDED,
    `fixture broken: seeded ${seeded.length} files, floor ${MIN_SEEDED}`);

  const summary = install(workspace, home, ["codex"]);

  assert.equal(fs.existsSync(legacyDir), false,
    "the codex install left the legacy skill directory in place");
  const preserved = summary.preservedLocalFiles.filter(
    (entry) => entry.original_path.includes(`${CODEX_LEGACY_SKILL}/`)
      || entry.original_path.includes(`${CODEX_LEGACY_SKILL}${path.sep}`),
  );
  assert.ok(preserved.length >= MIN_SEEDED,
    `the install preserved ${preserved.length} legacy-skill files, floor ${MIN_SEEDED} `
    + `(all preserved: ${summary.preservedLocalFiles.map((e) => e.original_path).join(", ")})`);
  let verified = 0;
  for (const entry of preserved) {
    // The codex adapter installs under $CODEX_HOME, outside the install target,
    // so the guard keys these records by ABSOLUTE path.
    const abs = path.resolve(workspace, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy is missing: ${entry.preserved_path}`);
    assert.ok(fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `preserved copy lost the operator's bytes: ${entry.preserved_path}`);
    assert.equal(abs.startsWith(`${codexSkills}${path.sep}`), false,
      `preserved copy was left inside the scanned codex skills root: ${abs}`);
    verified += 1;
  }
  assert.ok(verified >= MIN_SEEDED, `only ${verified} preserved copies were verified`);
  assert.deepEqual(summary.driftGuardWarnings, [],
    `the install reported guard limits: ${summary.driftGuardWarnings.join(" | ")}`);
});

// ---------------------------------------------------------------------------
// 6. THE REAL KIMI INSTALL — adapters/kimi/index.js:256 (recursive) and :269
// (single file), both with the legacy content PRESENT.
// ---------------------------------------------------------------------------

test("the real kimi install preserves a legacy skill tree and a stale hook", () => {
  const workspace = throwawayDir("kimi");
  const home = throwawayDir("kimi-home");
  const kimiDir = path.join(workspace, ".kimi");
  const legacyDir = path.join(kimiDir, "skills", KIMI_LEGACY_SKILL);
  const staleHook = path.join(kimiDir, "hooks", KIMI_STALE_HOOK);
  writeFile(path.join(legacyDir, "SKILL.md"), OPERATOR_EDIT);
  writeFile(path.join(legacyDir, "notes.md"), `${OPERATOR_EDIT}notes\n`);
  writeFile(staleHook, `${OPERATOR_EDIT}#!/bin/sh\n`);

  const MIN_LEGACY_FILES = 2;
  assert.ok(countFilesUnder(legacyDir) >= MIN_LEGACY_FILES,
    `fixture broken: the legacy skill dir holds ${countFilesUnder(legacyDir)} files`);
  assert.equal(fs.existsSync(staleHook), true, "fixture broken: the stale hook was not seeded");

  const summary = install(workspace, home, ["kimi"]);

  assert.equal(fs.existsSync(legacyDir), false,
    "the kimi install left the legacy skill directory in place");
  assert.equal(fs.existsSync(staleHook), false,
    "the kimi install left the stale hook in place");

  const preserved = summary.preservedLocalFiles;
  const treeCopies = preserved.filter((entry) => entry.original_path.includes(KIMI_LEGACY_SKILL));
  const hookCopies = preserved.filter((entry) => entry.original_path.endsWith(KIMI_STALE_HOOK));
  assert.ok(treeCopies.length >= MIN_LEGACY_FILES,
    `the legacy skill tree preserved ${treeCopies.length} files, floor ${MIN_LEGACY_FILES}`);
  assert.ok(hookCopies.length >= MIN_KIMI_STALE_HOOKS,
    `the stale hook preserved ${hookCopies.length} files, floor ${MIN_KIMI_STALE_HOOKS}`);

  let verified = 0;
  for (const entry of [...treeCopies, ...hookCopies]) {
    const abs = path.resolve(workspace, entry.preserved_path);
    assert.equal(fs.existsSync(abs), true, `preserved copy is missing: ${entry.preserved_path}`);
    assert.ok(fs.readFileSync(abs, "utf8").startsWith(OPERATOR_EDIT),
      `preserved copy lost the operator's bytes: ${entry.preserved_path}`);
    verified += 1;
  }
  assert.ok(verified >= MIN_LEGACY_FILES + MIN_KIMI_STALE_HOOKS,
    `only ${verified} preserved copies were verified`);
});

// ---------------------------------------------------------------------------
// 7. THE VACUITY CONTROL, stated outright.
// (a) With the legacy directory ABSENT the sweep runs zero times and preserves
//     nothing — so tests 1-6 above prove something only because they created it.
// (b) With NO guard armed the deletes behave exactly as they did before this
//     node, which is what keeps uninstall and dev-sync unchanged.
// ---------------------------------------------------------------------------

test("an absent directory preserves nothing, and a disarmed guard changes nothing", () => {
  // (a) ABSENT. This is the shape that made the unguarded rmSync survive review.
  const empty = throwawayDir("absent");
  const absentDir = path.join(empty, "skills", CODEX_LEGACY_SKILL);
  assert.equal(fs.existsSync(absentDir), false, "fixture broken: the directory is not absent");
  const absent = withArmedGuard(empty, () => {
    createSafeInstallFs(empty, { label: "delete-guard root" })
      .removePath(absentDir, { recursive: true });
  });
  assert.deepEqual(absent.preserved, [],
    `sweeping an absent directory preserved ${absent.preserved.length} files`);

  // (b) DISARMED. Same content, same calls, no guard.
  const root = throwawayDir("disarmed");
  const legacyDir = path.join(root, "skills", CODEX_LEGACY_SKILL);
  const staleHook = path.join(root, "hooks", KIMI_STALE_HOOK);
  writeFile(path.join(legacyDir, "SKILL.md"), OPERATOR_EDIT);
  writeFile(path.join(legacyDir, "notes.md"), OPERATOR_EDIT);
  writeFile(staleHook, OPERATOR_EDIT);
  const MIN_DISARMED_FILES = 3;
  assert.ok(countFilesUnder(root) >= MIN_DISARMED_FILES,
    `fixture broken: ${countFilesUnder(root)} files seeded, floor ${MIN_DISARMED_FILES}`);

  const installFs = createSafeInstallFs(root, { label: "delete-guard root" });
  installFs.removePath(legacyDir, { recursive: true });
  installFs.removePath(staleHook);

  assert.equal(fs.existsSync(legacyDir), false, "the disarmed recursive delete did not run");
  assert.equal(fs.existsSync(staleHook), false, "the disarmed single-file delete did not run");
  const strays = scanPreserved(root);
  assert.equal(strays.hits.length, 0,
    `a disarmed delete left ${strays.hits.length} preserved copies: ${strays.hits.join(", ")}`);
  assert.equal(countFilesUnder(root), 0,
    `a disarmed delete left ${countFilesUnder(root)} files behind`);
});

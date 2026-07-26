"use strict";

// Install drift guard — never silently overwrite (or delete) a file the
// operator edited after Bob installed it.
//
// WHY A SHARED MODULE. There are TWO independent copy stacks in this tree:
//
//   FAMILY A  scripts/install.js copyFile/copyDirFiles. Used by
//             copyResourceSet AND by the Claude adapter, which receives
//             copyDirFiles/copyFile INJECTED as parameters
//             (adapters/claude/index.js writes .claude/agents and
//             .claude/rules through them). This family wrote the file that
//             was actually destroyed.
//   FAMILY B  scripts/lib/install-fs.js copyFile, inside createSafeInstallFs.
//             Used by the codex, kimi and generic-mcp adapters ONLY.
//             adapters/claude/index.js never requires install-fs.js.
//
// A guard in only one family leaves the other silently destructive, so both
// require THIS module. Two divergent guards would be the same defect this
// module exists to fix.
//
// WHY THIS RECORD SHAPE. scripts/lib/optional-provider-lifecycle.js already
// implements per-file ownership with destination drift detection:
// FILE_RECORD_FIELDS = ["path", "byte_size", "sha256", "mode"] and an
// inspectInstalled loop that compares each installed file's sha256 against the
// recorded one. That is the same record-and-compare loop this needs, so the
// field names and record shape are reused verbatim rather than respelled. The
// difference is the RESPONSE: that module rejects the whole package on drift;
// an installer cannot reject, so this module preserves-and-reports instead.
//
// The guard is ambient (process-scoped) rather than threaded through every
// call site because family B is constructed independently by three adapters
// and family A is injected into a fourth. When no guard is active every entry
// point here is a no-op, so createSafeInstallFs stays usable standalone.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// Stored in .hacker-bob/install.json beside mcp_top_level_runtime_ownership.
// ADDITIVE: schema_version stays 2 and an install.json without this key is
// valid — it simply yields no recorded digests, which the guard treats as
// "possibly local" and preserves.
const INSTALLED_FILE_OWNERSHIP_KEY = "installed_file_ownership";
const INSTALLED_FILE_OWNERSHIP_VERSION = 1;

// Same four fields, same order, same meaning as
// scripts/lib/optional-provider-lifecycle.js FILE_RECORD_FIELDS.
const FILE_RECORD_FIELDS = Object.freeze(["path", "byte_size", "sha256", "mode"]);

// Predictable, and deliberately appended AFTER the extension: a preserved
// ".claude/agents/report-writer.md" becomes
// ".claude/agents/report-writer.md.bob-local", which no longer matches the
// `name.endsWith(".md")` predicates the adapters copy with and is not loaded
// by any host. Preservation must never resurrect the file as live config.
const PRESERVED_LOCAL_SUFFIX = ".bob-local";
const MAX_PRESERVED_SIDECAR_ATTEMPTS = 1000;

// FIRST-UPGRADE LISTING BOUNDS. On the one run that upgrades a pre-receipt
// install, the preserved set is the size of the RELEASE (measured: 273 files,
// 551 summary lines, upgrading a v2.0.1 workspace to 2.1.0), not the size of
// the operator's work. Naming every one of them buries the handful that might
// be real, so the listing is bounded — LOUDLY, with the count elided and the
// command that enumerates the rest. NO SILENT CAPS applies here as it does to
// every other bound in this module.
const MAX_MIGRATION_NAMED_FILES = 40;
const MAX_MIGRATION_NAMED_TREES = 12;

const MAX_OWNERSHIP_FILES = 8192;
const MAX_OWNERSHIP_FILE_BYTES = 256 * 1024 * 1024;
const MAX_OWNERSHIP_PATH_LENGTH = 1024;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;

const PRESERVE_REASON_MODIFIED = "locally_modified";
const PRESERVE_REASON_UNRECORDED = "no_recorded_digest";
// A symlink at an installed path is operator work by construction: nothing in
// this installer ever creates one.
const PRESERVE_REASON_SYMLINK = "symlinked_destination";

function sha256Buffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sha256File(filePath) {
  return sha256Buffer(fs.readFileSync(filePath));
}

function lstatIfExists(candidate) {
  try {
    return fs.lstatSync(candidate);
  } catch (error) {
    if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) return null;
    throw error;
  }
}

// Records are keyed by a stable, human-readable identity: a POSIX-separated
// path relative to the install target when the file is inside it, and the
// absolute path otherwise (the codex and kimi adapters write under $HOME).
function ownershipKey(targetAbs, absPath) {
  const relative = path.relative(targetAbs, absPath);
  if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
    return relative.split(path.sep).join("/");
  }
  return absPath;
}

// Receipt keys land in JSON and are compared as plain strings. A NUL byte can
// never appear in a real filesystem path, so a key carrying one is a poisoned
// record rather than a file. Spaces ARE legal in paths and are deliberately
// NOT rejected.
//
// The NUL is written as an ESCAPE on purpose. A raw control byte in source
// makes the file binary to git (`git diff` reports `Bin`, so the module lands
// unreviewable) and to BSD grep (a zero-hit search that proves nothing), and
// the line then LIES about what it checks. test/install-drift.test.js asserts
// no such byte can reappear in this node's files.
// maxLength is injectable for the same reason maxOwnershipFiles is: macOS caps
// a real path at PATH_MAX (1024), the same order as this bound, so the bound is
// otherwise unreachable from a test and its warning would go unproven.
function isUsableOwnershipKey(key, maxLength = MAX_OWNERSHIP_PATH_LENGTH) {
  return typeof key === "string"
    && key.length > 0
    && key.length <= maxLength
    && !key.includes("\u0000");
}

// How many records the receipt CLAIMS to carry, before validation. Compared
// against the normalized map so an all-or-nothing rejection cannot happen
// quietly: 606 valid records plus one bad mode normalizes to zero, and without
// this the operator is then told their edits were preserved for files they
// never touched.
function declaredInstalledFileOwnershipCount(metadata) {
  if (metadata == null || typeof metadata !== "object" || Array.isArray(metadata)) return 0;
  const receipt = metadata[INSTALLED_FILE_OWNERSHIP_KEY];
  if (receipt == null || typeof receipt !== "object" || Array.isArray(receipt)) return 0;
  if (!Array.isArray(receipt.files)) return 0;
  return receipt.files.length;
}

// Did a PREVIOUS install actually happen here? Distinguishes the two ways
// `previousMetadata` can carry no ownership records:
//
//   (1) there is no prior install at all (a fresh target) — scripts/install.js
//       passes null, nothing Bob owns is on disk, and nothing can be preserved;
//   (2) there IS a prior install and it predates the ownership receipt — the
//       one-time migration this module has to keep quiet about.
//
// Only (2) may claim "this is a first upgrade", so the claim is grounded in a
// positive marker rather than in the ABSENCE of the ownership key: any
// .hacker-bob/install.json Bob has ever written carries an installed_at stamp
// and a schema_version. If that shape ever changes this predicate goes false
// and the guard falls back to the pre-existing, louder behaviour — the safe
// direction. test/install-first-upgrade.test.js pins it against a real
// install.json produced by a real install rather than a hand-built fixture,
// so a rename cannot pass unnoticed.
function looksLikePreviousInstall(metadata) {
  if (metadata == null || typeof metadata !== "object" || Array.isArray(metadata)) return false;
  if (!Number.isSafeInteger(metadata.schema_version)) return false;
  return typeof metadata.installed_at === "string" && metadata.installed_at.length > 0;
}

// Tolerant reader. A malformed, oversized or foreign receipt yields an EMPTY
// map, which makes every destination "unrecorded" and therefore PRESERVED.
// Failing safe beats failing silent: a receipt we cannot trust must never
// authorize an overwrite.
function normalizeInstalledFileOwnership(metadata) {
  const empty = new Map();
  if (metadata == null || typeof metadata !== "object" || Array.isArray(metadata)) return empty;
  const receipt = metadata[INSTALLED_FILE_OWNERSHIP_KEY];
  if (receipt == null || typeof receipt !== "object" || Array.isArray(receipt)) return empty;
  if (Object.keys(receipt).length !== 2) return empty;
  if (receipt.version !== INSTALLED_FILE_OWNERSHIP_VERSION) return empty;
  if (!Array.isArray(receipt.files) || receipt.files.length > MAX_OWNERSHIP_FILES) return empty;
  const normalized = new Map();
  for (const file of receipt.files) {
    if (file == null || typeof file !== "object" || Array.isArray(file)) return empty;
    if (Object.keys(file).length !== FILE_RECORD_FIELDS.length) return empty;
    if (!isUsableOwnershipKey(file.path)) return empty;
    if (!Number.isSafeInteger(file.byte_size)
      || file.byte_size < 0
      || file.byte_size > MAX_OWNERSHIP_FILE_BYTES) return empty;
    if (typeof file.sha256 !== "string" || !SHA256_HEX_PATTERN.test(file.sha256)) return empty;
    if (!Number.isSafeInteger(file.mode) || file.mode < 0 || file.mode > 0o7777) return empty;
    if (normalized.has(file.path)) return empty;
    normalized.set(file.path, Object.freeze({
      path: file.path,
      byte_size: file.byte_size,
      sha256: file.sha256,
      mode: file.mode,
    }));
  }
  return normalized;
}

function incomingDigestOf(incoming) {
  if (incoming == null) return null;
  if (Buffer.isBuffer(incoming.contents)) return sha256Buffer(incoming.contents);
  if (typeof incoming.contents === "string") return sha256Buffer(Buffer.from(incoming.contents, "utf8"));
  if (typeof incoming.sourcePath === "string") {
    try {
      return sha256File(incoming.sourcePath);
    } catch {
      return null;
    }
  }
  return null;
}

function createInstallDriftGuard({
  targetAbs,
  previousMetadata = null,
  maxOwnershipFiles = MAX_OWNERSHIP_FILES,
  maxOwnershipPathLength = MAX_OWNERSHIP_PATH_LENGTH,
} = {}) {
  if (typeof targetAbs !== "string" || !targetAbs) {
    throw new Error("createInstallDriftGuard requires a targetAbs install root");
  }
  const root = path.resolve(targetAbs);
  const recorded = normalizeInstalledFileOwnership(previousMetadata);
  const written = new Map();
  const preserved = [];
  const warnings = [];
  let ownershipOverflowed = false;

  // NO SILENT CAPS. Every bound in this module that can drop work says so on
  // the operator's screen; a cap that fires quietly is the same class of defect
  // as an overwrite that happens quietly. The complete list, each verified to
  // reach warnOnce: the whole-receipt rejection (just below), all four
  // recordWrite early returns (non-file, oversize, unusable key, receipt full)
  // and the tree-sweep visit cap. Adding a bound here means adding a warning.
  function warnOnce(message) {
    if (!warnings.includes(message)) warnings.push(message);
  }

  // The receipt is read ALL-OR-NOTHING: one malformed record rejects the whole
  // map (normalizeInstalledFileOwnership above). That direction is right — a
  // receipt we cannot trust must never authorize an overwrite — but it must not
  // happen quietly. 606 valid records plus one bad mode normalizes to zero,
  // after which every destination takes the preserve branch and the operator is
  // told their edits were saved for files they never touched.
  const declaredRecords = declaredInstalledFileOwnershipCount(previousMetadata);
  if (declaredRecords > 0 && recorded.size === 0) {
    warnOnce(
      `the previous install.json declared ${declaredRecords} ownership records but NOT ONE of them could be read `
      + "(the receipt is malformed or was written by a different tool), so every installed file is treated as "
      + "possibly-local this run: expect preserved copies for files you never edited.",
    );
  }

  // THE FIRST UPGRADE. The branch above cannot describe it: the no-receipt case
  // is declaredRecords === 0, so that warning is gated OUT of the very run with
  // the largest blast radius. Upgrading a workspace installed by any released
  // Bob (none of which wrote this receipt) means EVERY file the new release
  // changed takes the unrecorded-therefore-preserve branch at once. Measured on
  // a real v2.0.1 -> 2.1.0 upgrade: 273 preserved files, 551 summary lines and a
  // 2.3 MB mcp/lib.bob-local tree, against ONE actual operator edit.
  //
  // Preserving them all stays correct — with no receipt there is genuinely no
  // way to tell the operator's edit from a file the release rewrote, and
  // guessing would silently destroy real work. What was wrong is the REPORT:
  // it told the operator "Bob did NOT overwrite your changes" about files
  // nobody touched, and "Re-apply anything you still want, then delete the
  // preserved copies" over a tree that is simply the PREVIOUS RELEASE's
  // runtime. Followed literally, that downgrades the install. Loud is the
  // requirement, but 551 lines of false alarm on the guard's debut teaches
  // operators to scroll past the notice the guard exists to make credible.
  //
  // So the run is tagged instead, and formatPreservedSummary gives it its own,
  // honest section. Deliberately NOT a warnOnce: the warnings channel prints
  // under "DRIFT GUARD LIMIT REACHED ... protection was INCOMPLETE this run",
  // and neither half is true here — nothing was capped and every file was
  // protected. It would also fire on a migration that preserved nothing at all,
  // which is exactly the clean path that must stay silent.
  const firstUpgrade = declaredRecords === 0
    && recorded.size === 0
    && looksLikePreviousInstall(previousMetadata);

  function keyFor(absPath) {
    return ownershipKey(root, absPath);
  }

  // Every early return in recordWrite leaves a path UNRECORDED, which makes the
  // NEXT install treat Bob's own bytes as local work and preserve a copy the
  // operator never asked for. Fail-safe, but not free — so each one says so.
  function warnUnrecorded(displayKey, reason) {
    warnOnce(
      `${displayKey} was NOT recorded in the ownership receipt (${reason}), so the next install cannot tell `
      + "Bob's own bytes from your edits there and will preserve them as local work.",
    );
  }

  // ONE collision-safe destination chooser, shared by BOTH preserve paths
  // (sidecar-beside-the-file and sweep-into-a-preserved-tree). The first
  // collision-free name wins; the counter is bounded so a pathological
  // directory cannot spin. Two divergent choosers is how a second drift event
  // at one path silently ate the first preserved copy.
  function collisionFreePath(basePath) {
    if (!lstatIfExists(basePath)) return basePath;
    for (let index = 1; index <= MAX_PRESERVED_SIDECAR_ATTEMPTS; index += 1) {
      const candidate = `${basePath}.${index}`;
      if (!lstatIfExists(candidate)) return candidate;
    }
    throw new Error(`Refusing to preserve local file: too many existing copies beside ${basePath}`);
  }

  // ONE move implementation. rename() is atomic and keeps the original
  // mode/ownership, so the local copy survives verbatim and the destination is
  // free for the incoming write.
  function preserveTo(absPath, basePath, reason) {
    const destination = collisionFreePath(basePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.renameSync(absPath, destination);
    const entry = Object.freeze({
      original_path: keyFor(absPath),
      preserved_path: keyFor(destination),
      reason,
      // ATTRIBUTION, not a second reason code. `reason` says WHY the file was
      // moved and is unchanged; this says whether Bob can claim the change was
      // the operator's. False on every ordinary run, so the existing notice is
      // untouched. True only during the one-time migration above, where the
      // honest answer is "unknown" — and a summary that says "your changes"
      // about 273 files it cannot attribute is a false alarm, not a warning.
      //
      // A SYMLINK is exempt even during the migration: no path in this
      // installer ever creates one, so a symlink at an installed path IS the
      // operator's work with or without a receipt. That certainty survives the
      // migration and keeps its louder, accurate notice.
      first_upgrade: firstUpgrade && reason !== PRESERVE_REASON_SYMLINK,
    });
    preserved.push(entry);
    return entry;
  }

  function preserveLocalFile(absPath, reason) {
    return preserveTo(absPath, `${absPath}${PRESERVED_LOCAL_SUFFIX}`, reason);
  }

  // Call IMMEDIATELY before a write. Returns null when the write is unguarded
  // or needs no preservation; otherwise the preservation entry. The returned
  // token also carries the incoming digest so recordWrite need not re-hash.
  function beforeWrite(destination, incoming) {
    const abs = path.resolve(destination);
    const incomingDigest = incomingDigestOf(incoming);
    const existing = lstatIfExists(abs);
    // Destination absent -> nothing to destroy. Unchanged behaviour.
    if (!existing) return { incomingDigest, preserved: null };
    // A SYMLINK at an installed path is operator work by construction: no
    // install path in this tree ever creates one. And FAMILY A HAS NO LEAF
    // CHECKS — scripts/install.js copyFile is mkdir -> guard -> fs.copyFileSync
    // -> chmod, with no lstat anywhere, and copyFileSync FOLLOWS the link and
    // rewrites whatever the operator pointed it at. (Family B does check:
    // install-fs.js assertWritableLeaf.) rename() moves the LINK ITSELF and
    // never touches its target, so the link is preserved aside and the
    // destination is left free for a fresh regular file.
    if (existing.isSymbolicLink()) {
      return { incomingDigest, preserved: preserveLocalFile(abs, PRESERVE_REASON_SYMLINK) };
    }
    // Directories and device nodes are deliberately NOT renamed aside — that is
    // a different, riskier action than this guard is scoped for. Family B
    // rejects them outright; family A's fs.copyFileSync fails LOUDLY with
    // EISDIR on a directory. Loud is acceptable here; only silent is not.
    if (!existing.isFile()) return { incomingDigest, preserved: null };

    const actualDigest = sha256File(abs);
    // The write would not change a single byte, so nothing can be destroyed.
    // This is what keeps the clean path quiet: a re-install of unchanged
    // content, and an upgrade of a file the operator never touched, both land
    // here without touching the recorded-digest question at all.
    if (incomingDigest != null && incomingDigest === actualDigest) {
      return { incomingDigest, preserved: null };
    }

    const key = keyFor(abs);
    // THIS RUN's write is the freshest authority on a path. Several install
    // paths legitimately write the same destination twice in one run — the
    // codex adapter copies the template `.mcp.json` through copyTree and then
    // rewrites the rendered config over it — and the operator cannot have
    // edited the file in between. Without this, the second write sees bytes
    // that match neither the incoming content nor the PREVIOUS install's
    // receipt and preserves a sidecar on a completely clean install, then
    // leaves the receipt permanently stale so it repeats on every future run.
    const sameRun = written.get(key);
    if (sameRun && sameRun.sha256 === actualDigest) {
      return { incomingDigest, preserved: null };
    }
    const record = recorded.get(key);
    // Bob wrote these exact bytes and the operator never touched them ->
    // overwrite silently.
    if (record && record.sha256 === actualDigest) {
      return { incomingDigest, preserved: null };
    }
    // Either the bytes drifted from what Bob recorded (LOCAL WORK), or there
    // is no record at all (upgrade from an install that predates this
    // receipt). Both are treated as local work and preserved.
    return {
      incomingDigest,
      preserved: preserveLocalFile(abs, record ? PRESERVE_REASON_MODIFIED : PRESERVE_REASON_UNRECORDED),
    };
  }

  // Call IMMEDIATELY after the write lands, so the receipt describes what is
  // actually on disk (mode included).
  function recordWrite(destination, token = null) {
    const abs = path.resolve(destination);
    const key = keyFor(abs);
    const stat = lstatIfExists(abs);
    if (!stat || !stat.isFile()) {
      warnUnrecorded(key, "it is not a regular file on disk after the write");
      return null;
    }
    if (stat.size > MAX_OWNERSHIP_FILE_BYTES) {
      warnUnrecorded(key, `it is ${stat.size} bytes, past the ${MAX_OWNERSHIP_FILE_BYTES}-byte per-record limit`);
      return null;
    }
    if (!isUsableOwnershipKey(key, maxOwnershipPathLength)) {
      warnUnrecorded(JSON.stringify(key), "its path cannot be used as a receipt key");
      return null;
    }
    if (!written.has(key) && written.size >= maxOwnershipFiles) {
      ownershipOverflowed = true;
      warnOnce(
        `ownership receipt is full at ${maxOwnershipFiles} files: ${keyFor(abs)} and any later file were NOT recorded, `
        + "so the next install cannot tell Bob's own bytes from your edits there and will preserve them as local work.",
      );
      return null;
    }
    const digest = token && typeof token.incomingDigest === "string"
      ? token.incomingDigest
      : sha256File(abs);
    const record = Object.freeze({
      path: key,
      byte_size: stat.size,
      sha256: digest,
      mode: stat.mode & 0o7777,
    });
    written.set(key, record);
    return record;
  }

  // Call IMMEDIATELY before a delete. Returns true when the file was preserved
  // instead — the caller must then NOT delete, because the path is already
  // vacated by the rename. Deleting a file the operator edited is the same
  // destruction as overwriting it.
  function beforeDelete(destination) {
    const abs = path.resolve(destination);
    const existing = lstatIfExists(abs);
    if (!existing) return false;
    // Same reasoning as beforeWrite: fs.rmSync unlinks a symlink silently, and
    // an installed path that is a symlink is the operator's, not Bob's.
    if (existing.isSymbolicLink()) {
      preserveLocalFile(abs, PRESERVE_REASON_SYMLINK);
      return true;
    }
    if (!existing.isFile()) return false;
    const key = keyFor(abs);
    const actualDigest = sha256File(abs);
    // Same-run authority as beforeWrite: a file this install just wrote is
    // Bob's own, whatever the previous receipt says.
    const sameRun = written.get(key);
    if (sameRun && sameRun.sha256 === actualDigest) return false;
    const record = recorded.get(key);
    if (record && record.sha256 === actualDigest) return false;
    preserveLocalFile(abs, record ? PRESERVE_REASON_MODIFIED : PRESERVE_REASON_UNRECORDED);
    return true;
  }

  // The third destruction shape, alongside overwrite and delete: a WHOLESALE
  // TREE REPLACE. scripts/install.js rmSync's the entire mcp/lib root before
  // re-copying it, so an operator edit there dies before any copyFile guard
  // can see the destination. Sweep the doomed tree first.
  //
  // Preserved files go to `preservedTree`, which MUST be outside `targetTree`
  // — a sidecar written inside the tree would be deleted by the very rmSync
  // this is protecting against.
  //
  // Quiet by construction: a file whose bytes already equal the incoming
  // source file cannot be destroyed by replacing it, and a file whose bytes
  // still match Bob's recorded digest is Bob's own (including a module a newer
  // release legitimately drops). Only genuinely local content is moved.
  // NO `predicate` filter, deliberately. An earlier revision accepted one and
  // no call site ever passed it, leaving two never-executed filter branches in
  // the sole protection for the one wholesale-replaced tree. The sweep must see
  // EVERY file about to be destroyed — a predicate here could only ever narrow
  // that, and a file the caller declines to copy back is exactly the file that
  // most needs preserving.
  function preserveBeforeTreeReplace({ targetTree, sourceTree, preservedTree }) {
    const targetRoot = path.resolve(targetTree);
    const sourceTreeRoot = sourceTree == null ? null : path.resolve(sourceTree);
    const preservedRoot = path.resolve(preservedTree);
    if (preservedRoot === targetRoot || preservedRoot.startsWith(`${targetRoot}${path.sep}`)) {
      throw new Error(`Preserved tree must live outside the replaced tree: ${preservedRoot}`);
    }
    const rootStat = lstatIfExists(targetRoot);
    if (!rootStat || !rootStat.isDirectory()) return [];

    const moved = [];
    let visited = 0;
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        if (visited >= maxOwnershipFiles) {
          // The caller wipes this tree the instant we return, so anything the
          // walk did not reach is about to be destroyed. Never silent.
          warnOnce(
            `preservation sweep of ${keyFor(targetRoot)} stopped after ${maxOwnershipFiles} files: the rest of that tree `
            + "was NOT checked for local edits before it was replaced wholesale.",
          );
          return;
        }
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === "node_modules") continue;
          walk(abs);
          continue;
        }
        // A symlink inside the doomed tree is operator work — rmSync unlinks it
        // as silently as it deletes a file — and there is no digest to compare,
        // so it is always preserved. rename() moves the link, not its target.
        if (entry.isSymbolicLink()) {
          visited += 1;
          const symlinkRelative = path.relative(targetRoot, abs);
          moved.push(preserveTo(
            abs,
            path.join(preservedRoot, symlinkRelative),
            PRESERVE_REASON_SYMLINK,
          ));
          continue;
        }
        if (!entry.isFile()) continue;
        visited += 1;
        const relative = path.relative(targetRoot, abs);
        const actualDigest = sha256File(abs);
        // Identical to the incoming replacement -> nothing can be destroyed.
        if (sourceTreeRoot) {
          const candidate = path.join(sourceTreeRoot, relative);
          const sourceStat = lstatIfExists(candidate);
          if (sourceStat && sourceStat.isFile() && sha256File(candidate) === actualDigest) continue;
        }
        const record = recorded.get(keyFor(abs));
        // Bob's own untouched bytes -> the replace (or drop) is legitimate.
        if (record && record.sha256 === actualDigest) continue;
        // SAME collision-safe chooser as the sidecar path. A second drift
        // event at one path must not eat the copy the first one saved.
        moved.push(preserveTo(
          abs,
          path.join(preservedRoot, relative),
          record ? PRESERVE_REASON_MODIFIED : PRESERVE_REASON_UNRECORDED,
        ));
      }
    };
    walk(targetRoot);
    return moved;
  }

  function ownership() {
    const files = [...written.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return Object.freeze({
      version: INSTALLED_FILE_OWNERSHIP_VERSION,
      files: Object.freeze(files.map((record) => Object.freeze({ ...record }))),
    });
  }

  function preservedFiles() {
    return [...preserved].sort((a, b) => (
      a.preserved_path < b.preserved_path ? -1 : a.preserved_path > b.preserved_path ? 1 : 0
    ));
  }

  return Object.freeze({
    targetAbs: root,
    beforeWrite,
    recordWrite,
    beforeDelete,
    preserveBeforeTreeReplace,
    ownership,
    preservedFiles,
    recordedFileCount: () => recorded.size,
    writtenFileCount: () => written.size,
    ownershipOverflowed: () => ownershipOverflowed,
    // POSITIVE CONTROL for the migration path. The per-entry `first_upgrade`
    // flag is what formatPreservedSummary consumes, but it exists only on
    // entries — so a migration run that preserved NOTHING is indistinguishable
    // from a run where the mode never engaged, and "the quiet first upgrade is
    // quiet" would pass vacuously against a broken fixture. This accessor is
    // how test/install-first-upgrade.test.js tells those two apart.
    firstUpgrade: () => firstUpgrade,
    // Consumed by printInstallSummary. Both bounds above feed this; neither is
    // allowed to fire without reaching the operator's screen.
    warnings: () => [...warnings],
  });
}

// ---------------------------------------------------------------------------
// Ambient guard. Inactive by default, so every hook below is a no-op unless an
// install is in flight.
// ---------------------------------------------------------------------------

let activeGuard = null;

function beginInstallDriftGuard(options) {
  const guard = createInstallDriftGuard(options);
  const previous = activeGuard;
  activeGuard = guard;
  return {
    guard,
    end() {
      if (activeGuard === guard) activeGuard = previous;
      return {
        ownership: guard.ownership(),
        preserved: guard.preservedFiles(),
        warnings: guard.warnings(),
        // How many records the PREVIOUS install's receipt contributed. A real
        // consumer for recordedFileCount(): scripts/install.js surfaces it on
        // the run summary and the tests floor it, so a receipt that silently
        // normalizes to zero cannot pass unnoticed.
        recordedFileCount: guard.recordedFileCount(),
        firstUpgrade: guard.firstUpgrade(),
      };
    },
  };
}

function activeInstallDriftGuard() {
  return activeGuard;
}

function guardBeforeWrite(destination, incoming) {
  if (!activeGuard) return null;
  return activeGuard.beforeWrite(destination, incoming);
}

function recordInstalledFile(destination, token) {
  if (!activeGuard) return null;
  return activeGuard.recordWrite(destination, token);
}

// true => already preserved; the caller must skip its delete.
function guardBeforeDelete(destination) {
  if (!activeGuard) return false;
  return activeGuard.beforeDelete(destination);
}

function guardBeforeTreeReplace(options) {
  if (!activeGuard) return [];
  return activeGuard.preserveBeforeTreeReplace(options);
}

// A preserved copy sits BESIDE the file it came from (`<file>.bob-local`, plus
// a collision counter) when a single guarded write moved it, and INSIDE a
// mirror of a wholesale-replaced directory (`mcp/lib.bob-local/<relative>`)
// when the tree sweep did. Only the sidecar form is derivable from the original
// path, which is exactly the test.
function isPreservedSidecar(entry) {
  const sidecar = `${entry.original_path}${PRESERVED_LOCAL_SUFFIX}`;
  return entry.preserved_path === sidecar || entry.preserved_path.startsWith(`${sidecar}.`);
}

// The `<name>.bob-local` mirror a swept file landed in. preserveBeforeTreeReplace
// builds that root once and never collision-suffixes it (only the leaf files
// inside it), so the first path segment ending in the suffix IS the root.
function preservedTreeRootOf(preservedPath) {
  const segments = preservedPath.split("/");
  for (let index = 0; index < segments.length; index += 1) {
    if (segments[index].endsWith(PRESERVED_LOCAL_SUFFIX)) return segments.slice(0, index + 1).join("/");
  }
  // Unreachable for anything preserveTo produced; degrade to the parent
  // directory rather than inventing a group name.
  const cut = preservedPath.lastIndexOf("/");
  return cut > 0 ? preservedPath.slice(0, cut) : preservedPath;
}

function byPath(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// The one-time first-upgrade section. Bob has no receipt for this workspace, so
// it CANNOT say whose change any of these files carries — and must not pretend
// otherwise. Three rules the ordinary notice breaks here:
//   - never assert the operator made the change ("your changes", "re-apply"),
//   - never invite a wholesale copy-back of a replaced runtime tree: those are
//     the PREVIOUS RELEASE's files and restoring them downgrades the install,
//   - stay bounded. 273 preserved files must not become 546 listed lines.
// Bounded is not silent: every elision states its count and the command that
// enumerates what it left out.
function formatFirstUpgradeSection(entries) {
  const lines = [];
  const sidecars = entries.filter(isPreservedSidecar).sort((a, b) => byPath(a.preserved_path, b.preserved_path));
  const swept = entries.filter((entry) => !isPreservedSidecar(entry));
  const trees = new Map();
  for (const entry of swept) {
    const root = preservedTreeRootOf(entry.preserved_path);
    trees.set(root, (trees.get(root) || 0) + 1);
  }
  const treeRoots = [...trees.keys()].sort(byPath);

  lines.push("");
  lines.push(`LOCAL EDITS PRESERVED (${entries.length}): FIRST UPGRADE - Bob cannot tell whose changes these are.`);
  lines.push("  The install this replaced kept no per-file ownership record, so Bob has no way to");
  lines.push("  separate a file YOU edited from a file THIS RELEASE rewrote. Rather than guess, it");
  lines.push("  moved every differing file aside and wrote the new version in its place. On this");
  lines.push("  ONE run the count above tracks the size of the release, not the size of your work.");
  lines.push("  Bob recorded digests this time, so the next install knows the difference and says");
  lines.push("  nothing. Assume these are Bob's own files unless you remember editing one.");

  if (treeRoots.length > 0) {
    const sweptTotal = swept.length;
    lines.push("");
    lines.push(`  ${sweptTotal} of them came from directories Bob replaces whole. These hold the PREVIOUS`);
    lines.push("  RELEASE's files: do NOT copy one back, that downgrades the runtime you just");
    lines.push("  installed. To find your own work inside one, compare it against the new tree:");
    let listedTrees = 0;
    for (const root of treeRoots) {
      if (listedTrees >= MAX_MIGRATION_NAMED_TREES) break;
      const live = root.slice(0, -PRESERVED_LOCAL_SUFFIX.length);
      lines.push(`      diff -rq ${root} ${live}    (${trees.get(root)} files)`);
      listedTrees += 1;
    }
    if (treeRoots.length > listedTrees) {
      lines.push(`      ... and ${treeRoots.length - listedTrees} more replaced directories, not listed here.`);
    }
  }

  if (sidecars.length > 0) {
    lines.push("");
    lines.push(`  ${sidecars.length} preserved copies sit beside the file they came from. Check these, keep`);
    lines.push("  what is yours, delete the rest:");
    let listed = 0;
    for (const entry of sidecars) {
      if (listed >= MAX_MIGRATION_NAMED_FILES) break;
      lines.push(`    ${entry.original_path}  ->  ${entry.preserved_path}`);
      listed += 1;
    }
    if (sidecars.length > listed) {
      lines.push(`    ... and ${sidecars.length - listed} more, NOT listed above so this notice stays readable.`);
    }
  }

  lines.push("");
  lines.push("  Every preserved copy, at any time:  find . -name '*" + PRESERVED_LOCAL_SUFFIX + "*'");
  return lines;
}

// The end-of-run operator notice. Returns [] when nothing was preserved AND no
// bound fired, so the clean path prints NOTHING new.
function formatPreservedSummary(preserved, warnings = []) {
  const entries = Array.isArray(preserved) ? preserved : [];
  const notes = Array.isArray(warnings) ? warnings : [];
  if (entries.length === 0 && notes.length === 0) return [];
  const lines = [];
  // Split by ATTRIBUTION, not by reason. Anything Bob can attribute keeps the
  // original notice verbatim; only the unattributable first-upgrade set gets
  // the migration wording. A migration run can still produce both — a symlink
  // at an installed path is operator work receipt or no receipt — and the
  // attributable section stays FIRST so its closing advice is not buried.
  const attributed = entries.filter((entry) => !entry.first_upgrade);
  const migrated = entries.filter((entry) => entry.first_upgrade);
  if (attributed.length > 0) {
    lines.push("");
    lines.push(`LOCAL EDITS PRESERVED (${attributed.length}): Bob did NOT overwrite your changes.`);
    lines.push("  Each file below differed from what Bob installed. Your copy was moved aside");
    lines.push("  and the new version written in its place. Nothing was deleted.");
    for (const entry of attributed) {
      lines.push(`    ${entry.original_path}`);
      lines.push(`      -> your version kept at: ${entry.preserved_path} (${entry.reason})`);
    }
    lines.push("  Re-apply anything you still want, then delete the preserved copies.");
  }
  if (migrated.length > 0) {
    lines.push(...formatFirstUpgradeSection(migrated));
  }
  // A cap that fires without saying so is the same defect as an overwrite that
  // happens without saying so, so these print even when nothing was preserved.
  if (notes.length > 0) {
    lines.push("");
    lines.push(`DRIFT GUARD LIMIT REACHED (${notes.length}): protection was INCOMPLETE this run.`);
    for (const note of notes) {
      lines.push(`    ${note}`);
    }
  }
  return lines;
}

module.exports = {
  FILE_RECORD_FIELDS,
  INSTALLED_FILE_OWNERSHIP_KEY,
  INSTALLED_FILE_OWNERSHIP_VERSION,
  MAX_MIGRATION_NAMED_FILES,
  MAX_MIGRATION_NAMED_TREES,
  MAX_OWNERSHIP_FILES,
  PRESERVED_LOCAL_SUFFIX,
  PRESERVE_REASON_MODIFIED,
  PRESERVE_REASON_SYMLINK,
  PRESERVE_REASON_UNRECORDED,
  activeInstallDriftGuard,
  beginInstallDriftGuard,
  createInstallDriftGuard,
  declaredInstalledFileOwnershipCount,
  formatPreservedSummary,
  guardBeforeDelete,
  guardBeforeTreeReplace,
  guardBeforeWrite,
  looksLikePreviousInstall,
  normalizeInstalledFileOwnership,
  ownershipKey,
  recordInstalledFile,
};

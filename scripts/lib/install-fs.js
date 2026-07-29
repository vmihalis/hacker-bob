"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Drift guard, shared with FAMILY A (scripts/install.js). Both copy stacks
// call the SAME implementation so a locally modified installed file is
// preserved-and-reported by whichever stack happens to write it. The hooks are
// no-ops unless an install has armed the guard, so createSafeInstallFs remains
// usable standalone.
const {
  PRESERVED_LOCAL_SUFFIX,
  guardBeforeDelete,
  guardBeforeTreeReplace,
  guardBeforeWrite,
  recordInstalledFile,
} = require("./install-drift.js");

// WHICH FAMILY-B WRITES ARE GUARDED, and why this is a tag and not a blanket.
//
// Every write below funnels through writeFileAtomic, but they are not the same
// kind of write. A WHOLESALE RENDER replaces the destination with content
// derived from the shipped templates alone — whatever the operator put there is
// gone — so it must be guarded. A read-modify-write MERGE re-emits the file it
// just read, so the operator's content survives inside the new file and moving
// a copy aside would be a false alarm, not protection.
//
// Guarded (kind === "generated file"), verified call sites:
//   adapters/codex/index.js:221  writeCommandFiles -> six command wrappers,
//                                fully rendered by renderCommand(), no merge.
//   adapters/codex/index.js:519  .codex/plugins/hacker-bob/.mcp.json —
//                                mergeConfig() (:172) ignores the existing file
//                                despite the name, so this IS a wholesale write.
//   copyFile below               FAMILY B's verbatim file copies ONLY. Family
//                                A's verbatim copies go through
//                                scripts/install.js copyFile and never enter
//                                this module — that is the corrected ground
//                                truth this whole node rests on, and the header
//                                at the top of this file states it too.
//
// NOT guarded, each verified to re-read and re-emit the existing file:
//   adapters/codex/index.js:282  .agents/plugins/marketplace.json (mergeMarketplace)
//   adapters/codex/index.js:458  $HOME/.codex/config.toml (upsertTomlSection)
//   adapters/kimi/index.js:309   .kimi/mcp.json (spreads existing servers)
//   adapters/kimi/index.js:343   $HOME/.kimi/config.toml (upsertKimiHookBlock)
//   adapters/generic-mcp/index.js:104  .mcp.json (spreads existing servers)
//   mcp/lib/egress-profiles.js:197,233 written only when absent / example file
// The two $HOME entries are also SHARED across projects, where one project's
// receipt cannot speak for another project's install, so a digest mismatch
// there is not evidence of local work.
//
// KNOWN RESIDUALS, unguarded because they carry no wholesale tag and are Bob's
// own regenerated metadata rather than operator surface:
//   adapters/kimi/index.js:315   .kimi/bob/VERSION
//   adapters/kimi/index.js:318   .kimi/bob/install.json (timestamped every run)
const GUARDED_WRITE_KIND = "generated file";

function isGuardedWriteKind(kind) {
  return kind === GUARDED_WRITE_KIND;
}

// WHICH FAMILY-B DELETES ARE GUARDED: ALL OF THEM, and why there is no
// opt-out tag here the way there is for writes.
//
// A write has two shapes — a wholesale render that discards the operator's
// bytes, and a read-modify-write merge that carries them forward — so
// writeFileAtomic needs the GUARDED_WRITE_KIND tag above to tell them apart.
// A DELETE has only one shape. There is no such thing as a delete that carries
// the operator's content forward, so every delete below is guarded and no call
// site can opt out. A delete destroys local work exactly like an overwrite.
//
// The call sites this reaches, all through removePath/removeDirContents:
//   adapters/codex/index.js:305  <pluginDir>/skills           (recursive)
//   adapters/codex/index.js:307  <pluginDir>/commands/<stale> (single file)
//   adapters/codex/index.js:313  $CODEX_HOME/skills/<legacy>  (recursive)
//   adapters/codex/index.js:443  the plugin cache base        (removeDirContents)
//   adapters/kimi/index.js:256   .kimi/skills/<legacy>        (recursive)
//   adapters/kimi/index.js:269   .kimi/hooks/<stale>          (single file)
// Family A's delete surface is already guarded at scripts/install.js
// removeIfExists (:1959) and its wholesale mcp/lib replace (:2141). This file
// is the family-B twin of both.
//
// Every hook is a no-op unless an install armed the ambient guard, so
// uninstall and dev-sync — which never arm it — delete exactly as before and
// leave no preserved copies behind.
const PRESERVED_TREE_ROOT = PRESERVED_LOCAL_SUFFIX;

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return !relative.startsWith("..") && !path.isAbsolute(relative);
}

function pathForMessage(root, candidate) {
  const relative = path.relative(root, candidate);
  if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) return relative;
  if (relative === "") return ".";
  return candidate;
}

function defaultLabel(label) {
  return label || "install root";
}

function lstatIfExists(candidate) {
  try {
    return fs.lstatSync(candidate);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function createSafeInstallFs(rootPath, options = {}) {
  const root = path.resolve(rootPath);
  const label = defaultLabel(options.label);
  if (options.createRoot) {
    fs.mkdirSync(root, { recursive: true });
  }
  const rootStat = lstatIfExists(root);
  if (rootStat && rootStat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symlink: ${root}`);
  }
  if (!rootStat || !rootStat.isDirectory()) {
    throw new Error(`${label} does not exist or is not a directory: ${root}`);
  }

  function resolveInside(candidate) {
    const absolute = path.resolve(path.isAbsolute(String(candidate))
      ? String(candidate)
      : path.join(root, String(candidate)));
    if (!isInside(root, absolute)) {
      throw new Error(`Refusing to access path outside ${label}: ${absolute}`);
    }
    return absolute;
  }

  function checkExistingParents(absPath) {
    const parent = path.dirname(absPath);
    if (parent === root) return true;
    if (!isInside(root, parent)) {
      throw new Error(`Refusing to access path outside ${label}: ${absPath}`);
    }
    const relative = path.relative(root, parent);
    if (!relative) return true;
    let current = root;
    for (const part of relative.split(path.sep)) {
      if (!part) continue;
      current = path.join(current, part);
      const stat = lstatIfExists(current);
      if (!stat) return false;
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing to use symlinked parent directory under ${label}: ${pathForMessage(root, current)}`);
      }
      if (!stat.isDirectory()) {
        throw new Error(`Expected parent directory under ${label}: ${pathForMessage(root, current)}`);
      }
    }
    return true;
  }

  function mkdirp(dirPath) {
    const dir = resolveInside(dirPath);
    if (dir === root) return dir;
    const relative = path.relative(root, dir);
    let current = root;
    for (const part of relative.split(path.sep)) {
      if (!part) continue;
      current = path.join(current, part);
      let stat = lstatIfExists(current);
      if (!stat) {
        fs.mkdirSync(current);
        stat = fs.lstatSync(current);
      }
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing to use symlinked parent directory under ${label}: ${pathForMessage(root, current)}`);
      }
      if (!stat.isDirectory()) {
        throw new Error(`Expected directory under ${label}: ${pathForMessage(root, current)}`);
      }
    }
    return dir;
  }

  function leafStat(absPath) {
    const parentsExist = checkExistingParents(absPath);
    if (!parentsExist) return null;
    return lstatIfExists(absPath);
  }

  function assertReadableFile(filePath, optionsForFile = {}) {
    const abs = resolveInside(filePath);
    const stat = leafStat(abs);
    if (!stat) return null;
    const kind = optionsForFile.kind || "file";
    if (stat.isSymbolicLink()) {
      if (optionsForFile.symlink === "missing") return null;
      throw new Error(`Refusing to read symlinked ${kind}: ${pathForMessage(root, abs)}`);
    }
    if (!stat.isFile()) {
      throw new Error(`Expected ${kind} to be a file: ${pathForMessage(root, abs)}`);
    }
    return { abs, stat };
  }

  function readTextIfExists(filePath, fallback = null, optionsForFile = {}) {
    const readable = assertReadableFile(filePath, optionsForFile);
    if (!readable) return fallback;
    return fs.readFileSync(readable.abs, "utf8");
  }

  function readJsonIfExists(filePath, fallback, optionsForFile = {}) {
    const text = readTextIfExists(filePath, null, optionsForFile);
    if (text == null) return fallback;
    return JSON.parse(text);
  }

  function assertWritableLeaf(absPath, optionsForFile = {}) {
    mkdirp(path.dirname(absPath));
    const stat = lstatIfExists(absPath);
    const kind = optionsForFile.kind || "file";
    if (!stat) return null;
    if (stat.isSymbolicLink()) {
      if (optionsForFile.rejectExistingSymlink) {
        throw new Error(`Refusing to write symlinked ${kind}: ${pathForMessage(root, absPath)}`);
      }
      return stat;
    }
    if (stat.isDirectory()) {
      throw new Error(`Refusing to replace directory with ${kind}: ${pathForMessage(root, absPath)}`);
    }
    if (!stat.isFile()) {
      throw new Error(`Refusing to replace non-file ${kind}: ${pathForMessage(root, absPath)}`);
    }
    return stat;
  }

  function tempPathFor(absPath) {
    const dir = path.dirname(absPath);
    const base = path.basename(absPath);
    return path.join(dir, `.${base}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
  }

  function writeFileAtomic(filePath, content, optionsForFile = {}) {
    const abs = resolveInside(filePath);
    const existing = assertWritableLeaf(abs, optionsForFile);
    const mode = optionsForFile.mode != null
      ? optionsForFile.mode
      : existing && !existing.isSymbolicLink()
        ? existing.mode & 0o777
        : 0o666;
    // Guard AFTER the symlink/kind checks (so a hostile leaf is still rejected
    // rather than renamed aside) and BEFORE the write (so the operator's bytes
    // are already moved while the destination is untouched).
    const guarded = isGuardedWriteKind(optionsForFile.kind);
    const guard = guarded ? guardBeforeWrite(abs, { contents: content }) : null;
    const tempPath = tempPathFor(abs);
    let fd = null;
    try {
      fd = fs.openSync(tempPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, mode);
      fs.writeFileSync(fd, content, optionsForFile.encoding || (Buffer.isBuffer(content) ? undefined : "utf8"));
      fs.closeSync(fd);
      fd = null;
      fs.chmodSync(tempPath, mode);
      fs.renameSync(tempPath, abs);
    } catch (error) {
      if (fd != null) {
        try {
          fs.closeSync(fd);
        } catch {}
      }
      try {
        fs.rmSync(tempPath, { force: true });
      } catch {}
      throw error;
    }
    if (guarded) recordInstalledFile(abs, guard);
    return abs;
  }

  function writeTextFile(filePath, content, optionsForFile = {}) {
    return writeFileAtomic(filePath, content, { ...optionsForFile, encoding: "utf8" });
  }

  function writeJson(filePath, value, optionsForFile = {}) {
    return writeTextFile(filePath, `${JSON.stringify(value, null, 2)}\n`, optionsForFile);
  }

  // FAMILY B lowest-level verbatim copy — the codex, kimi and generic-mcp
  // adapters install through here. Guarded identically to
  // scripts/install.js copyFile (via writeFileAtomic above); guarding only one
  // family would leave the other silently destructive.
  function copyFile(source, destination, mode) {
    const sourceStat = fs.statSync(source);
    if (!sourceStat.isFile()) {
      throw new Error(`Expected source file: ${source}`);
    }
    const fileMode = mode != null ? mode : sourceStat.mode & 0o777;
    const contents = fs.readFileSync(source);
    return writeFileAtomic(destination, contents, {
      kind: GUARDED_WRITE_KIND,
      mode: fileMode,
    });
  }

  function copyDirFiles(sourceDir, destinationDir, predicate) {
    mkdirp(destinationDir);
    const copied = [];
    for (const name of fs.readdirSync(sourceDir).sort()) {
      const source = path.join(sourceDir, name);
      if (!fs.statSync(source).isFile()) continue;
      if (predicate && !predicate(name)) continue;
      const destination = path.join(destinationDir, name);
      copyFile(source, destination);
      copied.push(name);
    }
    return copied;
  }

  function copyDirRecursive(sourceDir, destinationDir, predicate) {
    mkdirp(destinationDir);
    const copied = [];
    for (const name of fs.readdirSync(sourceDir).sort()) {
      const source = path.join(sourceDir, name);
      const destination = path.join(destinationDir, name);
      const stat = fs.statSync(source);
      if (stat.isDirectory()) {
        if (name === "node_modules") continue;
        for (const nested of copyDirRecursive(source, destination, predicate)) {
          copied.push(path.join(name, nested));
        }
        continue;
      }
      if (!stat.isFile()) continue;
      const relative = path.relative(sourceDir, source);
      if (predicate && !predicate(relative, name)) continue;
      copyFile(source, destination);
      copied.push(path.relative(destinationDir, destination));
    }
    return copied;
  }

  function copyTree(sourceDir, destinationDir) {
    mkdirp(destinationDir);
    const copied = [];
    const visit = (current) => {
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const source = path.join(current, entry.name);
        const relative = path.relative(sourceDir, source);
        const destination = path.join(destinationDir, relative);
        if (entry.isDirectory()) {
          mkdirp(destination);
          visit(source);
        } else if (entry.isFile()) {
          copyFile(source, destination);
          copied.push(relative);
        }
      }
    };
    visit(sourceDir);
    return copied.sort();
  }

  // WHERE A PRESERVED TREE GOES, and why it is NOT the sibling
  // `<dir>.bob-local` that scripts/install.js:2144 uses for mcp/lib.
  //
  // The sidecar convention is safe for mcp/lib because nothing scans `mcp/`
  // looking for directories to load. It is NOT safe here. The recursive deletes
  // this guards are legacy-SKILL sweeps under `$CODEX_HOME/skills/` and
  // `.kimi/skills/` — directories the host scans by listing subdirectories and
  // reading `<name>/SKILL.md`. Preserving `skills/bob-hunt/` as
  // `skills/bob-hunt.bob-local/` would leave a complete, loadable SKILL.md in a
  // scanned directory and RESURRECT the exact stale skill the sweep exists to
  // retire (adapters/kimi/index.js:249-254 states that purpose outright). That
  // is the directory-shaped version of the hazard install-drift.js:52-55 already
  // reasons about for files: preservation must never put the content back as
  // live config.
  //
  // So preserved trees go to ONE quarantine root at the install-fs root,
  // mirroring the original layout beneath it. It reuses the SAME
  // PRESERVED_LOCAL_SUFFIX string as the file sidecars — one spelling, one word
  // the operator has to learn — and that string already begins with a dot, so
  // the quarantine is hidden and outside every scanned directory:
  //   $CODEX_HOME/skills/bob-hunt/SKILL.md
  //     -> $CODEX_HOME/.bob-local/skills/bob-hunt/SKILL.md
  //
  // Removing the root ITSELF resolves to a quarantine inside the tree being
  // destroyed; preserveBeforeTreeReplace rejects that outright rather than
  // preserving copies into the path it is about to delete. Loud is correct —
  // no call site removes the root, and one that appeared should not be silent.
  function preservedTreeFor(absDir) {
    return path.join(root, PRESERVED_TREE_ROOT, path.relative(root, absDir));
  }

  // `sourceTree` (optional) is the tree the removed DIRECTORY mirrors. Files
  // whose bytes already equal their counterpart there cannot be destroyed by
  // removing them ahead of a re-copy, so passing it keeps the clean re-install
  // path silent. Omitting it is safe, never wrong — only noisier.
  function removePath(targetPath, optionsForRemove = {}) {
    const abs = resolveInside(targetPath);
    if (!checkExistingParents(abs)) return;
    const stat = lstatIfExists(abs);
    if (stat) {
      if (optionsForRemove.recursive && stat.isDirectory()) {
        // A recursive delete destroys every file under `abs` before any
        // per-file hook could see them, which is the same shape as the
        // wholesale tree replace preserveBeforeTreeReplace was built for.
        // Sweep the doomed tree into the quarantine first.
        guardBeforeTreeReplace({
          targetTree: abs,
          sourceTree: optionsForRemove.sourceTree == null ? null : optionsForRemove.sourceTree,
          preservedTree: preservedTreeFor(abs),
        });
      } else if (guardBeforeDelete(abs)) {
        // Preserved instead: the rename already vacated the path, so deleting
        // now would destroy the copy that was just saved.
        return;
      }
      // A directory reached WITHOUT `recursive` deliberately falls through
      // unswept: fs.rmSync then throws ERR_FS_EISDIR exactly as it does today.
      // Sweeping first would report preserved copies for a delete that never
      // happened.
    }
    fs.rmSync(abs, {
      force: optionsForRemove.force !== false,
      recursive: !!optionsForRemove.recursive,
    });
  }

  // `childSourceTree` (optional) is the tree each CHILD of `dirPath` mirrors —
  // deliberately not spelled `sourceTree`, because it describes the children
  // and not the directory named here. The codex plugin cache is exactly this
  // shape: every child of the cache base is a version directory holding a
  // verbatim copy of pluginDir (adapters/codex/index.js:444 copyTree).
  function removeDirContents(dirPath, optionsForRemove = {}) {
    const dir = resolveInside(dirPath);
    const stat = leafStat(dir);
    if (!stat) return;
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked directory under ${label}: ${pathForMessage(root, dir)}`);
    }
    if (!stat.isDirectory()) {
      throw new Error(`Expected directory under ${label}: ${pathForMessage(root, dir)}`);
    }
    for (const entry of fs.readdirSync(dir)) {
      removePath(path.join(dir, entry), {
        recursive: true,
        sourceTree: optionsForRemove.childSourceTree,
      });
    }
  }

  function removeEmptyDirIfExists(dirPath) {
    const dir = resolveInside(dirPath);
    const stat = leafStat(dir);
    if (!stat) return;
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked directory under ${label}: ${pathForMessage(root, dir)}`);
    }
    if (!stat.isDirectory()) return;
    if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
  }

  function fileExists(filePath, optionsForFile = {}) {
    return !!assertReadableFile(filePath, {
      kind: optionsForFile.kind || "file",
      symlink: optionsForFile.symlink || "missing",
    });
  }

  function dirExists(dirPath) {
    const dir = resolveInside(dirPath);
    const stat = leafStat(dir);
    if (!stat) return false;
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked directory under ${label}: ${pathForMessage(root, dir)}`);
    }
    return stat.isDirectory();
  }

  return {
    root,
    label,
    resolveInside,
    mkdirp,
    readJsonIfExists,
    readTextIfExists,
    writeFileAtomic,
    writeTextFile,
    writeJson,
    copyFile,
    copyDirFiles,
    copyDirRecursive,
    copyTree,
    removePath,
    removeDirContents,
    removeEmptyDirIfExists,
    fileExists,
    dirExists,
  };
}

module.exports = {
  createSafeInstallFs,
};

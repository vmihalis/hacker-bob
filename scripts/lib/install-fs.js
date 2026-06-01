"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

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
    return abs;
  }

  function writeTextFile(filePath, content, optionsForFile = {}) {
    return writeFileAtomic(filePath, content, { ...optionsForFile, encoding: "utf8" });
  }

  function writeJson(filePath, value, optionsForFile = {}) {
    return writeTextFile(filePath, `${JSON.stringify(value, null, 2)}\n`, optionsForFile);
  }

  function copyFile(source, destination, mode) {
    const sourceStat = fs.statSync(source);
    if (!sourceStat.isFile()) {
      throw new Error(`Expected source file: ${source}`);
    }
    const fileMode = mode != null ? mode : sourceStat.mode & 0o777;
    return writeFileAtomic(destination, fs.readFileSync(source), {
      kind: "generated file",
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

  function removePath(targetPath, optionsForRemove = {}) {
    const abs = resolveInside(targetPath);
    if (!checkExistingParents(abs)) return;
    fs.rmSync(abs, {
      force: optionsForRemove.force !== false,
      recursive: !!optionsForRemove.recursive,
    });
  }

  function removeDirContents(dirPath) {
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
      removePath(path.join(dir, entry), { recursive: true });
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

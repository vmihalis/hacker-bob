"use strict";

// A8R: pins a repo session's host filesystem identity and revalidates it
// through every byte-read, write, and docker-spawn effect path. Existing
// call sites (walkRepo, safeReadProbe, repoCheck, prepareRepoEnv,
// repoDockerRun, ...) did a one-shot realpath-then-open with no re-check,
// which a same-uid attacker can race: swap a symlink/hardlink between the
// check and the use and redirect a host read, write, or docker mount
// outside the bound repo root.
//
// This module is a leaf: it depends only on core/session (for the verified
// authority context) so domains/repo call sites can require it without a
// cycle.
//
// Byte-content reads (openContainedFile) are TOCTOU-CLOSED: the final
// component is opened O_NOFOLLOW and the held fd's fstat is compared
// against the lstat taken during resolution, so a leaf swap (symlink,
// rename, hardlink) between resolve and open is rejected before any byte
// is returned.
//
// Directory ENUMERATION (resolveContainedPath called at walkRepo dequeue
// time) is WINDOW-MINIMIZED, not closed: Node's fs.readdirSync/statSync
// are path-based, so there is always a residual gap between the last
// containment check and the following readdir call for a same-uid
// attacker who can swap the path in that instant. Closing it fully needs
// fd-relative traversal (openat/fdopendir chained on validated dirfds),
// which stock Node does not expose. The bounded impact of that residual
// is enumerated FILENAME metadata only -- never bytes (fd-validated on
// read), never a write, never a spawn. See the cross-referenced
// offensive-sandbox-isolation same-uid-arbitrary-code verdict; this is the
// same OS-isolation-class residual, not a new one.

const fs = require("fs");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
} = require("../../core/io/envelope.js");
const {
  getOrVerifySessionAuthorityContext,
} = require("../../core/session/session-authority-context.js");

function repoHostError(message, repoErrorCode, extra = null) {
  return new ToolError(ERROR_CODES.STATE_CONFLICT, message, {
    repo_error_code: repoErrorCode,
    ...(extra || {}),
  });
}

// Containment by RELATIVE-PATH comparison, never by raw realpath-string
// equality. A case- or Unicode-normalization-mismatched (but non-symlinked)
// path on APFS/Windows produces a byte-different realpath string with no
// actual traversal; deciding containment by path.relative keeps that path
// valid while still rejecting anything that resolves outside root.
function pathWithinRoot(rootReal, candidateReal) {
  const relative = path.relative(rootReal, candidateReal);
  return relative === "" || (!!relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}

// {realpath, dev, ino} for an existing directory. The dev/ino pair is what
// revalidateRepoHostIdentity compares against on every subsequent use --
// a directory replaced by a new mount/symlink/directory gets a fresh inode
// even when the path string is unchanged.
function captureRepoHostIdentity(realpath) {
  const lst = fs.lstatSync(realpath);
  if (lst.isSymbolicLink()) {
    throw repoHostError(
      `repo host identity root must not itself be a symlink: ${realpath}`,
      "repo_host_root_is_symlink",
    );
  }
  if (!lst.isDirectory()) {
    throw repoHostError(
      `repo host identity root is not a directory: ${realpath}`,
      "repo_host_root_not_directory",
    );
  }
  return Object.freeze({ realpath, dev: lst.dev, ino: lst.ino });
}

// Binds A8's frozen session context (verified nucleus -> scope_policy ->
// target_repo) to a captured filesystem identity. Commit semantics are
// derived HERE, once -- callers read repo_hash/commit off the returned
// identity rather than re-deriving the lowercase-commit-vs-path-hash
// fallback themselves.
function bindRepoHostIdentity(targetDomain) {
  const domain = String(targetDomain || "").trim();
  if (!domain) {
    throw repoHostError("target_domain is required", "repo_host_target_domain_required");
  }
  let context;
  try {
    context = getOrVerifySessionAuthorityContext(domain);
  } catch (error) {
    throw repoHostError(
      `target_domain ${domain} has no verified session nucleus: ${error.message || String(error)}`,
      "repo_host_nucleus_unverified",
    );
  }
  if (!context || !context.repo) {
    throw repoHostError(`target_domain ${domain} is not a repo session`, "repo_host_not_a_repo_session");
  }
  const rootPath = context.repo.root_path;
  let realpath;
  try {
    realpath = fs.realpathSync.native ? fs.realpathSync.native(rootPath) : fs.realpathSync(rootPath);
  } catch (error) {
    throw repoHostError(
      `bound repo root is unreachable: ${error.message || String(error)}`,
      "repo_host_root_unreachable",
    );
  }
  const identity = captureRepoHostIdentity(realpath);
  const boundCommit = context.repo.commit || null;
  return Object.freeze({
    ...identity,
    target_domain: context.target_domain,
    // Pinned-commit semantics: a lowercase repo_hash===commit binding wins;
    // otherwise retain the path-hash fallback already derived onto the
    // context by A8/readRepoSession. Not re-derived here -- read straight
    // off the same verified context this identity was captured from.
    repo_hash: context.repo_hash || boundCommit || null,
    commit: boundCommit,
  });
}

// Re-stats the pinned root and throws if its dev/ino pair has changed --
// the root directory entry was replaced (rm+mkdir, mount swap, symlink
// substitution) since capture. Callers invoke this immediately before
// every Bob write and docker build/run spawn on a repo-bound effect path.
function revalidateRepoHostIdentity(identity) {
  if (!identity || typeof identity.realpath !== "string") {
    throw repoHostError("revalidateRepoHostIdentity requires a captured identity", "repo_host_identity_required");
  }
  let lst;
  try {
    lst = fs.lstatSync(identity.realpath);
  } catch (error) {
    throw repoHostError(
      `repo host root is no longer reachable: ${error.message || String(error)}`,
      "repo_host_root_unreachable",
    );
  }
  if (lst.isSymbolicLink() || !lst.isDirectory() || lst.dev !== identity.dev || lst.ino !== identity.ino) {
    throw repoHostError(
      `repo host root identity changed since it was pinned: ${identity.realpath}`,
      "repo_host_root_identity_mismatch",
    );
  }
  return identity;
}

function normalizeRelPathSegments(relPath) {
  const raw = String(relPath == null ? "" : relPath);
  if (path.isAbsolute(raw)) {
    throw repoHostError("repo host relative path must not be absolute", "repo_host_path_must_be_relative");
  }
  const normalized = raw.split(path.sep).join("/");
  const segments = normalized.split("/").filter((segment) => segment.length > 0);
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw repoHostError("repo host relative path must not contain . or .. segments", "repo_host_path_escapes_root");
    }
  }
  return segments;
}

// Per-component containment walk from the pinned root. Every intermediate
// AND leaf component is lstat'd; a symlink component is followed only when
// its resolved target still lies within the pinned root (pathWithinRoot),
// matching walkRepo's existing "follow a symlinked directory that stays in
// scope" behavior. A component that resolves outside root, or is missing,
// throws -- callers distinguish "missing" (repo_host_path_missing) from a
// real rejection via error.details.repo_error_code.
//
// This call re-validates the ROOT itself first (revalidateRepoHostIdentity)
// so every resolution -- including a walkRepo dequeue-time re-check -- also
// re-proves the root hasn't been swapped since binding.
function resolveContainedPath(identity, relPath) {
  revalidateRepoHostIdentity(identity);
  const segments = normalizeRelPathSegments(relPath);
  let currentReal = identity.realpath;
  let lst = fs.lstatSync(currentReal);

  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i];
    const isLast = i === segments.length - 1;
    if (!lst.isDirectory()) {
      throw repoHostError(
        `repo host path component is not a directory: ${currentReal}`,
        "repo_host_not_a_directory",
      );
    }
    const candidate = path.join(currentReal, segment);
    let candidateLst;
    try {
      candidateLst = fs.lstatSync(candidate);
    } catch (error) {
      throw repoHostError(
        `repo host path does not exist: ${candidate}`,
        "repo_host_path_missing",
        { cause: error && error.code },
      );
    }
    let nextReal = candidate;
    let nextLst = candidateLst;
    if (candidateLst.isSymbolicLink()) {
      let resolved;
      try {
        resolved = fs.realpathSync.native ? fs.realpathSync.native(candidate) : fs.realpathSync(candidate);
      } catch (error) {
        throw repoHostError(
          `repo host symlink target does not exist: ${candidate}`,
          "repo_host_path_missing",
          { cause: error && error.code },
        );
      }
      if (!pathWithinRoot(identity.realpath, resolved)) {
        throw repoHostError(
          `repo host path traverses outside the bound repo root via a symlink: ${candidate}`,
          "repo_host_traversal_rejected",
        );
      }
      nextReal = resolved;
      nextLst = fs.lstatSync(resolved);
      if (nextLst.isSymbolicLink()) {
        // realpathSync fully resolves symlink chains; this should be
        // unreachable, but fail closed rather than trust an unresolved link.
        throw repoHostError(
          `repo host symlink resolution did not converge: ${candidate}`,
          "repo_host_traversal_rejected",
        );
      }
    }
    if (!isLast && !nextLst.isDirectory()) {
      throw repoHostError(
        `repo host intermediate path component is not a directory: ${nextReal}`,
        "repo_host_not_a_directory",
      );
    }
    currentReal = nextReal;
    lst = nextLst;
  }

  if (!pathWithinRoot(identity.realpath, currentReal)) {
    throw repoHostError(
      `repo host path resolved outside the bound repo root: ${currentReal}`,
      "repo_host_traversal_rejected",
    );
  }

  return Object.freeze({
    realpath: currentReal,
    dev: lst.dev,
    ino: lst.ino,
    isDirectory: lst.isDirectory(),
    isFile: lst.isFile(),
    size: lst.size,
  });
}

// Opens relPath's fully-resolved real path O_NOFOLLOW (so a leaf swapped to
// a symlink after resolution is rejected at open time), then fstat-matches
// the held fd against the lstat resolveContainedPath just took. A mismatch
// means the path was swapped between resolve and open (rename/unlink+
// recreate race) -- the fd is closed and the call throws. A regular file
// with more than one hard link is rejected too: a same-uid attacker can
// hardlink a sensitive host file into the repo root under an ordinary-
// looking name, which no symlink check catches (no symlink is involved).
// Caller owns the returned fd and must close it.
function openContainedFile(identity, relPath) {
  const resolved = resolveContainedPath(identity, relPath);
  if (!resolved.isFile) {
    throw repoHostError(`repo host path is not a regular file: ${resolved.realpath}`, "repo_host_not_a_file");
  }
  let fd;
  try {
    fd = fs.openSync(resolved.realpath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    throw repoHostError(
      `repo host file open rejected: ${error.message || String(error)}`,
      "repo_host_open_rejected",
    );
  }
  let fstat;
  try {
    fstat = fs.fstatSync(fd);
  } catch (error) {
    fs.closeSync(fd);
    throw repoHostError(`repo host fstat failed: ${error.message || String(error)}`, "repo_host_fstat_failed");
  }
  if (!fstat.isFile()) {
    fs.closeSync(fd);
    throw repoHostError(`repo host path is not a regular file (post-open): ${resolved.realpath}`, "repo_host_not_a_file");
  }
  if (fstat.nlink > 1) {
    fs.closeSync(fd);
    throw repoHostError(
      `repo host path has multiple hard links; refusing to read: ${resolved.realpath}`,
      "repo_host_hardlink_rejected",
    );
  }
  if (fstat.dev !== resolved.dev || fstat.ino !== resolved.ino) {
    fs.closeSync(fd);
    throw repoHostError(
      `repo host path identity changed between resolve and open: ${resolved.realpath}`,
      "repo_host_identity_mismatch",
    );
  }
  return fd;
}

// Convenience wrapper: openContainedFile + bounded read + close. Reads at
// most maxBytes from offset 0 when supplied, else the whole file.
function readContainedFile(identity, relPath, { maxBytes = null } = {}) {
  const fd = openContainedFile(identity, relPath);
  try {
    const fstat = fs.fstatSync(fd);
    const readLen = typeof maxBytes === "number" ? Math.min(maxBytes, fstat.size) : fstat.size;
    const buffer = Buffer.alloc(readLen);
    const bytesRead = readLen > 0 ? fs.readSync(fd, buffer, 0, readLen, 0) : 0;
    return { buffer: buffer.subarray(0, bytesRead), stat: fstat };
  } finally {
    fs.closeSync(fd);
  }
}

function statContainedPath(identity, relPath) {
  const fd = openContainedFile(identity, relPath);
  try {
    return fs.fstatSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// Pins an agent-supplied repo_path override subtree as its OWN identity,
// independently revalidated from then on -- NOT merely inheriting the
// outer session identity's revalidation. Without this, a symlink swap of
// the override subtree between the caller's initial containment check and
// the walk that follows it redirects the entire walk to an arbitrary
// external directory with no re-check (the session-top identity's
// revalidation never looks at the override path at all).
function pinOverrideIdentity(sessionIdentity, overrideRelPath) {
  const resolved = resolveContainedPath(sessionIdentity, overrideRelPath);
  if (!resolved.isDirectory) {
    throw repoHostError(`repo_path override is not a directory: ${resolved.realpath}`, "repo_host_override_not_directory");
  }
  return captureRepoHostIdentity(resolved.realpath);
}

module.exports = {
  bindRepoHostIdentity,
  captureRepoHostIdentity,
  openContainedFile,
  pathWithinRoot,
  pinOverrideIdentity,
  readContainedFile,
  resolveContainedPath,
  revalidateRepoHostIdentity,
  statContainedPath,
};

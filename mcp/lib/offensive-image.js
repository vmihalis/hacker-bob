"use strict";

// offensive-image.js — the SOLE source of the offensive container image digest, and the
// fail-closed preflight that the image is present locally before a wide-open offensive run.
//
// The sandbox (offensive-sandbox.js) runs with `--pull=never` + `name@sha256:<digest>`, so the
// arsenal image MUST be (1) digest-pinned and (2) already in the local docker store. A purely-local
// `docker build` has no RepoDigest, so the digest is minted by scripts/build-offensive-image.sh
// (build -> push to ghcr.io -> pull-by-digest) which writes the lockfile mcp/lib/offensive-image-lock.js
// (a generated `.js` module so install.js's mcp/lib `.js` copy picks it up automatically; a `.json`
// data file would be silently dropped by that copy). This module loads that lockfile and fail-closes
// when it is absent/unloadable (the image hasn't been minted yet), when the pinned digest is not a
// valid name@sha256, or when it is not in the local store (so `--pull=never` would otherwise fail
// cryptically).
//
// PR-IMAGE lands + unit-tests these functions; no production code calls them yet (no tool is wired in
// this PR). PR5b-tool's handler resolves the digest via resolveOffensiveImageDigest() and gates the run
// via assertOffensiveImagePresent().

const path = require("path");
const { IMAGE_DIGEST_RE } = require("./offensive-sandbox.js");

// Generated lockfile, committed next to this module so it travels with mcp/lib on install. It is
// operator-minted (scripts/build-offensive-image.sh) and ABSENT until then.
const LOCK_BASENAME = "offensive-image-lock.js";

function offensiveImageLockPath() {
  return path.join(__dirname, LOCK_BASENAME);
}

// Load + validate the pinned digest. Fail-closed: a missing lockfile, an unloadable lockfile, or a
// non-digest image_digest throws — the image has not been minted, or the lockfile was tampered.
function resolveOffensiveImageDigest({ lockPath = offensiveImageLockPath() } = {}) {
  let lock;
  try {
    lock = require(lockPath);
  } catch (err) {
    if (err && err.code === "MODULE_NOT_FOUND") {
      throw new Error(
        `offensive image not pinned: ${lockPath} is absent. Run scripts/build-offensive-image.sh ` +
          `(start Docker + 'docker login ghcr.io') to build, push, and pin the arsenal image.`
      );
    }
    throw new Error(`offensive image lockfile is not loadable (${lockPath}): ${err && err.message}`);
  }
  const digest = lock && typeof lock.image_digest === "string" ? lock.image_digest : "";
  if (!IMAGE_DIGEST_RE.test(digest)) {
    throw new Error(`offensive image lockfile has no valid name@sha256:<digest> image_digest: ${lockPath}`);
  }
  return digest;
}

// Fail-closed preflight: with `--pull=never` the digest MUST already be in the local image store.
// `docker.inspectImage(digest) -> Promise<boolean>` is injectable so tests drive it without docker.
// Any non-true result (absent, or inspect error) blocks the run with a clear remediation message.
async function assertOffensiveImagePresent(imageDigest, docker) {
  if (typeof imageDigest !== "string" || !IMAGE_DIGEST_RE.test(imageDigest)) {
    throw new Error("assertOffensiveImagePresent requires a digest-pinned image (name@sha256:<64 hex>)");
  }
  if (!docker || typeof docker.inspectImage !== "function") {
    throw new Error("assertOffensiveImagePresent requires a docker.inspectImage(digest) function");
  }
  let present = false;
  try {
    present = await docker.inspectImage(imageDigest);
  } catch {
    present = false;
  }
  if (present !== true) {
    throw new Error(
      `offensive image ${imageDigest} is not present in the local docker store. ` +
        `Run scripts/build-offensive-image.sh to build/push/pull-by-digest before an offensive run.`
    );
  }
}

module.exports = {
  offensiveImageLockPath,
  resolveOffensiveImageDigest,
  assertOffensiveImagePresent,
  OFFENSIVE_IMAGE_LOCK_BASENAME: LOCK_BASENAME,
};

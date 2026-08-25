"use strict";

// offensive-image.js — the SOLE source of the offensive container image digest, and the
// fail-closed preflight that the image is present locally before a wide-open offensive run.
//
// The sandbox (offensive-sandbox.js) runs with `--pull=never` + `name@sha256:<digest>`, so the
// arsenal image MUST be (1) digest-pinned and (2) already in the local docker store. A purely-local
// `docker build` has no RepoDigest, so the digest is minted by scripts/build-offensive-image.sh
// (build -> push to ghcr.io -> pull-by-digest) which writes the lockfile mcp/offensive-image.json.
//
// The lockfile is JSON read FRESH with fs.readFileSync + JSON.parse on every call — it is DATA, never
// executed. (An earlier `.js` + require() form was rejected in review: require() caches by resolved path,
// so a live MCP process would keep serving a stale digest after an image bump; and a generated `.js`
// lockfile executes arbitrary code before any validation — a broken trust boundary. JSON closes both.)
// Because the runtime subtree copy is `.js`/`.sh`-only, install.js copies this `.json` lockfile explicitly.
//
// Fail-closed when the lockfile is absent (not minted yet), unparseable, or carries a non-name@sha256
// digest; and when the pinned digest is not in the local store (so `--pull=never` won't fail cryptically).
//
// PR-IMAGE lands + unit-tests these functions; no production code calls them yet (no tool is wired in
// this PR). PR5b-tool's handler resolves the digest via resolveOffensiveImageDigest() and gates the run
// via assertOffensiveImagePresent().

const fs = require("fs");
const path = require("path");
const { IMAGE_DIGEST_RE } = require("./offensive-sandbox.js");

const LOCK_BASENAME = "offensive-image.json";

// Operator-minted lockfile next to this module — OPERATOR-LOCAL (gitignored; the digest is deployment-specific,
// so it is NOT committed/shipped). install.js copies it into the runtime if present; ABSENT until minted.
function offensiveImageLockPath() {
  return path.join(__dirname, "..", "..", LOCK_BASENAME);
}

// Load + validate the pinned digest, reading the lockfile FRESH each call (no module cache, so an image
// bump is picked up by a live process). Fail-closed on absent / unparseable / non-object / non-digest.
function resolveOffensiveImageDigest({ lockPath = offensiveImageLockPath() } = {}) {
  let raw;
  try {
    raw = fs.readFileSync(lockPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") {
      throw new Error(
        `offensive image not pinned: ${lockPath} is absent. Run scripts/build-offensive-image.sh ` +
          `(start Docker + 'docker login ghcr.io') to build, push, and pin the arsenal image.`
      );
    }
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`offensive image lockfile is not valid JSON: ${lockPath}`);
  }
  const digest =
    parsed && typeof parsed === "object" && typeof parsed.image_digest === "string" ? parsed.image_digest : "";
  if (!IMAGE_DIGEST_RE.test(digest)) {
    throw new Error(`offensive image lockfile has no valid name@sha256:<digest> image_digest: ${lockPath}`);
  }
  return digest;
}

// Fail-closed preflight: with `--pull=never` the digest MUST already be in the local image store.
// `docker.inspectImage(digest) -> Promise<boolean>` is injectable so tests drive it without docker.
// On a false/error result the run is blocked; the underlying docker error (e.g. daemon down vs image
// absent) is surfaced in the message for diagnosis while still failing closed.
async function assertOffensiveImagePresent(imageDigest, docker) {
  if (typeof imageDigest !== "string" || !IMAGE_DIGEST_RE.test(imageDigest)) {
    throw new Error("assertOffensiveImagePresent requires a digest-pinned image (name@sha256:<64 hex>)");
  }
  if (!docker || typeof docker.inspectImage !== "function") {
    throw new Error("assertOffensiveImagePresent requires a docker.inspectImage(digest) function");
  }
  let present = false;
  let inspectError = null;
  try {
    present = await docker.inspectImage(imageDigest);
  } catch (err) {
    inspectError = err;
    present = false;
  }
  if (present !== true) {
    const why = inspectError ? ` (docker inspect failed: ${inspectError.message})` : "";
    throw new Error(
      `offensive image ${imageDigest} is not present in the local docker store${why}. ` +
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

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  offensiveImageLockPath,
  resolveOffensiveImageDigest,
  assertOffensiveImagePresent,
  OFFENSIVE_IMAGE_LOCK_BASENAME,
} = require("../mcp/lib/offensive-image.js");

const GOOD = "ghcr.io/bobnetsec/bob-offense@sha256:" + "a".repeat(64);

// create a temp lockfile path; pass `contents` (a `.js` module body) to write the file, omit to
// leave it absent. Each call uses a fresh temp dir so require()-cache never collides across cases.
function tmpLock(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offimg-"));
  const p = path.join(dir, "offensive-image-lock.js");
  if (contents !== undefined) fs.writeFileSync(p, contents);
  return p;
}
const lockModule = (obj) => `module.exports = ${JSON.stringify(obj)};\n`;

test("offensiveImageLockPath resolves to mcp/lib/offensive-image-lock.js", () => {
  assert.equal(OFFENSIVE_IMAGE_LOCK_BASENAME, "offensive-image-lock.js");
  assert.ok(offensiveImageLockPath().endsWith(path.join("mcp", "lib", "offensive-image-lock.js")));
});

test("resolveOffensiveImageDigest: fail-closed when the lockfile is absent", () => {
  const p = tmpLock(undefined); // dir exists, file does not
  assert.throws(() => resolveOffensiveImageDigest({ lockPath: p }), /not pinned/);
});

test("resolveOffensiveImageDigest: fail-closed on an unloadable lockfile", () => {
  assert.throws(() => resolveOffensiveImageDigest({ lockPath: tmpLock("this is }{ not js") }), /not loadable/);
});

test("resolveOffensiveImageDigest: rejects a non-digest image_digest (mutable tag, short, empty, missing)", () => {
  for (const bad of [
    lockModule({ image_digest: "ghcr.io/x/bob-offense:latest" }),
    lockModule({ image_digest: "ghcr.io/x/bob-offense@sha256:short" }),
    lockModule({ image_digest: "" }),
    lockModule({ notdigest: GOOD }),
  ]) {
    assert.throws(() => resolveOffensiveImageDigest({ lockPath: tmpLock(bad) }), /no valid name@sha256/);
  }
});

test("resolveOffensiveImageDigest: returns a valid pinned digest", () => {
  const p = tmpLock(lockModule({ image_digest: GOOD, tools: { httpx: "1.0.0" } }));
  assert.equal(resolveOffensiveImageDigest({ lockPath: p }), GOOD);
});

test("assertOffensiveImagePresent: requires a digest-pinned image (rejects a mutable tag)", async () => {
  await assert.rejects(
    () => assertOffensiveImagePresent("bob-offense:latest", { inspectImage: async () => true }),
    /digest-pinned image/
  );
});

test("assertOffensiveImagePresent: requires a docker.inspectImage function", async () => {
  await assert.rejects(() => assertOffensiveImagePresent(GOOD, {}), /inspectImage/);
});

test("assertOffensiveImagePresent: resolves and queries the exact digest when present", async () => {
  let askedFor = null;
  await assertOffensiveImagePresent(GOOD, {
    inspectImage: async (d) => {
      askedFor = d;
      return true;
    },
  });
  assert.equal(askedFor, GOOD);
});

test("assertOffensiveImagePresent: fail-closed when the image is absent", async () => {
  await assert.rejects(
    () => assertOffensiveImagePresent(GOOD, { inspectImage: async () => false }),
    /not present in the local docker store/
  );
});

test("assertOffensiveImagePresent: fail-closed (not a leak) when inspect throws", async () => {
  await assert.rejects(
    () =>
      assertOffensiveImagePresent(GOOD, {
        inspectImage: async () => {
          throw new Error("boom");
        },
      }),
    /not present in the local docker store/
  );
});

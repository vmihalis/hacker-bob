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
} = require("../mcp/domains/web/offensive-image.js");

const GOOD = "ghcr.io/bobnetsec/bob-offense@sha256:" + "a".repeat(64);

// create a temp lockfile path; pass `contents` (JSON text) to write the file, omit to leave it absent.
function tmpLock(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offimg-"));
  const p = path.join(dir, "offensive-image.json");
  if (contents !== undefined) fs.writeFileSync(p, contents);
  return p;
}

test("offensiveImageLockPath resolves to mcp/offensive-image.json", () => {
  assert.equal(OFFENSIVE_IMAGE_LOCK_BASENAME, "offensive-image.json");
  assert.ok(offensiveImageLockPath().endsWith(path.join("mcp", "offensive-image.json")));
});

test("resolveOffensiveImageDigest: fail-closed when the lockfile is absent", () => {
  const p = tmpLock(undefined); // dir exists, file does not
  assert.throws(() => resolveOffensiveImageDigest({ lockPath: p }), /not pinned/);
});

test("resolveOffensiveImageDigest: fail-closed on invalid JSON", () => {
  assert.throws(() => resolveOffensiveImageDigest({ lockPath: tmpLock("not json{") }), /not valid JSON/);
});

test("resolveOffensiveImageDigest: rejects non-object and non-digest lockfiles", () => {
  for (const bad of [
    "null",
    "5",
    JSON.stringify({ image_digest: "ghcr.io/x/bob-offense:latest" }),
    JSON.stringify({ image_digest: "ghcr.io/x/bob-offense@sha256:short" }),
    JSON.stringify({ image_digest: "" }),
    JSON.stringify({ notdigest: GOOD }),
  ]) {
    assert.throws(() => resolveOffensiveImageDigest({ lockPath: tmpLock(bad) }), /no valid name@sha256/);
  }
});

test("resolveOffensiveImageDigest: returns a valid pinned digest", () => {
  const p = tmpLock(JSON.stringify({ image_digest: GOOD, tools: { httpx: "1.0.0" } }));
  assert.equal(resolveOffensiveImageDigest({ lockPath: p }), GOOD);
});

test("resolveOffensiveImageDigest: reads fresh each call (no require cache — picks up a bump)", () => {
  const p = tmpLock(JSON.stringify({ image_digest: GOOD }));
  assert.equal(resolveOffensiveImageDigest({ lockPath: p }), GOOD);
  const BUMPED = "ghcr.io/bobnetsec/bob-offense@sha256:" + "b".repeat(64);
  fs.writeFileSync(p, JSON.stringify({ image_digest: BUMPED }));
  assert.equal(resolveOffensiveImageDigest({ lockPath: p }), BUMPED);
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

test("assertOffensiveImagePresent: fail-closed AND surfaces the docker error when inspect throws", async () => {
  await assert.rejects(
    () =>
      assertOffensiveImagePresent(GOOD, {
        inspectImage: async () => {
          throw new Error("daemon down");
        },
      }),
    (e) => /not present in the local docker store/.test(e.message) && /daemon down/.test(e.message)
  );
});

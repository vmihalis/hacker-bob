"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  writeFileExclusiveAtomic,
  writeFileExclusiveAtomicReceipt,
} = require("../mcp/core/io/storage.js");

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-storage-exclusive-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function patchFs(method, replacement, fn) {
  const original = fs[method];
  fs[method] = replacement(original);
  try {
    return fn();
  } finally {
    fs[method] = original;
  }
}

function assertNoTempFor(target) {
  const entries = fs.existsSync(path.dirname(target))
    ? fs.readdirSync(path.dirname(target))
    : [];
  assert.deepEqual(
    entries.filter((entry) => entry.startsWith(`.${path.basename(target)}.`)),
    [],
  );
}

function isTempFor(target, candidate) {
  return path.dirname(candidate) === path.dirname(target)
    && path.basename(candidate).startsWith(`.${path.basename(target)}.`);
}

test("writeFileExclusiveAtomicReceipt contains mkdir failures as receipts", () => {
  withTempDir((dir) => {
    const parent = path.join(dir, "nested");
    const filePath = path.join(parent, "exclusive.txt");
    const injected = new Error("injected mkdir failure");

    const receipt = patchFs("mkdirSync", (realMkdir) => function patchedMkdirSync(target, options) {
      if (path.resolve(target) === path.resolve(parent)) throw injected;
      return realMkdir.call(fs, target, options);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "created"));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "mkdir");
    assert.equal(receipt.error, injected);
    assert.equal(receipt.tempPath, null);
    assert.equal(receipt.tempCandidate, null);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.existsSync(parent), false);

    assert.throws(
      () => patchFs("mkdirSync", (realMkdir) => function patchedMkdirSync(target, options) {
        if (path.resolve(target) === path.resolve(parent)) throw injected;
        return realMkdir.call(fs, target, options);
      }, () => writeFileExclusiveAtomic(filePath, "created")),
      (error) => error === injected && error.exclusiveReceipt.phase === "mkdir",
    );
  });
});

test("writeFileExclusiveAtomicReceipt reports temp-open EEXIST as unresolved failure", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "exclusive.txt");
    const injected = new Error("injected temp exists");
    injected.code = "EEXIST";

    const receipt = patchFs("openSync", (realOpen) => function patchedOpenSync(target, flags, mode) {
      if (isTempFor(filePath, target)) throw injected;
      return realOpen.call(fs, target, flags, mode);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "created"));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "temp_open");
    assert.equal(receipt.error, injected);
    assert.deepEqual(receipt.unresolvedTemp, {
      path: receipt.tempPath,
      reason: "temp_exists",
    });
    assert.equal(receipt.tempCandidate, null);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.existsSync(filePath), false);

    assert.throws(
      () => patchFs("openSync", (realOpen) => function patchedOpenSync(target, flags, mode) {
        if (isTempFor(filePath, target)) throw injected;
        return realOpen.call(fs, target, flags, mode);
      }, () => writeFileExclusiveAtomic(filePath, "created")),
      (error) => error === injected && error.exclusiveReceipt.phase === "temp_open",
    );
  });
});

test("link EEXIST winner probe failures are diagnostic and cleanup still runs", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "probe-winner.txt");
    const probeFailure = new Error("injected winner probe failure");
    fs.writeFileSync(filePath, "winner", "utf8");
    const before = fs.lstatSync(filePath);

    const receipt = patchFs("lstatSync", (realLstat) => function patchedLstatSync(target) {
      if (path.resolve(target) === path.resolve(filePath)) throw probeFailure;
      return realLstat.call(fs, target);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "replacement"));

    assert.equal(receipt.status, "exists");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.error.code, "EEXIST");
    assert.equal(receipt.probeError, probeFailure);
    assert.equal(receipt.cleanupError, undefined);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.readFileSync(filePath, "utf8"), "winner");
    const after = fs.lstatSync(filePath);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assertNoTempFor(filePath);
  });
});

test("writeFileExclusiveAtomic treats link EEXIST winners as final collisions", () => {
  withTempDir((dir) => {
    const cases = [
      ["file", (target) => fs.writeFileSync(target, "winner", "utf8")],
      ["symlink", (target) => {
        const winner = path.join(dir, "symlink-winner.txt");
        fs.writeFileSync(winner, "winner", "utf8");
        fs.symlinkSync(winner, target);
      }],
      ["directory", (target) => fs.mkdirSync(target)],
    ];

    for (const [kind, createWinner] of cases) {
      const filePath = path.join(dir, `${kind}-target`);
      createWinner(filePath);
      const before = fs.lstatSync(filePath);
      const beforeBytes = before.isFile() && !before.isSymbolicLink()
        ? fs.readFileSync(filePath, "utf8")
        : null;

      const receipt = writeFileExclusiveAtomicReceipt(filePath, "replacement");
      assert.equal(receipt.status, "exists", kind);
      assert.equal(receipt.phase, "link", kind);
      assert.equal(receipt.finalCandidate.type, kind, kind);
      assert.equal(receipt.finalCandidate.owned, false, kind);
      assert.equal(writeFileExclusiveAtomic(filePath, "replacement"), false, kind);

      const after = fs.lstatSync(filePath);
      assert.equal(after.dev, before.dev, kind);
      assert.equal(after.ino, before.ino, kind);
      if (beforeBytes !== null) assert.equal(fs.readFileSync(filePath, "utf8"), beforeBytes, kind);
    }
  });
});

test("link failure after publish keeps link primary when final probe fails", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "link-probe-failure.txt");
    const realLinkSync = fs.linkSync;
    const linkFailure = new Error("injected link failure after publish");
    const probeFailure = new Error("injected final probe failure");

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      realLinkSync.call(fs, source, destination);
      throw linkFailure;
    }, () => patchFs("lstatSync", (realLstat) => function patchedLstatSync(target) {
      if (path.resolve(target) === path.resolve(filePath)) throw probeFailure;
      return realLstat.call(fs, target);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned")));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.error, linkFailure);
    assert.equal(receipt.probeError, probeFailure);
    assert.equal(receipt.cleanupError, undefined);
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.readFileSync(filePath, "utf8"), "owned");
    assertNoTempFor(filePath);

    assert.throws(
      () => patchFs("linkSync", () => function patchedLinkSync(source, destination) {
        realLinkSync.call(fs, source, destination);
        throw linkFailure;
      }, () => patchFs("lstatSync", (realLstat) => function patchedLstatSync(target) {
        if (path.resolve(target) === path.resolve(path.join(dir, "wrapper-link-probe.txt"))) throw probeFailure;
        return realLstat.call(fs, target);
      }, () => writeFileExclusiveAtomic(path.join(dir, "wrapper-link-probe.txt"), "owned"))),
      (error) => error === linkFailure
        && error.probeError === probeFailure
        && error.exclusiveReceipt.probeError === probeFailure,
    );
  });
});

test("link failure after publish records post-cleanup re-probe failures", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "link-reprobe-failure.txt");
    const realLinkSync = fs.linkSync;
    const linkFailure = new Error("injected link failure after publish");
    const probeFailure = new Error("injected post-cleanup probe failure");
    let finalProbeCount = 0;

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      realLinkSync.call(fs, source, destination);
      throw linkFailure;
    }, () => patchFs("lstatSync", (realLstat) => function patchedLstatSync(target) {
      if (path.resolve(target) === path.resolve(filePath)) {
        finalProbeCount += 1;
        if (finalProbeCount === 2) throw probeFailure;
      }
      return realLstat.call(fs, target);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned")));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.error, linkFailure);
    assert.equal(receipt.probeError, probeFailure);
    assert.equal(receipt.cleanupError, undefined);
    assert.equal(receipt.finalCandidate.owned, true);
    assert.equal(fs.readFileSync(filePath, "utf8"), "owned");
    assertNoTempFor(filePath);
  });
});

test("link failure after publish preserves cleanup failure as diagnostic", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "link-cleanup-failure.txt");
    const realLinkSync = fs.linkSync;
    const linkFailure = new Error("injected link failure after publish");
    const cleanupFailure = new Error("injected temp cleanup failure");
    let stagedTemp = null;

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      stagedTemp = source;
      realLinkSync.call(fs, source, destination);
      throw linkFailure;
    }, () => patchFs("unlinkSync", (realUnlink) => function patchedUnlinkSync(target) {
      if (stagedTemp && path.resolve(target) === path.resolve(stagedTemp)) throw cleanupFailure;
      return realUnlink.call(fs, target);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned")));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.error, linkFailure);
    assert.equal(receipt.cleanupError, cleanupFailure);
    assert.equal(receipt.probeError, undefined);
    assert.equal(receipt.finalCandidate.owned, true);
    assert.equal(fs.readFileSync(filePath, "utf8"), "owned");
    assert.equal(fs.existsSync(stagedTemp), true);
  });
});

test("post-link proof failure records owned final candidate when temp was replaced", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "post-link.txt");
    const realLinkSync = fs.linkSync;
    let replacedTemp = null;

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      realLinkSync.call(fs, source, destination);
      if (path.resolve(destination) === path.resolve(filePath)) {
        replacedTemp = source;
        fs.unlinkSync(source);
        fs.writeFileSync(source, "replacement-temp", "utf8");
      }
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned-final"));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "postlink_proof");
    assert.equal(receipt.finalCandidate.owned, true);
    assert.equal(receipt.finalCandidate.nlink, 1);
    assert.equal(fs.readFileSync(filePath, "utf8"), "owned-final");
    assert.equal(fs.readFileSync(replacedTemp, "utf8"), "replacement-temp");
  });
});

test("wrong-source link return removes only the owned temp candidate", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "wrong-source.txt");
    const wrongSource = path.join(dir, "wrong-source-real.txt");
    fs.writeFileSync(wrongSource, "wrong", "utf8");
    const realLinkSync = fs.linkSync;

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      if (path.resolve(destination) === path.resolve(filePath)) {
        realLinkSync.call(fs, wrongSource, destination);
        return;
      }
      realLinkSync.call(fs, source, destination);
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned"));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "postlink_proof");
    assert.equal(receipt.finalCandidate, null);
    assert.equal(fs.readFileSync(filePath, "utf8"), "wrong");
    assert.equal(fs.existsSync(receipt.tempPath), false);
  });
});

test("real-link-then-throw records owned final candidate and cleans temp", () => {
  withTempDir((dir) => {
    const filePath = path.join(dir, "link-throw.txt");
    const realLinkSync = fs.linkSync;
    const injected = new Error("injected link failure after publish");

    const receipt = patchFs("linkSync", () => function patchedLinkSync(source, destination) {
      realLinkSync.call(fs, source, destination);
      throw injected;
    }, () => writeFileExclusiveAtomicReceipt(filePath, "owned"));

    assert.equal(receipt.status, "failed");
    assert.equal(receipt.phase, "link");
    assert.equal(receipt.error, injected);
    assert.equal(receipt.finalCandidate.owned, true);
    assert.equal(fs.readFileSync(filePath, "utf8"), "owned");
    assert.equal(fs.existsSync(receipt.tempPath), false);
  });
});

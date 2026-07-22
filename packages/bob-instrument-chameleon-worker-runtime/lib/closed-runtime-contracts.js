"use strict";

// Package-private copies of the two provider-neutral primitives required by
// the closed worker. Keeping this tiny contract seam inside the signed worker
// package makes the same bytes load in both Bob's embedded sibling-package
// topology and the optional worker's closed CommonJS topology. Parity tests
// bind these implementations to the canonical instrument contracts.

const crypto = require("node:crypto");

const MAX_PUBLIC_RESULT_GRAPH_NODES = 4_096;
const MAX_PUBLIC_RESULT_GRAPH_DEPTH = 64;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  if (isPlainObject(value)) {
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      Object.defineProperty(result, key, {
        value: canonicalize(value[key]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function hashCanonicalJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function assertNoPublicByteMaterial(value, label = "public_result") {
  const seen = new Set();
  const stack = [{ item: value, path: label, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    const item = current.item;
    if (item == null || typeof item !== "object") continue;
    if (seen.has(item)) throw new Error(`${current.path} must not contain repeated objects or cycles`);
    seen.add(item);
    nodes += 1;
    if (nodes > MAX_PUBLIC_RESULT_GRAPH_NODES
        || current.depth > MAX_PUBLIC_RESULT_GRAPH_DEPTH) {
      throw new Error(`${label} exceeds the bounded public result graph`);
    }
    if (Buffer.isBuffer(item)
        || item instanceof ArrayBuffer
        || ArrayBuffer.isView(item)) {
      throw new Error(`${current.path} must not contain raw byte material`);
    }
    const keys = Reflect.ownKeys(item);
    if (keys.some((field) => typeof field !== "string")) {
      throw new Error(`${current.path} cannot contain symbol fields`);
    }
    if (Array.isArray(item)) {
      const expected = new Set([
        "length",
        ...Array.from({ length: item.length }, (_, index) => String(index)),
      ]);
      if (keys.some((field) => !expected.has(field)) || keys.length !== expected.size) {
        throw new Error(`${current.path} must be a dense array without extra fields`);
      }
    }
    for (const field of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(item, field);
      const arrayLength = Array.isArray(item) && field === "length";
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
          || (!descriptor.enumerable && !arrayLength)) {
        throw new Error(`${current.path}.${field} must be an enumerable data field`);
      }
      if (!arrayLength) {
        stack.push({
          item: descriptor.value,
          path: Array.isArray(item) ? `${current.path}[${field}]` : `${current.path}.${field}`,
          depth: current.depth + 1,
        });
      }
    }
  }
  return true;
}

module.exports = Object.freeze({
  assertNoPublicByteMaterial,
  hashCanonicalJson,
});

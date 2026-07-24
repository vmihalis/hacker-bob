"use strict";

const crypto = require("crypto");
const { types: utilTypes } = require("node:util");

// These contracts authenticate authority, lease, journal, and evidence
// bindings. Capture the full canonical-hash seam once so application code
// cannot replace crypto, JSON, Array, Object, Reflect, or proxy-detection
// intrinsics after import and make attacker-selected data appear to retain a
// previously durable digest.
const ArrayIntrinsic = Array;
const arrayIsArray = Array.isArray;
const arrayPrototypeSort = Array.prototype.sort;
const cryptoCreateHash = crypto.createHash;
const cryptoHashDigest = crypto.Hash.prototype.digest;
const cryptoHashUpdate = crypto.Hash.prototype.update;
const JSONIntrinsic = JSON;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const NumberIntrinsic = Number;
const ObjectIntrinsic = Object;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const objectPrototype = Object.prototype;
const numberIsSafeInteger = Number.isSafeInteger;
const ReflectIntrinsic = Reflect;
const reflectApply = Reflect.apply;
const reflectDeleteProperty = Reflect.deleteProperty;
const reflectOwnKeys = Reflect.ownKeys;
const TypeErrorConstructor = TypeError;
const utilIsProxy = utilTypes.isProxy;
const WeakSetConstructor = WeakSet;
const weakSetAdd = WeakSet.prototype.add;
const weakSetDelete = WeakSet.prototype.delete;
const weakSetHas = WeakSet.prototype.has;

function apply(function_, receiver, arguments_) {
  return reflectApply(function_, receiver, arguments_);
}

function hasOwn(value, key) {
  return apply(objectHasOwnProperty, value, [key]);
}

function ownDescriptor(value, key) {
  return apply(objectGetOwnPropertyDescriptor, ObjectIntrinsic, [value, key]);
}

function descriptorValue(descriptor) {
  if (descriptor == null || !hasOwn(descriptor, "value")) {
    throw new TypeErrorConstructor("canonical JSON input cannot contain accessor properties");
  }
  return descriptor.value;
}

function dataPropertyDescriptor(value, enumerable, configurable, writable) {
  // ToPropertyDescriptor consults inherited `get`/`set` fields. A descriptor
  // object with Object.prototype in its chain therefore becomes attacker-
  // controlled after prototype pollution, even when defineProperty itself was
  // captured. Null-prototype dictionaries keep descriptor interpretation inert.
  const descriptor = apply(objectCreate, ObjectIntrinsic, [null]);
  descriptor.value = value;
  descriptor.enumerable = enumerable;
  descriptor.configurable = configurable;
  descriptor.writable = writable;
  return descriptor;
}

function defineDataProperty(target, key, value) {
  apply(objectDefineProperty, ObjectIntrinsic, [
    target,
    key,
    dataPropertyDescriptor(value, true, true, true),
  ]);
}

function preserveArrayLength(target, length) {
  apply(objectDefineProperty, ObjectIntrinsic, [
    target,
    "length",
    dataPropertyDescriptor(length, false, false, true),
  ]);
}

function proxyDetected(value) {
  return apply(utilIsProxy, utilTypes, [value]);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || proxyDetected(value)
      || apply(arrayIsArray, ArrayIntrinsic, [value])) return false;
  const prototype = apply(objectGetPrototypeOf, ObjectIntrinsic, [value]);
  return prototype === objectPrototype || prototype === null;
}

function arrayLength(value) {
  const descriptor = ownDescriptor(value, "length");
  const length = descriptorValue(descriptor);
  if (!apply(numberIsSafeInteger, NumberIntrinsic, [length]) || length < 0) {
    throw new TypeErrorConstructor("canonical JSON array length is invalid");
  }
  return length;
}

function arrayIndexForKey(key) {
  const numeric = apply(NumberIntrinsic, undefined, [key]);
  if (!apply(numberIsSafeInteger, NumberIntrinsic, [numeric])
      || numeric < 0 || numeric >= 0xffffffff || `${numeric}` !== key) {
    return null;
  }
  return numeric;
}

function compareCanonicalObjectKeys(left, right) {
  const leftIndex = arrayIndexForKey(left);
  const rightIndex = arrayIndexForKey(right);
  if (leftIndex != null && rightIndex != null) return leftIndex - rightIndex;
  if (leftIndex != null) return -1;
  if (rightIndex != null) return 1;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function sortedEnumerableStringKeys(value) {
  const ownKeys = apply(reflectOwnKeys, ReflectIntrinsic, [value]);
  const keys = [];
  let keyCount = 0;
  for (let index = 0; index < ownKeys.length; index += 1) {
    const key = ownKeys[index];
    if (typeof key !== "string") continue;
    const descriptor = ownDescriptor(value, key);
    if (descriptor == null || descriptor.enumerable !== true) continue;
    descriptorValue(descriptor);
    defineDataProperty(keys, `${keyCount}`, key);
    keyCount += 1;
  }
  // Legacy canonicalization first created lexically sorted properties on a
  // null-prototype object and then delegated enumeration to JSON.stringify.
  // Native property order moves array-index keys ahead in numeric order while
  // preserving lexical insertion order for all remaining string keys.
  apply(arrayPrototypeSort, keys, [compareCanonicalObjectKeys]);
  return keys;
}

function canonicalizeValue(value, ancestors) {
  const valueType = typeof value;
  if (value != null && (valueType === "object" || valueType === "function")
      && proxyDetected(value)) {
    throw new TypeErrorConstructor("canonical JSON input cannot contain proxies");
  }
  if (apply(arrayIsArray, ArrayIntrinsic, [value])) {
    if (apply(weakSetHas, ancestors, [value])) {
      throw new TypeErrorConstructor("canonical JSON input cannot contain cycles");
    }
    apply(weakSetAdd, ancestors, [value]);
    try {
      const result = [];
      const length = arrayLength(value);
      for (let index = 0; index < length; index += 1) {
        const descriptor = ownDescriptor(value, `${index}`);
        if (descriptor == null) continue;
        defineDataProperty(
          result,
          `${index}`,
          canonicalizeValue(descriptorValue(descriptor), ancestors),
        );
      }
      preserveArrayLength(result, length);
      return result;
    } finally {
      apply(weakSetDelete, ancestors, [value]);
    }
  }
  if (value != null && typeof value === "object") {
    if (!isPlainObject(value)) {
      throw new TypeErrorConstructor("canonical JSON input must contain only plain data objects");
    }
    if (apply(weakSetHas, ancestors, [value])) {
      throw new TypeErrorConstructor("canonical JSON input cannot contain cycles");
    }
    apply(weakSetAdd, ancestors, [value]);
    try {
      const result = apply(objectCreate, ObjectIntrinsic, [null]);
      const keys = sortedEnumerableStringKeys(value);
      for (let index = 0; index < keys.length; index += 1) {
        const key = descriptorValue(ownDescriptor(keys, `${index}`));
        const child = descriptorValue(ownDescriptor(value, key));
        if (child === undefined) continue;
        defineDataProperty(result, key, canonicalizeValue(child, ancestors));
      }
      return result;
    } finally {
      apply(weakSetDelete, ancestors, [value]);
    }
  }
  return value;
}

function canonicalize(value) {
  return canonicalizeValue(value, new WeakSetConstructor());
}

function serializePrimitive(value) {
  if (value === null || typeof value === "string" || typeof value === "number"
      || typeof value === "boolean") {
    return apply(jsonStringify, JSONIntrinsic, [value]);
  }
  if (typeof value === "bigint") {
    throw new TypeErrorConstructor("canonical JSON input cannot contain bigint values");
  }
  return undefined;
}

function serializeCanonicalValue(value) {
  if (apply(arrayIsArray, ArrayIntrinsic, [value])) {
    const length = arrayLength(value);
    let serialized = "[";
    for (let index = 0; index < length; index += 1) {
      if (index > 0) serialized += ",";
      const descriptor = ownDescriptor(value, `${index}`);
      if (descriptor == null) {
        serialized += "null";
        continue;
      }
      const child = serializeCanonicalValue(descriptorValue(descriptor));
      serialized += child === undefined ? "null" : child;
    }
    return `${serialized}]`;
  }
  if (isPlainObject(value)) {
    const keys = sortedEnumerableStringKeys(value);
    let serialized = "{";
    let emitted = 0;
    for (let index = 0; index < keys.length; index += 1) {
      const key = descriptorValue(ownDescriptor(keys, `${index}`));
      const childValue = descriptorValue(ownDescriptor(value, key));
      const child = serializeCanonicalValue(childValue);
      if (child === undefined) continue;
      if (emitted > 0) serialized += ",";
      serialized += `${serializePrimitive(key)}:${child}`;
      emitted += 1;
    }
    return `${serialized}}`;
  }
  return serializePrimitive(value);
}

function canonicalJson(value) {
  return serializeCanonicalValue(canonicalize(value));
}

function hashCanonicalJson(value) {
  const hash = apply(cryptoCreateHash, crypto, ["sha256"]);
  apply(cryptoHashUpdate, hash, [canonicalJson(value)]);
  return apply(cryptoHashDigest, hash, ["hex"]);
}

function cloneJson(value) {
  return apply(jsonParse, JSONIntrinsic, [canonicalJson(value)]);
}

function documentHashExcluding(document, fields) {
  const copy = cloneJson(document);
  if (proxyDetected(fields) || !apply(arrayIsArray, ArrayIntrinsic, [fields])) {
    throw new TypeErrorConstructor("excluded hash fields must be an array");
  }
  const length = arrayLength(fields);
  for (let index = 0; index < length; index += 1) {
    const descriptor = ownDescriptor(fields, `${index}`);
    const field = descriptor == null ? undefined : descriptorValue(descriptor);
    apply(reflectDeleteProperty, ReflectIntrinsic, [copy, field]);
  }
  return hashCanonicalJson(copy);
}

function finalVerificationHash(document) {
  return documentHashExcluding(document, ["final_verification_hash"]);
}

function adjudicationHashPayload(document) {
  const payload = cloneJson(document);
  apply(reflectDeleteProperty, ReflectIntrinsic, [payload, "adjudication_plan_hash"]);
  apply(reflectDeleteProperty, ReflectIntrinsic, [payload, "built_at"]);
  return payload;
}

function computeAdjudicationPlanHash(document) {
  return hashCanonicalJson(adjudicationHashPayload(document));
}

module.exports = {
  adjudicationHashPayload,
  canonicalJson,
  canonicalize,
  cloneJson,
  computeAdjudicationPlanHash,
  documentHashExcluding,
  finalVerificationHash,
  hashCanonicalJson,
  isPlainObject,
};

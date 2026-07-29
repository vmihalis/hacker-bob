"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const arrayIsArray = Array.isArray;
const arrayJoin = Array.prototype.join;
const arrayPush = Array.prototype.push;
const cryptoCreateHash = crypto.createHash;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const objectIs = Object.is;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const reflectOwnKeys = Reflect.ownKeys;
const reflectApply = Reflect.apply;
const safeString = String;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringFromCharCode = String.fromCharCode;
const utilTypesIsProxy = utilTypes.isProxy;

const ARRAY_PROTOTYPE = Array.prototype;
const MAX_CANONICAL_STRING_UNITS = 64 * 1024;
const MAX_CANONICAL_ARRAY_ITEMS = 256;
const HEX = "0123456789abcdef";
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;

function canonicalError() {
  const error = new SafeError("Canonical snapshot was rejected");
  objectDefineProperty(error, "code", {
    value: "canonical_snapshot_rejected",
    writable: false,
    enumerable: false,
    configurable: false,
  });
  return error;
}

function escapeString(value) {
  if (typeof value !== "string" || value.length > MAX_CANONICAL_STRING_UNITS) {
    throw canonicalError();
  }
  let encoded = '"';
  for (let index = 0; index < value.length; index += 1) {
    const unit = reflectApply(stringCharCodeAt, value, [index]);
    if (unit === 0x22) encoded += '\\"';
    else if (unit === 0x5c) encoded += "\\\\";
    else if (unit === 0x08) encoded += "\\b";
    else if (unit === 0x0c) encoded += "\\f";
    else if (unit === 0x0a) encoded += "\\n";
    else if (unit === 0x0d) encoded += "\\r";
    else if (unit === 0x09) encoded += "\\t";
    else if (unit < 0x20 || unit === 0x2028 || unit === 0x2029
        || (unit >= 0xd800 && unit <= 0xdfff)) {
      encoded += `\\u${HEX[(unit >> 12) & 0xf]}${HEX[(unit >> 8) & 0xf]}${
        HEX[(unit >> 4) & 0xf]}${HEX[unit & 0xf]}`;
    } else {
      encoded += stringFromCharCode(unit);
    }
  }
  return `${encoded}"`;
}

function serializeArray(value) {
  if (!arrayIsArray(value) || utilTypesIsProxy(value)
      || objectGetPrototypeOf(value) !== ARRAY_PROTOTYPE
      || value.length > MAX_CANONICAL_ARRAY_ITEMS) throw canonicalError();
  const ownKeys = reflectOwnKeys(value);
  if (ownKeys.length !== value.length + 1 || ownKeys[ownKeys.length - 1] !== "length") {
    throw canonicalError();
  }
  const serialized = [];
  for (let index = 0; index < value.length; index += 1) {
    const key = safeString(index);
    if (ownKeys[index] !== key) throw canonicalError();
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) throw canonicalError();
    reflectApply(arrayPush, serialized, [serializeValue(descriptor.value)]);
  }
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor == null || !objectHasOwn(lengthDescriptor, "value")
      || lengthDescriptor.value !== value.length) throw canonicalError();
  return `[${reflectApply(arrayJoin, serialized, [","])}]`;
}

function serializeValue(value) {
  if (typeof value === "string") return escapeString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!numberIsFinite(value) || !numberIsSafeInteger(value) || objectIs(value, -0)) {
      throw canonicalError();
    }
    return safeString(value);
  }
  if (arrayIsArray(value)) return serializeArray(value);
  throw canonicalError();
}

function copyFixedObject(input, fields) {
  if (input == null || typeof input !== "object" || utilTypesIsProxy(input)
      || !arrayIsArray(fields) || utilTypesIsProxy(fields)) throw canonicalError();
  const actual = objectKeys(input);
  if (actual.length !== fields.length) throw canonicalError();
  const copy = objectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (typeof field !== "string" || actual[index] !== field) throw canonicalError();
    const descriptor = objectGetOwnPropertyDescriptor(input, field);
    if (descriptor == null || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) throw canonicalError();
    objectDefineProperty(copy, field, {
      value: descriptor.value,
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }
  return copy;
}

function serializeFixedObject(input, fields) {
  const fixed = copyFixedObject(input, fields);
  const entries = [];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    reflectApply(arrayPush, entries, [
      `${escapeString(field)}:${serializeValue(fixed[field])}`,
    ]);
  }
  return `{${reflectApply(arrayJoin, entries, [","])}}`;
}

function digestFixedSnapshot(domain, snapshot, fields) {
  if (arguments.length !== 3 || typeof domain !== "string") throw canonicalError();
  const serialized = `{"domain":${escapeString(domain)},"snapshot":${
    serializeFixedObject(snapshot, fields)}}`;
  const hash = cryptoCreateHash("sha256");
  reflectApply(HASH_UPDATE, hash, [serialized]);
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

module.exports = {
  digestFixedSnapshot,
};

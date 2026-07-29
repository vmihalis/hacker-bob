"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwnProperty = Object.prototype.hasOwnProperty;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arrayJoin = Array.prototype.join;
const bufferByteLength = Buffer.byteLength;
const SafeDate = Date;
const dateParse = Date.parse;
const dateToISOString = Date.prototype.toISOString;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const bigintFromString = BigInt;
const regexpTest = RegExp.prototype.test;
const stringCharCodeAt = String.prototype.charCodeAt;
const stringEndsWith = String.prototype.endsWith;
const stringIncludes = String.prototype.includes;
const stringSplit = String.prototype.split;
const stringStartsWith = String.prototype.startsWith;
const cryptoCreateHash = crypto.createHash;
const hashPrototype = objectGetPrototypeOf(reflectApply(cryptoCreateHash, crypto, ["sha256"]));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, "update").value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, "digest").value;

const ARRAY_PROTOTYPE = Array.prototype;
const OBJECT_PROTOTYPE = Object.prototype;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,190}$/u;
const PATH_COMPONENT_PATTERN = /^[a-z0-9][a-z0-9._@+-]{0,127}$/u;
const SYSTEM_DEPENDENCY_PATTERN = /^(?:\/usr\/lib\/[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*|\/System\/Library\/Frameworks\/[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*)$/u;
const HEX = "0123456789abcdef";
const MAX_TEXT_BYTES = 4096;
const MAX_ARRAY_ITEMS = 256;
const DARWIN_O_ACCMODE = 0x3;
const DARWIN_FD_CLOEXEC = 0x1;
const UINT64_DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const UINT64_MAX = 18446744073709551615n;

class ContractError extends SafeError {
  constructor(code, message) {
    super(message);
    objectDefineProperty(this, "code", {
      value: code,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
}

function reject(code, message) {
  throw new ContractError(code, message);
}

function setArrayIndex(array, index, value) {
  objectDefineProperty(array, `${index}`, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return value;
}

function assertDarwinDescriptorFlagSemantics(accessMode, requiredStatusFlags,
  forbiddenStatusFlags, requiredDescriptorFlags, forbiddenDescriptorFlags,
  observedStatusFlags, observedDescriptorFlags, label, code) {
  let expectedAccess;
  if (accessMode === "read_only") expectedAccess = 0;
  else if (accessMode === "write_only") expectedAccess = 1;
  else if (accessMode === "read_write") expectedAccess = 2;
  else reject(code, `${label}.access_mode is unsupported`);
  const forbiddenAccess = DARWIN_O_ACCMODE ^ expectedAccess;
  if ((requiredStatusFlags & DARWIN_O_ACCMODE) !== expectedAccess
      || (forbiddenStatusFlags & DARWIN_O_ACCMODE) !== forbiddenAccess) {
    reject(code, `${label} does not encode the exact Darwin access mode`);
  }
  if ((requiredDescriptorFlags & DARWIN_FD_CLOEXEC) !== DARWIN_FD_CLOEXEC
      || (forbiddenDescriptorFlags & DARWIN_FD_CLOEXEC) !== 0) {
    reject(code, `${label} must require Darwin FD_CLOEXEC`);
  }
  if (observedStatusFlags != null
      && (observedStatusFlags & DARWIN_O_ACCMODE) !== expectedAccess) {
    reject(code, `${label} observed Darwin access mode does not match`);
  }
  if (observedDescriptorFlags != null
      && (observedDescriptorFlags & DARWIN_FD_CLOEXEC) !== DARWIN_FD_CLOEXEC) {
    reject(code, `${label} observed descriptor is missing Darwin FD_CLOEXEC`);
  }
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilTypes.isProxy(value)
      || arrayIsArray(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string") return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      return false;
    }
  }
  return true;
}

function assertExactObject(value, fields, label, code = "schema_invalid") {
  if (!isPlainDataObject(value)) reject(code, `${label} must be a plain own-data object`);
  const keys = reflectOwnKeys(value);
  if (keys.length !== fields.length) reject(code, `${label} fields are not exact`);
  for (let index = 0; index < fields.length; index += 1) {
    if (!reflectApply(objectHasOwnProperty, value, [fields[index]])) {
      reject(code, `${label} fields are not exact`);
    }
  }
  return value;
}

function ownValue(value, field, label, code = "schema_invalid") {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
    reject(code, `${label}.${field} must be an enumerable own data field`);
  }
  return descriptor.value;
}

function assertDenseArray(value, label, maximum = MAX_ARRAY_ITEMS, code = "schema_invalid") {
  if (!arrayIsArray(value) || utilTypes.isProxy(value)
      || objectGetPrototypeOf(value) !== ARRAY_PROTOTYPE) {
    reject(code, `${label} must be a dense ordinary array`);
  }
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor == null || lengthDescriptor.value !== value.length
      || !numberIsSafeInteger(value.length) || value.length > maximum) {
    reject(code, `${label} has an invalid length`);
  }
  const keys = reflectOwnKeys(value);
  if (keys.length !== value.length + 1) reject(code, `${label} must be dense`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true) {
      reject(code, `${label} must contain only indexed own data fields`);
    }
  }
  return value;
}

function assertString(value, label, options = {}) {
  const { pattern, minimumBytes = 1, maximumBytes = MAX_TEXT_BYTES,
    code = "schema_invalid" } = options;
  if (typeof value !== "string") reject(code, `${label} must be a string`);
  const bytes = bufferByteLength(value, "utf8");
  if (bytes < minimumBytes || bytes > maximumBytes
      || (pattern != null && !reflectApply(regexpTest, pattern, [value]))) {
    reject(code, `${label} is not canonical`);
  }
  return value;
}

function assertDigest(value, label, code = "digest_invalid") {
  return assertString(value, label, {
    pattern: HASH_PATTERN,
    minimumBytes: 64,
    maximumBytes: 64,
    code,
  });
}

function assertIdentifier(value, label, code = "schema_invalid") {
  return assertString(value, label, {
    pattern: IDENTIFIER_PATTERN,
    maximumBytes: 128,
    code,
  });
}

function assertOpaqueToken(value, label, code = "schema_invalid") {
  return assertString(value, label, {
    pattern: OPAQUE_TOKEN_PATTERN,
    maximumBytes: 191,
    code,
  });
}

function assertBoolean(value, label, code = "schema_invalid") {
  if (value !== true && value !== false) reject(code, `${label} must be boolean`);
  return value;
}

function assertInteger(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER,
  code = "schema_invalid") {
  if (!numberIsSafeInteger(value) || value < minimum || value > maximum) {
    reject(code, `${label} is outside its integer bound`);
  }
  return value;
}

function assertUint64Decimal(value, label, minimum = 0n, code = "schema_invalid") {
  assertString(value, label, {
    pattern: UINT64_DECIMAL_PATTERN,
    maximumBytes: 20,
    code,
  });
  const integer = bigintFromString(value);
  if (integer < minimum || integer > UINT64_MAX) {
    reject(code, `${label} is outside its uint64 bound`);
  }
  return value;
}

function assertTimestamp(value, label, code = "time_invalid") {
  if (typeof value !== "string") reject(code, `${label} must be a timestamp`);
  const milliseconds = reflectApply(dateParse, SafeDate, [value]);
  if (!numberIsFinite(milliseconds)
      || reflectApply(dateToISOString, new SafeDate(milliseconds), []) !== value) {
    reject(code, `${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  return value;
}

function timestampMilliseconds(value, label, code = "time_invalid") {
  assertTimestamp(value, label, code);
  return reflectApply(dateParse, SafeDate, [value]);
}

function assertRelativeArtifactPath(value, label, code = "path_invalid") {
  assertString(value, label, { maximumBytes: 512, code });
  if (reflectApply(stringCharCodeAt, value, [0]) === 47
      || reflectApply(stringIncludes, value, ["\\"])
      || reflectApply(stringIncludes, value, ["//"])
      || reflectApply(stringIncludes, value, ["\0"])) {
    reject(code, `${label} must be a canonical relative POSIX path`);
  }
  const components = reflectApply(stringSplit, value, ["/"]);
  if (components.length < 1 || components.length > 16) {
    reject(code, `${label} path depth is invalid`);
  }
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    if (component === "." || component === ".."
        || !reflectApply(regexpTest, PATH_COMPONENT_PATTERN, [component])) {
      reject(code, `${label} contains a forbidden path component`);
    }
  }
  return value;
}

function assertAbsoluteSystemDependency(value, label, code = "dependency_invalid") {
  assertString(value, label, { pattern: SYSTEM_DEPENDENCY_PATTERN, maximumBytes: 512, code });
  if (!(reflectApply(stringStartsWith, value, ["/usr/lib/"])
      || reflectApply(stringStartsWith, value, ["/System/Library/Frameworks/"]))
      || reflectApply(stringIncludes, value, ["\\"])
      || reflectApply(stringIncludes, value, ["//"])
      || reflectApply(stringIncludes, value, ["/../"])
      || reflectApply(stringEndsWith, value, ["/.."]) || reflectApply(
        stringIncludes,
        value,
        ["/./"],
      )
      || reflectApply(stringEndsWith, value, ["/."])) {
    reject(code, `${label} is not a canonical platform dependency`);
  }
  return value;
}

function makeRecord(fields, values) {
  const result = objectCreate(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    objectDefineProperty(result, field, {
      value: values[index],
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return objectFreeze(result);
}

function makeArray(values) {
  return objectFreeze(values);
}

function escapeCanonicalString(value) {
  let result = '"';
  for (let index = 0; index < value.length; index += 1) {
    const unit = reflectApply(stringCharCodeAt, value, [index]);
    if (unit === 0x22) result += '\\"';
    else if (unit === 0x5c) result += "\\\\";
    else if (unit === 0x08) result += "\\b";
    else if (unit === 0x0c) result += "\\f";
    else if (unit === 0x0a) result += "\\n";
    else if (unit === 0x0d) result += "\\r";
    else if (unit === 0x09) result += "\\t";
    else if (unit < 0x20 || unit === 0x2028 || unit === 0x2029
        || (unit >= 0xd800 && unit <= 0xdfff)) {
      result += `\\u${HEX[(unit >> 12) & 0xf]}${HEX[(unit >> 8) & 0xf]}${
        HEX[(unit >> 4) & 0xf]}${HEX[unit & 0xf]}`;
    } else result += value[index];
  }
  return `${result}"`;
}

function canonicalSerialize(value) {
  if (typeof value === "string") return escapeCanonicalString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && numberIsSafeInteger(value)) return `${value}`;
  if (arrayIsArray(value)) {
    if (utilTypes.isProxy(value) || objectGetPrototypeOf(value) !== ARRAY_PROTOTYPE
        || !objectIsFrozen(value)) {
      reject("canonical_invalid", "canonical arrays must be frozen ordinary arrays");
    }
    assertDenseArray(value, "canonical array", MAX_ARRAY_ITEMS, "canonical_invalid");
    const encoded = [];
    for (let index = 0; index < value.length; index += 1) {
      setArrayIndex(encoded, encoded.length, canonicalSerialize(
        ownValue(value, `${index}`, "canonical array", "canonical_invalid"),
      ));
    }
    return `[${reflectApply(arrayJoin, encoded, [","])}]`;
  }
  if (value != null && typeof value === "object") {
    if (!isPlainDataObject(value) || !objectIsFrozen(value)
        || objectGetPrototypeOf(value) !== null) {
      reject("canonical_invalid", "canonical objects must be frozen null-prototype own data");
    }
    const keys = reflectOwnKeys(value);
    const encoded = [];
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      setArrayIndex(encoded, encoded.length,
        `${escapeCanonicalString(key)}:${canonicalSerialize(ownValue(value, key, "canonical"))}`);
    }
    return `{${reflectApply(arrayJoin, encoded, [","])}}`;
  }
  reject("canonical_invalid", "value cannot be canonically encoded");
}

function domainDigest(domain, normalizedValue) {
  assertString(domain, "digest domain", { maximumBytes: 256, code: "domain_invalid" });
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(hashUpdate, hash, [`${domain}\0${canonicalSerialize(normalizedValue)}`, "utf8"]);
  return reflectApply(hashDigest, hash, ["hex"]);
}

function arraysEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

module.exports = {
  ContractError,
  arraysEqual,
  assertAbsoluteSystemDependency,
  assertBoolean,
  assertDarwinDescriptorFlagSemantics,
  assertDenseArray,
  assertDigest,
  assertExactObject,
  assertIdentifier,
  assertInteger,
  assertOpaqueToken,
  assertRelativeArtifactPath,
  assertString,
  assertTimestamp,
  assertUint64Decimal,
  domainDigest,
  makeArray,
  makeRecord,
  ownValue,
  reject,
  setArrayIndex,
  timestampMilliseconds,
};

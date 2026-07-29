"use strict";

const { types: utilTypes } = require("node:util");

const DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST = Object.freeze([
  "_CC_SHA256",
  "_CC_SHA256_Final",
  "_CC_SHA256_Init",
  "_CC_SHA256_Update",
  "___chkstk_darwin",
  "___error",
  "___memcpy_chk",
  "___stack_chk_fail",
  "___stack_chk_guard",
  "_bzero",
  "_calloc",
  "_close",
  "_closedir",
  "_dirfd",
  "_dup",
  "_dup2",
  "_environ",
  "_fcntl",
  "_fdopendir",
  "_free",
  "_fstat",
  "_fstatat",
  "_geteuid",
  "_getgroups$DARWIN_EXTSN",
  "_getpid",
  "_getuid",
  "_lseek",
  "_memchr",
  "_memcpy",
  "_open",
  "_openat",
  "_proc_pidinfo",
  "_proc_pidpath",
  "_qsort",
  "_read",
  "_readdir",
  "_snprintf",
  "_strchr",
  "_strcmp",
  "_strlen",
  "_strncmp",
  "_strstr",
  "_write",
]);

const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsProxy = utilTypes.isProxy;

function assertExactDarwinNativeFixtureUndefinedSymbols(input) {
  if (input == null || typeof input !== "object"
      || reflectApply(utilIsProxy, utilTypes, [input]) || !arrayIsArray(input)) {
    throw new Error("Darwin native fixture undefined-symbol set must be a dense array");
  }
  const length = objectGetOwnPropertyDescriptor(input, "length");
  if (length == null || length.value !== DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST.length
      || reflectOwnKeys(input).length !== length.value + 1) {
    throw new Error("Darwin native fixture undefined-symbol set is not exact");
  }
  const normalized = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(input, `${index}`);
    if (descriptor == null || !("value" in descriptor) || descriptor.enumerable !== true
        || descriptor.value !== DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST[index]) {
      throw new Error("Darwin native fixture undefined-symbol set is not exact");
    }
    reflectApply(objectDefineProperty, Object, [normalized, `${index}`, {
      configurable: true,
      enumerable: true,
      value: descriptor.value,
      writable: true,
    }]);
  }
  return objectFreeze(normalized);
}

module.exports = objectFreeze({
  DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST,
  assertExactDarwinNativeFixtureUndefinedSymbols,
});

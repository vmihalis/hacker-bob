"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { types: utilTypes } = require("node:util");

test("provider-neutral package exports the closed contract surfaces", () => {
  const provider = require("../lib/instrument-provider-contract.js");
  const quantities = require("../lib/physical-quantities.js");
  const effects = require("../lib/requested-effects.js");
  const verification = require("../lib/verification-contracts.js");

  assert.equal(provider.PROVIDER_ABI_VERSION, 3);
  assert.equal(typeof provider.defineProviderDescriptor, "function");
  assert.equal(typeof quantities.normalizeQuantityBound, "function");
  assert.equal(typeof effects.normalizeRequestedEffects, "function");
  assert.equal(verification.hashCanonicalJson({ b: 2, a: 1 }),
    verification.hashCanonicalJson({ a: 1, b: 2 }));
});

test("opaque reference validation is stable under ambient intrinsic poisoning", () => {
  const quantities = require("../lib/physical-quantities.js");
  const originalRegExpExec = RegExp.prototype.exec;
  const originalRegExpTest = RegExp.prototype.test;
  const originalStringStartsWith = String.prototype.startsWith;
  try {
    RegExp.prototype.exec = () => ["forged-match"];
    RegExp.prototype.test = () => true;
    String.prototype.startsWith = () => true;

    assert.throws(
      () => quantities.normalizeOpaqueRef(
        "artifact:/tmp/raw-evidence",
        "artifact_ref",
        { prefix: "artifact" },
      ),
      (error) => error instanceof Error
        && error.message === "artifact_ref must be a namespaced opaque reference",
    );
    assert.throws(
      () => quantities.normalizeOpaqueRef(
        "receipt:wrong-namespace",
        "artifact_ref",
        { prefix: "artifact" },
      ),
      (error) => error instanceof Error
        && error.message === "artifact_ref must use the artifact: namespace",
    );
    assert.equal(
      quantities.normalizeOpaqueRef(
        "artifact:stable-valid-ref",
        "artifact_ref",
        { prefix: "artifact" },
      ),
      "artifact:stable-valid-ref",
    );
  } finally {
    RegExp.prototype.exec = originalRegExpExec;
    RegExp.prototype.test = originalRegExpTest;
    String.prototype.startsWith = originalStringStartsWith;
  }
});

test("canonical verification hashes ignore post-import ambient intrinsic poisoning", () => {
  const verification = require("../lib/verification-contracts.js");
  const input = {
    z: [3, undefined, { y: true, x: "stable" }],
    a: { second: 2, first: 1 },
  };
  const expectedHash = verification.hashCanonicalJson(input);
  const expectedJson = verification.canonicalJson(input);
  const expectedExcludingHash = verification.documentHashExcluding(
    { retained: input, excluded: "volatile" },
    ["excluded"],
  );
  const originalCryptoCreateHash = crypto.createHash;
  const originalHashUpdate = crypto.Hash.prototype.update;
  const originalHashDigest = crypto.Hash.prototype.digest;
  const originalJsonParse = JSON.parse;
  const originalJsonStringify = JSON.stringify;
  const originalArrayIsArray = Array.isArray;
  const originalArrayMap = Array.prototype.map;
  const originalArraySort = Array.prototype.sort;
  const originalArrayToJSONDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
  const originalNumberIsSafeInteger = Number.isSafeInteger;
  const originalObjectCreate = Object.create;
  const originalObjectDefineProperty = Object.defineProperty;
  const originalObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const originalObjectGetPrototypeOf = Object.getPrototypeOf;
  const originalObjectHasOwnProperty = Object.prototype.hasOwnProperty;
  const originalObjectKeys = Object.keys;
  const originalObjectToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  const originalReflectApply = Reflect.apply;
  const originalReflectDeleteProperty = Reflect.deleteProperty;
  const originalReflectOwnKeys = Reflect.ownKeys;
  const originalUtilIsProxy = utilTypes.isProxy;
  const originalWeakSetAdd = WeakSet.prototype.add;
  const originalWeakSetDelete = WeakSet.prototype.delete;
  const originalWeakSetHas = WeakSet.prototype.has;
  let observedHash;
  let observedJson;
  let observedExcludingHash;
  try {
    crypto.createHash = () => { throw new Error("poisoned crypto.createHash"); };
    crypto.Hash.prototype.update = () => { throw new Error("poisoned Hash.update"); };
    crypto.Hash.prototype.digest = () => { throw new Error("poisoned Hash.digest"); };
    JSON.parse = () => { throw new Error("poisoned JSON.parse"); };
    JSON.stringify = () => "\"poisoned JSON.stringify\"";
    Array.isArray = () => false;
    Array.prototype.map = () => ["poisoned Array.map"];
    Array.prototype.sort = () => { throw new Error("poisoned Array.sort"); };
    Array.prototype.toJSON = () => ["poisoned Array.toJSON"];
    Number.isSafeInteger = () => false;
    Object.create = () => { throw new Error("poisoned Object.create"); };
    Object.defineProperty = () => { throw new Error("poisoned Object.defineProperty"); };
    Object.getOwnPropertyDescriptor = () => ({
      value: "poisoned Object.getOwnPropertyDescriptor",
      enumerable: true,
    });
    Object.getPrototypeOf = () => null;
    Object.prototype.hasOwnProperty = () => false;
    Object.prototype.toJSON = () => ({ poisoned: "Object.toJSON" });
    Object.keys = () => ["poisoned Object.keys"];
    Reflect.apply = () => { throw new Error("poisoned Reflect.apply"); };
    Reflect.deleteProperty = () => { throw new Error("poisoned Reflect.deleteProperty"); };
    Reflect.ownKeys = () => ["poisoned Reflect.ownKeys"];
    utilTypes.isProxy = () => true;
    WeakSet.prototype.add = () => { throw new Error("poisoned WeakSet.add"); };
    WeakSet.prototype.delete = () => { throw new Error("poisoned WeakSet.delete"); };
    WeakSet.prototype.has = () => { throw new Error("poisoned WeakSet.has"); };

    observedHash = verification.hashCanonicalJson(input);
    observedJson = verification.canonicalJson(input);
    observedExcludingHash = verification.documentHashExcluding(
      { retained: input, excluded: "volatile" },
      ["excluded"],
    );
  } finally {
    crypto.createHash = originalCryptoCreateHash;
    crypto.Hash.prototype.update = originalHashUpdate;
    crypto.Hash.prototype.digest = originalHashDigest;
    JSON.parse = originalJsonParse;
    JSON.stringify = originalJsonStringify;
    Array.isArray = originalArrayIsArray;
    Array.prototype.map = originalArrayMap;
    Array.prototype.sort = originalArraySort;
    if (originalArrayToJSONDescriptor == null) {
      originalReflectDeleteProperty(Array.prototype, "toJSON");
    } else {
      originalObjectDefineProperty(Array.prototype, "toJSON", originalArrayToJSONDescriptor);
    }
    Number.isSafeInteger = originalNumberIsSafeInteger;
    Object.create = originalObjectCreate;
    Object.defineProperty = originalObjectDefineProperty;
    Object.getOwnPropertyDescriptor = originalObjectGetOwnPropertyDescriptor;
    Object.getPrototypeOf = originalObjectGetPrototypeOf;
    Object.prototype.hasOwnProperty = originalObjectHasOwnProperty;
    if (originalObjectToJSONDescriptor == null) {
      originalReflectDeleteProperty(Object.prototype, "toJSON");
    } else {
      originalObjectDefineProperty(Object.prototype, "toJSON", originalObjectToJSONDescriptor);
    }
    Object.keys = originalObjectKeys;
    Reflect.apply = originalReflectApply;
    Reflect.deleteProperty = originalReflectDeleteProperty;
    Reflect.ownKeys = originalReflectOwnKeys;
    utilTypes.isProxy = originalUtilIsProxy;
    WeakSet.prototype.add = originalWeakSetAdd;
    WeakSet.prototype.delete = originalWeakSetDelete;
    WeakSet.prototype.has = originalWeakSetHas;
  }
  assert.equal(observedHash, expectedHash);
  assert.equal(observedJson, expectedJson);
  assert.equal(observedExcludingHash, expectedExcludingHash);
});

test("canonical verification JSON preserves standard sparse-array semantics", () => {
  const verification = require("../lib/verification-contracts.js");
  const trailingHoles = ["stable"];
  trailingHoles.length = 3;
  assert.equal(verification.canonicalJson(trailingHoles), '["stable",null,null]');
  assert.equal(verification.canonicalize(trailingHoles).length, 3);
});

test("canonical verification JSON preserves legacy integer-key and __proto__ ordering", () => {
  const verification = require("../lib/verification-contracts.js");
  const input = Object.create(null);
  for (const [key, value] of [
    ["10", "ten"],
    ["2", "two"],
    ["01", "leading-zero"],
    ["4294967294", "largest-index"],
    ["4294967295", "not-an-index"],
    ["__proto__", "own-data-property"],
  ]) {
    Object.defineProperty(input, key, { value, enumerable: true });
  }
  const expected = '{"2":"two","10":"ten","4294967294":"largest-index",'
    + '"01":"leading-zero","4294967295":"not-an-index",'
    + '"__proto__":"own-data-property"}';
  assert.equal(verification.canonicalJson(input), expected);
  assert.equal(
    verification.hashCanonicalJson(input),
    "b2b5aaf144c5b85f42bd1a448bf3949fd0669b237d9aef857c41e3f4a1800992",
  );

  const objectLiteralPrototypeSyntax = { __proto__: "not-an-own-property", stable: true };
  assert.equal(verification.canonicalJson(objectLiteralPrototypeSyntax), '{"stable":true}');
});

test("canonical verification descriptors ignore Object.prototype get pollution", () => {
  const verification = require("../lib/verification-contracts.js");
  const expectedHash = verification.hashCanonicalJson({ nested: [1, { stable: true }] });
  const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "get");
  const defineProperty = Object.defineProperty;
  const deleteProperty = Reflect.deleteProperty;
  let inheritedGetterCalls = 0;
  let observedHash;
  try {
    defineProperty(Object.prototype, "get", {
      configurable: true,
      get() {
        inheritedGetterCalls += 1;
        return () => "forged";
      },
    });
    observedHash = verification.hashCanonicalJson({ nested: [1, { stable: true }] });
  } finally {
    deleteProperty(Object.prototype, "get");
    if (originalDescriptor != null) {
      defineProperty(Object.prototype, "get", originalDescriptor);
    }
  }
  assert.equal(observedHash, expectedHash);
  assert.equal(inheritedGetterCalls, 0);
});

test("canonical verification hashes reject proxies and accessors without invoking them", () => {
  const verification = require("../lib/verification-contracts.js");
  let getterCalls = 0;
  const accessorObject = {};
  Object.defineProperty(accessorObject, "secret", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "forged";
    },
  });
  assert.throws(
    () => verification.hashCanonicalJson(accessorObject),
    /cannot contain accessor properties/,
  );
  assert.equal(getterCalls, 0);

  const accessorArray = [];
  Object.defineProperty(accessorArray, "0", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "forged";
    },
  });
  assert.throws(
    () => verification.hashCanonicalJson(accessorArray),
    /cannot contain accessor properties/,
  );
  assert.equal(getterCalls, 0);

  let proxyTrapCalls = 0;
  const proxy = new Proxy({ stable: true }, {
    ownKeys() {
      proxyTrapCalls += 1;
      return ["stable"];
    },
    getOwnPropertyDescriptor() {
      proxyTrapCalls += 1;
      return { value: true, enumerable: true, configurable: true };
    },
  });
  assert.throws(
    () => verification.hashCanonicalJson(proxy),
    /cannot contain proxies/,
  );
  assert.equal(proxyTrapCalls, 0);

  const callableProxy = new Proxy(() => "ignored", {
    get() {
      proxyTrapCalls += 1;
      return undefined;
    },
  });
  assert.throws(
    () => verification.hashCanonicalJson({ callableProxy }),
    /cannot contain proxies/,
  );
  assert.equal(proxyTrapCalls, 0);

  let toJSONCalls = 0;
  const omittedFunction = () => "ignored";
  omittedFunction.toJSON = () => {
    toJSONCalls += 1;
    return "forged";
  };
  assert.equal(verification.canonicalJson({ omittedFunction }), "{}");
  assert.equal(toJSONCalls, 0);

  const originalBigIntToJSONDescriptor = Object.getOwnPropertyDescriptor(BigInt.prototype, "toJSON");
  try {
    Object.defineProperty(BigInt.prototype, "toJSON", {
      configurable: true,
      value() {
        toJSONCalls += 1;
        return "forged";
      },
    });
    assert.throws(
      () => verification.hashCanonicalJson({ bigint: 1n }),
      /cannot contain bigint values/,
    );
    assert.equal(toJSONCalls, 0);
  } finally {
    if (originalBigIntToJSONDescriptor == null) {
      Reflect.deleteProperty(BigInt.prototype, "toJSON");
    } else {
      Object.defineProperty(BigInt.prototype, "toJSON", originalBigIntToJSONDescriptor);
    }
  }
});

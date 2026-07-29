"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const PEER_MODULE = path.join(ROOT, "lib", "peer-credentials.js");
const SELF_MODULE = path.join(ROOT, "lib", "self-identity.js");
const BINDING_PATH = path.join(ROOT, "build", "Release", "peer_credentials.node");

function runChild(source) {
  const result = spawnSync(process.execPath, ["-e", source], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("preexisting locked bound-JS cache forgery is rejected before native load", () => {
  const result = runChild([
    '"use strict";',
    'const crypto = require("node:crypto");',
    'const fs = require("node:fs");',
    `const bindingPath = ${JSON.stringify(BINDING_PATH)};`,
    `const peerPath = ${JSON.stringify(PEER_MODULE)};`,
    "function makeForged(name) {",
    "  const target = function forgedSnapshot() { return {self_pid: 1}; };",
    "  const bound = target.bind(null);",
    "  Object.defineProperty(bound, 'name', {value:name,writable:false,enumerable:false,configurable:true});",
    "  Object.freeze(bound);",
    "  return bound;",
    "}",
    "const forged = {};",
    "Object.defineProperty(forged, 'registerUnixPeerDescriptor', {value:makeForged('registerUnixPeerDescriptor'),writable:false,enumerable:true,configurable:false});",
    "Object.defineProperty(forged, 'inspectRegisteredUnixPeer', {value:makeForged('inspectRegisteredUnixPeer'),writable:false,enumerable:true,configurable:false});",
    "Object.defineProperty(forged, 'inspectLoadedImage', {value:makeForged('inspectLoadedImage'),writable:false,enumerable:true,configurable:false});",
    "Object.defineProperty(forged, 'inspectCurrentSelf', {value:makeForged('inspectCurrentSelf'),writable:false,enumerable:true,configurable:false});",
    "const digest = crypto.createHash('sha256').update(fs.readFileSync(bindingPath)).digest('hex');",
    "Object.defineProperty(forged, Symbol.for('hacker-bob.instrument-native-darwin.binding-file-measurement.v1'), {value:digest,writable:false,enumerable:false,configurable:false});",
    "Object.freeze(forged);",
    "require.cache[bindingPath] = {exports: forged};",
    "const peer = require(peerPath);",
    "let code = null;",
    "try { peer.createDarwinNativePeerCredentialInspector({adapter_id:'forged_cache'}); } catch (error) { code = error && error.code; }",
    "process.stdout.write(JSON.stringify({code}));",
  ].join(""));
  assert.deepEqual(result, { code: "darwin_native_peer_rejected" });
});

test("peer-first loader cannot be cache-poisoned before self inspection", () => {
  const result = runChild([
    '"use strict";',
    `const bindingPath = ${JSON.stringify(BINDING_PATH)};`,
    `const peerPath = ${JSON.stringify(PEER_MODULE)};`,
    `const selfPath = ${JSON.stringify(SELF_MODULE)};`,
    "const peer = require(peerPath);",
    "const self = require(selfPath);",
    "peer.createDarwinNativePeerCredentialInspector({adapter_id:'peer_first'});",
    "const authentic = require.cache[bindingPath];",
    "let replacementRejected = false;",
    "try { Object.defineProperty(require.cache, bindingPath, {value:{exports:{}},writable:true,enumerable:true,configurable:true}); } catch { replacementRejected = true; }",
    "let mutationRejected = false;",
    "try { authentic.exports = {}; } catch { mutationRejected = true; }",
    "const port = self.createDarwinNativeSelfIdentityInspector({adapter_id:'self_second'});",
    "const snapshot = self.inspectCurrentDarwinSelf(port);",
    "process.stdout.write(JSON.stringify({replacementRejected,mutationRejected,pid:snapshot.self_pid,actual:process.pid}));",
  ].join(""));
  assert.deepEqual(result, {
    replacementRejected: true,
    mutationRejected: true,
    pid: result.actual,
    actual: result.actual,
  });
  assert.ok(result.actual > 0);
});

test("global process substitution is rejected without consulting the substitute", () => {
  const result = runChild([
    '"use strict";',
    `const selfPath = ${JSON.stringify(SELF_MODULE)};`,
    "const realProcess = require('node:process');",
    "const original = Object.getOwnPropertyDescriptor(globalThis, 'process');",
    "const self = require(selfPath);",
    "let substituteReads = 0;",
    "const substitute = new Proxy({}, {get(){ substituteReads += 1; throw new Error('substitute read'); }});",
    "Object.defineProperty(globalThis, 'process', {value:substitute,writable:true,enumerable:false,configurable:true});",
    "let code = null;",
    "try { self.createDarwinNativeSelfIdentityInspector({adapter_id:'process_swap'}); } catch (error) { code = error && error.code; }",
    "Object.defineProperty(globalThis, 'process', original);",
    "realProcess.stdout.write(JSON.stringify({code,substituteReads}));",
  ].join(""));
  assert.deepEqual(result, {
    code: "darwin_native_self_rejected",
    substituteReads: 0,
  });
});

test("captured validation primordials survive prototype replacement", () => {
  const result = runChild([
    '"use strict";',
    `const peerPath = ${JSON.stringify(PEER_MODULE)};`,
    "const peer = require(peerPath);",
    "const port = peer.createDarwinNativePeerCredentialInspector({adapter_id:'primordial_port'});",
    "const originals = {weakSetHas:WeakSet.prototype.has,weakMapHas:WeakMap.prototype.has,weakMapGet:WeakMap.prototype.get,regexpTest:RegExp.prototype.test,numberIsInteger:Number.isInteger,arrayIterator:Array.prototype[Symbol.iterator]};",
    "let attackerCalls = 0;",
    "WeakSet.prototype.has = function(){ attackerCalls += 1; return true; };",
    "WeakMap.prototype.has = function(){ attackerCalls += 1; return true; };",
    "WeakMap.prototype.get = function(){ attackerCalls += 1; return {}; };",
    "RegExp.prototype.test = function(){ attackerCalls += 1; return true; };",
    "Number.isInteger = function(){ attackerCalls += 1; return true; };",
    "Array.prototype[Symbol.iterator] = function(){ attackerCalls += 1; throw new Error('ambient iterator used'); };",
    "let authenticAccepted = false;",
    "let secondPortAccepted = false;",
    "let forgedCode = null;",
    "let invalidCode = null;",
    "try {",
    "  authenticAccepted = peer.assertDarwinNativePeerCredentialInspector(port) === port;",
    "  const secondPort = peer.createDarwinNativePeerCredentialInspector({adapter_id:'primordial_second'});",
    "  secondPortAccepted = peer.assertDarwinNativePeerCredentialInspector(secondPort) === secondPort;",
    "  try { peer.assertDarwinNativePeerCredentialInspector(Object.freeze({})); } catch (error) { forgedCode = error && error.code; }",
    "  try { peer.createDarwinNativePeerCredentialInspector({adapter_id:'INVALID'}); } catch (error) { invalidCode = error && error.code; }",
    "} finally {",
    "  WeakSet.prototype.has = originals.weakSetHas;",
    "  WeakMap.prototype.has = originals.weakMapHas;",
    "  WeakMap.prototype.get = originals.weakMapGet;",
    "  RegExp.prototype.test = originals.regexpTest;",
    "  Number.isInteger = originals.numberIsInteger;",
    "  Array.prototype[Symbol.iterator] = originals.arrayIterator;",
    "}",
    "process.stdout.write(JSON.stringify({authenticAccepted,secondPortAccepted,forgedCode,invalidCode,attackerCalls}));",
  ].join(""));
  assert.deepEqual(result, {
    authenticAccepted: true,
    secondPortAccepted: true,
    forgedCode: "darwin_native_peer_rejected",
    invalidCode: "darwin_native_peer_rejected",
    attackerCalls: 0,
  });
});

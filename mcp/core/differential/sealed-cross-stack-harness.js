"use strict";

const fs = require("fs");
const path = require("path");

// SEALED cross-stack Foundry harness generator.
//
// Closes the forgery where an AGENT-AUTHORED harness manufactures the cross-stack differential
// against the REAL target's bytecode. Binding the on-chain bytecode (target_code_sha256 ==
// eth_getCode) stops a fake-deployed / vm.etch'd target, but NOT an agent setUp that
// vm.mockCall/vm.store's the real target keyed on the captured bytes, nor a rigged agent
// `lib/forge-std` that subverts vm/expectRevert. Both are possible because today the runner runs
// `forge test` inside the AGENT's Foundry project.
//
// The sealed harness removes the agent from the execution path entirely. The runner generates the
// WHOLE project from DATA slots:
//   - a self-contained test with an INLINED minimal Vm (only the cheatcodes the pinned test uses),
//     so the agent's forge-std is never on the build path;
//   - a runner-pinned setUp (`target = <bound address>`) — the agent cannot override it to
//     vm.mockCall/vm.store the target;
//   - a runner-pinned foundry.toml (ffi off, fs_permissions empty, pinned solc), so the agent
//     cannot enable ffi / scripts / a custom solc;
//   - the pinned BOB_TARGET_BIND emission (the runner still cross-checks the bytecode hash against
//     the trusted RPC ladder, defense-in-depth on top of the sealed build).
// The agent's ONLY inputs are DATA — the target address, the gated-function name, the victim type +
// value, and BOB_CONSUMED_ARTIFACT — and the invariant is decided by the REAL forked contract's own
// logic. Every DATA slot is shape-validated below so an agent value can never be Solidity injection.

const PINNED_SOLC_VERSION = "0.8.24";
const VM_ADDRESS = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D";
const CONSOLE_ADDRESS = "0x000000000000000000636F6e736F6c652e6c6f67";

// Shape validators (injection defense — the slots are agent-supplied DATA).
const SOLIDITY_IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
// The victim object's Solidity type — a bounded set of value types the gated call's first argument
// can take. Reference/array types that would need agent-authored construction code are NOT allowed
// (the sealed harness only takes a literal value), so such surfaces fall back to cross-stack-
// unverifiable (a lead) rather than reopening the agent-Solidity path.
const ALLOWED_VICTIM_TYPES = Object.freeze(new Set([
  "address", "bool", "bytes32",
  "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
  "int8", "int16", "int32", "int64", "int128", "int256",
]));

function assertIdent(value, label) {
  if (typeof value !== "string" || !SOLIDITY_IDENT_RE.test(value)) {
    throw new Error(`sealed-harness: ${label} must be a Solidity identifier (got ${JSON.stringify(value)})`);
  }
  return value;
}

function assertAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS_RE.test(value)) {
    throw new Error(`sealed-harness: ${label} must be a 20-byte 0x address (got ${JSON.stringify(value)})`);
  }
  return value;
}

// Validate the (victimType, victimValue) pair: the type must be in the bounded allow-set, and the
// value must be a literal that is valid for that type. Returns the EXACT Solidity literal to
// interpolate. Anything else throws (the surface is cross-stack-unverifiable, not forced through).
function assertVictim(victimType, victimValue) {
  if (typeof victimType !== "string" || !ALLOWED_VICTIM_TYPES.has(victimType)) {
    throw new Error(`sealed-harness: victim_type must be one of [${[...ALLOWED_VICTIM_TYPES].join(", ")}] (got ${JSON.stringify(victimType)})`);
  }
  if (typeof victimValue !== "string" || victimValue.length === 0 || victimValue.length > 80) {
    throw new Error(`sealed-harness: victim_value must be a non-empty literal string (got ${JSON.stringify(victimValue)})`);
  }
  if (victimType === "address") {
    if (!ADDRESS_RE.test(victimValue)) throw new Error(`sealed-harness: victim_value for address must be a 0x address (got ${JSON.stringify(victimValue)})`);
    return victimValue;
  }
  if (victimType === "bool") {
    if (victimValue !== "true" && victimValue !== "false") throw new Error(`sealed-harness: victim_value for bool must be true|false`);
    return victimValue;
  }
  if (victimType === "bytes32") {
    if (!/^0x[0-9a-fA-F]{64}$/.test(victimValue)) throw new Error(`sealed-harness: victim_value for bytes32 must be 32 hex bytes`);
    return victimValue;
  }
  // integer types: a decimal or 0x-hex literal, optionally negative for signed.
  const intRe = victimType.startsWith("int") ? /^-?(0x[0-9a-fA-F]+|\d+)$/ : /^(0x[0-9a-fA-F]+|\d+)$/;
  if (!intRe.test(victimValue)) {
    throw new Error(`sealed-harness: victim_value for ${victimType} must be a ${victimType.startsWith("int") ? "(signed) " : ""}integer literal (got ${JSON.stringify(victimValue)})`);
  }
  return victimValue;
}

// Build the self-contained sealed test source. Pure (string in -> string out) so it is unit-
// testable without the filesystem; writeSealedCrossStackProject wraps it with the project layout.
function buildSealedTestSource({ contractName, testFunctionName, targetAddress, gatedFunction, victimType, victimValue }) {
  const cn = assertIdent(contractName, "contract_name");
  const fn = assertIdent(testFunctionName, "test_function_name");
  const addr = assertAddress(targetAddress, "target_address");
  const gf = assertIdent(gatedFunction, "gated_function");
  const victimLiteral = assertVictim(victimType, victimValue);
  return [
    "// SPDX-License-Identifier: UNLICENSED",
    "pragma solidity >=0.8.0;",
    "",
    "// GENERATED BY THE RUNNER FROM DATA SLOTS — NOT agent-authored. Inlines a minimal Vm (no",
    "// forge-std on the build path), pins setUp, and emits the bound BOB_TARGET_BIND line.",
    "interface IBobVm {",
    "    function envOr(string calldata name, string calldata defaultValue) external view returns (string memory);",
    "    function parseBytes(string calldata) external pure returns (bytes memory);",
    "    function prank(address) external;",
    "    function expectRevert() external;",
    "    function addr(uint256 privateKey) external pure returns (address);",
    "    function toString(address value) external pure returns (string memory);",
    "    function toString(bytes32 value) external pure returns (string memory);",
    "}",
    "",
    `interface IBobTarget {`,
    `    function ${gf}(${victimType}, bytes calldata) external;`,
    "}",
    "",
    `contract ${cn} {`,
    `    IBobVm constant vm = IBobVm(${VM_ADDRESS});`,
    `    address constant BOB_CONSOLE = ${CONSOLE_ADDRESS};`,
    "    IBobTarget internal target;",
    "",
    "    function setUp() public {",
    `        // PINNED by the runner — the agent cannot override this to mock/store the target.`,
    `        // The address is emitted as a 42-hex uint160 literal (0x00-prefixed) so solc's EIP-55`,
    `        // checksum heuristic (which fires on any 40-hex literal) does not reject a lowercase`,
    `        // agent address; the leading zero byte is value-insignificant and fits uint160.`,
    `        target = IBobTarget(address(uint160(0x00${addr.slice(2)})));`,
    "    }",
    "",
    "    function _bobLog(string memory s) internal view {",
    "        (bool ok, ) = BOB_CONSOLE.staticcall(abi.encodeWithSignature(\"log(string)\", s));",
    "        ok;",
    "    }",
    "",
    "    function bobConsumedArtifact() internal view returns (bytes memory) {",
    "        string memory hexStr = vm.envOr(\"BOB_CONSUMED_ARTIFACT\", string(\"\"));",
    "        if (bytes(hexStr).length == 0) return bytes(\"\");",
    "        return vm.parseBytes(string.concat(\"0x\", hexStr));",
    "    }",
    "",
    `    function ${fn}() public {`,
    "        bytes memory capturedAuth = bobConsumedArtifact();",
    "        // CROSS-STACK TARGET BINDING — emitted BEFORE the gated call (the VIOLATED arm fails AT",
    "        // the call). The runner cross-checks this sha256 against eth_getCode on the TRUSTED ladder.",
    "        _bobLog(string.concat(\"BOB_TARGET_BIND:\", vm.toString(address(target)), \":\", vm.toString(sha256(address(target).code))));",
    "        // The web-captured payload as the on-chain auth arg. The invariant is that this REVERTS",
    "        // (an off-chain capture is not valid on-chain auth); the REAL forked contract decides.",
    "        vm.prank(vm.addr(uint256(keccak256(\"crossStackAttacker\"))));",
    "        vm.expectRevert();",
    `        target.${gf}(${victimLiteral}, capturedAuth);`,
    "    }",
    "}",
    "",
  ].join("\n");
}

function buildSealedFoundryToml() {
  return [
    "[profile.default]",
    "src = \"src\"",
    "test = \"test\"",
    "out = \"out\"",
    "libs = []",
    `solc = "${PINNED_SOLC_VERSION}"`,
    "ffi = false",
    "fs_permissions = []",
    "",
  ].join("\n");
}

// Materialize a sealed project under `parentDir` (a runner-controlled temp dir). Writes
// foundry.toml + test/<contractName>.t.sol, NOTHING else (no lib/, no scripts, no agent files).
// Returns the absolute project dir + the match identifiers the foundry runner pins forge to.
function writeSealedCrossStackProject(parentDir, opts) {
  const contractName = assertIdent(opts.contractName, "contract_name");
  const testFunctionName = assertIdent(opts.testFunctionName, "test_function_name");
  const source = buildSealedTestSource({ ...opts, contractName, testFunctionName });
  const projectDir = path.join(parentDir, "bob-sealed-cross-stack");
  fs.mkdirSync(path.join(projectDir, "test"), { recursive: true });
  fs.mkdirSync(path.join(projectDir, "src"), { recursive: true });
  fs.writeFileSync(path.join(projectDir, "foundry.toml"), buildSealedFoundryToml(), "utf8");
  const testPath = path.join(projectDir, "test", `${contractName}.t.sol`);
  fs.writeFileSync(testPath, source, "utf8");
  return Object.freeze({
    projectDir,
    testPath,
    matchContract: contractName,
    matchTest: testFunctionName,
    matchPath: testPath,
    source,
  });
}

module.exports = {
  PINNED_SOLC_VERSION,
  VM_ADDRESS,
  CONSOLE_ADDRESS,
  ALLOWED_VICTIM_TYPES,
  assertVictim,
  buildSealedTestSource,
  buildSealedFoundryToml,
  writeSealedCrossStackProject,
};

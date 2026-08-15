"use strict";

// The sealed cross-stack harness generator closes the forgery where an agent-authored harness
// setUp (vm.mockCall/vm.store) or a rigged agent forge-std manufactures the cross-stack
// differential against the real target. The generator emits the WHOLE project from DATA slots, so
// these tests pin (1) that every agent-supplied slot is shape-validated (no Solidity injection),
// and (2) that the generated self-contained project actually COMPILES under the pinned solc with
// NO forge-std on the build path (forge-gated; skipped when forge is unavailable).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  buildSealedTestSource,
  buildSealedFoundryToml,
  writeSealedCrossStackProject,
  assertVictim,
  PINNED_SOLC_VERSION,
} = require("../mcp/core/differential/index.js");

function forgeAvailable() {
  try {
    execFileSync("forge", ["--version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}
const FORGE_AVAILABLE = forgeAvailable();

const GOOD = {
  contractName: "BobSealedCrossStack_x",
  testFunctionName: "testCapturedAuthPayloadRejected",
  targetAddress: `0x${"ab".repeat(20)}`,
  gatedFunction: "gatedEffect",
  victimType: "uint256",
  victimValue: "42",
};

test("the generated source is self-contained: no forge-std import, inlined Vm, pinned setUp, BOB_TARGET_BIND", () => {
  const src = buildSealedTestSource(GOOD);
  assert.ok(!/import\s+["']forge-std/.test(src), "must NOT import forge-std (agent forge-std off the build path)");
  assert.ok(/interface IBobVm/.test(src), "inlines a minimal Vm");
  assert.ok(/target = IBobTarget\(address\(uint160\(0x00/.test(src), "setUp pins target to the bound address");
  assert.ok(/BOB_TARGET_BIND/.test(src) && /sha256\(address\(target\)\.code\)/.test(src), "emits the bound bytecode hash");
  assert.ok(/function gatedEffect\(uint256, bytes calldata\) external;/.test(src), "interface matches the gated call shape");
  assert.ok(/target\.gatedEffect\(42, capturedAuth\)/.test(src), "calls the gated function with the victim literal + captured bytes");
  assert.ok(/ffi = false/.test(buildSealedFoundryToml()) && buildSealedFoundryToml().includes(PINNED_SOLC_VERSION), "foundry.toml pins solc + disables ffi");
});

test("INJECTION DEFENSE: every agent-supplied DATA slot is shape-validated; a malicious value is refused, never interpolated", () => {
  // gated_function carrying Solidity injection
  assert.throws(() => buildSealedTestSource({ ...GOOD, gatedFunction: "x; selfdestruct(payable(0)); //" }), /gated_function must be a Solidity identifier/);
  // target_address not an address (e.g. a Solidity expression)
  assert.throws(() => buildSealedTestSource({ ...GOOD, targetAddress: "address(this)" }), /target_address must be a 20-byte/);
  assert.throws(() => buildSealedTestSource({ ...GOOD, targetAddress: `0x${"ab".repeat(20)}; vm.store(` }), /target_address must be a 20-byte/);
  // contract / test function names
  assert.throws(() => buildSealedTestSource({ ...GOOD, contractName: "A {} contract B" }), /contract_name must be a Solidity identifier/);
  // victim type outside the bounded set (no reference/array types that need construction code)
  assert.throws(() => assertVictim("bytes", "0xdead"), /victim_type must be one of/);
  assert.throws(() => assertVictim("uint256[]", "1"), /victim_type must be one of/);
  // victim value injection / type mismatch
  assert.throws(() => assertVictim("uint256", "1, abi.encode(msg.sender)"), /must be a integer literal|must be a non-empty/);
  assert.throws(() => assertVictim("address", "0xnotanaddress"), /must be a 0x address/);
  assert.throws(() => assertVictim("bool", "1"), /must be true\|false/);
  assert.throws(() => assertVictim("bytes32", "0xdead"), /must be 32 hex bytes/);
  // valid slots return the exact literal
  assert.equal(assertVictim("address", `0x${"cd".repeat(20)}`), `0x${"cd".repeat(20)}`);
  assert.equal(assertVictim("uint256", "0x2a"), "0x2a");
  assert.equal(assertVictim("bool", "true"), "true");
});

test("writeSealedCrossStackProject materializes ONLY foundry.toml + the test (no lib/, no agent files)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sealed-"));
  try {
    const out = writeSealedCrossStackProject(tmp, GOOD);
    assert.ok(fs.existsSync(path.join(out.projectDir, "foundry.toml")));
    assert.ok(fs.existsSync(out.testPath));
    assert.ok(!fs.existsSync(path.join(out.projectDir, "lib")), "no lib/ (no forge-std vendored from the agent)");
    assert.equal(out.matchContract, GOOD.contractName);
    assert.equal(out.matchTest, GOOD.testFunctionName);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("FORGE: the generated sealed project COMPILES under the pinned solc with no forge-std", { skip: !FORGE_AVAILABLE }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sealed-build-"));
  try {
    const out = writeSealedCrossStackProject(tmp, GOOD);
    // forge build compiles the self-contained test (no fork / no deploy needed to validate the
    // Solidity is well-formed and the inlined Vm + console + sha256(target.code) typecheck).
    execFileSync("forge", ["build"], { cwd: out.projectDir, stdio: "pipe" });
    assert.ok(fs.existsSync(path.join(out.projectDir, "out")), "forge produced compilation artifacts");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

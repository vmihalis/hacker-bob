"use strict";

// The recurrence gate for core reaching into a plane implementation.
//
// One rule — core may not require a plane module — violated 20 core files deep
// today. A boundary nobody counts is a boundary that drifts silently, so the
// count is re-derived from a parse on every run and frozen. These legs prove
// the gate is REAL, not decorative:
//
//   (a) the live tree passes, and the frozen list is exactly the measurement;
//   (b) NEGATIVE CONTROL — a planted core -> plane require fails, named with
//       the importing file, the plane module, and the line;
//   (c) NEGATIVE CONTROL — an allowlist entry whose violation is gone fails, so
//       the list can only shrink;
//   (d) a source the parser cannot read fails rather than passing as clean;
//   (e) a `require()` written in a comment or inside a regex literal that holds
//       a quote yields zero edges — the text-scanner defect the AST reader
//       exists to make unreachable;
//   (h) NEGATIVE CONTROLS, one per edge form a bare-`require` scan walked past —
//       `x.require(y)`, `import(x)`, an aliased `const r = require`, and a
//       resolvable in-root `.json`/`.cjs`/`.mjs` target. Each is either resolved
//       into a real edge or named with a count; each inverts, so a reader that
//       regresses to invisible turns the suite red instead of clean.
//
// Inverting (b) or (c) — allowlisting the planted edge, or deleting the stale
// entry — must turn the corresponding assertion red. A gate never observed
// failing is a gate nobody has proven runs.
//
// The list also carries an ADJUDICATION per edge and is bound to the seam audit
// that argued the verdict, so two more failure modes are pinned here:
//
//   (f) an entry with no class, or with a class outside the frozen vocabulary,
//       fails — and `composition_root`, the one derived class, cannot be pasted
//       onto an edge whose importer the walk read as something else;
//   (g) the doc and the tree cannot drift apart — an edge with no inventory row,
//       a row with no edge, and a row whose cited `file:line` no longer holds
//       its require all fail. That last one is not hypothetical: it is what
//       caught row 1 citing graph-scheduler.js:53 after the require moved.
//
// And the coverage claim those legs add up to is itself under test. The census
// at the bottom of this file reads the checker's own source for every
// `violations.push({ kind })` and reconciles it against the kinds these
// controls actually made fire, so a branch nobody plants cannot sit unwatched
// behind a green suite. It is derived from what the checker RUNS because the
// hand-count it replaces was wrong in both numbers.

const test = require("node:test");
const { after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  ALLOWLIST_BOUNDARY_VIOLATIONS,
  ALLOWLIST_DYNAMIC_REQUIRES,
  ALLOWLIST_MODULE_CYCLES,
  BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS,
  BLOCKCHAIN_PLANE_AXIS,
  BLOCKCHAIN_PLANE_MEMBERS,
  BLOCKCHAIN_SEAM_INVENTORY_RELPATH,
  BOUNDARY_ADJUDICATION_CLASSES,
  COMPOSITION_ROOT_MODULE,
  PLANE_AXIS,
  PLANE_AXES,
  PLANE_MEMBERS,
  SEAM_CENSUS_PATTERNS,
  SEAM_INVENTORY_RELPATH,
  SMART_CONTRACTS_ALLOWED_DEPENDENCIES,
  SMART_CONTRACTS_DEPENDENCY_CLASSES,
  SMART_CONTRACTS_DIR,
  SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS,
  SMART_CONTRACTS_INTERNALS,
  SMART_CONTRACTS_MEMBERS,
  UNBINDABLE_SEAM_CITATIONS,
  classifyModule,
  coverageNote,
  planeMemberOf,
  parseSeamInventoryRows,
  runChecks: rawRunChecks,
} = require("../scripts/check-module-boundaries.js");
const { collectStaticRequires, parseJsSource, walk } = require("../scripts/lib/js-source-facts.js");

const REPO_ROOT = path.join(__dirname, "..");
const CHECKER = path.join(REPO_ROOT, "scripts", "check-module-boundaries.js");
const MCP_LIB = path.join(REPO_ROOT, "mcp");
// The checker's violation kinds live in the entry point AND its rule modules
// (rule-one/two/three + shared), so the census must AST-walk all of them or it
// silently degrades to a hand-mirror of whatever moved out of the entry point.
// Derived from the directory so a new rule module is covered without a code edit.
const CHECKER_RULE_DIR = path.join(REPO_ROOT, "scripts", "lib", "module-boundaries");
const CHECKER_SOURCES = [
  CHECKER,
  ...fs.readdirSync(CHECKER_RULE_DIR)
    .filter((name) => name.endsWith(".js"))
    .sort()
    .map((name) => path.join(CHECKER_RULE_DIR, name)),
];
const EMPTY = new Map();
const EMPTY_DYNAMIC = new Set();

// Fixture roots hold a module tree and no seam audit, so the inventory binding
// is switched off there the same way the allowlists are emptied: explicitly.
// The cycle inventory names modules of the LIVE tree, so on a fixture root every
// entry would read as stale. Emptied here explicitly, exactly as the two
// allowlists are, rather than by teaching the checker to guess when it is
// running against a fixture.
const EMPTY_CYCLES = new Map();
// RULE THREE's four lists and the physical-plane inventory name modules of the
// LIVE tree too, so on a fixture root every member would read as missing and
// every entry as stale. Emptied explicitly for the same reason and in the same
// place as the cycle inventory; a fixture that means to exercise either rule
// supplies its own membership on top.
const NO_SMART_CONTRACTS = {
  planeMembers: null,
  blockchainAllowlist: null,
  blockchainInventory: null,
  blockchainPlaneMembers: null,
  smartContractsMembers: new Set(),
  smartContractsInternals: new Set(),
  smartContractsAllowedDependencies: new Map(),
  smartContractsEntrypointExceptions: new Map(),
};
const NO_SEAM = {
  allowlist: EMPTY,
  blockchainAllowlist: EMPTY,
  dynamicAllowlist: EMPTY_DYNAMIC,
  cycleAllowlist: EMPTY_CYCLES,
  inventory: null,
  blockchainInventory: null,
  blockchainPlaneMembers: null,
  ...NO_SMART_CONTRACTS,
};

function withTempDir(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-module-boundaries-"));
  try {
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeFixture(dir, files) {
  for (const [relativePath, contents] of Object.entries(files)) {
    const absolute = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, contents, "utf8");
  }
}

// Every violation kind this suite actually made the checker emit, collected at
// the ONE seam every control runs through. The census at the bottom of the file
// reconciles this against the kinds the checker's source can push, so a kind
// nobody plants cannot sit unfired behind a green suite. A kind fired only by
// `runCli` is not counted — that is a subprocess this collector cannot see —
// and every CLI assertion here is paired with an in-process run of the same
// fixture.
const FIRED_KINDS = new Set();

function runChecks(options) {
  const result = rawRunChecks(options);
  for (const violation of result.violations) FIRED_KINDS.add(violation.kind);
  return result;
}

function kindsOf(violations) {
  return violations.map((v) => v.kind).sort();
}

function runCli(args) {
  try {
    return { status: 0, output: execFileSync(process.execPath, [CHECKER, ...args], { encoding: "utf8" }) };
  } catch (err) {
    return { status: err.status, output: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

test("the live tree passes the module-boundary gate", () => {
  const { violations } = runChecks({ root: REPO_ROOT });
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
});

// CENSUS HONESTY. The frozen list must be the measurement, not a number copied
// from a spec or a document. An entry more than measured is rot; an entry fewer
// is an unpoliced edge.
test("the frozen allowlist is exactly the measured set of core -> plane edges", () => {
  const { measured } = runChecks({ root: REPO_ROOT, allowlist: EMPTY, dynamicAllowlist: EMPTY_DYNAMIC });
  assert.equal(measured.boundaryEdges.size, ALLOWLIST_BOUNDARY_VIOLATIONS.size);
  assert.deepEqual([...measured.boundaryEdges].sort(), [...ALLOWLIST_BOUNDARY_VIOLATIONS.keys()].sort());
  assert.deepEqual(
    measured.dynamicSites.map((site) => site.key).sort(),
    [...ALLOWLIST_DYNAMIC_REQUIRES].sort(),
  );
});

test("the frozen blockchain allowlist is exactly the measured core -> blockchain seam", () => {
  const { measured } = runChecks({
    root: REPO_ROOT,
    blockchainAllowlist: EMPTY,
    blockchainInventory: null,
  });
  assert.equal(measured.blockchain.boundaryEdges.size, BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.size);
  assert.deepEqual(
    [...measured.blockchain.boundaryEdges].sort(),
    [...BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.keys()].sort(),
  );
});

// The same census honesty for RULE TWO. The inventory must be the measurement:
// an entry more than measured is rot, an entry fewer is a cycle nobody argued
// for, and a size that is not the measured size is an argument about a set the
// tree no longer holds.
test("the frozen cycle inventory is exactly the measured set of module cycles", () => {
  const { measured } = runChecks({ root: REPO_ROOT });
  assert.equal(measured.moduleCycles.length, ALLOWLIST_MODULE_CYCLES.size);
  assert.deepEqual(
    measured.moduleCycles.map((cycle) => cycle.representative).sort(),
    [...ALLOWLIST_MODULE_CYCLES.keys()].sort(),
  );
  for (const cycle of measured.moduleCycles) {
    const entry = ALLOWLIST_MODULE_CYCLES.get(cycle.representative);
    assert.equal(entry.size, cycle.size, `${cycle.representative} size`);
    assert.ok(entry.argument.trim().length > 0, `${cycle.representative} argument`);
    // The representative is DERIVED — the first member in sort order — so it
    // cannot be a label someone chose for an entry.
    assert.equal(cycle.members[0], cycle.representative);
  }
  // The deferral count is a measurement of this tree, not a hypothesis: the
  // library has already paid for deferring a large share of the cycle's edges
  // and bought no acyclicity with it, which is why the gate counts a deferred
  // edge as an edge.
  assert.ok(measured.cycleDeferredEdges > 0);
  assert.ok(measured.cycleDeferredEdges < measured.cycleInternalEdges);
});

test("the cycle inventory is immutable at runtime, so it shrinks only via source edits", () => {
  assert.throws(() => ALLOWLIST_MODULE_CYCLES.set("x", { size: 1, argument: "y" }), TypeError);
  assert.throws(() => ALLOWLIST_MODULE_CYCLES.delete([...ALLOWLIST_MODULE_CYCLES.keys()][0]), TypeError);
  assert.throws(() => ALLOWLIST_MODULE_CYCLES.clear(), TypeError);
});

test("both allowlists are immutable at runtime, so they shrink only via source edits", () => {
  assert.throws(() => ALLOWLIST_DYNAMIC_REQUIRES.add("x"), TypeError);
  assert.throws(() => ALLOWLIST_DYNAMIC_REQUIRES.delete([...ALLOWLIST_DYNAMIC_REQUIRES][0]), TypeError);
  assert.throws(() => ALLOWLIST_DYNAMIC_REQUIRES.clear(), TypeError);
  // The boundary list is a Map now; freezing a Map leaves [[MapData]] writable,
  // so `set` has to be blocked for the same reason `add` was.
  assert.throws(() => ALLOWLIST_BOUNDARY_VIOLATIONS.set("x", "composition_root"), TypeError);
  assert.throws(() => ALLOWLIST_BOUNDARY_VIOLATIONS.delete([...ALLOWLIST_BOUNDARY_VIOLATIONS.keys()][0]), TypeError);
  assert.throws(() => ALLOWLIST_BOUNDARY_VIOLATIONS.clear(), TypeError);
  assert.throws(() => BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.set("x", "composition_root"), TypeError);
  assert.throws(() => BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.delete(
    [...BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.keys()][0],
  ), TypeError);
  assert.throws(() => BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.clear(), TypeError);
});

// ADJUDICATION. A bare edge count reads as a backlog; this one is not. Every
// entry carries exactly one class, and the one class that makes a checkable
// claim about the tree is checked against the tree.
test("every allowlisted edge carries exactly one class from the frozen vocabulary", () => {
  assert.equal(Object.isFrozen(BOUNDARY_ADJUDICATION_CLASSES), true);
  assert.equal(new Set(BOUNDARY_ADJUDICATION_CLASSES).size, BOUNDARY_ADJUDICATION_CLASSES.length);
  for (const [entry, adjudication] of ALLOWLIST_BOUNDARY_VIOLATIONS) {
    assert.equal(
      BOUNDARY_ADJUDICATION_CLASSES.includes(adjudication),
      true,
      `${entry} is classed ${JSON.stringify(adjudication)}`,
    );
  }

  const { measured } = runChecks({ root: REPO_ROOT });
  const histogram = BOUNDARY_ADJUDICATION_CLASSES.reduce((sum, name) => sum + measured.adjudication.get(name), 0);
  assert.equal(histogram, ALLOWLIST_BOUNDARY_VIOLATIONS.size);

  // composition_root is DERIVED: the labelled set must be exactly the set the
  // walk read as importing from the composition root module.
  assert.deepEqual(
    [...ALLOWLIST_BOUNDARY_VIOLATIONS].filter(([, c]) => c === "composition_root").map(([k]) => k).sort(),
    [...measured.boundaryEdgeFacts]
      .filter(([, facts]) => facts.importer === COMPOSITION_ROOT_MODULE)
      .map(([key]) => key)
      .sort(),
  );
});

// DOC BINDING. The seam audit's inventory is a second census of the same tree,
// and two censuses drift. Bind them: bijection in both directions, and every
// row's cited site re-read through the parser rather than trusted.
test("the seam inventory and the allowlist are in enforced bijection", () => {
  const { violations, measured } = runChecks({ root: REPO_ROOT });
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
  assert.equal(measured.inventoryPath, SEAM_INVENTORY_RELPATH);
  assert.equal(measured.inventoryPoliced, ALLOWLIST_BOUNDARY_VIOLATIONS.size);
  assert.equal(
    measured.inventoryRows,
    measured.inventoryPoliced + measured.inventoryCrossPackage + measured.inventoryPlaneToPlane,
    "every inventoried row must land in exactly one bucket",
  );
  // The only rows outside the gate's jurisdiction: the two edges that leave
  // mcp for a package, and the one plane -> plane edge.
  assert.equal(measured.inventoryCrossPackage, 2);
  assert.equal(measured.inventoryPlaneToPlane, 1);
});

test("the blockchain seam inventory and allowlist are in enforced bijection", () => {
  const { violations, measured } = runChecks({ root: REPO_ROOT });
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
  assert.equal(measured.blockchain.inventoryPath, BLOCKCHAIN_SEAM_INVENTORY_RELPATH);
  assert.equal(measured.blockchain.inventoryPoliced, BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS.size);
  assert.equal(
    measured.blockchain.inventoryRows,
    measured.blockchain.inventoryPoliced
      + measured.blockchain.inventoryCrossPackage
      + measured.blockchain.inventoryPlaneToPlane,
    "every blockchain inventory row must land in exactly one bucket",
  );
  assert.equal(measured.blockchain.inventoryCrossPackage, 0);
  assert.equal(measured.blockchain.inventoryPlaneToPlane, 0);
});

// Asserted here as well as inside the gate, because this is the property that
// actually rotted: a row cited graph-scheduler.js:53 after the require moved to
// :54, and nothing in the tree noticed for as long as nobody re-read it.
test("every seam inventory row cites a line that still holds its require", () => {
  const { rows, malformed } = parseSeamInventoryRows(
    fs.readFileSync(path.join(REPO_ROOT, SEAM_INVENTORY_RELPATH), "utf8"),
  );
  assert.deepEqual(malformed, []);
  assert.ok(rows.length > 0);
  for (const row of rows) {
    const source = fs.readFileSync(path.join(REPO_ROOT, row.importer), "utf8");
    const sites = collectStaticRequires(source, row.importer);
    assert.equal(
      sites.some((site) => site.line === row.line && site.specifier === row.specifier),
      true,
      `row ${row.row}: ${row.importer}:${row.line} no longer requires ${row.specifier} `
        + `(found at line(s) ${sites.filter((s) => s.specifier === row.specifier).map((s) => s.line).join(", ")})`,
    );
  }
});

// Structural classification and its frozen, only-shrinking inventory are
// deliberately separate: the path decides the layer, while the inventory makes
// moving a file in either direction fail rather than silently redefining it.
test("the plane classifier is structural and its live inventory is exact", () => {
  assert.equal(Object.isFrozen(PLANE_MEMBERS), true);
  assert.throws(() => PLANE_MEMBERS.add("laundered.js"), /PLANE_MEMBERS is immutable/);
  assert.equal(Object.isFrozen(BLOCKCHAIN_PLANE_MEMBERS), true);
  assert.throws(() => BLOCKCHAIN_PLANE_MEMBERS.add("laundered.js"), /BLOCKCHAIN_PLANE_MEMBERS is immutable/);
  assert.equal(typeof PLANE_AXIS, "string");
  assert.deepEqual(PLANE_AXES, ["physical", "blockchain"]);
  assert.equal(classifyModule(path.join(MCP_LIB, "surface-graph.js"), MCP_LIB), "core");
  assert.equal(classifyModule(path.join(MCP_LIB, "redaction", "index.js"), MCP_LIB), "core");
  assert.equal(classifyModule(path.join(MCP_LIB, "ledger-integrity", "index.js"), MCP_LIB), "core");
  assert.equal(classifyModule(path.join(MCP_LIB, "domains", "physical", "physical-resource-arbiter.js"), MCP_LIB), "plane");
  assert.equal(planeMemberOf(MCP_LIB, path.join(MCP_LIB, "domains", "physical", "renamed.js")), "domains/physical/renamed.js");
  assert.equal(planeMemberOf(MCP_LIB, path.join(MCP_LIB, "tools", "physical", "renamed.js")), "tools/physical/renamed.js");
  assert.equal(
    planeMemberOf(MCP_LIB, path.join(MCP_LIB, "domains", "blockchain", "renamed.js")),
    "domains/blockchain/renamed.js",
  );
  assert.equal(
    planeMemberOf(MCP_LIB, path.join(MCP_LIB, "tools", "blockchain", "renamed.js")),
    "tools/blockchain/renamed.js",
  );
  assert.equal(planeMemberOf(MCP_LIB, path.join(MCP_LIB, "tools", "renamed.js")), null);

  const onDisk = [];
  for (const directory of [path.join(MCP_LIB, "domains", "physical"), path.join(MCP_LIB, "tools", "physical")]) {
    onDisk.push(...fs.readdirSync(directory).filter((name) => name.endsWith(".js")));
  }
  assert.equal(onDisk.length, 57);
  assert.deepEqual(onDisk.sort(), [...PLANE_MEMBERS].sort());

  const blockchainOnDisk = [];
  for (const directory of [
    path.join(MCP_LIB, "domains", BLOCKCHAIN_PLANE_AXIS),
    path.join(MCP_LIB, "tools", BLOCKCHAIN_PLANE_AXIS),
  ]) {
    const visit = (current) => {
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        if (entry.isDirectory()) visit(path.join(current, entry.name));
        else if (entry.isFile() && entry.name.endsWith(".js")) blockchainOnDisk.push(entry.name);
      }
    };
    visit(directory);
  }
  assert.equal(blockchainOnDisk.length, 53);
  assert.deepEqual(blockchainOnDisk.sort(), [...BLOCKCHAIN_PLANE_MEMBERS].sort());
});

test("a domains/physical file absent from PLANE_MEMBERS fails as unrecorded", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/new-member.js": '"use strict";\nmodule.exports = {};\n',
  });
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", planeMembers: new Set(),
  });
  assert.deepEqual(kindsOf(violations), ["plane_member_unrecorded"]);
  assert.equal(violations[0].id, "new-member.js");
  assert.match(violations[0].detail, /sits below a domains\/physical\/ directory/);

  assert.deepEqual(runChecks({
    ...NO_SEAM, root: dir, walk: "lib", planeMembers: new Set(["new-member.js"]),
  }).violations, []);
}));

test("a PLANE_MEMBERS entry moved outside physical directories fails as missing", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/member.js": '"use strict";\nmodule.exports = {};\n',
  });
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", planeMembers: new Set(["member.js"]),
  });
  assert.deepEqual(kindsOf(violations), ["plane_member_missing"]);
  assert.equal(violations[0].id, "member.js");
  assert.match(violations[0].detail, /no such file is below a domains\/physical\/ directory/);

  writeFixture(dir, {
    "lib/domains/physical/member.js": '"use strict";\nmodule.exports = {};\n',
  });
  fs.rmSync(path.join(dir, "lib", "member.js"));
  assert.deepEqual(runChecks({
    ...NO_SEAM, root: dir, walk: "lib", planeMembers: new Set(["member.js"]),
  }).violations, []);
}));

test("a physical-axis tool outside tools/physical fails closed", () => withTempDir((dir) => {
  // The missing package makes the live load fail. The gate must still derive
  // the literal axis from the parsed descriptor rather than rendering the
  // unavailable export as an axis-free clean result.
  const source = '"use strict";\nrequire("definitely-missing-bob-axis-control");\n'
    + 'module.exports = { required_session_axes: ["physical"] };\n';
  writeFixture(dir, { "lib/tools/axis-tool.js": source });
  const { violations } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["physical_axis_tool_outside_physical_directory"]);
  assert.equal(violations[0].id, "tools/axis-tool.js");
  assert.match(violations[0].detail, /does not live below tools\/physical\//);

  writeFixture(dir, { "lib/tools/physical/axis-tool.js": source });
  fs.rmSync(path.join(dir, "lib", "tools", "axis-tool.js"));
  assert.deepEqual(runChecks({ root: dir, walk: "lib", ...NO_SEAM }).violations, []);
}));

test("a contracts-axis tool outside tools/blockchain fails closed", () => withTempDir((dir) => {
  const source = '"use strict";\nmodule.exports = { required_session_axes: ["contracts"] };\n';
  writeFixture(dir, { "lib/tools/axis-tool.js": source });
  const { violations } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["blockchain_axis_tool_outside_blockchain_directory"]);
  assert.equal(violations[0].id, "tools/axis-tool.js");
  assert.match(violations[0].detail, /does not live below tools\/blockchain\//);

  writeFixture(dir, { "lib/tools/blockchain/axis-tool.js": source });
  fs.rmSync(path.join(dir, "lib", "tools", "axis-tool.js"));
  assert.deepEqual(runChecks({ root: dir, walk: "lib", ...NO_SEAM }).violations, []);
}));

// The axis is a consistency signal, not a classifier. These tools are plane by
// path; the live export independently proves the axis-visible subset agrees.
test("plane tool modules are structural and their live session axes agree", () => {
  const planeTools = [
    "init-physical-session.js",
    "record-physical-candidate-claim.js",
    "verify-physical-candidate-claim.js",
    "verify-physical-verdict.js",
    "protocol-transceive.js",
    "query-instrument-capabilities.js",
  ];
  for (const basename of planeTools) {
    assert.equal(
      classifyModule(path.join(MCP_LIB, "tools", "physical", basename), MCP_LIB),
      "plane",
      `tools/physical/${basename} must classify as plane`,
    );
    for (const entry of ALLOWLIST_BOUNDARY_VIOLATIONS.keys()) {
      assert.equal(
        entry.startsWith(`tools/physical/${basename} ->`),
        false,
        `tools/physical/${basename} must contribute no allowlist entries`,
      );
    }
  }
  // protocol-transceive.js carries no plane token in its name, so it is the one
  // that proves the live-export arm is load-bearing rather than decorative.
  const axes = require("../mcp/tools/physical/protocol-transceive.js").required_session_axes;
  assert.equal(axes.includes(PLANE_AXIS), true);
});

// Why `role_bundles` is NOT the discriminator, measured rather than argued. If
// this ever becomes a sound predicate the checker can be simplified; until then
// the measurement is pinned so nobody re-derives the wrong rule from the name.
test("role_bundles alone would misclassify the boundary in both directions", () => {
  const toolsDir = path.join(MCP_LIB, "tools");
  const declaring = [];
  const toolFiles = [];
  const pending = [toolsDir];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && entry.name.endsWith(".js")) toolFiles.push(absolute);
    }
  }
  for (const toolFile of toolFiles.sort()) {
    const basename = path.basename(toolFile);
    let loaded;
    try {
      loaded = require(toolFile);
    } catch {
      continue;
    }
    const bundles = new Set();
    const absorb = (value) => {
      if (value && typeof value === "object" && Array.isArray(value.role_bundles)) {
        for (const bundle of value.role_bundles) bundles.add(bundle);
      }
    };
    absorb(loaded);
    if (loaded && typeof loaded === "object") for (const value of Object.values(loaded)) absorb(value);
    if (bundles.has(`evaluator-${PLANE_AXIS}`)) declaring.push(basename);
  }

  // OVER-inclusion: shared core tools declare the plane bundle too.
  const sharedCore = [
    "get-context-budget.js",
    "log-technique-attempt.js",
    "read-assignment-brief.js",
    "read-session-nucleus.js",
    "read-task-graph.js",
    "read-technique-pack.js",
    "select-technique-packs.js",
  ];
  for (const basename of sharedCore) {
    assert.equal(declaring.includes(basename), true, `${basename} declares the plane bundle`);
    assert.equal(classifyModule(path.join(toolsDir, basename), MCP_LIB), "core");
  }

  // UNDER-inclusion: real plane modules declare other bundles entirely.
  for (const basename of ["init-physical-session.js", "verify-physical-verdict.js", "verify-physical-candidate-claim.js"]) {
    assert.equal(declaring.includes(basename), false, `${basename} does not declare the plane bundle`);
    assert.equal(classifyModule(path.join(toolsDir, "physical", basename), MCP_LIB), "plane");
  }
});

// NEGATIVE CONTROL (b). Inverting this — adding the planted edge to the
// allowlist passed in — turns the assertion red.
test("a planted core -> plane require fails, naming the file, the module, and the line", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": '"use strict";\nmodule.exports = { thing: 1 };\n',
    "lib/core-thing.js": '"use strict";\nmodule.exports = { core: 1 };\n',
    "lib/importer.js": '"use strict";\n'
      + 'const { core } = require("./core-thing.js");\n'
      + 'const { thing } = require("./domains/physical/physical-thing.js");\n'
      + "module.exports = { core, thing };\n",
  });

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["core_requires_plane"]);
  assert.equal(violations[0].id, "importer.js -> domains/physical/physical-thing.js");
  assert.match(violations[0].detail, /^importer\.js:3 /);
  assert.match(violations[0].detail, /physical-thing\.js/);
  assert.equal(measured.filesWalked, 3);

  // INVERSION: allowlisting the same edge clears it, and nothing else appears.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      allowlist: new Map([["importer.js -> domains/physical/physical-thing.js", "plane_value_import"]]),
    }).violations,
    [],
  );

  const { status, output } = runCli(["--root", dir, "--walk", "lib", "--no-allowlist", "--no-inventory"]);
  assert.equal(status, 1);
  assert.match(output, /core_requires_plane/);
  assert.match(output, /importer\.js/);
  // The failure header carries the coverage note, not just the OK line.
  assert.match(output, /NOT enforced/);
  assert.match(output, /walked lib \(3 \.js file\(s\)/);
}));

// THE KEY IS A PATH, NOT A BASENAME. Two distinct edges from one importer to
// same-named plane modules in different directories are two edges, and one
// allowlist entry may silence only one of them. Keyed by basename this fixture
// measured ONE edge and ZERO violations under the single entry below — the
// second edge rode in free on the first one's adjudication. Nothing on the live
// tree collides today (38 edges keyed either way), so this planted collision is
// the only thing that holds the key form in place.
test("same-named plane modules in different directories are two distinct edges", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": '"use strict";\nmodule.exports = { thing: 1 };\n',
    "lib/domains/physical/sub/physical-thing.js": '"use strict";\nmodule.exports = { thing: 2 };\n',
    "lib/importer.js": '"use strict";\n'
      + 'const a = require("./domains/physical/physical-thing.js");\n'
      + 'const b = require("./domains/physical/sub/physical-thing.js");\n'
      + "module.exports = { a, b };\n",
  });

  const flat = "importer.js -> domains/physical/physical-thing.js";
  const nested = "importer.js -> domains/physical/sub/physical-thing.js";

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.equal(measured.boundaryEdges.size, 2);
  assert.deepEqual([...measured.boundaryEdges].sort(), [flat, nested]);
  assert.deepEqual(kindsOf(violations), ["core_requires_plane", "core_requires_plane"]);

  // The false-sibling input to consolidatable_not_taken, pinned directly: the
  // two targets bucket apart, so neither importer set absorbs the other's.
  assert.deepEqual([...measured.planeTargetImporters.keys()].sort(), ["domains/physical/physical-thing.js", "domains/physical/sub/physical-thing.js"]);
  assert.deepEqual([...measured.planeTargetImporters.get("domains/physical/physical-thing.js")], ["importer.js"]);
  assert.deepEqual([...measured.planeTargetImporters.get("domains/physical/sub/physical-thing.js")], ["importer.js"]);

  // One entry silences one edge. The other still fails, by its own key.
  const partial = runChecks({
    ...NO_SEAM,
    root: dir,
    walk: "lib",
    allowlist: new Map([[flat, "plane_value_import"]]),
  });
  assert.deepEqual(kindsOf(partial.violations), ["core_requires_plane"]);
  assert.equal(partial.violations[0].id, nested);

  // INVERSION: allowlisting both — and only both — clears the tree.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      allowlist: new Map([[flat, "plane_value_import"], [nested, "plane_value_import"]]),
    }).violations,
    [],
  );
}));

// NEGATIVE CONTROL (c). Only-shrinking: an entry whose violation is gone fails.
// Inverting this — dropping the entry from the allowlist — turns it red.
test("an allowlist entry whose violation is gone fails as stale, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": '"use strict";\nmodule.exports = { thing: 1 };\n',
    "lib/importer.js": '"use strict";\nmodule.exports = { core: 1 };\n',
  });

  const stale = "importer.js -> domains/physical/physical-thing.js";
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[stale, "plane_value_import"]]),
  });
  assert.deepEqual(kindsOf(violations), ["stale_allowlist_entry"]);
  assert.equal(violations[0].id, stale);
  assert.match(violations[0].detail, /stale allowlist entry/);

  // INVERSION: with the entry removed the same tree is clean.
  assert.deepEqual(
    runChecks({ root: dir, walk: "lib", ...NO_SEAM }).violations,
    [],
  );
}));

// ---------------------------------------------------------------------------
// RULE TWO — CYCLES. A module cannot be extracted across a cycle, so the cycle
// set is the ceiling on any layout this tree could adopt, and it is derived here
// rather than carried in a document. Four controls, each inverting:
//
//   (i)   a cycle nobody recorded FAILS, named with every member;
//   (ii)  an inventory entry whose cycle is gone FAILS as stale, so the list
//         only shrinks;
//   (iii) a recorded cycle that CHANGED SIZE fails — an argument written about
//         36 files does not cover the 37th;
//   (iv)  an entry with no irreducibility argument fails, so the inventory
//         cannot decay into the bare backlog the plane list already refuses.
//
// And the property that makes all four worth having: a require moved inside a
// function is still an edge. The last test plants exactly that shape and asserts
// the cycle is still found and still counted as deferred.

const CYCLE_FIXTURE = {
  "lib/a.js": '"use strict";\nconst b = require("./b.js");\nmodule.exports = { b };\n',
  "lib/b.js": '"use strict";\nconst a = require("./a.js");\nmodule.exports = { a };\n',
  "lib/loner.js": '"use strict";\nmodule.exports = {};\n',
};

test("a dependency cycle nobody recorded fails, named with every member", () => withTempDir((dir) => {
  writeFixture(dir, CYCLE_FIXTURE);

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unrecorded_module_cycle"]);
  // Keyed by the lexicographically first member, and the detail names them all.
  assert.equal(violations[0].id, "a.js");
  assert.match(violations[0].detail, /a\.js, b\.js/);
  assert.match(violations[0].detail, /cannot be extracted across a cycle/);
  assert.equal(measured.cycleCount, 1);
  assert.equal(measured.largestCycle, 2);
  assert.equal(measured.filesInCyclesCount, 2);
  // The lone module is a node in the graph and in no cycle — a component
  // derived only over importers would never have seen it.
  assert.equal(measured.filesWalked, 3);
  assert.equal(measured.cycleInternalEdges, 2);
  assert.equal(measured.cycleDeferredEdges, 0);

  // INVERSION: recording it with its size and an argument clears it.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      cycleAllowlist: new Map([["a.js", { size: 2, argument: "mutual by construction in this fixture" }]]),
    }).violations,
    [],
  );

  const { status, output } = runCli(["--root", dir, "--walk", "lib", "--no-allowlist", "--no-inventory"]);
  assert.equal(status, 1);
  assert.match(output, /unrecorded_module_cycle/);
  assert.match(output, /module cycles: 1 over 2 of 3 walked module\(s\)/);
}));

test("a cycle inventory entry whose cycle is gone fails as stale", () => withTempDir((dir) => {
  writeFixture(dir, { "lib/a.js": '"use strict";\nmodule.exports = {};\n' });

  const { violations } = runChecks({
    ...NO_SEAM,
    root: dir,
    walk: "lib",
    cycleAllowlist: new Map([["a.js", { size: 2, argument: "recorded when a.js and b.js were mutual" }]]),
  });
  assert.deepEqual(kindsOf(violations), ["stale_cycle_entry"]);
  assert.equal(violations[0].id, "a.js");
  assert.match(violations[0].detail, /the list only shrinks/);

  // INVERSION: with the entry dropped the same tree is clean.
  assert.deepEqual(runChecks({ root: dir, walk: "lib", ...NO_SEAM }).violations, []);
}));

test("a recorded cycle that changed size fails rather than passing on its representative", () => withTempDir((dir) => {
  // Same two-module cycle, plus a third file that joins it. The representative
  // is unchanged, so ONLY the size check can catch this.
  writeFixture(dir, {
    "lib/a.js": '"use strict";\nconst b = require("./b.js");\nmodule.exports = { b };\n',
    "lib/b.js": '"use strict";\nconst c = require("./c.js");\nmodule.exports = { c };\n',
    "lib/c.js": '"use strict";\nconst a = require("./a.js");\nmodule.exports = { a };\n',
  });

  const twoFile = new Map([["a.js", { size: 2, argument: "recorded before c.js joined" }]]);
  const { violations, measured } = runChecks({ ...NO_SEAM, root: dir, walk: "lib", cycleAllowlist: twoFile });
  assert.deepEqual(kindsOf(violations), ["module_cycle_size_drift"]);
  assert.equal(violations[0].id, "a.js");
  assert.match(violations[0].detail, /records a\.js as a 2-module cycle and the walk measured 3/);
  assert.match(violations[0].detail, /a\.js, b\.js, c\.js/);
  assert.equal(measured.largestCycle, 3);

  // INVERSION: correcting the size to the measured one clears it.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      cycleAllowlist: new Map([["a.js", { size: 3, argument: "re-derived at three" }]]),
    }).violations,
    [],
  );
}));

test("a recorded cycle with no irreducibility argument fails", () => withTempDir((dir) => {
  writeFixture(dir, CYCLE_FIXTURE);

  for (const argument of ["", "   ", undefined]) {
    const { violations } = runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      cycleAllowlist: new Map([["a.js", { size: 2, argument }]]),
    });
    assert.deepEqual(kindsOf(violations), ["unargued_module_cycle"], `argument ${JSON.stringify(argument)}`);
    assert.match(violations[0].detail, /a list of cycles with no arguments is a backlog/);
  }

  // INVERSION: any non-empty argument clears it.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM,
      root: dir,
      walk: "lib",
      cycleAllowlist: new Map([["a.js", { size: 2, argument: "mutual by construction" }]]),
    }).violations,
    [],
  );
}));

// THE DEFERRAL. Moving a require inside a function removes it from the top of
// the file and from nothing else. The cycle is still found, and the edge is
// counted as deferred so a reader can see that the deferral bought nothing.
test("a cycle written with an in-function require is still a cycle, and is counted as deferred", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/a.js": '"use strict";\nfunction later() { return require("./b.js"); }\nmodule.exports = { later };\n',
    "lib/b.js": '"use strict";\nconst a = require("./a.js");\nmodule.exports = { a };\n',
  });

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unrecorded_module_cycle"]);
  assert.equal(measured.cycleInternalEdges, 2);
  assert.equal(measured.cycleDeferredEdges, 1, "the in-function edge must be counted, not dropped");

  // Deferring BOTH directions still leaves the cycle, and now every edge in it
  // is deferred — which is the shape that reads as "broken" and is not.
  writeFixture(dir, {
    "lib/b.js": '"use strict";\nfunction later() { return require("./a.js"); }\nmodule.exports = { later };\n',
  });
  const both = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(both.violations), ["unrecorded_module_cycle"]);
  assert.equal(both.measured.cycleDeferredEdges, 2);
  assert.equal(both.measured.largestCycle, 2);
}));

// The deferral flag is a fact about a PARSE, not about indentation. Asserted on
// the reader directly, because the census above is only as honest as this is.
test("the require reader marks a site deferred iff it sits inside a function body", () => {
  const sites = collectStaticRequires(
    'const top = require("./top.js");\n'
    + 'if (top) require("./conditional.js");\n'
    + 'function f() { const inner = require("./inner.js"); return inner; }\n'
    + 'const arrow = () => require("./arrow.js");\n'
    + 'const obj = { m() { return require("./method.js"); } };\n',
    "fixture.js",
  );
  assert.deepEqual(
    Object.fromEntries(sites.map((site) => [site.specifier, site.deferred])),
    {
      "./top.js": false,
      // A conditional at module scope still runs at LOAD time; indentation is
      // not the question and a text scan that keyed on it would answer wrong.
      "./conditional.js": false,
      "./inner.js": true,
      // An expression-bodied arrow has no block, and its edge is still deferred.
      "./arrow.js": true,
      "./method.js": true,
    },
  );
});

test("a stale computed-require entry fails the same way", () => withTempDir((dir) => {
  writeFixture(dir, { "lib/importer.js": '"use strict";\nmodule.exports = {};\n' });
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", dynamicAllowlist: new Set(["importer.js (Identifier)"]),
  });
  assert.deepEqual(kindsOf(violations), ["stale_dynamic_allowlist_entry"]);
}));

// FAIL CLOSED (d). A file the parser cannot read is never counted as clean.
test("an unparseable module fails, naming the file and the parse message", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/ok.js": '"use strict";\nmodule.exports = {};\n',
    "lib/broken.js": '"use strict";\nfunction ( { unbalanced\n',
  });

  const { violations } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unparseable_module"]);
  assert.equal(violations[0].id, "broken.js");
  assert.match(violations[0].detail, /broken\.js cannot be parsed/);
  assert.match(violations[0].detail, /\(\d+:\d+\)/);

  const { status, output } = runCli(["--root", dir, "--walk", "lib", "--no-allowlist", "--no-inventory"]);
  assert.equal(status, 1);
  assert.match(output, /unparseable_module/);
  assert.match(output, /broken\.js/);
}));

// FAIL CLOSED, other half: an edge whose specifier is computed is named and
// counted, never dropped. The gate says what it cannot see.
test("a computed require specifier is reported rather than silently skipped", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/importer.js": '"use strict";\n'
      + "const which = process.env.WHICH;\n"
      + "const mod = require(which);\n"
      + "const tpl = require(`./${which}.js`);\n"
      + "module.exports = { mod, tpl };\n",
  });

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["non_static_require_specifier", "non_static_require_specifier"]);
  assert.deepEqual(
    measured.dynamicSites.map((site) => site.key),
    ["importer.js (Identifier)", "importer.js (TemplateLiteral)"],
  );
  assert.match(violations[0].detail, /importer\.js:3/);
}));

test("an unresolvable relative specifier fails rather than passing as external", () => withTempDir((dir) => {
  writeFixture(dir, { "lib/importer.js": '"use strict";\nrequire("./gone.js");\n' });
  const { violations } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unresolvable_require"]);
  assert.match(violations[0].detail, /gone\.js/);
}));

// PARSE, NEVER PATTERN-MATCH (e). The regression fixed when the AST reader
// landed: a hand-written mode machine has no regex-literal state, so
// `/^["']+|["']+$/` closes the double quote it opened and then opens a single
// that never closes — everything after it is read as string, or as code, at
// random. None of these four `require` occurrences is a call site.
test("requires inside comments and regex literals yield zero edges", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": '"use strict";\nmodule.exports = {};\n',
    "lib/importer.js": '"use strict";\n'
      + 'const t = (s) => s.replace(/require\\("\\.\\/physical-x\\.js"\\)/g, "");\n'
      + '// require("./physical-thing.js")\n'
      + '/* require("./physical-thing.js") */\n'
      + 'const quoted = "require(\'./physical-thing.js\')";\n'
      + "module.exports = { t, quoted };\n",
  });

  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
  assert.equal(measured.boundaryEdges.size, 0);
  assert.equal(measured.edgesWalked, 0);
}));

// The same property at the reader itself, so the guarantee is pinned where it
// is implemented and not only where it is consumed.
test("collectStaticRequires reads call sites only, and reports non-literal ones", () => {
  const source = [
    'const t = s.replace(/require\\("x"\\)|^["\']+/g, "");',
    '// require("./commented.js")',
    '/* require("./blocked.js") */',
    'const real = require("./real.js");',
    "const dyn = require(name);",
    "const none = require();",
    'const member = require.resolve("./resolved.js");',
  ].join("\n");
  const sites = collectStaticRequires(source, "<fixture>");
  assert.deepEqual(sites, [
    { specifier: "./real.js", line: 4, argument_type: "StringLiteral", callee_form: "require", deferred: false },
    { specifier: null, line: 5, argument_type: "Identifier", callee_form: "require", deferred: false },
    { specifier: null, line: 6, argument_type: "(no argument)", callee_form: "require", deferred: false },
    // Still not a module edge — but returned, so the exclusion can be counted
    // by the caller rather than assumed.
    { specifier: null, line: 7, argument_type: "StringLiteral", callee_form: "require_resolve", deferred: false },
  ]);
});

// The forms a bare-`require` scan walked straight past. Each is either RESOLVED
// (the specifier really does resolve against the importing file) or returned
// with a null specifier so the caller has to say something about it. A reader
// that regresses to invisible drops entries here.
test("collectStaticRequires sees the edge forms that are not a bare require", () => {
  const source = [
    'import("./imported.js");',
    "import(which);",
    'module.require("./from-module.js");',
    'other.require("./from-other.js");',
    "const aliased = require;",
    "const { require: destructured } = holder;",
  ].join("\n");
  assert.deepEqual(collectStaticRequires(source, "<fixture>"), [
    // `import(<literal>)` resolves against the importing file exactly as
    // `require` does, so it is a real edge with a real specifier.
    { specifier: "./imported.js", line: 1, argument_type: "StringLiteral", callee_form: "dynamic_import", deferred: false },
    { specifier: null, line: 2, argument_type: "Identifier", callee_form: "dynamic_import", deferred: false },
    // `module.require` resolves against THIS file; any other receiver resolves
    // against the receiver's path, so answering for it would be a wrong-base
    // resolution — a worse failure than the silence it replaces.
    { specifier: "./from-module.js", line: 3, argument_type: "StringLiteral", callee_form: "member_require", deferred: false },
    { specifier: null, line: 4, argument_type: "StringLiteral", callee_form: "member_require", deferred: false },
    { specifier: null, line: 5, argument_type: "(not a call)", callee_form: "require_alias_binding", deferred: false },
    { specifier: null, line: 6, argument_type: "(not a call)", callee_form: "require_alias_binding", deferred: false },
  ]);
});

// The constant fold. Narrow on purpose: a module-scope `const` bound to
// `path.resolve(__dirname, ...)` over literals, which is the one computed shape
// this tree writes. Everything wider stays null, so the fold cannot quietly
// become a dataflow analysis that is wrong somewhere nobody looks.
test("a __dirname-rooted module-path constant folds to a relative specifier", () => {
  const computed = (lines) => collectStaticRequires(lines.join("\n"), "<fixture>")
    .filter((site) => site.argument_type === "Identifier");

  assert.deepEqual(computed([
    'const path = require("path");',
    'const TARGET = path.resolve(__dirname, "sub", "target.js");',
    "require(TARGET);",
  ]).map((site) => site.specifier), ["./sub/target.js"]);

  // Reassigned: the fold cannot say which value reaches the call.
  assert.deepEqual(computed([
    'const path = require("path");',
    'let TARGET = path.resolve(__dirname, "target.js");',
    'TARGET = "./elsewhere.js";',
    "require(TARGET);",
  ]).map((site) => site.specifier), [null]);

  // Not rooted at __dirname, so the base is not the importing file.
  assert.deepEqual(computed([
    'const path = require("path");',
    'const TARGET = path.resolve(base, "target.js");',
    "require(TARGET);",
  ]).map((site) => site.specifier), [null]);
});

// The once-only binding count is the WHOLE safety argument for a fold that is
// keyed by name and blind to scope, so it has to see every form a name can be
// bound in. Each shadow below was invisible to an Identifier-only check and
// folded the call against the wrong file; each must now REFUSE.
test("a shadowed module-path constant refuses to fold, in every binding form", () => {
  const computed = (shadow) => collectStaticRequires([
    'const path = require("path");',
    'const TARGET = path.resolve(__dirname, "real.js");',
    shadow,
    "require(TARGET);",
  ].join("\n"), "<fixture>")
    .filter((site) => site.argument_type === "Identifier")
    .map((site) => site.specifier);

  // The un-shadowed baseline still folds. Without it a reader that simply
  // stopped folding altogether would pass this test by refusing everything.
  assert.deepEqual(computed("function f() { return TARGET; }"), ["./real.js"]);

  for (const shadow of [
    "function f() { const { TARGET } = other; return TARGET; }",
    "function f() { const { key: TARGET } = other; return TARGET; }",
    'function f() { const { TARGET = "x" } = other; return TARGET; }',
    "function f() { const [TARGET] = other; return TARGET; }",
    "function f() { const { a, ...TARGET } = other; return TARGET; }",
    "function f() { const [a, ...TARGET] = other; return TARGET; }",
    "function f() { for (const { TARGET } of xs) { g(TARGET); } }",
    "function f({ TARGET }) { return TARGET; }",
    'function f(TARGET = "x") { return TARGET; }',
    "function f(...TARGET) { return TARGET; }",
    "const g = ({ TARGET }) => TARGET;",
    "function f() { try { h(); } catch (TARGET) { g(TARGET); } }",
    "function f() { function TARGET() {} return TARGET; }",
    "function f() { class TARGET {} return TARGET; }",
  ]) {
    assert.deepEqual(computed(shadow), [null], `this shadow must refuse the fold: ${shadow}`);
  }

  // The same widening applies to the `path` binding the fold reads its shape
  // from: a destructured rebinding of it means the receiver is not known to be
  // the path module, so there is no shape to fold.
  assert.deepEqual(computed("function f({ path }) { return path; }"), [null]);
});

// The live edge the fold exists for. `role-trace-expectations.js` reads as a
// zero-fan-in orphan to any walk that cannot follow this one require. It is
// also the ceiling on the widening above: an empty frozen dynamic allowlist
// means a fold that refuses HERE turns the live tree red.
test("the live computed require in mcp resolves to the module it loads", () => {
  const importer = path.join(MCP_LIB, "core", "trace-reading-composer.js");
  const sites = collectStaticRequires(
    fs.readFileSync(importer, "utf8"),
    "core/trace-reading-composer.js",
  );
  const folded = sites.filter((site) => site.argument_type === "Identifier");
  assert.equal(folded.length, 1);
  assert.equal(folded[0].specifier, "./role-trace-expectations.js");
  assert.equal(fs.existsSync(path.join(MCP_LIB, "core", "role-trace-expectations.js")), true);
});

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS, one per edge form the reader used to walk past. Each is
// written so that a reader regressing to invisible turns the assertion RED
// rather than green: the "clean" outcome is never the passing one.

const PLANE_TARGET = '"use strict";\nmodule.exports = { thing: 1 };\n';

// (a) `x.require(y)` where x is not `module`: the receiver decides the
// resolution base, so the gate names the site instead of guessing at a base.
test("a member require is named as unpoliceable, not walked past", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-x.js": PLANE_TARGET,
    "lib/importer.js": '"use strict";\nconst m = require("module");\nm.require("./domains/physical/physical-x.js");\n',
  });
  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unpoliceable_require_form"]);
  assert.equal(violations[0].id, "importer.js:3 (member_require)");
  assert.equal(measured.boundaryEdges.size, 0);

  // INVERSION: written as a bare require, the SAME edge is a boundary
  // violation — which is what the member form was hiding.
  writeFixture(dir, {
    "lib/importer.js": '"use strict";\nrequire("./domains/physical/physical-x.js");\n',
  });
  const inverted = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(inverted.violations), ["core_requires_plane"]);
  assert.equal(inverted.violations[0].id, "importer.js -> domains/physical/physical-x.js");
}));

// (b) `import(<literal>)` is a real edge, resolved against the importing file
// exactly as require is — so it is SEEN, not merely named.
test("a dynamic import of a literal is a boundary edge, not an invisible one", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-x.js": PLANE_TARGET,
    "lib/importer.js": '"use strict";\nimport("./domains/physical/physical-x.js");\n',
  });
  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["core_requires_plane"]);
  assert.equal(violations[0].id, "importer.js -> domains/physical/physical-x.js");
  assert.equal(measured.edgesWalked, 1);

  // INVERSION: an expression argument cannot be resolved, so the same site
  // becomes a named exclusion rather than a silently clean file.
  writeFixture(dir, { "lib/importer.js": '"use strict";\nimport(which);\n' });
  const inverted = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(inverted.violations), ["unpoliceable_require_form"]);
  assert.equal(inverted.violations[0].id, "importer.js:2 (dynamic_import)");
}));

// (c) An alias binding ends the reader's completeness guarantee for the file,
// so the gate fails on the BINDING rather than chasing the call.
test("aliasing require fails the file closed rather than certifying it", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-x.js": PLANE_TARGET,
    "lib/importer.js": '"use strict";\nconst r = require;\nr("./domains/physical/physical-x.js");\n',
  });
  const { violations } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["unpoliceable_require_form"]);
  assert.equal(violations[0].id, "importer.js:2 (require_alias_binding)");

  // INVERSION: without the alias the file certifies clean.
  writeFixture(dir, { "lib/importer.js": '"use strict";\nmodule.exports = {};\n' });
  assert.deepEqual(runChecks({ root: dir, walk: "lib", ...NO_SEAM }).violations, []);
}));

// (d) A resolvable in-root target the `.js` file listing never reached. The
// plane-named one is policed; the rest are COUNTED, never assigned a layer.
test("an in-root target the walk never classified is policed or counted, never silent", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-data.json": "{}\n",
    "lib/importer.js": '"use strict";\nrequire("./domains/physical/physical-data.json");\n',
  });
  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["core_requires_plane"]);
  assert.equal(violations[0].id, "importer.js -> domains/physical/physical-data.json");
  assert.equal(measured.inRootUnwalkedTargets.size, 0);

  // INVERSION: a non-plane basename is not a boundary edge — but the gate says
  // so with a number instead of dropping the edge on the floor.
  writeFixture(dir, {
    "lib/ordinary-data.json": "{}\n",
    "lib/importer.js": '"use strict";\nrequire("./ordinary-data.json");\n',
  });
  fs.rmSync(path.join(dir, "lib", "domains", "physical", "physical-data.json"));
  const inverted = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(inverted.violations, [], JSON.stringify(inverted.violations, null, 2));
  assert.deepEqual([...inverted.measured.inRootUnwalkedTargets], ["importer.js -> ordinary-data.json"]);
  assert.match(coverageNote(inverted.measured), /1 require target\(s\) INSIDE lib/);
}));

// `require.resolve` stays excluded — it asks where a module WOULD be — but the
// exclusion is a count in the note, not an assumption in the reader.
test("require.resolve is counted and named, and is not an edge", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/importer.js": '"use strict";\nrequire.resolve("patchright");\nrequire.resolve("./domains/physical/physical-x.js");\n',
  });
  const { violations, measured } = runChecks({ root: dir, walk: "lib", ...NO_SEAM });
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
  assert.equal(measured.requireResolveSites, 2);
  assert.equal(measured.edgesWalked, 0);
  assert.match(coverageNote(measured), /2 require\.resolve\(\.\.\.\) probe\(s\)/);
}));

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS (f): the adjudication is enforced, not decorative. Each of
// these is written so that INVERTING the control — supplying the right class,
// or moving the importer to the composition root — turns the assertion red.

const ONE_EDGE = {
  "lib/domains/physical/physical-thing.js": '"use strict";\nmodule.exports = { thing: 1 };\n',
  "lib/importer.js": '"use strict";\nconst { thing } = require("./domains/physical/physical-thing.js");\nmodule.exports = { thing };\n',
};
const ONE_EDGE_KEY = "importer.js -> domains/physical/physical-thing.js";

test("an allowlist entry with no adjudication class fails, named", () => withTempDir((dir) => {
  writeFixture(dir, ONE_EDGE);
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[ONE_EDGE_KEY, undefined]]),
  });
  assert.deepEqual(kindsOf(violations), ["unclassified_allowlist_entry"]);
  assert.equal(violations[0].id, ONE_EDGE_KEY);

  // INVERSION: with a class the same tree is clean.
  assert.deepEqual(
    runChecks({
      ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    }).violations,
    [],
  );
}));

test("an adjudication class outside the frozen vocabulary fails, named", () => withTempDir((dir) => {
  writeFixture(dir, ONE_EDGE);
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[ONE_EDGE_KEY, "wontfix"]]),
  });
  assert.deepEqual(kindsOf(violations), ["unknown_adjudication_class"]);
  assert.match(violations[0].detail, /"wontfix"/);
  assert.match(violations[0].detail, /composition_root/);
}));

// The derived arm. A label that asserts something about the tree is checked
// against the tree, so it cannot be pasted onto an ordinary edge.
test("composition_root on an importer that is not the composition root fails", () => withTempDir((dir) => {
  writeFixture(dir, ONE_EDGE);
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[ONE_EDGE_KEY, "composition_root"]]),
  });
  assert.deepEqual(kindsOf(violations), ["misclassified_composition_root"]);
  assert.equal(violations[0].id, ONE_EDGE_KEY);
  assert.match(violations[0].detail, /importer\.js/);
  assert.match(violations[0].detail, new RegExp(COMPOSITION_ROOT_MODULE.replace(/[\\/]/g, "[\\\\/]")));

  // INVERSION: the SAME label on the SAME edge passes once the importer really
  // is the composition root.
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-module-boundaries-cr-"));
  try {
    writeFixture(rootDir, {
      "lib/domains/physical/physical-thing.js": ONE_EDGE["lib/domains/physical/physical-thing.js"],
      "lib/tools/index.js": '"use strict";\nconst { thing } = require("../domains/physical/physical-thing.js");\nmodule.exports = { thing };\n',
    });
    assert.deepEqual(
      runChecks({
        ...NO_SEAM,
        root: rootDir,
        walk: "lib",
        allowlist: new Map([[`${COMPOSITION_ROOT_MODULE} -> domains/physical/physical-thing.js`, "composition_root"]]),
      }).violations,
      [],
    );
  } finally {
    fs.rmSync(rootDir, { recursive: true, force: true });
  }
}));

test("consolidatable_not_taken on an edge that duplicates nothing fails", () => withTempDir((dir) => {
  writeFixture(dir, ONE_EDGE);
  const { violations } = runChecks({
    ...NO_SEAM, root: dir, walk: "lib", allowlist: new Map([[ONE_EDGE_KEY, "consolidatable_not_taken"]]),
  });
  assert.deepEqual(kindsOf(violations), ["misclassified_consolidatable"]);
  assert.match(violations[0].detail, /0 other allowlisted core importer\(s\)/);
}));

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS (g): the doc cannot drift from the tree. Row 1 already did.

// `prelude` is the doc's PROSE census — the bullets above the table that state
// counts the checker re-derives. `toolSplit` is the Tool Split section, whose
// rows bind a tool name to the registration that mints it. Both are parameters
// rather than second builders, for the reason `prelude` already was: the census
// control, the row controls, and the citation controls must read the SAME table
// shape, or a control passes on a doc the real gate would never see. Absent by
// default, because a fixture doc usually carries neither and an absent section
// is not an error — a wrong one is.
function seamDoc(rows, prelude = [], toolSplit = []) {
  return [
    "# Fixture Seam",
    "",
    ...(prelude.length ? [...prelude, ""] : []),
    "| # | Edge |",
    "|---:|---|",
    ...rows,
    "",
    ...(toolSplit.length
      ? ["## Tool Split", "", "| Tool | Registration | Role bundle citation |", "|---|---|---|", ...toolSplit, ""]
      : []),
  ].join("\n");
}

test("an allowlisted edge with no inventory row fails, named", () => withTempDir((dir) => {
  writeFixture(dir, { ...ONE_EDGE, "seam.md": seamDoc([]) });
  const options = {
    root: dir,
    walk: "lib",
    allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC,
    cycleAllowlist: EMPTY_CYCLES,
    inventory: "seam.md",
  };
  const { violations, measured } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["unrecorded_boundary_edge"]);
  assert.equal(violations[0].id, ONE_EDGE_KEY);
  assert.equal(measured.inventoryRows, 0);

  // INVERSION: adding the row — and nothing else — clears it.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    seamDoc(["| 1 | `lib/importer.js:2` -> `./domains/physical/physical-thing.js` |"]),
    "utf8",
  );
  assert.deepEqual(runChecks(options).violations, []);
}));

// The other direction of the same bijection: a row the tree cannot answer for.
test("an inventory row that is not a boundary edge fails, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "lib/core-thing.js": '"use strict";\nmodule.exports = { core: 1 };\n',
    "lib/other.js": '"use strict";\nrequire("./core-thing.js");\n',
    "seam.md": seamDoc([
      "| 1 | `lib/importer.js:2` -> `./domains/physical/physical-thing.js` |",
      "| 2 | `lib/other.js:2` -> `./core-thing.js` |",
    ]),
  });
  const { violations } = runChecks({
    root: dir,
    walk: "lib",
    allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC,
    cycleAllowlist: EMPTY_CYCLES,
    inventory: "seam.md",
  });
  assert.deepEqual(kindsOf(violations), ["inventory_row_not_a_boundary_edge"]);
  assert.match(violations[0].detail, /core -> core/);
}));

test("an inventory row whose cited line no longer holds its require fails, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "seam.md": seamDoc(["| 1 | `lib/importer.js:3` -> `./domains/physical/physical-thing.js` |"]),
  });
  const options = {
    root: dir,
    walk: "lib",
    allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC,
    cycleAllowlist: EMPTY_CYCLES,
    inventory: "seam.md",
  };
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["inventory_line_drift", "unrecorded_boundary_edge"]);
  const drift = violations.find((v) => v.kind === "inventory_line_drift");
  assert.match(drift.detail, /cites lib\/importer\.js:3/);
  assert.match(drift.detail, /it is required at line\(s\) 2/);

  // INVERSION: the real line clears both, and the identity balances.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    seamDoc(["| 1 | `lib/importer.js:2` -> `./domains/physical/physical-thing.js` |"]),
    "utf8",
  );
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.inventoryRows, 1);
  assert.equal(measured.inventoryPoliced, 1);
  assert.equal(measured.inventoryCrossPackage, 0);
  assert.equal(measured.inventoryPlaneToPlane, 0);
}));

test("a missing seam inventory fails rather than being skipped as absent", () => withTempDir((dir) => {
  writeFixture(dir, ONE_EDGE);
  const { violations } = runChecks({
    root: dir,
    walk: "lib",
    allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC,
    cycleAllowlist: EMPTY_CYCLES,
    inventory: "seam.md",
  });
  assert.deepEqual(kindsOf(violations), ["missing_seam_inventory"]);
  assert.match(violations[0].detail, /--no-inventory/);
}));

test("a numbered inventory row that carries no edge is named, not ignored", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "seam.md": seamDoc([
      "| 1 | `lib/importer.js:2` -> `./domains/physical/physical-thing.js` |",
      "| 2 | a prose row that lost its edge |",
    ]),
  });
  const { violations } = runChecks({
    root: dir,
    walk: "lib",
    allowlist: new Map([[ONE_EDGE_KEY, "control_flow_core"]]),
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC,
    cycleAllowlist: EMPTY_CYCLES,
    inventory: "seam.md",
  });
  assert.deepEqual(kindsOf(violations), ["unparseable_inventory_row"]);
  assert.match(violations[0].id, /seam\.md:6$/);
}));

// ---------------------------------------------------------------------------
// The rest of the inventory binding, and the walk root itself. These branches
// were assertions nobody had ever watched decide anything: the census below
// derives the kind list from the checker's own source, and these are the kinds
// it named as unfired. Each plants the condition, asserts the kind fires naming
// the offending row or file, and inverts the plant to a clean run.

// The one row shape every control below reuses for the edge the fixture tree
// really does have, so the plant is the only thing under test.
const ONE_EDGE_ROW = "| 1 | `lib/importer.js:2` -> `./domains/physical/physical-thing.js` |";

function seamOptions(dir, allowlist = new Map([[ONE_EDGE_KEY, "control_flow_core"]])) {
  return {
    root: dir, walk: "lib", allowlist,
    ...NO_SMART_CONTRACTS,
    dynamicAllowlist: EMPTY_DYNAMIC, cycleAllowlist: EMPTY_CYCLES, inventory: "seam.md",
  };
}

test("a walk root that does not exist fails, named", () => withTempDir((dir) => {
  writeFixture(dir, { "lib/importer.js": '"use strict";\nmodule.exports = {};\n' });
  const { violations, measured } = runChecks({ root: dir, walk: "gone", ...NO_SEAM });
  assert.deepEqual(kindsOf(violations), ["missing_walk_root"]);
  assert.equal(violations[0].id, "gone");
  assert.match(violations[0].detail, /^gone does not exist/);
  assert.equal(measured.filesWalked, 0);

  // INVERSION: the same run against a walk root that exists is clean.
  writeFixture(dir, { "gone/importer.js": '"use strict";\nmodule.exports = {};\n' });
  assert.deepEqual(runChecks({ root: dir, walk: "gone", ...NO_SEAM }).violations, []);
}));

// The doc's PROSE census, which drifted where the rows could not: a bullet is
// not a row, so the row binding never looked at it.
test("a drifted prose census fails, naming the inventory that was read", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "seam.md": seamDoc([ONE_EDGE_ROW], ["- the walk reads **9 `.js` files**"]),
  });
  const options = seamOptions(dir);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["seam_census_drift"]);
  // The id names the inventory actually READ. It used to name the module's
  // default seam path, which under `--inventory` is a file that is not the
  // offending one — every sibling row violation already keys off this label.
  assert.notEqual(SEAM_INVENTORY_RELPATH, "seam.md");
  assert.equal(violations[0].id, "seam.md#filesWalked");
  assert.match(violations[0].detail, /^the census in seam\.md claims 9 for filesWalked/);
  assert.match(violations[0].detail, /this checker measured 2/);

  // INVERSION: the measured number clears it.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    seamDoc([ONE_EDGE_ROW], ["- the walk reads **2 `.js` files**"]),
    "utf8",
  );
  assert.deepEqual(runChecks(options).violations, []);
}));

test("an inventory row citing a file the tree does not hold fails, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "seam.md": seamDoc([ONE_EDGE_ROW, "| 2 | `lib/gone.js:2` -> `./domains/physical/physical-thing.js` |"]),
  });
  const options = seamOptions(dir);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["inventory_row_missing_file"]);
  assert.equal(violations[0].id, "seam.md row 2");
  assert.match(violations[0].detail, /cites lib\/gone\.js/);

  // INVERSION: with only the row the tree answers for, the doc is clean.
  fs.writeFileSync(path.join(dir, "seam.md"), seamDoc([ONE_EDGE_ROW]), "utf8");
  assert.deepEqual(runChecks(options).violations, []);
}));

test("an inventory row whose specifier resolves to no file fails, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    // OUTSIDE the walk root on purpose. The same require written inside it
    // would also fire the walk's own `unresolvable_require`, and a control that
    // fires two kinds pins neither.
    "outside/x.js": '"use strict";\nrequire("./nowhere.js");\n',
    "seam.md": seamDoc([ONE_EDGE_ROW, "| 2 | `outside/x.js:2` -> `./nowhere.js` |"]),
  });
  const options = seamOptions(dir);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["inventory_row_unresolvable_target"]);
  assert.equal(violations[0].id, "seam.md row 2");
  assert.match(violations[0].detail, /"\.\/nowhere\.js"/);

  // INVERSION: give the specifier a file. The row now resolves outside the walk
  // root and lands in the cross-package bucket instead of failing.
  writeFixture(dir, { "outside/nowhere.js": '"use strict";\nmodule.exports = {};\n' });
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.inventoryCrossPackage, 1);
}));

test("an inventory row importing into the walk root from outside it fails, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...ONE_EDGE,
    "outside/x.js": '"use strict";\nrequire("../lib/domains/physical/physical-thing.js");\n',
    "seam.md": seamDoc([ONE_EDGE_ROW, "| 2 | `outside/x.js:2` -> `../lib/domains/physical/physical-thing.js` |"]),
  });
  const options = seamOptions(dir);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["inventory_row_outside_walk_root"]);
  assert.equal(violations[0].id, "seam.md row 2");
  assert.match(violations[0].detail, /outside\/x\.js/);
  assert.match(violations[0].detail, /which the walk never classified/);

  // INVERSION: the same outside importer requiring a sibling that is also
  // outside is a cross-package row, not an unclassifiable one — the failure is
  // the edge pointing INTO a partition this gate never derived a layer for.
  writeFixture(dir, {
    "outside/sibling.js": '"use strict";\nmodule.exports = {};\n',
    "outside/x.js": '"use strict";\nrequire("./sibling.js");\n',
    "seam.md": seamDoc([ONE_EDGE_ROW, "| 2 | `outside/x.js:2` -> `./sibling.js` |"]),
  });
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.inventoryCrossPackage, 1);
}));

// The inventory and the allowlist are a bijection, so two rows for one edge is
// a failure even when both rows cite a real require: the walk keys per EDGE,
// and one edge cannot be adjudicated twice.
test("two inventory rows for one edge fail as a duplicate, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": ONE_EDGE["lib/domains/physical/physical-thing.js"],
    "lib/importer.js": '"use strict";\n'
      + 'const a = require("./domains/physical/physical-thing.js");\n'
      + 'const b = require("./domains/physical/physical-thing.js");\n'
      + "module.exports = { a, b };\n",
  });
  const secondRow = "| 2 | `lib/importer.js:3` -> `./domains/physical/physical-thing.js` |";
  fs.writeFileSync(path.join(dir, "seam.md"), seamDoc([ONE_EDGE_ROW, secondRow]), "utf8");
  const options = seamOptions(dir);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["duplicate_inventory_row"]);
  assert.equal(violations[0].id, "seam.md row 2");
  assert.match(violations[0].detail, new RegExp(`repeats the edge ${ONE_EDGE_KEY}`));

  // INVERSION: one row for the one edge, and the identity balances.
  fs.writeFileSync(path.join(dir, "seam.md"), seamDoc([ONE_EDGE_ROW]), "utf8");
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.inventoryPoliced, 1);
}));

// ADJUDICATED, because this branch is reachable only through a divergence the
// checker keeps on purpose. CommonJS reads `require("domains/physical/physical-thing.js")` as a
// package request, so the walk records no relative edge; the row reader
// resolves the same string against the citing file and polices an edge nothing
// walked. Aligning the two would bucket such a row as cross-package and pass
// it, which is the wrong direction — so the divergence stays and this branch is
// the only term that decides the outcome. An unbound gate, now bound.
test("an inventory row for an edge the walk did not find fails as an orphan, named", () => withTempDir((dir) => {
  writeFixture(dir, {
    "lib/domains/physical/physical-thing.js": ONE_EDGE["lib/domains/physical/physical-thing.js"],
    "lib/importer.js": '"use strict";\nrequire("domains/physical/physical-thing.js");\n',
    "seam.md": seamDoc(["| 1 | `lib/importer.js:2` -> `domains/physical/physical-thing.js` |"]),
  });
  const { violations, measured } = runChecks(seamOptions(dir, EMPTY));
  assert.deepEqual(kindsOf(violations), ["orphan_inventory_row"]);
  assert.equal(violations[0].id, ONE_EDGE_KEY);
  assert.match(violations[0].detail, /^seam\.md inventories the core -> plane edge/);
  // The measurement that names the divergence: the walk saw the site and read
  // it as leaving the tree, so it contributed no boundary edge for the row.
  assert.equal(measured.externalEdges, 1);
  assert.equal(measured.boundaryEdges.size, 0);

  // INVERSION: written relatively, the walk finds the same edge and the row is
  // no longer an orphan.
  writeFixture(dir, {
    "lib/importer.js": '"use strict";\nrequire("./domains/physical/physical-thing.js");\n',
    "seam.md": seamDoc([ONE_EDGE_ROW]),
  });
  assert.deepEqual(runChecks(seamOptions(dir)).violations, [], "the relative form clears the orphan");
}));

// ONE LAYER RULE, ONE DEFINITION SITE. The walk and the row reader ask the same
// question about a target's layer. When they asked it separately this fixture
// emitted `inventory_row_not_a_boundary_edge` AND `unrecorded_boundary_edge` at
// once, so a correctly-inventoried plane-named `.json` edge was unsatisfiable:
// no seam doc could clear both at the same time.
test("a plane-named in-root target the walk never classified is inventoriable", () => withTempDir((dir) => {
  const key = "importer.js -> domains/physical/physical-data.json";
  writeFixture(dir, {
    "lib/domains/physical/physical-data.json": "{}\n",
    "lib/importer.js": '"use strict";\nrequire("./domains/physical/physical-data.json");\n',
    "seam.md": seamDoc(["| 1 | `lib/importer.js:2` -> `./domains/physical/physical-data.json` |"]),
  });
  const { violations, measured } = runChecks(seamOptions(dir, new Map([[key, "plane_value_import"]])));
  assert.deepEqual(violations, [], JSON.stringify(violations, null, 2));
  assert.equal(measured.inventoryPoliced, 1);
  assert.equal(measured.inRootUnwalkedTargets.size, 0);

  // INVERSION: an ordinary-named in-root target has no derived layer at all, so
  // the same row is not a boundary edge — and the failure says exactly that
  // rather than claiming a core -> core edge it never derived.
  fs.rmSync(path.join(dir, "lib", "domains", "physical", "physical-data.json"));
  writeFixture(dir, {
    "lib/ordinary-data.json": "{}\n",
    "lib/importer.js": '"use strict";\nrequire("./ordinary-data.json");\n',
    "seam.md": seamDoc(["| 1 | `lib/importer.js:2` -> `./ordinary-data.json` |"]),
  });
  const inverted = runChecks(seamOptions(dir, EMPTY));
  assert.deepEqual(kindsOf(inverted.violations), ["inventory_row_not_a_boundary_edge"]);
  assert.match(inverted.violations[0].detail, /core -> a target with no derived layer/);
}));

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS: the rest of the doc is bound too. The inventory rows were
// re-read against the tree and the 78 citations around them were not, and that
// is exactly where the rot went — six Tool Split citations pointed at lines
// their symbol had moved off while the rows beside them stayed correct. Each
// control below plants one failure mode of one arm and inverts it, so the arm
// can be shown to be the DECIDING term rather than a conjunct riding on the
// inventory binding next to it.

// A tools tree with a composition root, two loadable tool modules, and one that
// throws on load. Deliberately carries NO plane-named module: these controls are
// about the citation binding, and a boundary edge in the fixture would make the
// allowlist the thing under test instead.
const TOOL_SPLIT_TREE = {
  "lib/tools/index.js": '"use strict";\n'
    + "const TOOL_MODULES = [\n"
    + '  require("./widget.js"),\n'
    + '  require("./gadget.js"),\n'
    + '  require("./broken-tool.js"),\n'
    + "];\n"
    + "module.exports = { TOOL_MODULES };\n",
  "lib/tools/widget.js": '"use strict";\nmodule.exports = {\n  name: "bob_widget",\n'
    + '  role_bundles: ["orchestrator"],\n};\n',
  "lib/tools/gadget.js": '"use strict";\nmodule.exports = {\n  name: "bob_gadget",\n'
    + '  role_bundles: ["orchestrator"],\n};\n',
  // Parses cleanly and throws when it RUNS, which is the whole point: a gate
  // that only parsed would certify this registration.
  "lib/tools/broken-tool.js": '"use strict";\nthrow new Error("this tool module does not load");\n',
};

// The Tool Split row for `bob_widget` as the tree really is: registered at
// index.js:3, role bundle declared at widget.js:4.
const WIDGET_ROW = "| `bob_widget` | `lib/tools/index.js:3` | `role_bundles` at `lib/tools/widget.js:4` |";
// Where `seamDoc([], [], [row])` puts that row.
const TOOL_SPLIT_DOC_LINE = 10;

function toolSplitDoc(rows) {
  return seamDoc([], [], rows);
}

test("a symbol-anchored citation naming the wrong line fails, naming the line that declares it", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...TOOL_SPLIT_TREE,
    // widget.js:3 declares `name`, not `role_bundles`.
    "seam.md": toolSplitDoc(["| `bob_widget` | `lib/tools/index.js:3` | `role_bundles` at `lib/tools/widget.js:3` |"]),
  });
  const options = seamOptions(dir, EMPTY);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["symbol_citation_drift"]);
  assert.equal(violations[0].id, `seam.md:${TOOL_SPLIT_DOC_LINE}`);
  assert.match(violations[0].detail, /cites role_bundles at lib\/tools\/widget\.js:3/);
  assert.match(violations[0].detail, /it is declared at line\(s\) 4/);

  // A citation of a file the tree does not hold is the same failure, said
  // differently — never a skip.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    toolSplitDoc(["| `bob_widget` | `lib/tools/index.js:3` | `role_bundles` at `lib/tools/gone.js:4` |"]),
    "utf8",
  );
  const missing = runChecks(options);
  assert.deepEqual(kindsOf(missing.violations), ["symbol_citation_drift"]);
  assert.match(missing.violations[0].detail, /lib\/tools\/gone\.js is not a file in this tree/);

  // INVERSION. The SAME citation at the line that really declares the name
  // passes — so this arm decides the outcome rather than riding on one of the
  // conjuncts beside it.
  fs.writeFileSync(path.join(dir, "seam.md"), toolSplitDoc([WIDGET_ROW]), "utf8");
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.symbolAnchoredCites, 1);
}));

test("a Tool Split registration that mints a different tool fails, naming both", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...TOOL_SPLIT_TREE,
    // index.js:4 requires ./gadget.js, which registers bob_gadget.
    "seam.md": toolSplitDoc(["| `bob_widget` | `lib/tools/index.js:4` | `role_bundles` at `lib/tools/widget.js:4` |"]),
  });
  const options = seamOptions(dir, EMPTY);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["tool_split_registration_drift"]);
  assert.equal(violations[0].id, `seam.md:${TOOL_SPLIT_DOC_LINE}`);
  assert.match(violations[0].detail, /registers bob_gadget/);

  // A line that holds no require at all, and a row whose Registration column
  // lost its citation: same kind, and neither is a skip.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    toolSplitDoc(["| `bob_widget` | `lib/tools/index.js:1` | `role_bundles` at `lib/tools/widget.js:4` |"]),
    "utf8",
  );
  assert.match(runChecks(options).violations[0].detail, /holds no static require/);
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    toolSplitDoc(["| `bob_widget` | see the registry | `role_bundles` at `lib/tools/widget.js:4` |"]),
    "utf8",
  );
  const unreadable = runChecks(options);
  assert.deepEqual(kindsOf(unreadable.violations), ["tool_split_registration_drift"]);
  assert.match(unreadable.violations[0].detail, /carries no `file:line` citation/);
  assert.equal(unreadable.measured.toolSplitTools, 1);
  assert.equal(unreadable.measured.toolSplitRegistrations, 0);

  // INVERSION: the registration that really does mint the tool passes, and the
  // split is derived — widget.js is core, so it counts on the core side.
  fs.writeFileSync(path.join(dir, "seam.md"), toolSplitDoc([WIDGET_ROW]), "utf8");
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.toolSplitRegistrations, 1);
  assert.equal(measured.toolSplitCoreTools, 1);
  assert.equal(measured.toolSplitPlaneTools, 0);
}));

// LOAD, DO NOT JUST PARSE. `node --check` passes on a module whose body throws,
// so a registration confirmed from a parse is a registration nobody ran.
test("a Tool Split registration whose module will not load fails rather than being skipped", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...TOOL_SPLIT_TREE,
    "seam.md": toolSplitDoc(["| `bob_widget` | `lib/tools/index.js:5` | `role_bundles` at `lib/tools/widget.js:4` |"]),
  });
  const options = seamOptions(dir, EMPTY);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["unloadable_tool_module"]);
  assert.match(violations[0].detail, /this tool module does not load/);
  assert.match(violations[0].detail, /cannot be confirmed against the live descriptor/);

  // INVERSION: pointed at a module that loads, the same row passes.
  fs.writeFileSync(path.join(dir, "seam.md"), toolSplitDoc([WIDGET_ROW]), "utf8");
  assert.deepEqual(runChecks(options).violations, []);
}));

// COMPLETENESS, which is the arm the node exists for: a citation no class
// carries is one nothing re-reads, and that is how six of them rotted.
test("a citation in no bound class fails, and the symbol-anchored form clears it", () => withTempDir((dir) => {
  const prose = "The bundle is declared at `lib/tools/widget.js:4`.";
  writeFixture(dir, {
    ...TOOL_SPLIT_TREE,
    "seam.md": `${toolSplitDoc([WIDGET_ROW])}\n${prose}\n`,
  });
  const options = seamOptions(dir, EMPTY);
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["unbound_seam_citation"]);
  assert.match(violations[0].id, /lib\/tools\/widget\.js:4$/);
  assert.match(violations[0].detail, /no bound class carries/);
  assert.match(violations[0].detail, /symbol-anchored form/);

  // INVERSION: the same fact written in the declared grammar binds — and binds
  // to the TREE, so writing it in the grammar at the wrong line still fails.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    `${toolSplitDoc([WIDGET_ROW])}\nThe bundle is \`role_bundles\` at \`lib/tools/widget.js:4\`.\n`,
    "utf8",
  );
  assert.deepEqual(runChecks(options).violations, []);
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    `${toolSplitDoc([WIDGET_ROW])}\nThe bundle is \`role_bundles\` at \`lib/tools/widget.js:2\`.\n`,
    "utf8",
  );
  assert.deepEqual(kindsOf(runChecks(options).violations), ["symbol_citation_drift"]);
}));

// The unbindable list only shrinks, exactly as the two allowlists do: an entry
// whose citation has left the doc is a permanent excuse for a citation nobody
// writes any more.
test("an unbindable-citation entry the doc no longer cites fails as stale", () => withTempDir((dir) => {
  writeFixture(dir, { ...TOOL_SPLIT_TREE, "seam.md": toolSplitDoc([WIDGET_ROW]) });
  const unbindable = new Map([["lib/tools/widget.js:1", "the pragma line, which declares no name"]]);
  const options = { ...seamOptions(dir, EMPTY), unbindableCitations: unbindable };
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["stale_unbindable_citation"]);
  assert.equal(violations[0].id, "lib/tools/widget.js:1");
  assert.match(violations[0].detail, /the pragma line, which declares no name/);
  assert.match(violations[0].detail, /only shrinks/);

  // INVERSION: with the citation present the entry carries it, and the census
  // counts it as unbindable rather than unbound.
  fs.writeFileSync(
    path.join(dir, "seam.md"),
    `${toolSplitDoc([WIDGET_ROW])}\nSee \`lib/tools/widget.js:1\`.\n`,
    "utf8",
  );
  const { violations: clean, measured } = runChecks(options);
  assert.deepEqual(clean, [], JSON.stringify(clean, null, 2));
  assert.equal(measured.unbindableCites, 1);
  assert.deepEqual([...measured.unbindableCitationSites], ["lib/tools/widget.js:1"]);
}));

test("the unbindable list is immutable, so it shrinks only via source edits", () => {
  assert.throws(() => UNBINDABLE_SEAM_CITATIONS.set("x", "y"), TypeError);
  assert.throws(() => UNBINDABLE_SEAM_CITATIONS.delete([...UNBINDABLE_SEAM_CITATIONS.keys()][0]), TypeError);
  assert.throws(() => UNBINDABLE_SEAM_CITATIONS.clear(), TypeError);
});

// An exemption only the checker knows about reads, to the doc's next editor, as
// coverage. So the argument for each one is in the doc, verbatim.
test("every unbindable citation's argument is written into the doc it exempts", () => {
  const doc = fs.readFileSync(path.join(REPO_ROOT, SEAM_INVENTORY_RELPATH), "utf8");
  assert.ok(UNBINDABLE_SEAM_CITATIONS.size > 0);
  for (const [site, reason] of UNBINDABLE_SEAM_CITATIONS) {
    assert.ok(doc.includes(reason), `${site}: the doc must carry its exemption argument verbatim`);
    assert.ok(doc.includes(`\`${site}\``), `${site}: the doc must still cite it, or the entry is stale`);
  }
});

// THE LIVE DOC, against the live tree. Reverting one of the corrected Tool Split
// citations must turn the real gate red and say where the symbol really is —
// this is the property the whole binding was added for, so it is planted on the
// real inputs rather than on a fixture.
test("reverting a corrected Tool Split citation turns the gate red on the real doc", () => withTempDir((dir) => {
  const real = fs.readFileSync(path.join(REPO_ROOT, SEAM_INVENTORY_RELPATH), "utf8");
  const corrected = "`required_session_axes` at `mcp/tools/physical/record-physical-candidate-claim.js:312`";
  const rotted = "`required_session_axes` at `mcp/tools/physical/record-physical-candidate-claim.js:311`";
  assert.ok(real.includes(corrected), "the corrected citation must be in the doc to be reverted");
  const inventory = path.join(dir, "seam.md");
  // The frozen list belongs to THIS doc, so it travels with the copy of it.
  const options = { root: REPO_ROOT, inventory, unbindableCitations: UNBINDABLE_SEAM_CITATIONS };

  fs.writeFileSync(inventory, real.replace(corrected, rotted), "utf8");
  const { violations } = runChecks(options);
  assert.deepEqual(kindsOf(violations), ["symbol_citation_drift"]);
  assert.match(violations[0].detail, /record-physical-candidate-claim\.js:311/);
  assert.match(violations[0].detail, /it is declared at line\(s\) 312/);

  // INVERSION: the doc as it stands is clean against the same tree.
  fs.writeFileSync(inventory, real, "utf8");
  assert.deepEqual(runChecks(options).violations, [], "the doc as written must bind");
}));

// A census pattern that stops matching is a number that stops being checked,
// and it fails SILENTLY inside the gate because an absent bullet is not an
// error there — a fixture doc has no census. The real doc must match every one.
test("every census pattern still finds its number in the seam doc", () => {
  const doc = fs.readFileSync(path.join(REPO_ROOT, SEAM_INVENTORY_RELPATH), "utf8");
  const { measured } = runChecks({ root: REPO_ROOT });
  assert.ok(SEAM_CENSUS_PATTERNS.length > 5, "the census binds more than the original five bullets");
  for (const { key, re } of SEAM_CENSUS_PATTERNS) {
    const hit = doc.match(re);
    assert.ok(hit, `the census pattern for ${key} matches nothing in the doc, so ${key} is unchecked`);
    assert.equal(Number(hit[1]), Number(measured[key]), `${key} is claimed ${hit[1]} and measured ${measured[key]}`);
  }
});

// EVERY CLAIM THE NOTE PRINTS IS UNDER TEST. The citation census is a claim
// about how much of the doc is bound, so it is reconciled here: the classes sum
// to the total, and the exclusions it names are the ones it really excludes.
test("the coverage note's citation census adds up to the citations it read", () => {
  const { measured } = runChecks({ root: REPO_ROOT });
  assert.equal(
    measured.inventoryRowCites + measured.toolSplitRegistrations + measured.symbolAnchoredCites
      + measured.echoedCites + measured.unbindableCites,
    measured.seamCitations,
    "every citation must land in exactly one class",
  );
  assert.equal(measured.inventoryRowCites, measured.inventoryRows);
  assert.equal(measured.toolSplitRegistrations, measured.toolSplitTools);
  assert.equal(measured.toolSplitPlaneTools + measured.toolSplitCoreTools, measured.toolSplitTools);
  assert.equal(measured.unbindableCitationSites.size, UNBINDABLE_SEAM_CITATIONS.size);

  const note = coverageNote(measured);
  assert.match(note, new RegExp(`seam citations: ${measured.seamCitations} cite\\(s\\) = `));
  assert.match(note, new RegExp(`${measured.symbolAnchoredCites} symbol-anchored`));
  for (const site of measured.unbindableCitationSites) assert.ok(note.includes(site));
  // The two classes the gate does NOT bind are NAMED, not implied.
  assert.match(note, /a tool is SHARED only if a non-physical plane's behavior changes when it is absent/);
  assert.match(note, /Reverse Direction section's numbers/);
  assert.match(note, new RegExp(`Only that section's ${measured.reverseDirectionRows}-row table is bound`));
});

// ---------------------------------------------------------------------------
// RULE THREE — the extracted smart-contracts directory.
//
// The move is admissible only because the directory lets the gate DERIVE two
// things the flat listing could only assert: a set of modules nothing outside
// imports, and a dependency class re-checked against the walk. Both are pinned
// here, each with a control that inverts.

const SC = SMART_CONTRACTS_DIR;
// From a file at lib/${SC}/ up to the walk root (lib/): one `../` per SC segment,
// so the fixtures track SMART_CONTRACTS_DIR's depth instead of hard-coding it.
const SC_TO_LIB = "../".repeat(SC.split(path.sep).length);

// A minimal module tree with the same shape as the real one: a public member, an
// internal member, a tool importer, a non-tool importer, and a shared module
// outside the directory.
const SC_FIXTURE = {
  [`lib/${SC}/pub.js`]: '"use strict";\nrequire("./inner.js");\nmodule.exports = {};\n',
  [`lib/${SC}/inner.js`]: '"use strict";\nmodule.exports = {};\n',
  "lib/tools/t.js": `"use strict";\nrequire("../${SC}/pub.js");\nmodule.exports = {};\n`,
  "lib/shared.js": '"use strict";\nmodule.exports = {};\n',
};

function scOptions(dir, over = {}) {
  return {
    ...NO_SEAM,
    root: dir,
    walk: "lib",
    smartContractsMembers: new Set(["pub.js", "inner.js"]),
    smartContractsInternals: new Set(["inner.js"]),
    smartContractsAllowedDependencies: new Map(),
    smartContractsEntrypointExceptions: new Map(),
    ...over,
  };
}

// (a) GATE A, the half with NO exception list: outside the directory reaching an
// internal fails outright, and the only way to clear it is to stop calling the
// target internal.
test("a module outside the directory reaching an internal fails, and no allowlist can excuse it",
  () => withTempDir((dir) => {
    writeFixture(dir, {
      ...SC_FIXTURE,
      "lib/outside.js": `"use strict";\nrequire("./${SC}/inner.js");\nmodule.exports = {};\n`,
    });

    const { violations } = runChecks(scOptions(dir));
    assert.deepEqual(kindsOf(violations), ["smart_contracts_internal_reached_from_outside"]);
    assert.equal(violations[0].id, `outside.js -> ${SC}/inner.js`);
    assert.match(violations[0].detail, /outside\.js:2/);
    assert.match(violations[0].detail, new RegExp(`${SC}/inner\\.js`));

    // INVERSION: the ONLY clearance is promoting the target to the public
    // surface — and then it needs a recorded entry point, because the importer
    // is not a tool module. Both halves are asserted, so "clears" cannot mean
    // "fails differently".
    const promoted = scOptions(dir, { smartContractsInternals: new Set() });
    assert.deepEqual(kindsOf(runChecks(promoted).violations), ["smart_contracts_entrypoint_edge_unrecorded"]);
    assert.deepEqual(
      runChecks({
        ...promoted,
        smartContractsEntrypointExceptions: new Map([[`outside.js -> ${SC}/inner.js`, "argued"]]),
      }).violations,
      [],
    );
  }));

// (b) GATE A's derived arm, with a POSITIVE control beside the negative one: the
// SAME edge passes from tools/ and fails from anywhere else. Without the
// positive half the derived arm would be an assertion nobody watched decide.
test("a public member is reachable from tools/ and from nowhere else unrecorded", () => withTempDir((dir) => {
  writeFixture(dir, SC_FIXTURE);
  // POSITIVE: tools/t.js -> smart-contracts/pub.js, derived, no entry needed.
  const clean = runChecks(scOptions(dir));
  assert.deepEqual(clean.violations, []);
  assert.deepEqual([...clean.measured.smartContractsToolsEdges], [`tools/t.js -> ${SC}/pub.js`]);
  assert.equal(clean.measured.smartContractsEntrypointCount, 0);

  // NEGATIVE: the identical edge written from a non-tool module.
  writeFixture(dir, { "lib/outside.js": `"use strict";\nrequire("./${SC}/pub.js");\nmodule.exports = {};\n` });
  const { violations, measured } = runChecks(scOptions(dir));
  assert.deepEqual(kindsOf(violations), ["smart_contracts_entrypoint_edge_unrecorded"]);
  assert.equal(violations[0].id, `outside.js -> ${SC}/pub.js`);
  assert.equal(measured.smartContractsEntrypointCount, 1);

  // INVERSION: recording the entry point clears it.
  assert.deepEqual(
    runChecks(scOptions(dir, {
      smartContractsEntrypointExceptions: new Map([[`outside.js -> ${SC}/pub.js`, "argued"]]),
    })).violations,
    [],
  );
}));

// (c) GATE B: a member acquiring a dependency the boundary does not allow.
test("a member requiring a module off the allowed list fails, and recording it clears", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...SC_FIXTURE,
    [`lib/${SC}/pub.js`]: `"use strict";\nrequire("./inner.js");\nrequire("${SC_TO_LIB}shared.js");\nmodule.exports = {};\n`,
  });

  const { violations, measured } = runChecks(scOptions(dir));
  assert.deepEqual(kindsOf(violations), ["smart_contracts_dependency_not_allowed"]);
  assert.equal(violations[0].id, `${SC}/pub.js -> shared.js`);
  assert.match(violations[0].detail, new RegExp(`${SC}/pub\\.js:3`));
  assert.deepEqual([...measured.smartContractsDependencyTargets], ["shared.js"]);

  // INVERSION: the recorded dependency clears, and the member -> member edge in
  // the same file never needed recording.
  const recorded = runChecks(scOptions(dir, {
    smartContractsAllowedDependencies: new Map([["shared.js", "shared_vocabulary"]]),
  }));
  assert.deepEqual(recorded.violations, []);
  assert.equal(recorded.measured.smartContractsDependencyClasses.get("shared_vocabulary"), 1);
}));

// (d) EVERY LIST ONLY SHRINKS. One kind, one id naming the list and the entry,
// so an entry that has stopped naming anything cannot sit as a permanent excuse.
test("a smart-contracts entry that names nothing in the tree fails as stale", () => withTempDir((dir) => {
  writeFixture(dir, SC_FIXTURE);

  const internals = runChecks(scOptions(dir, {
    smartContractsInternals: new Set(["inner.js", "gone.js"]),
  }));
  assert.deepEqual(kindsOf(internals.violations), ["stale_smart_contracts_entry"]);
  assert.equal(internals.violations[0].id, "SMART_CONTRACTS_INTERNALS gone.js");

  const dependencies = runChecks(scOptions(dir, {
    smartContractsAllowedDependencies: new Map([["shared.js", "shared_vocabulary"]]),
  }));
  assert.deepEqual(kindsOf(dependencies.violations), ["stale_smart_contracts_entry"]);
  assert.equal(dependencies.violations[0].id, "SMART_CONTRACTS_ALLOWED_DEPENDENCIES shared.js");

  const entrypoints = runChecks(scOptions(dir, {
    smartContractsEntrypointExceptions: new Map([[`outside.js -> ${SC}/pub.js`, "argued"]]),
  }));
  assert.deepEqual(kindsOf(entrypoints.violations), ["stale_smart_contracts_entry"]);
  assert.equal(entrypoints.violations[0].id, `SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS outside.js -> ${SC}/pub.js`);

  // INVERSION: with no stale entries the same tree is clean.
  assert.deepEqual(runChecks(scOptions(dir)).violations, []);
}));

// (e) THE MODULE CANNOT PASS BY BEING EMPTY. Membership for the walk is derived
// from the directory, which is exactly why a derived-only membership would go
// green on a directory somebody deleted. The frozen names are the backstop.
test("a frozen member with no file on disk fails rather than vacuously passing", () => withTempDir((dir) => {
  writeFixture(dir, SC_FIXTURE);
  const { violations } = runChecks(scOptions(dir, {
    smartContractsMembers: new Set(["pub.js", "inner.js", "deleted.js"]),
  }));
  assert.deepEqual(kindsOf(violations), ["smart_contracts_member_missing"]);
  assert.equal(violations[0].id, "deleted.js");
  assert.match(violations[0].detail, /pass by being empty/);

  // INVERSION: the membership as measured is clean.
  assert.deepEqual(runChecks(scOptions(dir)).violations, []);
}));

// (f) THE ONE DERIVED CLASS. `exclusively_used_here` is a claim about the walk,
// so the walk decides it: a non-member importer of the same target refutes it.
test("exclusively_used_here is re-derived from the walk, not pasted on", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...SC_FIXTURE,
    [`lib/${SC}/pub.js`]: `"use strict";\nrequire("./inner.js");\nrequire("${SC_TO_LIB}shared.js");\nmodule.exports = {};\n`,
  });
  const allowed = new Map([["shared.js", "exclusively_used_here"]]);

  // Every in-root importer of shared.js is a member: the class holds.
  const derived = runChecks(scOptions(dir, { smartContractsAllowedDependencies: allowed }));
  assert.deepEqual(derived.violations, []);
  assert.equal(derived.measured.smartContractsDependencyClasses.get("exclusively_used_here"), 1);

  // One non-member importer, and it does not.
  writeFixture(dir, { "lib/outside.js": '"use strict";\nrequire("./shared.js");\nmodule.exports = {};\n' });
  const { violations } = runChecks(scOptions(dir, { smartContractsAllowedDependencies: allowed }));
  assert.deepEqual(kindsOf(violations), ["misclassified_smart_contracts_dependency"]);
  assert.equal(violations[0].id, "shared.js");
  assert.match(violations[0].detail, /1 importer\(s\) outside/);
  assert.match(violations[0].detail, /outside\.js/);
}));

// The same kind, from the two other arms that can produce it: a class outside
// the frozen vocabulary, and a target the walk reads no importers of — which
// would otherwise let `exclusively_used_here` pass on nothing at all.
test("a dependency class outside the vocabulary, or one the walk cannot derive, fails", () => withTempDir((dir) => {
  writeFixture(dir, {
    ...SC_FIXTURE,
    [`lib/${SC}/pub.js`]: `"use strict";\nrequire("./inner.js");\nrequire("${SC_TO_LIB}shared.js");\nmodule.exports = {};\n`,
  });
  const unknown = runChecks(scOptions(dir, {
    smartContractsAllowedDependencies: new Map([["shared.js", "seems_fine"]]),
  }));
  assert.deepEqual(kindsOf(unknown.violations), ["misclassified_smart_contracts_dependency"]);
  assert.match(unknown.violations[0].detail, new RegExp(SMART_CONTRACTS_DEPENDENCY_CLASSES.join(", ")));

  // A dependency OUTSIDE the walk root: the walk reads no importers there, so
  // the derived class cannot be claimed over it.
  writeFixture(dir, {
    "outer.js": '"use strict";\nmodule.exports = {};\n',
    [`lib/${SC}/pub.js`]: `"use strict";\nrequire("./inner.js");\nrequire("${SC_TO_LIB}../outer.js");\nmodule.exports = {};\n`,
  });
  const outside = runChecks(scOptions(dir, {
    smartContractsAllowedDependencies: new Map([["outer.js", "exclusively_used_here"]]),
  }));
  assert.deepEqual(kindsOf(outside.violations), ["misclassified_smart_contracts_dependency"]);
  assert.match(outside.violations[0].detail, /pass vacuously/);

  // INVERSION: the same out-of-root dependency under a class the walk CAN carry.
  assert.deepEqual(
    runChecks(scOptions(dir, {
      smartContractsAllowedDependencies: new Map([["outer.js", "shared_vocabulary"]]),
    })).violations,
    [],
  );
}));

// CENSUS HONESTY, live tree. Each frozen list must be exactly what the walk
// measures — and the INTERNALS set is re-derived independently of itself: a
// member is internal iff no inbound edge names it, and inbound edges are
// recorded before the internals test ever runs.
test("every frozen smart-contracts list is exactly the measurement", () => {
  const { measured } = runChecks({ root: REPO_ROOT });

  assert.deepEqual([...measured.smartContractsOnDisk].sort(), [...SMART_CONTRACTS_MEMBERS].sort());

  const reached = new Set(
    [...measured.smartContractsInboundEdges].map((key) => path.basename(key.split(" -> ")[1])),
  );
  const derivedInternals = [...measured.smartContractsOnDisk].filter((name) => !reached.has(name)).sort();
  assert.deepEqual(derivedInternals, [...SMART_CONTRACTS_INTERNALS].sort());

  assert.deepEqual(
    [...measured.smartContractsDependencyTargets].sort(),
    [...SMART_CONTRACTS_ALLOWED_DEPENDENCIES.keys()].sort(),
  );

  const unrecordedEntryPoints = [...measured.smartContractsInboundEdges]
    .filter((key) => !measured.smartContractsToolsEdges.has(key))
    .sort();
  assert.deepEqual(unrecordedEntryPoints, [...SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS.keys()].sort());

  // THE ADMISSION TEST, as a standing assertion rather than a paragraph: the
  // move is filing the moment the exception lists approach the edge counts they
  // police. Today they are 0 of 28 inbound and 3 of 28.
  assert.equal(SMART_CONTRACTS_INTERNALS.size > 0, true, "an empty internals set states no boundary at all");
  assert.equal(
    SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS.size * 4 < measured.smartContractsInboundEdges.size, true,
    "the entry-point exceptions have grown toward the edge set they police: the boundary is becoming the "
      + "old graph rewritten",
  );
});

test("the smart-contracts lists are immutable at runtime, so they shrink only via source edits", () => {
  assert.throws(() => SMART_CONTRACTS_MEMBERS.add("x.js"), TypeError);
  assert.throws(() => SMART_CONTRACTS_MEMBERS.clear(), TypeError);
  assert.throws(() => SMART_CONTRACTS_INTERNALS.add("x.js"), TypeError);
  assert.throws(() => SMART_CONTRACTS_INTERNALS.delete("sc-http-client.js"), TypeError);
  assert.throws(() => SMART_CONTRACTS_ALLOWED_DEPENDENCIES.set("x.js", "shared_vocabulary"), TypeError);
  assert.throws(() => SMART_CONTRACTS_ALLOWED_DEPENDENCIES.clear(), TypeError);
  assert.throws(() => SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS.set("a -> b", "why"), TypeError);
  assert.throws(() => SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS.clear(), TypeError);
});

// THE EXISTING SC DISPATCH SEAM, hardened without being duplicated. The one
// dispatch registry is ROUTED_SC_RUNNERS inside the container-exec seam, and the
// boundary's contribution is that nothing outside the directory may reach it —
// so every SC run still has to arrive through a runner.
test("the container-exec seam is internal, so no second dispatch registry can grow beside it", () => {
  assert.equal(SMART_CONTRACTS_INTERNALS.has("sc-container-exec.js"), true);
  const { measured } = runChecks({ root: REPO_ROOT });
  const reaching = [...measured.smartContractsInboundEdges]
    .filter((key) => key.endsWith(`${SC}/sc-container-exec.js`));
  assert.deepEqual(reaching, [], "something outside the directory now reaches the container-exec seam");
});

// EVERY FIGURE THE NOTE PRINTS FOR THIS RULE IS DERIVED AND UNDER TEST, beside
// the seam-citation census that already works this way.
test("the coverage note's smart-contracts census is the measurement", () => {
  const { measured } = runChecks({ root: REPO_ROOT });
  const note = coverageNote(measured);

  assert.equal(measured.smartContractsPublicCount + measured.smartContractsInternalCount,
    measured.smartContractsMemberCount, "every member is public or internal, and not both");
  assert.equal(
    measured.smartContractsToolsEdgeCount + measured.smartContractsEntrypointCount,
    measured.smartContractsInboundEdges.size,
    "every inbound edge is tools-derived or a recorded entry point",
  );
  assert.equal(
    SMART_CONTRACTS_DEPENDENCY_CLASSES.reduce((sum, name) => sum + measured.smartContractsDependencyClasses.get(name), 0),
    measured.smartContractsDependencyCount,
    "every allowed dependency carries exactly one class",
  );

  assert.match(note, new RegExp(`${SC}/: ${measured.smartContractsMemberCount} member\\(s\\) `));
  assert.match(note, new RegExp(
    `\\(${measured.smartContractsPublicCount} public, ${measured.smartContractsInternalCount} internal `
    + "with NO exception list\\)",
  ));
  assert.match(note, new RegExp(
    `${measured.smartContractsDependencyCount} allowed dependenc\\(ies\\) over `
    + `${measured.smartContractsDependencyEdges.size} outbound edge\\(s\\)`,
  ));
  assert.match(note, new RegExp(
    `${measured.smartContractsInboundEdges.size} inbound edge\\(s\\) = `
    + `${measured.smartContractsToolsEdgeCount} derived from tools/ \\+ `
    + `${measured.smartContractsEntrypointCount} recorded entry point\\(s\\)`,
  ));
  for (const name of SMART_CONTRACTS_DEPENDENCY_CLASSES) {
    assert.ok(note.includes(`${measured.smartContractsDependencyClasses.get(name)} ${name}`),
      `the note must carry the ${name} count`);
  }
  // The exclusion this rule inherits, NAMED rather than implied.
  assert.match(note, /INTERNAL here means internal to the runtime graph, not unreachable from a test/);
});

// ---------------------------------------------------------------------------
// THE CENSUS. "This suite covers the checker's violation kinds" is a claim
// about the code like any other, so it is derived rather than declared: an AST
// walk of the checker's own source for `violations.push({ kind })`, reconciled
// against the kinds the controls above actually fired. A hand-count is what
// produced the wrong number this block replaces — it read 22 kinds where the
// parse reads 23, because an own-line enumeration cannot see the one push that
// is written on a single line.

function violationKindsPushedBy(sourcePath) {
  const label = path.relative(REPO_ROOT, sourcePath);
  const ast = parseJsSource(fs.readFileSync(sourcePath, "utf8"), label);
  const kinds = new Set();
  let sites = 0;
  walk(ast.program, (node) => {
    if (node.type !== "CallExpression") return;
    const callee = node.callee;
    if (!callee || callee.type !== "MemberExpression" || callee.computed) return;
    if (!callee.property || callee.property.type !== "Identifier" || callee.property.name !== "push") return;
    if (!callee.object || callee.object.type !== "Identifier" || callee.object.name !== "violations") return;
    sites += 1;
    const where = `${label}:${node.loc ? node.loc.start.line : 0}`;
    const argument = node.arguments[0];
    assert.equal(
      argument && argument.type === "ObjectExpression", true,
      `the violations.push at ${where} must push an object literal the census can read`,
    );
    const kindProperty = argument.properties.find((property) => property.type === "ObjectProperty"
      && !property.computed && property.key && property.key.type === "Identifier"
      && property.key.name === "kind");
    assert.equal(
      Boolean(kindProperty) && kindProperty.value.type === "StringLiteral", true,
      `the violations.push at ${where} must carry a literal kind the census can read`,
    );
    kinds.add(kindProperty.value.value);
  });
  return { kinds, sites };
}

// The whole checker, not just the file that happens to hold the entry point:
// unions the AST census over every source in CHECKER_SOURCES so a kind pushed
// from a rule module is read from its real push site, not a hand-kept mirror.
function violationKindsAcrossChecker() {
  const kinds = new Set();
  let sites = 0;
  for (const source of CHECKER_SOURCES) {
    const one = violationKindsPushedBy(source);
    for (const kind of one.kinds) kinds.add(kind);
    sites += one.sites;
  }
  return { kinds, sites };
}

// Kinds this suite cannot fire, each keyed to the argument for why. EMPTY, and
// that is a measurement rather than an aspiration: every kind the checker
// pushes is reachable from a module tree and a seam doc a caller can write.
const UNREACHABLE_VIOLATION_KINDS = new Map();

test("every violation the checker pushes carries a kind the census can read", () => {
  const { kinds, sites } = violationKindsAcrossChecker();
  assert.ok(kinds.size > 0, "the census read no violation kinds at all");
  // A push site is not a kind: one kind is pushed from two arms.
  assert.ok(sites >= kinds.size);
  for (const kind of UNREACHABLE_VIOLATION_KINDS.keys()) {
    assert.equal(kinds.has(kind), true, `${kind} is annotated unreachable but the checker no longer pushes it`);
  }
});

// Runs after every control above, so FIRED_KINDS is this suite's real reach.
// A kind the checker can push and nobody plants is an assertion nobody has ever
// watched decide anything, and it fails here rather than passing in silence.
after(() => {
  const { kinds } = violationKindsAcrossChecker();
  const uncovered = [...kinds]
    .filter((kind) => !FIRED_KINDS.has(kind) && !UNREACHABLE_VIOLATION_KINDS.has(kind))
    .sort();
  assert.deepEqual(
    uncovered, [],
    `these violation kinds have no control that fires them: ${uncovered.join(", ")}. `
      + "Plant the condition, or add the kind to UNREACHABLE_VIOLATION_KINDS with the argument.",
  );
  const gone = [...FIRED_KINDS].filter((kind) => !kinds.has(kind)).sort();
  assert.deepEqual(gone, [], `these kinds fired but the checker no longer pushes them: ${gone.join(", ")}`);
});

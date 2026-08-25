"use strict";

const fs = require("fs");
const path = require("path");
const {
  JS_PARSE_ERROR_CODE,
  REQUIRE_CALLEE_FORMS,
  collectStaticRequires,
  parseJsSource,
  staticPropertyName,
  walk,
} = require("../js-source-facts.js");

const TOOLS_DIR = "tools";
// Object.freeze on a Set does NOT block Set.prototype.add/delete (freezing only
// affects own properties, not internal [[SetData]]). Harden mutators to throw so
// an allowlist is genuinely immutable — it only shrinks via source edits.
// Same shape as ALLOWLIST_UNDOCUMENTED in mcp/core/invariant-registry.js.
function frozenSet(name, values) {
  const s = new Set(values);
  const block = () => { throw new TypeError(`${name} is immutable`); };
  s.add = block;
  s.delete = block;
  s.clear = block;
  return Object.freeze(s);
}

// Same hardening for a Map, and for the same reason: Object.freeze does not
// touch [[MapData]], so set/delete/clear have to be blocked by hand.
function frozenMap(name, entries) {
  const m = new Map(entries);
  const block = () => { throw new TypeError(`${name} is immutable`); };
  m.set = block;
  m.delete = block;
  m.clear = block;
  return Object.freeze(m);
}

module.exports.TOOLS_DIR = TOOLS_DIR;
module.exports.frozenMap = frozenMap;
module.exports.frozenSet = frozenSet;

const {
  BOUNDARY_ADJUDICATION_CLASSES,
  planeMemberOf,
  planeMemberOfAxis,
} = require("./rule-one-core-plane.js");

// The seam audit this gate binds the tree to. One definition site.
const SEAM_INVENTORY_RELPATH = path.join("docs", "architecture", "physical-severance-seam.md");
// Citations in the seam audit that no bound class can carry, each with the
// argument for why. Same shape and same rule as ALLOWLIST_UNDOCUMENTED in
// mcp/core/invariant-registry.js: frozen, only-shrinking, and an entry the doc
// has stopped citing FAILS as stale rather than sitting as a permanent excuse.
// Keyed `path:line` exactly as the doc writes it, so every occurrence of the
// same citation is covered by the one argument.
//
// Each reason below is also written into the doc verbatim, because an exemption
// only the checker knows about reads to a doc's next editor as coverage.
const UNBINDABLE_SEAM_CITATIONS = frozenMap("UNBINDABLE_SEAM_CITATIONS", [
  [
    "mcp/core/session/session-authority.js:121",
    "an element inside an array literal, which declares no name for a symbol-anchored citation to bind to",
  ],
]);
// One inventory row of the seam audit: `| n | `file:line` -> `specifier` | ...`.
// A line that opens like a numbered row but does not carry an edge is malformed
// rather than absent — the caller names it instead of skipping it.
const SEAM_ROW_PREFIX_RE = /^\|\s*\d+\s*\|/;
const SEAM_ROW_RE = /^\|\s*(\d+)\s*\|\s*`([^`]+):(\d+)`\s*->\s*`([^`]+)`\s*\|/;

// THE CITATION GRAMMAR of the seam audit. One definition site each, exported so
// the doc's own "what is bound" section, this gate, and its suite all read the
// same forms rather than three drifting approximations of them.
//
// Written WITHOUT the global flag on purpose: a `/g` regex carries `lastIndex`,
// and a shared one is mutable state a second scan would resume in the middle of.
// Every scan below takes a fresh global copy through `globalOf`.
//
//   SEAM_CITATION_RE         a citation at all: `` `<path>:<line>` ``.
//   SEAM_SYMBOL_CITATION_RE  the bindable form: `` `<name>` at `<path>:<line>` ``.
//   TOOL_SPLIT_ROW_*         a Tool Split row, which is `` `bob_*` `` in column 1
//                            and its registration citation in column 2.
//   REVERSE_DIRECTION_ROW_RE a Reverse Direction row, whose first cell is a bare
//                            `mcp` path with no line. Only its COUNT is bound.
const SEAM_CITATION_RE = /`([^`\s]+\.(?:js|json|cjs|mjs)):(\d+)`/;
const SEAM_SYMBOL_CITATION_RE = /`([A-Za-z_$][A-Za-z0-9_$]*)` at `([^`\s]+\.(?:js|json|cjs|mjs)):(\d+)`/;
const TOOL_SPLIT_ROW_PREFIX_RE = /^\|\s*`(bob_[a-z0-9_]+)`\s*\|/;
const TOOL_SPLIT_ROW_RE = /^\|\s*`(bob_[a-z0-9_]+)`\s*\|\s*`([^`\s]+):(\d+)`\s*\|/;
const REVERSE_DIRECTION_ROW_RE = /^\|\s*`(mcp\/(?:core|domains|tools|fuzz)\/[^`\s]+\.js)`\s*\|/;

function globalOf(re) {
  return new RegExp(re.source, "g");
}

// The doc's lines with fenced code blocks BLANKED — emptied in place, so a line
// number is still a line number. A fence holds command text and bare
// `mcp/*.js` paths; reading it as prose would invent citations nobody wrote.
function proseLines(markdown) {
  let fenced = false;
  return markdown.split("\n").map((text) => {
    if (/^\s*```/.test(text)) { fenced = !fenced; return ""; }
    return fenced ? "" : text;
  });
}

// Every NAME a source DECLARES, by the line it is declared on — the TREE side of
// a symbol-anchored citation, derived from a parse and never from text.
// Memoized by absolute path for the same reason `readSites` is: the doc cites
// physical-technique-tool.js seven times and it is read once.
//
// Four declaring shapes, which is the set this doc cites: an object property key
// (`required_session_axes: [...]`, and the same node inside a destructuring
// pattern), a variable declarator, a function declaration, and a class
// declaration. `SYNTHETIC_AXIS_REGISTRY` is a `const`, not a property, so the
// declarator arm is not optional. A citation of anything else — an element
// inside an array literal, say — has no name to bind and belongs in
// UNBINDABLE_SEAM_CITATIONS with its reason.
function declaredNamesByLine(absolutePath, label, cache) {
  if (cache.has(absolutePath)) return cache.get(absolutePath);
  const ast = parseJsSource(fs.readFileSync(absolutePath, "utf8"), label);
  const byLine = new Map();
  const add = (node, name) => {
    if (name === null || !node || !node.loc) return;
    const line = node.loc.start.line;
    if (!byLine.has(line)) byLine.set(line, new Set());
    byLine.get(line).add(name);
  };
  walk(ast.program, (node) => {
    if (node.type === "ObjectProperty") {
      add(node.key, staticPropertyName(node.key, node.computed));
      return;
    }
    if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier") {
      add(node.id, node.id.name);
      return;
    }
    if ((node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") && node.id) {
      add(node.id, node.id.name);
    }
  });
  cache.set(absolutePath, byLine);
  return byLine;
}

// The tool names a LOADED module registers. Same absorb shape as
// `declaredSessionAxes`, and for the same reason: the fact this gate needs is
// what the runtime registers, not what a file looks like.
function declaredToolNames(loaded) {
  const names = new Set();
  const absorb = (value) => {
    if (value && typeof value === "object" && typeof value.name === "string") names.add(value.name);
  };
  absorb(loaded);
  if (loaded && typeof loaded === "object") for (const value of Object.values(loaded)) absorb(value);
  return names;
}

// The PROSE census above the inventory table. The numbered rows were bound to the
// tree; these bullets were not, and they drifted on the very next commit — the doc
// claimed 2822 require sites after one was deleted. Same rule as the rows: a number
// the doc credits to this checker is re-derived here, never trusted. An absent
// bullet is not an error (a fixture doc has no census); a wrong one is.
const SEAM_CENSUS_PATTERNS = Object.freeze([
  { key: "filesWalked", re: /\*\*(\d+) `\.js` files\*\*/ },
  { key: "coreModules", re: /\*\*(\d+) core, \d+ plane\*\*/ },
  { key: "planeModules", re: /\*\*\d+ core, (\d+) plane\*\*/ },
  { key: "edgesWalked", re: /\*\*(\d+) `require\(\)` call sites\*\*/ },
  { key: "crossWalkRootEdges", re: /- \*\*(\d+)\*\* edges leave/ },
  // The rest of the doc's numbers, bound for the same reason the five above
  // were: each was already IN `measured` and the doc was simply trusted to have
  // copied it right. Nothing here transcribes a constant — every row names a
  // key the walk fills in.
  { key: "boundaryEdgeCount", re: /- \*\*(\d+)\*\* of those edges run core -> plane/ },
  { key: "boundaryImporters", re: /from \*\*(\d+) distinct core files\*\*/ },
  { key: "computedSpecifierSites", re: /- \*\*(\d+)\*\* call sites? have a computed specifier/ },
  { key: "corePlanePackageEdgeCount", re: /\*\*(\d+)\*\* of them run from core into a plane-named package/ },
  // The reconciliation identity, one key per term.
  { key: "inventoryRows", re: /(\d+) inventoried rows = \d+ policed/ },
  { key: "inventoryPoliced", re: /= (\d+) policed core -> plane/ },
  { key: "inventoryCrossPackage", re: /\+ (\d+) cross-package/ },
  { key: "inventoryPlaneToPlane", re: /\+ (\d+) plane -> plane/ },
  // The adjudication histogram, derived from the vocabulary rather than listed,
  // so a fifth class cannot be added to the gate and left unbound in the doc.
  ...BOUNDARY_ADJUDICATION_CLASSES.map((name) => ({
    key: `adjudication_${name}`,
    re: new RegExp(`\\| \`${name}\` \\| (\\d+) \\|`),
  })),
  // The Tool Split totals. Both are derived from the walk's layer partition
  // applied to what each row's registration actually loads, so the doc cannot
  // move a tool between the two tables without the count following it.
  { key: "toolSplitPlaneTools", re: /Physical-only tools: (\d+)/ },
  { key: "toolSplitCoreTools", re: /Shared tools that must remain core-visible: (\d+)/ },
  // Bound to its own table's row count and to nothing else — see the coverage
  // note, which says so rather than letting the number read as measured.
  { key: "reverseDirectionRows", re: /\*\*(\d+)\*\* physical files touch a `paths` or lock-shaped dependency/ },
]);

// The inventory being reconciled is whichever one was READ — the default seam
// audit on the live tree, an override under `--inventory`. Naming the module
// constant here instead named a file that is not the offending one whenever the
// two differ, which is exactly the fixture case the negative control runs. Every
// sibling inventory violation is keyed off the same measured label.
function reconcileSeamCensus(markdown, measured, violations) {
  for (const { key, re } of SEAM_CENSUS_PATTERNS) {
    const hit = markdown.match(re);
    if (!hit) continue;
    const claimed = Number(hit[1]);
    const actual = Number(measured[key]);
    if (!Number.isFinite(actual) || claimed === actual) continue;
    violations.push({
      kind: "seam_census_drift",
      id: `${measured.inventoryPath}#${key}`,
      detail:
        `the census in ${measured.inventoryPath} claims ${claimed} for ${key}; this checker measured `
        + `${actual}. A number the doc credits to this gate must come out of this gate.`,
    });
  }
}

function parseSeamInventoryRows(markdown) {
  const rows = [];
  const malformed = [];
  const lines = markdown.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    if (!SEAM_ROW_PREFIX_RE.test(lines[i])) continue;
    const match = SEAM_ROW_RE.exec(lines[i]);
    if (!match) { malformed.push({ docLine: i + 1, text: lines[i].trim() }); continue; }
    rows.push({
      row: Number(match[1]),
      importer: match[2],
      line: Number(match[3]),
      specifier: match[4],
      docLine: i + 1,
    });
  }
  return { rows, malformed };
}

function listJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const absolute = path.join(dir, entry.name);
    // The runtime walk owns Bob's source modules, not installed dependencies.
    // This matters now that the canonical walk root is mcp/ rather than the old
    // child tier: mcp/node_modules is deliberately preserved by the installer.
    if (entry.isDirectory() && entry.name !== "node_modules") out.push(...listJsFiles(absolute));
    else if (entry.isFile() && entry.name.endsWith(".js")) out.push(absolute);
  }
  return out;
}

// Literal axis declarations in a source that cannot load. This is a fail-closed
// fallback, not the primary signal: moving a tool can break its relative loads
// before the live descriptor is available, and treating that absence as "no
// physical axis" would make the exact drift this arm exists to catch silent.
// Only literal string elements of a literal `required_session_axes` array are
// admitted; any wider expression contributes nothing rather than being guessed.
function staticallyDeclaredSessionAxes(absolutePath) {
  const axes = new Set();
  let ast;
  try {
    ast = parseJsSource(fs.readFileSync(absolutePath, "utf8"), absolutePath);
  } catch {
    return axes;
  }
  walk(ast.program, (node) => {
    if (node.type !== "ObjectProperty"
        || staticPropertyName(node.key, node.computed) !== "required_session_axes"
        || !node.value || node.value.type !== "ArrayExpression") return;
    for (const element of node.value.elements) {
      if (element && element.type === "StringLiteral") axes.add(element.value);
    }
  });
  return axes;
}

// The plane axes a tool module declares, read from the LIVE export so the gate
// cannot drift away from what the runtime registers. If the module will not
// load, use the narrow parsed fallback above so a path move cannot erase the
// consistency signal by breaking resolution first.
function declaredSessionAxes(absolutePath) {
  let loaded;
  try {
    loaded = require(absolutePath);
  } catch {
    return staticallyDeclaredSessionAxes(absolutePath);
  }
  const axes = new Set();
  const absorb = (value) => {
    if (value && typeof value === "object" && Array.isArray(value.required_session_axes)) {
      for (const axis of value.required_session_axes) axes.add(axis);
    }
  };
  absorb(loaded);
  if (loaded && typeof loaded === "object") for (const value of Object.values(loaded)) absorb(value);
  return axes;
}
// core | plane, for a module inside the walk root. Two-way and total: there is
// no third bucket to fail closed into, so the fail-closed obligation lives on
// the things that genuinely cannot be read — parses and specifiers — rather
// than on a fabricated "unknown layer" that no input can produce.
function classifyModule(absolutePath, walkRoot, planeAxis = null) {
  const member = planeAxis === null
    ? planeMemberOf(walkRoot, absolutePath)
    : planeMemberOfAxis(walkRoot, absolutePath, planeAxis);
  return member === null ? "core" : "plane";
}

// The layer of a require TARGET that lives inside the walk root, or undefined
// when this gate never derived one. ONE definition site, because the walk and
// the seam-inventory reconciliation both need the answer and they used to
// compute it separately — the walk applied a different fallback below and the
// inventory arm read `layerOf` alone, so a correctly-inventoried physical-path
// `.json` edge was simultaneously "not a boundary edge" (the row) and "an edge
// with no row" (the walk), and no seam doc could clear both.
//
// The fallback: the file listing is `.js` and CommonJS resolution is not, so
// `./x.json`, `./x.cjs`, and `./x.mjs` resolve to a real in-root file the walk
// never classified. Directory position applies to every extension, so a target
// under a domains/physical/ directory is still plane. Anything elsewhere has no
// derived layer, and undefined is that answer — no caller may assert one.
function targetLayerInsideWalkRoot(target, layerOf, walkRoot, planeAxis = null) {
  const walked = layerOf.get(target);
  if (walked !== undefined) return walked;
  const member = planeAxis === null
    ? planeMemberOf(walkRoot, target)
    : planeMemberOfAxis(walkRoot, target, planeAxis);
  return member === null ? undefined : "plane";
}

// The file a relative specifier denotes, or null when nothing on disk answers
// to it. CommonJS resolution order, restricted to the forms this tree uses.
function resolveRelative(fromFile, specifier) {
  const base = path.resolve(path.dirname(fromFile), specifier);
  for (const candidate of [base, `${base}.js`, path.join(base, "index.js")]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function isInside(dir, candidate) {
  const relative = path.relative(dir, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

// Static require sites of one source, memoized by absolute path so the seam
// inventory re-reads the walk's parse instead of parsing the same file twice.
// Throws the tagged parse error; every caller fails closed on it by name.
function readSites(absolutePath, label, cache) {
  if (cache.has(absolutePath)) return cache.get(absolutePath);
  const sites = collectStaticRequires(fs.readFileSync(absolutePath, "utf8"), label);
  cache.set(absolutePath, sites);
  return sites;
}

// Bind every `file:line` CITATION in the seam audit, not only the ones inside an
// inventory row. Three arms read the tree, and a fourth classifies what is left:
// a citation in no bound class is a violation, so the doc cannot grow a
// decorative cite that nobody re-reads. The classification is the answer to why
// six Tool Split citations rotted while the rows beside them did not.
function bindSeamCitations({
  root, walkRoot, markdown, label, rows, layerOf, planeAxis = null, siteCache, unbindableCitations, violations, measured,
}) {
  const lines = proseLines(markdown);
  const nameCache = new Map();
  // A citation OCCURRENCE, keyed by where it is written as well as what it says:
  // the same site cited twice on two lines is two occurrences, and each has to
  // land in a class of its own.
  const covered = new Set();
  const occurrence = (docLine, site) => `${docLine} ${site}`;

  // (a) INVENTORY ROWS. Already re-read against the tree above; recorded here so
  // the completeness arm can tell a row's own citation from a loose one, and so
  // an ECHO of a row elsewhere in the doc inherits that row's re-read.
  const echoes = new Set();
  for (const row of rows) {
    covered.add(occurrence(row.docLine, `${row.importer}:${row.line}`));
    echoes.add(`${row.importer}:${row.line}`);
  }
  measured.inventoryRowCites = rows.length;

  // (b) TOOL SPLIT REGISTRATIONS. The only binding available for the seven
  // shared-tool rows, which no inventory row covers, and strictly stronger than
  // the row echo for the twelve physical ones: the cited line must hold a static
  // require whose module LOADS and whose descriptor names the tool in column 1.
  for (let i = 0; i < lines.length; i += 1) {
    if (!TOOL_SPLIT_ROW_PREFIX_RE.test(lines[i])) continue;
    const docLine = i + 1;
    measured.toolSplitTools += 1;
    const match = TOOL_SPLIT_ROW_RE.exec(lines[i]);
    const tool = TOOL_SPLIT_ROW_PREFIX_RE.exec(lines[i])[1];
    const id = `${label}:${docLine}`;
    if (!match) {
      violations.push({
        kind: "tool_split_registration_drift",
        id,
        detail: `${id} is the Tool Split row for ${tool} but its Registration column carries no `
          + `\`file:line\` citation, so the registration cannot be re-read`,
      });
      continue;
    }
    const [, , citedPath, citedLine] = match;
    const line = Number(citedLine);
    measured.toolSplitRegistrations += 1;
    covered.add(occurrence(docLine, `${citedPath}:${line}`));
    const absolute = path.join(root, citedPath);
    if (!fs.existsSync(absolute)) {
      violations.push({
        kind: "tool_split_registration_drift",
        id,
        detail: `${id} registers ${tool} at ${citedPath}:${line}, but ${citedPath} is not a file in this tree`,
      });
      continue;
    }
    let sites;
    try {
      sites = readSites(absolute, citedPath, siteCache);
    } catch (err) {
      if (!err || err.code !== JS_PARSE_ERROR_CODE) throw err;
      violations.push({
        kind: "unparseable_module",
        id: citedPath,
        detail: `${citedPath} cannot be parsed, so the registration cited at ${id} cannot be `
          + `checked: ${err.parse_message}`,
      });
      continue;
    }
    const site = sites.find((candidate) => candidate.line === line
      && candidate.callee_form === REQUIRE_CALLEE_FORMS.REQUIRE
      && typeof candidate.specifier === "string");
    if (!site) {
      violations.push({
        kind: "tool_split_registration_drift",
        id,
        detail: `${id} registers ${tool} at ${citedPath}:${line}, but that line holds no static require`,
      });
      continue;
    }
    const target = resolveRelative(absolute, site.specifier);
    if (target === null) {
      violations.push({
        kind: "tool_split_registration_drift",
        id,
        detail: `${id} registers ${tool} at ${citedPath}:${line}, which requires `
          + `${JSON.stringify(site.specifier)} and resolves to no file`,
      });
      continue;
    }
    // FAIL CLOSED on the load, unlike the classification arm, which treats an
    // unloadable module as contributing no axis. Here the load IS the check:
    // a tool identity read from a module that did not run is not read at all.
    let loaded;
    try {
      loaded = require(target);
    } catch (err) {
      violations.push({
        kind: "unloadable_tool_module",
        id,
        detail: `${id} registers ${tool} through ${path.relative(root, target)}, which will not load, so the `
          + `registration cannot be confirmed against the live descriptor: ${err && err.message ? err.message : err}`,
      });
      continue;
    }
    const registered = declaredToolNames(loaded);
    if (!registered.has(tool)) {
      violations.push({
        kind: "tool_split_registration_drift",
        id,
        detail: `${id} says ${citedPath}:${line} registers ${tool}, but ${path.relative(root, target)} `
          + `registers ${registered.size ? [...registered].sort().join(", ") : "no named tool"}`,
      });
      continue;
    }
    // The split itself, derived: which table a row belongs in is the layer of
    // what it registers, not a column heading.
    const layer = isInside(walkRoot, target)
      ? targetLayerInsideWalkRoot(target, layerOf, walkRoot, planeAxis)
      : undefined;
    if (layer === "plane") measured.toolSplitPlaneTools += 1;
    else if (layer === "core") measured.toolSplitCoreTools += 1;
  }

  // (c) SYMBOL-ANCHORED CITATIONS. The declared grammar for citing a symbol, and
  // the arm that catches the rot: the cited line must DECLARE the cited name.
  const symbolRe = globalOf(SEAM_SYMBOL_CITATION_RE);
  for (let i = 0; i < lines.length; i += 1) {
    symbolRe.lastIndex = 0;
    let hit;
    while ((hit = symbolRe.exec(lines[i])) !== null) {
      const docLine = i + 1;
      const [, name, citedPath, citedLine] = hit;
      const line = Number(citedLine);
      const id = `${label}:${docLine}`;
      measured.symbolAnchoredCites += 1;
      covered.add(occurrence(docLine, `${citedPath}:${line}`));
      const absolute = path.join(root, citedPath);
      if (!fs.existsSync(absolute)) {
        violations.push({
          kind: "symbol_citation_drift",
          id,
          detail: `${id} cites ${name} at ${citedPath}:${line}, but ${citedPath} is not a file in this tree`,
        });
        continue;
      }
      let names;
      try {
        names = declaredNamesByLine(absolute, citedPath, nameCache);
      } catch (err) {
        if (!err || err.code !== JS_PARSE_ERROR_CODE) throw err;
        violations.push({
          kind: "unparseable_module",
          id: citedPath,
          detail: `${citedPath} cannot be parsed, so the citation at ${id} cannot be checked: ${err.parse_message}`,
        });
        continue;
      }
      const here = names.get(line);
      if (here && here.has(name)) continue;
      const elsewhere = [...names.entries()]
        .filter(([, declared]) => declared.has(name))
        .map(([declaredLine]) => declaredLine)
        .sort((a, b) => a - b);
      violations.push({
        kind: "symbol_citation_drift",
        id,
        detail: `${id} cites ${name} at ${citedPath}:${line}, but that line declares no such name`
          + (elsewhere.length ? ` — it is declared at line(s) ${elsewhere.join(", ")}` : ""),
      });
    }
  }

  // The Reverse Direction table, counted and nothing more. Its numbers come from
  // a reverse walk this gate does not perform, so the only claim it can hold
  // honest is that the section's own row count matches the number beside it.
  for (const text of lines) {
    if (REVERSE_DIRECTION_ROW_RE.test(text)) measured.reverseDirectionRows += 1;
  }

  // (d) COMPLETENESS. Every citation in the doc, classified. This is the arm
  // that answers the question: a citation carried by no class above and echoing
  // no inventoried site is one nothing re-reads, and that is how six of them
  // came to point at the wrong line.
  const seen = new Set();
  const citationRe = globalOf(SEAM_CITATION_RE);
  for (let i = 0; i < lines.length; i += 1) {
    citationRe.lastIndex = 0;
    let hit;
    while ((hit = citationRe.exec(lines[i])) !== null) {
      const docLine = i + 1;
      const site = `${hit[1]}:${Number(hit[2])}`;
      measured.seamCitations += 1;
      if (covered.has(occurrence(docLine, site))) continue;
      if (echoes.has(site)) { measured.echoedCites += 1; continue; }
      if (unbindableCitations.has(site)) {
        measured.unbindableCites += 1;
        measured.unbindableCitationSites.add(site);
        seen.add(site);
        continue;
      }
      violations.push({
        kind: "unbound_seam_citation",
        id: `${label}:${docLine} ${site}`,
        detail: `${label}:${docLine} cites ${site}, which no bound class carries: it is not an inventory row, `
          + `not a Tool Split registration, not an echo of an inventoried site, and not written in the `
          + `symbol-anchored form \`<name>\` at \`${site}\`. Write it in that form so this gate re-reads it, `
          + `or record it in UNBINDABLE_SEAM_CITATIONS with the reason it cannot be bound`,
      });
    }
  }
  for (const [site, reason] of unbindableCitations) {
    if (seen.has(site)) continue;
    violations.push({
      kind: "stale_unbindable_citation",
      id: site,
      detail: `UNBINDABLE_SEAM_CITATIONS records ${site} as unbindable (${reason}), but ${label} no longer `
        + `cites it; the list only shrinks, so drop the entry`,
    });
  }
}

// Bind the seam audit's inventory to the tree. Every row's cited site is re-read
// through the same parser the walk uses, every row is bucketed by what the walk
// says its endpoints ARE, and the buckets are reconciled against the measured
// edge set in both directions. A row without an edge and an edge without a row
// are both failures, because either one is the doc and the tree disagreeing.
function reconcileSeamInventory({
  root, walkRoot, inventory, layerOf, planeAxis = null, siteCache, unbindableCitations, violations, measured,
}) {
  const inventoryPath = path.isAbsolute(inventory) ? inventory : path.join(root, inventory);
  const label = path.relative(root, inventoryPath) || inventory;
  measured.inventoryPath = label;
  if (!fs.existsSync(inventoryPath)) {
    violations.push({
      kind: "missing_seam_inventory",
      id: label,
      detail: `${label} does not exist, so the allowlist has no inventory to reconcile against; `
        + `pass --no-inventory to audit a tree that has no seam audit`,
    });
    return;
  }

  const inventoryMarkdown = fs.readFileSync(inventoryPath, "utf8");
  const { rows, malformed } = parseSeamInventoryRows(inventoryMarkdown);
  for (const bad of malformed) {
    violations.push({
      kind: "unparseable_inventory_row",
      id: `${label}:${bad.docLine}`,
      detail: `${label}:${bad.docLine} opens as a numbered inventory row but carries no `
        + `\`file:line\` -> \`specifier\` edge: ${bad.text}`,
    });
  }
  measured.inventoryRows = rows.length;

  const policed = new Set();
  for (const row of rows) {
    const id = `${label} row ${row.row}`;
    const absoluteImporter = path.join(root, row.importer);
    if (!fs.existsSync(absoluteImporter)) {
      violations.push({
        kind: "inventory_row_missing_file",
        id,
        detail: `${id} cites ${row.importer}, which is not a file in this tree`,
      });
      continue;
    }
    let sites;
    try {
      sites = readSites(absoluteImporter, row.importer, siteCache);
    } catch (err) {
      if (!err || err.code !== JS_PARSE_ERROR_CODE) throw err;
      violations.push({
        kind: "unparseable_module",
        id: row.importer,
        detail: `${row.importer} cannot be parsed, so ${id} cannot be checked: ${err.parse_message}`,
      });
      continue;
    }
    if (!sites.some((site) => site.line === row.line && site.specifier === row.specifier)) {
      const elsewhere = sites.filter((site) => site.specifier === row.specifier).map((site) => site.line);
      violations.push({
        kind: "inventory_line_drift",
        id,
        detail: `${id} cites ${row.importer}:${row.line} requiring ${JSON.stringify(row.specifier)}, but that `
          + `line holds no such require`
          + (elsewhere.length ? ` — it is required at line(s) ${elsewhere.join(", ")}` : ""),
      });
      continue;
    }
    const target = resolveRelative(absoluteImporter, row.specifier);
    if (target === null) {
      violations.push({
        kind: "inventory_row_unresolvable_target",
        id,
        detail: `${id} requires ${JSON.stringify(row.specifier)}, which resolves to no file`,
      });
      continue;
    }
    if (!isInside(walkRoot, target)) { measured.inventoryCrossPackage += 1; continue; }
    const importerLayer = layerOf.get(absoluteImporter);
    if (importerLayer === undefined) {
      violations.push({
        kind: "inventory_row_outside_walk_root",
        id,
        detail: `${id} imports into ${measured.walkRoot} from ${row.importer}, which the walk never `
          + `classified, so this gate cannot say which layer the edge leaves`,
      });
      continue;
    }
    if (importerLayer !== "core") { measured.inventoryPlaneToPlane += 1; continue; }
    const targetLayer = targetLayerInsideWalkRoot(target, layerOf, walkRoot, planeAxis);
    if (targetLayer !== "plane") {
      violations.push({
        kind: "inventory_row_not_a_boundary_edge",
        id,
        detail: `${id} runs core -> ${targetLayer || "a target with no derived layer"} `
          + `(${row.importer} -> ${path.relative(walkRoot, target)}); the seam `
          + `inventory records boundary edges, and this is not one`,
      });
      continue;
    }
    const key = `${path.relative(walkRoot, absoluteImporter)} -> ${path.relative(walkRoot, target)}`;
    if (policed.has(key)) {
      violations.push({
        kind: "duplicate_inventory_row",
        id,
        detail: `${id} repeats the edge ${key}, which another row already records; the inventory and the `
          + `allowlist must be a bijection`,
      });
      continue;
    }
    policed.add(key);
  }
  measured.inventoryPoliced = policed.size;

  // ORPHAN ROWS, and the one divergence that reaches them. Both arms above run
  // the row through the same parse and the same target resolution, so a row that
  // gets this far names a site the walk also saw — with ONE exception, which is
  // deliberate and is what makes this branch a bound gate rather than a
  // redundant conjunct. The walk drops a specifier that does not start with `.`
  // as external, because in CommonJS `require("physical-thing.js")` is a package
  // request; the row reader resolves the same string against the citing file. So
  // a row written in the bare form is policed here while the walk records no
  // edge, and this branch is the only term that decides it.
  //
  // The divergence is KEPT rather than aligned. Aligning would mean the row
  // reader also treats a bare specifier as leaving the tree, which buckets it as
  // cross-package and passes — a row inventorying an edge that does not exist
  // would go green. Failing loudly here is the safe direction, and the branch
  // stays as the backstop for the bijection's other half.
  for (const key of policed) {
    if (!measured.boundaryEdges.has(key)) {
      violations.push({
        kind: "orphan_inventory_row",
        id: key,
        detail: `${label} inventories the core -> plane edge ${key}, which the walk did not find`,
      });
    }
  }
  for (const key of measured.boundaryEdges) {
    if (!policed.has(key)) {
      violations.push({
        kind: "unrecorded_boundary_edge",
        id: key,
        detail: `the core -> plane edge ${key} has no row in ${label}; an edge nobody adjudicated in the `
          + `seam audit is an edge the verdict does not cover`,
      });
    }
  }

  bindSeamCitations({
    root, walkRoot, markdown: inventoryMarkdown, label, rows, layerOf, planeAxis, siteCache,
    unbindableCitations, violations, measured,
  });
  // LAST, not first. Every number the census reconciles is one this run
  // measured, and the citation and Tool Split counts above are the newest of
  // them — reconciling before they were taken compared the doc against zero.
  reconcileSeamCensus(inventoryMarkdown, measured, violations);
}

Object.assign(module.exports, {
  REVERSE_DIRECTION_ROW_RE,
  SEAM_CENSUS_PATTERNS,
  SEAM_CITATION_RE,
  SEAM_INVENTORY_RELPATH,
  SEAM_ROW_PREFIX_RE,
  SEAM_ROW_RE,
  SEAM_SYMBOL_CITATION_RE,
  TOOL_SPLIT_ROW_PREFIX_RE,
  TOOL_SPLIT_ROW_RE,
  TOOLS_DIR,
  UNBINDABLE_SEAM_CITATIONS,
  bindSeamCitations,
  classifyModule,
  declaredNamesByLine,
  declaredSessionAxes,
  declaredToolNames,
  frozenMap,
  frozenSet,
  globalOf,
  isInside,
  listJsFiles,
  parseSeamInventoryRows,
  proseLines,
  readSites,
  reconcileSeamCensus,
  reconcileSeamInventory,
  resolveRelative,
  staticallyDeclaredSessionAxes,
  targetLayerInsideWalkRoot,
});

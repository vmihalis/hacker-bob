# Install Ownership Map

**Status:** survey only. This node changes no behaviour. It establishes, with
`path:line`, the set of files a Bob install WRITES INTO A TARGET — and therefore
the set a Bob update can destroy.

Every `path:line` below was re-derived from the tree on branch
`bob-install-drift-guard` in round 2 and machine-checked: each citation was
resolved against the file it names and the anchored line's text read back.
Round 1's call-site line numbers were exact but its parenthetical constant-list
citations had drifted (adversarial review found 14; re-greping surfaced a 15th,
generic-mcp's `copyPromptDocs` call site). All are corrected here. Nothing below
is cited from memory. Reproduce any count with the commands in §4.

**Reading rule for negatives.** Every "X does not exist" claim in this document
is paired with a positive control in the same command, so a zero-hit result can
be distinguished from a mistyped path or a moved file. A bare zero-hit grep is
not evidence and is not used as evidence here.

---

## 0. The correction that matters most

The working assumption going into this node was: *`copyDirFiles` lives in
`scripts/lib/install-fs.js`, has three call sites, and one chokepoint therefore
covers every adapter.*

That is **false**, and a drift guard built on it would miss the largest surface
in the product.

There are **two independent, unrelated implementations** of the copy helpers:

| Family | `copyFile` | `copyDirFiles` | `copyDirRecursive` | `copyTree` | Consumed by |
| --- | --- | --- | --- | --- | --- |
| **A — raw installer FS** | `scripts/install.js:264` | `scripts/install.js:291` | `scripts/install.js:270` | *(none)* | neutral installer **+ the Claude adapter** |
| **B — safe install FS** | `scripts/lib/install-fs.js:201` | `scripts/lib/install-fs.js:213` | `scripts/lib/install-fs.js:227` | `scripts/lib/install-fs.js:250` | codex, kimi, generic-mcp |

Only three modules `require` `install-fs.js`, and the Claude adapter is not one
of them. The grep returns **four** lines; the fourth is a comment in a release
check, not a require:

```
$ grep -rn "install-fs" scripts adapters mcp
scripts/release-check.js:237:  // (adapters/kimi/*, scripts/lib/kimi-role-renderer.js, scripts/lib/install-fs.js,
adapters/codex/index.js:10:const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
adapters/generic-mcp/index.js:5:const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
adapters/kimi/index.js:11:const { createSafeInstallFs } = require("../../scripts/lib/install-fs.js");
```

That absence is corroborated **positively**, not only by the missing line:
`scripts/install.js:2002-2018` special-cases `adapterId === "claude"` and hands
the adapter its filesystem helpers as call arguments —
`copyDirFiles` (`:2006`), `copyFile` (`:2007`), `readJsonIfExists` (`:2013`),
`removeIfExists` (`:2014`), `writeJson` (`:2017`). The Claude adapter
destructures exactly those names in its `install({...})` signature at
`adapters/claude/index.js:454-469`. Those injected helpers are the **Family A**
ones defined in `scripts/install.js`.

So `adapters/claude/index.js:487` (agents) and `adapters/claude/index.js:525`
(rules) run `scripts/install.js:291` → `scripts/install.js:264` →
`fs.copyFileSync` at `scripts/install.js:266`. They never touch `install-fs.js`.

**Implication for the drift guard: two chokepoints are required, not one.**
Guarding only `scripts/lib/install-fs.js` would leave `.claude/rules/*.md`,
`.claude/agents/*.md`, `.claude/hooks/*`, `.claude/skills/*/SKILL.md`,
`.hacker-bob/bypass-tables/*.txt` and `.hacker-bob/knowledge/*.json` completely
unprotected — which is to say, it would leave unprotected exactly the file that
bit (`.claude/agents/report-writer.md`).

Both families copy unconditionally. Neither reads the destination first:

```
$ grep -cE "sha256|createHash|backup|preserve" scripts/lib/install-fs.js ; echo "neg_exit=$?"
0
neg_exit=1
$ grep -cE "function copyFile|function writeFileAtomic" scripts/lib/install-fs.js ; echo "pos_exit=$?"
2
pos_exit=0
```

The positive control proves the file was read and the pattern engine works; the
zero is therefore a real absence, not a bad path.

### What the installer *does* digest, precisely

`scripts/install.js` has **four** `createHash` sites. Round 1 said two, in the
deletion branch; that was wrong. The accurate breakdown:

| Site | Function | What it hashes | Gates a write? |
| --- | --- | --- | --- |
| `scripts/install.js:182` | `sha256File` (`:181-183`), called only from `buildMcpTopLevelRuntimeOwnership` `:191` (itself invoked `:1879`) | the **source** `mcp/*.js` at receipt-build time | no — builds the receipt |
| `scripts/install.js:249` | `pruneRetiredMcpTopLevelRuntimeFiles` (`:226-262`) | the **installed** retired file | gates a **delete** (`:253`), never a write |
| `scripts/install.js:514` | runtime-dependency manifest preflight | source manifest bytes | no |
| `scripts/install.js:1274` | `copyStableRuntimeDependencyFile` (`:1238`) | the **source** bytes as they stream | aborts the copy at `:1303` and removes the partial destination at `:1324` on mismatch |

So the true, provable claim — and the one the guard is built against — is:

> **No write in the installer is gated on the DESTINATION having been locally
> modified.** `:1303` is a source-integrity check (did the source change under
> us mid-copy?), and its failure mode is *abort and delete the partial*, not
> *preserve the operator's file*. `:249` is the only destination digest compare
> in the tree, and it authorizes a delete rather than blocking an overwrite.

---

## 1. What `mcp_top_level_runtime_ownership` actually guarantees

Written into `<target>/.hacker-bob/install.json` at `scripts/install.js:177`,
under `schema_version: 2` (`NEUTRAL_INSTALL_SCHEMA_VERSION`,
`scripts/install.js:43`).

- Built by `buildMcpTopLevelRuntimeOwnership`, `scripts/install.js:185-194`
  (invoked `:1879`). For each name in `MCP_TOP_LEVEL_RUNTIME_FILES` it records
  `{ name, byte_size, sha256 }`.
- `MCP_TOP_LEVEL_RUNTIME_FILES` is `scripts/lib/package-policy.js:31-36` and
  contains exactly **four** names: `server.js`, `auto-signup.js`,
  `redaction.js`, `browser-driver.js`.
- Validated on read by `normalizeMcpTopLevelRuntimeOwnership`,
  `scripts/install.js:196-224`.
- Consumed by exactly one caller: `pruneRetiredMcpTopLevelRuntimeFiles`,
  `scripts/install.js:226-262`, invoked at `scripts/install.js:1899`.

### It guarantees

One thing only: Bob will not **delete** a top-level `mcp/*.js` file it shipped in
a previous release but no longer ships, unless the installed file still has the
exact `byte_size` (`scripts/install.js:248`), `sha256` (`:249-250`), and
filesystem identity (`dev`/`ino`, `:251-252`) recorded on the preceding install.
An operator who edited a now-retired runtime file keeps their edit.

### It does NOT guarantee

- **It never gates a write.** `scripts/install.js:1903-1905` copies all four
  current runtime files over the top of whatever is there, unconditionally. The
  receipt holds `browser-driver.js`'s digest and the installer does not consult
  it before overwriting (see the table in §0). Local edits to a *current*
  runtime file are destroyed silently; only edits to a *retired* one survive.
- **Scope is four filenames at the top level of `mcp/`.** Basename-only
  (`scripts/install.js:213`), must match `/^[A-Za-z0-9._-]+\.js$/u`
  (`MCP_TOP_LEVEL_RUNTIME_NAME_PATTERN`, `scripts/install.js:46`, tested `:212`),
  max 128 entries (`scripts/install.js:205`), max 16 MiB each
  (`MAX_MCP_TOP_LEVEL_RUNTIME_FILE_BYTES`, `scripts/install.js:45`, tested `:216`).
- **Nothing else in the target has any ownership record at all.** Not
  `.claude/`, `.kimi/`, `.codex/`, `.agents/`, `.hacker-bob/`, `mcp/lib/`,
  `mcp/node_modules/`, `packages/`, `testing/policy-replay/`, `$CODEX_HOME`, or
  `$KIMI_SHARE_DIR`.
- **The per-adapter receipts carry no ownership data.**
  `.claude/bob/install.json` (`adapters/claude/index.js:574-582`) and
  `.kimi/bob/install.json` (`adapters/kimi/index.js:318-326`) are both
  `schema_version: 1` and record only version/target/provenance.
- **On any mismatch the receipt is discarded and no prune happens.** If
  `schema_version !== 2` or `install_target !== targetAbs`,
  `normalizeMcpTopLevelRuntimeOwnership` returns `[]` (`scripts/install.js:196-199`;
  same for a malformed receipt at `:205` or a malformed entry at `:219`). This is
  **fail-closed with respect to destruction** — nothing extra becomes deletable.
  It grants no write protection either, because there never was any.

Net: `mcp_top_level_runtime_ownership` protects **4 filenames against deletion**.
It protects **zero files against overwrite**. The drift guard cannot be built on
top of it; it is a delete-authorization receipt, not an ownership ledger.

### Two in-tree precedents — they are different properties, do not conflate them

| Precedent | `path:line` | Property demonstrated |
| --- | --- | --- |
| `copyResourceSet` empty-copy refusal | `scripts/install.js:315-317` — `if (copied.length === 0) throw new Error(resourceSet.emptyMessage);` | **non-vacuity**: a copy that moved zero files is an error, not a silent success. Both `RESOURCE_SETS` entries carry an `emptyMessage` (`:60-77`; bypassTables `:61-68`, knowledge `:69-76`). This is the shape invariant 6 asks for — reuse it. |
| `ensureEgressProfilesConfig` | `mcp/lib/egress-profiles.js:208-227` — reads first (`:211-214` / `:222`), writes only when absent | **preserve-on-exist**: an operator file already on disk is never overwritten. |

**The live asymmetry an implementer must close.** `copyResourceSet` is the only
`copyDirFiles` caller with a non-vacuity floor. The two Claude call sites have
none:

- `adapters/claude/index.js:487` — `const agents = copyDirFiles(...)`; return
  value consumed only as a report count at `:585`.
- `adapters/claude/index.js:525` — `const rules = copyDirFiles(...)`; return
  value consumed only as a report count at `:587`.

Both return `[]` when the source directory is empty and the install still
**succeeds**. A guard fixture whose source `.claude/rules/` has zero files makes
every "operator edit preserved / drift detected" assertion pass vacuously. §4
floors the source collections for exactly this reason.

---

## 2. Helper inventory

### `scripts/lib/install-fs.js` — Family B (safe FS: codex, kimi, generic-mcp)

All defined inside the `createSafeInstallFs` factory (`:32`), returned at
`:323-342`, module export at `:345-347`.

| Helper | Line | Destroys existing content? |
| --- | --- | --- |
| `mkdirp` | `:80` | no |
| `writeFileAtomic` | `:162` | yes — temp + `rename(2)` over the target |
| `writeTextFile` | `:193` | yes (delegates to `writeFileAtomic`) |
| `writeJson` | `:197` | yes (delegates to `writeTextFile`) |
| `copyFile` | `:201` | **yes — unconditional, no destination digest, no backup** |
| `copyDirFiles` | `:213` | yes, per file, non-recursive |
| `copyDirRecursive` | `:227` | yes, per file, recursive, skips `node_modules` (`:235`) |
| `copyTree` | `:250` | yes, per file, recursive, no skip list |
| `removePath` | `:271` | **yes — `fs.rmSync`** |
| `removeDirContents` | `:280` | **yes — every entry under the dir** |
| `removeEmptyDirIfExists` | `:295` | only if empty |

`copyDirFiles`, `copyDirRecursive` and `copyTree` all funnel through `copyFile`
(`:221`, `:244`, `:262`), which delegates to `writeFileAtomic` at `:207`.
**One patch at `:201` covers all four** for this family.

### `scripts/install.js` — Family A (raw FS: neutral installer + Claude adapter)

| Helper | Line | Destroys existing content? |
| --- | --- | --- |
| `writeJson` | `:97-100` | yes — `fs.writeFileSync` `:99` |
| `copyFile` | `:264-268` | **yes — `fs.copyFileSync` `:266`, unconditional** |
| `copyDirRecursive` | `:270-289` | yes, recursive, skips `node_modules` (`:278`) |
| `copyDirFiles` | `:291-303` | yes, non-recursive |
| `removeEmptyDirIfExists` | `:1748-1751` | only if empty (`fs.rmdirSync` `:1750`) |
| `removeIfExists` | `:1769-1771` | **yes — `fs.rmSync(force)` `:1770`** |

`copyDirRecursive` (`:285`) and `copyDirFiles` (`:299`) both funnel through
`copyFile` (`:264`). **One patch at `:264` covers all three** for this family.

### Raw `fs` mutations reached during an install that bypass BOTH families

**Scope and derivation of this table — read before treating it as complete.**
It covers call sites reachable from `installProjectWithTargetAuthority`
(`scripts/install.js:1844`, which runs to `:2117`) and the adapter `install()`
functions it drives. Uninstall/doctor/dev-sync/render paths are deliberately
excluded. Derived by enumerating every
`fs.{writeFileSync,rmSync,unlinkSync,renameSync,rmdirSync,chmodSync,copyFileSync,
fchmodSync,writeSync,mkdirSync}` call in this bounded module set —

`scripts/install.js`, `adapters/{claude,kimi,codex,generic-mcp}/index.js`,
`mcp/lib/egress-profiles.js`, `scripts/lib/{claude,kimi,codex}-role-renderer.js`,
`scripts/merge-claude-config.js`, `scripts/lib/workspace-sessions-root.js`,
`scripts/lib/package-policy.js`, `mcp/lib/session-cap.js`

— then discarding those that live inside a Family A or Family B helper, or in a
function the install flow never enters. Two exclusions worth naming so they are
not mistaken for oversights: `scripts/lib/claude-role-renderer.js:669-670` writes
role files but its only adapter caller is `adapters/claude/index.js:449`, inside
`render()` (`:448-452`), not `install()` (`:454`) — and it targets the SOURCE
tree, not an install target; `scripts/merge-claude-config.js:524-525` is that
script's standalone CLI path, while the Claude adapter's install uses
`mergeConfig` plus the injected Family A `writeJson` at `:569`/`:570`. The
remaining modules in the set (`kimi`/`codex` role renderers, `package-policy.js`)
are likewise render/metadata-only.

None of the rows below are caught by patching either `copyFile`; each needs
individual handling.

| Call site | Effect |
| --- | --- |
| `scripts/install.js:166` | `fs.writeFileSync` on `.hacker-bob/VERSION` |
| `scripts/install.js:253` | `fs.unlinkSync` on a retired `mcp/*.js` — the one destination-digest-gated destruction |
| `scripts/install.js:1213` | `fs.rmSync(recursive)` per `mcp/node_modules/<dest>` |
| `scripts/install.js:1291` | `fs.writeSync` — raw byte write of a runtime dependency file (`:1311` `fchmodSync`) |
| `scripts/install.js:1324` | `fs.rmSync` of the partial destination when the source digest check at `:1303` fails |
| `scripts/install.js:1598` | `fs.writeFileSync(descriptor, …)` in `writeFreshCanonicalPackageFile` (`:1592`), called `:1683`; writes into the staging dir that `:1701` renames onto `packages/<root>` (`:1600` `fchmodSync`) |
| `scripts/install.js:1697` | `fs.renameSync` — moves the existing `packages/<root>` aside to a backup slot |
| `scripts/install.js:1701` | `fs.renameSync` — promotes staging over `packages/<root>` |
| `scripts/install.js:1704` | `fs.rmSync(recursive)` — deletes the backup after promotion |
| `scripts/install.js:1717` | `fs.rmSync(recursive)` — deletes staging on failure |
| `scripts/install.js:1760` | `fs.rmSync` per legacy `.claude/{bypass-tables,knowledge}/<name>` |
| `scripts/install.js:1906` | `fs.chmodSync` on `mcp/server.js` |
| `scripts/install.js:1922` | `fs.rmSync(recursive)` on the whole `mcp/lib/` tree |
| `scripts/install.js:1942` | `fs.rmSync` on `mcp/lib/offensive-image.json` |
| `adapters/claude/index.js:317` | `fs.writeFileSync` — the adapter's module-private `writeTextFile` (`:315-318`), used for rendered commands at `:503` |
| `adapters/claude/index.js:500` | `fs.rmSync(recursive)` on `.claude/skills/<legacy>/` |
| `adapters/claude/index.js:573` | `fs.writeFileSync` on `.claude/bob/VERSION` |
| `adapters/claude/index.js:1015` | `fs.mkdirSync(recursive)` — module-private `fsSafeMkdir` (`:1014-1016`), called `:471` and `:473`. Non-destructive, listed for completeness: it belongs to neither family. |
| `adapters/claude/index.js:1020` | `fs.rmdirSync` — module-private `removeEmptyDirIfExists` (`:1018-1021`), called `:498`. Removes only an empty dir; belongs to neither family. |
| `mcp/lib/egress-profiles.js:239` | `fs.writeFileSync` on `.claude/bob/egress-profiles.example.json`. Reached because `adapters/claude/index.js:558` calls `ensureEgressProfilesExample(targetAbs)` with **no** `options.installFs`, so the guard at `:232` is false and the raw branch `:237-240` runs. |
| `mcp/lib/egress-profiles.js:203` | `fs.writeFileSync` on `.claude/bob/egress-profiles.json`, inside `writeEgressProfilesDocument` (`:193-206`) raw branch. Reached from `adapters/claude/index.js:559` → `ensureEgressProfilesConfig` `:222-224` — **first install only**, because `:222` is preserve-on-exist. |
| `scripts/lib/workspace-sessions-root.js:169` | `fs.mkdirSync(recursive, mode 0700)` on the workspace sessions root — **outside the target**. `ensureSessionsRoot` (`:168-171`), called from `scripts/install.js:2061`. Non-destructive; listed because it belongs to neither family. |
| `mcp/lib/session-cap.js:71` | `fs.writeSync` of the session-cap nonce into `~/.bob/session-cap` — **outside the target**. `ensureSessionCapNonce` (`:54-91`), reached from `scripts/install.js:2076`, which `require`s the copy of this module **already installed into the target** (`:2073-2075`). Preserve-on-exist: guarded by `:66` plus `O_EXCL` (`"wx"`, `:70`) and an `EEXIST` fall-through at `:73`. Also `:57` mkdir, `:60` and `:86` `chmodSync`. Best-effort — `scripts/install.js:2078` swallows all errors. |

Adapter-private `writeJson` helpers exist in kimi (`adapters/kimi/index.js:216-219`),
codex (`adapters/codex/index.js:109-112`) and generic-mcp
(`adapters/generic-mcp/index.js:29-32`), but their only callers are the
uninstall paths (`adapters/kimi/index.js:582`, `adapters/codex/index.js:778`,
`adapters/generic-mcp/index.js:258`), so they are deliberately not in the table
above. Claude has no private `writeJson`; its `writeJson` at `:569`, `:570`,
`:574` is the injected Family A one.

---

## 3. The map

`<target>` is the install root. `$CODEX_HOME` defaults to `~/.codex`
(`codexHome()`, `adapters/codex/index.js:288-290`); `$KIMI_SHARE_DIR` defaults to
`~/.kimi` (`kimiHome()`, `adapters/kimi/index.js:64-70`).

**Hand-edit column** is the one that decides guard coverage:
**HIGH** = operators routinely edit this and losing it is the reported failure;
**MED** = plausible (debugging patches, prompt tuning);
**LOW** = machine-owned, an edit would be unusual;
**MERGE** = existing content is read and spread forward, so operator keys
survive but Bob-owned keys are replaced;
**SAFE** = already preserve-on-exist, no guard needed.

### 3.1 Neutral installer — runs for every adapter

Driver: `installProjectWithTargetAuthority`, `scripts/install.js:1844`.

| Target path pattern | Helper | Call site | Hand-edit |
| --- | --- | --- | --- |
| `<target>/.hacker-bob/bypass-tables/*.txt` | `copyDirFiles` (A) | `scripts/install.js:310` (via `copyResourceSet` `:305`, driven `:1884-1885`; set `:61-68`) — **has a non-vacuity floor at `:315-317`** | **HIGH** |
| `<target>/.hacker-bob/knowledge/*.json` | `copyDirFiles` (A) | `scripts/install.js:310` (set `:69-76`) — same floor | **HIGH** |
| `<target>/.hacker-bob/docs/provider-authoring.md` | `copyFile` (A) | `scripts/install.js:327` (via `copyCanonicalInstallSupportFiles` `:321`, called `:1887`; manifest `scripts/lib/package-policy.js:143-149`) | LOW |
| **DELETE** `<target>/.claude/bypass-tables/<name>`, `<target>/.claude/knowledge/<name>` | raw `fs.rmSync` | `scripts/install.js:1760` (via `removeLegacyResourceCopies` `:1753`, called `:1888`) | **HIGH** |
| **RMDIR** `<target>/.claude/{bypass-tables,knowledge}` when empty | `removeEmptyDirIfExists` (A) | `scripts/install.js:1764` | LOW |
| **DELETE** `<target>/mcp/<retired>.js` | raw `fs.unlinkSync` | `scripts/install.js:253` (via `pruneRetiredMcpTopLevelRuntimeFiles` `:226`, invoked `:1899`) | MED — destination-digest-gated; the only protected path in the tree |
| `<target>/mcp/{server.js,auto-signup.js,redaction.js,browser-driver.js}` | `copyFile` (A) | `scripts/install.js:1904` (loop `:1903-1905`) | MED |
| `<target>/mcp/server.js` mode `0755` | raw `fs.chmodSync` | `scripts/install.js:1906` | LOW |
| **DELETE** `<target>/mcp/lib/` (entire tree) | raw `fs.rmSync(recursive)` | `scripts/install.js:1922` | MED |
| `<target>/mcp/lib/**/*.{js,sh}` | `copyDirRecursive` (A) | `scripts/install.js:1927` | MED |
| `<target>/mcp/lib/offensive-image.json` (or **DELETE** it) | `copyFile` (A) / raw `fs.rmSync` | `scripts/install.js:1938` / `:1942` | LOW |
| `<target>/packages/{bob-artifact-vault,bob-instrument-broker,bob-instrument-contracts,bob-instrument-chameleon,bob-instrument-chameleon-worker-runtime,bob-instrument-deterministic,bob-instrument-native-prebuild-trust,bob-instrument-principal-acl-darwin}/**` — whole root **REPLACED** | staged raw write + rename | `scripts/install.js:1944` → `copyCanonicalRuntimePackages` `:1726`, which dispatches at `:1734` to `copyCanonicalRuntimePackagesDirect` `:1611` (or `:1732` with a target authority). Staged writes `:1683`/`:1598`; `:1697` rename-out, `:1701` rename-in, `:1704` backup rm. Roots at `scripts/lib/package-policy.js:68-77` | LOW |
| `<target>/mcp/node_modules/**` — per-destination **REPLACED** | raw `fs.rmSync` + descriptor copy | `scripts/install.js:1949` → `applyRuntimeNodeDependencyCopy` `:1422` (`:1213` remove, `:1477` → `copyStableRuntimeDependencyFile` `:1238`) | LOW |
| `<target>/testing/policy-replay/**/*.{mjs,md,json}` | `copyDirRecursive` (A) | `scripts/install.js:1956` | **HIGH** — `prompts/*.md` and `cases/*.json` are tuning inputs |
| `<target>/.hacker-bob/VERSION` | raw `fs.writeFileSync` | `scripts/install.js:166` | LOW |
| `<target>/.hacker-bob/install.json` | `writeJson` (A) | `scripts/install.js:167` (via `writeNeutralInstallMetadata` `:151`) | LOW |

### 3.2 Claude adapter — `adapters/claude/index.js:454`

Helpers are the **Family A** `scripts/install.js` ones, injected at
`scripts/install.js:2003-2018`. Where a row says "claude-private" the helper
belongs to neither family and needs its own gate.

| Target path pattern | Helper | Call site | Hand-edit |
| --- | --- | --- | --- |
| **DELETE** `.claude/hooks/{bob-update-lib.js,scope-guard.sh,scope-guard-mcp.sh}` | `removeIfExists` (A) | `adapters/claude/index.js:476` (`STALE_HOOK_FILES`, **3 entries**, `:38-42`) | LOW |
| **DELETE** `.claude/agents/{hunter-agent,hunter-cosmwasm-agent,hunter-evm-agent,hunter-move-agent,hunter-substrate-agent,hunter-svm-agent,recon-agent,deep-recon-agent}.md` | `removeIfExists` (A) | `adapters/claude/index.js:481` (`LEGACY_AGENT_FILES`, **8 entries**, `:121-130`) | **HIGH** — deletes eight fixed names with no digest check; an operator file at any of those paths is removed |
| **DELETE** `.claude/hooks/{hunter-subagent-stop.js,bounty-statusline.js}` | `removeIfExists` (A) | `adapters/claude/index.js:484` (`LEGACY_HOOK_FILES`, **2 entries**, `:137-140`) | MED |
| `.claude/agents/*.md` (**21 source files today**) | `copyDirFiles` (A) | `adapters/claude/index.js:487`; result used only as a count at `:585` — **no non-vacuity floor** | **HIGH** |
| **DELETE** `.claude/commands/{bountyagent.md,bountyagentdebug.md}` | `removeIfExists` (A) | `adapters/claude/index.js:493`, `:494` | LOW |
| **DELETE** `.claude/commands/bob/{evaluate,status,debug,update}.md` | `removeIfExists` (A) | `adapters/claude/index.js:496` (`LEGACY_BOB_COMMAND_FILES`, **4 entries**, `:73-78`) | MED |
| **RMDIR** `.claude/commands/bob` when empty | claude-private `removeEmptyDirIfExists` (`:1018-1021`) | `adapters/claude/index.js:498` | LOW |
| **DELETE** `.claude/skills/{bountyagent,bountyagentdebug,bountyagentstatus,bob-hunt,bob-evaluate}/` recursively | raw `fs.rmSync` | `adapters/claude/index.js:500` (`LEGACY_BOB_SKILLS`, **5 entries**, `:108-114`) | MED — bypasses the injected helper entirely |
| `.claude/commands/{bob-evaluate.md,bob-update.md,bob-export.md}` (rendered, **3** ids from `COMMAND_SPECS` `:80-93` via `commandIds()` `:217-219`) | claude-private `writeTextFile` (`:315-318`) | `adapters/claude/index.js:503` (loop `:502-507`) | MED |
| `.claude/commands/bob-egress.md` | `copyFile` (A) | `adapters/claude/index.js:513` | MED |
| `.claude/skills/{bob-evaluate-runner,bob-status,bob-debug,bob-diff-review}/SKILL.md` | `copyFile` (A) | `adapters/claude/index.js:519` (`BOB_SKILLS`, **4 entries**, `:95-100`) | MED |
| `.claude/rules/*.md` (**2 source files today**: `evaluating.md`, `reporting.md`) | `copyDirFiles` (A) | `adapters/claude/index.js:525`; result used only as a count at `:587` — **no non-vacuity floor**. **This is the one that bit.** | **HIGH** |
| `.claude/hooks/<name>` — `HOOK_FILES` has **12 entries** (`:23-36`, entries `:24-35`); mode `0755` when in `EXECUTABLE_HOOKS` (**10 entries**, `:53-64`) | `copyFile` (A) | `adapters/claude/index.js:533` (loop `:531-538`, mode chosen `:532`) | **HIGH** — guards are the natural local-policy edit point |
| `.claude/hooks/write-guard-tables.json` | `copyFile` (A) | `adapters/claude/index.js:544` (`HOOK_DATA_FILES`, **1 entry**, `:49-51`) | MED |
| `.claude/bob/egress-profiles.example.json` | raw `fs.writeFileSync` (`mcp/lib/egress-profiles.js:239`) — `adapters/claude/index.js:558` passes no `installFs`, so `:232` is false | `adapters/claude/index.js:558` → `ensureEgressProfilesExample` `:230-242` | LOW |
| `.claude/bob/egress-profiles.json` | create-if-absent (raw `fs.writeFileSync` `mcp/lib/egress-profiles.js:203` on first install only) | `adapters/claude/index.js:559` → `ensureEgressProfilesConfig` `:208-227` (`:222` is the preserve-on-exist test) | **SAFE** |
| `<target>/.mcp.json` | `writeJson` (A) | `adapters/claude/index.js:569` | **MERGE** |
| `.claude/settings.json` | `writeJson` (A) | `adapters/claude/index.js:570` | **MERGE** |
| `.claude/bob/VERSION` | raw `fs.writeFileSync` | `adapters/claude/index.js:573` | LOW |
| `.claude/bob/install.json` (schema_version 1, no ownership record) | `writeJson` (A) | `adapters/claude/index.js:574` | LOW |

Directories are created first by claude-private `fsSafeMkdir` (`:1014-1016`) at
`:471` and `:473` for `agents`, `commands`, `rules`, `hooks`, `skills`, `bob`.

### 3.3 Kimi adapter — `adapters/kimi/index.js:230`

Uses `createSafeInstallFs` — Family B (`require` at `:11`, instantiated `:242`).

| Target path pattern | Helper | Call site | Hand-edit |
| --- | --- | --- | --- |
| **DELETE** `.kimi/skills/<LEGACY_BOB_SKILLS>/` recursively (**2 entries**, `adapters/kimi/config.js`) | `removePath` (B) | `adapters/kimi/index.js:256` | MED |
| `.kimi/skills/{bob-evaluate,bob-status,bob-debug,bob-update,bob-export,bob-egress}/*` (**6** skills, `BOB_SKILLS` from `adapters/kimi/config.js`) | `copyDirFiles` (B) | `adapters/kimi/index.js:263` (loop `:259-265`) | **HIGH** |
| **DELETE** `.kimi/hooks/scope-guard.sh` | `removePath` (B) | `adapters/kimi/index.js:269` (`STALE_HOOK_FILES`, **1 entry**, `:49-51`) | LOW |
| `.kimi/hooks/{session-read-guard.sh,session-write-guard.sh}` mode `0755` | `copyFile` (B) | `adapters/kimi/index.js:277` (`HOOK_FILES`, **2 entries**, `:26-29`) | **HIGH** |
| `.kimi/hooks/write-guard-tables.json` | `copyFile` (B) | `adapters/kimi/index.js:286` (`HOOK_DATA_FILES`, **1 entry**, `:43-45`) | MED |
| `<target>/.kimi/mcp.json` | `writeJson` (B) | `adapters/kimi/index.js:309` | **MERGE** |
| `.kimi/bob/VERSION` | `writeTextFile` (B) | `adapters/kimi/index.js:315` | LOW |
| `.kimi/bob/install.json` (schema_version 1, no ownership record) | `writeJson` (B) | `adapters/kimi/index.js:318` | LOW |
| `$KIMI_SHARE_DIR/config.toml` — **outside the target** | `writeTextFile` (B) on `homeFs` (`:336`) | `adapters/kimi/index.js:343` | **MERGE** (sentinel block constants `:56-57`, upserted by `upsertKimiHookBlock` at `:342`) |

Latent, not an observed gap: `copyDirFiles` is non-recursive
(`scripts/lib/install-fs.js:213-225`), and `adapters/kimi/config.js:9` declares a
`references_path` of `adapters/kimi/skills/bob-evaluate/references` for the
`bob-evaluate` skill. **That directory does not exist on disk today** — every
`adapters/kimi/skills/*/` contains only `SKILL.md` — so nothing is currently
dropped by `:263`. If a `references/` subtree is ever added, `:263` will silently
skip it.

### 3.4 Codex adapter — `adapters/codex/index.js:503`

Uses `createSafeInstallFs` — Family B — for both the project (`projectFs`, `:504`)
and `$CODEX_HOME` (`homeFs`, `:506`).

| Target path pattern | Helper | Call site | Hand-edit |
| --- | --- | --- | --- |
| **DELETE** `.codex/plugins/hacker-bob/skills/` recursively | `removePath` (B) | `adapters/codex/index.js:305` (via `removeStalePluginSurfaces` `:304`, called `:509`) | MED |
| **DELETE** `.codex/plugins/hacker-bob/commands/{evaluate,status,debug,update,bob-hunt}.md` | `removePath` (B) | `adapters/codex/index.js:307` (`STALE_COMMAND_FILES`, **5 entries**, `:46-53`) | MED |
| `.codex/plugins/hacker-bob/**` (whole plugin tree; source `adapters/codex/hacker-bob/`, `PLUGIN_SOURCE_DIR` `:19`) | `copyTree` (B) | `adapters/codex/index.js:510` | **HIGH** |
| `.codex/plugins/hacker-bob/commands/bob-{evaluate,status,debug,update,export,egress}.md` | `writeTextFile` (B) | `adapters/codex/index.js:221` (via `writeCommandFiles` `:219`, called `:511`) | MED |
| `.codex/plugins/hacker-bob/.mcp.json` — **full replace, not a merge** | `writeJson` (B) | `adapters/codex/index.js:512` | MED |
| `<target>/.agents/plugins/marketplace.json` | `writeJson` (B) | `adapters/codex/index.js:282` (via `installMarketplace` `:276`, called `:515`) | **MERGE** (`mergeMarketplace` `:244`) |
| **DELETE** `$CODEX_HOME/skills/<LEGACY_SKILL_DIRS>/` (**6 entries**, `:28-37`) — **outside the target** | `removePath` (B) | `adapters/codex/index.js:313` (via `removeLegacyDirectSkillDirs` `:311`, called `:319`) | MED |
| `$CODEX_HOME/skills/<spec.name>/SKILL.md` — **6** specs (`CODEX_SKILL_SPECS`, `scripts/lib/codex-role-renderer.js:53`) — **outside the target** | `copyFile` (B) | `adapters/codex/index.js:323` (via `installDirectSkills` `:317`, called `:516`) | **HIGH** |
| **DELETE ALL** of `$CODEX_HOME/plugins/cache/hacker-bob-local/hacker-bob/` — every cached version — **outside the target** | `removeDirContents` (B) | `adapters/codex/index.js:436` (in `activateCodexPlugin` `:428`) | LOW |
| `$CODEX_HOME/plugins/cache/hacker-bob-local/hacker-bob/<version>/**` | `copyTree` (B) | `adapters/codex/index.js:437` | LOW |
| `$CODEX_HOME/config.toml` — **outside the target** | `writeTextFile` (B) | `adapters/codex/index.js:451` | **MERGE** (section upserts `:443-450`) |

### 3.5 generic-mcp adapter — `adapters/generic-mcp/index.js:89`

Uses `createSafeInstallFs` — Family B (`require` `:5`, instantiated `:90`).

| Target path pattern | Helper | Call site | Hand-edit |
| --- | --- | --- | --- |
| `<target>/.mcp.json` | `writeJson` (B) | `adapters/generic-mcp/index.js:104` | **MERGE** |
| `<target>/.hacker-bob/generic-mcp/hacker-bob.md` (`PROMPT_FILES`, **1 entry**, `:21-23`) | `copyFile` (B) | `adapters/generic-mcp/index.js:83` (via `copyPromptDocs` `:78`, called `:109`) | MED |

---

## 4. Counts and hardcoded floors

Invariant 6: a check that iterates a collection is satisfied vacuously by an
empty one. The collections that matter are **the ones the copy helpers actually
walk at runtime** — source directories and constant name lists — not the rows of
this document. Round 1 floored the wrong things; §4.1 is the correction.

Every number below was produced by the command shown, whose literal output is
pasted. None were derived by reading a line range.

### 4.1 Source-collection floors — assert these in the guard's fixtures

A guard test must assert the SOURCE side is non-empty **before** drawing any "no
drift" or "drift detected" conclusion. Otherwise an empty source directory makes
the whole assertion vacuous while the install still exits 0.

```
$ cd /Users/noot/Documents/hacker-bob
$ c() { printf '%-46s %s\n' "$1" "$(eval "$2" | wc -l | tr -d ' ')"; }
$ c ".claude/agents/*.md"                      "find .claude/agents -maxdepth 1 -type f -name '*.md'"
$ c ".claude/rules/*.md"                       "find .claude/rules -maxdepth 1 -type f -name '*.md'"
$ c ".claude/skills/*/SKILL.md"                "find .claude/skills -maxdepth 2 -type f -name 'SKILL.md'"
$ c ".hacker-bob/bypass-tables/*.txt"          "find .hacker-bob/bypass-tables -maxdepth 1 -type f -name '*.txt'"
$ c ".hacker-bob/knowledge/*.json"             "find .hacker-bob/knowledge -maxdepth 1 -type f -name '*.json'"
$ c "mcp/lib/**/*.{js,sh}"                     "find mcp/lib -type f \( -name '*.js' -o -name '*.sh' \)"
$ c "testing/policy-replay/**/*.{mjs,md,json}" "find testing/policy-replay -type f \( -name '*.mjs' -o -name '*.md' -o -name '*.json' \) -not -path '*/node_modules/*'"
$ c "adapters/codex/hacker-bob/** (copyTree)"  "find adapters/codex/hacker-bob -type f"
$ c "adapters/kimi/skills/*/* (copyDirFiles)"  "find adapters/kimi/skills -type f"

.claude/agents/*.md                            21
.claude/rules/*.md                             2
.claude/skills/*/SKILL.md                      4
.hacker-bob/bypass-tables/*.txt                8
.hacker-bob/knowledge/*.json                   1
mcp/lib/**/*.{js,sh}                           541
testing/policy-replay/**/*.{mjs,md,json}       10
adapters/codex/hacker-bob/** (copyTree)        2
adapters/kimi/skills/*/* (copyDirFiles)        6
```

| Source collection | Iterated by | Count today | Floor to assert |
| --- | --- | --- | --- |
| `.claude/agents/*.md` | `adapters/claude/index.js:487` | 21 | `>= 21` |
| `.claude/rules/*.md` | `adapters/claude/index.js:525` | 2 | `>= 2` |
| `.claude/skills/*/SKILL.md` | `adapters/claude/index.js:519` | 4 | `>= 4` |
| `.hacker-bob/bypass-tables/*.txt` | `scripts/install.js:310` | 8 | `>= 8` |
| `.hacker-bob/knowledge/*.json` | `scripts/install.js:310` | 1 | `>= 1` |
| `mcp/lib/**/*.{js,sh}` | `scripts/install.js:1927` | 541 | `>= 500` |
| `testing/policy-replay/**/*.{mjs,md,json}` | `scripts/install.js:1956` | 10 | `>= 10` |
| `adapters/codex/hacker-bob/**` | `adapters/codex/index.js:510` | 2 | `>= 2` |
| `adapters/kimi/skills/*/*` | `adapters/kimi/index.js:263` | 6 | `>= 6` |

### 4.2 Constant-list floors — the name lists the adapters iterate

```
$ cd /Users/noot/Documents/hacker-bob && node -e '
const fs=require("fs");
const L=(f,n)=>{const m=fs.readFileSync(f,"utf8").match(new RegExp("const "+n+" = Object\\.freeze\\(\\[([\\s\\S]*?)\\n\\]\\)"));
  if(!m) throw new Error("NOT FOUND "+n+" in "+f);
  const k=(m[1].match(/^\s*"/gm)||[]).length; if(k===0) throw new Error("EMPTY "+n); return k;};
const C="adapters/claude/index.js", K="adapters/kimi/index.js", X="adapters/codex/index.js", G="adapters/generic-mcp/index.js";
const pp=require("./scripts/lib/package-policy.js"), crr=require("./scripts/lib/codex-role-renderer.js"), kc=require("./adapters/kimi/config.js");
const r=[["claude HOOK_FILES",L(C,"HOOK_FILES")],["claude EXECUTABLE_HOOKS",L(C,"EXECUTABLE_HOOKS")],
["claude HOOK_DATA_FILES",L(C,"HOOK_DATA_FILES")],["claude BOB_SKILLS",L(C,"BOB_SKILLS")],
["claude STALE_HOOK_FILES",L(C,"STALE_HOOK_FILES")],["claude LEGACY_AGENT_FILES",L(C,"LEGACY_AGENT_FILES")],
["claude LEGACY_HOOK_FILES",L(C,"LEGACY_HOOK_FILES")],["claude LEGACY_BOB_COMMAND_FILES",L(C,"LEGACY_BOB_COMMAND_FILES")],
["claude LEGACY_BOB_SKILLS",L(C,"LEGACY_BOB_SKILLS")],["kimi HOOK_FILES",L(K,"HOOK_FILES")],
["kimi HOOK_DATA_FILES",L(K,"HOOK_DATA_FILES")],["kimi STALE_HOOK_FILES",L(K,"STALE_HOOK_FILES")],
["kimi BOB_SKILLS",kc.BOB_SKILLS.length],["kimi LEGACY_BOB_SKILLS",kc.LEGACY_BOB_SKILLS.length],
["codex CODEX_SKILL_SPECS",Object.keys(crr.CODEX_SKILL_SPECS).length],["codex STALE_COMMAND_FILES",L(X,"STALE_COMMAND_FILES")],
["codex LEGACY_SKILL_DIRS",L(X,"LEGACY_SKILL_DIRS")],["generic-mcp PROMPT_FILES",L(G,"PROMPT_FILES")],
["MCP_TOP_LEVEL_RUNTIME_FILES",pp.MCP_TOP_LEVEL_RUNTIME_FILES.length],
["CANONICAL_INSTALL_SUPPORT_FILES",pp.CANONICAL_INSTALL_SUPPORT_FILES.length],
["CANONICAL_RUNTIME_PACKAGE_ROOTS",pp.CANONICAL_RUNTIME_PACKAGE_ROOTS.length]];
for(const [k,v] of r) console.log(k.padEnd(40)+" = "+v);'

claude HOOK_FILES                        = 12
claude EXECUTABLE_HOOKS                  = 10
claude HOOK_DATA_FILES                   = 1
claude BOB_SKILLS                        = 4
claude STALE_HOOK_FILES                  = 3
claude LEGACY_AGENT_FILES                = 8
claude LEGACY_HOOK_FILES                 = 2
claude LEGACY_BOB_COMMAND_FILES          = 4
claude LEGACY_BOB_SKILLS                 = 5
kimi HOOK_FILES                          = 2
kimi HOOK_DATA_FILES                     = 1
kimi STALE_HOOK_FILES                    = 1
kimi BOB_SKILLS                          = 6
kimi LEGACY_BOB_SKILLS                   = 2
codex CODEX_SKILL_SPECS                  = 6
codex STALE_COMMAND_FILES                = 5
codex LEGACY_SKILL_DIRS                  = 6
generic-mcp PROMPT_FILES                 = 1
MCP_TOP_LEVEL_RUNTIME_FILES              = 4
CANONICAL_INSTALL_SUPPORT_FILES          = 1
CANONICAL_RUNTIME_PACKAGE_ROOTS          = 8
```

The `L()` helper above throws on both "list not found" and "list found but
empty", so the emitted numbers cannot themselves be vacuous. Floors: assert each
value `>= ` the number shown. The COPY lists (`HOOK_FILES` 12, `BOB_SKILLS` 4,
`kimi BOB_SKILLS` 6, `CODEX_SKILL_SPECS` 6, `PROMPT_FILES` 1,
`MCP_TOP_LEVEL_RUNTIME_FILES` 4) bound what the guard must protect; the DELETE
lists (`LEGACY_AGENT_FILES` 8, `LEGACY_BOB_SKILLS` 5, `LEGACY_SKILL_DIRS` 6,
`STALE_COMMAND_FILES` 5, `STALE_HOOK_FILES` 3/1, `LEGACY_HOOK_FILES` 2,
`LEGACY_BOB_COMMAND_FILES` 4) bound what it must protect from *deletion*.

**`HOOK_FILES` is 12, not 13.** Round 1 wrote 13, which was the height of the
line range `:23-35`, not the number of entries. The block is
`adapters/claude/index.js:23-36`; the twelve string entries are `:24-35`.

### 4.3 Guard-correctness assertions

Round 1 proposed "call sites that consult a digest before writing == 0, assert
`== 0` today". That assertion is self-invalidating — it fails the moment the
guard lands — and it is also the wrong polarity, because a zero can be reached by
looking in the wrong place. Replace it with a pair:

| Assertion | Polarity | Why it cannot pass vacuously |
| --- | --- | --- |
| Write call sites that reach the filesystem **through** the drift gate `>= N` (N = the guard's own registered chokepoints, at minimum 2: `scripts/install.js:264` and `scripts/lib/install-fs.js:201`) | positive floor | a counter with a hardcoded floor |
| Write call sites that reach the filesystem **without** passing the gate `== 0`, enumerated over the same bypass list as §2's third table | zero on a complement whose total is separately floored | the complement's total is asserted `>= 23` first, so a zero can only mean "all covered", never "found nothing" |
| Call sites that compare the **DESTINATION's** digest before overwriting it | `== 0` **today**, expected `> 0` after the guard | true and testable as written (see §0); `scripts/install.js:1303` does not count — it compares the SOURCE |

### 4.4 Survey-completeness check (secondary)

These count rows in this document, not runtime collections. They catch a
truncated survey; they do **not** substitute for §4.1/§4.2.

| Collection | Count today | Floor |
| --- | --- | --- |
| Adapters that write into a target | 4 (claude, codex, kimi, generic-mcp) | `>= 4` |
| Independent copy-helper families | 2 (Family A `install.js`, Family B `install-fs.js`) | `>= 2` |
| Write/delete helpers returned from `createSafeInstallFs`. The return object at `:323-342` has **18** keys (`:324-341`); 8 are non-mutating (`root`, `label`, `resolveInside`, `mkdirp`, `readJsonIfExists`, `readTextIfExists`, `fileExists`, `dirExists`) | 10 | `>= 10` |
| Duplicate raw helpers in `install.js` (`:97`, `:264`, `:270`, `:291`, `:1748`, `:1769`) | 6 | `>= 6` |
| Raw-`fs` install-time call sites bypassing both families (§2, third table) | 23 | `>= 23` |
| Files covered by `mcp_top_level_runtime_ownership` | 4 | exactly 4; **and** assert 0 of them are write-protected |

---

## 5. What the drift guard must cover

Ordered by the failure the operator actually reports.

1. **`.claude/rules/*.md`** — `adapters/claude/index.js:525`. The reported bite.
2. **`.claude/agents/*.md`** — `adapters/claude/index.js:487`, plus the
   *deletion* at `:481`, which removes eight named files with no digest check at
   all. A delete is destruction too.
3. **`.claude/hooks/*`** — `adapters/claude/index.js:533`, `:544`, and the
   deletes at `:476`/`:484`. Mirrored on kimi at `adapters/kimi/index.js:277`/`:286`.
4. **`.hacker-bob/bypass-tables/*.txt`, `.hacker-bob/knowledge/*.json`** —
   `scripts/install.js:310`, plus the legacy-copy deletes at `:1760`.
5. **`.claude/skills/*/SKILL.md`, `.kimi/skills/**`, `$CODEX_HOME/skills/*/SKILL.md`**
   — `adapters/claude/index.js:519`, `adapters/kimi/index.js:263`,
   `adapters/codex/index.js:323`.
6. **`testing/policy-replay/prompts/*.md` and `cases/*.json`** —
   `scripts/install.js:1956`. Tuning inputs, wholesale-overwritten.
7. **`mcp/*.js` top level** — `scripts/install.js:1904`. The receipt already
   holds the digests; nothing reads them before the write.

Cheapest complete coverage of items 1-7 is a compare-then-write gate inside the
two `copyFile` definitions — `scripts/install.js:264` (Family A) and
`scripts/lib/install-fs.js:201` (Family B) — since every
`copyDirFiles`/`copyDirRecursive`/`copyTree` in the tree funnels through one of
them (`scripts/install.js:285`, `:299`; `scripts/lib/install-fs.js:221`, `:244`,
`:262`). That leaves the deletes (`removeIfExists` `scripts/install.js:1769`,
`removePath` `scripts/lib/install-fs.js:271`, and the raw `fs.rmSync` at
`adapters/claude/index.js:500`) needing their own gate, and the 23
helper-bypassing raw calls in §2 needing individual handling.

### Test-fixture requirement (from invariant 6)

Before any test asserts "no drift" or "drift detected", it must assert the
**source** tree is non-empty using the §4.1 floors. `copyDirFiles` returns `[]`
on an empty source and the Claude install still succeeds (`adapters/claude/index.js:487`
and `:525` consume the result only as counts at `:585`/`:587`), so an empty
fixture silently makes every downstream assertion vacuous. Model the assertion on
`copyResourceSet`'s existing throw at `scripts/install.js:315-317` — that is the
in-tree precedent for refusing a zero-file copy.

Constraints the gate must respect (bound invariants for this work):

- Loud beats silent. A warning the operator sees beats a backup they never find.
- Idempotent: a second install with no local edits must change nothing and say
  nothing new.
- No regression on the clean path — the common case stays quiet and fast.
- Reproduce against a throwaway target directory. Never run an installer against
  a working project without an undo.

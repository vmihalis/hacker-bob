# report.md format facts

Verified against hacker-bob source on branch `bob-install-drift-guard`. Every fact
below cites the `path:line` that settles it. Line numbers are from the working tree
at the time of writing — re-check the cited symbol, not the number, if they drift.

Four claims were carried in. Three are **CONFIRMED**. One is **PARTLY FALSIFIED**:
the stated *mechanism* does not exist in hacker-bob, but the stated *outcome* —
phantom findings minted from headings — is real here, by a different mechanism, and
is reproduced below.

## How the numbers in this document were produced

Every count below is the output of a command, not a reading of a line range, and
every "X does not exist" claim is paired with a positive control run under the same
grep shape so a zero result cannot be confused with a broken pattern. Reproduction
is by `renderMarkdown` (`mcp/tools/compose-report.js:1085-1140`) driven directly
and its output fed to `parseAuditReportMarkdown`
(`mcp/core/audit-report-parser.js:85`). `renderMarkdown` is not in the module's export
list (`mcp/tools/compose-report.js:1438-1448`, and `module.exports` is the
non-extensible result of `wrapWriteTool` at `:1381`), so the probe compiles the
untouched source text with one appended `globalThis` handoff line under the real file
path. No repo file is modified and no session directory is written.

---

## 1. CONFIRMED — `SECTION_KINDS` is a frozen eight-value enum

`mcp/tools/compose-report.js:64-73` declares the array; the eight string literals
are on `:65-72`:

```js
const SECTION_KINDS = Object.freeze([
  "impact", "repro", "evidence", "severity",
  "remediation", "chain_summary", "proof_bundle", "provenance",
]);
```

Counted at runtime rather than read off the range:

```
section_kinds_count=8 frozen=true
values=["impact","repro","evidence","severity","remediation","chain_summary","proof_bundle","provenance"]
```

Enforcement is `assertEnum(section.kind, SECTION_KINDS, …)` at
`mcp/tools/compose-report.js:791`; `assertEnum` is defined at `:120-128` and
throws `ERROR_CODES.INVALID_ARGUMENTS` from `:122-125` on any other value. The same
closed list is mirrored into the published JSON schema at `:1397`
(`enum: [...SECTION_KINDS]`).

**Consequence:** new `kind:` values are not authorable. A section that does not fit
one of the eight must reuse the nearest kind — the enum is not extensible from the
caller side.

Anchor drift from the carried-in claim: claimed at `:60` and `:787`; actually `:64`
and `:791` (+4 on both).

A sibling enum, `PROVENANCE_VALUES` (`:74-78`, three values, `Object.isFrozen` true),
is closed the same way and checked at `:794`: `bob_verified` / `operator_osint` /
`external_research`.

## 2. CONFIRMED — `SECTION_PROSE_MAX` is 4096, and over-limit prose is REFUSED, not truncated

`mcp/tools/compose-report.js:80` — `const SECTION_PROSE_MAX = 4096;`

Applied at `:793` via `assertString(section.prose, …, { maxLength: SECTION_PROSE_MAX })`.
`assertString` is defined at `:107-118`; its over-length branch is `:114` and the
`throw` is `:115`. There is no truncating branch anywhere in the function. Mirrored
in the schema at `:1399`.

**Consequence:** an oversized table or transcript must be **split across consecutive
sections** by the caller. Nothing clips it for you, and nothing warns — the whole
`bob_compose_report` call fails with `INVALID_ARGUMENTS`. Splitting is unbounded:
`sections` declares `minItems: 0` at `:1392` and no `maxItems`. (Controlled negative:
the file contains exactly **1** `maxItems` occurrence in total, at `:1418`, inside
`repro_steps_by_finding.steps` — so the grep is live and the absence at `:1390-1408`
is real, not a pattern failure.)

Anchor drift: claimed at `:76`; actually `:80` (+4).

Companion caps, same block, each anchor re-grepped for this revision:

| Constant | Value | Declared at | Compared at | Throws at |
| --- | --- | --- | --- | --- |
| `SECTION_HEADING_MAX` | 200 | `:81` | `:792` | `:115` (via `assertString`) |
| `SEVERITY_SUMMARY_MAX` | 2048 | `:82` | `:1255` | `:115` (via `assertString`) |
| `REPRO_STEPS_PER_FINDING_MAX` | 12 | `:83` | `:823` | `:824` |
| `REPRO_STEP_MAX` | 512 | `:84` | `:830` | `:115` (via `assertString`) |

Round 1 of this document cited `REPRO_STEPS_PER_FINDING_MAX` as "applied at `:824`".
That was wrong: `:823` is `if (steps.length > REPRO_STEPS_PER_FINDING_MAX) {` and
`:824` is the `throw new ToolError(`. Corrected above.

## 3. CONFIRMED — `section_id` auto-fills to `section-N` and never has to name a finding

`mcp/tools/compose-report.js:799-801`:

```js
const sectionId = typeof section.section_id === "string" && section.section_id
  ? section.section_id
  : `section-${index + 1}`;
```

`section_id` is absent from the schema's `required` list, which is
`["kind", "heading", "prose", "provenance"]` (`:1406`).

Anchor drift: claimed at `:795-797`; actually `:799-801` (+4).

**The 64-character cap is schema-declared only, not runtime-enforced.** `section_id`
carries `{ type: "string", maxLength: 64 }` at `:1396`, but `normalizeSection`
(`:787-810`) applies **no** `assertString` to it — contrast `heading` (`:792`),
`prose` (`:793`) and each `evidence_refs[i]` (`:797`), which do get one. Any
non-empty string reaches the renderer. Round 1 of this document said "free-form text
up to 64 chars"; the cap binds only a schema-validating MCP client. This repo ships
no runtime JSON-schema validator: `package.json` declares 7 dependencies
(`@babel/parser`, `@anthropic-ai/claude-agent-sdk`, `@aws-sdk/client-s3`,
`@aws-sdk/client-securityhub`, `proxy-agent`, `psl`, `ws`) and none is a schema
validator, and `mcp/server.js` is 64 lines containing zero occurrences of
`inputSchema`, `ajv`, `validateSchema` or `maxLength`. The dependency list is the
positive control for that second count.

`FINDING_ID_RE` and `parseFindingId` are never applied to `section_id`. Controlled
negative: `grep -rn 'FINDING_ID_RE\|parseFindingId' mcp/lib --include='*.js'` returns
**48** hits across the tree (the control — the pattern is live) and **0** of them are
in `compose-report.js`. `FINDING_ID_RE` itself resolves at only four sites:
`mcp/core/io/identifier-contracts.js` (definition/export), `mcp/core/io/validation.js`
(import) and `:163` (its sole `.test()`), inside `parseFindingId`
(`mcp/core/io/validation.js:161-167`). So a `section_id` is arbitrary non-empty text at
runtime and is not required to lead with, contain, or resolve to a finding id.

**Two caveats worth knowing before you rely on it:**

- The auto-filled id is derived from the section's array index, so auto-filled ids
  never collide with each other — but **explicit caller-supplied `section_id`s are
  not checked against each other**. The only collision check
  (`mcp/tools/compose-report.js:497-508`) builds `callerIds` as a `Set` at `:497`
  and compares *capability-pack-generated* ids against it and against other generated
  ids at `:501`. Building a `Set` silently absorbs caller-vs-caller duplicates; two
  caller sections may legally share one id.
- `bob_amend_report` targets a section **by `section_id`**
  (`mcp/tools/amend-report.js:49`), and the amendment renders under
  `### ${amend.section_id}` (`mcp/tools/compose-report.js:1131`). A duplicated or
  index-derived id therefore makes the amend target ambiguous or position-dependent.
  Pass explicit, stable, unique `section_id`s when you intend to amend later. Note the
  asymmetry: `bob_amend_report` *does* apply a runtime 64-char cap to its own
  `section_id` (`mcp/tools/amend-report.js:30`, asserted at `:49` through the
  local `assertString` at `:34-42`); `bob_compose_report` does not.

## 4. PARTLY FALSIFIED, PARTLY REPRODUCED — the heading footgun

### 4a. FALSIFIED: no `<1-3 letters><optional hyphen><digits>` token matcher is applied to a heading in hacker-bob

The carried-in claim described a heading token matched as one-to-three letters, an
optional hyphen, then digits. Two separate claims settle this; the first is narrow,
the second is the one that actually carries the verdict.

**Narrow claim (what the grep proves).** No literal `{1,3}`-quantified letter class
occurs in any `*.js` / `*.ts` / `*.md` outside `node_modules`:

```
pattern:  [A-Za-z]{1,3} | [a-zA-Z]{1,3} | [A-Z]{1,3} | [a-z]{1,3} | \w{1,3} | [A-Za-z]?[A-Za-z]?
hits(target family) = 0
POSITIVE CONTROL, same grep -rnE shape, same --include/--exclude:
pattern:  [1-9]\d*
hits(control)       = 13   (domain constant homes such as mcp/core/io/identifier-contracts.js, …)
```

That command is blind to `\w{1,3}` written another way, to a runtime-built `RegExp`,
and to spellings like `[A-Za-z][A-Za-z]?[A-Za-z]?`. It is stated here only for what
it covers. Round 1 of this document asserted in bold "No such regex exists anywhere
in this repo" on the strength of this grep alone; that was a repo-wide exhaustion
claim the evidence did not deliver, and it is withdrawn.

**Strong claim (exhaustive by enumeration).** The verdict rests instead on
enumerating every regex that can ever see a heading string.
`mcp/core/audit-report-parser.js` contains **34** regex literals in total; **11** of
them are reachable from a heading line, and every one is a literal keyword or
markdown-marker pattern:

| Line | Regex | What it is |
| --- | --- | --- |
| `:24` | `/(?:^\|\W)(?:\*\*)?severity\s*[:\-]…/i` | inline severity keyword |
| `:25` | `/^\s*###?\s*(?:\*\*)?severity…$/i` | typed H3 keyword |
| `:26` | `/^\s*###?\s*(?:\*\*)?(?:recommendation\|remediation\|fix\|mitigation)…$/i` | typed H3 keyword |
| `:27` | `/^\s*###?\s*(?:\*\*)?description…$/i` | typed H3 keyword |
| `:28` | `/^\s*###?\s*(?:\*\*)?(?:scope\|affected\|location\|target)…$/i` | typed H3 keyword |
| `:130` | `/\(.*?severity.*?\)/gi` | strips a parenthetical from a title |
| `:131` | `SEVERITY_INLINE` re-applied | strips inline severity from a title |
| `:151` | `/^# /` | H1 marker |
| `:163` | `/^##\s+/` | H2 marker |
| `:166` | `/^(?:summary\|overview\|introduction\|scope)\b/i` | summary-prefix exemption |
| `:173` | `/^###\s+/` | H3 marker |

None is a letters-then-digits token matcher. Nothing in `compose-report.js` applies
any regex to `section.heading` at all (see the controlled `FINDING_ID_RE` negative in
§3). So the *mechanism* in the carried-in claim is not hacker-bob behaviour, and
should not be documented as such.

**hacker-bob has three finding-id grammar spellings, not one.** Round 1 of this
document said "exactly one", citing only `FINDING_ID_RE`. Counted:

```
/^F-([1-9]\d*)$/          (JS RegExp literal)         sites=3
    mcp/core/io/identifier-contracts.js             (FINDING_ID_RE)
    mcp/tools/record-candidate-claim.js:194     (independent inline copy)
    mcp/core/waves/wave-handoff-contracts.js:484           (independent inline copy)
^F-[1-9][0-9]*$           (JSON-schema spelling)      sites=7
    mcp/tools/physical/verify-physical-candidate-claim.js:32
    mcp/tools/write-chain-attempt.js:17
    mcp/tools/write-evidence-packs.js:24
    mcp/tools/write-proof-bundle.js:27, :46
    mcp/tools/replay-context-schema.js:10
    mcp/tools/write-wave-handoff.js:173
^F-[0-9]+$                (LOOSE: accepts F-0, F-007) sites=2
    mcp/tools/blockchain/run-invariant-for-finding.js:68
    mcp/tools/blockchain/verify-invariant-differential.js:45
distinct_spellings=3  total_sites=12
```

The precise true statement is: `FINDING_ID_RE` is bob's *canonical* finding-id
grammar and is reached only through `parseFindingId`; two independent inline copies
of the same pattern exist, and two JSON-schema patterns are strictly looser. All
twelve are anchored `^F-…$` and all require the literal `F-` prefix, so the
FALSIFIED verdict survives: none is a `<1-3 letters><optional hyphen><digits>`
matcher, and none is applied to a heading.

Letters-then-digits matchers *do* exist elsewhere in-tree — for example
`/\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}\b/g` at
`mcp/domains/web/offensive-massread-producer.js:276` and `/&[a-zA-Z]{2,6};/` at
`mcp/core/auth/auth-placeholders.js:358`. Neither touches a heading; they are named here so
the negative above is not mistaken for a claim that no such shape exists anywhere.

### 4b. CONFIRMED: `renderMarkdown` interpolates caller text into report.md unescaped at 11 of 11 sites

`renderMarkdown` spans `mcp/tools/compose-report.js:1085-1140`. Within it, every
`parts.push` that interpolates rather than pushing a literal string was extracted
programmatically and counted:

```
caller_interpolation_sites=11        (floor asserted at 10)
  :1087  parts.push(`# Hacker Bob Report — ${domain}`);
  :1092  parts.push(severitySummary);
  :1096  parts.push(`## ${section.heading}`);
  :1098  parts.push(`<!-- section_id: ${section.section_id} | kind: … -->`);
  :1100  parts.push(section.prose);
  :1105  parts.push(`- \`${ref}\``);
  :1114  parts.push(`### ${entry.finding_id}`);
  :1117  parts.push(`${i + 1}. ${step}`);
  :1131  parts.push(`### ${amend.section_id}`);
  :1133  parts.push(`Rationale: ${amend.rationale}`);
  :1135  parts.push(amend.new_prose);
```

**None of the eleven is escaped, pattern-checked, or newline-stripped.** Three reach
column 0 with no prefix at all (`:1092`, `:1100`, `:1135`). The other eight carry a
prefix — but every validator on the path is length-only, so an embedded `\n` ends the
prefixed line and puts the rest of the value at column 0. `assertString` (`:107-118`)
checks `typeof`, `minLength` and `maxLength`; it has no character-class branch.
`assertSafeDomain` (`mcp/core/io/paths.js:20-26`) rejects only `/`, `\` and `..`.

Each of the eleven was driven end-to-end through `renderMarkdown` →
`parseAuditReportMarkdown`. All eleven mint at least one finding the caller never
wrote:

| # | Channel | Render site | Validated by | Result |
| --- | --- | --- | --- | --- |
| 1 | `target_domain` | `:1087` | `assertSafeDomain` (`paths.js:20-26`) — permits `\n` | `F-105` minted |
| 2 | `severity_summary` | `:1092` | length ≤2048 (`:1255`) | `F-77` minted |
| 3 | `sections[].heading` | `:1096` | length ≤200 (`:792`) | `F-9` minted; `\n` variant mints `F-55` |
| 4 | `sections[].section_id` | `:1098` | **nothing at runtime** (`:799-801`) | `F-66` minted |
| 5 | `sections[].prose` | `:1100` | length ≤4096 (`:793`) | `F-42` minted, plus a second H1 |
| 6 | `sections[].evidence_refs[]` | `:1105` | length ≤512 (`:797`) | `F-102` minted |
| 7 | `repro_steps_by_finding[].finding_id` | `:1114` | length ≤64 (`:821`) | `F-104` minted |
| 8 | `repro_steps_by_finding[].steps[]` | `:1117` | length ≤512 (`:830`) | `F-100` minted |
| 9 | `amendments[].section_id` | `:1131` | length ≤64 (`amend-report.js:49`) | `F-103` minted |
| 10 | `amendments[].rationale` | `:1133` | length ≤512 (`amend-report.js:51`) | `F-88` minted |
| 11 | `amendments[].new_prose` | `:1135` | length ≤4096 (`amend-report.js:50`) | `F-99` minted |

`checked=11, minted_phantom=11`. Every run returned `parser_warnings=[]` — see §4e
for why that is not evidence of a passing check.

Channel 6 is admissible because `validateProvenance` returns immediately for any
section whose provenance is not `bob_verified`
(`mcp/tools/compose-report.js:711-712`); only on the `bob_verified` path is an
unclassifiable ref refused (`:726-735`). The probe used `external_research`.

Round 1 of this document claimed "every other H2 in a bob report is
`## ${section.heading}`" and "the rendered document has exactly one H1". **Both are
false** and are withdrawn. Prose at `:1100` carrying `# Injected H1` produces a
second H1; the table above shows ten further H2 sources besides `heading`
(11 channels − `heading` = 10).

Two useful controls on the prefixed channels:

- A repro step containing `## F-101 Should NOT mint` with **no** newline does *not*
  mint: the `${i + 1}. ` prefix at `:1117` keeps the `##` off column 0.
  `finding_count` stayed at 2, unchanged from the benign baseline. The prefix is a
  real defence — it just does not survive a `\n`.
- `assertSafeDomain` genuinely rejects `a/b`, `a\b` and `..` (each threw
  `target_domain contains invalid path characters`), and accepts
  `"x\n\n## F-105 Phantom from domain"` verbatim. Path-safety is enforced;
  line-safety is not.

The composer's own comment at `:1164-1168` already recognises this class — it keeps
caller strings out of *refusal messages* so a credential pasted into a heading cannot
leak back through the error. The same strings are still emitted into the document
itself.

The composer emits **six** literal server-rendered H2s, none of them caller text.
Extracted and counted from source rather than transcribed:

```
literal_h2_count=6            (floor asserted at 6)
  :939   "CVSS / CWE (informational)"                    exempt=false
  :988   "Coverage closure (informational)"              exempt=false
  :1060  "Surfaces Not Tested (blocked prerequisites)"   exempt=false
  :1090  "Severity Summary"                              exempt=false
  :1111  "Reproduction Steps"                            exempt=false
  :1126  "Operator Amendments"                           exempt=false
checked=6  matched_exemption=0
```

That list is complete **as an enumeration of literal string constants**. It is not a
complete enumeration of H2s in a rendered report, because an H2 can arrive inside any
of the eleven interpolated values above — which is exactly the mistake round 1 made.

### 4c. CONFIRMED: bob's own markdown parser treats an H2 as a finding boundary, with one narrow exemption

`mcp/core/audit-report-parser.js` is hacker-bob's in-tree markdown-to-findings parser,
reached through `bob_ingest_audit_report`. The tool module requires the entry point at
`mcp/tools/ingest-audit-report.js:3`, wraps it at `:5-11`, and binds it as
`handler` at `:32`; the schema text that states the rule outright — *"H1 is the title;
H2 sections are findings"* — is the `raw_markdown` description at `:23`.

The grammar, at `mcp/core/audit-report-parser.js:163-172` (`:172` is the closing
brace shown below):

```js
if (/^##\s+/.test(line)) {
  const headingText = line.replace(/^##\s+/, "").trim();
  // Treat H2 as a finding boundary unless it's a top-level summary keyword.
  if (currentFinding == null && /^(?:summary|overview|introduction|scope)\b/i.test(headingText)) {
    startSection("_summary");
    continue;
  }
  startFinding(headingText);
  continue;
}
```

Three properties settle the footgun:

1. **Every H2 that is not exempted mints a finding** (`:170` → `startFinding`,
   `:125-142`), taking the heading text as the finding title. The absolute "every H2"
   is wrong — property 2 is the exception, and it is stated here rather than as an
   afterthought.
2. **The only exemption is positional and prefix-anchored** (`:166`): it fires only
   while `currentFinding == null` — i.e. before the first finding — *and* only when
   the heading **starts with** `summary`, `overview`, `introduction`, or `scope`.
   Counted against the six literal H2s the composer emits: `checked=6,
   matched_exemption=0`. `Severity Summary` starts with "Severity", not "summary".
3. **An H3 is not reliably a subheading.** Four distinct behaviours, all verified by
   execution:
   - A **bare typed H3** — `### Remediation`, `### Severity`, `### Description`,
     `### Scope|Affected|Location|Target` — routes into a typed field (`:175-178`).
     Verified: `### Remediation` / `patch it` produced `recommendation: "patch it"`.
   - A **typed keyword with trailing text** does *not* route, because all four
     patterns (`:25-28`) are `$`-anchored. Verified: `### Remediation and follow-up`
     fell to the `else` at `:179-182` and its heading text was inlined into
     `description`.
   - Any **unknown H3** under an open finding is likewise absorbed into that
     finding's body buffer (`:179-182`; the code comment there reads
     "Unknown H3 header"). That is the "attached to a finding instead of staying
     global" outcome from the original claim — reached by position, not by a token
     regex.
   - An H3 with **no finding open** fails the `currentFinding != null` guard at
     `:173` entirely, falls through to `buffer.push(line)` at `:189`, and lands in
     the document summary. Verified: `### F-3 Orphan H3` placed before the first H2
     produced no finding at all.

   Round 1 of this document stated this as an unqualified "a document-level H3 is
   swallowed into whatever finding is open". That over-generalised; the corrected
   four-way split is above.

### 4d. CONFIRMED: bob will emit an `### F-N` heading for a finding that does not exist

`repro_steps_by_finding[].finding_id` is validated as a **plain 64-char string**
(`mcp/tools/compose-report.js:821`):

```js
const findingId = assertString(entry.finding_id, `repro_steps_by_finding[${idx}].finding_id`, { maxLength: 64 });
```

It is not matched against `FINDING_ID_RE` (see the controlled negative in §3: zero
`FINDING_ID_RE` / `parseFindingId` references in this file against 48 tree-wide), and
it is not checked for membership in the session's finding ledger. The path is short
enough to state exhaustively: `normalizeReproSteps` (`:812-834`) does the length
check and returns `{ finding_id, steps }` at `:832`; the handler calls it at `:1256`
and passes the result straight to `renderMarkdown` at `:1326`; `renderMarkdown` writes
it as a heading at `:1114`. No step in that chain consults a findings artifact.

Round 1 of this document supported this with "grep for `finding_id` across the
`handler` body (`compose-report.js:1240-1345`) returns nothing." **That sentence was
false in two ways** and is withdrawn: the handler is `function handler(args)` at
`:1244` through its closing brace at `:1377`, not `1240-1345`; and `finding_id` *does*
occur inside it, at `:1368` and `:1370` (`packReportProjection.handled_finding_ids`,
which concerns capability-pack sections, not repro steps). The conclusion stands on
the traced chain above, not on a grep.

So the composer itself will write `### F-9` into report.md when no `F-9` was ever
recorded.

### 4e. The silence is structural, not observed

Every reproduction above returned `parser_warnings: []`. That is **not** evidence
that the parser checked anything. `mcp/core/audit-report-parser.js` declares
`const warnings = []` at `:86` and contains exactly **one** `warnings.push` site —
`warnings.push("no_findings_detected")` at `:200`, guarded by
`if (findings.length === 0)` at `:199` — returned as `parser_warnings` at `:233`.
Positive control for that count: the file has 7 `.push(` sites in total, of which 1
is `warnings.push`.

The array's total capacity is one string, and it can only be non-empty when zero
findings parse. For any document yielding ≥1 finding, `[]` is structurally forced.
Both directions verified:

```
zero-finding doc ("# Only a title" + prose, no H2):
  finding_count=0  parser_warnings=["no_findings_detected"]
any probe in §4b:
  finding_count>=2 parser_warnings=[]
```

Read `[]` as "the parser has no check that could fire here", not as "the parser
checked and found nothing wrong". Round 1 of this document presented it as the
latter.

### The headline reproduction

Feeding a document produced by `renderMarkdown` — one real finding `F-1`, one
intended-global `## Methodology and Scope Notes`, one `## F-9 …` appendix heading
naming a finding that does not exist — through `parseAuditReportMarkdown` yields
**5 findings from 1**:

```
finding_count=5
  "Severity Summary"                        -> "One high, one medium."
  "F-1 Unauthenticated admin read"          -> "<!-- section_id: s1 … -->\n\nImpact prose."
  "Methodology and Scope Notes"             -> "<!-- section_id: s2 … -->\n\nGlobal note…"
  "F-9 Appendix: rate-limit observations"   -> "<!-- section_id: s3 … -->\n\nAppendix prose."
  "Reproduction Steps"                      -> "F-1\n\n1. GET /admin"
parser_warnings=[]
```

Note the last row: `### F-1` (emitted at `mcp/tools/compose-report.js:1114`) is an
unknown H3 under the open "Reproduction Steps" finding, so
`mcp/core/audit-report-parser.js:181` buffered its text and `flushSection` wrote the
buffer into `description` at `:116`, the `currentSection === "_default"` branch that
`startFinding` set at `:141`. The real `F-1` is thus recorded as *body text of a
phantom*. Note also that the section-id HTML comment emitted at
`mcp/tools/compose-report.js:1098` is not stripped — it becomes the first line of
the description of each of the three section-derived findings.

### What this means when you author sections

The guidance below covers all eleven channels from §4b, not just `heading`. A reader
who guards only the heading still mints phantoms through prose, and round 1 of this
document made exactly that error.

- **Keep finding-id-shaped tokens out of every caller-supplied string that reaches
  report.md**, not just `heading`. `## F-9 Appendix …` reads to any heading-keyed
  consumer as finding `F-9`, and bob's own parser mints it — but so does an `## F-9`
  written inside `prose`, `severity_summary`, an amendment's `new_prose` or
  `rationale`, an `evidence_ref`, a repro step, or a `section_id`. Use the token only
  when the text really is about that finding.
- **Never put a newline in a value that renders under a prefix.** `heading`,
  `section_id`, `evidence_refs[]`, `repro_steps_by_finding[].finding_id`, `steps[]`,
  `amendments[].section_id` and `amendments[].rationale` all render behind a prefix
  that a `\n` escapes. None of the validators strips one.
- **Do not expect a document-level heading to stay document-level.** There is no
  "global section" concept in the rendered markdown: to bob's parser an H2 is a
  finding boundary, and an H3 is either a typed field (only when the heading is
  exactly the bare keyword) or body text absorbed into whatever finding is open.
- **Keep global material above the first finding section and prefix it** with
  `Summary`, `Overview`, `Introduction`, or `Scope` — that is the one and only
  exemption the parser honours, and it only works before the first finding
  (`mcp/core/audit-report-parser.js:166`).
- **Pass `repro_steps_by_finding[].finding_id` values you have actually recorded.**
  Nothing checks them against the ledger.
- **Do not treat an empty `parser_warnings` as a clean bill of health.** It holds at
  most one string and only when nothing parsed at all.

### Scope of this hazard

`parseAuditReportMarkdown` has exactly one caller: `ingestAuditReport` at
`mcp/core/audit-report-parser.js:287`, which parses the `raw_markdown` **tool
argument** (asserted a non-empty string at `:283`), not a file on disk.
`ingestAuditReport` in turn is required only by
`mcp/tools/ingest-audit-report.js:3` and dispatched as `bob_ingest_audit_report`'s
handler at `:32`. So nothing in this repo round-trips a composed `report.md` back
through the parser today. That scoping is stated so the reproduction is not mistaken
for a live data-flow inside bob.

The constraint still belongs here, for two reasons that are verifiable rather than
speculative:

1. `bob_ingest_audit_report` accepts arbitrary caller `raw_markdown`, so the grammar
   above is reachable with any document, including one a composer produced.
2. The rendered `report.md` leaves bob verbatim. `report.md` is read at
   `mcp/core/report-finalize.js:75`, `mcp/core/session/session-summary.js:219`,
   `mcp/core/telemetry/pipeline-session-artifacts.js:990`,
   `mcp/domains/physical/physical-lifecycle-capstone.js:455`, `mcp/core/telemetry/pipeline-analytics.js:1200`,
   `mcp/core/bob-export.js:253` and — most directly —
   `mcp/tools/export-security-hub-finding.js:139`, which embeds the whole file
   into an exported evidence bundle. None of those calls the parser, but each carries
   the document, and its heading ambiguity, outward. The composer is the producer of
   that ambiguity, so the constraint belongs in the composer's docs.

---

## Round-2 correction ledger

Round 1 of this document failed adversarial review on accuracy. Each defect raised is
either fixed above or refuted here with the anchor that settles it. Nothing was
dropped.

| # | Defect raised | Disposition |
| --- | --- | --- |
| D1 / D7 | "Every other H2 is `## ${section.heading}`"; "exactly one H1" — false completeness | **FIXED.** Both sentences withdrawn; §4b now enumerates 11 interpolation sites, all reproduced |
| D2 | Vacuous negative grep, no positive control | **FIXED.** §4a and §3 now pair every zero-hit grep with a control in the same shape |
| D3 | `parser_warnings: []` presented as an observed pass | **FIXED.** New §4e states the one-string capacity, `:86` / `:199-200` / `:233`, both directions verified |
| D4a | "0 of 6" table unfloored | **FIXED.** Now produced by an extraction reporting `checked=6 matched_exemption=0` with a hardcoded floor of 6 |
| D4b / D12 | `REPRO_STEPS_PER_FINDING_MAX` cited at `:824` | **FIXED.** Compared at `:823`, throws at `:824`; whole constants table re-grepped |
| D4c | Six-literal-H2 rows correct, generalisation false | **FIXED.** Rows kept, now extracted and counted; the false generalisation is called out explicitly |
| D5 | "free-form text up to 64 chars" overstated | **FIXED.** §3 now states the cap is schema-only (`:1396`) and `normalizeSection` (`:787-810`) applies none |
| D5 | `ingest-audit-report.js:4-11` cited for the schema text | **FIXED.** Require at `:3`, handler `:5-11`, quoted text at `:23`, bound at `:32` |
| D6 | Scope paragraph accurate, not overstated | **NO CHANGE NEEDED** — kept, and strengthened with the `:287` / `:283` / `:3` / `:32` chain and the seven `report.md` readers |
| D8 | "exactly one finding-id grammar" false | **FIXED.** 3 spellings / 12 sites enumerated and counted, including a third inline copy the review did not list (`mcp/core/waves/wave-handoff-contracts.js:484`) |
| D9 | Handler extent `1240-1345`; "grep returns nothing" false | **FIXED.** Handler is `:1244-1377`; `finding_id` occurs at `:1368` and `:1370`; conclusion re-grounded on the traced chain `:821 → :832 → :1256 → :1326 → :1114` |
| D10 | "No such regex exists anywhere in this repo" overstated | **FIXED.** Narrowed to what the grep covers; the verdict now rests on enumerating all 34 parser regex literals and the 11 heading-reachable ones |
| D11 | H3 claim over-broad | **FIXED.** Four-way split (bare typed / typed-with-trailing-text / unknown / no-finding-open), each verified by execution |
| D13 | "Every H2 mints a finding" self-contradicts the exemption | **FIXED.** Property 1 now reads "every H2 that is not exempted", with the exception on the same line |
| D14 | What held | **KEPT** — all re-derived independently for this revision, not carried over on trust |
| D15 | Process/scope: Verify exits 0, no tracked file touched | **NO CHANGE NEEDED** — this revision edits the same single owned file in place |
| FU1 (opt.) | Verify line is three single-token greps; passes on a near-empty file | **NOTED, NOT ACTED ON.** The Verify command belongs to the orchestrator, not to this node. A floor such as `[ "$(grep -c '^## \|^### ' docs/report-md-format-facts.md)" -ge 10 ]` would close it; this document satisfies that today |
| FU3 (1) | Round 1 bypassed a refused `Write` via `cp`, an unconditional overwrite | **NOT REPEATED.** `Write` refused this filename again; this revision used in-place `Edit` on a file already read in-session rather than an unconditional copy |

"use strict";

// Plane O Cycle O.9 — orchestrator OSS branch + `/bob-evaluate <repo-path>` +
// re-entry reconciliation contract (O-P8).
//
// Asserts on the structural shape of the rendered orchestrator role, not on
// stylistic phrasing. The orchestrator role is a single role (per O-D1) that
// branches on the first non-flag token of $ARGUMENTS:
//   - URL  → web mode → bob_init_session
//   - path → OSS mode → bob_init_repo_session + repo lenses + repo tools
// Remote shapes (git@, ssh://, owner/repo) are refused at this entry point.
//
// The re-entry contract (O-P8) covers BOTH web and OSS modes per Reviewer D's
// carry-back: the bug surfaced first in OSS sessions but the underlying
// contract is general. On every re-entry, the orchestrator MUST call
// bob_read_state_summary BEFORE issuing any new lens dispatch.
//
// Cross-mode (O-P6): a session may carry both target_repo AND target_url. The
// rendered narrative must name BOTH surface families so the orchestrator
// understands the OSS lens runs on the repo surface while the HTTP lens runs
// on the URL surface — both feeding the same frontier ledger.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  renderClaudeRole,
  renderClaudePromptBody,
} = require("../scripts/lib/claude-role-renderer.js");
const {
  hackerBobSkillAllowedTools,
  mcpPermissionForTool,
} = require("../adapters/claude/config.js");
const {
  TOOL_MANIFEST,
} = require("../mcp/lib/tool-registry.js");
const {
  ROLE_DEFINITIONS,
  mcpToolNamesForRole,
} = require("../mcp/lib/role-model.js");
const {
  OSS_LENSES,
  REPO_WORKFLOW_TEXT,
  buildBriefExtrasForProfile,
  readAssignmentBrief,
} = require("../mcp/lib/assignment-brief.js");
const {
  initRepoSession,
  buildRepoInventory,
} = require("../mcp/lib/repo-target.js");
const {
  prepareRepoEnv,
} = require("../mcp/lib/repo-env.js");
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  advanceSession,
} = require("../mcp/lib/session-state.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  currentSurfaces,
} = require("../mcp/lib/frontier-projections.js");

const ROOT = path.join(__dirname, "..");

// ── Helpers ──────────────────────────────────────────────────────────────────

function renderedOrchestratorBody() {
  // The skill renders frontmatter + orchestrator prompt body. The frontmatter
  // is the permission allowlist (auto-derived from the role bundle); the body
  // is what the orchestrator actually reads at run time.
  return renderClaudeRole("orchestrator");
}

function tempRepoFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-orch-oss-"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    name: "synthesized-oss-fixture",
    version: "0.0.0",
  }, null, 2));
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src", "index.js"), "module.exports = 1;\n");
  return dir;
}

function parseResult(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-orch-oss-home-"));
  process.env.HOME = tempHome;
  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };
  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

// ── Argument-axis branching (web vs OSS repo) ────────────────────────────────

test("orchestrator role names both axes: URL → bob_init_session, repo path → bob_init_repo_session", () => {
  const body = renderedOrchestratorBody();
  // Web-mode init tool must remain referenced (regression).
  assert.match(body, /bob_init_session/, "URL-mode entry must still name bob_init_session");
  // OSS-mode init tool must be referenced.
  assert.match(body, /bob_init_repo_session/, "OSS-mode entry must name bob_init_repo_session");
  // The branching rule must say "first non-flag token" picks the axis — this
  // is the load-bearing parser contract; renaming it would silently break
  // operator expectations.
  assert.match(
    body,
    /first non-flag token/i,
    "orchestrator must specify the parser contract for the first token of $ARGUMENTS",
  );
});

test("orchestrator role refuses remote-shape inputs per O-P1 (no git clone from this entry)", () => {
  const body = renderedOrchestratorBody();
  // The hard rule must be stated explicitly. We assert on the structural
  // anchors: the keyword `clone` must appear as a forbidden operation, and at
  // least one of the remote-shape exemplars must appear so the operator can
  // pattern-match their own input.
  assert.match(body, /no remote clone|never performs a `git clone`|no\b.*\bgit clone/i,
    "orchestrator must declare 'no remote clone' as a hard rule");
  // The remote shapes the parser refuses (at least one of the exemplars):
  const remoteShapes = [/git@/, /git\+https/, /ssh:\/\//, /owner\/repo/i];
  assert.ok(
    remoteShapes.some((re) => re.test(body)),
    "orchestrator must enumerate at least one remote-shape exemplar (git@, git+, ssh://, owner/repo)",
  );
  // O-P1 invariant ID must be mentioned (it's the source-of-truth anchor).
  assert.match(body, /O-P1/, "orchestrator must cite the O-P1 invariant");
});

test("orchestrator role declares O-P2: source visibility ≠ permission to attack hosted instance", () => {
  const body = renderedOrchestratorBody();
  assert.match(body, /O-P2/, "orchestrator must cite the O-P2 invariant");
  // The key concept: source visibility does NOT authorize attacking a deployed
  // sibling. We assert on the structural phrasing (one of the canonical forms)
  // rather than an exact string.
  assert.match(
    body,
    /source visibility (≠|is not|!=|does not).*permission|never auto-derives.*target_url/i,
    "orchestrator must declare that source visibility is not permission to attack hosted instance",
  );
  // The cross-mode escape hatch must be named (O-P6) so the operator knows
  // there IS a legitimate way to combine repo + URL work — they just have to
  // pass a second URL explicitly.
  assert.match(body, /cross-mode|O-P6|target_url companion/i,
    "orchestrator must name the cross-mode opt-in path (O-P6 target_url companion)");
});

// ── Repo-mode operator flags ─────────────────────────────────────────────────

test("orchestrator role names the repo-mode operator flags --build, --allow-network, --target-id", () => {
  const body = renderedOrchestratorBody();
  assert.match(body, /--build\b/, "orchestrator must document the --build flag");
  assert.match(body, /--allow-network\b/, "orchestrator must document the --allow-network flag");
  assert.match(body, /--target-id\b/, "orchestrator must document the --target-id flag");
});

// ── OSS lens dispatch (3 OSS lenses; web lenses regression) ──────────────────

test("orchestrator role dispatches the three OSS lenses for repo-bound surfaces", () => {
  const body = renderedOrchestratorBody();
  for (const lens of OSS_LENSES) {
    assert.match(body, new RegExp(`\\b${lens}\\b`),
      `orchestrator must name OSS lens '${lens}' in dispatch narrative`);
  }
  // Regression: HTTP lenses must still be named for the web axis.
  for (const lens of ["behavior_probe", "browser_behavior_probe", "surface_scout"]) {
    assert.match(body, new RegExp(`\\b${lens}\\b`),
      `orchestrator must still name web lens '${lens}' (regression)`);
  }
});

// ── Repo-mode dispatch names the repo-bound MCP tools ────────────────────────

test("orchestrator role's repo-mode SETUP names bob_repo_inventory, bob_repo_check, bob_repo_docker_run", () => {
  const body = renderedOrchestratorBody();
  // bob_repo_inventory is the orchestrator-owned enumeration call.
  assert.match(body, /bob_repo_inventory/,
    "orchestrator must name bob_repo_inventory in the repo-mode SETUP flow");
  // bob_repo_prepare_env is the orchestrator-owned env preparation call.
  assert.match(body, /bob_repo_prepare_env/,
    "orchestrator must name bob_repo_prepare_env in the repo-mode SETUP flow");
  // bob_repo_check and bob_repo_docker_run are evaluator tools — the
  // orchestrator's narrative must REFERENCE them so the operator sees the full
  // tool surface that will appear in dispatch, but the orchestrator itself
  // does NOT call them (the role-bundle excludes the orchestrator from those
  // tools per O.4 / Reviewer D).
  assert.match(body, /bob_repo_check/,
    "orchestrator must reference bob_repo_check (called by evaluators) in the OSS narrative");
  assert.match(body, /bob_repo_docker_run/,
    "orchestrator must reference bob_repo_docker_run (called by evaluators) in the OSS narrative");
});

test("orchestrator role-bundle does NOT grant docker_run or repo_check (evaluator-only per O.4)", () => {
  // The orchestrator dispatches but never executes docker. bob_repo_docker_run
  // and bob_repo_check live in evaluator/verifier/evidence bundles, not the
  // orchestrator bundle.
  const orchestratorTools = mcpToolNamesForRole("orchestrator");
  assert.ok(
    !orchestratorTools.includes("bob_repo_docker_run"),
    "orchestrator role-bundle must NOT include bob_repo_docker_run (evaluator-only per O.4)",
  );
  assert.ok(
    !orchestratorTools.includes("bob_repo_check"),
    "orchestrator role-bundle must NOT include bob_repo_check (evaluator-shared per O.5)",
  );
  // Orchestrator DOES own the bootstrap and orchestration-side repo tools.
  assert.ok(
    orchestratorTools.includes("bob_init_repo_session"),
    "orchestrator must own bob_init_repo_session (session bootstrap)",
  );
  assert.ok(
    orchestratorTools.includes("bob_repo_inventory"),
    "orchestrator must own bob_repo_inventory (frontier enumeration)",
  );
  assert.ok(
    orchestratorTools.includes("bob_repo_prepare_env"),
    "orchestrator must own bob_repo_prepare_env (Dockerfile.bob synthesis)",
  );
});

// ── Same lifecycle, different SETUP sub-flow ─────────────────────────────────

test("orchestrator role keeps the same six-state lifecycle regardless of axis", () => {
  const body = renderedOrchestratorBody();
  // The six lifecycle states must appear as section headings, in canonical
  // order. The fact that the OSS branch reuses the same lifecycle (per O-P5)
  // is asserted by the absence of any new STATE: section AND the presence of
  // all six existing ones.
  const states = ["SETUP", "OPEN_FRONTIER", "CLAIM_FREEZE", "VERIFY", "GRADE", "REPORT"];
  for (const state of states) {
    assert.match(body, new RegExp(`## STATE: ${state}\\b`),
      `orchestrator must keep lifecycle state '${state}' (O-P5 reuse)`);
  }
  // No parallel OSS state machine — repo-mode SETUP is a sub-flow inside
  // SETUP, not a parallel lifecycle.
  assert.equal(
    body.match(/## STATE:/g).length,
    states.length,
    "orchestrator must declare exactly six STATE sections; no parallel OSS lifecycle",
  );
});

test("orchestrator role's SETUP state contains a repo-mode sub-flow stanza", () => {
  const body = renderedOrchestratorBody();
  // The repo-mode SETUP stanza must be inside the SETUP section, not in a
  // parallel section. We assert by checking the substring distance between
  // the SETUP marker and the repo-mode stanza.
  const setupIdx = body.indexOf("## STATE: SETUP");
  const nextStateIdx = body.indexOf("## STATE: OPEN_FRONTIER");
  assert.ok(setupIdx >= 0, "SETUP section must exist");
  assert.ok(nextStateIdx > setupIdx, "OPEN_FRONTIER section must follow SETUP");
  const setupSection = body.slice(setupIdx, nextStateIdx);
  assert.match(setupSection, /repo[-_ ]mode|OSS axis|Repo-mode SETUP/i,
    "SETUP section must contain an explicit repo-mode sub-flow");
  assert.match(setupSection, /bob_init_repo_session/,
    "SETUP section must name bob_init_repo_session in the repo-mode sub-flow");
});

// ── Re-entry reconciliation contract (O-P8) ──────────────────────────────────

test("orchestrator role encodes the O-P8 re-entry reconciliation contract", () => {
  const body = renderedOrchestratorBody();
  // The contract must be named (so future readers can find it).
  assert.match(body, /O-P8/, "orchestrator must cite the O-P8 invariant by name");
  // The contract has three load-bearing claims:
  //   1. EVERY re-entry turn must call bob_read_state_summary FIRST.
  //   2. The call comes BEFORE any new lens dispatch / spawn / mutation.
  //   3. The contract applies to BOTH web and OSS (per Reviewer D carry-back).
  assert.match(
    body,
    /EVERY re-entry|every re-entry|re-entry turn/i,
    "contract must say 'every re-entry turn' — not 'sometimes' or 'when convenient'",
  );
  assert.match(
    body,
    /bob_read_state_summary.{0,400}(BEFORE|first|before)/is,
    "contract must order: bob_read_state_summary BEFORE new dispatch",
  );
  assert.match(
    body,
    /both web and OSS|web and OSS|OSS and web/i,
    "contract must apply to BOTH web and OSS modes per Reviewer D",
  );
});

test("orchestrator's re-entry contract names the reconciliation triggers (pending wave / pending merge / unsettled bundle)", () => {
  const body = renderedOrchestratorBody();
  // The triggers must be enumerated so the orchestrator knows when to
  // reconcile vs. when to proceed.
  assert.match(body, /pending_wave|pending wave/i,
    "contract must name 'pending wave' as a reconciliation trigger");
  assert.match(body, /pending merge|pending_merge|CLAIM_FREEZE_PENDING/i,
    "contract must name 'pending merge' / CLAIM_FREEZE_PENDING as a trigger");
  assert.match(body, /AgentRun bundle|in-flight AgentRun/i,
    "contract must name 'in-flight AgentRun bundle' as a trigger");
});

test("orchestrator's re-entry contract names the merged/pending decision branches", () => {
  const body = renderedOrchestratorBody();
  // On `merged` → continue. On `pending` → report counts and stop.
  assert.match(body, /\bmerged\b.*continue|merged.*next wave|on .?merged.?.*continue/i,
    "contract must say: on 'merged', continue with next wave");
  assert.match(body, /\bpending\b.*(report|stop)|received\/expected|received\/expected handoff/i,
    "contract must say: on 'pending', report received/expected counts and stop");
  // The contract must mention missing/invalid/unexpected handoffs (the three
  // bucket categories MVP commit 845939a carried back).
  assert.match(body, /missing|invalid|unexpected/i,
    "contract must enumerate missing/invalid/unexpected handoff buckets");
});

// ── Cross-mode (O-P6): target_repo + target_url ──────────────────────────────

test("orchestrator role names cross-mode (target_repo + target_url) per O-P6", () => {
  const body = renderedOrchestratorBody();
  assert.match(body, /O-P6/, "orchestrator must cite the O-P6 invariant");
  assert.match(body, /target_repo.*target_url|target_url.*target_repo|cross-mode/i,
    "orchestrator must name cross-mode (target_repo + target_url)");
  // Cross-mode brief must reference BOTH surface families.
  assert.match(body, /repo.*surface|repo-bound/i, "cross-mode narrative must name repo surface family");
  assert.match(body, /URL.*surface|HTTP.*surface|hosted instance|web surface/i,
    "cross-mode narrative must name URL/HTTP surface family");
});

// ── URL-mode dispatch unchanged (regression) ─────────────────────────────────

test("URL-mode SETUP path unchanged: signup detect, http_scan, auto-signup, surface-router still wired", () => {
  const body = renderedOrchestratorBody();
  // The URL-mode SETUP playbook from prior cycles must remain intact. These
  // are the load-bearing tool names that a web-mode operator depends on.
  for (const tool of [
    "bob_init_session",
    "bob_signup_detect",
    "bob_http_scan",
    "bob_auto_signup",
    "bob_temp_email",
    "bob_auth_store",
    "bob_route_surfaces",
    "bob_read_surface_routes",
  ]) {
    assert.match(body, new RegExp(`\\b${tool}\\b`),
      `URL-mode SETUP regression: orchestrator must still name '${tool}'`);
  }
});

test("URL dispatch produces the same web brief shape (regression for non-OSS sessions)", () => {
  // The orchestrator role is a single static prompt template that is rendered
  // identically regardless of the operator's $ARGUMENTS at run time. We assert
  // that the rendered body is byte-identical across two render calls (no
  // hidden RNG / clock dependence), and that the rendered body still carries
  // the seed-mapping / surface-router agent spawns the web flow depends on.
  const first = renderClaudeRole("orchestrator");
  const second = renderClaudeRole("orchestrator");
  assert.equal(first, second, "orchestrator render must be deterministic (no RNG/clock)");
  // Web-mode template spawns: seed discovery + surface router.
  assert.match(first, /surface-discovery-agent/, "web mode must still spawn surface-discovery-agent");
  assert.match(first, /surface-router-agent/, "web mode must still spawn surface-router-agent");
  // Web-mode evaluator template names the HTTP lens prioritization inputs.
  assert.match(first, /bob_read_assignment_brief/, "evaluator spawn must call bob_read_assignment_brief");
});

// ── Repo-path dispatch produces a brief referencing the repo tools ───────────

test("repo-path dispatch: orchestrator narrative directs evaluators to bob_repo_inventory + bob_repo_check + bob_repo_docker_run", () => {
  // The orchestrator's evaluator spawn template carries the prompt the
  // evaluator reads on startup. The OSS-lens evaluator brief (assembled by
  // the brief-slice registry) carries the `repo_workflow` slice — that slice
  // is what tells the evaluator to lead with repo tools. We assert the
  // orchestrator's *narrative* references those tools so the operator can
  // verify dispatch will work end-to-end before launching a wave.
  const body = renderedOrchestratorBody();
  // Each repo tool name must appear at least once.
  for (const tool of ["bob_repo_inventory", "bob_repo_check", "bob_repo_docker_run", "bob_repo_prepare_env"]) {
    assert.match(body, new RegExp(`\\b${tool}\\b`),
      `repo-path dispatch must reference '${tool}'`);
  }
  // The repo_workflow slice content (the actual stanza the evaluator reads in
  // a repo-bound brief) must independently name the same tools — verified by
  // pulling REPO_WORKFLOW_TEXT and asserting on its content. This proves the
  // orchestrator narrative + the slice registry agree on the dispatch shape.
  for (const tool of ["bob_repo_inventory", "bob_repo_check", "bob_repo_docker_run"]) {
    assert.match(REPO_WORKFLOW_TEXT, new RegExp(`\\b${tool}\\b`),
      `repo_workflow slice content must name '${tool}'`);
  }
});

test("OSS brief extras partition technique packs by task lens and keep CLI packs repo-scoped", () => {
  const extras = buildBriefExtrasForProfile("oss", {
    domain: "repo-oss-brief-direct",
    surface: {
      id: "repo:module:src-parser.c",
      title: "src/parser.c",
      surface_type: "oss_native_code",
      endpoints: ["src/parser.c"],
      language: "c",
    },
    assignment: {
      surface_id: "repo:module:src-parser.c",
      task_lens: "fuzz_run",
    },
    routeMetadata: {
      capability_pack: "oss_native_code",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      context_budget: {
        candidate_pack_limit: 5,
        full_pack_read_limit: 2,
        attempt_log_required: true,
      },
    },
  });

  assert.equal(extras.repo_workflow, REPO_WORKFLOW_TEXT);
  assert.equal(extras.code_surface_pack.route_metadata.brief_profile, "oss");
  assert.ok(extras.technique_packs.selected.some((pack) => pack.id === "oss_native_code"));
  assert.ok(extras.technique_packs.other_applicable.some((pack) => pack.id === "oss_ci_cd"));
  assert.equal(extras.technique_packs.selection_limits.selected_count, extras.technique_packs.selected.length);
  assert.match(extras.cli_tools, /semgrep|trivy/);
});

test("readAssignmentBrief accepts routed OSS brief_profile and emits OSS technique packs", () => withTempHome(async (home) => {
  const repo = path.join(home, "brief-oss-native");
  fs.mkdirSync(repo, { recursive: true });
  fs.writeFileSync(path.join(repo, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.22)\nproject(brief_oss C)\n");
  fs.mkdirSync(path.join(repo, "src"), { recursive: true });
  fs.writeFileSync(path.join(repo, "src", "parser.c"), "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  fs.mkdirSync(path.join(repo, "fuzz", "corpus"), { recursive: true });
  fs.writeFileSync(path.join(repo, "fuzz", "corpus", "minimal.bin"), "AAAA");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-brief-oss-native" }));
  parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  await prepareRepoEnv({ target_domain: init.target_domain });
  materializeFrontier(init.target_domain, { write: true });
  parseResult(routeSurfaces({ target_domain: init.target_domain }));
  const surfaces = currentSurfaces(init.target_domain).surfaces;
  const nativeSurface = surfaces.find((surface) => surface.title === "src/parser.c");
  assert.ok(nativeSurface, "expected native parser surface");
  assert.equal(nativeSurface.file_path, "src/parser.c");
  assert.equal(nativeSurface.language, "c");
  assert.equal(nativeSurface.native_source, true);
  parseResult(advanceSession({ target_domain: init.target_domain, to_state: "OPEN_FRONTIER" }));
  const wave = parseResult(startWave({
    target_domain: init.target_domain,
    wave_number: 1,
    assignments: [{
      agent: "a1",
      surface_id: nativeSurface.id,
      task_lens: "fuzz_run",
    }],
  }));
  const assignment = wave.assignments[0];
  assert.equal(assignment.capability_pack, "oss_native_code");
  assert.equal(assignment.brief_profile, "oss");

  const brief = JSON.parse(readAssignmentBrief({
    target_domain: init.target_domain,
    wave: "w1",
    agent: "a1",
  }));
  assert.equal(brief.run_context.brief_profile, "oss");
  assert.equal(brief.run_context.capability_pack, "oss_native_code");
  assert.deepEqual(brief.valid_surface_ids, surfaces.map((surface) => surface.id));
  assert.ok(brief.repo_workflow);
  assert.equal(brief.code_surface_pack.assigned_surface.file_path, "src/parser.c");
  assert.equal(brief.code_surface_pack.assigned_surface.language, "c");
  assert.equal(brief.code_surface_pack.assigned_surface.native_source, "true");
  assert.equal(brief.repo_env_recommendations.seed_corpus_count, 1);
  assert.equal(brief.repo_env_recommendations.seed_corpus[0].rel_path, "fuzz/corpus");
  const fuzzCommand = brief.repo_env_recommendations.recommended_commands.find((command) => command.role === "fuzz");
  assert.ok(fuzzCommand, "brief must expose a fuzz recommendation when seed corpus exists");
  assert.equal(fuzzCommand.seed_path, "fuzz/corpus");
  assert.ok(brief.technique_packs.selected.some((pack) => pack.id === "oss_native_code"));
  assert.ok(!String(JSON.stringify(brief)).includes("Unsupported brief profile"));
}));

// ── Re-entry simulation: synthesized pending wave → reconciliation first ─────

test("re-entry simulation: orchestrator narrative directs to call bob_read_state_summary first on pending-wave state", () => {
  // We can't run the orchestrator (it's a prompt template), so we simulate the
  // operator's mental model: given a synthesized state.summary with a pending
  // wave, what does the orchestrator narrative tell them to do FIRST?
  //
  // The contract is a textual one. We assert that the resume-path narrative
  // orders the reconciliation steps:
  //   1. Read state summary
  //   2. If pending wave, apply wave merge (reconciliation)
  //   3. Only then dispatch new lens work
  const body = renderedOrchestratorBody();
  // Find the Resume section.
  const resumeIdx = body.indexOf("## Resume");
  assert.ok(resumeIdx > 0, "Resume section must exist");
  const setupIdx = body.indexOf("## STATE: SETUP");
  const resumeSection = body.slice(resumeIdx, setupIdx > resumeIdx ? setupIdx : resumeIdx + 4000);
  // First action: bob_read_state_summary.
  const stateSummaryIdx = resumeSection.indexOf("bob_read_state_summary");
  assert.ok(stateSummaryIdx >= 0, "Resume section must call bob_read_state_summary");
  // Reconciliation via bob_apply_wave_merge must appear AFTER the state-summary
  // call in the resume narrative ordering.
  const applyMergeIdx = resumeSection.indexOf("bob_apply_wave_merge");
  assert.ok(applyMergeIdx > stateSummaryIdx,
    "Resume narrative must order bob_read_state_summary BEFORE bob_apply_wave_merge");
  // The narrative must explicitly stop on `pending` and ask the operator (no
  // silent retry).
  assert.match(resumeSection, /pending.{0,400}(stop|resume again|force-merge)/is,
    "Resume narrative must stop on 'pending' and ask the operator");
});

test("re-entry contract applies even when the operator did not type 'resume' (worker-completion notifications)", () => {
  // Reviewer D's carry-back: the contract is not just for `resume`. It applies
  // to EVERY orchestrator re-entry, including background worker-completion
  // notifications and `wait_agent` results. The contract section above the
  // Resume section must say this explicitly.
  const body = renderedOrchestratorBody();
  // The contract enumerates the re-entry triggers — at least one of:
  //   - operator resume
  //   - background worker-completion notification
  //   - wait_agent result
  //   - "still running?" check
  const triggers = [
    /worker-completion notification/i,
    /wait_agent/i,
    /still running\?/i,
    /background.*notification/i,
  ];
  assert.ok(
    triggers.some((re) => re.test(body)),
    "contract must enumerate at least one non-resume re-entry trigger (worker-completion / wait_agent / still-running)",
  );
});

// ── Cross-mode brief shape ───────────────────────────────────────────────────

test("cross-mode session (target_repo + target_url) produces a brief that names both surface families", () => {
  // The orchestrator narrative must say: in cross-mode, repo + URL surfaces
  // both feed the same frontier ledger, and each lens dispatches against its
  // own surface kind only (HTTP lens on URL, OSS lens on repo).
  const body = renderedOrchestratorBody();
  // Find the OSS lens dispatch section (in the Lenses block, not the SETUP).
  const lensesIdx = body.indexOf("## Lenses");
  assert.ok(lensesIdx > 0, "Lenses section must exist");
  // Search both the Lenses block and the Hard Rules section for the cross-mode
  // narrative. The narrative must reference both 'repo surface' and 'URL
  // surface' (or HTTP surface).
  const ossDispatchSection = body.slice(lensesIdx, lensesIdx + 5000);
  assert.match(ossDispatchSection, /cross-mode/i,
    "Lenses section must name cross-mode dispatch");
  assert.match(ossDispatchSection, /repo surface|repo-bound|repo target/i,
    "cross-mode narrative must name the repo surface family");
  assert.match(ossDispatchSection, /URL surface|HTTP-shaped lens|URL.surface|hosted instance/i,
    "cross-mode narrative must name the URL/HTTP surface family");
  // Both halves feed the same frontier ledger.
  assert.match(ossDispatchSection, /(same|one|both).*frontier ledger/i,
    "cross-mode narrative must say both halves feed the same frontier ledger");
});

// ── Evaluator OSS stanza regression ──────────────────────────────────────────

test("evaluator role prompt carries an OSS source-review stanza naming the repo tools + staging conventions", () => {
  const evaluatorBody = fs.readFileSync(
    path.join(ROOT, "prompts", "roles", "evaluator.md"),
    "utf8",
  );
  // The OSS stanza must name the two repo-bound tools the evaluator uses
  // directly. bob_repo_inventory is orchestrator-only; the evaluator reads
  // the orchestrator's inventory output via the assignment brief — it does
  // not call the tool itself (per O.2 role_bundles).
  assert.match(evaluatorBody, /bob_repo_check/,
    "evaluator OSS stanza must name bob_repo_check");
  assert.match(evaluatorBody, /bob_repo_docker_run/,
    "evaluator OSS stanza must name bob_repo_docker_run");
  // The OSS lenses must be enumerated so the evaluator knows when this stanza
  // applies.
  for (const lens of OSS_LENSES) {
    assert.match(evaluatorBody, new RegExp(`\\b${lens}\\b`),
      `evaluator OSS stanza must name lens '${lens}'`);
  }
  // The /work/repo staging convention (O-D7 compose role) must be referenced
  // so the evaluator knows where mutable build artifacts go.
  assert.match(evaluatorBody, /\/work\/repo/,
    "evaluator OSS stanza must reference the /work/repo staging convention");
  // The sandbox flags from O-P3 must be mentioned (load-bearing for safety).
  assert.match(evaluatorBody, /cap-drop ALL|--cap-drop ALL/,
    "evaluator OSS stanza must mention the --cap-drop ALL sandbox flag");
  assert.match(evaluatorBody, /--network none/,
    "evaluator OSS stanza must mention the --network none default");
});

test("each per-stack evaluator role carries an OSS source-review stanza", () => {
  for (const stack of ["cosmwasm", "evm", "move", "substrate", "svm"]) {
    const body = fs.readFileSync(
      path.join(ROOT, "prompts", "roles", `evaluator-${stack}.md`),
      "utf8",
    );
    assert.match(body, /OSS source-review stanza/i,
      `evaluator-${stack} must carry the OSS source-review stanza`);
    // bob_repo_inventory is orchestrator-only; per-stack evaluators (like the
    // web evaluator) consume the inventory output via the assignment brief.
    // The chain evaluator stanza references the orchestrator's inventory call
    // for context but the evaluator does not invoke it directly.
    assert.match(body, /bob_repo_inventory/,
      `evaluator-${stack} OSS stanza must reference bob_repo_inventory (read by evaluators via the brief; called by the orchestrator)`);
    assert.match(body, /bob_repo_check/,
      `evaluator-${stack} OSS stanza must reference bob_repo_check`);
    assert.match(body, /bob_repo_docker_run/,
      `evaluator-${stack} OSS stanza must reference bob_repo_docker_run`);
    assert.match(body, /\/work\/repo/,
      `evaluator-${stack} OSS stanza must reference the /work/repo staging convention`);
    // The OSS lens names must appear so the stanza is keyed to the right
    // trigger condition.
    for (const lens of OSS_LENSES) {
      assert.match(body, new RegExp(`\\b${lens}\\b`),
        `evaluator-${stack} OSS stanza must enumerate lens '${lens}'`);
    }
  }
});

// ── Tempdir fixture sanity (synthesized; never committed) ────────────────────

test("temp repo fixture for orchestrator argument parsing is a real local directory (not committed)", () => {
  // Per Reviewer B parsimony, no committed test fixture. We synthesize a
  // throwaway repo at test time so the orchestrator's local-path argument
  // parser has something realistic to assert on. The fixture has the minimal
  // shape needed: a directory containing at least one manifest + one source
  // file, and not a URL.
  const dir = tempRepoFixture();
  try {
    assert.ok(fs.statSync(dir).isDirectory(), "temp fixture must be a real directory");
    assert.ok(fs.existsSync(path.join(dir, "package.json")), "temp fixture must contain a manifest");
    // The path is NOT a URL (the orchestrator's parser would route it to OSS
    // mode, not web mode).
    assert.ok(!/^https?:\/\//.test(dir), "temp fixture path must not look like a URL");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

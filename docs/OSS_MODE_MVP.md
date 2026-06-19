# Hacker Bob OSS Mode MVP

Bob OSS mode extends the existing Hacker Bob runtime for authorized open-source
project review. It is **not** a separate OSS-mode orchestrator: it is realized
as **Plane O technique packs** — the seven `oss_*` capability packs surfaced
through the same registry-driven `bob_*` MCP tools, the single wave-scheduler /
graph-scheduler spawner topology, and the server-enforced v2 lifecycle
(`SETUP → OPEN_FRONTIER → CLAIM_FREEZE → VERIFY → GRADE → REPORT`) defined by
`mcp/lib/lifecycle-gates.js`. It stays inside this repo and reuses the current
MCP pipeline, host adapters, session artifacts, capability routing,
verification, grading, and reporting unchanged.

## Scope

The first version is local-repo first:

- accept a local repository path;
- initialize a repo-target session with `target_kind: "repo"`;
- inventory manifests, lockfiles, route/schema files, auth-sensitive code,
  CI/CD, container/IaC config, docs, and tests;
- write a repo inventory artifact plus a compatible `attack_surface.json`;
- write a Docker environment plan (`repo-env.json`) and session-owned
  `Dockerfile.bob`;
- route repo surfaces to OSS capability packs;
- optionally build a Docker image and run bounded build/test repro commands when
  the operator explicitly asks for dependency installation or command replay;
- let the existing wave, verification, grade, and report flow continue.

GitHub URL cloning, automatic PR creation, hosted scanning, and write-mode fixes
are out of scope for this MVP.

## Multi-Repo Dashboard

Use the local dashboard when running several OSS sessions in parallel:

```bash
hacker-bob dashboard --repo-only
```

The command starts a read-only server on `127.0.0.1:4873` by default and reads
the existing `~/hacker-bob-sessions` artifacts. It does not launch agents or
mutate sessions. It shows each repo session's phase, wave handoff progress,
coverage, technique attempts, findings, final reportable counts,
evidence/grade/report state, and bottlenecks.

For automation or tests, print the same cross-session snapshot without starting
the UI:

```bash
hacker-bob dashboard --repo-only --json
```

## Task Graph

```text
bob-oss command
  -> bob_init_repo_session
  -> target_kind/session metadata
  -> bob_repo_inventory
  -> repo-inventory.json + attack_surface.json
  -> bob_repo_prepare_env
  -> repo-env.json + Dockerfile.bob
  -> bob_route_surfaces
  -> OSS capability packs
  -> existing wave scheduler / evaluators
  -> bob_repo_check + optional bob_repo_docker_run during verification
  -> existing grade/report artifacts
```

## Repo Surface Families

- `oss_dependency`: package manifests, lockfiles, dependency manager metadata.
- `oss_native_code`: C/C++ parser, protocol, filesystem, and memory-safety
  review surfaces.
- `oss_api_schema`: route declarations, OpenAPI/GraphQL/schema files.
- `oss_authz`: auth middleware, guards, policies, permission checks.
- `oss_ci_cd`: GitHub Actions, CI files, Docker/container/IaC config.
- `oss_secrets_config`: env examples, config files, secret-like key names.
- `oss_docs_behavior`: README/security docs and docs-vs-code review targets.

## Verification Contract

OSS findings should cite file paths, symbols, manifests, affected packages, and
repro commands when available. `bob_repo_check` confirms repo-local evidence
still exists. `bob_repo_docker_run` is available for concrete repro/build
commands, using Docker with the repo mounted read-only at `/src`, a session-owned
writable `/work`, and `--network none` by default.

For native C/C++ repositories, candidates must connect the exact file/function
to a reachable attacker-controlled input path and include the malformed field,
impact, false-positive conditions, and the smallest build/test/fuzz/sanitizer
command that would raise confidence.

Dependency installation is Docker-backed rather than host-backed. The default
startup path only writes the plan and Dockerfile; it does not install packages or
build an image. To build the prepared image, the operator must explicitly allow
it, typically with `bob_repo_prepare_env({ target_domain, build_image: true,
allow_network: true })`.

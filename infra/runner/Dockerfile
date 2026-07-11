# Dockerfile — the AgentCore Runtime microVM image.
# Installs the pinned `claude` CLI + Node, copies the unmodified hacker-bob engine,
# and layers the Bedrock settings overlay at build time. Authorized deployment image.
# Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md

# --- disclosed libheif F-22 historical-replay differential -----------------
# The original long Hacker Bob OSS evaluation cannot run inside the AgentCore
# microVM: Bob's repo executor requires a Docker sandbox and the Runtime has no
# nested Docker substrate. The stage demo instead executes these two sealed,
# network-independent binaries and binds their output to the frozen grade. This
# is explicitly a public historical reproduction, never a rediscovery claim.
FROM gcc:13.3.0-bookworm@sha256:1d71f0f3450214bef38fe09e6f610fb6cca90cf97b43f4ce845bfc32a4168818 AS libheif-replay-build-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates cmake curl \
 && rm -rf /var/lib/apt/lists/*
COPY infra/runner/demo-targets/libheif-cve-2026-49271/container/build-one.sh /usr/local/bin/build-libheif-replay
COPY infra/runner/demo-targets/libheif-cve-2026-49271/harness/icef_oob.cc /fixture/icef_oob.cc
RUN printf '%s  %s\n' \
      'eb4e37a5b6c03618a5a9d7b53e983ea1f3fcfc36f721335e326a96c0f9d8fb55' \
      '/fixture/icef_oob.cc' \
      | sha256sum --check --strict \
 && chmod 0555 /usr/local/bin/build-libheif-replay

FROM libheif-replay-build-base AS libheif-replay-vulnerable
ENV LIBHEIF_COMMIT=b12b733d1716595483413ccd7e2dfb73c44a8d69
ENV LIBHEIF_TARBALL_SHA256=5d052fc8cc664d365a5d761415a2eea09b934bd6c6ffee174e76ed2f346fc73d
ENV OUTPUT_PATH=/opt/replay/libheif-vulnerable
RUN /usr/local/bin/build-libheif-replay

FROM libheif-replay-build-base AS libheif-replay-fixed
ENV LIBHEIF_COMMIT=5782bca04a70ebc01c59397205a3cfff22841311
ENV LIBHEIF_TARBALL_SHA256=d1a065121210b9716791ac5e7afbb11a90f7c1e41c68ebd0bf38f85d66e1117f
ENV OUTPUT_PATH=/opt/replay/libheif-fixed
RUN /usr/local/bin/build-libheif-replay

# Independently buildable target used by CI and operator rehearsal without
# rebuilding the full AgentCore/Claude image.
FROM debian:bookworm-slim AS libheif-replay-artifacts
RUN apt-get update \
 && apt-get install -y --no-install-recommends libasan8 libubsan1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=libheif-replay-vulnerable /opt/replay/libheif-vulnerable /opt/replay/libheif-vulnerable
COPY --from=libheif-replay-fixed /opt/replay/libheif-fixed /opt/replay/libheif-fixed
COPY infra/runner/demo-targets/libheif-cve-2026-49271/target.lock.json /opt/replay/target.lock.json
COPY infra/runner/demo-targets/libheif-cve-2026-49271/container/replay-selftest.sh /usr/local/bin/replay-selftest
RUN chmod 0555 /opt/replay/libheif-vulnerable /opt/replay/libheif-fixed /usr/local/bin/replay-selftest
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/replay-selftest"]

FROM public.ecr.aws/docker/library/node:22-bookworm-slim

# --- pinned claude CLI (host that spawns the unmodified stdio MCP engine) ---
# claude-code and claude-agent-sdk@^0.3.167 are independently versioned; confirm compatibility with the build-day smoke test documented in bedrock-model-overrides.json.
RUN npm install -g @anthropic-ai/claude-code@2.1.202

# --- python + AgentCore SDK for the entrypoint ---
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip python3-venv jq libasan8 libubsan1 \
 && rm -rf /var/lib/apt/lists/*
# boto3 is explicit (not merely assumed transitive via bedrock-agentcore): both the
# entrypoint (secretsmanager, for the zai/agt-token interim path) AND
# .claude/hooks/bob-approval-gate-impl.py (s3 + secretsmanager, for the fx-gate-hardening
# S3-backed/HMAC-verified approval artifact — that hook runs as a python3 subprocess of
# this same container, invoked by the `claude` CLI's PreToolUse matcher) import boto3
# directly and must not silently ImportError at runtime.
RUN python3 -m venv /opt/agentcore-venv \
 && /opt/agentcore-venv/bin/pip install --no-cache-dir \
      bedrock-agentcore==1.18.0 \
      boto3==1.43.46
ENV PATH=/opt/agentcore-venv/bin:$PATH

# --- hacker-bob engine (UNMODIFIED) ---
WORKDIR /opt/hacker-bob
COPY mcp/ ./mcp/
# Schema mirrors packages/bob-diff-review/src/bob-runner.ts buildMcpConfig().
RUN printf '{"mcpServers":{"hacker-bob":{"command":"node","args":["/opt/hacker-bob/mcp/server.js"]}}}' > /opt/hacker-bob/mcp/agentcore-mcp-config.json
COPY .claude/ ./.claude/
# --- bake the approval-gate PreToolUse matcher into the IMAGE's settings.json ---
# Regenerates .claude/settings.json with BOB_AGENTCORE=1 so bob-approval-gate.sh is
# wired up for bob_advance_session|bob_finalize_report. The git-tracked source-tree
# .claude/settings.json is NEVER touched by this Dockerfile (it stays flag-off so
# `npm run check:settings` remains green for normal dev off this image). The
# generator's require graph (adapters/claude/config.js, scripts/merge-claude-config.js,
# scripts/lib/claude-role-renderer.js, scripts/lib/package-policy.js, plus the mcp/lib/*
# modules already copied above) reaches mcp/lib/scope.js (via tool-registry.js ->
# tools/index.js), which requires `psl` — a regular (non-dev) dependency. So the bake
# must run AFTER `npm ci --omit=dev` has installed it, not before.
COPY scripts/ ./scripts/
COPY adapters/ ./adapters/
COPY package.json package-lock.json ./
COPY packages/bob-diff-review/package.json ./packages/bob-diff-review/package.json
# The AgentCore path launches the globally pinned Claude CLI. Root optional
# dependencies include duplicate platform CLI binaries and Patchright without a
# browser install; neither is used by this bounded HTTP demo image.
RUN npm ci --omit=dev --omit=optional
RUN BOB_AGENTCORE=1 node scripts/generate-claude-settings.js

# --- Bedrock settings overlay (does NOT touch the generator-owned settings.json source) ---
COPY infra/runner/bedrock-model-overrides.json /tmp/bedrock-overrides.json
# This targets ONLY /opt/hacker-bob/.claude/settings.json inside the image — the git-tracked source-tree .claude/settings.json is NEVER touched by this Dockerfile. Do not move this step earlier than the COPY .claude/ ./.claude/ line above.
RUN jq --slurpfile o /tmp/bedrock-overrides.json '.modelOverrides = $o[0].modelOverrides' .claude/settings.json > /tmp/merged-settings.json \
 && mv /tmp/merged-settings.json .claude/settings.json \
 && rm -f /tmp/bedrock-overrides.json

# --- CI guard: fail the image build if the approval-gate bake or the modelOverrides
# overlay above drifted .claude/settings.json away from the BOB_AGENTCORE=1 canonical
# shape (matcher present, permissions.allow canonical). package.json is already copied
# by this point.
RUN BOB_AGENTCORE=1 npm run check:settings:agentcore

# --- bounded historical replay artifacts -----------------------------------
# Only the two compiled binaries and their public-source lock enter the final
# Runtime image. Source downloads/compiler/build outputs remain in discarded
# stages. The entrypoint owns the fixed paths and required output markers;
# execution input cannot override a commit, binary, or expected signal.
COPY --from=libheif-replay-vulnerable /opt/replay/libheif-vulnerable /opt/replay/libheif-vulnerable
COPY --from=libheif-replay-fixed /opt/replay/libheif-fixed /opt/replay/libheif-fixed
COPY infra/runner/demo-targets/libheif-cve-2026-49271/target.lock.json /opt/replay/target.lock.json
RUN chmod 0555 /opt/replay/libheif-vulnerable /opt/replay/libheif-fixed \
 && chmod 0444 /opt/replay/target.lock.json

# --- HOME on the EFS mount so $HOME/hacker-bob-sessions survives the split ---
# GRADE / resume-REPORT invocations (paths.js:44 sessionsRoot() has no env override).
ENV HOME=/mnt/efs/bob-home
ENV AWS_REGION=us-east-1

# --- BEDROCK MODEL DEFAULTS ---
# Claude Code accepts provider-native model IDs in these variables. Set them
# explicitly so every `model: opus` / `model: sonnet` role resolves to the two
# Bedrock inference profiles this image and its IAM policy are built around,
# independent of Claude Code's moving built-in aliases.
ENV ANTHROPIC_DEFAULT_OPUS_MODEL=us.anthropic.claude-opus-4-8
ENV ANTHROPIC_DEFAULT_SONNET_MODEL=us.anthropic.claude-sonnet-5
ENV ANTHROPIC_DEFAULT_HAIKU_MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0
ENV ANTHROPIC_MODEL=us.anthropic.claude-sonnet-5

# --- MODEL PROVIDER FLAG ---
# DEFAULT MODEL_PROVIDER=bedrock: the entrypoint sets CLAUDE_CODE_USE_BEDROCK=1
# and uses the AgentCore execution role; no model credential secret or public
# model-gateway egress is required. MODEL_PROVIDER=zai remains an explicit
# operator override for the interim fallback path only; that path fetches the
# token from Secrets Manager and requires its separately declared egress rule.
ENV MODEL_PROVIDER=bedrock
ENV BOB_MCP_CONFIG=/opt/hacker-bob/mcp/agentcore-mcp-config.json
# Off in the reusable image; the owned-target demo stack/CLI turns it on.
ENV BOB_BUILTIN_DEMO_TARGET=false
ENV BOB_INVOCATION_TIMEOUT_SECONDS=780
ENV BOB_MAX_BUDGET_USD=2.00

COPY infra/runner/agentcore-entrypoint.py /opt/entrypoint.py
EXPOSE 8080
USER node
CMD ["python3", "/opt/entrypoint.py"]

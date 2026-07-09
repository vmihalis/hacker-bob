# Dockerfile — the AgentCore Runtime microVM image.
# Installs the pinned `claude` CLI + Node, copies the unmodified hacker-bob engine,
# and layers the Bedrock settings overlay at build time. Authorized deployment image.
# Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md

FROM public.ecr.aws/docker/library/node:20-bookworm

# --- pinned claude CLI (host that spawns the unmodified stdio MCP engine) ---
# claude-code and claude-agent-sdk@^0.3.167 are independently versioned; confirm compatibility with the build-day smoke test documented in bedrock-model-overrides.json.
RUN npm install -g @anthropic-ai/claude-code@2.1.162

# --- python + AgentCore SDK for the entrypoint ---
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip jq \
 && rm -rf /var/lib/apt/lists/*
# boto3 is explicit (not merely assumed transitive via bedrock-agentcore): both the
# entrypoint (secretsmanager, for the zai/agt-token interim path) AND
# .claude/hooks/bob-approval-gate-impl.py (s3 + secretsmanager, for the fx-gate-hardening
# S3-backed/HMAC-verified approval artifact — that hook runs as a python3 subprocess of
# this same container, invoked by the `claude` CLI's PreToolUse matcher) import boto3
# directly and must not silently ImportError at runtime.
RUN pip3 install --no-cache-dir bedrock-agentcore boto3

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
RUN npm ci --omit=dev
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

# --- HOME on the EFS mount so $HOME/hacker-bob-sessions survives the split ---
# GRADE / resume-REPORT invocations (paths.js:44 sessionsRoot() has no env override).
ENV HOME=/mnt/efs/bob-home
ENV AWS_REGION=us-east-1

# --- MODEL PROVIDER FLAG (zai now → bedrock when H1 lands) ---
# INTERIM MODEL_PROVIDER=zai: the entrypoint sets ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN
#   (Z.ai / GLM-5.1) from AWS Secrets Manager — NEVER bake the agt_ token into the image;
#   needs ONE narrow declared egress hole to the Z.ai gateway.
# TARGET  MODEL_PROVIDER=bedrock: the entrypoint sets CLAUDE_CODE_USE_BEDROCK=1 (no egress hole).
ENV MODEL_PROVIDER=zai
ENV BOB_MCP_CONFIG=/opt/hacker-bob/mcp/agentcore-mcp-config.json

COPY infra/runner/agentcore-entrypoint.py /opt/entrypoint.py
CMD ["python3", "/opt/entrypoint.py"]

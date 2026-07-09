# Dockerfile — the AgentCore Runtime microVM image.
# Installs the pinned `claude` CLI + Node, copies the unmodified hacker-bob engine,
# and layers the Bedrock settings overlay at build time. Authorized deployment image.
# Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md

# TODO(build-day): pin the base + claude CLI version actually used by the repo.
FROM public.ecr.aws/docker/library/node:20-bookworm

# --- pinned claude CLI (host that spawns the unmodified stdio MCP engine) ---
# TODO(build-day): install the exact `claude` CLI version this repo is validated against.
# RUN npm install -g @anthropic-ai/claude-code@<pinned>

# --- python + AgentCore SDK for the entrypoint ---
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir bedrock-agentcore

# --- hacker-bob engine (UNMODIFIED) ---
WORKDIR /opt/hacker-bob
COPY mcp/ ./mcp/
COPY .claude/ ./.claude/
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# --- Bedrock settings overlay (does NOT touch the generator-owned settings.json source) ---
COPY infra/runner/bedrock-model-overrides.json /tmp/bedrock-overrides.json
# TODO(build-day): merge /tmp/bedrock-overrides.json into .claude/settings.json here
# (jq deep-merge), so the two-tier role map resolves to Bedrock inference profiles.

# --- HOME on the EFS mount so $HOME/hacker-bob-sessions survives the split ---
# GRADE / resume-REPORT invocations (paths.js:44 sessionsRoot() has no env override).
ENV HOME=/mnt/efs/bob-home
ENV CLAUDE_CODE_USE_BEDROCK=1
ENV AWS_REGION=us-east-1
# ENV BOB_MCP_CONFIG=/opt/hacker-bob/mcp/mcp-config.json   # TODO(build-day): wire the mcp-config path

COPY infra/runner/agentcore-entrypoint.py /opt/entrypoint.py
CMD ["python3", "/opt/entrypoint.py"]

"use strict";

const { prepareRepoEnv } = require("../repo-env.js");

async function handler(args) {
  const result = await prepareRepoEnv({
    target_domain: args.target_domain,
    base_image: args.base_image,
    build_image: args.build_image,
    dry_run: args.dry_run,
    allow_network: args.allow_network,
    image_tag: args.image_tag,
    timeout_ms: args.timeout_ms,
    egress_profile: args.egress_profile,
    platform: args.platform,
    harness_override: args.harness_override,
  });
  return JSON.stringify({
    version: 1,
    ...result,
  });
}

module.exports = Object.freeze({
  name: "bob_repo_prepare_env",
  description:
    "Generate a per-session Dockerfile.bob + repo-env.json for an OSS repo session (Plane O O.3). " +
    "Detects language from manifests, picks a sandbox-friendly base image, and emits recommended " +
    "build/test/fuzz/compose commands. dry_run is the default; build_image: true exec's docker build " +
    "with O-P3 sandbox flags and an O-D6 ARG SESSION_ID cache-bust. Never bakes proxy/secret into ENV. " +
    "Native C/C++ fuzz sessions emit two input-to-state arms over the discovered LLVMFuzzerTestOneInput " +
    "harness: a libFuzzer+ASAN/UBSAN recipe with the always-on -use_value_profile=1 floor, and an afl++ " +
    "CmpLog/RedQueen campaign (afl++ baked into the session image when allow_network:true) that replays " +
    "crashes through the ASAN binary into the differential repro gate; the afl arm no-ops where afl++ is absent.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Repo session target_domain derived by bob_init_repo_session.",
      },
      base_image: {
        type: "string",
        description: "Optional override of the detected base image (e.g. node:20, rust:1.79). Defaults to the language-detected image.",
      },
      build_image: {
        type: "boolean",
        description: "When true, exec docker build with O-P3 sandbox flags. Defaults to false (dry_run flow).",
      },
      dry_run: {
        type: "boolean",
        description: "When true (default), write Dockerfile.bob + repo-env.json without invoking docker.",
      },
      allow_network: {
        type: "boolean",
        description: "When true, allow docker build --network default and inject the resolved egress proxy via --build-arg. Defaults to false (--network none).",
      },
      image_tag: {
        type: "string",
        description: "Optional explicit image tag. Defaults to bob-oss-<target_domain>:<repo_hash>.",
      },
      timeout_ms: {
        type: "integer",
        minimum: 1000,
        maximum: 600000,
        description: "docker build timeout in milliseconds. Defaults to 300000 (5m); max 600000 (10m).",
      },
      egress_profile: {
        type: "string",
        description: "Optional egress profile name override for build-time proxy resolution. Defaults to the session's bound profile.",
      },
      platform: {
        type: "string",
        enum: ["native", "linux/amd64", "linux/arm64"],
        description: "Container platform. 'native' (default) = host arch; 'linux/amd64' runs an x86_64 image (via emulation on Apple Silicon) so x86-only targets like Firedancer build/fuzz correctly — the emulated CPU here supports AVX2+AES-NI.",
      },
      harness_override: {
        type: "string",
        description: "Optional repo-relative path (no absolute path, no .. escape) to the LLVMFuzzerTestOneInput harness the native fuzz arms must use. Forces the image-baked builder to use that TU verbatim instead of its auto-selection; the builder fails closed if the file is absent. Use this to disambiguate a multi-harness tree (e.g. select a protocol harness instead of an app-config one).",
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["Dockerfile.bob", "repo-env.json"],
});

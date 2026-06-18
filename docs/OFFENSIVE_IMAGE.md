# Offensive arsenal image (`bob-offense`)

The wide-open offensive container runner (`mcp/lib/offensive-runner.js` + `offensive-sandbox.js`) runs
each arsenal tool inside a **digest-pinned** image with `--pull=never`. This doc is the one-time build +
pin procedure and the design rationale. It is **`PR-IMAGE`**: image infrastructure only — no MCP tool is
wired here (that is `PR5b-tool`).

## Why a registry push is required (not just a local build)

`offensive-sandbox.js` enforces `--pull=never` + `name@sha256:<digest>` (`IMAGE_DIGEST_RE`). A purely-local
`docker build`/retag has **no `RepoDigest`**, so `docker run --pull=never name@sha256:…` cannot resolve it.
The only sound way to mint a resolvable digest is **build → push to a registry → pull-by-digest**. We use
`ghcr.io` (its TLS is clean on the build host; verified 2026-06-18 — the documented Docker-Hub TLS-intercept
is registry-specific, which is also why the base image is pulled from `gcr.io`, not Docker Hub).

## One-time operator steps (mint the digest)

```sh
# 1. Start Docker Desktop (the daemon must be running).
# 2. Authenticate to ghcr.io with a PAT carrying the write:packages scope:
docker login ghcr.io                       # username = your GitHub handle; password = the PAT

# 3. Build + push + pull-by-digest + write the lockfile (pin the CURRENT release versions — required):
HTTPX_VERSION=<current> DALFOX_VERSION=<current> ./scripts/build-offensive-image.sh   # --stage-only skips docker

# 4. Commit the generated lockfile:
git add mcp/lib/offensive-image.json && git commit -m "chore(offense): pin offensive arsenal image digest"
```

The script fetches `httpx` + `dalfox` release binaries **on the host**, verifies each against its official
GitHub release checksums file, stages them, builds a hermetic image (no in-build network), pushes to
`ghcr.io/bobnetsec/bob-offense`, pulls the result **by digest** so the local store can resolve `--pull=never`,
and writes the digest to `mcp/lib/offensive-image.json` (the **sole source** of `runOffensiveTool`'s
`imageDigest`). The lockfile is JSON **data** — read fresh with `fs.readFileSync` + `JSON.parse`, never
executed — and `install.js` copies it explicitly (the `mcp/lib` copy is `.js`-only).

> **Tool versions are required** (`HTTPX_VERSION` / `DALFOX_VERSION`) — there is no shipped default (a
> hardcoded guess can 404). Pin the current release tags from
> [httpx](https://github.com/projectdiscovery/httpx/releases) /
> [dalfox](https://github.com/hahwul/dalfox/releases); the script fails closed if they're unset, and a
> tampered asset fails the checksum gate.
>
> **Pin the binary SHA256s in-repo for release-tamper protection.** The first mint is TOFU — the asset is
> verified against the release's *own* checksums file (same channel) and the computed SHA is printed. Set
> `HTTPX_SHA256` / `DALFOX_SHA256` (env or at the top of the script) to those values so a later compromised
> upstream release fails against the in-repo reference. (The base image is auto-resolved to an immutable
> `@sha256:` digest at mint time and recorded in the lockfile's `base_image`; override `BASE_IMAGE` to pin a
> different base.)

## Runtime behavior (fail-closed)

`mcp/lib/offensive-image.js`:
- `resolveOffensiveImageDigest()` reads + validates the lockfile fresh each call; **throws** if absent (not
  yet minted), unparseable, or carrying a non-`name@sha256` digest.
- `assertOffensiveImagePresent(digest, docker)` runs `docker image inspect <digest>` before a run; **throws**
  with a clear "run `scripts/build-offensive-image.sh`" message if the image is not in the local store, so
  `--pull=never` never fails cryptically.

Until the lockfile is minted, both fail closed — an offensive container run is impossible, by design.

## Design notes

- **Hermetic + reproducible build:** binaries are fetched + checksum-verified on the host (clean egress) and
  `COPY`-ed into a shell-less `gcr.io/distroless/base-debian12` base that the script resolves to an immutable
  `@sha256:` digest before building (recorded in `base_image`). No builder toolchain, no in-build network.
- **Runtime posture** is enforced by `offensive-sandbox.js`, not the image: `--user 1000:1000`, `--cap-drop ALL`,
  `--read-only`, no host mounts, `/tmp`+`/work` tmpfs, a per-run throwaway network. The image only holds the
  static binaries world-executable and points `HOME`/XDG at the writable `/work` tmpfs.
- **Accepted residual** (operator-locked): wide-open OUTBOUND egress once a container runs. Mitigations live in
  the runner (redaction-before-agent, count/boolean oracle default) and the build plan — see
  `docs/OFFENSIVE_BOB_BUILD_PLAN.md`.

## Bumping the image

Edit the pinned versions in `scripts/build-offensive-image.sh`, re-run it, commit the regenerated
`mcp/lib/offensive-image.json`, and re-run `./install.sh <runtime>` so the operational runtime picks up the
new digest.

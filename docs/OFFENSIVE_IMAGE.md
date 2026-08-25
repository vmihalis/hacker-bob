# Offensive arsenal image (`bob-offense`)

The wide-open offensive container runner (`mcp/domains/web/offensive-runner.js` + `offensive-sandbox.js`) runs
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

# 3. Build + push + pull-by-digest + write the lockfile. Copy each tool's linux release ARCHIVE URL for
#    your arch + its published sha256 from the releases page, and pass all four (required):
HTTPX_URL=... HTTPX_SHA256=... DALFOX_URL=... DALFOX_SHA256=... ./scripts/build-offensive-image.sh
#    (add --stage-only to fetch+verify+stage the binaries without Docker)

# 4. The lockfile is operator-local (gitignored) — DON'T commit it. Refresh your runtime so it's picked up:
./install.sh <your-runtime>          # install copies the local mcp/domains/web/offensive-image.json into the runtime
```

The script fetches the `httpx` + `dalfox` archives **on the host** from the URLs you supply, verifies each
against the sha256 you supply, stages them, builds a hermetic image (no in-build network), pushes to your
`OFFENSIVE_REGISTRY` (default `ghcr.io/bobnetsec/bob-offense`), pulls the result **by digest** so the local
store can resolve `--pull=never`, and writes the digest to `mcp/domains/web/offensive-image.json` (the **sole source**
of `runOffensiveTool`'s `imageDigest`). The lockfile is JSON **data** — read fresh with `fs.readFileSync` +
`JSON.parse`, never executed — operator-local (gitignored); `install.js` copies it into the runtime if present.

> **You supply the exact archive URL + sha256 per tool** (`HTTPX_URL`+`HTTPX_SHA256`,
> `DALFOX_URL`+`DALFOX_SHA256`) — all required, no defaults. Copy the linux archive URL for your arch and
> its published sha256 from the releases pages
> ([httpx](https://github.com/projectdiscovery/httpx/releases) /
> [dalfox](https://github.com/hahwul/dalfox/releases)). This avoids guessing release asset names (which
> differ per tool/version) and pins each binary to the published hash — no trust-on-first-use; a mismatch
> fails the checksum gate.
>
> The base image is auto-resolved to an immutable `@sha256:` digest at mint time and recorded in the
> lockfile's `base_image`; override `BASE_IMAGE` with a `@sha256:` ref to pin a different base.

## Runtime behavior (fail-closed)

`mcp/domains/web/offensive-image.js`:
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

Re-run the mint (step 3) with the new release URLs + sha256s, then re-run `./install.sh <runtime>` so your
runtime picks up the regenerated `mcp/domains/web/offensive-image.json`. The lockfile stays operator-local — don't commit it.

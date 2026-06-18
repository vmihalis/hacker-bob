# offensive.Dockerfile — the digest-pinned image for Hacker Bob's wide-open offensive
# container runner (mcp/lib/offensive-runner.js + offensive-sandbox.js). It carries the
# arsenal binaries the find-axis tools invoke (httpx for the smoke; dalfox for the first
# real prover tool in PR5b-tool).
#
# HERMETIC BUILD: the arsenal binaries are fetched + sha256-verified ON THE HOST by
# scripts/build-offensive-image.sh (where egress is verified clean) and COPIED in. There is
# NO network fetch during this build and NO builder toolchain in the final image — the only
# registry pull is the base image.
#
# PROVENANCE: the OFFENSIVE image's own sha256 digest is what's pinned in
# mcp/lib/offensive-image.json and enforced at run time by the sandbox (--pull=never +
# name@sha256). This Dockerfile only has to produce that image reproducibly. The base is
# overridable + digest-pinnable via BASE_IMAGE.
#
# RUNTIME POSTURE (enforced by offensive-sandbox.js, NOT here): --user 1000:1000,
# --cap-drop ALL, --read-only, no host mounts, /tmp + /work tmpfs, per-run throwaway network.
# This image only needs to (a) hold the static binaries world-executable and (b) point HOME at
# a writable tmpfs path so the tools never write a read-only $HOME.

# distroless/base carries glibc (safer than :static for release binaries that may use the cgo resolver).
# The DEFAULT below is a mutable tag; scripts/build-offensive-image.sh resolves it to an immutable
# @sha256: digest and passes --build-arg BASE_IMAGE=...@sha256:. A direct `docker build` WITHOUT that arg
# is NOT digest-pinned — override BASE_IMAGE with a @sha256: ref to pin a standalone build.
ARG BASE_IMAGE=gcr.io/distroless/base-debian12:nonroot

FROM ${BASE_IMAGE}

# Arsenal binaries staged under ./bin by scripts/build-offensive-image.sh as 0755; COPY preserves the host
# mode (world read+exec) so the runner's forced --user 1000:1000 (not the image's default nonroot uid) can
# execute them. No `--chmod` => no BuildKit external-frontend pull from Docker Hub.
COPY bin/ /usr/local/bin/

# The fs is read-only at run time except /tmp + /work (tmpfs). Point HOME + the XDG dirs at /work
# so httpx/dalfox never try to write a read-only $HOME. (-disable-update-check / -silent are forced
# per-tool in the offensive-tools.js spec, so no tool reaches out to update at run time.)
ENV HOME=/work \
    XDG_CONFIG_HOME=/work/.config \
    XDG_CACHE_HOME=/work/.cache

# Start in the writable /work tmpfs (the rootfs is --read-only at runtime) so tools that write to their CWD
# (temp files, crash dumps, relative output) don't hit a read-only /.
WORKDIR /work

# Fixed non-root uid so the image stays non-root even when run directly (the manual smoke, or any use
# outside the sandbox's forced --user 1000:1000) — defense-in-depth, independent of which BASE_IMAGE is used.
USER 1000:1000

# No entrypoint: the runner supplies the full tool argv as the container command. CMD is only the
# default smoke — a no-network, read-only invocation proving the image+digest+--pull=never plumbing.
ENTRYPOINT []
CMD ["httpx", "-version"]

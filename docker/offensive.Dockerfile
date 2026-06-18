# syntax=docker/dockerfile:1
#
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

# distroless/base carries glibc (safer than :static for PD release binaries that may use the
# cgo resolver). Pin to a digest in BASE_IMAGE for a fully reproducible rebuild.
ARG BASE_IMAGE=gcr.io/distroless/base-debian12:nonroot

FROM ${BASE_IMAGE}

# Arsenal binaries staged under ./bin by scripts/build-offensive-image.sh. World read+exec so
# the runner's forced --user 1000:1000 (not the image's default nonroot uid) can execute them.
COPY --chmod=0755 bin/ /usr/local/bin/

# The fs is read-only at run time except /tmp + /work (tmpfs). Point HOME + the XDG dirs at /work
# so httpx/dalfox never try to write a read-only $HOME. (-disable-update-check / -silent are forced
# per-tool in the offensive-tools.js spec, so no tool reaches out to update at run time.)
ENV HOME=/work \
    XDG_CONFIG_HOME=/work/.config \
    XDG_CACHE_HOME=/work/.cache

# No entrypoint: the runner supplies the full tool argv as the container command. CMD is only the
# default smoke — a no-network, read-only invocation proving the image+digest+--pull=never plumbing.
ENTRYPOINT []
CMD ["httpx", "-version"]

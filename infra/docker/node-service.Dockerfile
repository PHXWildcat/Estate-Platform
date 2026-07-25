# syntax=docker/dockerfile:1.7
#
# One image recipe for EVERY Node workload in the monorepo (the six bounded-
# context services plus the GraphQL BFF), selected by the PKG build arg:
#
#   docker build -f infra/docker/node-service.Dockerfile \
#     --build-arg PKG=@estate/service-identity -t estate/identity .
#
# Deliberately ONE parameterized file rather than seven near-identical ones:
# a hardening change (base image, user, entrypoint) must land in exactly one
# place, and seven copies would drift. Per-service differences are config
# (env vars), never image shape — the services are already uniform by design.
#
# Security posture (docs/01 §3 "containers distroless, non-root, read-only
# filesystems"; docs/03 supply chain):
#   * runtime is distroless — no shell, no package manager, no busybox, so a
#     command-injection foothold has nothing to exec;
#   * runs as the built-in `nonroot` user (uid 65532), never root;
#   * the filesystem is treated as read-only (enforced at the pod
#     securityContext; nothing in these services writes to disk in production —
#     the documents service writes blobs to S3, not local fs);
#   * build and runtime are both Debian 12 / glibc so the prebuilt native
#     addon (@node-rs/argon2 in identity) matches its host ABI. Alpine/musl
#     would silently pull a different binary.
#
# Base images are pinned by TAG here, not digest. Digest pinning (docs/03) is a
# tracked follow-up for when the image pipeline gains a registry + an automated
# bump: hand-written digests that nothing can refresh rot into an unpatchable
# base, which is worse than a floating patch tag on a rebuilt-every-CI image.

ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot

# ---------------------------------------------------------------- base tooling
FROM ${NODE_IMAGE} AS base
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    # Never let a dependency's install script run (pnpm 10 blocks by default;
    # this makes it explicit and survives a settings change).
    npm_config_ignore_scripts=true
# Pin the package manager to the version in the repo's `packageManager` field.
RUN npm install -g pnpm@10.12.1
WORKDIR /app

# --------------------------------------------------------------------- pruning
# `turbo prune --docker` emits a minimal workspace containing only the target
# package and its internal dependencies, split into `out/json` (manifests +
# lockfile) and `out/full` (sources). Installing from the manifest-only layer
# first means dependency installation is cached until a package.json actually
# changes — source edits don't re-run the install.
FROM base AS pruner
ARG PKG
COPY . .
RUN pnpm dlx turbo@2 prune "${PKG}" --docker

# --------------------------------------------------------------------- builder
FROM base AS builder
ARG PKG
COPY --from=pruner /app/out/json/ ./
RUN pnpm install --frozen-lockfile
COPY --from=pruner /app/out/full/ ./
# Turborepo orders `^build`, so the internal packages this service consumes are
# compiled to their `dist` before the service itself is built.
RUN pnpm turbo run build --filter="${PKG}"
# Collect just this package plus its PRODUCTION dependency closure (workspace
# packages are materialized as real directories) into a self-contained tree.
RUN pnpm deploy --filter="${PKG}" --prod --legacy /deploy

# --------------------------------------------------------------------- runtime
FROM ${RUNTIME_IMAGE} AS runtime
WORKDIR /app
# The distroless `nonroot` tag already defaults to uid 65532; state it anyway so
# the guarantee is visible in the image config and survives a base-image swap.
USER nonroot
COPY --from=builder --chown=nonroot:nonroot /deploy ./
# The distroless nodejs entrypoint IS node, so CMD carries only the script path.
# No shell form anywhere: nothing to interpolate, nothing to inject.
CMD ["dist/main.js"]

# syntax=docker/dockerfile:1.7
#
# Next.js frontend image.
#
#   docker build -f infra/docker/web.Dockerfile -t estate/web .
#
# Separate from node-service.Dockerfile because Next.js does not ship a plain
# `dist/main.js`: `output: 'standalone'` (see apps/web/next.config.ts) emits a
# traced server bundle whose static assets must be copied alongside it. The
# hardening posture is identical — distroless, non-root, no shell.

ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot
ARG PKG=@estate/web

FROM ${NODE_IMAGE} AS base
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    npm_config_ignore_scripts=true
RUN npm install -g pnpm@10.12.1
WORKDIR /app

FROM base AS pruner
ARG PKG
COPY . .
RUN pnpm dlx turbo@2 prune "${PKG}" --docker

FROM base AS builder
ARG PKG
# Telemetry is an outbound call from a build machine — off by default.
# NEXT_STANDALONE opts into the traced server bundle; it is gated behind this
# flag because emitting it needs symlinks, which Windows workstations refuse
# (see apps/web/next.config.ts). Linux builders have no such problem.
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_STANDALONE=1
COPY --from=pruner /app/out/json/ ./
RUN pnpm install --frozen-lockfile
COPY --from=pruner /app/out/full/ ./
RUN pnpm turbo run build --filter="${PKG}"

FROM ${RUNTIME_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
USER nonroot
# `standalone` already contains the minimal node_modules closure and a server.js
# entrypoint; the static assets are copied in beside it because Next deliberately
# leaves them out of the traced bundle. There is no `public/` directory in this
# app — add a COPY for it here if one is ever introduced, since Next excludes it
# from the bundle too.
COPY --from=builder --chown=nonroot:nonroot /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nonroot:nonroot /app/apps/web/.next/static ./apps/web/.next/static
EXPOSE 3000
CMD ["apps/web/server.js"]

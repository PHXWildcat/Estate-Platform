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
# WHERE THE BFF LIVES IS A BUILD-TIME FACT, not a runtime one. next.config.ts
# reads BFF_URL when the config is evaluated, and `next build` serialises the
# resulting rewrite into the routes manifest; the standalone server.js boots
# from that manifest and never re-evaluates the config. Setting BFF_URL in the
# running container therefore has NO effect — the image would keep proxying
# /graphql to localhost:4000, i.e. to itself. It has to be an ARG.
ARG BFF_URL=http://localhost:4000
# Telemetry is an outbound call from a build machine — off by default.
# NEXT_STANDALONE opts into the traced server bundle; it is gated behind this
# flag because emitting it needs symlinks, which Windows workstations refuse
# (see apps/web/next.config.ts). Linux builders have no such problem.
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_STANDALONE=1 \
    BFF_URL=${BFF_URL}
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
# leaves them out of the traced bundle. BOTH of the copies below are required for
# that reason — `.next/static` and `public/` are excluded from the traced bundle
# alike, and a missing one produces a 404 at runtime rather than a build error.
#
# `public/` held nothing when this file was written and that comment outlived the
# fact: the Evergreen-rail redesign vendored Instrument Sans into
# apps/web/public/fonts precisely so no build or page load reaches a third-party
# CDN, and without this copy every page in the shipped image silently fell back
# to a system font. .github/workflows/images.yml asserts each file under
# apps/web/public is served with a 200 by the built image, so the next asset
# added is covered by a test rather than by this comment.
COPY --from=builder --chown=nonroot:nonroot /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nonroot:nonroot /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=nonroot:nonroot /app/apps/web/public ./apps/web/public
EXPOSE 3000
CMD ["apps/web/server.js"]

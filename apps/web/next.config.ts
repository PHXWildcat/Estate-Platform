import { join } from 'node:path';
import type { NextConfig } from 'next';

/**
 * The BFF is reached same-origin via a rewrite so that auth cookies stay
 * first-party and the browser never talks to the BFF host directly.
 * In production this is fronted by CloudFront routing instead.
 */
const bffUrl = process.env.BFF_URL ?? 'http://localhost:4000';

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

/**
 * `output: 'standalone'` emits a self-contained server bundle with only the
 * traced runtime dependencies — exactly what the container should ship (no pnpm
 * store, no workspace symlinks, no dev dependencies).
 *
 * It is opt-in via NEXT_STANDALONE because producing it CREATES SYMLINKS, and
 * Windows refuses those without Developer Mode or elevation (EPERM), which would
 * break `pnpm build` on the maintainer's workstation. The container build (Linux)
 * sets the flag; everyday local builds and `pnpm build` in CI do not.
 */
const standalone =
  process.env.NEXT_STANDALONE === '1'
    ? {
        output: 'standalone' as const,
        // The traced root must be the workspace root, or Next resolves the
        // monorepo's hoisted dependencies outside the app directory and omits
        // them. Turborepo runs this task with the package as cwd.
        outputFileTracingRoot: join(process.cwd(), '..', '..'),
      }
    : {};

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  ...standalone,
  // Linting runs from the repo root flat config (`pnpm exec eslint apps/web`);
  // next build must not require a separate eslint-config-next setup.
  eslint: { ignoreDuringBuilds: true },
  rewrites() {
    return Promise.resolve([{ source: '/graphql', destination: `${bffUrl}/graphql` }]);
  },
  headers() {
    return Promise.resolve([{ source: '/:path*', headers: securityHeaders }]);
  },
};

export default nextConfig;

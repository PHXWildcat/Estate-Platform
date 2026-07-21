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

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
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

const nextJest = require('next/jest');

const createJestConfig = nextJest({ dir: __dirname });

module.exports = createJestConfig({
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  // NOTE: no <rootDir>-prefixed testMatch globs — on Windows worktree paths
  // containing "\." jest's glob normalization breaks them. Jest's default
  // testMatch already picks up src/**/*.test.ts(x).
  clearMocks: true,
  // Collect from ALL source (not just test-touched files), consistent with the
  // backend packages — this counts the untested pages honestly.
  collectCoverageFrom: ['src/**/*.{ts,tsx}', '!src/**/*.d.ts'],
  // Coverage floor: a few points below current full-source coverage, ratcheting
  // toward the 90% FE target as the pages get component tests.
  coverageThreshold: { global: { statements: 62, branches: 55, functions: 58, lines: 65 } },
});

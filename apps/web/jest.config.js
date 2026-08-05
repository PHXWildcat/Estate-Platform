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
  // toward the 90% FE target as the pages get component tests. Raised with M8
  // PR5, whose AssetsPanel/SignOutButton tests lifted the real number, and
  // RATCHETED again at M10 PR4 from a measured `--coverage` run
  // (80.08/74.09/83.33/83.76) — the readiness panel, its consent controls and
  // the finding-copy table all arrived with tests. Measured, not guessed: PR3's
  // CI failure was a floor nobody had run.
  coverageThreshold: { global: { statements: 79, branches: 73, functions: 82, lines: 83 } },
});

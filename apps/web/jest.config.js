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
  // RATCHETED again at M11 (the conversation surface): measured
  // 80.71/75.32/84.66/84.55 with the chat panel and the message renderer under
  // test. Never lowered.
  // RATCHETED again at M12 (the documents surface): PR1 measured
  // 82.26/78.88/85.65/85.90 — the viewer, the two panels, the generator, the
  // revise gate and the copy table all arrived with tests — and PR2 measured
  // 82.96/79.13/85.77/86.42 with upload, search and the execution ladder.
  // Measured from a local `--coverage` run, never guessed: the one time a
  // floor was invented from an unmeasured number (M10 PR3) it failed CI.
  // RATCHETED once more by the M12 SECURITY REVIEW, which added the binary
  // presentation, the write-path guards and the widened embedding fence:
  // measured 83.13/79.48/85.88/86.55.
  // M13 PR2 re-measured with the people surface: 85.36/82.08/87.13/88.74.
  // Ratcheted up from 83/79/85/86 — never down.
  // M13 PR3, measured: 86.02/82.6/87.43/89.37. Ratcheted up from 85/82/87/88.
  // M16 PR1 re-measured with the paired-devices list, the pairing ceremony and
  // the audience vocabulary under test: 86.5/83.63/87.52/89.87. Branches
  // ratcheted 82 -> 83. Never down.
  // Ratcheted up with M19 PR2's measured 87.33/83.38/88.16/90.61 — up, never down.
  // M20 PR3 measured 88.85/84.83/89.66/92.15 (isolated run): lines 91 -> 92.
  coverageThreshold: { global: { statements: 88, branches: 84, functions: 89, lines: 92 } },
});

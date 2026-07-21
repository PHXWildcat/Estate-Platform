'use strict';
const path = require('path');

/**
 * Shared Jest configuration factory.
 *
 * @param {string} pkgDir - absolute directory of the package (pass __dirname
 *   from the package's jest.config.js).
 * @param {object} [overrides] - shallow-merged over the defaults. Pass
 *   `coverageThreshold` to set a per-package regression floor.
 * @returns {import('jest').Config}
 */
module.exports = function makeJestConfig(pkgDir, overrides = {}) {
  return {
    testEnvironment: 'node',
    testMatch: ['**/*.spec.ts', '**/*.test.ts'],
    transform: {
      '^.+\\.ts$': ['ts-jest', { tsconfig: path.join(pkgDir, 'tsconfig.json') }],
    },
    clearMocks: true,
    collectCoverageFrom: ['src/**/*.ts'],
    ...overrides,
  };
};

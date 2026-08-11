'use strict';
// Coverage floor set from the FIRST measured run of this package (M16 PR2a),
// with the floor placed just below it. Ratcheted up thereafter, never down —
// the M10 PR3 lesson about a floor nobody had produced a number for.
//
// `main.ts` sits at 0% and that is deliberate: it is a three-line bootstrap
// around code the suite drives directly, and a test that imports it only proves
// it can be imported (the `vault-web` precedent, stated the same way).
module.exports = require('@estate/config/jest')(__dirname, {
  testEnvironment: 'jsdom',
  // jsdom is a DOM implementation, not a browser: no `structuredClone`, which
  // `chrome.storage` semantics depend on. See the file for what the stand-in
  // does and does not prove.
  setupFiles: ['<rootDir>/test/setup-jsdom.ts'],
  /*
   * The source's relative imports carry an explicit `.js`, because they are
   * NATIVE ES MODULES that the browser loads as written — there is no bundler
   * here on purpose (see tsconfig.build.json). Jest resolves from the
   * TypeScript sources, so it needs the extension mapped back off.
   *
   * Deliberately narrow: RELATIVE specifiers only, so a bare package specifier
   * still fails to resolve rather than being silently redirected. The fence in
   * `fences.spec.ts` forbids those anyway, and two mechanisms disagreeing about
   * which imports are legal is how one of them stops meaning anything.
   */
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  // `chrome.d.ts` is a declaration, not code: it emits nothing and can be
  // neither executed nor covered, so counting it would drag the number down
  // with a file no test could ever reach.
  coveragePathIgnorePatterns: ['\\.d\\.ts$'],
  coverageThreshold: { global: { statements: 95, branches: 88, functions: 96, lines: 96 } },
});

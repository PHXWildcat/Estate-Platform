'use strict';
// Coverage floor set from the FIRST measured run of this package (M15 PR1):
// 83.82/76.25/86.36/86.31, with the floor placed just below it. Ratcheted up
// thereafter, never down — the M10 PR3 lesson about a floor nobody had produced
// a number for.
//
// The two `main.ts` entry points sit at 0% and that is deliberate: each is a
// three-line bootstrap around code the suite drives directly, and a test that
// imports one only proves it can be imported.
module.exports = require('@estate/config/jest')(__dirname, {
  /*
   * The client's relative imports carry an explicit `.js`, because they are
   * NATIVE ES MODULES that a browser loads as written (see
   * tsconfig.client.json — there is no bundler here on purpose). Jest resolves
   * from the TypeScript sources, so it needs the extension mapped back off.
   *
   * Deliberately narrow: it rewrites RELATIVE specifiers only, so a bare
   * package specifier still fails to resolve rather than being silently
   * redirected — the fence in `fences.spec.ts` forbids those anyway, and two
   * mechanisms disagreeing about which imports are legal is how one of them
   * stops meaning anything.
   */
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  coverageThreshold: { global: { statements: 83, branches: 75, functions: 85, lines: 85 } },
});

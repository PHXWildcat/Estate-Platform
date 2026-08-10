'use strict';
// Coverage floor set from the FIRST measured run of this package (M15 PR1):
// 83.82/76.25/86.36/86.31, with the floor placed just below it. Ratcheted up
// thereafter, never down — the M10 PR3 lesson about a floor nobody had produced
// a number for.
//
// M15 PR2 re-measured at 88.49/75.54/86.48/90.53 with the vault surface, the
// device store, the generator and the clipboard under test. Raised to just
// below that. The PR2 run is what surfaced two real defects — a malformed
// Secret Key throwing with no message, and two fields sharing a visible label —
// so the floor did its job by refusing to be met without them.
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
  /*
   * jsdom is a DOM implementation, not a browser: no TextEncoder, no WebCrypto.
   * The vault client needs both, so Node's own implementations of the same
   * specs are installed first. See the file for what that does and does not
   * prove.
   */
  setupFiles: ['<rootDir>/test/setup-jsdom.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    /*
     * The client loads vault-crypto from this ORIGIN by absolute path. Jest
     * resolves it to the package SOURCE rather than to `dist`, so the suite
     * exercises the real crypto and cannot be fooled by a stale build — the
     * 2026-08-06 rule that a stale artifact is not evidence about source.
     */
    '^/lib/vault-crypto/index\\.js$': '<rootDir>/../../packages/vault-crypto/src/index.ts',
  },
  coverageThreshold: { global: { statements: 89, branches: 77, functions: 86, lines: 91 } },
});

'use strict';
// A pure-arithmetic package with no I/O and no branches to leave uncovered, so
// the floor is the repo's target rather than a few points below it. Anything
// less here would be a gap in the one module whose wrongness is silent: a
// rounding error does not throw, it just makes an estate slightly untrue.
module.exports = require('@estate/config/jest')(__dirname, {
  coverageThreshold: { global: { statements: 100, branches: 100, functions: 100, lines: 100 } },
});

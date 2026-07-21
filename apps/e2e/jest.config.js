'use strict';
const base = require('@estate/config/jest')(__dirname);
// Test-only package: no src/, coverage is not collected here.
module.exports = { ...base, collectCoverageFrom: [] };

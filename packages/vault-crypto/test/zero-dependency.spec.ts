/**
 * The zero-dependency rule, enforced.
 *
 * docs/04 boundary rule 3 makes the empty dependency tree the control for this
 * package's audit surface (docs/03 TB6, risk #4). An ESLint fence catches a
 * violation while typing; this spec is the one that fails the build, and it
 * scans the source directly rather than trusting the linter to be configured.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import packageJson from '../package.json';

const SRC = join(__dirname, '..', 'src');

function sourceFiles(): string[] {
  return readdirSync(SRC)
    .filter((name) => name.endsWith('.ts'))
    .map((name) => join(SRC, name));
}

/** Comments discuss other packages by name; only real specifiers count. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function importSpecifiers(file: string): string[] {
  const code = stripComments(readFileSync(file, 'utf8'));
  const patterns = [
    /^\s*import\s[\s\S]*?from\s*['"]([^'"]+)['"]/gm, // import x from 'y'
    /^\s*import\s*['"]([^'"]+)['"]/gm, // import 'y'
    /^\s*export\s[\s\S]*?from\s*['"]([^'"]+)['"]/gm, // export … from 'y'
    /\bimport\s*\(\s*['"]([^'"]+)['"]/g, // await import('y')
    /\brequire\s*\(\s*['"]([^'"]+)['"]/g, // require('y')
  ];
  return patterns.flatMap((pattern) => [...code.matchAll(pattern)].map((match) => match[1] ?? ''));
}

describe('@estate/vault-crypto dependency surface', () => {
  it('declares no runtime dependencies', () => {
    expect(packageJson).not.toHaveProperty('dependencies');
    expect(packageJson).not.toHaveProperty('peerDependencies');
    expect(packageJson).not.toHaveProperty('optionalDependencies');
  });

  it('has source files to check', () => {
    expect(sourceFiles().length).toBeGreaterThan(5);
  });

  it('finds the imports it is meant to be checking', () => {
    // Guards against the scan silently matching nothing and passing vacuously.
    expect(importSpecifiers(join(SRC, 'keyset.ts')).length).toBeGreaterThan(3);
  });

  it.each(sourceFiles())('%s imports nothing outside this package', (file) => {
    for (const specifier of importSpecifiers(file)) {
      // Relative only: no packages, and not even node: builtins, which would
      // also break the browser build this package promises.
      expect(specifier).toMatch(/^\.\.?\//);
    }
  });

  it('never imports the server-side crypto package', () => {
    for (const file of sourceFiles()) {
      expect(importSpecifiers(file)).not.toContain('@estate/crypto');
    }
  });
});

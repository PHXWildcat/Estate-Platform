import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * WHAT THIS SURFACE OFFERS MUST BE WHAT THE PLATFORM ENFORCES, and neither side
 * can import the other — this app cannot depend on a Nest service, so the check
 * reads the other file and asserts agreement (the M8 compose-parity mechanism,
 * as used by `step-up.test.ts` for auth-guard's cache TTL).
 *
 * The defect this closes was exactly a drift of this kind, standing for three
 * milestones: `RESOURCES` offered contacts, assets and documents, and profile's
 * only grant reader honoured `contact`/`read` alone. Both lists were internally
 * consistent, both suites were green, and the product told owners they had
 * shared their assets. A drift between a promise and its enforcement is not
 * something either side's tests can see on their own.
 */
const ENFORCED_GRANTS_SRC = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'apps',
  'services',
  'profile',
  'src',
  'enforced-grants.ts',
);

const ROLE_CONTROLS_SRC = join(__dirname, 'RoleControls.tsx');

/** Comments stripped, so prose describing a resource cannot stand in for one. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('the people surface offers exactly what profile enforces', () => {
  it('grants a resource here only if profile declares it enforced', () => {
    // Parsed, never evaluated: reading a constant must not run the file.
    const enforced = [
      ...code(readFileSync(ENFORCED_GRANTS_SRC, 'utf8')).matchAll(
        /resource:\s*'([a-z][a-z0-9_.]*)'/g,
      ),
    ].map(([, resource]) => resource as string);

    const grantable = [
      ...code(readFileSync(ROLE_CONTROLS_SRC, 'utf8')).matchAll(
        /resource:\s*'([a-z][a-z0-9_.]*)',[\s\S]{0,400}?grantable:\s*(true|false)/g,
      ),
    ]
      .filter(([, , flag]) => flag === 'true')
      .map(([, resource]) => resource as string);

    // Anti-vacuity in BOTH directions: two regexes that quietly match nothing
    // agree perfectly. A fence that stops matching goes green, which is the
    // failure this repo keeps finding in its own fences.
    expect(enforced.length).toBeGreaterThan(0);
    expect(grantable.length).toBeGreaterThan(0);

    expect([...new Set(grantable)].sort()).toEqual([...new Set(enforced)].sort());
  });

  it('states the flag on every resource rather than leaving it to be inferred', () => {
    // A missing `grantable` key fails SAFE at runtime (filtered out, so no
    // button) and fails SILENT here: the extractor above only sees entries that
    // carry the flag, so an unflagged resource would be absent from both lists
    // and the equality would pass over it. Requiring one flag per entry is what
    // makes the equality total.
    const source = code(readFileSync(ROLE_CONTROLS_SRC, 'utf8'));
    const start = source.indexOf('const RESOURCES');
    const end = source.indexOf('];', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const table = source.slice(start, end);

    const resources = [...table.matchAll(/resource:\s*'/g)].length;
    const flags = [...table.matchAll(/grantable:\s*(?:true|false)/g)].length;
    expect(resources).toBeGreaterThan(1);
    expect(flags).toBe(resources);
  });
});

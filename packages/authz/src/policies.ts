import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The in-repo policy set: every `.cedar` file under `packages/authz/policies`,
 * concatenated in sorted order. Policies are versioned and reviewed like code
 * (docs/01 §5). `loadBundledPolicies()` reads the set shipped with this
 * package; services can also pass their own text to PolicyDecisionPoint.
 */

export function loadPolicyDir(dir: string): string {
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.cedar'))
    .sort();
  return files.map((f) => readFileSync(join(dir, f), 'utf8')).join('\n\n');
}

/** Absolute path to the policies bundled with this package. */
export const BUNDLED_POLICY_DIR = join(__dirname, '..', 'policies');

export function loadBundledPolicies(): string {
  return loadPolicyDir(BUNDLED_POLICY_DIR);
}

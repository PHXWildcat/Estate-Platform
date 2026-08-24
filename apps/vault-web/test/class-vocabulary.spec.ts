/**
 * EVERY CLASS THIS ORIGIN NAMES IS ONE ITS STYLESHEET DEFINES (M27 PR2).
 *
 * A `className` is a string. An app that names a class nothing defines
 * type-checks, lints, and passes every unit test while rendering unstyled — the
 * defect commit 8a255e6 closed for `apps/web`, whose fence says in its own
 * comment that this origin still needs one. M27 PR1a's browser drive is what
 * caught the equivalent here, by eye, which is not a gate.
 *
 * PR2 is the first change to add markup to this origin in several milestones,
 * so it is the change that owes the fence.
 *
 * BOTH SETS ARE DERIVED. A hand-listed vocabulary beside a growing stylesheet
 * is this repo's most repeated defect, and the fence would then be asserting
 * that two copies of a list agree rather than that the app is styled.
 *
 * THE ONE INTERPOLATED CLASS IS EXPANDED FROM ITS OWN SOURCE. `status()` builds
 * `status status-${tone}` from a `'ok' | 'warn' | 'error'` union, and a scan
 * that took the literal would either record a token no stylesheet can define
 * (making this red on arrival) or match only quoted strings — silently
 * exempting the most-used class family on the origin, which is a fence whose
 * input is narrower than its claim. The union is read from the signature that
 * produces it, so a fourth tone widens this automatically.
 *
 * ONE DIRECTION ONLY. `used ⊆ defined` is asserted; `defined ⊆ used` is not.
 * The stylesheet legitimately defines classes only `public/index.html` uses
 * (`shell`, `rail`, `brand`, `foot`), and a dead-CSS rule is a different claim
 * needing a different corpus.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const CLIENT_DIR = join(__dirname, '..', 'src', 'client');
const STYLES = join(__dirname, '..', 'public', 'styles.css');
const INDEX = join(__dirname, '..', 'public', 'index.html');

/** Class selectors the stylesheet actually defines. */
function definedClasses(): Set<string> {
  const css = readFileSync(STYLES, 'utf8');
  const found = new Set<string>();
  for (const m of css.matchAll(/\.([a-zA-Z][\w-]*)/g)) found.add(m[1] as string);
  return found;
}

/**
 * The tone vocabulary, read from the `status()` signature rather than restated.
 * Anchored on the parameter the runtime interpolates, not on a name.
 */
function toneValues(source: string): string[] {
  const match = /tone:\s*((?:'[a-z]+'\s*\|\s*)+'[a-z]+')/.exec(source);
  if (!match) throw new Error('could not derive the tone union from app.ts');
  return [...(match[1] as string).matchAll(/'([a-z]+)'/g)].map((m) => m[1] as string);
}

/** Every class named by client source, with the one interpolation expanded. */
function usedClasses(): Set<string> {
  const files = readdirSync(CLIENT_DIR).filter((f) => f.endsWith('.ts'));
  // ANTI-VACUITY ON THE CORPUS ITSELF: a wrong directory reads as "nothing
  // names a class", which is indistinguishable from a clean result.
  if (files.length < 5) throw new Error(`client corpus looks wrong: ${files.length} files`);
  const app = readFileSync(join(CLIENT_DIR, 'app.ts'), 'utf8');
  const tones = toneValues(app);

  const used = new Set<string>();
  for (const file of files) {
    const source = readFileSync(join(CLIENT_DIR, file), 'utf8');
    for (const m of source.matchAll(/class:\s*(?:`([^`]*)`|'([^']*)')/g)) {
      const literal = (m[1] ?? m[2] ?? '').trim();
      const expansions = literal.includes('${')
        ? tones.map((tone) => literal.replace(/\$\{[^}]*\}/g, tone))
        : [literal];
      for (const expansion of expansions) {
        for (const token of expansion.split(/\s+/)) if (token) used.add(token);
      }
    }
  }
  // The static shell names classes too, and they are the app's just as much.
  for (const m of readFileSync(INDEX, 'utf8').matchAll(/class="([^"]*)"/g)) {
    for (const token of (m[1] as string).split(/\s+/)) if (token) used.add(token);
  }
  return used;
}

describe('the vault origin’s class vocabulary (M27 PR2)', () => {
  const defined = definedClasses();
  const used = usedClasses();

  it('found both vocabularies at all', () => {
    // Two empty sets are a subset of each other. Without this, a moved
    // stylesheet or a renamed attribute makes the assertion below vacuous.
    expect(defined.size).toBeGreaterThanOrEqual(20);
    expect(used.size).toBeGreaterThanOrEqual(15);
  });

  it('expanded the interpolated class family', () => {
    // `status-ok` appears NOWHERE as a literal — it exists only through
    // `status status-${tone}`. If the expansion silently stopped working this
    // token would vanish and the subset check would pass while ignoring the
    // most-used family on the origin.
    expect(used.has('status-ok')).toBe(true);
    expect(used.has('status-error')).toBe(true);
  });

  it('names no class the stylesheet does not define', () => {
    const undefinedClasses = [...used].filter((c) => !defined.has(c)).sort();
    expect(undefinedClasses).toEqual([]);
  });
});

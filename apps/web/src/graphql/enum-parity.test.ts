import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * EVERY GRAPHQL ENUM IS DECLARED TWICE, AND UNTIL THIS FILE NOTHING COMPARED THE
 * COPIES.
 *
 * The BFF declares each one in its SDL; this app re-declares it as a string
 * union in `client.ts`, because apps/web cannot import from apps/bff (a separate
 * workspace package with a Nest dependency tree — the same constraint that gave
 * `error-codes.test.ts` and `step-up.test.ts` their read-the-file shape).
 *
 * WHAT THIS CAUGHT, live on the running stack (M20 PR1): `MfaLevel` was declared
 * here as `'none' | 'mfa' | 'stepup'` while GraphQL serialises an enum as its
 * NAME, so the wire carries `"NONE"`. Every `session.mfaLevel === 'none'` in the
 * app was therefore PERMANENTLY FALSE, and an account with no `mfa_methods` row
 * at all was shown "MFA enrolled" and offered "Re-enroll authenticator app" —
 * a security page stating the opposite of its own state, on the two controls a
 * person reads to decide whether their account has a second factor.
 *
 * NEITHER EXISTING GATE COULD SEE IT. `tsc` compares values against this
 * DECLARATION and the declaration was the thing that was wrong, so a comparison
 * that can never be true type-checks perfectly. And every fixture in the suite
 * said `mfaLevel: 'mfa'` — the same invented vocabulary — which is the M15
 * lesson that a fixture inventing an enum tests the fixture. Only running it
 * against a real BFF said otherwise.
 *
 * DIRECTION, stated because it is not symmetric: this checks SDL → app. It
 * cannot check app → SDL, because most unions here (`GqlErrorCode`,
 * `GqlFailureCode`) are not GraphQL enums at all. So a renamed enum fails on its
 * new name (loudly) and leaves the old union behind as dead code (harmlessly).
 */
const BFF_SCHEMA = join(__dirname, '..', '..', '..', '..', 'apps', 'bff', 'src', 'schema.ts');
const APP_CLIENT = join(__dirname, 'client.ts');

/** The enums the BFF's SDL declares, as `name -> members`. */
function schemaEnums(): Map<string, string[]> {
  const source = readFileSync(BFF_SCHEMA, 'utf8');
  // ANCHORED AT BOTH ENDS on the tagged template that holds the SDL. A scan that
  // is too wide catches a planted defect and hides that it is not reading the
  // stated layer (the M15 review's proxy-allowlist fence).
  const sdl = /export const typeDefs = \/\* GraphQL \*\/ `([\s\S]*?)\n`;/.exec(source);
  expect(sdl?.[1]).toBeTruthy();
  const body = sdl?.[1] ?? '';

  const found = new Map<string, string[]>();
  for (const [, name, members] of body.matchAll(/\benum\s+(\w+)\s*\{([^}]*)\}/g)) {
    /*
     * DESCRIPTIONS STRIPPED FIRST. A GraphQL member may carry a `""".."""`
     * description, and splitting the body on whitespace turns every WORD of
     * that prose into a member — which is what happened the first time a member
     * in this schema was documented: the fence went red listing "Named", "a",
     * "and" as enum members. Silently wrong in the loud direction this time,
     * but a parser that cannot read a legal construct is a parser that either
     * lies or forbids documenting the thing it checks.
     */
    // BOTH legal spellings. Block descriptions were stripped from M21 PR4b;
    // single-line `"…"` ones were not, and this SDL already uses that spelling
    // on `Session`'s fields — so documenting an enum member the same way turned
    // every word of the prose into a member. Loud, not silent: it could not
    // certify a wrong mirror, but a parser that cannot read a legal construct
    // forbids documenting the thing it checks, which is the complaint the
    // comment above raises about the state this replaced.
    const declarations = (members as string)
      .replace(/"""[\s\S]*?"""/g, ' ')
      .replace(/"(?:[^"\\\n]|\\.)*"/g, ' ');
    // Anti-vacuity: stripping must never leave an enum with no members at all.
    const parsed = declarations.split(/\s+/).filter(Boolean);
    expect({ enum: name, members: parsed.length > 0 }).toEqual({ enum: name, members: true });
    found.set(name as string, parsed);
  }
  return found;
}

/** The string-literal unions this app exports, as `name -> members`. */
function appUnions(): Map<string, string[]> {
  const source = readFileSync(APP_CLIENT, 'utf8');
  const found = new Map<string, string[]>();
  for (const [, name, body] of source.matchAll(/export type (\w+) =([^;]*);/g)) {
    const members = [...(body as string).matchAll(/'([^']+)'/g)].map(([, m]) => m as string);
    if (members.length > 0) found.set(name as string, members);
  }
  return found;
}

describe('the BFF’s GraphQL enums and this app’s copies of them', () => {
  it('agree member for member, for every enum the SDL declares', () => {
    const enums = schemaEnums();
    const unions = appUnions();

    // ANTI-VACUITY, on both scans. The M14 review found a credential-graph scan
    // that had silently stopped matching and gone green for a whole milestone;
    // two regexes that quietly match nothing agree perfectly.
    expect(enums.size).toBeGreaterThanOrEqual(5);
    expect(enums.get('MfaLevel')).toEqual(['NONE', 'MFA', 'STEPUP']);
    expect(unions.size).toBeGreaterThanOrEqual(5);

    for (const [name, members] of enums) {
      // A GraphQL enum with no mirror is not an omission this fence tolerates:
      // the app either models the enum or does not select the field, and an
      // absent union means somebody is about to hand-write the literals inline
      // where nothing compares them (which is where these two started).
      expect(unions.has(name)).toBe(true);
      // EQUALITY, not containment, and sorted so declaration order is free.
      expect([...(unions.get(name) as string[])].sort()).toEqual([...members].sort());
    }
  });

  it('spells them the way the wire does — enum members serialise as their NAME', () => {
    // The defect this file exists for was a CASE mismatch, and the equality
    // check above would also catch a same-case renaming. This case names the
    // property on its own so a future reader knows which layer it is about: the
    // app compares against raw JSON, so an SDL member and its mirror must match
    // byte for byte, not case-insensitively.
    for (const [name, members] of schemaEnums()) {
      for (const member of members) {
        expect(member).toBe(member.toUpperCase());
        expect(appUnions().get(name)).toContain(member);
      }
    }
  });
});

/**
 * EVERY PATH THAT MINTS A SESSION, DECLARED (M17 PR3).
 *
 * docs/04's M17 decision 2 said PR3 must "assert what a reset session CANNOT
 * do, the way `session-audience.spec.ts` derives its refused set". That
 * sentence presumes a reset session EXISTS. It does not: redemption sets the
 * password and returns no tokens, so there is nothing to constrain — which is
 * a stronger property than any refused-set assertion, because a capability that
 * is never created cannot be mis-scoped.
 *
 * So this is the fence that property actually needs. It asserts the SET of mint
 * paths, and the reset is proven absent from it. Adding one is then a deliberate
 * edit to the table below, which is where somebody has to think about what
 * audience it states — the same reason `SessionsRepo.create` made `audience`
 * required rather than defaulted.
 *
 * ═══ THE HAZARDS THIS SCAN IS ARRANGED AROUND ═══
 *
 * Each one is a way a naive scan for the literal `sessions.create(` would be
 * wrong, and every one of them exists in this repo today:
 *
 *  · VAULT HAS AN UNRELATED `this.sessions.create(` — a different class
 *    (`VaultSessionsRepo`), a different table, a vault UNLOCK rather than an
 *    account session. Scoping to identity's `src` is what excludes it.
 *  · TESTS AND BUILD OUTPUT contain the same text. Eight test files call it,
 *    and `coverage/lcov-report/*.html` has matched a source-shaped grep in this
 *    repo before.
 *  · COMMENTS mention it — `auth.service.ts` and `sessions.repo.ts` both
 *    discuss "mint paths" in prose. Comments are stripped before scanning.
 *  · A NAME-KEYED SCAN IS EVADABLE BY RENAMING THE FIELD, which is exactly how
 *    the credential-graph fence went blind for a whole milestone (2026-08-07).
 *    So the anchor is the injected TYPE — `SessionsRepo` — resolved from the
 *    constructor annotation, not the identifier a caller chose.
 *  · A MINT CAN BYPASS THE REPO ENTIRELY with a raw `INSERT INTO sessions`.
 *    Asserted separately, because no method-name scan can see it.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(__dirname, '..', 'src');

/**
 * The three paths that may mint an account session, with WHY each exists.
 * Declared as data with a reason per entry — the credential-graph convention —
 * because "which code may create a credential" is a security question and a
 * bare list invites someone to append to it without answering one.
 */
const MINT_PATHS: ReadonlyArray<{ file: string; audience: string; why: string }> = [
  {
    file: 'auth.service.ts',
    audience: 'DEFAULT_SESSION_AUDIENCE',
    why: 'login — the ordinary session, and the only one a password produces',
  },
  {
    file: 'handoff.service.ts',
    audience: 'handoff.audience',
    why: 'the M15 vault handoff: 15 minutes, no usable refresh token, no step-up',
  },
  {
    file: 'extension-pairing.service.ts',
    audience: "'extension'",
    why: 'the M16 pairing: a real refresh token, 30-day hard cap, no step-up',
  },
];

/** Source with block and line comments removed, so prose cannot look like code. */
function code(file: string): string {
  return readFileSync(join(SRC, file), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

function sourceFiles(): string[] {
  return readdirSync(SRC).filter((name) => name.endsWith('.ts'));
}

/** Files whose constructor injects `SessionsRepo`, by TYPE rather than by name. */
function injectsSessionsRepo(file: string): string | null {
  const match = /(?:private|readonly)\s+(?:readonly\s+)?(\w+)\s*:\s*SessionsRepo\b/.exec(
    code(file),
  );
  return match ? (match[1] as string) : null;
}

describe('the session mint paths are a closed, declared set', () => {
  it('finds the surface it is meant to be checking', () => {
    // Anti-vacuity, and the floor is the DECLARED size rather than 1: a scan
    // that found only one mint path must not pass while two go unwatched.
    const files = sourceFiles();
    expect(files.length).toBeGreaterThanOrEqual(20);
    expect(MINT_PATHS.length).toBeGreaterThanOrEqual(3);
    for (const { file } of MINT_PATHS) {
      expect(files).toContain(file);
    }
  });

  it('EXACTLY the declared files call sessions.create — no more, no fewer', () => {
    // The property docs/04 decision 2 actually wanted. A fourth caller — the
    // reset service being the one this PR is about — turns this red, and the
    // fix is to come here and say what audience it mints and why.
    const callers = sourceFiles().filter((file) => {
      const field = injectsSessionsRepo(file);
      return field !== null && new RegExp(`this\\.${field}\\.create\\(`).test(code(file));
    });
    expect(callers.sort()).toEqual(MINT_PATHS.map((m) => m.file).sort());
  });

  it('THE PASSWORD RESET MINTS NOTHING — the whole point of its shape', () => {
    // Named rather than left to the sweep, because this is the sentence docs/03
    // §6m makes a claim about and the M15 PR4 escalation is what it prevents:
    // an unauthenticated redeem route that produced a session would be that
    // escalation delivered by email, to a code that lives thirty minutes.
    const reset = code('password-reset.service.ts');
    expect(reset).toContain('completeReset');
    expect(reset).not.toMatch(/\.create\(/);
    expect(reset).not.toContain('generateOpaqueToken');
    expect(reset).not.toContain('grantStepUp');
    // …and it does not import the token minter at all, so it could not start.
    expect(reset).not.toMatch(/from '\.\/tokens'/);
  });

  it('each declared path states its audience, and none defaults', () => {
    // `SessionsRepo.create` made `audience` required precisely so a new mint
    // path cannot compile without stating one. This asserts the value is
    // actually at the call site rather than derived somewhere a reader cannot
    // see — one of them is a column (`handoff.audience`), which is deliberate
    // and constrained by that table's own CHECK.
    for (const { file, audience } of MINT_PATHS) {
      expect({ file, states: code(file).includes(audience) }).toEqual({ file, states: true });
    }
  });

  it('NOTHING bypasses the repo with a raw INSERT into sessions', () => {
    // No method-name scan can see this, so it is its own assertion. A raw
    // insert would skip the required-audience type entirely and could write the
    // DDL default — which is `account`, the most powerful thing the column can
    // hold.
    for (const file of sourceFiles()) {
      const text = code(file);
      expect({ file, rawInsert: /INSERT\s+INTO\s+sessions\b/i.test(text) }).toEqual({
        file,
        rawInsert: file === 'sessions.repo.ts',
      });
    }
  });
});

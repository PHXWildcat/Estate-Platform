/**
 * EVERY PATH THAT GRANTS STEP-UP, DECLARED (M25 PR5).
 *
 * The sibling of `mint-paths.spec.ts`, and the reason it lands with the erasure
 * milestone rather than with the step-up machinery it guards. Step-up is the
 * key to a growing set of doors, and until M25 the worst thing behind one was a
 * single zone — the M15 PR4 escalation, where an unauthenticated redeem route
 * that granted step-up let a stolen code reach `POST /v1/vault/reset` and
 * crypto-shred a Zone A vault. ACCOUNT ERASURE MOVES THE CEILING: the same
 * escalation now reaches a verb that destroys the account's own key. A third
 * grant path arriving quietly is worth a red suite.
 *
 * WHAT THIS ASSERTS. The set of files that may call
 * `SessionsRepo.grantStepUp` is exactly the two below, each with a reason —
 * the credential-graph convention, because "which code may grant a credential"
 * is a security question and a bare list invites someone to append to it
 * without answering one.
 *
 * ═══ THE HAZARDS THIS SCAN IS ARRANGED AROUND ═══
 *
 * Deliberately the same set `mint-paths.spec.ts` names, and for the same
 * reasons — one behaviour, one spelling:
 *
 *  · A NAME-KEYED SCAN IS EVADABLE BY RENAMING THE FIELD, which is how the
 *    credential-graph fence went blind for a whole milestone (2026-08-07). The
 *    anchor is the injected TYPE, `SessionsRepo`, resolved from the constructor
 *    annotation — not the identifier a caller happened to choose.
 *  · COMMENTS MENTION IT. `webauthn.service.ts` discusses `grantStepUp` in
 *    prose two hundred lines above the call, and `password-reset.service.ts`
 *    is asserted below to be free of it — a scan that read prose would find it
 *    in the file whose whole point is that it does not do this.
 *  · A GRANT CAN BYPASS THE REPO with a raw UPDATE of `stepup_expires_at`.
 *    Asserted separately, because no method-name scan can see it.
 *  · THE FRESHNESS WINDOW IS A SECOND WAY TO WIDEN A GRANT without adding a
 *    caller. A path that granted a longer window than `STEPUP_WINDOW_MS` would
 *    pass every assertion about WHO grants, so the value is checked too.
 *
 * WHAT IT DOES NOT PROVE: that a grant is preceded by a real factor proof. That
 * is `auth.service.spec.ts` and `webauthn.service.spec.ts`, each of which
 * asserts its own path refuses to grant on a bad code, a cloned authenticator
 * and an unverified factor. Two halves, stated so neither is mistaken for the
 * whole.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(__dirname, '..', 'src');

/** The two paths that may grant step-up, with WHY each exists. */
const GRANT_PATHS: ReadonlyArray<{ file: string; why: string }> = [
  {
    file: 'auth.service.ts',
    why:
      'the TOTP step-up ceremony — a code from an enrolled, VERIFIED factor ' +
      '(`verifiedOnly: true`), behind a per-session and per-account guessing ' +
      'bound evaluated BEFORE the secret is scored.',
  },
  {
    file: 'webauthn.service.ts',
    why:
      'the M19 passkey assertion, reusing the same repo method and the same ' +
      'window. It refuses on counter regression (clone detection) rather than ' +
      'granting, which is the arm that makes this path a second FACTOR proof ' +
      'and not a second door.',
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

describe('the step-up grant paths are a closed, declared set', () => {
  it('finds the surface it is meant to be checking', () => {
    // Anti-vacuity, floored at the DECLARED size rather than 1: a scan that
    // found only one grant path must not pass while the other goes unwatched.
    const files = sourceFiles();
    expect(files.length).toBeGreaterThanOrEqual(20);
    expect(GRANT_PATHS.length).toBeGreaterThanOrEqual(2);
    for (const { file } of GRANT_PATHS) {
      expect(files).toContain(file);
    }
  });

  it('the TYPE-anchored resolver really resolves (positive control)', () => {
    // The scan below is a set comparison, and a resolver returning null for
    // everything would produce an empty set that matches nothing — red, but
    // for the wrong reason, and green the moment somebody "fixes" the
    // declaration to match. This proves the anchor finds a real field name.
    for (const { file } of GRANT_PATHS) {
      expect({ file, field: injectsSessionsRepo(file) }).toEqual({ file, field: 'sessions' });
    }
  });

  it('EXACTLY the declared files call grantStepUp — no more, no fewer', () => {
    // A third caller turns this red, and the fix is to come here and say what
    // proved a factor before it granted one.
    const callers = sourceFiles().filter((file) => {
      const field = injectsSessionsRepo(file);
      return field !== null && new RegExp(`this\\.${field}\\.grantStepUp\\(`).test(code(file));
    });
    expect(callers.sort()).toEqual(GRANT_PATHS.map((g) => g.file).sort());
  });

  it('EVERY grant path is a FACTOR proof — none is a ceremony redemption', () => {
    // The M15 PR4 rule stated as a property of the set rather than of one file:
    // an unauthenticated redeem route grants NO step-up, because redemption is
    // authority to do one thing and never a credential that can mint another.
    // The three redemption services are named because they are the category —
    // each holds a mailed or typed code, and each is a plausible place for
    // somebody to add "and sign them in properly while we are here".
    for (const file of [
      'password-reset.service.ts',
      'email-change.service.ts',
      'email-verification.service.ts',
      'handoff.service.ts',
      'extension-pairing.service.ts',
    ]) {
      expect({ file, grants: code(file).includes('grantStepUp') }).toEqual({
        file,
        grants: false,
      });
    }
  });

  it('NOTHING bypasses the repo with a raw UPDATE of the freshness column', () => {
    // No method-name scan can see this. A raw write would skip the repo
    // entirely and could set any window it liked.
    for (const file of sourceFiles()) {
      const text = code(file);
      expect({ file, rawGrant: /stepup_expires_at\s*=/i.test(text) }).toEqual({
        file,
        rawGrant: file === 'sessions.repo.ts',
      });
    }
  });

  it('both paths grant THE SAME window, and it is the shared constant', () => {
    // The second way to widen a grant WITHOUT adding a caller: two paths that
    // computed their own windows could drift, and the longer one would silently
    // become the freshness guarantee for every gated verb in the product.
    //
    // ANCHORED ON THE COMPUTATION, NOT ON A MENTION. The first version of this
    // asserted the file CONTAINED `STEPUP_WINDOW_MS` and a mutation replacing
    // the webauthn window with a literal hour SURVIVED IT — because the import
    // line still mentioned the constant. A fence whose input is wider than its
    // claim goes green for the same reason it is wrong. So the assignment
    // itself is extracted and each one must reference the constant.
    for (const { file } of GRANT_PATHS) {
      const text = code(file);
      const assignments = [...text.matchAll(/stepupExpiresAt\s*=\s*([^;]+);/g)].map((m) =>
        (m[1] as string).replace(/\s+/g, ' '),
      );
      // Anti-vacuity: an empty match set would satisfy `every` for free, and
      // that is precisely the shape a renamed local would produce.
      expect({ file, found: assignments.length }).toEqual({ file, found: 1 });
      expect({ file, assignments }).toEqual({
        file,
        assignments: ['new Date(now.getTime() + STEPUP_WINDOW_MS)'],
      });
    }
  });
});

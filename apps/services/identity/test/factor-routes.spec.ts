/**
 * EVERY PATH THAT MUTATES AN AUTHENTICATION FACTOR IS GATED — enforced.
 *
 * ═══ WHY A DECORATOR SCAN CANNOT DO THIS ═══
 *
 * The rule these routes obey is "you may add your FIRST factor with a session;
 * you may add another only by proving the one you have". The condition is
 * ACCOUNT STATE, which a route decorator cannot see, so the gate lives in
 * `SecondFactorGate` and is called from the services.
 *
 * Every other fence in this repo that checks step-up gating scans for the
 * `StepUpGuard` DECORATOR. A gate that lives in a service is invisible to all
 * of them — which is exactly how `POST /v1/auth/webauthn/register/verify` sat
 * `SessionGuard`-only while the TOTP twin was being fixed one file away, and
 * why measuring that fix found the same escalation still open through the other
 * factor. This file is the fence that would have said so.
 *
 * ═══ IT DISCOVERS BY WHAT THE CODE DOES, NOT BY WHAT IT IS CALLED ═══
 *
 * A table of route names would be a table somebody has to remember to update —
 * and the whole failure being closed here is a rule that was applied to one
 * factor and forgotten for the other. So discovery is anchored on the REPO
 * METHODS THAT WRITE FACTOR STATE. Anything that binds, confirms or retires a
 * factor must go through one of them, because they are the only code in the
 * service that touches `mfa_methods` or `webauthn_credentials`. A new enrolment
 * path, however it is named and whatever controller it hangs off, is discovered
 * by the call it has to make.
 *
 * That is the 2026-07-28 and 2026-08-07 lesson applied ahead of time: anchor on
 * what the RUNTIME does, never on an identifier a caller chose.
 *
 * ═══ SCOPE, STATED ═══
 *
 * Identity is the only service that can reach these tables — they live in the
 * auth cluster and no other service has a connection to it — so a repo-wide
 * scan would be a wider net over the same fish. `WRITERS` is asserted against
 * the real repo classes, so a renamed or deleted method fails here rather than
 * silently shrinking the net.
 *
 * What this deliberately does NOT cover: whether the gate's own POLICY is right
 * (that is `factor-enrollment-gate.int.spec.ts` and
 * `webauthn-enrollment-gate.int.spec.ts`, against real Postgres), and factor
 * mutations performed outside the service — an operator with psql is TB7's
 * problem, not a route's.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MfaRepo } from '../src/mfa.repo';
import { WebAuthnRepo } from '../src/webauthn.repo';

const SRC = join(__dirname, '..', 'src');

/**
 * THE METHODS THAT WRITE FACTOR STATE, and the reason each one counts.
 *
 * A read is not here: `hasVerifiedTotp`, `findActiveTotp`, `findCredentialById`
 * and friends answer questions, they do not bind anything. Adding a WRITER to
 * either repo means adding a line here, and the assertion below that every name
 * exists on its class is what stops this list quietly describing a repo that
 * has moved on.
 */
const WRITERS: ReadonlyArray<{
  readonly repo: string;
  readonly method: string;
  readonly why: string;
}> = [
  { repo: 'MfaRepo', method: 'insertTotp', why: 'binds a new TOTP secret to the account' },
  { repo: 'MfaRepo', method: 'markVerified', why: 'turns a pending secret into a usable factor' },
  { repo: 'MfaRepo', method: 'revokeUnverifiedTotp', why: 'retires pending secrets' },
  {
    repo: 'WebAuthnRepo',
    method: 'insertCredential',
    why: 'binds a new authenticator to the account',
  },
];

/**
 * WHICH SERVICE METHODS MAY WRITE FACTOR STATE, and how each is gated.
 *
 * `service-gate` means it calls `SecondFactorGate.assertMayAddFactor`, which is
 * asserted below rather than trusted. `proves-possession` means the caller had
 * to present a correct code or a verified assertion to reach it at all, so the
 * factor is already proven and a step-up would be asking for the same thing
 * twice.
 */
const GATED_BY = {
  SERVICE_GATE: 'service-gate',
  PROVES_POSSESSION: 'proves-possession',
} as const;

const DECLARED: ReadonlyArray<{
  readonly file: string;
  readonly method: string;
  readonly gate: (typeof GATED_BY)[keyof typeof GATED_BY];
  /**
   * Does this method itself WRITE factor state?
   *
   * The distinction was found by this fence on its first run, which is the best
   * argument for it existing: `startRegistration` is gated but writes no
   * factor — it issues a challenge. Collapsing the two would have meant either
   * dropping a real gate from the table or asserting a write that never
   * happens, and both are ways a table starts describing something other than
   * the code.
   */
  readonly writes: boolean;
  readonly why: string;
}> = [
  {
    file: 'auth.service.ts',
    method: 'enrollTotp',
    gate: GATED_BY.SERVICE_GATE,
    writes: true,
    why: 'mints a TOTP secret; the M16 PR5 escalation was this route ungated',
  },
  {
    file: 'auth.service.ts',
    method: 'verifyTotp',
    gate: GATED_BY.PROVES_POSSESSION,
    writes: true,
    why: 'reached only by submitting a correct code for the secret it confirms',
  },
  {
    file: 'webauthn.service.ts',
    method: 'startRegistration',
    gate: GATED_BY.SERVICE_GATE,
    writes: false,
    why: 'writes no factor — it issues the challenge, and is gated so a refusal comes before the hardware ceremony',
  },
  {
    file: 'webauthn.service.ts',
    method: 'finishRegistration',
    gate: GATED_BY.SERVICE_GATE,
    writes: true,
    why: 'binds the authenticator — the write the escalation needed',
  },
];

/** Source of every service module, comments stripped so prose cannot match. */
function services(): Array<{ file: string; code: string }> {
  return readdirSync(SRC)
    .filter((name) => name.endsWith('.service.ts'))
    .map((file) => ({
      file,
      code: readFileSync(join(SRC, file), 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, ''),
    }));
}

/** The method a given offset sits inside, by the nearest preceding declaration. */
function enclosingMethod(code: string, index: number): string {
  const before = code.slice(0, index);
  const decls = [...before.matchAll(/^\s{2}(?:private\s+|public\s+)?(?:async\s+)?(\w+)\s*\(/gm)];
  return decls.length > 0 ? (decls[decls.length - 1]?.[1] ?? '<none>') : '<none>';
}

/**
 * Which constructor field holds which repo, DERIVED FROM THE TYPE ANNOTATION.
 *
 * A bare method-name scan is not good enough, and this fence found that out on
 * its own first run: `EmailVerificationRepo` also has a `markVerified`, so
 * `email-verification.service.ts` was reported as an undeclared factor writer.
 * A false positive is not harmless here — the cheapest way to silence one is to
 * widen the declaration table, which is how a fence starts describing something
 * other than what it watches.
 *
 * Reading the TYPE rather than the field name is also what keeps this
 * un-evadable. `private readonly mfa: MfaRepo` could be renamed to anything;
 * what cannot change without changing the meaning is the type it is bound to.
 */
function repoFields(code: string, repo: string): string[] {
  const pattern = new RegExp(`readonly\\s+(\\w+)\\s*:\\s*${repo}\\b`, 'g');
  return [...code.matchAll(pattern)].map((m) => m[1] ?? '');
}

/** Every (file, method) that calls a factor WRITER on the repo that owns it. */
function writeSites(): Array<{ file: string; method: string; writer: string }> {
  const found: Array<{ file: string; method: string; writer: string }> = [];
  for (const { file, code } of services()) {
    for (const writer of WRITERS) {
      for (const field of repoFields(code, writer.repo)) {
        const call = new RegExp(`this\\.${field}\\.${writer.method}\\s*\\(`, 'g');
        for (const hit of code.matchAll(call)) {
          found.push({
            file,
            method: enclosingMethod(code, hit.index),
            writer: `${writer.repo}.${writer.method}`,
          });
        }
      }
    }
  }
  return found;
}

describe('the writers this fence watches are real', () => {
  it('every declared WRITER exists on its repo', () => {
    // Without this the net shrinks silently: a renamed method stops being
    // scanned for and every route that calls it becomes invisible.
    const classes: Record<string, Record<string, unknown>> = {
      MfaRepo: MfaRepo.prototype as unknown as Record<string, unknown>,
      WebAuthnRepo: WebAuthnRepo.prototype as unknown as Record<string, unknown>,
    };
    for (const { repo, method } of WRITERS) {
      const proto = classes[repo] ?? {};
      expect({ repo, method, present: typeof proto[method] }).toEqual({
        repo,
        method,
        present: 'function',
      });
    }
  });

  it('finds the write sites it is meant to be checking', () => {
    // Anti-vacuity. A scan that matches nothing passes every assertion below —
    // which is the failure this whole file exists to prevent, so it is the
    // first thing asserted rather than the last.
    const sites = writeSites();
    expect(sites.length).toBeGreaterThanOrEqual(WRITERS.length);
    expect(sites.every((s) => s.method !== '<none>')).toBe(true);
    // And both factor types are actually represented, so a scan that found only
    // TOTP writers cannot pass while WebAuthn goes unwatched — the exact shape
    // of the defect this closes.
    expect(sites.some((s) => s.writer.startsWith('MfaRepo'))).toBe(true);
    expect(sites.some((s) => s.writer.startsWith('WebAuthnRepo'))).toBe(true);
  });
});

describe('every path that writes a factor is declared and gated', () => {
  it('NO UNDECLARED method writes factor state', () => {
    // The direction that catches a new enrolment path: it is discovered by the
    // write it has to perform, whatever it or its route is called.
    const declared = new Set(DECLARED.map((d) => `${d.file}#${d.method}`));
    for (const site of writeSites()) {
      expect({
        site: `${site.file}#${site.method}`,
        writes: site.writer,
        declared: declared.has(`${site.file}#${site.method}`),
      }).toEqual({
        site: `${site.file}#${site.method}`,
        writes: site.writer,
        declared: true,
      });
    }
  });

  it('every entry CLAIMING to write really does, and every entry claiming not to does not', () => {
    // Both directions on the claim itself. An entry left behind after its write
    // moved away is dead weight that reads as coverage; an entry marked
    // `writes: false` that starts writing is a gate whose scope quietly grew.
    const sites = new Set(writeSites().map((s) => `${s.file}#${s.method}`));
    for (const entry of DECLARED) {
      const key = `${entry.file}#${entry.method}`;
      expect({ entry: key, writes: sites.has(key) }).toEqual({ entry: key, writes: entry.writes });
    }
  });

  it('every SERVICE-GATE entry actually calls the gate', () => {
    // The load-bearing assertion. A declaration that a method is gated is worth
    // nothing if the call was deleted; this reads the method body and looks for
    // it. `assertMayAddFactor` has a name a scan can anchor on precisely so
    // this is possible — it is deliberately not three inlined lines.
    const byFile = new Map(services().map((s) => [s.file, s.code]));
    for (const entry of DECLARED.filter((d) => d.gate === GATED_BY.SERVICE_GATE)) {
      const code = byFile.get(entry.file) ?? '';
      const sites = [...code.matchAll(/this\.factors\.assertMayAddFactor\s*\(/g)].map((hit) =>
        enclosingMethod(code, hit.index),
      );
      expect({
        entry: `${entry.file}#${entry.method}`,
        gated: sites.includes(entry.method),
      }).toEqual({ entry: `${entry.file}#${entry.method}`, gated: true });
    }
  });

  it('every entry carries a reason, so the table cannot become a list of names', () => {
    for (const entry of DECLARED) {
      expect({ entry: entry.method, reasoned: entry.why.length > 20 }).toEqual({
        entry: entry.method,
        reasoned: true,
      });
    }
    for (const writer of WRITERS) {
      expect({ writer: writer.method, reasoned: writer.why.length > 20 }).toEqual({
        writer: writer.method,
        reasoned: true,
      });
    }
  });
});

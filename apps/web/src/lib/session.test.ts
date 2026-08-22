import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { factorChip, stepUpChip } from './session';

/**
 * THE WORDING FENCE FOR A FIELD THAT HAS BEEN MISREAD TWICE (M24 PR4).
 *
 * `mfaLevel` is the SESSION's factor level. Rendering it as account enrolment
 * is not a typo — it is a claim the app cannot support, and it has now been
 * written twice by two different milestones (M20 fixed the enum and left the
 * sentence; M24 PR3 fixed `SessionCard`'s copy and left /security's). Both
 * times a person had to find it by signing in.
 *
 * So the rule stops being prose. The corpus is the COMPONENT TREE — read from
 * disk, not listed here, because a hand-kept list beside a directory that
 * grows is this repo's most repeated defect — and the forbidden spellings are
 * data. A new component that renders "MFA enrolled" reddens this the moment it
 * lands, whatever it is named and wherever it sits.
 */

const COMPONENTS_DIR = join(__dirname, '..', 'components');

/**
 * Sentences that assert something about the ACCOUNT's factor set. The app has
 * no field carrying that fact: `session` exposes `userId`, `mfaLevel` and
 * `stepUpFresh`, and the SDL has no account-level enrolment query at all, so
 * any component saying these words is stating something it cannot know.
 */
const ACCOUNT_CLAIMS = ['MFA enrolled', 'MFA not enrolled', 'Re-enroll authenticator app'] as const;

function componentSources(): ReadonlyArray<{ readonly file: string; readonly text: string }> {
  return readdirSync(COMPONENTS_DIR)
    .filter((name) => name.endsWith('.tsx') && !name.endsWith('.test.tsx'))
    .map((name) => ({ file: name, text: readFileSync(join(COMPONENTS_DIR, name), 'utf8') }));
}

describe('a session fact is never rendered as an account fact', () => {
  it('reads a real corpus — the anti-vacuity floor', () => {
    const sources = componentSources();
    // A scan that found nothing and a scan that read nothing look identical.
    expect(sources.length).toBeGreaterThan(30);
    // Two files this rule is ABOUT must be in the corpus, by name, or the
    // filter has quietly excluded the thing under test.
    expect(sources.map((s) => s.file)).toEqual(
      expect.arrayContaining(['Dashboard.tsx', 'SecurityPanel.tsx']),
    );
    // And the reader really returns source: the shared chips are imported by
    // the two surfaces that render them.
    const importers = sources.filter((s) => s.text.includes("from '../lib/session'"));
    expect(importers.map((s) => s.file).sort()).toEqual(['Dashboard.tsx', 'SecurityPanel.tsx']);
  });

  it('no component claims the ACCOUNT has (or lacks) a second factor', () => {
    /*
     * A PLAIN SUBSTRING SCAN, AND THE ABSENCE OF A PARSER IS THE POINT. The
     * first draft exempted matches that sat inside comments, so that the
     * comments explaining this defect could quote it — and that exemption is a
     * filter with a bug in it (a continuation line of a block comment does not
     * start with `*`, so the fence reported its own documentation). The fix is
     * the repo's own rule: prefer an ABSENCE to a filter. Nothing in the
     * component tree spells these strings, comments included; the wording that
     * was wrong is quoted in docs/03 §6tt and in this file, neither of which
     * can reach a screen.
     */
    const offenders: string[] = [];
    for (const source of componentSources()) {
      for (const claim of ACCOUNT_CLAIMS) {
        if (source.text.includes(claim)) {
          offenders.push(`${source.file}: ${claim}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('POSITIVE CONTROL: the scan can see a string that IS on screen', () => {
    // Without this, the test above passes for a scanner that reads no text at
    // all. "Password-only session" is the replacement wording and is rendered
    // by both surfaces through the shared chip.
    const seen = componentSources().filter((s) => s.text.includes('Password-only session'));
    expect(seen.map((s) => s.file).sort()).toEqual([]);
    // The chips live in lib/, so no component spells them; the label reaches
    // the DOM through this function, and THAT is what the surfaces import.
    expect(factorChip('NONE').label).toBe('Password-only session');
  });
});

describe('the chips say what the field measures', () => {
  it('NONE is a fact about this SESSION, not about the account', () => {
    expect(factorChip('NONE')).toEqual({
      label: 'Password-only session',
      className: 'chip chip-warn',
    });
  });

  it('an elevated session reads as verified, at both levels above NONE', () => {
    // MFA and STEPUP are both "a second factor was proven on this session" —
    // the distinction between them is freshness, which the step-up chip owns.
    expect(factorChip('MFA').label).toBe('Second factor verified');
    expect(factorChip('STEPUP').label).toBe('Second factor verified');
    expect(factorChip('MFA').className).toBe('chip chip-success');
  });

  it('step-up freshness keeps its own chip, and its neutral tone when stale', () => {
    // Not `chip-warn`: a lapsed step-up is the normal state of a session, not
    // a warning about the account. Only the action that needs one says so.
    expect(stepUpChip(false)).toEqual({ label: 'Step-up not fresh', className: 'chip' });
    expect(stepUpChip(true)).toEqual({
      label: 'Step-up fresh',
      className: 'chip chip-success',
    });
  });
});

/**
 * EVERY RESIDUAL IN docs/03 §6 CARRIES A DISPOSITION, AND DEFERRED WORK NAMES
 * ITS OWNER.
 *
 * WHY THIS EXISTS. docs/03's threat-model deltas carry 107 "residual" bullets —
 * things a milestone recorded rather than fixed. Until M21 PR0 nothing
 * distinguished a PERMANENT ACCEPTED TRADE-OFF ("JS bigint is not
 * constant-time" — true of every JavaScript SRP) from DEFERRED WORK, and
 * nothing named who owns the deferred ones. That is not a tidiness problem. It
 * is exactly how the TB7 operator platform silently absorbed TWELVE separate
 * deferrals without ever appearing in a milestone list or being sized: an item
 * nobody has costed is an item everything can defer to, and prose makes that
 * invisible because each individual sentence reads as diligence. The sweep it
 * forced put 40 of the 107 down as permanent and 60 under an owner, of which
 * NINETEEN are one owner — E1, the AWS half — which is a fact about the
 * programme nobody could read off the prose.
 *
 * WHAT IT ASSERTS. Every residual bullet opens with exactly one tag from a
 * CLOSED vocabulary:
 *
 *   **[ACCEPTED]**      A permanent trade-off. No work is owed; the sentence
 *                       exists so a reader knows the cost was chosen, not
 *                       missed.
 *   **[OWNER: M25]**    Deferred work, with the milestone that owns it.
 *   **[OWNER: E1]**     Deferred work blocked outside engineering (money,
 *                       procurement) — an escalation, not a schedule item.
 *   **[CLOSED: §6n]**   Already closed by a later delta; the bullet is history.
 *
 * WHY A TAG AND NOT A PROSE SCAN. The obvious cheaper fence is "the bullet must
 * mention a milestone somewhere". That fence would go green on `M4's decision`
 * — a CITATION, not an assignment of future work — and on any of the dozens of
 * incidental milestone references these paragraphs carry. This repo has fixed
 * the same mistake three times (the credential graph keyed on a property name,
 * the route-audience fence keyed on a decorator identifier, the password-policy
 * fence keyed on a field name), and the rule it settled on is to anchor on what
 * the consumer actually reads. Here the consumer is a human sweeping the doc,
 * so the anchor has to be a mark a human put there on purpose.
 *
 * WHY THE TAG LEADS THE BULLET. The failure being fixed is that you could not
 * SEE the deferrals. A trailing tag is greppable; a leading one is scannable,
 * and scanning is what nobody could do before.
 *
 * SCOPE, stated so it is not over-read: this checks that a disposition was
 * DECLARED, not that it is correct. Nothing mechanical can tell a genuine
 * permanent trade-off from deferred work somebody labelled ACCEPTED to avoid
 * owning it. What it buys is that the decision is visible and reviewable in the
 * diff, which is the half that was missing.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const DOC = join(__dirname, '..', '..', '..', 'docs', '03-threat-model.md');
const PLAN = join(__dirname, '..', '..', '..', 'docs', '04-monorepo-and-milestones.md');

/**
 * Owners a residual may name. Milestones are the proposed sequence recorded in
 * docs/04; escalations are the items blocked outside engineering.
 *
 * A new owner arrives here or the fence refuses it — the same closed-vocabulary
 * discipline as AUDIT_ACTIONS and NOTIFICATION_KINDS, for the same reason: a
 * free-text owner is a way to look owned without being owned.
 */
const OWNERS: readonly string[] = [
  // Milestones — the settlement program and what follows it (docs/04).
  'M21', // TB7 operator platform, minimum slice
  'M22', // settlement reporter/owner surface
  'M23', // executor surface
  'M24', // dashboard / aggregate readiness
  'M25', // crypto-shredding execution path
  'M26', // forensic audit completeness
  'M27', // emergency-access reader + vault item restore
  'M28', // owner-initiated sharing (§5.5 / §6s)
  'M29', // passkey sign-in / passwordless discovery
  'M30', // in-app notification feed + channel preferences
  'M31', // Plaid link surface
  'M32', // subscription manager
  'M33', // global search
  'M34', // operability instrumentation
  'M35', // load / chaos / DR / penetration
  'M36', // Plaid-assisted subscription detection
  'M37', // passkey provisioning (Estate as authenticator)
  'M38', // referral marketplace
  'M39', // Zone A hardening — SRP abuse bound + rollback detection (added M27 PR0)
  'M40', // residual ownership re-sweep (added M27 PR0)
  'M41', // Plaid item refusal + the read-before-authz sweep (added M27 PR1a)
  'M42', // cross-user free text, and everywhere else it crosses (added M27 PR5)
  'M43', // one derivation per closed vocabulary (added M27 PR5)
  'M44', // the step-up refusal discriminator (added M27 PR6)
  'M45', // fence corpus breadth — a scan states its reach (added M40 PR2)
  'M46', // TB7 follow-on — the operator authorization model (added M40 PR2)
  'M47', // the isolated origins, hardened as a pair (added M40 PR3)
  'M48', // the link that outlives the unlink (added M40 PR4)
  // Escalations — blocked on a decision outside engineering.
  'E1', // AWS cloud half (money)
  'E2', // legal / tax reference review (procurement)
  'E3', // Plaid sandbox credentials (procurement)
  'E4', // SMS carrier / 10DLC / APNs / FCM (procurement)
  'E5', // penetration-test firm (procurement + a deployed target)
];

/**
 * Floors. Two regexes that quietly match nothing agree perfectly, which is the
 * 2026-08-07 lesson — a fence that stops matching goes green. These are set
 * BELOW the counts measured at M21 PR0 (26 sections counting §6 itself, 107
 * residuals) so ordinary editing does not trip them, and high enough that a
 * parser which breaks cannot pass.
 */
const MIN_SECTIONS = 24;
const MIN_RESIDUALS = 95;

/**
 * A FLOOR PER SECTION, BECAUSE A TOTAL CANNOT SEE A DELETION (M27 PR1b).
 *
 * `MIN_RESIDUALS` sits at 95 against 212 actual bullets, which is deliberate —
 * it exists to catch a parser that stopped matching, not an editor. But that
 * leaves the fence unable to notice a single residual being REMOVED, and the
 * one it was least able to notice is the §6j bullet recording that no restore
 * surface existed: the most load-bearing sentence about M27's own scope, which
 * this milestone had every reason to want gone. CLAUDE.md's rule is that an
 * anti-vacuity floor belongs at every LEVEL of a scan and not just its total;
 * the total was the only level this fence had.
 *
 * RATCHETS UP AND NEVER DOWN, exactly like a coverage threshold. Adding a
 * residual to a section and not updating its floor is harmless; removing one
 * reddens a named assertion that says which section lost it. A floor that must
 * come down is a deliberate edit with a reason beside it — the same bargain
 * `coverageThreshold` makes, and for the same reason.
 */
const MIN_PER_SECTION: Readonly<Record<string, number>> = {
  '6a': 4,
  '6b': 5,
  '6c': 7,
  '6d': 3,
  '6e': 3,
  '6f': 2,
  '6g': 4,
  '6h': 5,
  '6i': 5,
  '6j': 11,
  '6k': 10,
  '6l': 6,
  '6m': 6,
  '6n': 4,
  '6o': 4,
  '6p': 4,
  '6q': 10,
  '6r': 4,
  '6s': 2,
  '6t': 2,
  '6u': 3,
  '6v': 3,
  '6w': 3,
  '6x': 6,
  '6y': 3,
  '6z': 6,
  '6aa': 9,
  '6bb': 6,
  '6cc': 6,
  '6dd': 10,
  '6ee': 4,
  '6ff': 4,
  '6gg': 2,
  '6hh': 2,
  '6ii': 3,
  '6jj': 2,
  '6kk': 4,
  '6ll': 4,
  '6mm': 4,
  '6nn': 5,
  '6oo': 3,
  '6pp': 3,
  '6qq': 2,
  '6rr': 2,
  '6ss': 2,
  '6tt': 3,
  '6uu': 7,
  '6vv': 4,
  '6ww': 4,
  '6xx': 3,
  '6yy': 5,
  '6zz': 8,
  '6aaa': 3,
  '6bbb': 2,
  // M44 PR2 closed the row; the one bullet is an ACCEPTED trade-off.
  '6ccc': 1,
  // M40 PR0: one ACCEPTED bound and two owned items — the escalations half of
  // the same question, and the hand-kept register this PR chose to keep.
  '6ddd': 3,
  // M40 PR1: the category's reach, its underived membership, and the four
  // assertions that pin the behaviour a fix must change.
  '6eee': 3,
  // M40 PR2: the fence corpus that never read §4, the difference between an
  // owner and a schedule, and the closure nothing detects.
  '6fff': 3,
  // M40 PR3, all FIVE named so the floor and its justification cannot drift
  // apart — the round-1 bump from 3 to 4 moved the number and left this comment
  // enumerating three, which is the second-copy-that-rots defect inside the
  // fence built to catch it: the deferral whose trigger nobody watched, the
  // delta-section count that never said which tree it meant, the corpus
  // language rule that cannot tell use from mention, the control that proves
  // the detector rather than the document, and the undrived pair of origins.
  '6ggg': 5,
  // M40 PR4: the sweep's own bound, the probes' source-only reach, and the
  // measured state that ratchets in if it was measured wrong.
  '6hhh': 3,
  '6iii': 4,
  '6jjj': 3,
};
/**
 * Floors for the out-of-corpus census (M27 PR0). Measured at 132 bullets under
 * 30 lead-ins; set below those so ordinary editing does
 * not trip them, and high enough that a parser which stopped collecting cannot
 * pass. A census whose scan breaks reports an empty complement, which would
 * otherwise agree perfectly with an emptied declaration.
 */
const MIN_OUT_OF_CORPUS = 120;
const MIN_OUT_OF_CORPUS_LEADS = 25;
const MIN_SECTION_SIX_BULLETS = 300;
/** Bullets outside §6 (§§1-5 and §7), and completed milestones in docs/04. */
const MIN_NON_SIX_BULLETS = 4;
const MIN_QUEUE_ROWS = 15;
// Ratcheted 6 -> 7 by M40 PR4, which flips M40's own row to COMPLETE, then
// 7 -> 8 by M48 PR3, which flips M48's. A floor equal to the true derived value
// is the sensitive setting: the story above is a floor set from a BROKEN
// derivation (3, when six had shipped), not a floor that sat too high. At 6
// this assertion could not see M40's own flip.
//
// THIS RATCHET IS DISCIPLINE, NOT MECHANISM, and saying so is the point. The
// assertion below is `>=`, so leaving it at 7 while eight rows say COMPLETE
// passes green — measured on this very change. Nothing catches a forgotten
// ratchet; what the number buys is that a LATER regression which un-completes a
// row is caught, and that only holds while it tracks the true value.
const MIN_COMPLETED_MILESTONES = 8;

/**
 * THE LIFECYCLE A QUEUE ROW DECLARES — a closed vocabulary, and TOTAL over the
 * rows (M40 PR0).
 *
 * WHAT WENT WRONG. The assertion below derives "has this milestone shipped?"
 * from docs/04's Status column, and until this milestone that column was free
 * prose. A row could therefore decline to answer, and four of them did:
 *
 *   M21 said `**APPROVED**, section above` — no lifecycle word at all.
 *   M24 said `**APPROVED 2026-08-21, section below.**` with PR0-PR4 all shipped.
 *   M27 said `**SCOPED 2026-08-22, section below.**` with every PR shipped.
 *   M44 said `... and the row is now complete.` — inside a bold run, in lower
 *     case, which `/\bCOMPLETE\b/` does not match. A human reader saw the
 *     sentence; the derivation could not.
 *
 * Three of those four were FINISHED. The derived completed set was {M22, M23,
 * M25} against a true six, so the fence's own anti-vacuity floor
 * (`MIN_COMPLETED_MILESTONES`, then 3) sat exactly on the wrong number and had
 * no headroom to notice. A residual tagged to M24, M27 or M44 would have read
 * as live debt forever.
 *
 * THE FIX IS TOTALITY, NOT A BIGGER REGEX. Every row opens its Status cell with
 * exactly one of these tokens, as a bold run that is the token and nothing
 * else. One behaviour, one spelling: no case to get wrong, no adjective to bury
 * it under, no position to guess. Silence is now RED
 * (`every queue row DECLARES a lifecycle status`), which is the property the
 * old column could not have at any regex quality — the failure was that a row
 * was allowed to say nothing, and a parser cannot fix that.
 *
 * WHAT THIS DOES NOT DO, stated because both alternatives were MEASURED rather
 * than waved off. Nothing here checks a status is TRUE — the same bound the
 * ACCEPTED tag carries at the top of this file. Two cross-checks were tried:
 *
 *   - "a COMPLETE row's PR-split bullets must all say SHIPPED": 17 of docs/04's
 *     40 `- **PR…` bullets carry no shipped marker at all, M27's PR0, PR1a,
 *     PR3b, PR5 and PR6 among them, and all five shipped.
 *   - "a PLANNED row must have no per-PR record section": only M21, M24 and M25
 *     use `#### M<nn> PR…` headings, 3 of the 7 milestones that have shipped a
 *     PR. M22 and M23 carry no `####` heading whatsoever.
 *
 * Both would be a fence whose input is narrower than its claim, green for the
 * reason it is wrong. Recorded here so the next author does not re-derive the
 * rejection. docs/03 §6ddd.
 */
const ROW_STATUSES: readonly string[] = ['PLANNED', 'IN PROGRESS', 'COMPLETE'];

/**
 * The token as the document writes it, BUILT FROM the vocabulary above so the
 * two cannot drift — the parser and the list are one spelling.
 */
const ROW_STATUS = new RegExp(`^\\s*\\*\\*(${ROW_STATUSES.join('|')})\\.\\*\\*`);

/**
 * The header that makes the third cell a STATUS, quoted from docs/04.
 *
 * Anchored on the document rather than on a column index somebody assumed. The
 * escalations table above it is `| | Item | Blocker |` — a third cell that
 * answers a DIFFERENT question — so reading "cell 3" without checking which
 * table you are in is how this fence would come to assert a blocker is a
 * lifecycle. Both headers are asserted, and the escalations one is asserted to
 * be NOT a status column, which is this fence stating its own reach as a
 * mechanism instead of a sentence.
 */
const QUEUE_HEADER = '| # | Milestone | Status |';
const ESCALATION_HEADER = '| | Item | Blocker | State |';

/**
 * THE ESCALATION HALF, AND WHY IT IS NOT THE MILESTONE VOCABULARY — M40 PR4.
 *
 * docs/03 §6vv recorded that twenty-two residual tags name an escalation while
 * the escalations table answered only "what is this blocked on", so nothing
 * could report a change. The obvious fix is to copy `ROW_STATUSES` across. That
 * is the fix that looks total and is not, because the two tables mean opposite
 * things by the same event:
 *
 *   - A milestone reading `COMPLETE` makes a residual naming it STALE. The work
 *     is DONE, so the tag points at nobody, and `no residual is owned by a
 *     milestone that has already SHIPPED` is the assertion that follows.
 *   - An escalation reading `CLEARED` makes a residual naming it SCHEDULABLE.
 *     The blocker lifted, so the work can finally START — and until somebody
 *     re-owns it to a milestone, it is owed by an entry that is no longer
 *     blocking anything. The work is not done; it is newly doable and unassigned.
 *
 * Same mechanism, opposite meaning. `COMPLETE` on an escalation row would say
 * the work finished when it has not begun, which is why the vocabulary is two
 * different words rather than three shared ones.
 */
const ESCALATION_STATES: readonly string[] = ['BLOCKED', 'CLEARED'];

/** Built FROM the vocabulary, so the parser and the list are one spelling. */
const ESCALATION_STATE = new RegExp(`^\\s*\\*\\*(${ESCALATION_STATES.join('|')})\\.\\*\\*`);

interface EscalationRow {
  readonly id: string;
  readonly state: string;
  readonly line: number;
}

/**
 * docs/04's escalations table. Deliberately a SECOND parser rather than a
 * parameter on `queueRows`: the two tables have different column counts and
 * different vocabularies, and the one bug worth designing against here is a
 * reader that treats a blocker as a lifecycle. The State cell is the FOURTH;
 * the tail is rejoined so a cell containing a pipe cannot truncate the scan.
 */
function escalationRows(): EscalationRow[] {
  return readFileSync(PLAN, 'utf8')
    .split('\n')
    .map((line, index) => ({ line, index }))
    .map(({ line, index }) => ({ m: /^\| (E\d) \|/.exec(line), line, index }))
    .filter((x): x is { m: RegExpExecArray; line: string; index: number } => x.m !== null)
    .map(({ m, line, index }) => ({
      id: m[1] as string,
      state: line.split('|').slice(4).join('|'),
      line: index + 1,
    }));
}

/**
 * Residuals owned by a milestone whose queue row is COMPLETE. Declared debt.
 *
 * HAND-KEPT, AND SAYING SO IS THE POINT (M40 PR0). The blindness this list used
 * to carry is gone — `completed` is now derived from a column that cannot stay
 * silent — but the list itself is still written by hand, because its job is not
 * to mirror the data. It is a REGISTER: these two milestones are known to have
 * finished while still carrying residuals, and M40's later PRs adjudicate each
 * one. Deriving it from the same data it is checking would assert nothing.
 *
 * Compared as a SET and not just a count, because mis-attribution between two
 * closed milestones preserves the total and the owner is what says which
 * programme owes the work.
 *
 * M43 owns the general form of "one derivation per closed vocabulary" and this
 * is one of its cases; the overlap is stated rather than quietly resolved here.
 */
/*
 * ZERO, since M40 PR3 — and a zero needs a different guard than a thirteen did.
 *
 * These two constants used to pin a real, non-empty set: thirteen residuals
 * across M22 and M23. Pinned that way they were a genuine measurement, because
 * a parser that broke, a status column that stopped being read, or a corpus
 * that came back empty all produced a number that was not thirteen.
 *
 * At zero every one of those failures produces `[]` and `0`, which is exactly
 * what a correct run produces. THE ASSERTION CANNOT SURVIVE ITS OWN SUCCESS:
 * "no residual names a shipped milestone" and "this fence read nothing at all"
 * became the same observation. So the real-corpus expectation stays — it is
 * still the thing anyone cares about — and it is paired below with a POSITIVE
 * CONTROL that feeds a synthetic bullet through the SAME predicate and asserts
 * it fires. A floor cannot do this job: there is no number above zero to floor.
 */
const STALE_OWNED = 0;
const STALE_OWNERS: readonly string[] = [];

/**
 * The bolded lead-ins that OPEN a residual region, as exact strings.
 *
 * Not a regex, and the reason is the one this repo keeps arriving at. A regex
 * over "any bold label mentioning residual" both over- and under-matches: it
 * swallows `**§6l's residual was a promise the code did not keep.**` (a
 * FINDING) while missing `**Two residuals.**` (a region). An exact list is
 * reviewable in a diff, and `every residual lead-in is classified` below makes
 * a sixteenth idiom turn the fence RED instead of silently narrowing it.
 */
const REGION_MARKERS: readonly string[] = [
  'Residuals accepted, and why.', // §6a, §6i
  'Residual added by PR2.', // §6b
  'Residuals accepted.', // §6b
  'Residuals, accepted and recorded:', // §6c
  'Recorded, not fixed.', // §6d, §6e
  'RECORDED, OWED BY PR2 (§4 TB4).', // §6f
  'ACCEPTED RESIDUALS, stated rather than implied.', // §6g
  'Residuals carried, not closed.', // §6j
  'Episode semantics and the honest residuals.', // §6q
  'Residuals, stated rather than implied.', // §6q
  'Two residuals.', // §6s
  'Residuals, stated.', // §6t
  'Residuals: none, and the row is closed.', // §6ccc — a region with nothing in it
];

/**
 * Bolded lead-ins that MENTION a residual and do not open a region. Each is a
 * sentence about one residual, not a heading over a list — declared here so the
 * classification below is total, on the credential-graph habit of stating
 * exceptions as data rather than letting a regex quietly skip them.
 */
const NON_REGION_LABELS: readonly { readonly label: string; readonly why: string }[] = [
  {
    label: 'THE FOUR IMPRECISE ONES ARE RECORDED, NOT FIXED',
    why:
      '§6hhh — a FINDING lead-in over EVIDENCE. The four bullets under it are ' +
      'ACCEPTED dispositions elsewhere in this document whose prose the M40 PR4 ' +
      're-adjudication found wrong in one clause each. They are not work owed ' +
      'here: each is a note about a bullet that lives in §6b, §6dd, §6o and §6d ' +
      'and keeps its own tag there. Recording them without fixing them is the ' +
      'sweep-does-not-fix-what-it-trips-over rule this milestone has used since PR0.',
  },
  {
    label:
      'TWELVE absence-asserting residuals were checked against the CODE, not against other prose',
    why:
      '§6hhh — a RESULT statement, not a region. It reports what the M40 PR4 sweep ' +
      'covered and carries no bullets; the residuals that sweep produced are under ' +
      "§6hhh's own `### Residuals` heading. It is here rather than in REGION_MARKERS " +
      'because a finding is not a region, and a fence that treated every bolded ' +
      'sentence mentioning residuals as one would collect prose into the corpus.',
  },
  {
    label: "A DEFERRAL'S PRECONDITION CAN BE SPENT BY A LATER PR, AND NOTHING WATCHES.",
    why:
      '§6ggg — a FINDING lead-in. The two bullets under it are the EVIDENCE for one ' +
      'shape (a stated precondition met by a later PR with nobody watching), not two ' +
      'items of work. The work they produced is tagged where it lives: the ' +
      'distribution emit at §6dd under M26, the interstitial at §6bb as ACCEPTED.',
  },
  {
    label:
      'The general form: a deferral that names its own trigger is only as good as whatever watches the trigger, and here nothing did.',
    why:
      '§6ggg — the RULE the finding above generalises to, stated as prose and carrying ' +
      'no bullets. It is in this list rather than REGION_MARKERS because a rule is not ' +
      "a region; the residual it implies is the [OWNER: M40] bullet in §6ggg's own " +
      'declared region, which says the preconditions are English and nothing can watch them.',
  },
  {
    label: 'Residual accepted here:',
    why: '§6a — an inline sentence continuing a paragraph, not a heading over bullets.',
  },
  {
    label: 'The Secret Key on the device, as a residual rather than a control.',
    why: '§6i — a prose paragraph explaining one decision; the bullets after it are its evidence.',
  },
  {
    label: "§6l's residual was a promise the code did not keep.",
    why: '§6t — a FINDING lead-in. What follows describes a defect that was fixed, not work owed.',
  },
  {
    label: "§6n's own residual, closed by the PR that line predicted.",
    why: '§6v — a CLOSURE lead-in; the bullets under it record what shipped.',
  },
  {
    label: 'Decisions and their residuals.',
    why:
      "§6j — a MIXED list: M16's decisions, four of which are not residuals at all " +
      '("origin matching is the boundary\'s defining control"). Treating it as a region ' +
      'would demand a disposition on a decision. The residuals inside it are reached by ' +
      'the language rule instead, and §6j declares a real region below it.',
  },
  {
    label: 'FINDING 2 — A SECOND LIVE BLIND INDEX, AND A RESIDUAL SWEEP THAT SAID OTHERWISE.',
    why:
      '§6pp — a FINDING lead-in, and the first one this list gained by MEASUREMENT rather ' +
      'than by review. Its bold run wraps across two lines, so `boldLabel` returned null and ' +
      'the classification scan skipped it for the whole of M25; the M27 PR0 multi-line fix ' +
      'made it visible on the first run. What follows it is a defect that was FIXED — a sweep ' +
      'that grouped by column name and never asked the ownership question — not work owed.',
  },
  {
    label:
      "THE FENCE BUILT TO MAKE DEFERRALS VISIBLE COULD NOT SEE THIS MILESTONE'S HEADLINE ITEM.",
    why:
      "§6uu — a prose lead-in describing this fence's own defect and the census that closes " +
      'it. No bullets follow it; §6uu declares its residuals under `### Residuals`.',
  },
  {
    label: 'NOT closed by this PR, and stated so it is not assumed.',
    why:
      '§6u — a PROSE paragraph with no bullets under it. Its content is genuine residual ' +
      'work, which is why §6u now also carries a bulleted `### Residuals` region: the ' +
      'paragraph says it, the region makes it sweepable.',
  },
];

interface Residual {
  readonly section: string;
  readonly line: number;
  readonly text: string;
}

/** A bolded label at the start of a line, if there is one. */
function boldLabel(line: string, rest: readonly string[] = []): string | null {
  const m = /^\*\*(.+?)\*\*/.exec(line);
  if (m !== null) return m[1] as string;
  // A BOLD RUN THAT WRAPS. `**A reset requires the mailed code and nothing
  // else, even for an account holding\na verified TOTP or passkey.**` closes on
  // its SECOND line, so the single-line regex returns null and both callers
  // fell back to `line.trim()` — half a sentence, ending mid-clause. Harmless
  // while nothing keyed on it; the M27 PR0 census keys on it, and half a
  // sentence is a key that changes when somebody re-wraps a paragraph. It also
  // means the classification scan below reads the whole label, so a lead-in
  // whose word "residual" falls on its second line is no longer invisible.
  if (!line.startsWith('**')) return null;
  const buf = [line];
  for (const next of rest) {
    if (next.trim() === '') break;
    buf.push(next);
    const joined = /^\*\*(.+?)\*\*/.exec(buf.join(' '));
    if (joined !== null) return joined[1] as string;
  }
  return null;
}

/** Does this line's label or heading mention a residual, in any of the doc's idioms? */
const MENTIONS_RESIDUAL =
  /\bresiduals?\b|\brecorded, not fixed\b|\bnot closed\b|\bowed\b|\bdeferr/i;

/**
 * The residual bullets of §6, found TWO WAYS, because neither alone works and
 * discovering that was most of the design.
 *
 * BY REGION. A residual block opens with a subheading naming residuals, or with
 * one of the bolded lead-ins declared in REGION_MARKERS. Both idioms are in the
 * doc and neither is going away, so the parser reads both. A block ENDS at the
 * next heading OR the next bolded lead-in — that second clause is load-bearing:
 * without it §6a's block runs on and swallows `**§5.2 emergency-access
 * controls, now shipped**`, five bullets describing controls that SHIPPED,
 * which a disposition tag would be actively wrong about.
 *
 * BY LANGUAGE. Region alone under-collects, because §6j organises itself by PR
 * (`**Added by PR3a (origin matching).**`) and mixes decisions with residuals
 * under one lead-in. So a bullet anywhere in §6 that SAYS it is a residual —
 * "remains open", "recorded, not fixed", "its own milestone" — is in the corpus
 * wherever it lives, and the disposition of a long bullet is often in its LAST
 * sentence, which is why the whole bullet including continuations is the unit.
 *
 * Language alone is far worse: most residuals simply DESCRIBE the residual —
 * "*Autofill does not resist phishing.*" — and name no marker word at all.
 * Hence the union: 107 bullets, 89 reached by region and 18 by language.
 *
 * THE BOUND, STATED RATHER THAN DISCOVERED LATER: a residual written as prose,
 * outside a declared region and using none of the marker phrases, is invisible
 * to this fence. That is not closable by a better regex — the doc's structure
 * genuinely does not distinguish those bullets. What closes it instead is the
 * `every delta declares a residual region` assertion below, which forces the
 * NEXT milestone's residuals to land somewhere the region rule already sees.
 */
/**
 * A region marker that opened, and how many bullets it went on to collect.
 *
 * A DECLARED REGION THAT COLLECTS NOTHING IS THIS FENCE'S SILENT FAILURE. The
 * marker is recognized, the block opens, the parser reads on — and if the
 * residuals under it are written as PROSE PARAGRAPHS rather than as `- `
 * bullets, every one of them is invisible while the file stays green. That is
 * not hypothetical: §6b's `Residual added by PR2.` and `Residuals accepted.`
 * are both declared markers standing over paragraphs, so M21 PR0's sweep
 * tagged nothing in §6b at all, and the two TB7 deferrals it holds — M-of-N
 * operator approval, and the users-row-lock fix for the liveness race — were
 * left out of the count the milestone was scoped from.
 *
 * The bound PR0 stated was "a residual outside a declared region and using
 * none of the marker phrases is invisible". This is narrower and worse: INSIDE
 * a declared region, and still invisible.
 */
interface Region {
  readonly section: string;
  readonly line: number;
  readonly label: string;
  count: number;
}

function residuals(): {
  items: Residual[];
  sections: Set<string>;
  declared: Set<string>;
  regions: Region[];
  interruptions: Array<{ section: string; line: number; label: string }>;
  outside: Array<{ section: string; line: number; lead: string }>;
} {
  const lines = readFileSync(DOC, 'utf8').split('\n');
  const blockHeading = (line: string): boolean =>
    /^#{3,4}\s/.test(line) && MENTIONS_RESIDUAL.test(line);
  const residualLanguage =
    /(recorded,? (?:rather than|not) (?:fixed|closed)|accepted residual|residual (?:is|here|accepted|stated|carried)|remains? open|stays open|is not closed|left open|still open|owed by|no (?:self-service|operator) remedy|until TB7|its own milestone|a later milestone|needs its own)/i;
  const items: Residual[] = [];
  const outside: Array<{ section: string; line: number; lead: string }> = [];
  const sections = new Set<string>();
  const declared = new Set<string>();
  const interruptions: Array<{ section: string; line: number; label: string }> = [];
  const regions: Region[] = [];
  let section: string | null = null;
  let inBlock = false;
  let region: Region | null = null;
  // The most recent bolded lead-in or subheading, tracked UNCONDITIONALLY —
  // `region` only exists while a residual block is open, and the bullets this
  // census exists to see are the ones with no block open over them.
  let lead: string | null = null;

  /** Open a region, or close the one in force. Both paths run for every line. */
  const setBlock = (open: boolean, line: number, label: string): void => {
    if (region !== null && (!open || region.line !== line)) region = null;
    if (open && section !== null) {
      region = { section, line, label, count: 0 };
      regions.push(region);
    }
  };

  lines.forEach((line, index) => {
    // TWO-LETTER SECTIONS ARE REAL. `^## (6[a-z]?)\.` stopped matching at §6aa
    // (M21 PR2) — it needs a literal `.` after one optional letter and finds a
    // second letter instead — so §6aa and §6bb were attributed to §6z, the last
    // heading that DID match. Mis-attribution, not blindness: every bullet was
    // still collected and still tagged, but the failure message named the wrong
    // section, which is the wrong file for whoever goes looking. Found by §6bb
    // reporting itself as §6z.
    //
    // THREE LETTERS NOW (M27 PR5), and forced rather than tidy: §6zz is the
    // LAST two-letter section there is, so the next delta this milestone
    // writes is §6aaa and lands on the same wall §6aa did. The bound is
    // written out in six places; `the section vocabulary has ONE spelling`
    // names all six and fails if an extension reaches only some of them, which
    // is how the one-letter era lasted — every copy was wrong together.
    const delta = /^## (6[a-z]{0,3})\./.exec(line);
    if (delta !== null) {
      section = delta[1] as string;
      sections.add(section);
      inBlock = false;
      region = null;
      lead = null;
    } else if (/^## /.test(line)) {
      // A TOP-LEVEL HEADING THAT IS NOT A §6 DELTA ENDS §6, and this parser did
      // not say so. `## 7. Validation program` sits BETWEEN
      // §6hh and §6ii — the doc appends deltas after the numbered sections and
      // §7 was overtaken — so `section` stayed '6hh' and §7's four bullets were
      // attributed to it. The same mis-attribution class as the one-letter
      // section regex, and invisible for the same reason: none of those bullets
      // is tagged or uses residual language, so none reached the corpus and
      // nothing went red. A residual written in §7 WOULD have been collected,
      // and reported under a section that does not contain it. The
      // classification scan below always had this clause; the parser did not.
      // Found by the M27 PR0 census, which is the first assertion to look at
      // the bullets the corpus rejects.
      section = null;
      inBlock = false;
      region = null;
      lead = null;
    }
    if (/^#{2,4}\s/.test(line)) {
      inBlock = blockHeading(line);
      // A DELTA HEADING IS NOT A LEAD-IN. `## 6c.` already reset `lead` above;
      // letting this branch set it again files §6c's four preamble bullets under
      // the section's own title, which reads like a lead-in and is not one.
      lead = delta === null ? line.replace(/^#+\s*/, '').trim() : null;
      setBlock(inBlock, index + 1, line.trim());
      if (inBlock && section !== null) declared.add(section);
    } else if (line.startsWith('**')) {
      // A NEW BOLDED LEAD-IN CLOSES THE BLOCK, and this line is load-bearing.
      // Without it §6a's block runs on and swallows "**§5.2 emergency-access
      // controls, now shipped**" — five bullets describing controls that
      // SHIPPED. Caught only because an independent classification of the
      // corpus disagreed with this parser about two bullets.
      const label = boldLabel(line, lines.slice(index + 1, index + 4));
      const wasInBlock = inBlock;
      inBlock = label !== null && REGION_MARKERS.includes(label);
      lead = label ?? line.trim();
      // A CLOSURE IS A LOSS, and it used to be a silent one. Every bullet after
      // this line leaves the corpus, but the region still reports the bullets
      // BEFORE it — so `count === 0`, the check this file calls its own silent
      // failure, cannot see a region that went blank after its first bullet.
      // That is the level-vs-total rule the file applies correctly elsewhere
      // (it compares SETS for reach and for owners) and not here.
      if (wasInBlock && !inBlock && section !== null) {
        interruptions.push({ section, line: index + 1, label: label ?? line.trim() });
      }
      setBlock(inBlock, index + 1, label ?? line.trim());
      if (inBlock && section !== null) declared.add(section);
    }

    if (section !== null && line.startsWith('- ')) {
      // Continuation lines are indented; the disposition of a long bullet is
      // often in its last sentence, so the whole bullet is the unit.
      const buf = [line];
      for (let j = index + 1; j < lines.length; j += 1) {
        const next = lines[j] as string;
        if (!next.startsWith('  ') || next.trim() === '') break;
        buf.push(next);
      }
      const text = buf.map((l) => l.trim()).join(' ');
      if (inBlock || residualLanguage.test(text)) {
        items.push({ section, line: index + 1, text });
        if (region !== null) region.count += 1;
      } else {
        // NOT IN THE CORPUS. This is the half the fence used to leave unsaid.
        outside.push({ section, line: index + 1, lead: lead ?? SECTION_PREAMBLE });
      }
    }
  });

  return { items, sections, declared, regions, interruptions, outside };
}

/**
 * The one tag a bullet may open with.
 *
 * The section suffix is `[a-z]{0,2}` rather than `[a-z]?` for the same reason
 * the delta regex below is: the doc reached §6aa in M21 PR2 and a one-letter
 * pattern silently stops matching there — a `CLOSED: §6aa` tag would read as
 * untagged, and a delta heading would be attributed to whichever single-letter
 * section preceded it.
 */
/**
 * Bolded lead-ins that CLOSE a residual region, frozen as data.
 *
 * Closing is deliberate — see the parser — because without it §6a's block runs
 * on and swallows five bullets describing controls that SHIPPED. But a closure
 * is also a LOSS: every bullet after one of these leaves the corpus, and the
 * region still reports the bullets BEFORE it, so `count === 0` (the check this
 * file calls its own silent failure) cannot see a region that went blank after
 * its first bullet. An untagged residual below one of these lines was invisible
 * to every assertion here, and the §6 count is what a milestone gets scoped
 * from.
 *
 * So the set is declared and compared. This freezes today's behaviour rather
 * than adjudicating ten doc sections: what it buys is that the NEXT one fails
 * loudly, and whoever adds it has to say whether the bullets below it are
 * residuals. Adding a lead-in to a §6 list is an ordinary way to write these
 * paragraphs, which is exactly why it needed to stop being free.
 */
const DECLARED_INTERRUPTIONS: ReadonlyArray<{ section: string; label: string }> = [
  { section: '6a', label: '§5.2 emergency-access controls, now shipped (M6 PR2).' },
  {
    section: '6b',
    label: 'Service-credential scoping (added by the M7 security review, 2026-07-28).',
  },
  { section: '6c', label: 'The M6 delivery-channel identifier leakage item: PARTIALLY CLOSED.' },
  { section: '6e', label: 'PR2 addendum — ingest, the ladder, and deletion (2026-08-06).' },
  { section: '6i', label: 'The Secret Key on the device, as a residual rather than a control.' },
  { section: '6j', label: 'Added by PR2a (the extension and its transport).' },
  { section: '6m', label: 'Proven live, and one defect the whole suite passed over.' },
  { section: '6q', label: "The window's clock, and what that costs (M18 PR3)." },
  { section: '6q', label: 'Evidence, one database, one table.' },
  { section: '6t', label: 'Proven live, on the disagreeing arm.' },
];

/** A §6 bullet standing under no lead-in at all, directly beneath the heading. */
const SECTION_PREAMBLE = '(section preamble)';

/**
 * THE BULLETS THIS FENCE DOES NOT WATCH, STATED AS DATA INSTEAD OF AS PROSE.
 *
 * WHY THIS EXISTS, and it is the defect M27 PR0 was scoped from. §6j:1623
 * recorded "there is no restore surface", assigned it to "the operator platform
 * (TB7)", and carried NO disposition tag — while this file stayed green for
 * five milestones. TB7 then shipped as M21 without the surface. The bullet was
 * never in the corpus: §6j organises by PR, `**Added by PR3a (origin
 * matching).**` is in neither `REGION_MARKERS` nor `NON_REGION_LABELS`, and the
 * classification assertion below skips any lead-in whose LABEL does not itself
 * say "residual" — so the bullet was reachable only by the language rule, and it
 * used none of the marker phrases. The single most load-bearing sentence about
 * M27's restore half was invisible to the mechanism built to make deferrals
 * visible.
 *
 * The docstring at the top of `residuals()` already STATED this bound. A stated
 * bound is not a mechanism: it tells a reader the gap exists and tells the next
 * author nothing when they write into it.
 *
 * WHAT THIS ASSERTS. The corpus reaches most of §6's bullets. The rest are
 * declared here, keyed by the lead-in they sit under and counted — and the
 * shape of that list is itself the argument that the corpus is drawn in roughly
 * the right place: the large entries are "Controls now shipped.", "What PR N
 * changes", "The other confirmed findings". Bullets describing work that was
 * DONE. A residual hiding among them is exactly what happened, and now it
 * cannot happen silently: a bullet added under any declared lead-in changes that
 * lead-in's count and turns this red, so the author either tags it (it moves
 * into the corpus and the count drops) or bumps the number, which is a one-line
 * diff saying "I looked at this bullet and it is not work owed".
 *
 * WHY PER LEAD-IN AND NOT PER FILE. A total passes happily while one lead-in
 * goes blind — the level-vs-total rule this file already applies to reach and to
 * owners. `kind` is required for the same reason `why` is required on
 * `NON_REGION_LABELS`: it makes each entry a judgement somebody made rather than
 * a number somebody pasted.
 *
 * THE BOUND, stated rather than discovered later — this is a COUNT per lead-in,
 * so deleting one bullet and adding another beneath the same heading preserves
 * it. Keying on each bullet's opening phrase would close that, and would mean
 * hand-listing 132 prose sentences beside a document that grows, which is the
 * defect this repo names most often. docs/03 §6uu records the trade.
 *
 * A RED ASSERTION HERE IS NOT NOISE. It means a bullet was written somewhere
 * this fence cannot see a disposition. Tag it, or say here that you looked.
 * Never delete an entry to make the number agree.
 */
const OUT_OF_CORPUS: ReadonlyArray<{
  readonly section: string;
  readonly label: string;
  readonly bullets: number;
  readonly kind: 'shipped' | 'decision' | 'evidence' | 'closure' | 'tracked-elsewhere';
}> = [
  {
    section: '6hhh',
    label: 'THE FOUR IMPRECISE ONES ARE RECORDED, NOT FIXED',
    bullets: 4,
    kind: 'evidence',
    // Four notes about ACCEPTED bullets in OTHER sections — §6b's cross-reference
    // that M40 PR3 invalidated a day after PR2 wrote it, §6dd's operator
    // assertion count asserted of a two-edge pair, §6o's dead §6m pointer, and
    // §6d's rung-spelling undercount. Each is evidence for "an ACCEPTED bullet's
    // prose rots where nothing reads it", not an item of work: the work, where
    // any is owed, sits under the tag in the section that owns the bullet.
  },
  { section: '6a', label: 'Controls now shipped.', bullets: 6, kind: 'shipped' },
  {
    section: '6a',
    label: 'Not yet shipped, and therefore not yet mitigated.',
    bullets: 3,
    kind: 'tracked-elsewhere',
  },
  {
    section: '6a',
    label: '§5.2 emergency-access controls, now shipped (M6 PR2).',
    bullets: 6,
    kind: 'shipped',
  },
  { section: '6aa', label: 'What PR2 changes', bullets: 6, kind: 'shipped' },
  {
    section: '6b',
    label: 'Control 5 — staged executor access — now shipped (PR2).',
    bullets: 6,
    kind: 'shipped',
  },
  {
    section: '6b',
    label: 'Controls now shipped (PR1: intake → review → waiting period → verified).',
    bullets: 5,
    kind: 'shipped',
  },
  {
    section: '6bb',
    label: 'The three decisions, and what each one is not',
    bullets: 3,
    kind: 'decision',
  },
  { section: '6bb', label: 'What PR3a changes', bullets: 5, kind: 'shipped' },
  {
    section: '6ccc',
    label: 'DRIVEN IN A REAL BROWSER, and the drive cost two checks that could not fail.',
    bullets: 2,
    kind: 'evidence',
  },
  {
    section: '6ccc',
    label:
      'Two fences, and they catch different things — stated because a guard at two layers needs each test to say which layer it proves.',
    bullets: 2,
    kind: 'evidence',
  },
  {
    section: '6bbb',
    label: 'The same fence had the same defect TWICE MORE, and the review found both.',
    bullets: 2,
    kind: 'evidence',
  },
  { section: '6c', label: '(section preamble)', bullets: 4, kind: 'shipped' },
  { section: '6cc', label: 'What PR3b changes', bullets: 6, kind: 'shipped' },
  {
    section: '6f',
    label: 'A §5.1 control was revocable by accident, twice.',
    bullets: 2,
    kind: 'evidence',
  },
  { section: '6g', label: 'The ceremony.', bullets: 3, kind: 'evidence' },
  {
    section: '6i',
    label: 'The §4 TB6 controls, now shipped and their status.',
    bullets: 7,
    kind: 'shipped',
  },
  {
    section: '6j',
    label: 'Added by PR2a (the extension and its transport).',
    bullets: 3,
    kind: 'shipped',
  },
  { section: '6j', label: 'Added by PR2b (unlock and read).', bullets: 4, kind: 'shipped' },
  { section: '6j', label: 'Added by PR3a (origin matching).', bullets: 6, kind: 'shipped' },
  { section: '6j', label: 'Added by PR5 (the security review).', bullets: 12, kind: 'shipped' },
  { section: '6j', label: 'Decisions and their residuals.', bullets: 4, kind: 'decision' },
  { section: '6j', label: 'What M16 closes that predates it.', bullets: 2, kind: 'closure' },
  { section: '6k', label: 'What M17 PR1 closes that predates it', bullets: 1, kind: 'closure' },
  { section: '6l', label: 'A FIFTH NOTIFICATIONS EDGE', bullets: 3, kind: 'shipped' },
  {
    section: '6m',
    label:
      'A reset requires the mailed code and nothing else, even for an account holding a verified TOTP or passkey.',
    bullets: 4,
    kind: 'decision',
  },
  { section: '6m', label: 'The rest of the shape', bullets: 5, kind: 'evidence' },
  {
    section: '6n',
    label: 'VERIFY-THEN-SWITCH, and the ordering is the whole design.',
    bullets: 3,
    kind: 'decision',
  },
  {
    section: '6p',
    label: 'What the review REFUTED, and why the refutations are worth keeping',
    bullets: 1,
    kind: 'evidence',
  },
  {
    section: '6q',
    label: "The window's clock, and what that costs (M18 PR3).",
    bullets: 3,
    kind: 'decision',
  },
  {
    section: '6t',
    label:
      "Three identity call sites read a discriminated union's DISCRIMINANT as if it were its ANSWER.",
    bullets: 3,
    kind: 'shipped',
  },
  {
    section: '6v',
    label: 'The 202 is not a delivery receipt, and no layer is allowed to render it as one.',
    bullets: 3,
    kind: 'decision',
  },
  { section: '6y', label: 'The other confirmed findings', bullets: 7, kind: 'shipped' },
  { section: '6z', label: 'What PR1 changes', bullets: 6, kind: 'shipped' },
  {
    section: '6ddd',
    label: 'The mechanism being repaired.',
    bullets: 4,
    kind: 'evidence',
    // The four docs/04 rows whose Status cell could not be read as a lifecycle.
    // Evidence for the defect, not work owed: three of the four were finished
    // and all four now declare a token.
  },
  {
    section: '6eee',
    label: 'The category, enumerated.',
    bullets: 2,
    kind: 'evidence',
    // The eight members, grouped by service. Evidence for an ownership
    // decision, not work owed: both bullets are already tagged where they
    // live, in §6e and §6vv.
  },
  {
    section: '6ggg',
    label: "A DEFERRAL'S PRECONDITION CAN BE SPENT BY A LATER PR, AND NOTHING WATCHES.",
    bullets: 2,
    kind: 'evidence',
    // The two deferrals whose stated condition a later PR met with nobody
    // watching — §6dd's distribution emit ("the route has no consumer
    // anywhere", and M23 PR4b built it) and §6bb's interstitial ("once there
    // is something behind it", and the console shipped). EVIDENCE for one
    // shape, not two items: each produced a disposition tagged where the item
    // actually lives, so counting them here would count them twice.
  },
  {
    section: '6ddd',
    label: 'What this does NOT check, measured rather than assumed.',
    bullets: 2,
    kind: 'decision',
    // The two cross-checks built against the tree and REJECTED on measurement.
    // A decision with its numbers attached, so the next author does not rebuild
    // them; the bound they leave behind is the ACCEPTED residual in §6ddd.
  },
];

/**
 * DEFERRAL PRECONDITIONS, AS DATA — M40 PR4.
 *
 * Some residuals justify leaving a defect alone by asserting an ABSENCE: "the
 * route has no consumer anywhere", "read by nothing", "a surface that does not
 * exist". Those justifications were TRUE when written and nothing re-checks
 * them. M40 PR3 found one that had been spent — a distribution audit emit
 * deferred because the route had no consumer, and M23 PR4b then built exactly
 * that consumer without the emit, turning a latent defect into a live one on a
 * step-up-gated, money-moving verb. The only reader of such a condition was a
 * sweep that happens on its own schedule; §6ggg records that as owed, and this
 * is it.
 *
 * WHAT THE ENTRY DECLARES IS THE MEASURED STATE OF THE WORLD, not an intention.
 * `state: 'absent'` says the absence still holds; `state: 'filled'` says it has
 * been spent and the residual names an owner for the consequence. The assertion
 * is that the state has not CHANGED, which reddens in BOTH directions: a
 * consumer appearing under an 'absent' entry is the M40 PR3 defect happening
 * again, and one disappearing under a 'filled' entry means the owner's fix was
 * scoped against a surface that has since moved.
 *
 * THE 'filled' ENTRY IS THE POSITIVE CONTROL, and it is drawn from the real
 * corpus rather than synthesised. A registry of absences whose every probe
 * returns "still absent" passes identically when the scanner is broken, the
 * glob matches nothing, or the pattern cannot match — the same
 * cannot-survive-its-own-success shape the stale-owner assertion had one test
 * below. Here one entry MUST report FILLED against the live tree, so a scanner
 * that can only answer "absent" fails this file.
 *
 * WHY `CLOSED` BULLETS ARE OUT OF THE CORPUS, which was measured rather than
 * assumed. The M40 PR4 sweep ran this question over twelve absence-asserting
 * residuals with two refute-by-default verifiers each. Every false positive it
 * produced was a CLOSED bullet, three of three, and always for the same reason:
 * in a CLOSED bullet the absence has the OPPOSITE POLARITY. It explains why a
 * FIX WAS CHEAP ("no consumer exists to break"), not why a fix was DEFERRED.
 * Nothing was left undone on the strength of it, so it cannot be spent in the
 * sense that matters. Scanning them anyway is how a fence earns a reputation
 * for crying wolf.
 *
 * WHY THE PROBES ARE NARROW, also measured. A first draft of the
 * `document_search_tokens` probe grepped for `DELETE FROM` and reported the
 * absence SPENT. What it had found was `SearchTokensRepo.replaceForDocument` —
 * a sanctioned replace-in-place on re-index, which that file's own docstring
 * declares — and not the erasure purge the residual is about. A probe shaped
 * like the absence's SUBJECT rather than its WORDS finds the wrong thing and
 * reports it confidently.
 */
interface Precondition {
  /** The §6 section the residual lives in. */
  readonly section: string;
  /** The residual's italic title, verbatim — the anchor a reader can grep. */
  readonly title: string;
  /** The absence the bullet asserts, quoted from it. */
  readonly absence: string;
  /** Repo-relative directories to scan. Non-empty is asserted, not assumed. */
  readonly corpus: readonly string[];
  /** A match means the absence has been FILLED. */
  readonly filledWhen: RegExp;
  /** Paths whose match does not count, each with the reason it does not. */
  readonly notCountedIn: readonly { readonly path: string; readonly why: string }[];
  /** The state MEASURED at M40 PR4. */
  readonly state: 'absent' | 'filled';
  readonly why: string;
}

const PRECONDITIONS: readonly Precondition[] = [
  {
    section: '6dd',
    title: 'Two of three distribution status transitions emit no audit event',
    absence:
      'left as found because the route has no consumer anywhere — no BFF client, ' +
      "and the operator edge's exact-match allowlist does not carry it",
    corpus: ['apps/bff/src', 'apps/operator-web/src'],
    filledWhen: /setEstateDistributionStatus|distributions\/:distributionId\/amount/,
    notCountedIn: [],
    state: 'filled',
    why:
      'THE POSITIVE CONTROL, and the defect this whole mechanism exists for. M23 ' +
      'PR4b (4e125e1) built the consumer the deferral said did not exist and did ' +
      'not add the emit. M26 owns the emit. This entry must keep reporting FILLED: ' +
      'if it ever reads absent, the scanner is broken, not the tree.',
  },
  {
    section: '6bb',
    title: 'The operator interstitial is reachable only by typing its URL',
    absence: "`/operator` is deliberately not in the app's navigation",
    corpus: ['apps/web/src'],
    filledWhen: /href[=:]\s*['"`]\/operator/,
    notCountedIn: [],
    state: 'absent',
    why:
      'ACCEPTED on the reasoning that minting is role-blind, so a navigation entry ' +
      'would advertise a surface most holders cannot use. A link appearing here ' +
      'does not create a vulnerability; it retires the reasoning, which is exactly ' +
      'the event nobody was watching for.',
  },
  {
    section: '6dd',
    title: '`config.secureCookies` is asserted by a test and read by nothing',
    absence: 'read by nothing',
    corpus: ['apps/operator-web/src', 'apps/vault-web/src'],
    filledWhen: /secureCookies/,
    notCountedIn: [
      {
        path: 'config.ts',
        why: 'the declaration itself, on both origins — the subject, not a reader',
      },
    ],
    state: 'absent',
    why:
      'ACCEPTED because a value nothing reads cannot be misconfigured. The day ' +
      'something reads it, that argument dies and the flag becomes a control with ' +
      'a default nobody chose. Both isolated origins are scanned, because this ' +
      'shape was recorded on one edge and lives on two (§6ggg, M47).',
  },
  {
    section: '6ll',
    title: '`document_search_tokens` is not purged by anything',
    absence: 'not purged by anything',
    corpus: ['apps/services/documents/src'],
    filledWhen: /DELETE\s+FROM\s+document_search_tokens/,
    notCountedIn: [
      {
        path: 'search-tokens.repo.ts',
        why:
          'replaceForDocument is a sanctioned replace-in-place on RE-INDEX, declared ' +
          'as such in that file and in 002_document_vault.sql. It is not the erasure ' +
          'purge this residual is about, and a probe that counts it reports the ' +
          'absence spent on the strength of the wrong DELETE.',
      },
    ],
    state: 'absent',
    why:
      'A blind index of a crypto-shredded document outliving the document is the ' +
      'defect. The migration comment promises a privileged retention job; no such ' +
      'job exists. M26 owns it. This probe watches for the purge ARRIVING, which ' +
      'would mean the residual can close.',
  },
  {
    section: '6d',
    title: 'Conversations are outside staged settlement access',
    absence: 'conversations are in none of those rungs',
    corpus: ['apps/services/settlement/src'],
    filledWhen: /conversation|transcript/i,
    notCountedIn: [],
    state: 'absent',
    why:
      'ACCEPTED because the three rungs are inventory, documents and vault, and ' +
      'assistant.cedar keys its one permit on `subject` rather than `owner`. A ' +
      'settlement source file learning the word "conversation" is the first sign ' +
      'that a fourth rung is being built, which is when this decision needs remaking.',
  },
];

/**
 * Absence-asserting residuals that are NOT probed, each with the reason.
 *
 * Stated as data for the same reason the corpus is: a silent skip and a clean
 * result are indistinguishable. Every one of these was checked by hand in the
 * M40 PR4 sweep and found to HOLD; what they lack is a probe narrow enough to
 * be worth arming, which is a different thing from being unchecked.
 */
const UNPROBED_ABSENCES: readonly { readonly section: string; readonly why: string }[] = [
  {
    section: '6j',
    why:
      "the stolen-session bootstrap: the absence is 'an account that never enrolled " +
      "a factor has no proof to demand', which is a property of an account rather " +
      'than of the tree. No file appearing or disappearing changes it.',
  },
  {
    section: '6z',
    why:
      'the revocation notice: its absence was ALREADY spent and the bullet says so ' +
      "in its own text — M40 PR2 re-owned it to M46 noting 'that surface now EXISTS'. " +
      'Probing it would re-report a finding already recorded, which is how a fence ' +
      'teaches its readers to ignore it.',
  },
  {
    section: '6bb',
    why:
      'operator READS bounded/counted/reviewed by nothing: three absences in one ' +
      'bullet, and the honest probe for each is a different shape (a ledger EXEMPT ' +
      'map, a gate call site, a review surface). M46 owns the whole bullet; splitting ' +
      'it into three probes before it is split into three bullets would put the ' +
      'mechanism ahead of the record.',
  },
  {
    section: '6ww',
    why:
      'the versions reader: the absence is that a reset leaves no reachable caller ' +
      'for a killed row, which is bounded by the uniform 404 rather than by a filter. ' +
      'The probe would have to model reachability, not presence.',
  },
];

/**
 * Read every file under a repo-relative directory, skipping build output and
 * tests. The corpus is the SOURCE a deployment ships, not what asserts about it.
 */
function sourceFiles(dir: string): string[] {
  const root = join(__dirname, '..', '..', '..', dir);
  let names: string[];
  try {
    names = readdirSync(root, { recursive: true, encoding: 'utf8' });
  } catch {
    return [];
  }
  return names
    .filter((n) => /\.(ts|tsx|sql)$/.test(n))
    .filter((n) => !/(^|[/\\])(node_modules|dist|dist-esm|coverage|\.next)[/\\]/.test(n))
    .filter((n) => !/\.spec\.|\.test\.|(^|[/\\])test[/\\]/.test(n))
    .map((n) => join(root, n))
    .filter((f) => statSync(f).isFile());
}

/**
 * The predicate, extracted so the controls exercise the REAL matcher rather
 * than a paraphrase of it — the same lesson as `staleAmong` below.
 */
function fillMatches(p: Precondition, files: readonly string[]): { file: string; line: number }[] {
  const out: { file: string; line: number }[] = [];
  for (const file of files) {
    if (p.notCountedIn.some((x) => file.endsWith(x.path))) continue;
    const lines = readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      if (p.filledWhen.test(line)) out.push({ file, line: i + 1 });
    });
  }
  return out;
}

const TAG = /^- \*\*\[(ACCEPTED|OWNER: ([A-Z]\d{1,2})|CLOSED: §6[a-z]{0,3})\]\*\*/;

interface QueueRow {
  readonly id: string;
  readonly status: string;
  readonly line: number;
}

/**
 * docs/04's queue table, parsed ONCE and read by everything below it.
 *
 * One behaviour, one spelling (M40 PR0). The shipped-owner check below carried
 * this parse inline, and the totality check added here is a second caller of it;
 * N copies of a parse is N places for the column index to be wrong in. The owner-vocabulary check is
 * deliberately NOT a caller: it reads the FIRST column of BOTH tables
 * (`(M\d{2}|E\d)`), which is a different corpus answering a different question,
 * and folding the two together is how this fence would come to assert that an
 * escalation has a lifecycle.
 *
 * The Status cell is the THIRD; `| M40 | name | status |` splits to
 * ['', ' M40 ', ' name ', ' status ', ''] and the tail is rejoined so a status
 * containing a pipe cannot silently truncate what is scanned. Which table that
 * index belongs to is asserted separately, against the document's own header.
 */
function queueRows(): QueueRow[] {
  return readFileSync(PLAN, 'utf8')
    .split('\n')
    .map((line, index) => ({ line, index }))
    .map(({ line, index }) => ({ m: /^\| (M\d{2}) \|/.exec(line), line, index }))
    .filter((x): x is { m: RegExpExecArray; line: string; index: number } => x.m !== null)
    .map(({ m, line, index }) => ({
      id: m[1] as string,
      status: line.split('|').slice(3).join('|'),
      line: index + 1,
    }));
}

describe('docs/03 §6 — every residual declares a disposition', () => {
  const { items, sections, declared, regions, interruptions, outside } = residuals();

  it('every DECLARED region actually collects a residual', () => {
    /*
     * A REGION THAT OPENS OVER PROSE COLLECTS NOTHING AND SAYS NOTHING.
     *
     * The corpus is bullets, so a marker standing over paragraphs is
     * recognized, opens a block, and yields zero — indistinguishable from a
     * region whose residuals are all tagged. Every other assertion in this
     * file then passes over content it never saw, which is the shape M21 PR2.5
     * found in §6b: two declared markers, two TB7 deferrals underneath them,
     * and no tag on either, so the milestone scoped from those deferrals
     * counted neither of its own.
     *
     * The remedy in the doc is to write a residual as a bullet. The remedy
     * here is to refuse to be silent about the difference.
     */
    // SETS, not a total. Mis-attribution preserves a count.
    expect(interruptions.map((i) => `${i.section} :: ${i.label}`).sort()).toEqual(
      DECLARED_INTERRUPTIONS.map((d) => `${d.section} :: ${d.label}`).sort(),
    );
    const empty = regions.filter((r) => r.count === 0);
    expect(
      empty.map((r) => `docs/03 §${r.section} line ${r.line}: "${r.label}" collected no bullet`),
    ).toEqual([]);
  });

  it('finds the residual bullets at all (anti-vacuity)', () => {
    // Without this the whole file passes when the parser breaks, which is the
    // failure mode every fence in this repo has had at least once.
    expect(sections.size).toBeGreaterThanOrEqual(MIN_SECTIONS);
    expect(items.length).toBeGreaterThanOrEqual(MIN_RESIDUALS);
  });

  it('no SECTION has lost a residual — a floor at every level, not just the total', () => {
    // The total floor exists to catch a broken parser and is set far below the
    // real count so ordinary editing does not trip it. That leaves a single
    // DELETION invisible, which is the one thing a milestone editing its own
    // residuals is most likely to do. Reported per section and as a whole set
    // rather than a first failure, so one run names everything that moved.
    //
    // WHAT A COUNT FLOOR CANNOT SEE, stated because the claim above is narrower
    // than it reads: a deletion and an addition IN THE SAME SECTION cancel, and
    // this stays green. The set comparison that would close it needs a stable
    // identity per residual, and a residual is free prose whose only stable
    // parts are its section and its disposition tag — so the identity would
    // have to be the text, and every reword would be a failure. The bound is
    // therefore deliberate: this catches a section getting SMALLER, which is
    // what an accidental deletion looks like, and does not catch a swap, which
    // is what a deliberate edit looks like. §6's own review is the control for
    // the second kind.
    const actual = new Map<string, number>();
    for (const item of items) actual.set(item.section, (actual.get(item.section) ?? 0) + 1);

    const shortfalls = Object.entries(MIN_PER_SECTION)
      .filter(([section, floor]) => (actual.get(section) ?? 0) < floor)
      .map(([section, floor]) => `§${section}: ${actual.get(section) ?? 0} < ${floor}`);
    expect(shortfalls).toEqual([]);

    // And the floors must cover every section that HAS residuals, or a whole
    // new section could be emptied without any floor noticing — the same gap
    // one level up. A section gaining residuals is not a failure; a section
    // holding residuals that nothing floors is.
    const unfloored = [...actual.keys()]
      .filter((section) => !(section in MIN_PER_SECTION))
      .map((section) => `§${section} has ${actual.get(section)} residuals and no floor`);
    expect(unfloored).toEqual([]);
  });

  it('every residual opens with exactly one disposition tag', () => {
    const untagged = items
      .filter((r) => !TAG.test(r.text))
      .map((r) => `docs/03-threat-model.md:${r.line} (§${r.section}) ${r.text.slice(0, 90)}`);
    expect(untagged).toEqual([]);
  });

  it('the owner vocabulary is DERIVED from the plan, not a second copy of it', () => {
    // OWNERS above is a hand-kept list with a reason per entry, which is what
    // makes a wrong owner reviewable in a diff. What it must not become is a
    // SECOND SOURCE for which milestones exist: renumber M27 in docs/04 and a
    // free-standing list keeps blessing an id nothing plans to build, which is
    // the drift shape this repo fixes with the compose-parity mechanism. So the
    // list is checked against docs/04's own two tables — one row per item,
    // first column — in BOTH directions.
    const rows = readFileSync(PLAN, 'utf8')
      .split('\n')
      .map((line) => /^\| (M\d{2}|E\d) \|/.exec(line))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => m[1] as string);
    expect(rows.length).toBeGreaterThanOrEqual(20);
    expect([...rows].sort()).toEqual([...OWNERS].sort());
  });

  it('every OWNER names someone from the closed vocabulary', () => {
    // A free-text owner is a way to look owned without being owned. Growing the
    // list is a deliberate edit here, in the same change as the milestone.
    const unknown = items
      .map((r) => ({ r, m: TAG.exec(r.text) }))
      .filter(({ m }) => m !== null && m[2] !== undefined && !OWNERS.includes(m[2]))
      .map(
        ({ r, m }) => `docs/03-threat-model.md:${r.line} names unknown owner "${String(m?.[2])}"`,
      );
    expect(unknown).toEqual([]);
  });

  it('a CLOSED residual cites a delta that EXISTS', () => {
    // "closed" with no citation is the claim-without-a-mechanism shape: it
    // stops the next reader looking and offers them nowhere to look.
    //
    // THE SHAPE CHECK WAS NOT ENOUGH, and M40 PR2's mutation harness is what
    // said so: `[CLOSED: §6zzz]` satisfied `§6[a-z]{0,3}` and the file stayed
    // green. A citation to a section that does not exist offers the next reader
    // nowhere to look just as completely as no citation does — it is the same
    // defect wearing the format. So the cited id is now checked against the
    // SECTIONS THE PARSER ACTUALLY FOUND rather than against a pattern, which
    // is the same derive-don't-describe rule the owner vocabulary follows one
    // test above. PR2 is what made this load-bearing — but by DRAFTING two
    // CLOSED tags, not by shipping them. Its own review killed both (docs/03
    // §6fff), so this PR adds ZERO CLOSED tags and the document's total is 28
    // before and after it. The assertion is therefore exercised entirely by
    // residuals OLDER than this change, which is exactly what the floor below
    // is for. An earlier draft of this comment said "add", present tense, and
    // survived the revert of the thing it described.
    const closed = items.filter((r) => /^- \*\*\[CLOSED/.test(r.text));
    const malformed = closed
      .filter((r) => !/^- \*\*\[CLOSED: §6[a-z]{0,3}\]\*\*/.test(r.text))
      .map((r) => `docs/03-threat-model.md:${r.line} is CLOSED without naming a §`);
    const dangling = closed
      .map((r) => ({ r, m: /^- \*\*\[CLOSED: §(6[a-z]{0,3})\]\*\*/.exec(r.text) }))
      .filter(({ m }) => m !== null && !sections.has(m[1] as string))
      .map(
        ({ r, m }) =>
          `docs/03-threat-model.md:${r.line} is CLOSED citing §${String(m?.[1])}, which is not a section in this document`,
      );
    expect(malformed).toEqual([]);
    expect(dangling).toEqual([]);
    // ANTI-VACUITY: this assertion is worth nothing if nothing is CLOSED.
    expect(closed.length).toBeGreaterThanOrEqual(20);
  });

  it('every residual lead-in is classified — the marker list cannot narrow in silence', () => {
    // THE FENCE'S OWN ANTI-VACUITY, and the reason REGION_MARKERS is data.
    // Under-collecting is this fence's silent failure: a delta that opens its
    // residuals with a sixteenth idiom would contribute ZERO bullets and the
    // whole file would still pass. So every bolded lead-in in §6 that mentions
    // a residual must be classified as one or the other, and an unrecognised
    // one fails HERE, naming itself.
    const lines = readFileSync(DOC, 'utf8').split('\n');
    const known = new Set(NON_REGION_LABELS.map((n) => n.label));
    let inSix: string | null = null;
    const unclassified: string[] = [];
    const reached = new Set<string>();
    let seen = 0;
    lines.forEach((line, index) => {
      // `6[a-z]{0,3}` — and this is the occurrence where the one-letter
      // version was not merely mis-attributing but BLIND. `## 6aa.` failed the
      // first test and passed the second (`^## `), so `inSix` went FALSE at
      // §6aa and stayed false: §6aa and §6bb were outside this scan entirely,
      // and a residual lead-in written there with an unrecognised idiom would
      // have been unclassified and unreported. A fence that stops matching goes
      // green, which is the failure this file exists to make loud.
      const heading = /^## (6[a-z]{0,3})\./.exec(line);
      if (heading !== null) inSix = heading[1] as string;
      else if (/^## /.test(line)) inSix = null;
      if (inSix === null) return;
      reached.add(inSix);
      const label = boldLabel(line, lines.slice(index + 1, index + 4));
      if (label === null || !MENTIONS_RESIDUAL.test(label)) return;
      seen += 1;
      if (!REGION_MARKERS.includes(label) && !known.has(label)) unclassified.push(label);
    });
    // ANTI-VACUITY ON EVERY LEVEL OF THE SCAN, not only on its total. A floor
    // over the whole file passes happily while two entire sections are skipped
    // — which is exactly what the one-letter regex did — so the SET of sections
    // this scan reached is compared against the set the parser found. A count
    // preserves totals under mis-attribution; a set does not.
    expect([...reached].sort()).toEqual([...sections].sort());
    expect(seen).toBeGreaterThanOrEqual(REGION_MARKERS.length);
    expect(unclassified).toEqual([]);
  });

  it('the parser sees every §6 delta the FILE contains — no heading shape escapes it', () => {
    /*
     * THE ASSERTION THAT WOULD HAVE CAUGHT THE ONE-LETTER REGEX, and the
     * reason it is written as a comparison rather than as a floor.
     *
     * Three patterns in this file matched `## 6[a-z]?\.`, which stopped
     * matching the day the doc reached §6aa. Two of them mis-attributed (a
     * two-letter section's bullets were reported under the last single-letter
     * heading); the third turned its scan OFF at §6aa and left two whole
     * deltas unexamined. Nothing went red, because every bullet in them
     * happened to be tagged.
     *
     * So the parser's own view of which sections exist is compared against an
     * independently permissive read of the file. A count would not do: it
     * passes as long as the totals agree, and mis-attribution preserves totals.
     */
    const headings = readFileSync(DOC, 'utf8')
      .split('\n')
      .map((line) => /^## (6[a-z]*)\. /.exec(line))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => m[1] as string);
    expect(headings.length).toBeGreaterThanOrEqual(MIN_SECTIONS);
    expect([...sections].sort()).toEqual([...new Set(headings)].sort());
  });

  it('the section vocabulary has ONE spelling, and the guard above is still the LOOSER one', () => {
    /*
     * WHAT THE TEST ABOVE CANNOT SEE ABOUT ITSELF (M27 PR5).
     *
     * The letter bound on `## 6<letters>.` is written out in SIX places in
     * this file: the parser, the lead-in classification scan, the partition
     * total, the outside-§6 scan, and twice as a `CLOSED: §` citation. They
     * are separate on purpose — the comment on the partition total says so —
     * because an independently re-derived scan is what turns a break in the
     * parser into a DISAGREEMENT instead of a shared blind spot.
     *
     * Independence in the traversal is the property worth having. Independence
     * in the LETTER BOUND is pure liability, and it is the half-applied-rule
     * shape this milestone kept finding: extending the bound is a six-line
     * edit, five of which nothing forces you to make. The one-letter era
     * survived precisely because every copy was wrong together.
     *
     * The second assertion is the one with teeth. The test above compares the
     * parser against an "independently permissive read" — but nothing made
     * that read permissive except an author's care. Widen the parser to
     * `[a-z]*` and that comparison becomes a tautology: it would pass on every
     * possible file, forever, while reading exactly like the fence that caught
     * the one-letter regex. A fence that measures nothing is worse than no
     * fence, because it is load-bearing in someone's head.
     *
     * So: every bounded copy agrees, and the guard's bound strictly exceeds
     * theirs. Extending to four letters means changing one number in seven
     * places and this test names all of them.
     */
    // Built by concatenation, never as literals: a scanner written with the
    // pattern it scans for finds ITSELF and reports a clean file.
    const bounded = new RegExp('6\\[a-z\\]\\{0,(\\d+)\\}', 'g');
    const open = new RegExp('6\\[a-z\\]\\*', 'g');

    const self = readFileSync(__filename, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^[ \t]*\/\/.*$/gm, '');

    // ANTI-VACUITY FIRST, and on the corpus rather than the result: comment
    // stripping that ate the file would leave every `new Set` below empty and
    // every assertion green. The parser's own line must survive the strip.
    expect(self).toContain('sections.add(section)');
    expect(self.length).toBeGreaterThan(20000);

    const bounds = [...self.matchAll(bounded)].map((m) => Number(m[1]));
    // A FLOOR AT THIS LEVEL TOO. Five of the six copies could be renamed out
    // of existence and a set of one distinct value would still be a set of one.
    expect(bounds.length).toBeGreaterThanOrEqual(6);
    expect([...new Set(bounds)]).toHaveLength(1);

    // The guard's read is unbounded, so it is looser than any bound at all —
    // and there is exactly one of it, because a second unbounded copy is how
    // the parser becomes unbounded without anyone editing the parser.
    expect(self.match(open) ?? []).toHaveLength(1);
  });

  it('every §6 DELTA declares a residual region, so the next one lands where the fence looks', () => {
    // THE FORCING FUNCTION, and the answer to this fence's own stated bound.
    // A residual written as prose outside a declared region, using none of the
    // marker phrases, is invisible to the parser — no regex closes that,
    // because the doc's structure genuinely does not distinguish those
    // bullets. What closes it is requiring every delta to HAVE a residual
    // region: then the next milestone's residuals land somewhere already
    // watched, and a delta with none has to say so out loud.
    //
    // §6 itself is the risk register, not a delta, so it is exempt by name.
    const deltas = [...sections].filter((s) => s !== '6');
    const silent = deltas.filter((s) => !declared.has(s)).sort();
    expect(silent).toEqual([]);
  });

  it('the bullets OUTSIDE the corpus are declared per lead-in — the fence states its own reach', () => {
    // THE ASSERTION M27 PR0 ADDED, and the one that would have caught §6j:1623.
    // See OUT_OF_CORPUS above for why a stated bound was not enough.
    const derived = new Map<string, number>();
    for (const b of outside) {
      const key = `${b.section} § ${b.lead}`;
      derived.set(key, (derived.get(key) ?? 0) + 1);
    }
    // Annotated, because inference makes the key a TEMPLATE-LITERAL type and
    // then refuses every plain-string lookup below. A jest run does not
    // typecheck, so this only surfaced under `pnpm typecheck`.
    const declaredCensus = new Map<string, number>(
      OUT_OF_CORPUS.map((d) => [`${d.section} § ${d.label}`, d.bullets] as const),
    );

    // SETS FIRST. Mis-attribution preserves a total: a bullet that moves from
    // one lead-in to another leaves every count in this file unchanged unless
    // the KEYS are compared.
    expect([...derived.keys()].sort()).toEqual([...declaredCensus.keys()].sort());

    // THEN THE PER-LEVEL COUNTS. This is the half that catches a bullet added
    // under an existing lead-in, which is how the restore residual arrived.
    const disagreements = [...derived.entries()]
      .filter(([key, n]) => declaredCensus.get(key) !== n)
      .map(([key, n]) => `${key} :: declared ${String(declaredCensus.get(key))}, found ${n}`);
    expect(disagreements).toEqual([]);

    // ANTI-VACUITY, at the level of this scan rather than the file's total: a
    // parser that stopped collecting `outside` at all would satisfy both
    // assertions above the moment somebody emptied the list to match it.
    expect(outside.length).toBeGreaterThanOrEqual(MIN_OUT_OF_CORPUS);
    expect(derived.size).toBeGreaterThanOrEqual(MIN_OUT_OF_CORPUS_LEADS);
    // And the classification cannot collapse to one value that means nothing —
    // a census where every entry says 'shipped' is a census nobody read.
    expect(new Set(OUT_OF_CORPUS.map((d) => d.kind)).size).toBeGreaterThanOrEqual(4);
  });

  it('the corpus and its complement partition §6 — no bullet is in both or neither', () => {
    // The two halves are produced by one branch of one parser, so this cannot
    // fail without the parser changing shape. It is here because that is
    // precisely the change that would make the census meaningless while both
    // assertions above still passed: `outside` quietly collecting a subset.
    const total = readFileSync(DOC, 'utf8')
      .split('\n')
      .reduce((n, line, i, all) => {
        if (!line.startsWith('- ')) return n;
        // Only §6 counts, and only bullets the parser would reach — the same
        // section test, re-derived here rather than shared, so a break in the
        // parser's own section tracking shows up as a DISAGREEMENT.
        const before = all.slice(0, i);
        const lastHeading = [...before].reverse().find((l) => /^## /.test(l)) ?? '';
        return /^## 6[a-z]{0,3}\./.test(lastHeading) ? n + 1 : n;
      }, 0);
    expect(items.length + outside.length).toBe(total);
    expect(total).toBeGreaterThanOrEqual(MIN_SECTION_SIX_BULLETS);
  });

  it('a residual written OUTSIDE §6 is still caught — the §6-boundary repair cut both ways', () => {
    /*
     * THE ONE PLACE M27 PR0 MADE A PRE-EXISTING ASSERTION WEAKER, restored.
     *
     * PR0 taught the parser that a non-§6 `## ` heading ends §6, because
     * `## 7. Validation program` sits BETWEEN §6hh and §6ii,
     * the deltas having been appended after the numbered sections — and its
     * four bullets were being attributed to §6hh. That fixed a real
     * mis-attribution and cost something the fence's own review caught: BEFORE
     * the repair, an untagged residual written in §7 was collected into the
     * corpus (mislabelled §6hh) and reddened `every residual opens with exactly
     * one disposition tag`. AFTER it, `section` is null there, so such a bullet
     * is invisible to that assertion AND absent from the census, which is
     * §6-scoped by construction.
     *
     * Attributing it to §6hh was never the right answer. Requiring a
     * disposition tag on §7's bullets is not either — they are a validation
     * PROGRAMME, not residuals. So the claim here is narrower and true: a
     * bullet outside §6 that SAYS it is deferred work must still carry a
     * disposition, wherever it lives.
     */
    const lines = readFileSync(DOC, 'utf8').split('\n');
    const residualLanguage =
      /(recorded,? (?:rather than|not) (?:fixed|closed)|accepted residual|residual (?:is|here|accepted|stated|carried)|remains? open|stays open|is not closed|left open|still open|owed by|no (?:self-service|operator) remedy|until TB7|its own milestone|a later milestone|needs its own)/i;
    // SCOPED TO WHAT THE REPAIR ACTUALLY COST, which is narrower than "outside
    // §6". The parser's `section` starts null, so §§1-5 were never collected
    // BEFORE PR0 either — their STRIDE bullets state residuals inline and have
    // never used the §6 disposition vocabulary, and demanding tags there would
    // be a new claim wearing a regression's clothes. What PR0 lost is bullets
    // in a non-§6 top-level section that appears AFTER the deltas begin, which
    // today is `## 7. Validation program` alone and tomorrow is whatever else
    // gets overtaken by an appended delta.
    let sawSix = false;
    let outsideSix = false;
    let seen = 0;
    const untagged: string[] = [];
    lines.forEach((line, index) => {
      if (/^## /.test(line)) {
        const isSix = /^## 6[a-z]{0,3}\./.test(line);
        if (isSix) sawSix = true;
        outsideSix = sawSix && !isSix;
      }
      if (!outsideSix || !line.startsWith('- ')) return;
      const buf = [line];
      for (let j = index + 1; j < lines.length; j += 1) {
        const next = lines[j] as string;
        if (!next.startsWith('  ') || next.trim() === '') break;
        buf.push(next);
      }
      const text = buf.map((l) => l.trim()).join(' ');
      seen += 1;
      if (residualLanguage.test(text) && !TAG.test(text)) {
        untagged.push(`docs/03-threat-model.md:${index + 1} ${text.slice(0, 90)}`);
      }
    });
    // ANTI-VACUITY: §§1-5 and §7 carry plenty of bullets. A scan reaching none
    // of them would report zero violations and read exactly like a clean one.
    expect(seen).toBeGreaterThanOrEqual(MIN_NON_SIX_BULLETS);
    expect(untagged).toEqual([]);
  });

  it('the queue table is the shape this fence reads — the corpus, asserted', () => {
    /*
     * STATE THE CORPUS AND ASSERT IT. Everything below reads docs/04's third
     * cell as a lifecycle. That is only true of ONE of the two tables on that
     * page, and the OTHER table on it — the escalations one, immediately above —
     * has a third cell that answers "what is this blocked on". A fence that reads a column by index
     * without checking which table it landed in is the narrower-input-than-claim
     * shape §6y names, so the index is anchored on the headers themselves.
     */
    const plan = readFileSync(PLAN, 'utf8').split('\n');
    const queueHeader = plan.indexOf(QUEUE_HEADER);
    const escalationHeader = plan.indexOf(ESCALATION_HEADER);
    expect(queueHeader).toBeGreaterThan(-1);
    expect(escalationHeader).toBeGreaterThan(-1);
    // Exactly one of each, or "the header" names two places and the anchor is
    // no longer an anchor.
    expect(plan.filter((l) => l === QUEUE_HEADER)).toHaveLength(1);
    expect(plan.filter((l) => l === ESCALATION_HEADER)).toHaveLength(1);
    /*
     * THE THIRD COLUMN OF EACH, READ OUT OF THE DOCUMENT. An earlier draft
     * asserted `ESCALATION_HEADER` did not contain 'Status' — a property of a
     * string this file declares, which reads like a check and is one only by
     * way of the `indexOf` above. Naming the cells makes the claim direct: the
     * queue's third column IS the lifecycle this fence reads, and the
     * escalations' third column is a BLOCKER and answers something else. Either
     * table re-columned reddens here, which is the whole point of anchoring.
     */
    const thirdCell = (line: string): string => (line.split('|')[3] as string).trim();
    expect(thirdCell(plan[queueHeader] as string)).toBe('Status');
    expect(thirdCell(plan[escalationHeader] as string)).toBe('Blocker');
    // And every milestone row lives under the queue header, not the other one.
    const firstRow = plan.findIndex((l) => /^\| M\d{2} \|/.test(l));
    expect(firstRow).toBeGreaterThan(queueHeader);
    expect(queueHeader).toBeGreaterThan(escalationHeader);
  });

  it('every queue row DECLARES a lifecycle status — silence is no longer a status', () => {
    /*
     * THE M40 PR0 ASSERTION, and the one that could not be written as a better
     * regex. Four rows used to answer the completion question with prose that
     * meant something else (`APPROVED`, `SCOPED`) or with the right word in the
     * wrong case (`the row is now complete`), and three of those four had in
     * fact finished. Nothing looked, because nothing REQUIRED an answer.
     *
     * Totality is the fix: a row with no token in the closed vocabulary, at the
     * head of its Status cell, in the one spelling, reddens here by name.
     */
    const rows = queueRows();
    expect(rows.length).toBeGreaterThanOrEqual(MIN_QUEUE_ROWS);

    const undeclared = rows
      .filter((r) => ROW_STATUS.exec(r.status) === null)
      .map(
        (r) => `docs/04-monorepo-and-milestones.md:${r.line} ${r.id} declares no lifecycle status`,
      );
    expect(undeclared).toEqual([]);

    /*
     * ANTI-VACUITY ON THE PARSER, PROBED RATHER THAN INFERRED FROM THE TABLE.
     *
     * The first draft asserted that the tokens FOUND in the table were exactly
     * the vocabulary — "a member nobody uses is a member nobody validates". It
     * was wrong, and the way it was wrong is worth keeping: it goes RED on a
     * legitimate state. The day M21 ships PR5 and this milestone closes, the
     * table can honestly hold no `IN PROGRESS` row at all, and a fence that
     * reddens because the programme is between milestones is a fence people
     * learn to weaken. That is the failure mode, not a hypothetical.
     *
     * The concern underneath it is real, so it is asserted DIRECTLY instead:
     * every declared member must be one the parser can actually SEE. Probing a
     * synthetic cell per token settles that independently of what the table
     * happens to contain today, and cannot false-red.
     */
    for (const token of ROW_STATUSES) {
      const probe = ROW_STATUS.exec(` **${token}.** narrative follows |`);
      expect(probe?.[1]).toBe(token);
    }

    /*
     * AND THE PARSER MUST REFUSE, or "it matches every token" is satisfied by a
     * regex that matches everything. The three near-misses are the ones this
     * column actually produced: no token at all, the M22/M23 spelling with no
     * period, and the M44 defect — the right word, in a bold run, in lower case.
     */
    for (const nearMiss of [
      ' Approved 2026-08-21, section below |',
      ' **COMPLETE** (PR1) |',
      ' **complete.** the row is now done |',
    ]) {
      expect(ROW_STATUS.exec(nearMiss)).toBeNull();
    }

    // A light floor on the real table, which the probes above do not replace:
    // it says the column is still being used to draw a distinction at all.
    const found = new Set(rows.map((r) => (ROW_STATUS.exec(r.status) as RegExpExecArray)[1]));
    expect(found.size).toBeGreaterThanOrEqual(2);
  });

  it('every ESCALATION row declares a state — the blocker half can report a change', () => {
    // M40 PR4, answering docs/03 §6vv. The escalations table could not say
    // whether anything had moved, so twenty-two residual tags sat behind a
    // column with no state at all. See ESCALATION_STATES for why this is not
    // the milestone vocabulary.
    const rows = escalationRows();

    // ANTI-VACUITY: a renamed first column would empty this and pass.
    expect(rows.length).toBeGreaterThanOrEqual(5);

    const silent = rows
      .filter((r) => !ESCALATION_STATE.test(r.state))
      .map((r) => `${r.id} (docs/04:${r.line}) declares no state: ${r.state.trim().slice(0, 60)}`);
    expect(silent).toEqual([]);

    // The header says the fourth cell is the State, read out of the document
    // rather than assumed — the same anchoring the queue table gets, and the
    // reason a re-columned table reddens here instead of silently mis-parsing.
    const plan = readFileSync(PLAN, 'utf8').split('\n');
    const header = plan.indexOf(ESCALATION_HEADER);
    expect(header).toBeGreaterThan(-1);
    expect((plan[header] as string).split('|')[4]?.trim()).toBe('State');
  });

  it('no residual names an escalation whose blocker has CLEARED', () => {
    /*
     * THE ASSERTION THE STATE COLUMN MAKES POSSIBLE, and the opposite in meaning
     * to its neighbour below. A milestone going COMPLETE leaves a residual with
     * nobody who owes it. An escalation going CLEARED leaves one that is newly
     * DOABLE and still unassigned — the blocker that justified deferring it is
     * gone, and nothing has re-owned it to a milestone.
     *
     * IT IS VACUOUS TODAY AND SAYS SO. All five escalations read BLOCKED, so
     * `cleared` is empty and this compares [] against []. That is exactly the
     * shape M40 PR3 had to repair one test below, so it gets the same repair
     * rather than waiting to acquire the same defect: the predicate is extracted
     * and exercised by a control.
     */
    const cleared = new Set(
      escalationRows()
        .filter((r) => /\*\*CLEARED\.\*\*/.test(r.state))
        .map((r) => r.id),
    );

    const namingCleared = (rows_: readonly { text: string }[]): { text: string }[] =>
      rows_.filter((r) => {
        const m = TAG.exec(r.text);
        return m !== null && m[2] !== undefined && cleared.has(m[2]);
      });

    expect(namingCleared(items)).toEqual([]);

    /*
     * THE POSITIVE CONTROL. `cleared` is empty, so the assertion above cannot
     * fail for any reason — a broken parser, a renamed column and a healthy tree
     * all produce []. The control feeds a synthetic bullet through the SAME
     * predicate with a synthetically-cleared set, and requires it to FIRE.
     *
     * The escalation id is taken from the DERIVED rows rather than hard-coded,
     * so deleting E1 from the plan cannot leave this control asserting about an
     * escalation that no longer exists.
     */
    const [anEscalation] = escalationRows()
      .map((r) => r.id)
      .sort();
    expect(typeof anEscalation).toBe('string');

    const withCleared = new Set([String(anEscalation)]);
    const namingClearedSynthetic = (rows_: readonly { text: string }[]): { text: string }[] =>
      rows_.filter((r) => {
        const m = TAG.exec(r.text);
        return m !== null && m[2] !== undefined && withCleared.has(m[2]);
      });
    expect(
      namingClearedSynthetic([{ text: `- **[OWNER: ${String(anEscalation)}]** *synthetic.*` }]),
    ).toHaveLength(1);

    // ...and the NEGATIVE twin, because a predicate that fires on everything
    // also "fires". A milestone tag must not be caught by an escalation set.
    expect(namingClearedSynthetic([{ text: '- **[OWNER: M46]** *synthetic.*' }])).toEqual([]);

    // AND THE REAL CORPUS IS NON-EMPTY FOR THIS TAG SHAPE, so `namingCleared`
    // returning [] above is a statement about states rather than about there
    // being no escalation-owned residuals to check. Twenty-two of them exist.
    const escalationOwned = items.filter((r) => {
      const m = TAG.exec(r.text);
      return m !== null && m[2] !== undefined && /^E\d$/.test(m[2]);
    });
    expect(escalationOwned.length).toBeGreaterThanOrEqual(20);
  });

  it('no residual is owned by a milestone that has already SHIPPED', () => {
    /*
     * THE COMPLEMENTARY HOLE, and PR0 exists because of its twin. §6j:1623
     * assigned the restore surface to "the operator platform (TB7)" and TB7
     * shipped as M21 without it — the bullet was untagged, so the census now
     * catches that shape. This is the other half: a bullet that IS tagged, to a
     * milestone that has since COMPLETED. Nothing looked at it, and `OWNERS` is
     * derived from every row of docs/04's table INCLUDING the completed ones,
     * so a tag naming a shipped milestone passes the vocabulary check exactly
     * as a live one does. Found by the M27 PR0 review.
     *
     * Derived on both sides: the completed set comes from docs/04's own status
     * column, so a milestone marked COMPLETE tomorrow reddens this the moment
     * its row changes — which is the point. There is no list to maintain here.
     */
    const rows = queueRows();
    // ANTI-VACUITY on the ROWS, before any status is read from them: a table
    // that moved, or a row format that changed, would otherwise leave every
    // derivation below operating on an empty corpus and passing in silence.
    expect(rows.length).toBeGreaterThanOrEqual(MIN_QUEUE_ROWS);

    /*
     * READ THE DECLARED TOKEN, NOT THE PROSE — and this assertion has now been
     * wrong twice in the same direction, each time by asking a sentence a
     * question only a mark can answer.
     *
     * The first draft read the whole row: `/^\| (M\d{2}) \|.*COMPLETE/` matched
     * the word ANYWHERE in a 400-character cell, so the M40 row joined the
     * completed set the moment it EXPLAINED that thirteen residuals name
     * milestones "whose docs/04 rows read COMPLETE". The repair was to read
     * bold runs only, on the theory that prose is not bold.
     *
     * It is. `**PR2 (2026-08-25) CLOSED THE REST — docs/03 §6ccc, and the row is
     * now complete.**` is a bold run, and a sentence, and the case-sensitive
     * `\bCOMPLETE\b` did not match it — so M44 announced its own completion in
     * the Status column and the derivation read nothing. Meanwhile M24 and M27
     * had finished under `**APPROVED …**` and `**SCOPED …**`, which no regex
     * looking for a completion word could ever have caught, because the word
     * was not there to catch.
     *
     * So the token is now DECLARED rather than detected: one member of
     * `ROW_STATUSES`, at the head of the cell, as a bold run that is the token
     * and nothing else. Narrative keeps the rest of the cell and can no longer
     * be mistaken for a status. Totality is asserted separately, which is what
     * stops a row from answering by saying nothing at all.
     */
    const completed = new Set(
      rows.filter((r) => ROW_STATUS.exec(r.status)?.[1] === 'COMPLETE').map((r) => r.id),
    );
    // ANTI-VACUITY on the STATUSES: a token regex that stopped matching would
    // find no completed milestones and pass just as quietly.
    //
    // A RATCHET, NOT A SLACK FLOOR, and the distinction matters because the old
    // one looked identical. It sat at 3 against a derived set of exactly 3 — a
    // guard pinned to the output of the derivation it was guarding, which is no
    // guard at all, and 3 was the WRONG number besides. It sits at the derived
    // value for the opposite reason: that many milestones are known finished,
    // and one more is a `>=` that passes while un-marking any of them reddens.
    // (This comment said "6 against a derived 6" through two ratchets — M40 PR4
    // to 7 and M48 PR3 to 8 — because nothing reads a number written in prose.
    // It now names the constant instead of restating its value.)
    // Same shape as MIN_PER_SECTION, which every section already sits exactly
    // on. Totality carries the broken-parser case now, so this no longer has to.
    expect(completed.size).toBeGreaterThanOrEqual(MIN_COMPLETED_MILESTONES);

    // ONE SPELLING of the predicate, because the positive control below has to
    // exercise the code the real corpus exercises. A control that re-implements
    // the thing it is controlling proves only that two copies agree.
    const staleAmong = (rows_: readonly { text: string }[]): { text: string }[] =>
      rows_.filter((r) => {
        const m = TAG.exec(r.text);
        return m !== null && m[2] !== undefined && completed.has(m[2]);
      });

    const stale = staleAmong(items);

    // PINNED, NOT ZERO — and the difference is the honest part. Thirteen
    // residuals name a milestone whose queue row is COMPLETE: M23 twelve, M22
    // one. Re-owning them means deciding, one at a time, whether a later slice
    // of the same programme still owes the work or whether it closed with the
    // milestone — a sweep, and M40's later PRs own it. What ships here is that
    // the number cannot GROW in silence: a residual newly tagged to a shipped
    // milestone, or a milestone declaring COMPLETE while residuals still name
    // it, reddens this immediately.
    //
    // M21 OWNS NONE AT ALL NOW, and the history is worth stating because this
    // comment has carried two wrong versions of it. It once read "Thirty-one …
    // (M21 eighteen, M23 twelve, M22 one)", counting M21 as stale. M21 has NOT
    // shipped: docs/04's
    // `- **PR5 — documents evidence content + the legal-hold lift ceremony.**`
    // bullet ends `NOT YET SHIPPED.`, and no commit names it. (Cited by its TEXT
    // rather than by a line number: this comment said `docs/04:5639`, and M40
    // PR1 moved that line by eight while editing the same file. A line number
    // into another file is a citation that rots on the next edit above it.) So
    // M21's row saying nothing about completion was HONEST, not the stale prose
    // the M40 row called it, and its residuals were live debt on a live
    // milestone rather than debt on a closed one. M40 PR2 then adjudicated all
    // seventeen (docs/03 §6fff) and the count is now ZERO. Seventeen bullets
    // held TWENTY items: thirteen went to owners that PR had to create (M45,
    // M46), five are accepted on their own bounds, two went to owners that
    // already existed (E1, M43), and nothing closed.
    //
    // M40 PR3 THEN TOOK THE STALE THIRTEEN — M23's twelve and M22's one — TO
    // ZERO AS WELL (docs/03 §6ggg). Thirteen bullets held SEVENTEEN items:
    // eight accepted, four to M45, two to M46, two to M47, one to M26.
    //
    // SETS for the owners, count for the total — mis-attribution between two
    // closed milestones preserves the count, and the owner set is what says
    // WHICH programme the debt belongs to. Both are now zero-valued, so
    // NEITHER IS LEFT TO CARRY THIS ALONE; see the control below.
    expect([...new Set(stale.map((r) => String(TAG.exec(r.text)?.[2])))].sort()).toEqual(
      [...STALE_OWNERS].sort(),
    );
    expect(stale.length).toBe(STALE_OWNED);

    // POSITIVE CONTROL — the half that can still fail.
    //
    // A synthetic bullet tagged with a milestone docs/04 REALLY marks
    // `**COMPLETE.**` — taken from the derived set above rather than hard-coded,
    // so it cannot outlive the milestone it names — fed through the SAME
    // predicate the real corpus just used.
    //
    // WHAT THIS ACTUALLY COVERS, measured rather than asserted. An earlier draft
    // of this comment claimed it caught a broken status column or an empty
    // completed set; it does not, and the mutation said so. Both of those are
    // already caught one assertion above by `MIN_COMPLETED_MILESTONES`, which
    // reddens before this line runs. What the control uniquely catches is the
    // PREDICATE going wrong while its inputs stay healthy — `staleAmong`
    // mutated to return `[]` leaves the two expectations above at `[] vs []`
    // and `0 === 0`, and the whole file stays GREEN without this. Demonstrated
    // by the pair: same mutation, control present = 1 failed; control removed =
    // 18 passed.
    const [aCompleted] = [...completed].sort();
    expect(typeof aCompleted).toBe('string');
    expect(
      staleAmong([{ text: `- **[OWNER: ${String(aCompleted)}]** *synthetic.*` }]),
    ).toHaveLength(1);

    // ...and its NEGATIVE twin, because "the predicate fires" is also what a
    // predicate that fires on EVERYTHING does. A live milestone in the same
    // shape must not be flagged.
    const live = OWNERS.find((o) => !completed.has(o));
    expect(typeof live).toBe('string');
    expect(staleAmong([{ text: `- **[OWNER: ${String(live)}]** *synthetic.*` }])).toEqual([]);
  });

  it('no deferral has had its stated precondition SPENT while nobody watched', () => {
    // THE ASSERTION IS THAT THE WORLD HAS NOT MOVED UNDER A RECORDED DECISION.
    // Each entry declares the state measured at M40 PR4 and the fence compares
    // today against it, so the failure names the RESIDUAL rather than the file:
    // whoever just added the consumer is told which decision they retired.
    const observed = PRECONDITIONS.map((p) => {
      const files = PRECONDITIONS.length ? p.corpus.flatMap((d) => sourceFiles(d)) : [];

      // ANTI-VACUITY, PER ENTRY AND NOT JUST IN TOTAL. An empty corpus and an
      // absence that still holds produce the same verdict, and a renamed
      // directory would quietly turn every probe below it into a pass.
      expect({ section: p.section, corpusEmpty: files.length === 0 }).toEqual({
        section: p.section,
        corpusEmpty: false,
      });

      const hits = fillMatches(p, files);
      return { section: p.section, title: p.title, state: hits.length > 0 ? 'filled' : 'absent' };
    });

    expect(observed).toEqual(
      PRECONDITIONS.map((p) => ({ section: p.section, title: p.title, state: p.state })),
    );

    // THE POSITIVE CONTROL, drawn from the real tree rather than synthesised:
    // at least one entry must report FILLED. Without this, a scanner that can
    // only ever answer "absent" — a broken glob, a pattern that cannot match,
    // a `readdirSync` throwing into the empty-array fallback — passes this test
    // exactly as a healthy one does. Same shape as the stale-owner assertion
    // above, and the reason it needed a control too.
    expect(observed.filter((o) => o.state === 'filled').length).toBeGreaterThanOrEqual(1);

    // ...and its NEGATIVE twin: the matcher must be capable of saying "absent"
    // on a corpus that genuinely lacks the pattern, so that "filled" above is a
    // measurement rather than a matcher that fires on everything.
    expect(observed.filter((o) => o.state === 'absent').length).toBeGreaterThanOrEqual(1);
  });

  it('every absence-justified residual is DECLARED — probed, or exempt with a reason', () => {
    // THE COMPLETENESS HALF. A hand-kept registry beside a corpus that grows is
    // this repo's most repeated defect, so the corpus decides membership and the
    // registry only decides what to DO about each member. A new residual written
    // with an absence justification lands here and reddens until someone says
    // which it is.
    const ABSENCE =
      /\b(no consumer|nothing (?:reads|calls|uses|exercises)|does not exist|has no caller|no caller|no reader|read by nothing|not purged by anything|surface that does not exist)\b/i;

    // CLOSED is out of the corpus, and the reason is measured — see the header
    // on PRECONDITIONS. In a CLOSED bullet the absence explains why a FIX was
    // cheap, not why one was DEFERRED, so it cannot be spent in the sense this
    // fence hunts. Three of three false positives in the M40 PR4 sweep were this.
    const deferrals = items.filter((r) => {
      const m = TAG.exec(r.text);
      return m !== null && m[1] !== undefined && !m[1].startsWith('CLOSED');
    });
    expect(deferrals.length).toBeGreaterThan(100);

    const asserting = deferrals.filter((r) => ABSENCE.test(r.text));

    // Anti-vacuity: the pattern must actually select a subset, in both
    // directions. All-or-nothing is what a broken regex produces.
    expect(asserting.length).toBeGreaterThan(0);
    expect(asserting.length).toBeLessThan(deferrals.length);

    const declared = new Set([
      ...PRECONDITIONS.map((p) => p.section),
      ...UNPROBED_ABSENCES.map((u) => u.section),
    ]);
    const undeclared = asserting
      .filter((r) => !declared.has(r.section))
      .map((r) => `docs/03-threat-model.md:${r.line} (§${r.section}) — ${r.text.slice(0, 90)}`);

    expect(undeclared).toEqual([]);

    // Every exemption carries a reason, because an exemption list without them
    // is a skip list wearing a better name.
    expect(UNPROBED_ABSENCES.filter((u) => u.why.trim().length < 40)).toEqual([]);
    expect(PRECONDITIONS.filter((p) => p.why.trim().length < 40)).toEqual([]);
  });

  it('deferred work still exists — the doc has not quietly become all-ACCEPTED', () => {
    // The one way this fence could be satisfied while making things WORSE is a
    // sweep that labels everything ACCEPTED. That is not mechanically
    // distinguishable from honest acceptance, so this asserts the shape of an
    // honest corpus instead: real deferred work is present and owned.
    const owned = items.filter((r) => /^- \*\*\[OWNER: /.test(r.text));
    expect(owned.length).toBeGreaterThanOrEqual(20);
    // And it is spread across owners rather than parked on one.
    const distinct = new Set(owned.map((r) => TAG.exec(r.text)?.[2]));
    expect(distinct.size).toBeGreaterThanOrEqual(5);
  });
});

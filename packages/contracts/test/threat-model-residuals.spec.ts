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
import { readFileSync } from 'node:fs';
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
  'M40',
  'M41', // residual ownership re-sweep (added M27 PR0)
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
  '6b': 4,
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
  '6aa': 7,
  '6bb': 6,
  '6cc': 6,
  '6dd': 6,
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
  '6ww': 3,
  '6xx': 3,
  '6yy': 5,
  '6zz': 7,
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
const MIN_COMPLETED_MILESTONES = 3;
/** Residuals owned by a milestone whose queue row is closed. Declared debt. */
const STALE_OWNED = 13;
const STALE_OWNERS = ['M22', 'M23'];

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
];

/**
 * Bolded lead-ins that MENTION a residual and do not open a region. Each is a
 * sentence about one residual, not a heading over a list — declared here so the
 * classification below is total, on the credential-graph habit of stating
 * exceptions as data rather than letting a regex quietly skip them.
 */
const NON_REGION_LABELS: readonly { readonly label: string; readonly why: string }[] = [
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
    const delta = /^## (6[a-z]{0,2})\./.exec(line);
    if (delta !== null) {
      section = delta[1] as string;
      sections.add(section);
      inBlock = false;
      region = null;
      lead = null;
    } else if (/^## /.test(line)) {
      // A TOP-LEVEL HEADING THAT IS NOT A §6 DELTA ENDS §6, and this parser did
      // not say so. `## 7. Validation program` sits at docs/03:4523, BETWEEN
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
];

const TAG = /^- \*\*\[(ACCEPTED|OWNER: ([A-Z]\d{1,2})|CLOSED: §6[a-z]{0,2})\]\*\*/;

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

  it('a CLOSED residual cites the delta that closed it', () => {
    // "closed" with no citation is the claim-without-a-mechanism shape: it
    // stops the next reader looking and offers them nowhere to look.
    const bad = items
      .filter((r) => /^- \*\*\[CLOSED/.test(r.text))
      .filter((r) => !/^- \*\*\[CLOSED: §6[a-z]{0,2}\]\*\*/.test(r.text))
      .map((r) => `docs/03-threat-model.md:${r.line} is CLOSED without naming a §`);
    expect(bad).toEqual([]);
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
      // `6[a-z]{0,2}` — and this is the occurrence where the one-letter
      // version was not merely mis-attributing but BLIND. `## 6aa.` failed the
      // first test and passed the second (`^## `), so `inSix` went FALSE at
      // §6aa and stayed false: §6aa and §6bb were outside this scan entirely,
      // and a residual lead-in written there with an unrecognised idiom would
      // have been unclassified and unreported. A fence that stops matching goes
      // green, which is the failure this file exists to make loud.
      const heading = /^## (6[a-z]{0,2})\./.exec(line);
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
        return /^## 6[a-z]{0,2}\./.test(lastHeading) ? n + 1 : n;
      }, 0);
    expect(items.length + outside.length).toBe(total);
    expect(total).toBeGreaterThanOrEqual(MIN_SECTION_SIX_BULLETS);
  });

  it('a residual written OUTSIDE §6 is still caught — the §6-boundary repair cut both ways', () => {
    /*
     * THE ONE PLACE M27 PR0 MADE A PRE-EXISTING ASSERTION WEAKER, restored.
     *
     * PR0 taught the parser that a non-§6 `## ` heading ends §6, because
     * `## 7. Validation program` sits at docs/03:4523 — BETWEEN §6hh and §6ii,
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
        const isSix = /^## 6[a-z]{0,2}\./.test(line);
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
    const queueRows = readFileSync(PLAN, 'utf8')
      .split('\n')
      .filter((line) => /^\| M\d{2} \|/.test(line));
    // ANTI-VACUITY on the ROWS, before any status is read from them: a table
    // that moved, or a row format that changed, would otherwise leave every
    // derivation below operating on an empty corpus and passing in silence.
    expect(queueRows.length).toBeGreaterThanOrEqual(MIN_QUEUE_ROWS);

    /*
     * READ THE STATUS, NOT THE ROW — and the first draft of this assertion read
     * the row. `/^\| (M\d{2}) \|.*COMPLETE/` matched the word ANYWHERE in a
     * 400-character cell, so the M40 row went into the completed set the moment
     * it explained that thirteen residuals name milestones "whose docs/04 rows
     * read COMPLETE" — a row describing closed milestones was classified as one.
     * A status is a BOLD RUN in the status cell (`**COMPLETE**`,
     * `**SCOPED ... COMPLETE.**`); prose about other rows is not bold and is not
     * a status. Caught by adding the M40 residual this same fence demanded.
     */
    // The status is the THIRD cell; `| M40 | name | status |` splits to
    // ['', ' M40 ', ' name ', ' status ', ''] and the tail is rejoined so a
    // status containing a pipe cannot silently truncate what is scanned.
    const statusOf = (line: string): string => line.split('|').slice(3).join('|');
    const isComplete = (status: string): boolean =>
      [...status.matchAll(/\*\*([^*]+)\*\*/g)].some((m) => /\bCOMPLETE\b/.test(m[1] as string));
    const completed = new Set(
      queueRows
        .filter((line) => isComplete(statusOf(line)))
        .map((line) => (/^\| (M\d{2}) \|/.exec(line) as RegExpExecArray)[1] as string),
    );
    // ANTI-VACUITY on the STATUSES: a bold-run regex that stopped matching
    // would find no completed milestones and pass just as quietly.
    expect(completed.size).toBeGreaterThanOrEqual(MIN_COMPLETED_MILESTONES);

    const stale = items
      .map((r) => ({ r, m: TAG.exec(r.text) }))
      .filter(({ m }) => m !== null && m[2] !== undefined && completed.has(m[2]));

    // PINNED, NOT ZERO — and the difference is the honest part. Thirty-one
    // residuals name a milestone whose queue row is closed (M21 eighteen, M23
    // twelve, M22 one). Re-owning them means deciding, one at a time, whether a
    // later slice of the same programme still owes the work or whether it
    // closed with the milestone — a sweep, not a line in this PR, and M40 owns
    // it. What ships here is that the number cannot GROW in silence: a residual
    // newly tagged to a shipped milestone, or a milestone marked COMPLETE while
    // residuals still name it, reddens this immediately.
    //
    // SETS for the owners, count for the total — mis-attribution between two
    // closed milestones preserves the count, and the owner set is what says
    // WHICH programme the debt belongs to.
    expect([...new Set(stale.map((x) => String(x.m?.[2])))].sort()).toEqual(
      [...STALE_OWNERS].sort(),
    );
    expect(stale.length).toBe(STALE_OWNED);
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

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
function boldLabel(line: string): string | null {
  const m = /^\*\*(.+?)\*\*/.exec(line);
  return m === null ? null : (m[1] as string);
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
} {
  const lines = readFileSync(DOC, 'utf8').split('\n');
  const blockHeading = (line: string): boolean =>
    /^#{3,4}\s/.test(line) && MENTIONS_RESIDUAL.test(line);
  const residualLanguage =
    /(recorded,? (?:rather than|not) (?:fixed|closed)|accepted residual|residual (?:is|here|accepted|stated|carried)|remains? open|stays open|is not closed|left open|still open|owed by|no (?:self-service|operator) remedy|until TB7|its own milestone|a later milestone|needs its own)/i;
  const items: Residual[] = [];
  const sections = new Set<string>();
  const declared = new Set<string>();
  const regions: Region[] = [];
  let section: string | null = null;
  let inBlock = false;
  let region: Region | null = null;

  /** Open a region, or close the one in force. Both paths run for every line. */
  const setBlock = (open: boolean, line: number, label: string): void => {
    if (region !== null && (!open || region.line !== line)) region = null;
    if (open && section !== null) {
      region = { section, line, label, count: 0 };
      regions.push(region);
    }
  };

  lines.forEach((line, index) => {
    const delta = /^## (6[a-z]?)\./.exec(line);
    if (delta !== null) {
      section = delta[1] as string;
      sections.add(section);
      inBlock = false;
      region = null;
    }
    if (/^#{2,4}\s/.test(line)) {
      inBlock = blockHeading(line);
      setBlock(inBlock, index + 1, line.trim());
      if (inBlock && section !== null) declared.add(section);
    } else if (line.startsWith('**')) {
      // A NEW BOLDED LEAD-IN CLOSES THE BLOCK, and this line is load-bearing.
      // Without it §6a's block runs on and swallows "**§5.2 emergency-access
      // controls, now shipped**" — five bullets describing controls that
      // SHIPPED. Caught only because an independent classification of the
      // corpus disagreed with this parser about two bullets.
      const label = boldLabel(line);
      inBlock = label !== null && REGION_MARKERS.includes(label);
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
      }
    }
  });

  return { items, sections, declared, regions };
}

/** The one tag a bullet may open with. */
const TAG = /^- \*\*\[(ACCEPTED|OWNER: ([A-Z]\d{1,2})|CLOSED: §6[a-z]?)\]\*\*/;

describe('docs/03 §6 — every residual declares a disposition', () => {
  const { items, sections, declared, regions } = residuals();

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
      .filter((r) => !/^- \*\*\[CLOSED: §6[a-z]?\]\*\*/.test(r.text))
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
    let inSix = false;
    const unclassified: string[] = [];
    let seen = 0;
    lines.forEach((line) => {
      if (/^## 6[a-z]?\./.test(line)) inSix = true;
      else if (/^## /.test(line)) inSix = false;
      if (!inSix) return;
      const label = boldLabel(line);
      if (label === null || !MENTIONS_RESIDUAL.test(label)) return;
      seen += 1;
      if (!REGION_MARKERS.includes(label) && !known.has(label)) unclassified.push(label);
    });
    expect(seen).toBeGreaterThanOrEqual(REGION_MARKERS.length);
    expect(unclassified).toEqual([]);
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

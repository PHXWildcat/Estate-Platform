'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type ReactElement } from 'react';
import {
  gqlRequest,
  type AnalysisInfo,
  type FindingInfo,
  type ReadinessInfo,
} from '../graphql/client';
import { findingCopy, sortFindings, STATUS_COPY } from '../lib/findings';
import { ConsentControls } from './ConsentControls';

/**
 * The estate-readiness surface (M10 PR4) — the first consumer of the analysis
 * routes M10 PR3 built for exactly this.
 *
 * NO MODEL IS INVOLVED ON THIS PATH, and that is the point of the whole
 * design. The assistant service computes these findings deterministically from
 * the caller's own estate and returns enum codes; `lib/findings.ts` turns a
 * code into a sentence. So the numbers on this page are arithmetic, they are
 * the same for two users with the same estate, and an instruction hidden in an
 * uploaded document cannot invent one.
 *
 * A NON-OK ANALYSIS NEVER RENDERS AS "NOTHING FOUND". Each of the four cards
 * carries its own status, so one failing check costs its own card and not the
 * page — and a failed or refused check says so in words a person can act on,
 * rather than showing an empty list that reads like a clean bill of health.
 */

interface AnalysisSection {
  readonly key: keyof ReadinessInfo;
  readonly title: string;
  readonly blurb: string;
}

const SECTIONS: readonly AnalysisSection[] = [
  {
    key: 'missingDocuments',
    title: 'Documents',
    blurb: 'Which instruments are on file, and whether they are actually in force.',
  },
  {
    key: 'beneficiaryConflicts',
    title: 'Beneficiaries',
    blurb: 'Designations that do not add up, and assets that pass outside your trust.',
  },
  {
    key: 'funding',
    title: 'Trust funding',
    blurb: 'Assets a trust was meant to hold that are not titled into it.',
  },
  {
    key: 'estateTax',
    title: 'Estate tax',
    blurb: 'A gross estimate against federal and state thresholds.',
  },
];

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; readiness: ReadinessInfo; consents: string[] };

const SEVERITY_CHIP: Record<FindingInfo['severity'], string> = {
  high: 'chip chip-warn',
  medium: 'chip',
  info: 'chip chip-trust',
};

const SEVERITY_LABEL: Record<FindingInfo['severity'], string> = {
  high: 'Needs attention',
  medium: 'Worth a look',
  info: 'For information',
};

/** Uppercase micro-label, matching the assets surface. */
const STAT_LABEL = 'text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-ink-muted';

function FindingRow({ finding }: { finding: FindingInfo }): ReactElement {
  const copy = findingCopy(finding);
  // A finding about a SPECIFIC asset links to the place the owner can act on
  // it (M19 PR3 — the incoherence this milestone closes, closed literally):
  // the readiness page said "no beneficiary designated" for years about
  // designations the product offered no way to create.
  const assetHref =
    finding.subject.kind === 'asset' && finding.subject.ref !== null
      ? `/assets/${encodeURIComponent(finding.subject.ref)}`
      : null;
  return (
    <li className="border-b border-line py-3 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="text-sm font-medium">
          {assetHref !== null ? (
            <Link className="hover:underline" href={assetHref}>
              {copy.title}
            </Link>
          ) : (
            copy.title
          )}
        </p>
        <span className={SEVERITY_CHIP[finding.severity]}>{SEVERITY_LABEL[finding.severity]}</span>
      </div>
      <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">{copy.body}</p>
    </li>
  );
}

function AnalysisCard({
  section,
  analysis,
}: {
  section: AnalysisSection;
  analysis: AnalysisInfo;
}): ReactElement {
  const headingId = `analysis-${section.key}`;
  const attention = analysis.findings.filter((finding) => finding.severity === 'high').length;
  return (
    <section aria-labelledby={headingId} className="card p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id={headingId} className="text-base font-semibold">
            {section.title}
          </h2>
          <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">{section.blurb}</p>
        </div>
        {analysis.status === 'OK' && attention > 0 ? (
          <span className="chip chip-warn">
            {attention} {attention === 1 ? 'item' : 'items'}
          </span>
        ) : null}
      </div>

      {analysis.status === 'OK' ? (
        <ul className="mt-3">
          {sortFindings(analysis.findings).map((finding, index) => (
            // The INDEX is part of the key, and it has to be: an estate-level
            // finding carries no subject ref, and the commonest analysis in the
            // product emits several of one code that way — "no guardian
            // designation on file" and "no HIPAA authorization on file" are both
            // `instrument_missing` about no particular row. Keying on
            // code+ref alone collided, and React's remedy for a duplicate key is
            // to drop or duplicate a child: a finding about someone's estate
            // would have silently vanished from the page. Found by rendering the
            // real app, invisible to every unit test.
            <FindingRow
              key={`${finding.code}:${finding.subject.ref ?? 'estate'}:${index}`}
              finding={finding}
            />
          ))}
        </ul>
      ) : (
        // Every non-OK status says what happened in words. An empty list here
        // would read as "nothing wrong", which is the one thing it never means.
        <div className="mt-3 border-t border-line pt-3" role="status">
          <p className="text-sm font-medium">{STATUS_COPY[analysis.status].title}</p>
          <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
            {STATUS_COPY[analysis.status].body}
          </p>
        </div>
      )}
    </section>
  );
}

export function ReadinessPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  const load = useCallback(async (): Promise<void> => {
    const [readiness, consents] = await Promise.all([
      gqlRequest('Readiness', {}),
      gqlRequest('Consents', {}),
    ]);
    // A MISSING FIELD IS NO DATA (M11). `gqlRequest` answers ok for any `data`
    // object, so a BFF predating either query arrives as `{"data":{}}` and
    // these dereferences hand `undefined` to a renderer that maps over it —
    // a white screen, which is what this shape did in M11, M12 and M15 before
    // each was fixed in turn. An absent field reads as an outage, never as an
    // empty estate.
    if (readiness.ok && consents.ok) {
      const cards = readiness.data.readiness;
      const grants = consents.data.consents;
      if (cards === undefined || grants === undefined) {
        setState({ kind: 'error' });
        return;
      }
      setState({ kind: 'ready', readiness: cards, consents: grants });
      return;
    }
    const code = !readiness.ok ? readiness.code : !consents.ok ? consents.code : 'UNKNOWN';
    setState(code === 'UNAUTHENTICATED' ? { kind: 'signedOut' } : { kind: 'error' });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Checking your estate…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t run these checks. Please try again in a moment — this is not a statement about
          your estate.
        </p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">
          These checks run over your own estate. Sign in to see them.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
          <Link className="btn btn-secondary" href="/register">
            Create account
          </Link>
        </div>
      </div>
    );
  }

  const { readiness, consents } = state;
  const analyses = SECTIONS.map((section) => ({ section, analysis: readiness[section.key] }));
  const needsAttention = analyses.reduce(
    (total, { analysis }) =>
      total +
      (analysis.status === 'OK'
        ? analysis.findings.filter((finding) => finding.severity === 'high').length
        : 0),
    0,
  );
  // The watermark comes from the SERVER's payload, not from a string in this
  // app: docs/01 §2.8 makes it the platform's statement, and a copy here would
  // drift from it silently. Every status carries one, so the first is enough.
  const disclaimer = analyses[0]?.analysis.disclaimer ?? '';

  return (
    <div className="space-y-4">
      <section aria-label="Summary" className="card p-5">
        <h2 className={STAT_LABEL}>Needs attention</h2>
        <p className="mt-1.5 text-4xl font-semibold tabular-nums tracking-tight">
          {needsAttention}
        </p>
        <p className="mt-1.5 text-[0.8125rem] text-ink-muted">
          {needsAttention === 0
            ? 'Nothing urgent in the checks that ran.'
            : 'Items below with a real consequence today.'}
        </p>
      </section>

      {/* Adjacent to the findings, never behind a disclosure control. */}
      <p className="max-w-prose text-[0.8125rem] text-ink-muted">{disclaimer}</p>

      <div className="grid gap-4 lg:grid-cols-2">
        {analyses.map(({ section, analysis }) => (
          <AnalysisCard key={section.key} section={section} analysis={analysis} />
        ))}
      </div>

      <ConsentControls
        granted={consents}
        onChanged={(granted) => {
          setState({ ...state, consents: granted });
          // A consent change changes what the analysers may read, so the
          // findings are re-fetched rather than left stale behind a new grant.
          void load();
        }}
      />
    </div>
  );
}

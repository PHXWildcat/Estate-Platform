'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';
import {
  gqlRequest,
  type AnalysisInfo,
  type AssetInfo,
  type DocumentInfo,
  type LiveSessionInfo,
  type NetWorthInfo,
  type PasskeyInfo,
  type ReadinessInfo,
  type SessionInfo,
} from '../graphql/client';
import { useSharedRead } from '../graphql/read-cache';
import { categoryLabel, INSURANCE_CATEGORIES } from '../lib/categories';
import { documentsSummaryLine, inForceCount } from '../lib/documents';
import { SECTIONS } from '../lib/findings';
import { trustFundingPct } from '../lib/funding';
import { formatMoney } from '../lib/money';
import { formatPct } from '../lib/percent';
import { STAT_LABEL } from '../lib/stat';
import { SettlingEstatesPanel } from './SettlingEstatesPanel';

/**
 * The dashboard (M24 PR3) — the home page, made of the platform's own numbers.
 *
 * Every tile consumes an operation an existing page already uses; nothing here
 * asked for a new SDL field (`dashboard-computability.spec.ts` in the BFF pins
 * which backings exist, and docs/04 M24 pins which of them are IN). Three
 * design rules govern the whole file:
 *
 * 1. A FAILED READ MUST NOT RENDER AS ZERO. Each tile carries its own
 *    loading / error / empty arms, and the error arm is an explicit
 *    non-statement — a $0 net worth on a failed read would be "we could not
 *    ask" wearing "nothing is here"'s face. Dollar figures render only when a
 *    successful read carried one.
 * 2. AUDITED-DECRYPT VOLUME IS A UI CONSTRAINT. The mount-time reads are the
 *    /assets page's own shape (Assets + NetWorth — the sanctioned per-row
 *    est_value decrypts) plus decrypt-free reads (Documents, Session,
 *    Sessions, Passkeys, and the cache-shared EmailVerification). The
 *    readiness analyses are NOT read on mount: one `Readiness` ask runs four
 *    analysers server-side — per-row asset decrypts times four, two full
 *    profile PII reads, a family read — so the estate-checks card runs them
 *    only when the owner asks, exactly once per press.
 * 3. ONE READ, MANY TILES. The page fetches each operation once and passes
 *    results down as props; tiles are presentational. The shared read cache is
 *    used only where a fact is already shared with the app shell
 *    (EmailVerification — the banner and this page's security tile are the two
 *    designed-for subscribers). Nothing new enrolls: Assets is parameterized,
 *    NetWorth and Readiness are decrypt-backed, and Session's step-up
 *    freshness decays by clock — each fails the cache's own written bar.
 *
 * The session read GATES the rest: signed-out visitors get the product hero
 * and a get-started card, and none of the tile reads fire at all. The ONE
 * query a signed-out landing still issues is SettlingEstatesPanel's
 * decrypt-free ExecutorCases probe — its M23 self-hiding design, kept
 * verbatim, which answers a refusal and renders nothing. A tile read that
 * answers UNAUTHENTICATED after the gate passed collapses the page back to
 * the signed-out arm (one mechanism — see the escalation in the loaders).
 */

type Gate =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'signedIn'; session: SessionInfo };

/** One tile read. An error is an ANSWER — rendered, never defaulted to zero. */
type TileRead<T> =
  { kind: 'loading' } | { kind: 'error'; code: string } | { kind: 'ready'; data: T };

type ChecksState =
  | { kind: 'idle' }
  | { kind: 'running' }
  | { kind: 'error'; code: string }
  | { kind: 'ready'; readiness: ReadinessInfo };

/** M11 shape guard: a version-skewed peer's `{"data":{}}` must not destructure. */
function isReadiness(value: ReadinessInfo | undefined): value is ReadinessInfo {
  const record = value as Record<string, { status?: unknown } | undefined> | undefined;
  return (['funding', 'missingDocuments', 'beneficiaryConflicts', 'estateTax'] as const).every(
    (key) => typeof record?.[key]?.status === 'string',
  );
}

export function Dashboard(): ReactElement {
  const [gate, setGate] = useState<Gate>({ kind: 'loading' });
  const [netWorth, setNetWorth] = useState<TileRead<NetWorthInfo>>({ kind: 'loading' });
  const [assets, setAssets] = useState<TileRead<AssetInfo[]>>({ kind: 'loading' });
  const [documents, setDocuments] = useState<TileRead<DocumentInfo[]>>({ kind: 'loading' });
  const [liveSessions, setLiveSessions] = useState<TileRead<LiveSessionInfo[]>>({
    kind: 'loading',
  });
  const [passkeys, setPasskeys] = useState<TileRead<PasskeyInfo[]>>({ kind: 'loading' });
  const [checks, setChecks] = useState<ChecksState>({ kind: 'idle' });
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await gqlRequest('Session', {});
      if (cancelled) return;
      // The wire type says `session` is non-null; the SDL says nullable. Trust
      // the SDL: null is "no credentials at all", the signed-out answer.
      if (result.ok && result.data.session !== null) {
        setGate({ kind: 'signedIn', session: result.data.session });
      } else if (result.ok || result.code === 'UNAUTHENTICATED') {
        setGate({ kind: 'signedOut' });
      } else {
        setGate({ kind: 'error' });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const signedIn = gate.kind === 'signedIn';
  useEffect(() => {
    if (!signedIn) return;
    let cancelled = false;
    /**
     * A surviving UNAUTHENTICATED (the client's silent refresh already
     * retried) means the SESSION is gone, not the backing — so it collapses
     * the whole page to the signed-out arm instead of landing in one tile.
     * ONE mechanism: the alternative — each tile wording its own session-end
     * sentence — was the review's "rule half-applied" finding, with three
     * surfaces saying "sign in" while three others wore an outage's face.
     */
    const escalate = (code: string): boolean => {
      if (code !== 'UNAUTHENTICATED') return false;
      setGate({ kind: 'signedOut' });
      return true;
    };
    // Concurrent, and each lands in its own state: one backing failing costs
    // its own tile, never the page.
    void gqlRequest('NetWorth', {}).then((result) => {
      if (cancelled) return;
      if (result.ok && typeof result.data.netWorth?.totalValue === 'string') {
        setNetWorth({ kind: 'ready', data: result.data.netWorth });
      } else if (!escalate(result.ok ? '' : result.code)) {
        setNetWorth({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
      }
    });
    void gqlRequest('Assets', {}).then((result) => {
      if (cancelled) return;
      if (result.ok && Array.isArray(result.data.assets)) {
        setAssets({ kind: 'ready', data: result.data.assets });
      } else if (!escalate(result.ok ? '' : result.code)) {
        setAssets({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
      }
    });
    void gqlRequest('Documents', {}).then((result) => {
      if (cancelled) return;
      if (result.ok && Array.isArray(result.data.documents)) {
        setDocuments({ kind: 'ready', data: result.data.documents });
      } else if (!escalate(result.ok ? '' : result.code)) {
        setDocuments({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
      }
    });
    void gqlRequest('Sessions', {}).then((result) => {
      if (cancelled) return;
      if (result.ok && Array.isArray(result.data.sessions)) {
        setLiveSessions({ kind: 'ready', data: result.data.sessions });
      } else if (!escalate(result.ok ? '' : result.code)) {
        setLiveSessions({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
      }
    });
    void gqlRequest('Passkeys', {}).then((result) => {
      if (cancelled) return;
      if (result.ok && Array.isArray(result.data.passkeys)) {
        setPasskeys({ kind: 'ready', data: result.data.passkeys });
      } else if (!escalate(result.ok ? '' : result.code)) {
        setPasskeys({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [signedIn]);

  const runChecks = useCallback(async (): Promise<void> => {
    setChecks({ kind: 'running' });
    const result = await gqlRequest('Readiness', {});
    if (!mounted.current) return;
    if (result.ok && isReadiness(result.data.readiness)) {
      setChecks({ kind: 'ready', readiness: result.data.readiness });
    } else if (!result.ok && result.code === 'UNAUTHENTICATED') {
      // Same escalation as the tile reads: a dead session is the page's
      // fact, not this card's.
      setGate({ kind: 'signedOut' });
    } else {
      setChecks({ kind: 'error', code: result.ok ? 'UNKNOWN' : result.code });
    }
  }, []);

  if (gate.kind === 'signedOut') {
    return (
      <div className="space-y-10">
        <section>
          <h1 className="text-3xl font-semibold tracking-tight">
            Your estate, in order. Your wishes, protected.
          </h1>
          <p className="mt-3 max-w-prose text-ink-muted">
            Estate keeps your plans, documents, and beneficiaries organized — with security designed
            for the things that matter most. Everything sensitive is encrypted, every access is
            audited, and the most private items only you can unlock.
          </p>
        </section>
        {/*
          M23 PR2, kept through the M24 PR3 restructure: ABOVE the account
          content and SELF-HIDING — it renders nothing at all unless settlement
          returns an estate this person is settling. An executor arrives here
          days after a death and should not have to hunt; everybody else never
          learns the panel exists.
        */}
        <SettlingEstatesPanel />
        <div className="card p-6">
          <h2 className="text-lg font-semibold">Get started</h2>
          <p className="mt-2 max-w-prose text-sm text-ink-muted">
            Create an account to begin organizing your estate, or sign in to pick up where you left
            off.
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link className="btn btn-primary" href="/register">
              Create account
            </Link>
            <Link className="btn btn-secondary" href="/login">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-10">
      <section>
        <h1 className="text-3xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-3 max-w-prose text-ink-muted">Your estate at a glance.</p>
      </section>
      {/* Same placement rule as the signed-out arm — see the comment there. */}
      <SettlingEstatesPanel />
      {gate.kind === 'loading' ? (
        <div className="card p-6" role="status">
          <p className="text-sm text-ink-muted">Checking your session…</p>
        </div>
      ) : gate.kind === 'error' ? (
        <div className="card p-6" role="status">
          <p className="text-sm text-ink-muted">
            We couldn’t check your session right now. You can still{' '}
            <Link className="text-accent underline underline-offset-2" href="/login">
              sign in
            </Link>
            .
          </p>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <EstateTile netWorth={netWorth} assets={assets} />
          <FundingTile netWorth={netWorth} />
          <DocumentsTile documents={documents} />
          {/* The two-column span sits before the one remaining single card so
              the grid's rag falls at its end, not mid-page. */}
          <ChecksCard checks={checks} onRun={runChecks} />
          <SecurityTile session={gate.session} sessions={liveSessions} passkeys={passkeys} />
        </div>
      )}
    </div>
  );
}

/**
 * The error arm every tile shares: an explicit non-statement. This arm never
 * has to word a session-end — a surviving UNAUTHENTICATED collapses the whole
 * page to the signed-out arm before any tile renders it (the escalation in
 * the loaders), so what reaches here is genuinely "we could not ask".
 */
function TileError({ subject }: { subject: string }): ReactElement {
  return (
    <p className="mt-1.5 text-sm text-ink-muted" role="status">
      We couldn’t load {subject} just now. This is not a statement about your estate — try again in
      a moment.
    </p>
  );
}

function StatFigure({ children }: { children: string }): ReactElement {
  return <p className="mt-1.5 text-4xl font-semibold tabular-nums tracking-tight">{children}</p>;
}

function StatCaption({ children }: { children: string }): ReactElement {
  return <p className="mt-1.5 text-[0.8125rem] text-ink-muted">{children}</p>;
}

function Loading(): ReactElement {
  return (
    <p className="mt-1.5 text-sm text-ink-muted" role="status">
      Loading…
    </p>
  );
}

/**
 * Net worth, inventory, and the insurance facet — docs/04 M24 scopes insurance
 * as "a facet of the assets/net-worth tile": three asset CATEGORIES counted,
 * never a client-side money sum (summing shares would re-implement the
 * service's `ownedShareCents` in the browser — a second copy of a money
 * guard).
 */
function EstateTile({
  netWorth,
  assets,
}: {
  netWorth: TileRead<NetWorthInfo>;
  assets: TileRead<AssetInfo[]>;
}): ReactElement {
  return (
    <section aria-label="Estate" className="card p-5 lg:col-span-2">
      <div className="flex flex-col gap-4 sm:flex-row">
        <div className="flex-[1.6]">
          <h2 className={STAT_LABEL}>Net worth</h2>
          {netWorth.kind === 'loading' ? (
            <Loading />
          ) : netWorth.kind === 'error' ? (
            <TileError subject="your net worth" />
          ) : netWorth.data.assetCount === 0 ? (
            <>
              <StatFigure>—</StatFigure>
              <StatCaption>Nothing recorded yet.</StatCaption>
            </>
          ) : netWorth.data.valuedAssetCount === 0 ? (
            // A true "$0.00" here would be a lie of omission: the estate has
            // assets, none of which has a recorded value.
            <>
              <StatFigure>—</StatFigure>
              <StatCaption>
                {`None of your ${netWorth.data.assetCount} assets has a recorded value yet.`}
              </StatCaption>
            </>
          ) : (
            <>
              <StatFigure>{formatMoney(netWorth.data.totalValue)}</StatFigure>
              <StatCaption>
                {`${netWorth.data.valuedAssetCount} of ${netWorth.data.assetCount} ${
                  netWorth.data.assetCount === 1 ? 'asset' : 'assets'
                } valued`}
              </StatCaption>
            </>
          )}
        </div>
        <div className="flex-1">
          <h2 className={STAT_LABEL}>Assets</h2>
          {netWorth.kind === 'loading' ? (
            <Loading />
          ) : netWorth.kind === 'error' ? (
            <TileError subject="your asset count" />
          ) : (
            <>
              <StatFigure>{String(netWorth.data.assetCount)}</StatFigure>
              <StatCaption>
                {netWorth.data.assetCount === 0
                  ? 'Add your first asset to begin.'
                  : netWorth.data.assetCount - netWorth.data.valuedAssetCount === 0
                    ? 'All valued'
                    : `${netWorth.data.assetCount - netWorth.data.valuedAssetCount} ${
                        netWorth.data.assetCount - netWorth.data.valuedAssetCount === 1
                          ? 'asset'
                          : 'assets'
                      } unvalued`}
              </StatCaption>
            </>
          )}
        </div>
      </div>
      <div className="mt-4 border-t border-line pt-3">
        <h3 className={STAT_LABEL}>Insurance</h3>
        {assets.kind === 'loading' ? (
          <Loading />
        ) : assets.kind === 'error' ? (
          <TileError subject="your insurance summary" />
        ) : (
          <p className="mt-1.5 text-[0.8125rem] text-ink-muted">{insuranceLine(assets.data)}</p>
        )}
      </div>
      <Link className="btn btn-secondary mt-4" href="/assets">
        View assets
      </Link>
    </section>
  );
}

/** Counts per insurance category, as one plain sentence. */
function insuranceLine(assets: readonly AssetInfo[]): string {
  const present = INSURANCE_CATEGORIES.map((category) => ({
    category,
    count: assets.filter((asset) => asset.category === category).length,
  })).filter((entry) => entry.count > 0);
  if (present.length === 0) {
    return 'None recorded. Life insurance, long-term-care insurance and annuities are tracked as assets.';
  }
  return `On file: ${present
    .map((entry) => `${categoryLabel(entry.category)} (${entry.count})`)
    .join(', ')}.`;
}

function FundingTile({ netWorth }: { netWorth: TileRead<NetWorthInfo> }): ReactElement {
  return (
    <section aria-label="Trust funding" className="card p-5">
      <h2 className={STAT_LABEL}>Trust funding</h2>
      {netWorth.kind === 'loading' ? (
        <Loading />
      ) : netWorth.kind === 'error' ? (
        <TileError subject="your trust funding" />
      ) : (
        <FundingFigure netWorth={netWorth.data} />
      )}
    </section>
  );
}

function FundingFigure({ netWorth }: { netWorth: NetWorthInfo }): ReactElement {
  const pct = trustFundingPct(netWorth.inTrustValue, netWorth.totalValue);
  if (pct === null) {
    // The service answers null here too: a percentage of a zero-value estate
    // is not 0%, it is no answer.
    return (
      <>
        <StatFigure>—</StatFigure>
        <StatCaption>No valued estate to measure yet.</StatCaption>
      </>
    );
  }
  return (
    <>
      <StatFigure>{`${formatPct(pct)}%`}</StatFigure>
      <StatCaption>
        {`${formatMoney(netWorth.inTrustValue)} of ${formatMoney(netWorth.totalValue)} held in trust`}
      </StatCaption>
    </>
  );
}

function DocumentsTile({ documents }: { documents: TileRead<DocumentInfo[]> }): ReactElement {
  return (
    <section aria-label="Documents" className="card p-5">
      <h2 className={STAT_LABEL}>Documents in force</h2>
      {documents.kind === 'loading' ? (
        <Loading />
      ) : documents.kind === 'error' ? (
        <TileError subject="your documents" />
      ) : (
        <DocumentsFigure documents={documents.data} />
      )}
      <Link className="btn btn-secondary mt-4" href="/documents">
        View documents
      </Link>
    </section>
  );
}

function DocumentsFigure({ documents }: { documents: readonly DocumentInfo[] }): ReactElement {
  if (documents.length === 0) {
    return (
      <>
        <StatFigure>—</StatFigure>
        <StatCaption>Nothing on file yet.</StatCaption>
      </>
    );
  }
  // Completion over EVERY document on file — the /documents page's own
  // denominator (see lib/documents.ts inForceCount) so the two surfaces can
  // never disagree. A computed number goes through the formatter.
  const inForce = inForceCount(documents);
  return (
    <>
      <StatFigure>{`${formatPct((inForce / documents.length) * 100)}%`}</StatFigure>
      <StatCaption>{documentsSummaryLine(documents, inForce)}</StatCaption>
    </>
  );
}

/**
 * Security facts, never a score (docs/04 M24: "no invented scores"). The
 * session facts arrive as props from the page's own gate read;
 * EmailVerification is subscribed through the shared read cache — the
 * designed-for second subscriber beside the app-shell banner, one identity
 * round trip between them.
 */
function SecurityTile({
  session,
  sessions,
  passkeys,
}: {
  session: SessionInfo;
  sessions: TileRead<LiveSessionInfo[]>;
  passkeys: TileRead<PasskeyInfo[]>;
}): ReactElement {
  const emailVerification = useSharedRead('EmailVerification');
  return (
    <section aria-label="Security" className="card p-5">
      <h2 className={STAT_LABEL}>Security</h2>
      <div className="mt-2 flex flex-wrap gap-2">
        {/* mfaLevel is the SESSION's factor level, not account enrollment —
            SessionCard's old "MFA not enrolled" wording was falsified the
            first time the M24 PR3 drive signed a TOTP-enrolled account in
            with password only. Say what the value actually measures. */}
        {session.mfaLevel === 'NONE' ? (
          <span className="chip chip-warn">Password-only session</span>
        ) : (
          <span className="chip chip-success">Second factor verified</span>
        )}
        {session.stepUpFresh ? (
          <span className="chip chip-success">Step-up fresh</span>
        ) : (
          <span className="chip">Step-up not fresh</span>
        )}
      </div>
      <ul className="mt-3 space-y-1 text-[0.8125rem] text-ink-muted">
        <li>
          {passkeys.kind === 'loading'
            ? 'Passkeys: checking…'
            : passkeys.kind === 'error'
              ? 'Passkeys: could not load just now'
              : passkeys.data.length === 0
                ? 'Passkeys: none yet'
                : `Passkeys: ${passkeys.data.length}`}
        </li>
        <li>
          {/* A failed read must never imply "nothing else can reach your
              account" — the count is withheld, not defaulted. */}
          {sessions.kind === 'loading'
            ? 'Active sessions: checking…'
            : sessions.kind === 'error'
              ? 'Active sessions: could not load just now'
              : `Active sessions: ${sessions.data.length}`}
        </li>
        <li>
          {/* UNAVAILABLE is a fact about the platform, never rendered as
              "unverified" — the M14 rule, kept. */}
          {emailVerification === null
            ? 'Email: checking…'
            : !emailVerification.ok
              ? 'Email: verification could not be checked just now'
              : emailVerification.data.emailVerification === 'VERIFIED'
                ? 'Email address verified'
                : emailVerification.data.emailVerification === 'UNVERIFIED'
                  ? 'Email address not verified yet'
                  : 'Email: verification could not be checked just now'}
        </li>
      </ul>
      <Link className="btn btn-secondary mt-4" href="/security">
        Manage security
      </Link>
    </section>
  );
}

/**
 * The estate checks — `Query.readiness`, run ON DEMAND. One press runs the
 * four analyses once and renders all four statuses in an always-mounted
 * polite region. The M24 PR2 lesson has TWO halves and both are here: the
 * region announces without stealing focus, AND focus is moved onto the
 * landing outcome — because merely keeping the button mounted is not enough:
 * a natively `disabled` control blurs to `<body>` the moment the attribute
 * lands (this PR's review demonstrated it live), so the button uses
 * `aria-disabled` plus a handler guard instead, and the run's landing pulls
 * focus to the outcome region.
 */
function ChecksCard({
  checks,
  onRun,
}: {
  checks: ChecksState;
  onRun: () => Promise<void>;
}): ReactElement {
  const outcomeRef = useRef<HTMLDivElement | null>(null);
  const priorKind = useRef(checks.kind);
  useEffect(() => {
    const wasRunning = priorKind.current === 'running';
    priorKind.current = checks.kind;
    // Only the running→outcome transition moves focus — a press the user is
    // still deciding about must not have its focus stolen.
    if (wasRunning && (checks.kind === 'ready' || checks.kind === 'error')) {
      outcomeRef.current?.focus();
    }
  }, [checks.kind]);
  return (
    <section aria-labelledby="estate-checks-heading" className="card p-5 sm:p-6 lg:col-span-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="estate-checks-heading" className="text-base font-semibold">
            Estate checks
          </h2>
          <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
            The four readiness analyses — documents, beneficiaries, trust funding and estate tax —
            computed fresh from your own records each time. They run when you ask: each run reads
            your assets, documents and profile, and every sensitive read lands on your audit trail.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          aria-disabled={checks.kind === 'running'}
          onClick={() => {
            if (checks.kind === 'running') return;
            void onRun();
          }}
        >
          {checks.kind === 'idle'
            ? 'Run the checks'
            : checks.kind === 'running'
              ? 'Running…'
              : 'Run again'}
        </button>
      </div>
      <div aria-live="polite" className="mt-3" ref={outcomeRef} role="status" tabIndex={-1}>
        {checks.kind === 'running' ? (
          <p className="text-sm text-ink-muted">Running the four analyses…</p>
        ) : null}
        {checks.kind === 'error' ? (
          <p className="max-w-prose text-sm text-ink-muted">
            We couldn’t run these checks. Please try again in a moment — this is not a statement
            about your estate.
          </p>
        ) : null}
        {checks.kind === 'ready' ? <ChecksResults readiness={checks.readiness} /> : null}
      </div>
    </section>
  );
}

function ChecksResults({ readiness }: { readiness: ReadinessInfo }): ReactElement {
  const disabled = SECTIONS.some((section) => readiness[section.key].status === 'DISABLED');
  return (
    <div>
      <ul className="border-t border-line">
        {SECTIONS.map((section) => (
          <li
            key={section.key}
            className="flex items-center justify-between gap-3 border-b border-line py-2"
          >
            <span className="text-sm font-medium">{section.title}</span>
            <AnalysisChip analysis={readiness[section.key]} />
          </li>
        ))}
      </ul>
      {disabled ? (
        <p className="mt-3 max-w-prose text-[0.8125rem] text-ink-muted">
          The assistant is switched off — nothing is analysed while it is off. You can turn it on
          from the{' '}
          <Link className="text-accent underline underline-offset-2" href="/assistant">
            assistant page
          </Link>
          .
        </p>
      ) : (
        <p className="mt-3">
          <Link className="text-sm underline underline-offset-2" href="/assistant">
            Open the assistant for the full findings
          </Link>
        </p>
      )}
      {/* The non-legal-advice watermark is the SERVER's sentence, never an
          app string; it is the same string on all four analyses. */}
      <p className="mt-3 max-w-prose text-[0.6875rem] text-ink-muted">
        {readiness.funding.disclaimer}
      </p>
    </div>
  );
}

/**
 * A status in words. `OK` with findings is counted, never summarised away;
 * every non-OK status names itself — an empty or green chip on a check that
 * did not run would be a clean bill of health nobody issued.
 */
function AnalysisChip({ analysis }: { analysis: AnalysisInfo }): ReactElement {
  if (analysis.status === 'OK') {
    const attention = analysis.findings.filter((finding) => finding.severity === 'high').length;
    if (attention > 0) {
      return (
        <span className="chip chip-warn">
          {attention} {attention === 1 ? 'item needs' : 'items need'} attention
        </span>
      );
    }
    if (analysis.findings.length > 0) {
      return (
        <span className="chip">
          {analysis.findings.length} {analysis.findings.length === 1 ? 'note' : 'notes'}
        </span>
      );
    }
    return <span className="chip chip-success">Nothing found</span>;
  }
  if (analysis.status === 'UNAVAILABLE') {
    return <span className="chip">Could not run</span>;
  }
  if (analysis.status === 'REFUSED') {
    return <span className="chip">Not published here</span>;
  }
  if (analysis.status === 'DISABLED') {
    return <span className="chip">Assistant off</span>;
  }
  // A status this build has no words for (a server deployed ahead of this
  // app) — the lib/findings unknown-code rule: a neutral honest fallback,
  // never the most specific claim in the union.
  return <span className="chip">Unknown status</span>;
}

import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { SettlementCases } from '../../../../components/SettlementCases';

export const metadata: Metadata = { title: 'Estate settlement' };

/**
 * The owner's settlement surface (M22 PR3).
 *
 * A ROUTE OF ITS OWN, AND DELIBERATELY NOT IN `AppNav`. The operator
 * interstitial set the precedent for an unlisted page, but the reason here is
 * different and worth stating: this surface is EMPTY for virtually everybody,
 * and a permanent navigation item reading "Death cases" in an estate app is a
 * standing memento mori for ten million people who will never have one. So it
 * is reached the way the fact itself arrives — contextually, through the
 * app-shell banner that appears only while a case naming you is open, and
 * through a pointer on /security for anyone who comes looking unprompted.
 *
 * It sits under /security rather than at the top level because that is where
 * the protections on an account already live, and because the waiting period —
 * the other half of this control — is on the /security page itself.
 */
export default function SettlementCasesPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Estate settlement</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        If someone reports you as deceased, we open a case and tell you before anything is released.
        You can close it yourself, immediately, at any point before it completes.{' '}
        <Link href="/security" className="font-medium text-ink underline underline-offset-4">
          The waiting period is on your security page
        </Link>
        .
      </p>
      <SettlementCases />
    </div>
  );
}

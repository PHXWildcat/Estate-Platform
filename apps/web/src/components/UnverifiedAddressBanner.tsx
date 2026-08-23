'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactElement } from 'react';
import { useSharedRead } from '../graphql/read-cache';

/**
 * A quiet, app-wide reminder that the platform cannot yet PROVE it reaches you.
 *
 * WHY IT IS APP-WIDE. An unverified address is not cosmetic: since M14 PR2 it
 * silently withholds capabilities. An owner who tries to arm emergency access
 * or invite a contact will be refused, and the refusal arrives at a moment that
 * explains nothing about why. This banner is what makes the cause visible
 * BEFORE the effect, which is the difference between a control and a bug
 * report.
 *
 * WHAT IT DELIBERATELY IS NOT: a blocker, a modal, or a nag with a dismiss
 * button that hides a real gap. It is one line with a link, on every page of
 * the app, until the thing it describes is true.
 *
 * IT RENDERS NOTHING ON UNAVAILABLE OR ON ERROR. `UNAVAILABLE` is a fact about
 * the platform, not about the user — telling somebody to go and confirm an
 * address during a notifications outage sends them to a ceremony that cannot
 * run. Staying silent is the honest failure mode here, because the settings
 * page says the same thing properly when they get there. This is the one place
 * in the milestone where the fail-closed direction is to say LESS.
 *
 * ONE QUERY PER NAVIGATION, and no polling — unchanged, now THROUGH the shared
 * read cache (M24 PR1): the pathname is the revalidate key, so the server is
 * asked exactly as often as before. What the cache adds is the ending of the
 * §6v staleness residual — when either vouching ceremony completes
 * (`VerifyEmail`, `CompleteEmailChange`), the transport's own announcement
 * invalidates this read and the banner re-asks WITHOUT waiting for a
 * navigation. The read still costs identity a notifications round trip, which
 * is why it stays off the session resolver that backs every authenticated
 * request (see the BFF schema).
 */
export function UnverifiedAddressBanner(): ReactElement | null {
  const pathname = usePathname();
  const result = useSharedRead('EmailVerification', { revalidateKey: pathname });

  // Only the one state that is actionable. Signed-out callers get
  // UNAUTHENTICATED here, which is not a state this banner has an opinion
  // about — the app shell already handles that. And null is NOTHING YET, not
  // an answer: the banner stays down rather than guessing.
  const unverified = result !== null && result.ok && result.data.emailVerification === 'UNVERIFIED';

  if (!unverified) {
    return null;
  }

  return (
    <div className="border-b border-line bg-sunken">
      <p className="mx-auto w-full max-w-4xl px-6 py-2.5 text-sm text-ink-muted lg:px-10">
        Your email address isn’t confirmed, so we can’t warn you if someone tries to open your
        estate.{' '}
        <Link href="/security" className="font-medium text-ink underline underline-offset-4">
          Confirm it now
        </Link>
      </p>
    </div>
  );
}

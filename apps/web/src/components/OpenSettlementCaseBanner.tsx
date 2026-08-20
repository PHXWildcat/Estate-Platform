'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { isOpen } from '../lib/settlement';

/**
 * SOMEONE HAS REPORTED YOU AS DECEASED, and you are reading this, so they are
 * wrong (M22 PR3).
 *
 * THIS BANNER IS WHY THE SURFACE NEEDS NO NAV ENTRY. A permanent "Death cases"
 * item would be a standing memento mori on every page for ten million people
 * who will never have a case — while the people who DO have one need to find it
 * within seconds, on whatever page they happen to be on. An app-wide line that
 * appears only when the fact is true serves the second group without taxing the
 * first, which is the `UnverifiedAddressBanner` shape applied to a much sharper
 * fact.
 *
 * IT IS NOT DISMISSIBLE, and that is a deliberate departure from the usual
 * courtesy. A dismissed banner hides a live case from the one person entitled
 * to kill it, and the case does not stop advancing because the banner was
 * closed. It disappears when the case is closed, and only then.
 *
 * IT RENDERS NOTHING ON ERROR. A failed read is not "no case" — but it is also
 * not something to alarm somebody about in a page-wide banner they cannot act
 * on, and the page behind it reports the failure properly. Silence is the
 * honest failure mode in a banner; the surface it links to is where a refused
 * read must be visible, and there it is.
 *
 * ONE QUERY PER NAVIGATION, no polling — the `UnverifiedAddressBanner` budget.
 * A case is opened by a human ceremony and has a waiting period measured in
 * days; the seconds a poll would save are not seconds that matter, and the read
 * costs settlement a round trip on every page of the app.
 */
export function OpenSettlementCaseBanner(): ReactElement | null {
  const pathname = usePathname();
  const [openCases, setOpenCases] = useState(0);

  useEffect(() => {
    let live = true;
    void (async () => {
      const result = await gqlRequest('SettlementCases', {});
      if (!live) {
        return;
      }
      // A missing field is NO DATA: a BFF predating this query must leave the
      // banner silent rather than confidently claiming there is no case.
      if (!result.ok || !Array.isArray(result.data.settlementCases)) {
        setOpenCases(0);
        return;
      }
      // ABOUT ME, not "filed by me". A reporter's own case is not a threat to
      // them and must never raise this alarm on their pages.
      setOpenCases(result.data.settlementCases.filter((row) => row.aboutMe && isOpen(row)).length);
    })();
    return () => {
      live = false;
    };
  }, [pathname]);

  if (openCases === 0) {
    return null;
  }

  return (
    <div className="border-b border-danger/40 bg-danger/10">
      <p className="mx-auto w-full max-w-4xl px-6 py-2.5 text-sm lg:px-10">
        <strong className="font-semibold">
          {openCases === 1
            ? 'Someone has reported you as deceased.'
            : `There are ${openCases} open reports that you are deceased.`}
        </strong>{' '}
        Nothing has been released.{' '}
        <Link href="/security/cases" className="font-medium text-ink underline underline-offset-4">
          Close {openCases === 1 ? 'it' : 'them'} now
        </Link>
      </p>
    </div>
  );
}

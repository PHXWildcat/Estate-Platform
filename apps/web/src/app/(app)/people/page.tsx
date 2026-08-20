import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { HouseholdPanel } from '../../../components/HouseholdPanel';
import { LinkedEstatesPanel } from '../../../components/LinkedEstatesPanel';
import { PeoplePanel } from '../../../components/PeoplePanel';

export const metadata: Metadata = { title: 'People' };

export default function PeoplePage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">People</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Who your plan names, and what each of them may see. Naming someone records your intent —
            it grants nothing on its own.
          </p>
        </div>
      </div>
      <div className="mt-6 grid gap-6">
        <PeoplePanel />
        <HouseholdPanel />
        {/*
          M22 PR4a. LAST, and the order is the point: the two panels above are
          the plan this person is making, and this one is the plans other people
          have made that involve them. Putting it first would open a page called
          "People" with somebody else's estate.
        */}
        <LinkedEstatesPanel />
      </div>
    </div>
  );
}

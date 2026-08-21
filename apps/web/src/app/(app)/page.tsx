import type { ReactElement } from 'react';
import { SessionCard } from '../../components/SessionCard';
import { SettlingEstatesPanel } from '../../components/SettlingEstatesPanel';

export default function HomePage(): ReactElement {
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
        M23 PR2, ABOVE the session card and SELF-HIDING: it renders nothing at
        all unless settlement returns an estate this person is settling. An
        executor arrives here days after a death and should not have to hunt;
        everybody else never learns the panel exists.
      */}
      <SettlingEstatesPanel />
      <SessionCard />
    </div>
  );
}

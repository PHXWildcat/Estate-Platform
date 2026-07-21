import type { ReactElement } from 'react';
import { SessionCard } from '../components/SessionCard';

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
      <SessionCard />
    </div>
  );
}

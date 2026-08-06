import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { ContactDetailPanel } from '../../../../components/ContactDetailPanel';

/**
 * One person's page. The title is deliberately generic: a contact's name is
 * encrypted under the owner's key and is not available to a server component
 * without a decrypt, and putting it in a document title would also put it in
 * browser history and in any window-title telemetry.
 */
export const metadata: Metadata = { title: 'Person' };

export default async function ContactPage({
  params,
}: {
  params: Promise<{ contactId: string }>;
}): Promise<ReactElement> {
  const { contactId } = await params;
  return (
    <div>
      <Link className="text-sm text-ink-muted underline-offset-2 hover:underline" href="/people">
        ← People
      </Link>
      <div className="mt-4">
        <ContactDetailPanel contactId={contactId} />
      </div>
    </div>
  );
}

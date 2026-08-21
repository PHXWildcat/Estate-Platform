import { render, screen, waitFor, within } from '@testing-library/react';
import type { ContactSummaryInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { EstateContacts, contactRole, professionalsFirst } from './EstateContacts';

/**
 * THE ESTATE'S PEOPLE (M23 PR4a) — docs/03 §5.4's control against grief-window
 * phishing, specified since the threat model was written and unbuilt until now.
 *
 * Three properties carry this file.
 *
 * The FIRST is that the panel says what it is FOR. §5.4's attack is an
 * impostor claiming to act for the estate ("probate portal fee required"),
 * and a list of names with no stated purpose is a directory rather than a
 * control — a reader who does not know why it is there cannot use it to
 * recognise anyone.
 *
 * The SECOND is that a SHUT RUNG is not an outage and not an empty estate.
 * Three different facts, three different sentences: access has not opened yet,
 * we could not read this, and nobody was named.
 *
 * The THIRD is that no contact detail is fetched. Each of email, phone and
 * address is another audited decrypt on a dead person's trail, and knowing WHO
 * the attorney is does not require knowing how to call them.
 */

const CASE_ID = 'case-1';

function contact(over: Partial<ContactSummaryInfo> = {}): ContactSummaryInfo {
  return {
    id: 'contact-1',
    name: 'Charles Babbage',
    relationship: 'child',
    professionalKind: null,
    hasEmail: false,
    hasPhone: false,
    hasAddress: false,
    hasNotes: false,
    linked: false,
    ...over,
  };
}

const ATTORNEY = contact({
  id: 'contact-2',
  name: 'Grace Hopper',
  relationship: null,
  professionalKind: 'attorney',
  hasEmail: true,
  hasPhone: true,
  linked: true,
});

function handlers(estateContacts?: OperationHandler): Record<string, OperationHandler> {
  return {
    EstateContacts:
      estateContacts ??
      // The relative FIRST, so "professionals first" is a re-ordering this
      // component performs rather than the order it was handed.
      (() => jsonResponse({ data: { estateContacts: [contact(), ATTORNEY] } })),
  };
}

describe('what a card says', () => {
  it('prefers the professional role over the family relationship', () => {
    // An impostor claims to be the attorney, not the son — so on a row that is
    // both, the role that matters to §5.4 is the one shown.
    expect(contactRole(contact({ professionalKind: 'attorney', relationship: 'child' }))).toBe(
      'Attorney',
    );
  });

  it('falls back to the relationship, and says nothing when there is neither', () => {
    expect(contactRole(contact({ relationship: 'child' }))).toBe('Child');
    expect(contactRole(contact({ relationship: null }))).toBeNull();
  });
});

describe('the ordering', () => {
  it('puts professionals first', () => {
    expect(professionalsFirst([contact(), ATTORNEY]).map((c) => c.id)).toEqual([
      'contact-2',
      'contact-1',
    ]);
  });

  it('keeps the server’s order WITHIN each group', () => {
    // Stable, so the service's own ordering survives inside a group rather than
    // being replaced by something this screen invented.
    const a = contact({ id: 'a' });
    const b = contact({ id: 'b' });
    const cpa = contact({ id: 'cpa', professionalKind: 'cpa' });
    expect(professionalsFirst([a, cpa, b]).map((c) => c.id)).toEqual(['cpa', 'a', 'b']);
  });
});

describe('the estate’s people', () => {
  it('names the estate’s attorney, professionals first', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateContacts caseId={CASE_ID} />);
    const list = await screen.findByRole('list');
    const items = within(list).getAllByRole('listitem');
    expect(within(items[0] as HTMLElement).getByText('Grace Hopper')).toBeInTheDocument();
    expect(within(items[0] as HTMLElement).getByText('Attorney')).toBeInTheDocument();
  });

  it('says what the list is FOR — an impostor has something to contradict', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateContacts caseId={CASE_ID} />);
    await screen.findByRole('list');
    // The control, in words. Without this the panel is a directory.
    expect(screen.getByText(/aren’t on this list/i)).toBeInTheDocument();
    expect(screen.getByText(/never send you a payment link/i)).toBeInTheDocument();
  });

  it('says what is ON FILE without having read any of it', async () => {
    installGraphqlFetchMock(handlers());
    render(<EstateContacts caseId={CASE_ID} />);
    // Built from the `has` flags. An address or a phone number appearing here
    // would mean the list had spent decrypts it has no budget for.
    expect(await screen.findByText(/on file: email, phone/i)).toBeInTheDocument();
    expect(screen.getByText(/no contact details on file/i)).toBeInTheDocument();
  });

  it('renders a SHUT RUNG as "not opened yet", never as an error', async () => {
    installGraphqlFetchMock(handlers(() => graphqlError('STAGE_NOT_APPROVED')));
    render(<EstateContacts caseId={CASE_ID} />);
    // A control firing must not wear the face of an outage — no "try again",
    // because there is nothing for the reader to retry.
    expect(await screen.findByText(/opens once the documents stage/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument();
  });

  it('renders a real FAILURE as its own panel, with a retry', async () => {
    installGraphqlFetchMock(handlers(() => graphqlError('UNKNOWN')));
    render(<EstateContacts caseId={CASE_ID} />);
    // The other side of the same rule: this one IS retryable, and saying "not
    // opened yet" here would send the reader to wait for something that already
    // happened.
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/opens once the documents stage/i)).not.toBeInTheDocument();
  });

  it('says an estate that names NOBODY names nobody', async () => {
    installGraphqlFetchMock(handlers(() => jsonResponse({ data: { estateContacts: [] } })));
    render(<EstateContacts caseId={CASE_ID} />);
    // A third distinct sentence: not locked, not broken, genuinely empty.
    expect(await screen.findByText(/doesn’t name anyone/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as a failed read', async () => {
    installGraphqlFetchMock(handlers(() => jsonResponse({ data: {} })));
    render(<EstateContacts caseId={CASE_ID} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });
    expect(screen.queryByText(/doesn’t name anyone/i)).not.toBeInTheDocument();
  });
});

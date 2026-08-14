import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { RedeemLinkPanel } from './RedeemLinkPanel';

function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(overrides: Partial<Record<string, OperationHandler>> = {}): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    RedeemContactLink: () => jsonResponse({ data: { redeemContactLink: { ok: true } } }),
    ...overrides,
  });
  render(<RedeemLinkPanel />);
  return requests;
}

describe('the code is the whole request', () => {
  it('asks for nothing else — no email, no whose-estate', () => {
    mount();
    expect(screen.getByLabelText('Invitation code')).toBeInTheDocument();
    // Anything more would be a parameter in which to name an account, which is
    // exactly what docs/03 §6b's anti-enumeration property forbids.
    expect(screen.queryByLabelText(/email/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/owner/i)).not.toBeInTheDocument();
  });

  it('sends only the trimmed code', async () => {
    const requests = mount();
    fireEvent.change(screen.getByLabelText('Invitation code'), {
      target: { value: '  ESL1-ABCD  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Accept invitation' }));
    await waitFor(() => {
      expect(opNames(requests)).toContain('RedeemContactLink');
    });
    expect(
      requests.find((r) => r.body.query?.includes('RedeemContactLink'))?.body.variables,
    ).toEqual({ code: 'ESL1-ABCD' });
  });

  it('warns that a code arriving by email is suspicious', () => {
    mount();
    // The platform never emails codes, so one that arrives that way is either a
    // person forwarding it or somebody phishing (docs/03 §5.4).
    expect(
      screen.getByText(/if you were sent one\s+by email, treat it with suspicion/i),
    ).toBeInTheDocument();
  });
});

describe('success and failure both stay quiet about the estate', () => {
  it('confirms the link without naming whose estate it is', async () => {
    mount();
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'ESL1-X' } });
    fireEvent.click(screen.getByRole('button', { name: 'Accept invitation' }));
    expect(await screen.findByText('You are linked')).toBeInTheDocument();
    // No owner, no contact name: the server returns neither, and a stolen code
    // must not become a read.
    expect(screen.getByText(/person who invited you has been told/)).toBeInTheDocument();
    // ...and it does not over-promise what a link can lead to. This used to say
    // "anything they choose to share with you will appear in your account",
    // which is the same false expectation the people surface used to create
    // with buttons for resources nothing enforces: contacts are the only thing
    // a role can be allowed to read.
    expect(screen.getByText(/only thing they can allow today/)).toBeInTheDocument();
    expect(screen.queryByText(/[Aa]nything they choose to share/)).not.toBeInTheDocument();
  });

  it('gives ONE message for every kind of bad code, pointing at a fresh one', async () => {
    mount({ RedeemContactLink: () => graphqlError('INVALID_LINK_CODE') });
    fireEvent.change(screen.getByLabelText('Invitation code'), { target: { value: 'ESL1-nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Accept invitation' }));
    expect(await screen.findByText(/ask for a fresh one/)).toBeInTheDocument();
    // Never "expired" or "already used": that would confirm the code was real.
    expect(screen.queryByText(/expired/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/already used/i)).not.toBeInTheDocument();
  });

  it('refuses an empty code locally', async () => {
    const requests = mount();
    fireEvent.click(screen.getByRole('button', { name: 'Accept invitation' }));
    expect(await screen.findByText('Enter the code you were given.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('RedeemContactLink');
  });
});

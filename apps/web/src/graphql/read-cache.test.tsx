import { render, screen, waitFor, act } from '@testing-library/react';
import type { ReactElement } from 'react';
import {
  installGraphqlFetchMock,
  jsonResponse,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { gqlRequest } from './client';
import {
  CACHED_OPERATIONS,
  INVALIDATED_BY,
  invalidateSharedRead,
  resetSharedReadsForTests,
  useSharedRead,
} from './read-cache';

/**
 * The shared read cache (M24 PR1), tested through the REAL client against the
 * fetch mock — the announcement path under test here is
 * gqlRequest → operation-events → read-cache, and mocking the client away
 * would leave the wiring this capability exists for unexercised.
 */

function Probe({ id, revalidateKey }: { id: string; revalidateKey?: string }): ReactElement {
  const result = useSharedRead('EmailVerification', { revalidateKey });
  return (
    <span data-testid={id}>
      {result === null
        ? 'loading'
        : result.ok
          ? result.data.emailVerification
          : `error:${result.code}`}
    </span>
  );
}

function verificationRequests(requests: RecordedRequest[]): number {
  return requests.filter((r) => r.body.query?.includes('EmailVerification')).length;
}

beforeEach(() => {
  resetSharedReadsForTests();
});

describe('useSharedRead', () => {
  it('two subscribers share ONE request and one answer', async () => {
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: 'VERIFIED' } }),
    });
    render(
      <>
        <Probe id="first" />
        <Probe id="second" />
      </>,
    );

    await waitFor(() => expect(screen.getByTestId('first')).toHaveTextContent('VERIFIED'));
    expect(screen.getByTestId('second')).toHaveTextContent('VERIFIED');
    // The dedup is the point: the banner and a future dashboard tile must not
    // each bill identity a notifications round trip for the same fact.
    expect(verificationRequests(requests)).toBe(1);
  });

  it('a failed read is an ANSWER — delivered, rendered, and not retried', async () => {
    const { requests } = installGraphqlFetchMock({
      // No error code and no data: the client narrows this to UNKNOWN.
      EmailVerification: () => jsonResponse({}, false),
    });
    const { rerender } = render(<Probe id="probe" />);

    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('error:UNKNOWN'));
    rerender(<Probe id="probe" />);
    // Re-rendering is not permission to hammer a failing backend.
    expect(verificationRequests(requests)).toBe(1);
  });

  it('a successful VerifyEmail invalidates the read and every subscriber re-asks', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'UNVERIFIED';
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: answer } }),
      VerifyEmail: () => jsonResponse({ data: { verifyEmail: { ok: true } } }),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));

    answer = 'VERIFIED';
    // The REAL transport announces this — no component tells the cache.
    await act(async () => {
      await gqlRequest('VerifyEmail', { code: 'EV1-TEST' });
    });

    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));
    // A re-READ, not a patched local value: the server stays the authority.
    expect(verificationRequests(requests)).toBe(2);
  });

  it('a successful CompleteEmailChange invalidates too — the category, not one member', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'UNVERIFIED';
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: answer } }),
      CompleteEmailChange: () => jsonResponse({ data: { completeEmailChange: { ok: true } } }),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));

    answer = 'VERIFIED';
    await act(async () => {
      await gqlRequest('CompleteEmailChange', { code: 'EC1-TEST' });
    });

    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });

  it('a successful mutation OUTSIDE the map invalidates nothing (negative control)', async () => {
    // CancelEmailChange is the map's own documented deliberate absence:
    // cancelling a staged change alters nothing about what
    // `emailVerification` answers. (Logout used to play this role — it joined
    // the map when M24 PR3 made the auth boundary invalidate every enrolled
    // read. ResendEmailVerification, the other documented absence, would
    // collide with this file's substring matcher.)
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }),
      CancelEmailChange: () => jsonResponse({ data: { cancelEmailChange: { ok: true } } }),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));

    await act(async () => {
      await gqlRequest('CancelEmailChange', {});
    });

    expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED');
    expect(verificationRequests(requests)).toBe(1);
  });

  it('a REFUSED mutation in the map invalidates nothing — nothing was performed', async () => {
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }),
      VerifyEmail: () => jsonResponse({}, false),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));

    await act(async () => {
      await gqlRequest('VerifyEmail', { code: 'EV1-WRONG' });
    });

    expect(verificationRequests(requests)).toBe(1);
  });

  it('an invalidation mid-flight DISCARDS the stale answer', async () => {
    let release: ((response: Response) => void) | null = null;
    let call = 0;
    installGraphqlFetchMock({
      EmailVerification: () => {
        call += 1;
        if (call === 1) {
          // Held open: this answer was read from a world the mutation is
          // about to change.
          return new Promise<Response>((resolve) => {
            release = resolve;
          });
        }
        return jsonResponse({ data: { emailVerification: 'VERIFIED' } });
      },
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(call).toBe(1));

    act(() => {
      invalidateSharedRead('EmailVerification');
    });
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));

    // The pre-invalidation answer lands late and must NOT overwrite.
    await act(async () => {
      release?.(jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }));
      await Promise.resolve();
    });
    expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED');
  });

  it('a revalidateKey change re-asks while the OLD answer keeps rendering', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'UNVERIFIED';
    let release: (() => void) | null = null;
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => {
        const value = answer;
        if (value === 'VERIFIED') {
          // Hold the SECOND response open to observe the in-between state.
          return new Promise<Response>((resolve) => {
            release = () => resolve(jsonResponse({ data: { emailVerification: value } }));
          });
        }
        return jsonResponse({ data: { emailVerification: value } });
      },
    });
    const { rerender } = render(<Probe id="probe" revalidateKey="/assets" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));
    expect(verificationRequests(requests)).toBe(1);

    answer = 'VERIFIED';
    rerender(<Probe id="probe" revalidateKey="/documents" />);
    await waitFor(() => expect(verificationRequests(requests)).toBe(2));
    // Merely old, not known wrong: the navigation case keeps rendering it.
    expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED');

    await act(async () => {
      release?.();
      await Promise.resolve();
    });
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));
  });

  it('a stale answer landing after an UNWATCHED invalidation is still discarded', async () => {
    // The narrow path: fetch in flight, subscriber unmounts, THEN the
    // invalidation arrives (no refetch — nobody is watching). The in-flight
    // answer predates the mutation; if it were allowed to land, the next
    // mount would be served a cached lie with no fetch to correct it.
    let release: ((response: Response) => void) | null = null;
    let call = 0;
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => {
        call += 1;
        if (call === 1) {
          return new Promise<Response>((resolve) => {
            release = resolve;
          });
        }
        return jsonResponse({ data: { emailVerification: 'VERIFIED' } });
      },
    });
    const { unmount } = render(<Probe id="probe" />);
    await waitFor(() => expect(call).toBe(1));
    unmount();

    act(() => {
      invalidateSharedRead('EmailVerification');
    });
    await act(async () => {
      release?.(jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }));
      await Promise.resolve();
    });

    render(<Probe id="fresh" />);
    await waitFor(() => expect(screen.getByTestId('fresh')).toHaveTextContent('VERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });

  it('an invalidation with NO subscriber fetches nothing; the next mount re-asks fresh', async () => {
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: 'VERIFIED' } }),
    });
    const { unmount } = render(<Probe id="probe" />);
    await waitFor(() => expect(verificationRequests(requests)).toBe(1));
    unmount();

    act(() => {
      invalidateSharedRead('EmailVerification');
    });
    // Nobody is watching — a fetch here would be a read with no reader.
    expect(verificationRequests(requests)).toBe(1);

    render(<Probe id="fresh" />);
    await waitFor(() => expect(screen.getByTestId('fresh')).toHaveTextContent('VERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });
});

describe('the auth boundary (M24 PR3)', () => {
  // The cache keys answers by OPERATION NAME, not by principal, and its
  // entries outlive their subscribers across client-side navigations. These
  // three tests are the shared-browser scenario: without the boundary, user
  // B's first mount finds user A's answer cached and renders it with ZERO
  // fetches.

  it('a successful Logout discards every enrolled answer — the next mount fetches fresh', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'VERIFIED';
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: answer } }),
      Logout: () => jsonResponse({ data: { logout: { ok: true } } }),
    });
    // User A sees their answer, then leaves the page.
    const { unmount } = render(<Probe id="userA" />);
    await waitFor(() => expect(screen.getByTestId('userA')).toHaveTextContent('VERIFIED'));
    unmount();

    await act(async () => {
      await gqlRequest('Logout', {});
    });

    // User B's mount must be served the SERVER's answer about user B, never
    // user A's cached one.
    answer = 'UNVERIFIED';
    render(<Probe id="userB" />);
    await waitFor(() => expect(screen.getByTestId('userB')).toHaveTextContent('UNVERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });

  it('a successful Login discards the previous principal’s answer', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'VERIFIED';
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: answer } }),
      Login: () => jsonResponse({ data: { login: { ok: true } } }),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));

    answer = 'UNVERIFIED';
    await act(async () => {
      await gqlRequest('Login', { email: 'b@example.com', password: 'pw' });
    });

    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });

  it('a successful Register discards it too — every door into a session is on the boundary', async () => {
    let answer: 'UNVERIFIED' | 'VERIFIED' = 'VERIFIED';
    const { requests } = installGraphqlFetchMock({
      EmailVerification: () => jsonResponse({ data: { emailVerification: answer } }),
      Register: () => jsonResponse({ data: { register: { ok: true } } }),
    });
    render(<Probe id="probe" />);
    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('VERIFIED'));

    answer = 'UNVERIFIED';
    await act(async () => {
      await gqlRequest('Register', { email: 'b@example.com', password: 'pw' });
    });

    await waitFor(() => expect(screen.getByTestId('probe')).toHaveTextContent('UNVERIFIED'));
    expect(verificationRequests(requests)).toBe(2);
  });
});

describe('the enrolled set', () => {
  it('is pinned EXACTLY, so growth is a reviewed decision against the written bar', () => {
    // The bar (read-cache.ts): no audited decrypts, no decrypted PII, no
    // variables. Every audited-decrypt read the app has — document content,
    // contact detail, distribution amounts, asset history — must fail this
    // assertion loudly if someone enrolls it for a loading spinner.
    expect(CACHED_OPERATIONS).toEqual(['EmailVerification']);
  });

  it('every auth-boundary door maps to CACHED_OPERATIONS BY REFERENCE, not a copy', () => {
    // The §6ss guarantee — "a future enrollment inherits the boundary
    // without anyone remembering it" — is only true while these are the SAME
    // list. A hand-copied literal equal to today's contents would pass every
    // behavior test above and quietly stop covering the next enrollment, so
    // this pins the reference itself (toBe, never toEqual).
    expect(INVALIDATED_BY.Login).toBe(CACHED_OPERATIONS);
    expect(INVALIDATED_BY.Register).toBe(CACHED_OPERATIONS);
    expect(INVALIDATED_BY.Logout).toBe(CACHED_OPERATIONS);
  });
});

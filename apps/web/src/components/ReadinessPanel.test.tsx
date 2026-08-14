import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { AnalysisInfo, FindingInfo, ReadinessInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { ReadinessPanel } from './ReadinessPanel';

/**
 * The readiness surface. What these tests defend is not layout — it is that
 * every distinction the analysers drew survives to the screen:
 *
 *   * a CODE always renders as a sentence, never as a raw token;
 *   * a failed or refused check never renders as "nothing found";
 *   * the non-legal-advice watermark comes from the server and is always shown;
 *   * granting consent takes a step-up, and revoking never does.
 */

const DISCLAIMER =
  'This is an automated analysis of the information in your account, for education only. It is not legal or tax advice.';

function analysis(over: Partial<AnalysisInfo> = {}): AnalysisInfo {
  return { status: 'OK', reason: null, findings: [], disclaimer: DISCLAIMER, ...over };
}

function finding(over: Partial<FindingInfo> = {}): FindingInfo {
  return {
    code: 'asset_not_titled_in_trust',
    severity: 'high',
    subject: { kind: 'asset', ref: 'a1', label: 'The lake house' },
    detail: { category: 'real_estate' },
    ...over,
  };
}

function readiness(over: Partial<ReadinessInfo> = {}): ReadinessInfo {
  return {
    funding: analysis(),
    missingDocuments: analysis(),
    beneficiaryConflicts: analysis(),
    estateTax: analysis(),
    ...over,
  };
}

function handlers(options: {
  readiness?: ReadinessInfo;
  consents?: string[];
  grant?: OperationHandler;
  revoke?: OperationHandler;
  stepUp?: OperationHandler;
}): Record<string, OperationHandler> {
  return {
    Readiness: () => jsonResponse({ data: { readiness: options.readiness ?? readiness() } }),
    Consents: () => jsonResponse({ data: { consents: options.consents ?? ['assistant.enabled'] } }),
    GrantConsent:
      options.grant ??
      (() => jsonResponse({ data: { grantConsent: ['assistant.enabled', 'assistant.assets'] } })),
    RevokeConsent:
      options.revoke ?? (() => jsonResponse({ data: { revokeConsent: ['assistant.enabled'] } })),
    StepUp: options.stepUp ?? (() => jsonResponse({ data: { stepUp: { ok: true } } })),
  };
}

describe('findings render as sentences, never as codes', () => {
  it('turns a funding code into words about the named asset', async () => {
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({ funding: analysis({ findings: [finding()] }) }),
      }),
    );
    render(<ReadinessPanel />);

    expect(await screen.findByText('The lake house is outside your trust')).toBeInTheDocument();
    // The raw token must never reach the screen.
    expect(screen.queryByText(/asset_not_titled_in_trust/)).not.toBeInTheDocument();
  });

  it('formats money from the detail map without parsing it', async () => {
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          estateTax: analysis({
            findings: [
              finding({
                code: 'federal_exposure',
                severity: 'high',
                subject: { kind: 'estate', ref: null, label: null },
                detail: {
                  grossEstate: '90071992547409.91',
                  exemption: '15000000.00',
                  amountOverExemption: '75071992547409.91',
                  estimatedTaxUpperBound: '30028797018963.96',
                  topRatePct: 40,
                },
              }),
            ],
          }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    // Digit-perfect past MAX_SAFE_INTEGER: the whole reason money is a string.
    expect(await screen.findByText(/\$90,071,992,547,409\.91/)).toBeInTheDocument();
  });

  it('describes an unknown code safely instead of blanking or leaking it', async () => {
    // A service deployed ahead of this app must not produce an empty card.
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          funding: analysis({ findings: [finding({ code: 'a_code_from_the_future' })] }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    expect(await screen.findByText('A finding we cannot describe yet')).toBeInTheDocument();
    expect(screen.queryByText(/a_code_from_the_future/)).not.toBeInTheDocument();
  });

  it('an asset finding links to the asset it is about; an estate finding does not', async () => {
    // The M19 PR3 closure of the M10 incoherence: the page that says "no
    // beneficiary designated" now takes the owner to the place they can act.
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          funding: analysis({
            findings: [
              finding(),
              finding({
                code: 'no_trust_on_file',
                subject: { kind: 'estate', ref: null, label: null },
              }),
            ],
          }),
        }),
      }),
    );
    render(<ReadinessPanel />);
    const links = await screen.findAllByRole('link');
    const assetLinks = links.filter((l) => l.getAttribute('href')?.startsWith('/assets/'));
    // Exactly ONE finding links (the asset-scoped one); the estate-wide
    // finding renders as plain text.
    expect(assetLinks).toHaveLength(1);
    expect(assetLinks[0]).toHaveAttribute('href', '/assets/a1');
  });

  it('renders EVERY finding when several share a code and no subject row', async () => {
    // The commonest analysis in the product emits exactly this shape: "no
    // guardian designation on file" and "no HIPAA authorization on file" are
    // both `instrument_missing` about no particular row. An earlier key of
    // code+ref collided, and React's remedy for a duplicate key is to drop or
    // duplicate a child — so a real finding about someone's estate would have
    // vanished from the page. The browser console said so; no unit test did.
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          missingDocuments: analysis({
            findings: [
              finding({
                code: 'instrument_missing',
                severity: 'high',
                subject: { kind: 'estate', ref: null, label: null },
                detail: { expectedKind: 'guardian_designation' },
              }),
              finding({
                code: 'instrument_missing',
                severity: 'medium',
                subject: { kind: 'estate', ref: null, label: null },
                detail: { expectedKind: 'hipaa_auth' },
              }),
            ],
          }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    expect(await screen.findByText('No guardian designation on file')).toBeInTheDocument();
    expect(screen.getByText('No HIPAA authorization on file')).toBeInTheDocument();
  });

  it('orders high-severity findings first', async () => {
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          funding: analysis({
            findings: [
              finding({ code: 'no_trust_on_file', severity: 'info', detail: { assetCount: 2 } }),
              finding({ code: 'asset_not_titled_in_trust', severity: 'high' }),
            ],
          }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    const items = await screen.findAllByRole('listitem');
    const texts = items.map((item) => item.textContent ?? '');
    const high = texts.findIndex((t) => t.includes('is outside your trust'));
    const info = texts.findIndex((t) => t.includes('No trust on file'));
    expect(high).toBeLessThan(info);
  });
});

describe('a failed or refused check never reads as a clean bill of health', () => {
  it.each([
    ['UNAVAILABLE', 'We could not run this check'],
    ['REFUSED', 'We do not publish this check here'],
    ['DISABLED', 'The assistant is switched off'],
  ] as const)('says what happened for %s', async (status, headline) => {
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          estateTax: analysis({ status, reason: 'reference_unreviewed', findings: [] }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    expect(await screen.findByText(headline)).toBeInTheDocument();
  });

  it('keeps the other three checks rendering when one fails', async () => {
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          estateTax: analysis({ status: 'UNAVAILABLE', reason: 'upstream_unavailable' }),
          funding: analysis({ findings: [finding()] }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    expect(await screen.findByText('The lake house is outside your trust')).toBeInTheDocument();
    expect(screen.getByText('We could not run this check')).toBeInTheDocument();
  });

  it('counts only OK checks toward "needs attention"', async () => {
    // A failed check contributes nothing to the headline number — it must not
    // read as zero problems OR as a problem.
    installGraphqlFetchMock(
      handlers({
        readiness: readiness({
          funding: analysis({
            findings: [
              finding(),
              finding({ subject: { kind: 'asset', ref: 'a2', label: 'Boat' } }),
            ],
          }),
          estateTax: analysis({ status: 'UNAVAILABLE', reason: 'upstream_unavailable' }),
        }),
      }),
    );
    render(<ReadinessPanel />);

    const summary = await screen.findByRole('region', { name: 'Summary' });
    expect(within(summary).getByText('2')).toBeInTheDocument();
  });
});

describe('the watermark', () => {
  it('renders the SERVER’s disclaimer text, adjacent to the findings', async () => {
    // docs/01 §2.8: the platform's statement, not this app's — a copy here
    // would drift from it silently.
    installGraphqlFetchMock(handlers({}));
    render(<ReadinessPanel />);

    expect(await screen.findByText(DISCLAIMER)).toBeInTheDocument();
  });
});

describe('load states', () => {
  it('offers sign-in rather than an empty estate when unauthenticated', async () => {
    installGraphqlFetchMock({
      Readiness: () => graphqlError('UNAUTHENTICATED'),
      Consents: () => graphqlError('UNAUTHENTICATED'),
    });
    render(<ReadinessPanel />);

    expect(await screen.findByText('Sign in required')).toBeInTheDocument();
  });

  it('says a failure is not a statement about the estate', async () => {
    installGraphqlFetchMock({
      Readiness: () => graphqlError('UNKNOWN'),
      Consents: () => jsonResponse({ data: { consents: [] } }),
    });
    render(<ReadinessPanel />);

    expect(
      await screen.findByText(/this is not a statement about your estate/i),
    ).toBeInTheDocument();
  });
});

describe('consent controls', () => {
  it('shows what is on, and turns a scope off in one click', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ consents: ['assistant.enabled', 'assistant.assets'] }),
    );
    render(<ReadinessPanel />);

    await screen.findByText('What the assistant may read');
    const assetsRow = screen.getByText('Read my asset list').closest('li');
    fireEvent.click(within(assetsRow as HTMLElement).getByRole('button', { name: 'Turn off' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('RevokeConsent'))).toBe(true);
    });
    // Revoking is never step-up gated — the protective action must not be
    // harder than the permissive one.
    expect(requests.some((r) => r.body.query?.includes('StepUp'))).toBe(false);
  });

  it('asks for a code when granting, then retries the grant', async () => {
    let grantAttempts = 0;
    const { requests } = installGraphqlFetchMock(
      handlers({
        consents: ['assistant.enabled'],
        grant: () => {
          grantAttempts += 1;
          return grantAttempts === 1
            ? graphqlError('STEPUP_REQUIRED')
            : jsonResponse({ data: { grantConsent: ['assistant.enabled', 'assistant.assets'] } });
        },
      }),
    );
    render(<ReadinessPanel />);

    await screen.findByText('What the assistant may read');
    const assetsRow = screen.getByText('Read my asset list').closest('li');
    fireEvent.click(within(assetsRow as HTMLElement).getByRole('button', { name: 'Turn on' }));

    // The prompt appears in place — the user is not sent to another page.
    const codeField = await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(codeField, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and turn on' }));

    await waitFor(() => {
      expect(grantAttempts).toBe(2);
    });
    expect(requests.some((r) => r.body.query?.includes('StepUp'))).toBe(true);
  });

  it('rejects a malformed code before spending a step-up attempt', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ consents: ['assistant.enabled'], grant: () => graphqlError('STEPUP_REQUIRED') }),
    );
    render(<ReadinessPanel />);

    await screen.findByText('What the assistant may read');
    const assetsRow = screen.getByText('Read my asset list').closest('li');
    fireEvent.click(within(assetsRow as HTMLElement).getByRole('button', { name: 'Turn on' }));

    const codeField = await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(codeField, { target: { value: '12' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and turn on' }));

    expect(await screen.findByText('The code is 6 digits, numbers only.')).toBeInTheDocument();
    expect(requests.some((r) => r.body.query?.includes('StepUp'))).toBe(false);
  });
});

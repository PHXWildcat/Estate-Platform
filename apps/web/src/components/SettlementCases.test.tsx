import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { SettlementCaseInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { SettlementCases } from './SettlementCases';

/**
 * The owner's kill switch (M22 PR3).
 *
 * What these tests defend is not layout. It is the handful of places where the
 * obvious rendering would harm the one person this surface exists for:
 *
 *   * a case the OWNER voided must never be described as fraud found against
 *     them, even though the DDL forces its status to spell `rejected_fraud`;
 *   * a refused read must never render as "nobody has reported you";
 *   * an outage must never render as a refusal, or the owner stops trying;
 *   * a reporter must never be offered a control the server would refuse;
 *   * and the kill switch must survive every refusal that leaves the case open.
 */

function settlementCase(over: Partial<SettlementCaseInfo> = {}): SettlementCaseInfo {
  return {
    caseId: 'case-1',
    status: 'reported',
    reportSource: 'trusted_contact',
    evidenceCount: 0,
    waitingPeriodEnds: null,
    resolution: null,
    resolvedAt: null,
    createdAt: '2026-08-01T00:00:00.000Z',
    aboutMe: true,
    voidable: true,
    ...over,
  };
}

function handlers(
  options: {
    cases?: OperationHandler;
    voidCase?: OperationHandler;
    stepUp?: OperationHandler;
  } = {},
): Record<string, OperationHandler> {
  return {
    SettlementCases:
      options.cases ?? (() => jsonResponse({ data: { settlementCases: [settlementCase()] } })),
    VoidSettlementCase:
      options.voidCase ??
      (() =>
        jsonResponse({
          data: {
            voidSettlementCase: settlementCase({
              status: 'rejected_fraud',
              resolution: 'owner_voided',
              voidable: false,
            }),
          },
        })),
    StepUp: options.stepUp ?? (() => jsonResponse({ data: { stepUp: { ok: true } } })),
    Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
  };
}

describe('a case the owner closed is never described as fraud', () => {
  /**
   * THE DEFECT THIS PREVENTS IS A SENTENCE, NOT A CRASH. `settlement_cases`
   * CHECKs `(resolution IS NOT NULL) = (status = 'rejected_fraud')`, so an
   * owner's own void lands the row in a status literally spelled
   * `rejected_fraud`. Rendering `status` would tell someone who just protected
   * themselves that fraud was found AGAINST them.
   */
  it('reads resolution, not status, for an owner-voided case', async () => {
    installGraphqlFetchMock(
      handlers({
        cases: () =>
          jsonResponse({
            data: {
              settlementCases: [
                settlementCase({
                  status: 'rejected_fraud',
                  resolution: 'owner_voided',
                  resolvedAt: '2026-08-02T00:00:00.000Z',
                  voidable: false,
                }),
              ],
            },
          }),
      }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/you confirmed you’re alive/i)).toBeInTheDocument();
    expect(screen.queryByText(/fraud/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/rejected_fraud/)).not.toBeInTheDocument();
  });

  it('distinguishes an operator rejection from the owner’s own void', async () => {
    installGraphqlFetchMock(
      handlers({
        cases: () =>
          jsonResponse({
            data: {
              settlementCases: [
                settlementCase({
                  status: 'rejected_fraud',
                  resolution: 'operator_rejected',
                  voidable: false,
                }),
              ],
            },
          }),
      }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/we reviewed this and rejected it/i)).toBeInTheDocument();
  });

  it('never prints a raw status token for a vocabulary it does not know', async () => {
    // The service's status list has grown twice. An unrecognised value must
    // become a vague sentence, never the word `deceased_pending` shown to
    // somebody about themselves.
    installGraphqlFetchMock(
      handlers({
        cases: () =>
          jsonResponse({
            data: { settlementCases: [settlementCase({ status: 'some_new_status' })] },
          }),
      }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/in progress/i)).toBeInTheDocument();
    expect(screen.queryByText(/some_new_status/)).not.toBeInTheDocument();
  });
});

describe('a failed read is not an empty one', () => {
  it('refuses to say "nobody has reported you" when the read failed', async () => {
    installGraphqlFetchMock(
      handlers({ cases: () => graphqlError('UNKNOWN', 'Something went wrong') }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/couldn’t check this/i)).toBeInTheDocument();
    expect(screen.queryByText(/nobody has reported you/i)).not.toBeInTheDocument();
  });

  it('says the reassuring thing only when the server actually said it', async () => {
    installGraphqlFetchMock(
      handlers({ cases: () => jsonResponse({ data: { settlementCases: [] } }) }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/nobody has reported you/i)).toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as no data, not as no cases', async () => {
    installGraphqlFetchMock(handlers({ cases: () => jsonResponse({ data: {} }) }));
    render(<SettlementCases />);
    expect(await screen.findByText(/couldn’t check this/i)).toBeInTheDocument();
  });
});

describe('the kill switch', () => {
  it('is offered to the subject of an open case', async () => {
    installGraphqlFetchMock(handlers());
    render(<SettlementCases />);
    expect(await screen.findByRole('button', { name: /i’m alive/i })).toBeInTheDocument();
  });

  it('is NOT offered on a case the caller merely reported', async () => {
    // Cedar gives `void` to the decedent only. Offering it to a reporter would
    // be an action the server refuses — never offer one of those.
    installGraphqlFetchMock(
      handlers({
        cases: () =>
          jsonResponse({
            data: {
              settlementCases: [settlementCase({ aboutMe: false, voidable: false })],
            },
          }),
      }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/reports you’ve made/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /i’m alive/i })).not.toBeInTheDocument();
  });

  it('is NOT offered once a case is past the point of self-rescue', async () => {
    installGraphqlFetchMock(
      handlers({
        cases: () =>
          jsonResponse({
            data: { settlementCases: [settlementCase({ status: 'verified', voidable: false })] },
          }),
      }),
    );
    render(<SettlementCases />);
    expect(await screen.findByText(/verified/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /i’m alive/i })).not.toBeInTheDocument();
  });

  it('raises the step-up prompt, which IS the proof of life', async () => {
    let attempts = 0;
    installGraphqlFetchMock(
      handlers({
        voidCase: () => {
          attempts += 1;
          return attempts === 1
            ? graphqlError('STEPUP_REQUIRED', 'Step-up verification required')
            : jsonResponse({
                data: {
                  voidSettlementCase: settlementCase({
                    status: 'rejected_fraud',
                    resolution: 'owner_voided',
                    voidable: false,
                  }),
                },
              });
        },
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /i’m alive/i }));
    expect(await screen.findByText(/proves you’re alive/i)).toBeInTheDocument();
  });

  /**
   * THE DISTINCTION THIS WHOLE MILESTONE TURNS ON. A rolled-back transition is
   * not a refusal: nothing happened, and the remedy is to try again. An owner
   * who reads "that is not allowed" stops trying, and a fraudulent case about
   * them stays alive on the difference.
   */
  it('reports an outage as an outage, and keeps the kill switch on screen', async () => {
    installGraphqlFetchMock(
      handlers({
        voidCase: () => graphqlError('SETTLEMENT_UNAVAILABLE', 'unavailable'),
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /i’m alive/i }));
    expect(await screen.findByText(/nothing has changed/i)).toBeInTheDocument();
    // The case did not move, so the control that acts on it must still be here.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /i’m alive/i })).toBeInTheDocument();
    });
  });

  it('reports "too late" differently from "we could not reach the service"', async () => {
    installGraphqlFetchMock(
      handlers({ voidCase: () => graphqlError('CASE_NOT_VOIDABLE', 'too late') }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /i’m alive/i }));
    expect(await screen.findByText(/already been verified/i)).toBeInTheDocument();
    expect(screen.queryByText(/nothing has changed/i)).not.toBeInTheDocument();
  });

  it('confirms the close, and stops offering it', async () => {
    installGraphqlFetchMock(
      handlers({
        cases: (() => {
          let call = 0;
          return () => {
            call += 1;
            return jsonResponse({
              data: {
                settlementCases: [
                  call === 1
                    ? settlementCase()
                    : settlementCase({
                        status: 'rejected_fraud',
                        resolution: 'owner_voided',
                        voidable: false,
                      }),
                ],
              },
            });
          };
        })(),
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /i’m alive/i }));
    expect(await screen.findByText(/that case is closed/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /i’m alive/i })).not.toBeInTheDocument();
    });
  });

  it('lets a failed read be retried, rather than stranding the page', async () => {
    let call = 0;
    installGraphqlFetchMock(
      handlers({
        cases: () => {
          call += 1;
          return call === 1
            ? graphqlError('UNKNOWN')
            : jsonResponse({ data: { settlementCases: [settlementCase()] } });
        },
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /try again/i }));
    expect(await screen.findByRole('button', { name: /i’m alive/i })).toBeInTheDocument();
  });

  it('Cancel on the prompt puts the kill switch back, never withdraws it', async () => {
    // Fail-closed means DE-ESCALATE. Abandoning the identity check must return
    // the owner to the control, not leave them on a page with nothing to press.
    installGraphqlFetchMock(handlers({ voidCase: () => graphqlError('STEPUP_REQUIRED') }));
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /i’m alive/i }));
    fireEvent.click(await screen.findByRole('button', { name: /cancel/i }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /i’m alive/i })).toBeInTheDocument();
    });
  });
});

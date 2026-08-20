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
    documents?: OperationHandler;
    attach?: OperationHandler;
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
    Documents: options.documents ?? (() => jsonResponse({ data: { documents: DOCUMENTS } })),
    AttachCaseEvidence:
      options.attach ??
      (() =>
        jsonResponse({
          data: {
            attachCaseEvidence: settlementCase({
              aboutMe: false,
              voidable: false,
              evidenceCount: 1,
            }),
          },
        })),
  };
}

const DOCUMENTS = [
  {
    documentId: 'doc-1',
    docType: 'other',
    source: 'uploaded',
    title: 'Death certificate',
    currentVersion: 4,
    executionStatus: 'none',
    executedAt: null,
    legalHold: false,
    sealed: false,
    templateId: null,
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt: '2026-08-01T00:00:00.000Z',
  },
];

/** A case this caller REPORTED — settlement returns it from the same list. */
function reported(over: Partial<SettlementCaseInfo> = {}): SettlementCaseInfo {
  return settlementCase({ aboutMe: false, voidable: false, ...over });
}

/**
 * ATTACHING EVIDENCE TO A REPORT YOU FILED (M22 PR4c).
 *
 * `evidence_add` is the ONE verb Cedar grants a reporter on the case they
 * filed, and until PR4c it had no caller at any layer. The properties worth
 * pinning are about what is OFFERED: the kill switch must stay absent here
 * (Cedar refuses it to the reporter), and the attach must be absent once the
 * case has moved past the window where settlement accepts one.
 */
describe('the reporter’s own cases', () => {
  it('offers the attach on an open report, and never the kill switch', async () => {
    installGraphqlFetchMock(
      handlers({ cases: () => jsonResponse({ data: { settlementCases: [reported()] } }) }),
    );
    render(<SettlementCases />);
    expect(await screen.findByRole('button', { name: /attach a document/i })).toBeInTheDocument();
    // The reporter is not the subject. Offering it would be an action the
    // server declines — and would suggest they can end a case they filed.
    expect(screen.queryByRole('button', { name: /close this case/i })).not.toBeInTheDocument();
  });

  it.each(['verified', 'active', 'closed', 'rejected_fraud'])(
    'does not offer the attach on a %s case, which settlement would refuse',
    async (status) => {
      installGraphqlFetchMock(
        handlers({
          cases: () => jsonResponse({ data: { settlementCases: [reported({ status })] } }),
        }),
      );
      render(<SettlementCases />);
      await screen.findByText(/reports you’ve made/i);
      expect(screen.queryByRole('button', { name: /attach a document/i })).not.toBeInTheDocument();
    },
  );

  it('sends the document at its current version and updates the count', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ cases: () => jsonResponse({ data: { settlementCases: [reported()] } }) }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /attach a document/i }));
    fireEvent.change(await screen.findByLabelText(/document to attach to this report/i), {
      target: { value: 'doc-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^attach$/i }));
    await screen.findByText(/we’ve attached that to the case/i);
    const sent = requests.filter((r) => r.body.query?.includes('AttachCaseEvidence'));
    expect(sent[0]?.body.variables).toEqual({
      caseId: 'case-1',
      documentId: 'doc-1',
      version: 4,
    });
    // The list re-renders from the mutation's own answer rather than re-reading.
    expect(await screen.findByText(/1 piece of evidence/i)).toBeInTheDocument();
  });

  it('a failed documents read says so, and does not claim there are none', async () => {
    installGraphqlFetchMock(
      handlers({
        cases: () => jsonResponse({ data: { settlementCases: [reported()] } }),
        documents: () => graphqlError('UNKNOWN'),
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /attach a document/i }));
    expect(await screen.findByText(/couldn’t load your documents/i)).toBeInTheDocument();
    expect(screen.queryByText(/haven’t uploaded any documents/i)).not.toBeInTheDocument();
  });

  it('points at the upload page, not the template generator', async () => {
    // The same defect as the report flow's, found the same way — in a browser.
    installGraphqlFetchMock(
      handlers({
        cases: () => jsonResponse({ data: { settlementCases: [reported()] } }),
        documents: () => jsonResponse({ data: { documents: [] } }),
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /attach a document/i }));
    expect(await screen.findByRole('link', { name: /upload one/i })).toHaveAttribute(
      'href',
      '/documents',
    );
  });

  it('reads a closed window as its own fact, not as the kill switch’s', async () => {
    /*
     * Settlement spends one `invalid_transition` on the void and on this
     * route. "You can no longer close this case yourself" is simply false for
     * somebody attaching a certificate — and they are not the person who
     * could close it in the first place.
     */
    installGraphqlFetchMock(
      handlers({
        cases: () => jsonResponse({ data: { settlementCases: [reported()] } }),
        attach: () => graphqlError('EVIDENCE_WINDOW_CLOSED'),
      }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /attach a document/i }));
    fireEvent.change(await screen.findByLabelText(/document to attach to this report/i), {
      target: { value: 'doc-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^attach$/i }));
    expect(await screen.findByText(/moved too far along/i)).toBeInTheDocument();
    // Anchored on CASE_NOT_VOIDABLE's own sentence rather than on a phrase the
    // owner-side empty state legitimately uses a few elements away.
    expect(screen.queryByText(/already been verified/i)).not.toBeInTheDocument();
  });

  it('attaches nothing until a document is chosen', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ cases: () => jsonResponse({ data: { settlementCases: [reported()] } }) }),
    );
    render(<SettlementCases />);
    fireEvent.click(await screen.findByRole('button', { name: /attach a document/i }));
    const submit = await screen.findByRole('button', { name: /^attach$/i });
    expect(submit).toBeDisabled();
    fireEvent.click(submit);
    await waitFor(() => {
      expect(requests.filter((r) => r.body.query?.includes('AttachCaseEvidence'))).toHaveLength(0);
    });
  });
});

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

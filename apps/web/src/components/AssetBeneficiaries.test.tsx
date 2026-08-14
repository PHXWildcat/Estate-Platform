import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AssetBeneficiaries } from './AssetBeneficiaries';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';

const ASSET_ID = 'a2c2e6a4-0000-4000-8000-00000000000a';
const ALICE = 'f0000000-0000-4000-8000-000000000001';
const DANGLING = 'f0000000-0000-4000-8000-00000000dead';

const ACK = {
  assetId: ASSET_ID,
  eventId: 'e2c2e6a4-0000-4000-8000-00000000000e',
  version: '9',
  occurredAt: '2026-08-13T00:00:00.000Z',
  replayed: false,
};

const DESIGNATIONS = {
  assetId: ASSET_ID,
  beneficiaries: [
    { contactId: ALICE, name: 'Alice Attorney', designation: 'primary', sharePct: 60 },
    { contactId: DANGLING, name: null, designation: 'primary', sharePct: 40 },
  ],
  totals: [{ designation: 'primary', sharePct: 100, designationComplete: true }],
};

const CONTACTS = [
  {
    id: ALICE,
    name: 'Alice Attorney',
    relationship: 'friend',
    professionalKind: 'attorney',
    hasEmail: true,
    hasPhone: false,
    hasAddress: false,
    hasNotes: false,
    linked: false,
  },
];

function beneficiariesHandler(data = DESIGNATIONS) {
  return () => jsonResponse({ data: { assetBeneficiaries: data } });
}

const NO_DESIGNATIONS = { assetId: ASSET_ID, beneficiaries: [], totals: [] };

function renderPanel(overrides: { retired?: boolean; onVersionBumped?: (v: string) => void } = {}) {
  return render(
    <AssetBeneficiaries
      assetId={ASSET_ID}
      version="3"
      retired={overrides.retired ?? false}
      onVersionBumped={overrides.onVersionBumped ?? ((): void => undefined)}
    />,
  );
}

describe('AssetBeneficiaries', () => {
  it('renders designations with names; a dangling contact says so and stays removable', async () => {
    installGraphqlFetchMock({ AssetBeneficiaries: beneficiariesHandler() });
    renderPanel();
    expect(await screen.findByText('Alice Attorney')).toBeInTheDocument();
    expect(screen.getByText('No longer in your contacts')).toBeInTheDocument();
    expect(screen.getByText('Contact removed')).toBeInTheDocument();
    // BOTH rows keep their Remove — a dangling designation must be removable.
    expect(screen.getAllByRole('button', { name: 'Remove' })).toHaveLength(2);
    expect(screen.getByText(/100% designated/)).toBeInTheDocument();
    expect(screen.getByText(/complete/)).toBeInTheDocument();
  });

  it('reads a BFF response missing its field as NO DATA, never as no designations (M11)', async () => {
    installGraphqlFetchMock({ AssetBeneficiaries: () => jsonResponse({ data: {} }) });
    renderPanel();
    expect(await screen.findByText(/couldn’t load the beneficiary/)).toBeInTheDocument();
  });

  it('renders a fractional share and its remainder without float noise', async () => {
    // The M19 PR3 review's finding: `100 - total.sharePct` is arithmetic, and
    // IEEE-754 subtraction turned 2.058 into "97.94200000000001% unassigned".
    // Pinned at the COMPONENT, not only in formatPct's own spec, because the
    // defect was a raw interpolation here rather than a broken formatter.
    installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler({
        assetId: ASSET_ID,
        beneficiaries: [
          { contactId: ALICE, name: 'Alice Attorney', designation: 'primary', sharePct: 2.058 },
        ],
        totals: [{ designation: 'primary', sharePct: 2.058, designationComplete: false }],
      }),
    });
    renderPanel();
    expect(await screen.findByText('2.058% designated (97.942% unassigned)')).toBeInTheDocument();
    expect(screen.getByText(/Primary · 2\.058%/)).toBeInTheDocument();
    expect(screen.queryByText(/0000000/)).not.toBeInTheDocument();
  });

  it('says out loud that a designation is not access and that nobody can see it', async () => {
    installGraphqlFetchMock({ AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS) });
    renderPanel();
    expect(await screen.findByText(/A designation is not access/)).toBeInTheDocument();
    expect(screen.getByText(/beneficiary\s+visibility is not built yet/)).toBeInTheDocument();
  });

  it('loads contacts ONLY when the picker opens (the decrypt budget)', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
    });
    requests = mock.requests;
    renderPanel();
    await screen.findByText(/No beneficiaries designated/);
    // What this pins, stated precisely (the first wording overclaimed and the
    // M19 PR3 review said so): loading the view never fetches the WHOLE
    // CONTACT BOOK. It is not "the read-only view spends no decrypts" — a
    // designation-bearing asset spends one contact-name decrypt per
    // DESIGNATED row inside the BFF's own resolver, by design, and this
    // fixture has no designations. The budget saved here is the difference
    // between N designations and every contact the owner has.
    expect(requests.some((r) => r.body.query?.includes('query Contacts'))).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    expect(await screen.findByLabelText('Who')).toBeInTheDocument();
    expect(requests.some((r) => r.body.query?.includes('query Contacts'))).toBe(true);
  });

  it('designates through the form, bumps the version up, and reloads', async () => {
    const bumped: string[] = [];
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
      DesignateBeneficiary: () => jsonResponse({ data: { designateBeneficiary: ACK } }),
    });
    requests = mock.requests;
    renderPanel({
      onVersionBumped: (v) => {
        bumped.push(v);
      },
    });
    await screen.findByText(/No beneficiaries designated/);
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    await screen.findByLabelText('Who');
    fireEvent.change(screen.getByLabelText('Designation'), { target: { value: 'contingent' } });
    fireEvent.change(screen.getByLabelText('Share %'), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: 'Designate' }));

    expect(await screen.findByText('Beneficiary designated.')).toBeInTheDocument();
    expect(bumped).toEqual(['9']);
    const call = requests.find((r) => r.body.query?.includes('DesignateBeneficiary'));
    const { clientEventId, ...vars } = call?.body.variables as Record<string, unknown>;
    expect(String(clientEventId)).toMatch(/^[0-9a-f-]{36}$/);
    expect(vars).toEqual({
      assetId: ASSET_ID,
      expectedVersion: '3',
      contactId: ALICE,
      designation: 'contingent',
      sharePct: 50,
    });
  });

  it('a step-up refusal opens ONE prompt whose wording names the refused action', async () => {
    installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      DesignateBeneficiary: () => graphqlError('STEPUP_REQUIRED'),
    });
    renderPanel();
    await screen.findByText(/No beneficiaries designated/);
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    await screen.findByLabelText('Who');
    fireEvent.change(screen.getByLabelText('Share %'), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: 'Designate' }));

    expect(
      await screen.findByText(/Naming a beneficiary changes who your estate passes to/),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Confirm and designate' })).toBeInTheDocument();
    // While the consent ceremony is up the designate form is HIDDEN — one
    // Cancel on screen, the ceremony's own (the M15 identical-label rule) —
    // and no other opener exists to press.
    expect(screen.queryByLabelText('Share %')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Designate' })).not.toBeInTheDocument();

    // Cancelling the ceremony restores the form with its values intact.
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Designate' })).toBeEnabled();
    });
    expect(screen.getByLabelText('Share %')).toHaveValue('50');
  });

  it('after a code is accepted, the prompt retries THE REFUSED ACTION — the remove, not a designate', async () => {
    // The M13-review class: a shared prompt whose retry runs a DIFFERENT
    // action than the one refused. The union carries the remove's own args;
    // this drives the elevate path end to end and asserts the retried wire
    // call is RemoveBeneficiary with the ROW's designation.
    let removeAttempts = 0;
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      RemoveBeneficiary: () => {
        removeAttempts += 1;
        return removeAttempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { removeBeneficiary: ACK } });
      },
    });
    requests = mock.requests;
    renderPanel();
    await screen.findByText('Alice Attorney');
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[1] as HTMLElement);

    // The ceremony opens with the REMOVE wording.
    expect(
      await screen.findByText(/Removing a beneficiary designation changes who your estate/),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Confirm it/), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and remove' }));

    expect(await screen.findByText('Designation removed.')).toBeInTheDocument();
    const removes = requests.filter((r) => r.body.query?.includes('RemoveBeneficiary'));
    expect(removes).toHaveLength(2);
    const retried = removes[1]?.body.variables as Record<string, unknown>;
    expect(retried['contactId']).toBe(DANGLING);
    expect(retried['designation']).toBe('primary');
    // No designate was ever attempted.
    expect(requests.some((r) => r.body.query?.includes('DesignateBeneficiary'))).toBe(false);
  });

  it('remove sends the ROW’S OWN designation, not the form’s current state', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(),
      RemoveBeneficiary: () => jsonResponse({ data: { removeBeneficiary: ACK } }),
    });
    requests = mock.requests;
    renderPanel();
    await screen.findByText('Alice Attorney');
    // The DANGLING row's Remove (second in the list).
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[1] as HTMLElement);
    expect(await screen.findByText('Designation removed.')).toBeInTheDocument();
    const call = requests.find((r) => r.body.query?.includes('RemoveBeneficiary'));
    const { clientEventId, ...vars } = call?.body.variables as Record<string, unknown>;
    expect(String(clientEventId)).toMatch(/^[0-9a-f-]{36}$/);
    expect(vars).toEqual({
      assetId: ASSET_ID,
      expectedVersion: '3',
      contactId: DANGLING,
      designation: 'primary',
    });
  });

  it('surfaces SHARE_SUM_EXCEEDED as its own sentence', async () => {
    installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
      DesignateBeneficiary: () => graphqlError('SHARE_SUM_EXCEEDED'),
    });
    renderPanel();
    await screen.findByText('Alice Attorney');
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    await screen.findByLabelText('Who');
    fireEvent.change(screen.getByLabelText('Share %'), { target: { value: '90' } });
    fireEvent.click(screen.getByRole('button', { name: 'Designate' }));
    expect(await screen.findByText(/would add past 100%/)).toBeInTheDocument();
  });

  it('validates the share locally before any request leaves', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
    });
    requests = mock.requests;
    renderPanel();
    await screen.findByText(/No beneficiaries designated/);
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    await screen.findByLabelText('Who');
    fireEvent.change(screen.getByLabelText('Share %'), { target: { value: '150' } });
    fireEvent.click(screen.getByRole('button', { name: 'Designate' }));
    expect(await screen.findByText(/between 0 and 100/)).toBeInTheDocument();
    expect(requests.some((r) => r.body.query?.includes('DesignateBeneficiary'))).toBe(false);
  });

  it('picker failure, remove conflict, and picker cancel all land honestly', async () => {
    installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(),
      Contacts: () => graphqlError('UNKNOWN'),
      RemoveBeneficiary: () => graphqlError('VERSION_CONFLICT'),
    });
    renderPanel();
    await screen.findByText('Alice Attorney');

    // A contacts load failure is an error, never an empty picker.
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    expect(await screen.findByText(/couldn’t load your contacts/)).toBeInTheDocument();

    // A stale-version remove surfaces the re-read copy.
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0] as HTMLElement);
    expect(await screen.findByText(/This changed since you opened it/)).toBeInTheDocument();
  });

  it('the picker cancel closes the form without a designate request', async () => {
    let requests: RecordedRequest[] = [];
    const mock = installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: CONTACTS } }),
    });
    requests = mock.requests;
    renderPanel();
    await screen.findByText(/No beneficiaries designated/);
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    await screen.findByLabelText('Who');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByLabelText('Who')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Designate a beneficiary' })).toBeInTheDocument();
    expect(requests.some((r) => r.body.query?.includes('DesignateBeneficiary'))).toBe(false);
  });

  it('a RETIRED asset shows its designations read-only', async () => {
    installGraphqlFetchMock({ AssetBeneficiaries: beneficiariesHandler() });
    renderPanel({ retired: true });
    await screen.findByText('Alice Attorney');
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Designate a beneficiary' }),
    ).not.toBeInTheDocument();
  });

  it('an empty contact list explains where people come from', async () => {
    installGraphqlFetchMock({
      AssetBeneficiaries: beneficiariesHandler(NO_DESIGNATIONS),
      Contacts: () => jsonResponse({ data: { contacts: [] } }),
    });
    renderPanel();
    await screen.findByText(/No beneficiaries designated/);
    fireEvent.click(screen.getByRole('button', { name: 'Designate a beneficiary' }));
    expect(await screen.findByText(/Add the person under People first/)).toBeInTheDocument();
  });
});

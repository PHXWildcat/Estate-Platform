import { FetchProfileClient } from '../src/profile-client';

/**
 * The REAL client against a stubbed transport (the peer-client pattern). What
 * matters here is the wire contract and the error firewall: the caller's bearer
 * goes out on every call, downstream response text never comes back, a malformed
 * answer is refused rather than half-trusted, and the refusals whose remedies
 * differ arrive as different codes.
 */

const TOKEN = 'access-token-value-123';
const BASE = 'http://profile.test';

function response(status: number, body: unknown): Response {
  const json = (): Promise<unknown> => Promise.resolve(body);
  const res = {
    ok: status >= 200 && status < 300,
    status,
    json,
    clone: () => ({ json }) as unknown as Response,
  };
  return res as unknown as Response;
}

const PROFILE = {
  userId: 'a1111111-1111-4111-8111-111111111111',
  legalName: 'Jane Quincy Public',
  dob: '1950-04-02',
  ssnLast4: '6789',
  address: '1 Main St',
  phone: '555-0100',
  occupation: 'Architect',
  maritalStatus: 'married',
  stateOfResidence: 'AZ',
};

const SUMMARY = {
  id: 'f0000000-0000-4000-8000-000000000001',
  ownerUserId: PROFILE.userId,
  name: 'Alice Attorney',
  relationship: 'friend',
  professionalKind: 'attorney',
  hasEmail: true,
  hasPhone: false,
  hasAddress: false,
  hasNotes: false,
  linked: false,
};

function client(fetchFn: jest.Mock): FetchProfileClient {
  return new FetchProfileClient(BASE, fetchFn as never);
}

function callOf(fetchFn: jest.Mock, index = 0): { url: string; init: RequestInit } {
  const [url, init] = fetchFn.mock.calls[index] as [string, RequestInit];
  return { url, init };
}

describe('FetchProfileClient', () => {
  it('sends the bearer and reads the profile back', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, PROFILE));
    await expect(client(fetchFn).profile(TOKEN)).resolves.toEqual(PROFILE);
    const { url, init } = callOf(fetchFn);
    expect(url).toBe(`${BASE}/v1/profile`);
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('reads a 404 not_found as "nothing on file", not as a failure', async () => {
    // The M10 lesson, verbatim: profile answers 404 for a user who never saved
    // one, and treating that as an outage made three analyses a permanent 503
    // for everyone who skipped onboarding.
    const fetchFn = jest.fn().mockResolvedValue(response(404, { error: 'not_found' }));
    await expect(client(fetchFn).profile(TOKEN)).resolves.toBeNull();
  });

  it('but a route-level 404 with a different body still fails', async () => {
    // A misconfigured PROFILE_URL hitting Nest's default 404 must not read as
    // "this user has no profile" — that would be a fail-open dressed as data.
    const fetchFn = jest
      .fn()
      .mockResolvedValue(response(404, { statusCode: 404, message: 'Cannot GET /v1/profile' }));
    await expect(client(fetchFn).profile(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'NOT_FOUND' },
    });
  });

  describe('the save carries only the keys it was given', () => {
    it('omits absent fields on the wire, so the service leaves them alone', async () => {
      const fetchFn = jest.fn().mockResolvedValue(response(200, { status: 'ok' }));
      await client(fetchFn).saveProfile(TOKEN, { legalName: 'X', stateOfResidence: 'AZ' });
      const { init } = callOf(fetchFn);
      expect(JSON.parse(init.body as string)).toEqual({
        legalName: 'X',
        stateOfResidence: 'AZ',
      });
    });

    it('keeps an explicit null, which is how a field is cleared', async () => {
      const fetchFn = jest.fn().mockResolvedValue(response(200, { status: 'ok' }));
      await client(fetchFn).saveProfile(TOKEN, { legalName: 'X', phone: null });
      expect(JSON.parse(callOf(fetchFn).init.body as string)).toEqual({
        legalName: 'X',
        phone: null,
      });
    });
  });

  it('lists contacts from the OWNER-RELATIVE route', async () => {
    // Not /v1/profiles/:ownerUserId/contacts: that is the §5.5 cross-owner ABAC
    // route, and this client is only ever about the caller themselves.
    const fetchFn = jest.fn().mockResolvedValue(response(200, [SUMMARY]));
    await expect(client(fetchFn).contacts(TOKEN)).resolves.toEqual([SUMMARY]);
    expect(callOf(fetchFn).url).toBe(`${BASE}/v1/contacts`);
  });

  it('refuses a contact summary that does not match the schema', async () => {
    // A downstream that dropped `linked` would otherwise render as "not linked",
    // which is a different claim about someone's estate than "we do not know".
    const { linked: _linked, ...withoutLinked } = SUMMARY;
    const fetchFn = jest.fn().mockResolvedValue(response(200, [withoutLinked]));
    await expect(client(fetchFn).contacts(TOKEN)).rejects.toThrow(
      'profile response failed validation',
    );
  });

  /**
   * Every remaining method, as a table: each is a bearer, a verb, a path and a
   * body, and the thing worth pinning is that none of them addresses anybody but
   * the caller — no path here takes an owner id.
   */
  describe('the wire contract of every method', () => {
    const cases: ReadonlyArray<{
      name: string;
      call: (c: FetchProfileClient) => Promise<unknown>;
      method: string;
      path: string;
      body?: unknown;
      reply?: unknown;
    }> = [
      {
        name: 'family',
        call: (c) => c.family(TOKEN),
        method: 'GET',
        path: '/v1/profile/family',
        reply: [],
      },
      {
        name: 'createFamilyMember',
        call: (c) => c.createFamilyMember(TOKEN, { relation: 'child', name: 'Kid' }),
        method: 'POST',
        path: '/v1/profile/family',
        body: { relation: 'child', name: 'Kid' },
        reply: { id: 'c1' },
      },
      {
        name: 'updateFamilyMember',
        call: (c) => c.updateFamilyMember(TOKEN, 'c1', { relation: 'child', name: 'Kid' }),
        method: 'PUT',
        path: '/v1/profile/family/c1',
        body: { relation: 'child', name: 'Kid' },
        reply: { status: 'ok' },
      },
      {
        name: 'deleteFamilyMember',
        call: (c) => c.deleteFamilyMember(TOKEN, 'c1'),
        method: 'DELETE',
        path: '/v1/profile/family/c1',
        reply: {},
      },
      {
        name: 'contact',
        call: (c) => c.contact(TOKEN, SUMMARY.id),
        method: 'GET',
        path: `/v1/contacts/${SUMMARY.id}`,
        reply: {
          id: SUMMARY.id,
          ownerUserId: PROFILE.userId,
          name: 'Alice',
          email: null,
          phone: null,
          address: null,
          relationship: null,
          professionalKind: null,
          notes: null,
        },
      },
      {
        name: 'createContact',
        call: (c) => c.createContact(TOKEN, { name: 'Alice' }),
        method: 'POST',
        path: '/v1/contacts',
        body: { name: 'Alice' },
        reply: { id: 'f1' },
      },
      {
        name: 'updateContact',
        call: (c) => c.updateContact(TOKEN, 'f1', { name: 'Alice' }),
        method: 'PUT',
        path: '/v1/contacts/f1',
        body: { name: 'Alice' },
        reply: { status: 'ok' },
      },
      {
        name: 'deleteContact',
        call: (c) => c.deleteContact(TOKEN, 'f1'),
        method: 'DELETE',
        path: '/v1/contacts/f1',
        reply: {},
      },
      {
        name: 'roleAssignments',
        call: (c) => c.roleAssignments(TOKEN),
        method: 'GET',
        path: '/v1/role-assignments',
        reply: [],
      },
      {
        name: 'grantRole',
        call: (c) => c.grantRole(TOKEN, { contactId: 'f1', role: 'executor', scopeType: 'estate' }),
        method: 'POST',
        path: '/v1/role-assignments',
        body: { contactId: 'f1', role: 'executor', scopeType: 'estate' },
        reply: { id: 'e1' },
      },
      {
        name: 'revokeRole',
        call: (c) => c.revokeRole(TOKEN, 'e1'),
        method: 'DELETE',
        path: '/v1/role-assignments/e1',
        reply: {},
      },
      {
        name: 'permissions',
        call: (c) => c.permissions(TOKEN, 'e1'),
        method: 'GET',
        path: '/v1/role-assignments/e1/permissions',
        reply: [],
      },
      {
        name: 'grantPermission',
        call: (c) => c.grantPermission(TOKEN, 'e1', { resource: 'contact', action: 'read' }),
        method: 'POST',
        path: '/v1/role-assignments/e1/permissions',
        body: { resource: 'contact', action: 'read' },
        reply: { id: 'g1' },
      },
    ];

    it.each(cases)('$name', async ({ call, method, path, body, reply }) => {
      const fetchFn = jest.fn().mockResolvedValue(response(200, reply ?? {}));
      await call(client(fetchFn));
      const sent = callOf(fetchFn);
      expect(sent.url).toBe(`${BASE}${path}`);
      expect(sent.init.method).toBe(method);
      expect((sent.init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
      if (body === undefined) {
        expect(sent.init.body).toBeUndefined();
      } else {
        expect(JSON.parse(sent.init.body as string)).toEqual(body);
      }
      // No route addresses anyone but the caller: the cross-owner ABAC paths
      // (/v1/profiles/:ownerUserId/...) are a role-holder surface, not this one.
      expect(sent.url).not.toContain('/v1/profiles/');
    });

    it.each(cases)('$name surfaces a refusal rather than a value', async ({ call }) => {
      const fetchFn = jest.fn().mockResolvedValue(response(401, { error: 'unauthorized' }));
      await expect(call(client(fetchFn))).rejects.toMatchObject({
        extensions: { code: 'UNAUTHENTICATED' },
      });
    });
  });

  it('scopes a permission revoke to its assignment on the wire', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(204, {}));
    await client(fetchFn).revokePermission(TOKEN, 'ra-1', 'grant-1');
    const { url, init } = callOf(fetchFn);
    expect(url).toBe(`${BASE}/v1/role-assignments/ra-1/permissions/grant-1`);
    expect(init.method).toBe('DELETE');
  });

  describe('the error firewall', () => {
    it.each([
      [401, 'unauthorized', 'UNAUTHENTICATED'],
      [403, 'stepup_required', 'STEPUP_REQUIRED'],
      [409, 'contact_in_use', 'CONTACT_IN_USE'],
      [409, 'profile_key_retired', 'CONTENT_ERASED'],
      [400, 'invalid_request', 'INVALID_REQUEST'],
    ])('maps %i %s to %s', async (status, token, code) => {
      const fetchFn = jest.fn().mockResolvedValue(response(status, { error: token }));
      await expect(client(fetchFn).contacts(TOKEN)).rejects.toMatchObject({
        extensions: { code },
      });
    });

    it('narrows a 403 forbidden to the uniform not-found', async () => {
      // Every route here is about the caller's own data, so a deny means an id
      // that is not theirs — and "not yours" must stay indistinguishable from
      // "does not exist" or a contact id becomes a probe (the M12 rule).
      const fetchFn = jest.fn().mockResolvedValue(response(403, { error: 'forbidden' }));
      await expect(client(fetchFn).contact(TOKEN, 'someone-elses-id')).rejects.toMatchObject({
        extensions: { code: 'NOT_FOUND' },
      });
    });

    it('never forwards a downstream body, even on an unmapped status', async () => {
      const fetchFn = jest
        .fn()
        .mockResolvedValue(response(500, { error: 'ssn_ct decrypt failed for jane@example.com' }));
      await expect(client(fetchFn).contacts(TOKEN)).rejects.toThrow(
        'profile responded with status 500',
      );
    });

    it('turns a transport failure into a message with no cause in it', async () => {
      const fetchFn = jest.fn().mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:3002'));
      await expect(client(fetchFn).contacts(TOKEN)).rejects.toThrow('profile service unreachable');
    });
  });
});

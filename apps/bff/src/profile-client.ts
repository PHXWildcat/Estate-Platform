import { z } from 'zod';
import { bffError } from './identity-client';

/**
 * Client for the profile & contacts service (apps/services/profile) — the BFF's
 * FOURTH non-identity downstream, on exactly the assets/assistant/documents
 * terms: THE BFF FORWARDS THE CALLER'S OWN BEARER TOKEN, injects no identity
 * header, and holds no credential for profile. The service's Cedar PEP decides
 * every request against the session the browser already had, so a compromised
 * BFF replays the sessions it is currently serving rather than minting new ones.
 *
 * THERE IS NO WRITE PATH FOR THE SSN HERE, AND THAT IS THE POINT. The service
 * accepts `ssn` on its profile upsert; this client has no field for it, so
 * nothing reachable from a browser can set or clear one. The M13 decision is
 * that the people surface displays `ssnLast4` (so an owner can see whether we
 * hold an SSN) and never collects it: no shipped feature reads the full value,
 * and an SSN input on a web surface is a phishing template. Combined with the
 * service's absent-means-unchanged semantics, that makes the column safe from
 * this direction by construction rather than by care — the same reasoning as
 * M12's `Document` type having no `content` field.
 *
 * OWNER-RELATIVE ROUTES ONLY. Every path below is about the caller themselves
 * (`/v1/profile`, `/v1/contacts`, `/v1/role-assignments`). The cross-owner ABAC
 * routes (`/v1/profiles/:ownerUserId/contacts...`) are the docs/03 §5.5
 * delegated-read boundary and belong to a role-holder surface that does not
 * exist yet; naming them here would mean this client knew how to ask about
 * somebody else's estate.
 *
 * Same error contract as the peer clients: downstream response text is NEVER
 * forwarded to GraphQL clients. Recognized machine tokens become stable codes;
 * everything else is a masked generic error.
 */

/**
 * The caller's own profile.
 *
 * `ssnLast4` is the only SSN-shaped value that crosses this boundary, and it is
 * read-only in both senses — the service stores it separately for display
 * (docs/02 §2) and derives it from the full value, which never leaves the
 * service at all.
 */
export const ProfileSchema = z.object({
  userId: z.string().min(1),
  legalName: z.string(),
  dob: z.string().nullable(),
  ssnLast4: z.string().nullable(),
  address: z.string().nullable(),
  phone: z.string().nullable(),
  occupation: z.string().nullable(),
  maritalStatus: z.string().nullable(),
  stateOfResidence: z.string().nullable(),
});
export type Profile = z.infer<typeof ProfileSchema>;

export const FamilyMemberSchema = z.object({
  id: z.string().min(1),
  relation: z.string().min(1),
  name: z.string(),
  dob: z.string().nullable(),
  isMinor: z.boolean().nullable(),
  notes: z.string().nullable(),
});
export type FamilyMember = z.infer<typeof FamilyMemberSchema>;

/**
 * A contact as a LIST returns it: one audited decrypt per row, not five.
 *
 * The `has*` flags come from column nullity downstream, so a list can say what
 * is on file without decrypting it. There are deliberately no `email`, `phone`,
 * `address` or `notes` fields — see `ContactDetailSchema`, and docs/03 §6f for
 * why audited-decrypt volume is an API constraint rather than a nicety.
 */
export const ContactSummarySchema = z.object({
  id: z.string().min(1),
  ownerUserId: z.string().min(1),
  name: z.string(),
  relationship: z.string().nullable(),
  professionalKind: z.string().nullable(),
  hasEmail: z.boolean(),
  hasPhone: z.boolean(),
  hasAddress: z.boolean(),
  hasNotes: z.boolean(),
  /** Whether this contact is a platform user — see `ContactSummary` downstream. */
  linked: z.boolean(),
});
export type ContactSummary = z.infer<typeof ContactSummarySchema>;

/** One contact, decrypted in full. Each read is several audited decrypts. */
export const ContactDetailSchema = z.object({
  id: z.string().min(1),
  ownerUserId: z.string().min(1),
  name: z.string(),
  email: z.string().nullable(),
  phone: z.string().nullable(),
  address: z.string().nullable(),
  relationship: z.string().nullable(),
  professionalKind: z.string().nullable(),
  notes: z.string().nullable(),
});
export type ContactDetail = z.infer<typeof ContactDetailSchema>;

/**
 * A role assignment: WHO is trustee/executor/beneficiary of WHAT.
 *
 * `effectiveCondition` is load-bearing and must not be presented as access.
 * `immediate` means the holder can act now (subject to a permission grant);
 * `on_incapacity` and `on_death_verified` are DESIGNATIONS that confer nothing
 * until settlement resolves them (M7 — designation alone grants nothing).
 */
export const RoleAssignmentSchema = z.object({
  id: z.string().min(1),
  contactId: z.string().min(1),
  role: z.string().min(1),
  scopeType: z.string().min(1),
  scopeId: z.string().nullable(),
  effectiveCondition: z.string().min(1),
  startsAt: z.string().nullable(),
  endsAt: z.string().nullable(),
});
export type RoleAssignment = z.infer<typeof RoleAssignmentSchema>;

export const PermissionGrantSchema = z.object({
  id: z.string().min(1),
  resource: z.string().min(1),
  action: z.string().min(1),
  createdAt: z.string().min(1),
});
export type PermissionGrant = z.infer<typeof PermissionGrantSchema>;

const CreatedSchema = z.object({ id: z.string().min(1) });

/**
 * A profile write. `undefined` means "leave it alone" and `null` means "clear
 * it" — the service's own three-way rule, carried through unchanged, which is
 * what lets a form that holds six fields write six fields.
 *
 * No `ssn`. See the module docstring.
 */
export interface SaveProfileInput {
  readonly legalName: string;
  readonly dob?: string | null;
  readonly address?: string | null;
  readonly phone?: string | null;
  readonly occupation?: string | null;
  readonly maritalStatus?: string | null;
  readonly stateOfResidence?: string | null;
}

export interface ContactInput {
  readonly name: string;
  readonly email?: string;
  readonly phone?: string;
  readonly address?: string;
  readonly relationship?: string;
  readonly professionalKind?: string;
  readonly notes?: string;
}

export interface FamilyMemberInput {
  readonly relation: string;
  readonly name: string;
  readonly dob?: string;
  readonly isMinor?: boolean;
  readonly notes?: string;
}

export interface RoleAssignmentInput {
  readonly contactId: string;
  readonly role: string;
  readonly scopeType: string;
  readonly scopeId?: string;
  readonly effectiveCondition?: string;
}

export interface PermissionGrantInput {
  readonly resource: string;
  readonly action: string;
}

/**
 * A minted link invitation. `code` is the ONLY time this value exists outside
 * the owner's own head: the service stores its sha256 and cannot re-show it, so
 * a client that discards it has to mint another.
 */
export const LinkInvitationSchema = z.object({
  code: z.string().min(8),
  expiresAt: z.string().min(1),
});
export type LinkInvitation = z.infer<typeof LinkInvitationSchema>;

export interface ProfileClient {
  /** The caller's own profile, or null when they have never saved one. */
  profile(accessToken: string): Promise<Profile | null>;
  saveProfile(accessToken: string, input: SaveProfileInput): Promise<void>;
  family(accessToken: string): Promise<FamilyMember[]>;
  createFamilyMember(accessToken: string, input: FamilyMemberInput): Promise<string>;
  updateFamilyMember(accessToken: string, id: string, input: FamilyMemberInput): Promise<void>;
  deleteFamilyMember(accessToken: string, id: string): Promise<void>;
  contacts(accessToken: string): Promise<ContactSummary[]>;
  contact(accessToken: string, contactId: string): Promise<ContactDetail>;
  createContact(accessToken: string, input: ContactInput): Promise<string>;
  updateContact(accessToken: string, contactId: string, input: ContactInput): Promise<void>;
  deleteContact(accessToken: string, contactId: string): Promise<void>;
  roleAssignments(accessToken: string): Promise<RoleAssignment[]>;
  grantRole(accessToken: string, input: RoleAssignmentInput): Promise<string>;
  revokeRole(accessToken: string, roleAssignmentId: string): Promise<void>;
  permissions(accessToken: string, roleAssignmentId: string): Promise<PermissionGrant[]>;
  grantPermission(
    accessToken: string,
    roleAssignmentId: string,
    input: PermissionGrantInput,
  ): Promise<string>;
  revokePermission(accessToken: string, roleAssignmentId: string, grantId: string): Promise<void>;
  /** Mint a single-use link code. STEP-UP GATED downstream. */
  inviteLink(accessToken: string, contactId: string): Promise<LinkInvitation>;
  revokeLinkInvitation(accessToken: string, contactId: string): Promise<void>;
  unlink(accessToken: string, contactId: string): Promise<void>;
  /** Redeem a code as the person being linked. Takes NO id — see the service. */
  redeemLink(accessToken: string, code: string): Promise<void>;
}

type FetchFn = (input: string, init: RequestInit) => Promise<Response>;
type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

export class FetchProfileClient implements ProfileClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  /**
   * A user who never saved a profile gets `404 not_found` from the service, and
   * that is a REAL ANSWER — "nothing on file" — not an outage. The assistant's
   * own profile client learned this the hard way in M10 (reading it as a failure
   * made three analyses a permanent 503 for anyone who skipped onboarding), so
   * exactly that token maps to null and every other failure still throws.
   */
  async profile(accessToken: string): Promise<Profile | null> {
    const res = await this.request('GET', '/v1/profile', accessToken);
    if (res.status === 404) {
      const token = await errorTokenOf(res);
      if (token === 'not_found') {
        return null;
      }
    }
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, ProfileSchema);
  }

  async saveProfile(accessToken: string, input: SaveProfileInput): Promise<void> {
    // Only the keys the caller actually supplied travel: an absent key is the
    // service's "leave it alone", and JSON.stringify drops undefined values, so
    // this object shape IS the merge semantics.
    await this.send('PUT', '/v1/profile', accessToken, { ...input });
  }

  async family(accessToken: string): Promise<FamilyMember[]> {
    const res = await this.request('GET', '/v1/profile/family', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(FamilyMemberSchema));
  }

  createFamilyMember(accessToken: string, input: FamilyMemberInput): Promise<string> {
    return this.created('POST', '/v1/profile/family', accessToken, { ...input });
  }

  async updateFamilyMember(
    accessToken: string,
    id: string,
    input: FamilyMemberInput,
  ): Promise<void> {
    await this.send('PUT', `/v1/profile/family/${encodeURIComponent(id)}`, accessToken, {
      ...input,
    });
  }

  async deleteFamilyMember(accessToken: string, id: string): Promise<void> {
    await this.send('DELETE', `/v1/profile/family/${encodeURIComponent(id)}`, accessToken);
  }

  async contacts(accessToken: string): Promise<ContactSummary[]> {
    const res = await this.request('GET', '/v1/contacts', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(ContactSummarySchema));
  }

  async contact(accessToken: string, contactId: string): Promise<ContactDetail> {
    const res = await this.request(
      'GET',
      `/v1/contacts/${encodeURIComponent(contactId)}`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, ContactDetailSchema);
  }

  createContact(accessToken: string, input: ContactInput): Promise<string> {
    return this.created('POST', '/v1/contacts', accessToken, { ...input });
  }

  async updateContact(accessToken: string, contactId: string, input: ContactInput): Promise<void> {
    await this.send('PUT', `/v1/contacts/${encodeURIComponent(contactId)}`, accessToken, {
      ...input,
    });
  }

  async deleteContact(accessToken: string, contactId: string): Promise<void> {
    await this.send('DELETE', `/v1/contacts/${encodeURIComponent(contactId)}`, accessToken);
  }

  async roleAssignments(accessToken: string): Promise<RoleAssignment[]> {
    const res = await this.request('GET', '/v1/role-assignments', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(RoleAssignmentSchema));
  }

  grantRole(accessToken: string, input: RoleAssignmentInput): Promise<string> {
    return this.created('POST', '/v1/role-assignments', accessToken, { ...input });
  }

  async revokeRole(accessToken: string, roleAssignmentId: string): Promise<void> {
    await this.send(
      'DELETE',
      `/v1/role-assignments/${encodeURIComponent(roleAssignmentId)}`,
      accessToken,
    );
  }

  async permissions(accessToken: string, roleAssignmentId: string): Promise<PermissionGrant[]> {
    const res = await this.request(
      'GET',
      `/v1/role-assignments/${encodeURIComponent(roleAssignmentId)}/permissions`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(PermissionGrantSchema));
  }

  grantPermission(
    accessToken: string,
    roleAssignmentId: string,
    input: PermissionGrantInput,
  ): Promise<string> {
    return this.created(
      'POST',
      `/v1/role-assignments/${encodeURIComponent(roleAssignmentId)}/permissions`,
      accessToken,
      { ...input },
    );
  }

  async revokePermission(
    accessToken: string,
    roleAssignmentId: string,
    grantId: string,
  ): Promise<void> {
    await this.send(
      'DELETE',
      `/v1/role-assignments/${encodeURIComponent(roleAssignmentId)}/permissions/${encodeURIComponent(grantId)}`,
      accessToken,
    );
  }

  async inviteLink(accessToken: string, contactId: string): Promise<LinkInvitation> {
    const res = await this.request(
      'POST',
      `/v1/contacts/${encodeURIComponent(contactId)}/link-invitation`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, LinkInvitationSchema);
  }

  async revokeLinkInvitation(accessToken: string, contactId: string): Promise<void> {
    await this.send(
      'DELETE',
      `/v1/contacts/${encodeURIComponent(contactId)}/link-invitation`,
      accessToken,
    );
  }

  async unlink(accessToken: string, contactId: string): Promise<void> {
    await this.send('DELETE', `/v1/contacts/${encodeURIComponent(contactId)}/link`, accessToken);
  }

  /**
   * The code is the whole request: no owner id, no contact id, nothing to name
   * an account with (docs/03 §6b). The response carries no estate data either,
   * so a stolen code cannot become a read.
   */
  async redeemLink(accessToken: string, code: string): Promise<void> {
    await this.send('POST', '/v1/contact-links/redeem', accessToken, { code });
  }

  private async created(
    method: Method,
    path: string,
    accessToken: string,
    body: Record<string, unknown>,
  ): Promise<string> {
    const res = await this.request(method, path, accessToken, body);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, CreatedSchema)).id;
  }

  private async send(
    method: Method,
    path: string,
    accessToken: string,
    body?: Record<string, unknown>,
  ): Promise<void> {
    const res = await this.request(method, path, accessToken, body);
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  private async request(
    method: Method,
    path: string,
    accessToken: string,
    body?: Record<string, unknown>,
  ): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    try {
      return await this.fetchFn(`${this.baseUrl}${path}`, init);
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('profile service unreachable');
    }
  }

  private async mapError(res: Response): Promise<Error> {
    const token = await errorTokenOf(res);
    if (res.status === 401) {
      return bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    /*
     * A 403 becomes the uniform not-found AT THE EDGE, the M12 rule. Every route
     * this client calls is about the caller's own data, so a deny here means an
     * id that is not theirs — and "not yours" and "does not exist" must stay
     * indistinguishable or a contact id becomes a probe. The service's own
     * 404-vs-403 distinction is unchanged; this is the edge narrowing it.
     */
    if (res.status === 403 || res.status === 404) {
      return bffError('NOT_FOUND');
    }
    /*
     * The two 409s stay apart because the remedies are opposite. `contact_in_use`
     * is actionable — revoke the roles naming this contact and try again — and it
     * exists because deleting a contact used to silently retire its fiduciary
     * designations. `profile_key_retired` means the row's DEK was destroyed
     * (crypto-shredded), so no retry will ever work and offering one would be a
     * lie about erased data.
     */
    if (res.status === 409 && token === 'contact_in_use') {
      return bffError('CONTACT_IN_USE');
    }
    /*
     * The two "you already did that" conflicts. Migration 004 and 005 promised
     * these would surface as ORDINARY REFUSALS rather than a 500 — a promise this
     * mapping is what keeps: without a case here they fall through to a plain
     * Error, yoga masks it, and a double click reads as "something went wrong on
     * our side" for something the user did nothing wrong to cause.
     */
    if (res.status === 409 && token === 'role_already_granted') {
      return bffError('ROLE_ALREADY_GRANTED');
    }
    if (res.status === 409 && token === 'permission_already_granted') {
      return bffError('PERMISSION_ALREADY_GRANTED');
    }
    if (res.status === 409 && token === 'already_linked') {
      return bffError('ALREADY_LINKED');
    }
    /*
     * `invalid_code` is the service's ONE answer for every failed redemption —
     * unknown, expired, spent, revoked, self-directed. It is forwarded as one
     * code for the same reason: distinguishing them would tell whoever is
     * holding a guess that their guess named something real.
     */
    if (res.status === 400 && token === 'invalid_code') {
      return bffError('INVALID_LINK_CODE');
    }
    if (res.status === 503 && token === 'notifications_unavailable') {
      return bffError('NOTIFICATIONS_UNAVAILABLE');
    }
    if (res.status === 409 && token === 'profile_key_retired') {
      return bffError('CONTENT_ERASED');
    }
    /*
     * A grant the platform does not implement. Kept apart from the generic
     * INVALID_REQUEST below — which is where it would otherwise land, 422 being
     * a parse failure everywhere else on this client — because the remedies are
     * nothing alike: a malformed body is a bug in the caller, and this is a
     * capability the platform does not have yet. Reachable only by a client
     * that has drifted ahead of the service (the people surface offers exactly
     * what is enforced), which is precisely when a legible answer is worth
     * having.
     */
    if (res.status === 422 && token === 'grant_not_enforced') {
      return bffError('GRANT_NOT_ENFORCED');
    }
    if (res.status === 400 || res.status === 422) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`profile responded with status ${res.status}`);
  }

  private async parseBody<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('profile response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Field paths only — never response values.
      throw new Error('profile response failed validation');
    }
    return parsed.data as z.infer<T>;
  }
}

/** The machine token from an error body, or '' when there is not one. */
async function errorTokenOf(res: Response): Promise<string> {
  try {
    const parsed = z.object({ error: z.string() }).safeParse(await res.clone().json());
    return parsed.success ? parsed.data.error : '';
  } catch {
    return '';
  }
}

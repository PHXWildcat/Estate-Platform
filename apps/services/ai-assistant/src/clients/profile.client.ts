import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { ABSENT, defaultFetch, readJson, readJsonOrAbsent, type FetchLike } from './http';

/**
 * Read-only client for the profile service (apps/services/profile), forwarding
 * the caller's own bearer on every call.
 *
 * THE NARROWING HAPPENS HERE, AND ONLY HERE. `GET /v1/profile` returns the
 * caller's full Zone B profile — legal name, date of birth, SSN last four,
 * address, phone, occupation — because the owner is entitled to their own
 * record. The assistant is not, and does not need to be: estate-planning advice
 * turns on WHICH STATE the user lives in and WHETHER THEY ARE MARRIED, and
 * nothing else on that row changes an answer. So this client drops the rest
 * before it exists as a value in this process. zod strips unknown keys, so the
 * schema below is the enforcement, not a convention — a future tool can only
 * widen this by editing this file, which is exactly the review it deserves.
 *
 * Keeping the identifiers out of the process at all (rather than out of the
 * prompt) is what makes the property hold under the threat this service lives
 * with: the model's context contains untrusted document text (docs/03 §4 TB5,
 * risk #6), and an injected instruction cannot exfiltrate a field the assistant
 * never fetched. It also keeps this service off the docs/03 §5.3 bulk-decrypt
 * path — every profile decrypt is a logged event in profile's own audit trail,
 * and the assistant asks for the two least sensitive fields on the row.
 *
 * Every failure — network, non-2xx, non-JSON, schema drift — is `null`, meaning
 * "this read did not happen". The rationale lives on `readJson`: these reads
 * feed a model, so a partially-understood response must read as no data rather
 * than as data.
 *
 * ONE deliberate exception (M10 PR3, found by the stack e2e's first live run):
 * profile answers `404 {error: 'not_found'}` for a user who never created a
 * profile row, and that is a REAL ANSWER — "nothing on file" — not an outage.
 * Reading it as a failure made three analyses and the profile-facts tool a
 * permanent 503 for every user who skipped profile onboarding, which is a
 * different sentence entirely from the true one ("state of residence unknown").
 * So `facts()` maps exactly that token to the empty facts view; every OTHER
 * failure, including a route-level 404 with Nest's default body, stays null
 * (`readJsonOrAbsent` documents the discrimination).
 */

/**
 * The only profile facts the assistant may hold.
 *
 * DELIBERATELY ABSENT, and this list is the specification: `legalName`, `dob`,
 * `ssnLast4`, `address`, `phone`, `occupation`. Each is on the wire from
 * profile and each is discarded by this schema. Nothing here identifies a
 * person; both fields are the sort of thing a paralegal would ask before
 * naming a form.
 */
const ProfileFactsViewSchema = z.object({
  stateOfResidence: z.string().nullable(),
  maritalStatus: z.string().nullable(),
});
export type ProfileFactsView = z.infer<typeof ProfileFactsViewSchema>;

/**
 * A family member, narrowed to STRUCTURE rather than identity.
 *
 * `name`, `dob` and `notes` are on the wire and deliberately dropped, by the
 * same rule that governs the owner's own facts above — a third party's name and
 * birth date are no more the assistant's business than the owner's are, and
 * arguably less, since that person never agreed to anything. What planning
 * actually turns on is structural: is there a spouse, is there a minor child
 * who needs a guardian named. `id` survives so a consumer can correlate a
 * finding back to a row; if a sentence needs to name someone, the right move is
 * to ask the user, not to widen this schema.
 */
const FamilyMemberViewSchema = z.object({
  id: z.string().min(1),
  relation: z.string().min(1),
  /** Null when the member's date of birth is unknown, so minority is unknown. */
  isMinor: z.boolean().nullable(),
});
export type FamilyMemberView = z.infer<typeof FamilyMemberViewSchema>;

const FamilyListSchema = z.array(FamilyMemberViewSchema);

@Injectable()
export class ProfileClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(profileUrl: string, fetchImpl?: FetchLike) {
    // Exactly one trailing slash (the house idiom).
    this.baseUrl = profileUrl.replace(/\/$/, '');
    this.fetchImpl = fetchImpl ?? defaultFetch;
  }

  /** State of residence and marital status. Nothing identifying — see above. */
  async facts(bearer: string): Promise<ProfileFactsView | null> {
    const result = await readJsonOrAbsent(
      this.fetchImpl,
      `${this.baseUrl}/v1/profile`,
      bearer,
      ProfileFactsViewSchema,
    );
    if (result === ABSENT) {
      // No profile row is the true answer "nothing on file", which the
      // analysers already know how to say ("state of residence unknown") —
      // see the module docstring for why this is not a fail-open.
      return { stateOfResidence: null, maritalStatus: null };
    }
    return result;
  }

  /** Household structure: relations and minority, never names or birth dates. */
  family(bearer: string): Promise<FamilyMemberView[] | null> {
    return readJson(this.fetchImpl, `${this.baseUrl}/v1/profile/family`, bearer, FamilyListSchema);
  }
}

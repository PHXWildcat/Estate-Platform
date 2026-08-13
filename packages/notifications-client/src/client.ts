import { z } from 'zod';

/** DI token consumers use to inject the client (or a test double). */
export const NOTIFICATIONS = Symbol('NOTIFICATIONS');

/** Header carrying the service credential. Mirrors @estate/auth-guard's
 * constant; duplicated rather than imported so this package keeps a
 * zero-workspace-dependency tree (the settlement-client precedent). */
export const SERVICE_CREDENTIAL_HEADER = 'x-estate-service-credential';

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * ESTATE notifications: the closed set of things a SEND holder can make the
 * platform say. Adding a kind means adding a template in the notifications
 * service — there is deliberately NO free-text field anywhere on this wire, so
 * no caller can put estate content into a carrier message (docs/03 §5.4:
 * emails/SMS are content-free pointers).
 */
export const ESTATE_NOTIFICATION_KINDS = [
  'emergency.requested',
  'emergency.blocked',
  'emergency.reminder',
  'emergency.released',
  'emergency.revoked',
  'vault.reset',
  'vault.grantees_changed',
  'settlement.case_opened',
  'settlement.owner_contact',
  // M13: somebody claimed a link to this owner's estate contact, which is the
  // moment they become able to open a death case against them (docs/03 §6b).
  'contact.link_claimed',
] as const;
export type EstateNotificationKind = (typeof ESTATE_NOTIFICATION_KINDS)[number];

/**
 * SYSTEM notifications: kinds that are NOT reachable through `send`.
 *
 * M14's address verification is the first and only one, and the separation is
 * the control rather than tidiness. Its template needs a CODE, so a caller who
 * could name it on the send route would render a message with `undefined`
 * where the code belongs — a "here is your Estate verification code:
 * undefined" mail, authored by whichever service holds the broadly-held send
 * credential. It travels on its own route, behind its own credential
 * (`NOTIFICATIONS_VERIFY_INTERNAL_TOKEN`, identity alone), with its own typed
 * input; `SendSchema` in the notifications service is built from
 * ESTATE_NOTIFICATION_KINDS so the exclusion is structural, not a comment.
 */
export const SYSTEM_NOTIFICATION_KINDS = [
  'identity.address_verification',
  // M17: the account's own credentials changed. A SYSTEM kind for the reason
  // above turned the other way round — this one carries no variable at all, but
  // it must not be reachable through `send`, because that credential is held by
  // vault, settlement and profile and none of them has any business telling a
  // user their password was changed. It is the one message an attacker would
  // most like to be able to send: it is exactly what a phishing pretext looks
  // like, and a user who receives it acts on it.
  'identity.password_changed',
  // M17 PR3: the mailed password-reset code. A system kind for the first
  // reason above — its template needs a CODE, so a caller who could name it on
  // the estate send wire would render "enter this code: undefined".
  'identity.password_reset',
  // M17 PR4: the email-change challenge code, mailed to a PROSPECTIVE address.
  // A system kind for both reasons at once: its template needs a code, and its
  // wire is the only one that names a destination — the last thing an estate
  // send holder may ever choose.
  'identity.email_change',
  // M17 PR4: "your sign-in address was changed", sent to the address being
  // LEFT — the only recipient who can dispute a takeover. Carries nothing.
  'identity.email_changed',
] as const;
export type SystemNotificationKind = (typeof SYSTEM_NOTIFICATION_KINDS)[number];

/**
 * The ACCOUNT-SECURITY kinds — the subset of system kinds that
 * `NOTIFICATIONS_SECURITY_INTERNAL_TOKEN` opens (M17).
 *
 * A subset rather than "all system kinds", and the distinction is the whole
 * reason this is a separate edge: `identity.address_verification` needs a code
 * and travels on the VERIFY credential, while these say something happened to
 * the account and carry nothing. A holder of one must not inherit the other —
 * the M14 reasoning that split VERIFY from RECIPIENTS, applied before the
 * second holder exists rather than after.
 */
export const ACCOUNT_SECURITY_KINDS = [
  'identity.password_changed',
  // M17 PR4: the change-of-address notice. It rides THIS wire and not the new
  // email-change one because it carries nothing — no code, no address, no
  // timestamp — and because WHO IT REACHES is an ordering property, not a wire
  // property: identity sends it BEFORE the recipient store is repointed, so the
  // store still resolves the address being LEFT, which is the only mailbox
  // whose reader can dispute a takeover. A route that could name the old
  // address explicitly would be a route that names destinations, and only the
  // challenge wire is allowed to do that.
  'identity.email_changed',
] as const;
export type AccountSecurityKind = (typeof ACCOUNT_SECURITY_KINDS)[number];

/**
 * The RECOVERY kind (M17 PR3) — deliberately its own one-member list rather
 * than a member of `ACCOUNT_SECURITY_KINDS`.
 *
 * That list's wire carries no variables at all, which is the property that
 * makes it safe for a holder who should never choose what a user reads. This
 * one carries a code. Keeping them apart is what lets each of the four send
 * routes on the notifications service build its schema from its own closed
 * list, so no holder of one credential can fire another's vocabulary.
 */
export const RECOVERY_KINDS = ['identity.password_reset'] as const;
export type RecoveryKind = (typeof RECOVERY_KINDS)[number];

/**
 * The shape a RESET code may take on the wire (M17 PR3), beside
 * `VERIFICATION_CODE_PATTERN` and for the identical reason: the M14 review
 * found the two ends of that ceremony disagreeing, so the pattern lives in the
 * contract both import rather than being written twice. Anchored on its own
 * prefix, so a verification code cannot be mailed as a reset code or the
 * reverse.
 */
export const RESET_CODE_PATTERN = /^PR1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/;

/**
 * The EMAIL-CHANGE kind (M17 PR4) — its own one-member list on the same
 * reasoning as `RECOVERY_KINDS`: each send route on the notifications service
 * builds its schema from its own closed list, so no holder of one credential
 * can fire another's vocabulary. This one's wire is the only one that NAMES A
 * DESTINATION, which is exactly why it must not share a list with anything.
 */
export const EMAIL_CHANGE_KINDS = ['identity.email_change'] as const;
export type EmailChangeKind = (typeof EMAIL_CHANGE_KINDS)[number];

/**
 * The shape an email-change code may take on the wire (M17 PR4), beside its
 * two siblings and for their reason: one declaration both ends import, so the
 * mint and the route cannot drift. Anchored on its own prefix, so this route
 * cannot mail a verification or reset code and neither of those can mail this.
 */
export const EMAIL_CHANGE_CODE_PATTERN = /^EC1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/;

/**
 * One user id, one opaque platform-minted single-use reset code, and the kind
 * that code is being mailed AS.
 *
 * `kind` is carried even though `RECOVERY_KINDS` has one member today, because
 * it is what `notification_sends.kind` records, and a route that INFERS the
 * kind logs what it assumed rather than what the caller asked for. That matches
 * `sendAccountSecurity`, its sibling from the same milestone, and deliberately
 * NOT `sendAddressVerification`, where M14 let the route supply the kind — the
 * asymmetry is noted rather than propagated, since changing a shipped wire to
 * match a new one is a change to M14. It also means a second
 * recovery kind arrives as a compile error at each call site instead of
 * silently inheriting the first one's template.
 */
export interface PasswordResetInput {
  userId: string;
  code: string;
  kind: RecoveryKind;
}

/**
 * Every kind the platform can log a send for. This is the vocabulary of
 * `notification_sends.kind` — its DDL CHECK is derived from this list and an
 * int spec drives every member, because M13 added a kind here and not there and
 * the mismatch mailed owners while telling their audit trail it had not.
 */
export const NOTIFICATION_KINDS = [
  ...ESTATE_NOTIFICATION_KINDS,
  ...SYSTEM_NOTIFICATION_KINDS,
] as const;
export type NotificationKind = (typeof NOTIFICATION_KINDS)[number];

/**
 * The channel the CALLER asked for (settlement's contact sweep cycles these).
 * Delivery this milestone is email-only: the service substitutes and reports
 * the channel it actually used, and the caller records that truth.
 */
export const NOTIFICATION_CHANNELS = ['email', 'push', 'sms', 'voice'] as const;
export type NotificationChannel = (typeof NOTIFICATION_CHANNELS)[number];

export interface NotificationSendInput {
  /** The recipient, as a user id. Address resolution happens inside the
   * notifications service against its own encrypted recipient store — no
   * caller ever handles an address. */
  userId: string;
  kind: EstateNotificationKind;
  channel?: NotificationChannel;
  /** Deadline the notification may state (waiting-period end). The one piece
   * of variable data an ESTATE template may carry, per the M6/M7 port
   * contracts. */
  deadline?: Date;
}

/**
 * The address-verification send (M14). Its own input type, its own route and
 * its own credential — see SYSTEM_NOTIFICATION_KINDS.
 *
 * `code` is the SECOND piece of variable data the platform has ever put in a
 * carrier message, and the first that is not a date. That is an approved
 * deviation from M9's content doctrine, recorded in docs/03 §6c: it is
 * PLATFORM-AUTHORED (minted by identity from `randomBytes`, never derived from
 * anything the user wrote), it is opaque, it carries no estate fact, and it is
 * single-use and short-lived. It is a `code` and never a `text` field
 * precisely so the doctrine's real property survives — no caller has anywhere
 * to put prose. "We never link you" is also untouched: the template states the
 * code and tells the reader to type it into the app.
 */
export interface AddressVerificationInput {
  userId: string;
  code: string;
}

/**
 * An account-security notice (M17). A user id and a CLOSED kind — no text, no
 * code, no timestamp, no deadline.
 *
 * The absence of a date field is deliberate and slightly awkward: "your
 * password was changed" would read better with a time in it, and the moment
 * this wire carries one it carries a variable a caller chooses. The message
 * says to sign in and check, which is what a recipient should do anyway and
 * cannot be faked into a plausible-looking lie.
 */
export interface AccountSecurityInput {
  userId: string;
  kind: AccountSecurityKind;
}

/**
 * The email-change challenge send (M17 PR4): mail one platform-minted code to
 * a PROSPECTIVE address — one the platform does not yet hold for this user.
 *
 * `email` IS THE DESTINATION AND NOTHING ELSE. It is the one field on any
 * notifications wire that names where a message goes: every other send
 * resolves its destination from the encrypted recipient store by user id (the
 * M9 design), and this ceremony is by definition a challenge to a mailbox the
 * store does not hold, so the destination cannot come from anywhere but the
 * caller. What keeps that from widening the content doctrine: the address is
 * the SMTP envelope, never the body — the body carries the code and the
 * platform's fixed words, exactly like its two siblings — and the
 * notifications service uses it for this one delivery and STORES NOTHING (no
 * recipient row is created, read or touched; the store keeps pointing at the
 * proven old address until identity replaces it after the proof).
 */
export interface EmailChangeInput {
  userId: string;
  kind: EmailChangeKind;
  code: string;
  email: string;
}

/**
 * Replace a user's delivery address with one the ceremony JUST PROVED (M17
 * PR4). Rides the RECIPIENTS credential: repointing an address and vouching
 * for one are the same capability class (M14 decision 5), and this is both at
 * once — which is the point. The M14 forward commitment said an address-change
 * route "must clear `verified_at` in the same statement, or the platform will
 * vouch for an address nobody proved"; replacement discharges it one step
 * stronger, because the new address arrives already proved and the old proof
 * leaves in the same UPDATE. There is no moment when the store vouches for an
 * address nobody proved, and no moment when a proven address reads unverified.
 */
export interface ReplaceRecipientInput {
  userId: string;
  email: string;
}

/**
 * The exact shape a verification code may take ON THE WIRE.
 *
 * IT LIVES HERE, in the wire contract both services import, because the M14
 * review found the two ends disagreeing: notifications validated
 * `/^[0-9A-Z-]+$/` with a 64-character cap while identity mints Crockford
 * base32 (no I, L, O or U), so the route accepted 64 characters of readable
 * uppercase English and `renderAddressVerification` interpolated it verbatim
 * into a real message from the platform's verified sender. A free-text field
 * by another name, in the one wire the content doctrine exists to keep
 * text-free.
 *
 * The obvious fix — tighten notifications' regex — was rejected on identity's
 * own stated reasoning that a second pattern "would only add a second place
 * for the alphabet to drift". One shared declaration is the version of that
 * fix without the drift: notifications validates against it, and identity has
 * a spec asserting every code it mints satisfies it, so a change to either end
 * fails a test instead of silently widening what may be mailed.
 *
 * NOTIFICATIONS MUST STILL VALIDATE IT ITSELF. The doctrine is a property of
 * the delivery boundary, and the credential model is that a bearer of a secret
 * IS the service — so "identity would never send prose" is not something the
 * notifications service may assume about its caller.
 */
export const VERIFICATION_CODE_PATTERN = /^EV1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/;

/**
 * What the delivery store knows about reaching a user.
 *
 * `verified` answers the question three shipped fail-closed gates have always
 * ASSUMED and never asked: not "is a carrier wired" (that is
 * `deliversToRealChannels`, a property of the adapter that cannot be wrong
 * about a recipient because it never looks at one), but "did the person who
 * owns this account prove they receive mail at the address we would use".
 */
export interface RecipientStatus {
  readonly verified: boolean;
}

/**
 * What happened to a send. `accepted: false` means the request never reached a
 * healthy notifications service (unwired credential, network failure, non-2xx,
 * contract drift); `delivered: false` means the service answered but could not
 * deliver (no recipient on record, carrier refusal). Callers record either as
 * a non-delivery — this client NEVER throws, because a notification failure
 * must not roll back the state change it describes (the M6 design).
 */
export type SendOutcome =
  | {
      accepted: true;
      delivered: boolean;
      channel: string;
      /**
       * Whether the address this was sent to had been PROVED by the user (M14).
       *
       * It rides the send response so a caller that proceeds on an unverified
       * recipient can record that fact on its own audit trail without holding
       * the status credential — settlement is the case that matters: its §5.1
       * gates proceed and record, so it must never need to ask the question
       * separately.
       *
       * `false` also covers "the service could not tell", which is the safe
       * reading: a caller records that it could not confirm reach, never that
       * it could.
       */
      recipientVerified: boolean;
    }
  | { accepted: false };

export interface NotificationsPort {
  send(input: NotificationSendInput): Promise<SendOutcome>;
  /** Registers/refreshes the user's delivery address. Identity calls this at
   * registration and login — two of the three moments the user themselves
   * supplies the plaintext email (the third, the M17 PR4 change ceremony, goes
   * through `replaceRecipient` because it also carries a proof) — so no
   * service ever needs a ciphertext read path. */
  upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }>;
  /** Mail one address-verification code. Identity alone; its own credential. */
  sendAddressVerification(input: AddressVerificationInput): Promise<SendOutcome>;
  /**
   * Tell a user something changed about their ACCOUNT's credentials (M17).
   * Identity alone, on its own credential — not the estate send one, which
   * vault, settlement and profile hold.
   *
   * The input carries a user id and a CLOSED kind and nothing else: there is no
   * field for text, no field for a code, and no field for a timestamp, so a
   * holder chooses which of a closed set of platform-authored notices fires and
   * nothing about what it says.
   */
  sendAccountSecurity(input: AccountSecurityInput): Promise<SendOutcome>;
  /**
   * Mail one password-reset code (M17 PR3). Identity alone, on its own
   * credential — the most powerful of the mail-something grants, because
   * redeeming what it sends needs no session.
   */
  sendPasswordReset(input: PasswordResetInput): Promise<SendOutcome>;
  /**
   * Mail one email-change challenge code to a PROSPECTIVE address (M17 PR4).
   * Identity alone, on its own credential: this is the ONE send whose payload
   * names a destination, so its holder set must be exactly the service that
   * runs the ceremony and nothing that merely sends.
   */
  sendEmailChange(input: EmailChangeInput): Promise<SendOutcome>;
  /**
   * Replace the delivery address with one the ceremony just proved (M17 PR4).
   * Identity alone, on the RECIPIENTS credential — see `ReplaceRecipientInput`
   * for why replacement, not clear-then-upsert.
   */
  replaceRecipient(input: ReplaceRecipientInput): Promise<{ ok: boolean }>;
  /** Record that the user proved ownership of the stored address. Identity
   * alone, on the SAME credential as `upsertRecipient` — vouching for an
   * address and setting one are the same capability class (M14 decision 5). */
  markRecipientVerified(input: { userId: string }): Promise<{ ok: boolean }>;
  /**
   * Ask the delivery store whether it can reach a user provably.
   *
   * `null` means UNANSWERABLE — no credential, network failure, non-2xx,
   * contract drift — and is deliberately NOT collapsed into
   * `{verified: false}`. This is the first network round trip the M6/M7/M13
   * notification gates have ever made, so before M14 the check could not fail
   * and no call site had an error path for it. Making the two outcomes
   * distinct forces each caller to write down what an outage means for its own
   * gate rather than letting a thrown exception decide; the arming gates
   * treat both as "refuse", which is a decision they state rather than inherit.
   */
  recipientStatus(userId: string): Promise<RecipientStatus | null>;
}

const SendResponseSchema = z.object({
  delivered: z.boolean(),
  channel: z.string().min(1),
  // M14. `.default(false)` rather than required, so a client talking to a
  // notifications service that predates the field degrades to "could not
  // confirm" instead of narrowing the whole send to contract drift. The safe
  // direction: a caller records that it could not confirm reach, never that it
  // could.
  recipientVerified: z.boolean().default(false),
});

const UpsertResponseSchema = z.object({ ok: z.literal(true) });

const StatusResponseSchema = z.object({ verified: z.boolean() });

/**
 * The credentials a caller holds, ONE PER EDGE.
 *
 * Seven now, and each field is a separate capability the credential graph
 * grants separately — no service holds more than a few, and every field is
 * optional
 * because an absent credential is the normal state for a service that does not
 * hold that edge. A method whose credential is missing short-circuits to its
 * failure outcome WITHOUT a round trip, so an over-broad client is a
 * configuration that cannot reach the route rather than one that reaches it
 * and is rejected.
 *
 * They are separate fields and not one string because that single string is
 * precisely what the M9 security review found: send and recipient-upsert
 * shared one secret, so vault's copy could repoint any owner's address.
 */
export interface NotificationsCredentials {
  /** NOTIFICATIONS_INTERNAL_TOKEN — fire an estate template kind. */
  send?: string;
  /** NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN — set the address, vouch for it. */
  recipients?: string;
  /** NOTIFICATIONS_VERIFY_INTERNAL_TOKEN — mail one verification code. */
  verification?: string;
  /** NOTIFICATIONS_STATUS_INTERNAL_TOKEN — read the verified bit. */
  status?: string;
  /** NOTIFICATIONS_SECURITY_INTERNAL_TOKEN — mail one account-security notice. */
  security?: string;
  /** NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN — mail one password-reset code. */
  recovery?: string;
  /** NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN — mail one change challenge to
   * a prospective address. The one send credential that names a destination. */
  emailChange?: string;
}

export interface HttpNotificationsClientOptions {
  /** Base URL of the notifications service (e.g. http://notifications:3008). */
  notificationsUrl: string;
  credentials?: NotificationsCredentials;
  fetchImpl?: FetchLike;
}

const NOT_ACCEPTED: SendOutcome = { accepted: false };

/**
 * HTTP implementation against the notifications service's internal routes.
 * Every failure narrows to an outcome, never an exception: senders (vault,
 * settlement) treat notification delivery as best-effort-and-recorded, and
 * identity's recipient upsert is best-effort by design (a notifications
 * outage must not block registration or login).
 */
export class HttpNotificationsClient implements NotificationsPort {
  private readonly notificationsUrl: string;
  private readonly credentials: NotificationsCredentials;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpNotificationsClientOptions) {
    this.notificationsUrl = options.notificationsUrl.replace(/\/$/, '');
    this.credentials = options.credentials ?? {};
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /** Request + parse, or null on ANY failure — including an unheld credential. */
  private async requestJson(
    credential: string | undefined,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (!credential) {
      // No round trip: a service that does not hold this edge must not even
      // announce itself to the route (and a blank header would be rejected
      // anyway — the guard fails closed on '').
      return null;
    }
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.notificationsUrl}${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          [SERVICE_CREDENTIAL_HEADER]: credential,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      return null; // network/DNS failure ⇒ the outcome, not an exception
    }
    if (!response.ok) {
      return null;
    }
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  private static outcomeOf(body: unknown): SendOutcome {
    const parsed = SendResponseSchema.safeParse(body);
    if (!parsed.success) {
      return NOT_ACCEPTED; // contract drift ⇒ recorded as not sent, never guessed
    }
    return {
      accepted: true,
      delivered: parsed.data.delivered,
      channel: parsed.data.channel,
      recipientVerified: parsed.data.recipientVerified,
    };
  }

  async send(input: NotificationSendInput): Promise<SendOutcome> {
    const payload = {
      userId: input.userId,
      kind: input.kind,
      channel: input.channel ?? 'email',
      ...(input.deadline !== undefined ? { deadline: input.deadline.toISOString() } : {}),
    };
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.send,
        'POST',
        '/internal/v1/notifications/send',
        payload,
      ),
    );
  }

  async upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }> {
    const body = await this.requestJson(
      this.credentials.recipients,
      'PUT',
      '/internal/v1/notifications/recipients',
      { userId: input.userId, email: input.email },
    );
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }

  async markRecipientVerified(input: { userId: string }): Promise<{ ok: boolean }> {
    const body = await this.requestJson(
      this.credentials.recipients,
      'PUT',
      `/internal/v1/notifications/recipients/${encodeURIComponent(input.userId)}/verified`,
      {},
    );
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }

  async sendAddressVerification(input: AddressVerificationInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.verification,
        'POST',
        '/internal/v1/notifications/verification',
        { userId: input.userId, code: input.code },
      ),
    );
  }

  async sendAccountSecurity(input: AccountSecurityInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.security,
        'POST',
        '/internal/v1/notifications/security',
        {
          userId: input.userId,
          kind: input.kind,
        },
      ),
    );
  }

  async sendPasswordReset(input: PasswordResetInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.recovery,
        'POST',
        '/internal/v1/notifications/recovery',
        { userId: input.userId, kind: input.kind, code: input.code },
      ),
    );
  }

  async sendEmailChange(input: EmailChangeInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.emailChange,
        'POST',
        '/internal/v1/notifications/email-change',
        { userId: input.userId, kind: input.kind, code: input.code, email: input.email },
      ),
    );
  }

  async replaceRecipient(input: ReplaceRecipientInput): Promise<{ ok: boolean }> {
    const body = await this.requestJson(
      this.credentials.recipients,
      'PUT',
      `/internal/v1/notifications/recipients/${encodeURIComponent(input.userId)}/replace`,
      { email: input.email },
    );
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }

  async recipientStatus(userId: string): Promise<RecipientStatus | null> {
    const body = await this.requestJson(
      this.credentials.status,
      'GET',
      `/internal/v1/notifications/recipients/${encodeURIComponent(userId)}/status`,
    );
    const parsed = StatusResponseSchema.safeParse(body);
    // null, not `{verified:false}`: see NotificationsPort.recipientStatus. An
    // unanswerable query and a real "not verified" are different facts, and the
    // callers decide separately what each means for their own gate.
    return parsed.success ? { verified: parsed.data.verified } : null;
  }
}

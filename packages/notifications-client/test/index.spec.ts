import * as api from '../src/index';

describe('package surface', () => {
  it('exports the client, the DI token, and the closed vocabularies', () => {
    expect(typeof api.HttpNotificationsClient).toBe('function');
    expect(typeof api.NOTIFICATIONS).toBe('symbol');
    expect(api.SERVICE_CREDENTIAL_HEADER).toBe('x-estate-service-credential');
    // The kind set is the contract: adding one is a deliberate template
    // decision in the notifications service, never an ad-hoc string.
    expect(api.ESTATE_NOTIFICATION_KINDS).toEqual([
      'emergency.requested',
      'emergency.blocked',
      'emergency.reminder',
      'emergency.released',
      'emergency.revoked',
      'vault.reset',
      'vault.grantees_changed',
      'settlement.case_opened',
      'settlement.owner_contact',
      // M13: somebody claimed a link to an owner's estate contact.
      'contact.link_claimed',
    ]);
    // M14. A SEPARATE, deliberately tiny set: kinds unreachable through
    // `send`, because their templates carry a variable and the send wire has
    // nowhere to put one. Listed here rather than derived, precisely so that
    // moving a kind across this boundary is a visible diff in a test that says
    // what the boundary is for.
    expect(api.SYSTEM_NOTIFICATION_KINDS).toEqual([
      'identity.address_verification',
      // M17: the account's own credentials changed. A system kind for the
      // MIRROR of the reason above — it carries no variable at all, but it must
      // not be reachable through `send`, whose credential vault, settlement and
      // profile hold. "Your password was changed" is a phishing pretext a
      // recipient acts on, and it is the message an attacker would most like
      // to be able to make the platform send.
      'identity.password_changed',
      // M17 PR3: the mailed reset code. A system kind because its template
      // needs a code, exactly like address verification.
      'identity.password_reset',
      // M17 PR4: the challenge to a PROSPECTIVE address — a system kind for
      // both reasons at once (a code in the template, and a destination on the
      // wire that no estate holder may ever choose).
      'identity.email_change',
      // M17 PR4: the change notice to the address being LEFT. Carries nothing;
      // reaches the old mailbox by ordering, not by naming it.
      'identity.email_changed',
    ]);
    // Together they are the send LOG's vocabulary — the notifications DDL's
    // kind CHECK is written against this, and the int suite drives every member.
    expect(api.NOTIFICATION_KINDS).toEqual([
      ...api.ESTATE_NOTIFICATION_KINDS,
      ...api.SYSTEM_NOTIFICATION_KINDS,
    ]);
    expect(api.NOTIFICATION_CHANNELS).toEqual(['email', 'push', 'sms', 'voice']);
    // M17. The account-security kinds are a SUBSET of the system kinds, and
    // that relationship is the control: each of the three send routes builds
    // its schema from a different one of these lists, so a holder of one
    // credential cannot fire another's vocabulary. Asserted as a subset rather
    // than as a literal so the property survives a third security kind, and
    // asserted DISJOINT from the estate list because that is the exclusion the
    // broadly-held send credential depends on.
    expect(api.ACCOUNT_SECURITY_KINDS).toEqual([
      'identity.password_changed',
      'identity.email_changed',
    ]);
    // M17 PR3. Its own one-member list, DISJOINT from the account-security one:
    // that wire carries no variables at all, which is what makes it safe for a
    // holder who must never choose what a user reads, and this one carries a
    // code. Five send routes, five closed lists, no holder able to fire
    // another's vocabulary.
    expect(api.RECOVERY_KINDS).toEqual(['identity.password_reset']);
    // M17 PR4. The fifth send vocabulary, one member, disjoint from all four
    // siblings — and the one whose wire names a destination.
    expect(api.EMAIL_CHANGE_KINDS).toEqual(['identity.email_change']);
    for (const kind of api.EMAIL_CHANGE_KINDS) {
      expect(api.NOTIFICATION_KINDS).toContain(kind);
    }
    for (const kind of api.RECOVERY_KINDS) {
      expect(api.SYSTEM_NOTIFICATION_KINDS).toContain(kind);
      expect(api.ACCOUNT_SECURITY_KINDS as readonly string[]).not.toContain(kind);
      expect(api.ESTATE_NOTIFICATION_KINDS as readonly string[]).not.toContain(kind);
    }
    // The two mailed-code patterns are anchored on DIFFERENT prefixes, so
    // neither route can mail the other's code.
    expect(api.RESET_CODE_PATTERN.test('PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E')).toBe(true);
    expect(api.RESET_CODE_PATTERN.test('EV1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E')).toBe(false);
    expect(api.VERIFICATION_CODE_PATTERN.test('PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E')).toBe(
      false,
    );
    for (const kind of api.ACCOUNT_SECURITY_KINDS) {
      expect(api.SYSTEM_NOTIFICATION_KINDS).toContain(kind);
      expect(api.ESTATE_NOTIFICATION_KINDS as readonly string[]).not.toContain(kind);
    }
    // M14 review: the code shape lives on the WIRE contract, so both ends
    // import one declaration instead of keeping two patterns free to drift —
    // which is how the notifications route came to accept 64 characters of
    // readable English for a field identity mints from Crockford base32.
    expect(api.VERIFICATION_CODE_PATTERN.test('EV1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E')).toBe(
      true,
    );
    expect(api.VERIFICATION_CODE_PATTERN.test('YOUR-ESTATE-VAULT-IS-LOCKED-CALL-NOW')).toBe(false);
    // I, L, O and U are exactly what the alphabet excludes so a code survives
    // being read aloud — and exactly what makes English spellable.
    expect(api.VERIFICATION_CODE_PATTERN.test('EV1-IIII-LLLL-OOOO-UUUU-2222-3333-4444-5555')).toBe(
      false,
    );
  });
});

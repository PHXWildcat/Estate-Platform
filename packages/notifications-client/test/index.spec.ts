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
    expect(api.SYSTEM_NOTIFICATION_KINDS).toEqual(['identity.address_verification']);
    // Together they are the send LOG's vocabulary — the notifications DDL's
    // kind CHECK is written against this, and the int suite drives every member.
    expect(api.NOTIFICATION_KINDS).toEqual([
      ...api.ESTATE_NOTIFICATION_KINDS,
      ...api.SYSTEM_NOTIFICATION_KINDS,
    ]);
    expect(api.NOTIFICATION_CHANNELS).toEqual(['email', 'push', 'sms', 'voice']);
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

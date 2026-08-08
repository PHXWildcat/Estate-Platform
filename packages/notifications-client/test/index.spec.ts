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
  });
});

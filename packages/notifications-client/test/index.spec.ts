import * as api from '../src/index';

describe('package surface', () => {
  it('exports the client, the DI token, and the closed vocabularies', () => {
    expect(typeof api.HttpNotificationsClient).toBe('function');
    expect(typeof api.NOTIFICATIONS).toBe('symbol');
    expect(api.SERVICE_CREDENTIAL_HEADER).toBe('x-estate-service-credential');
    // The kind set is the contract: adding one is a deliberate template
    // decision in the notifications service, never an ad-hoc string.
    expect(api.NOTIFICATION_KINDS).toEqual([
      'emergency.requested',
      'emergency.blocked',
      'emergency.reminder',
      'emergency.released',
      'emergency.revoked',
      'vault.reset',
      'vault.grantees_changed',
      'settlement.case_opened',
      'settlement.owner_contact',
    ]);
    expect(api.NOTIFICATION_CHANNELS).toEqual(['email', 'push', 'sms', 'voice']);
  });
});

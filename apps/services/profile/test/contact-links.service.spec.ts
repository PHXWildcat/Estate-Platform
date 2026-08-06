import {
  canonicalCode,
  ContactLinksService,
  INVITATION_TTL_MS,
} from '../src/contact-links.service';
import { CODE_RANDOM_BYTES } from '../src/contact-links.service';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { ProfileAuthz } from '../src/authz.service';
import type { ProfileConfig } from '../src/config';
import { StubLinkNotifier } from '../src/notifications';

const OWNER = 'a1111111-1111-4111-8111-111111111111';

/**
 * The code's WIDTH is the security parameter, and this spec pins it the way the
 * M6 review pinned the grantee fingerprint after finding it carrying 50 bits
 * where its own spec said 80. The first implementation of this generator made
 * the same mistake — one character per byte, 100 bits where the docs said 160 —
 * and was caught by reading a code the live stack minted.
 */
describe('the invitation code', () => {
  function build() {
    const inserted: Array<{ codeSha256: Buffer }> = [];
    const codes: string[] = [];
    const links = {
      revokeLive: () => Promise.resolve(null),
      insert: (input: { codeSha256: Buffer }) => {
        inserted.push(input);
        return Promise.resolve('i-1');
      },
    };
    const contacts = {
      findById: () =>
        Promise.resolve({
          id: 'f0000000-0000-4000-8000-000000000001',
          owner_user_id: OWNER,
          linked_user_id: null,
        }),
    };
    const events = {
      contactLinkInvited: () => Promise.resolve(),
      contactLinkInvitationRevoked: () => Promise.resolve(),
      contactLinkClaimed: () => Promise.resolve(),
    };
    const service = new ContactLinksService(
      links as never,
      contacts as never,
      new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
      events as never,
      new StubLinkNotifier(),
      { nodeEnv: 'test' } as ProfileConfig,
      () => new Date('2026-08-06T00:00:00Z'),
    );
    return { service, inserted, codes };
  }

  it('carries exactly 160 bits: 32 base32 characters from 20 random bytes', async () => {
    const { service } = build();
    const { code } = await service.invite(OWNER, 'f0000000-0000-4000-8000-000000000001');
    const body = code.replace(/^ESL1-/, '').replace(/-/g, '');
    expect(CODE_RANDOM_BYTES).toBe(20);
    expect(body).toHaveLength((CODE_RANDOM_BYTES * 8) / 5); // 32, i.e. 160 bits
    // Crockford-style base32: no I, L, O or U to misread over a phone.
    expect(body).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{32}$/);
  });

  it('uses every character position, not one per byte', async () => {
    // The defect being pinned: byte-per-character generation can only ever emit
    // 20 characters. 200 mints must show variation across all 32 positions.
    const { service } = build();
    const seen = Array.from({ length: 32 }, () => new Set<string>());
    for (let i = 0; i < 200; i++) {
      const { code } = await service.invite(OWNER, 'f0000000-0000-4000-8000-000000000001');
      const body = code.replace(/^ESL1-/, '').replace(/-/g, '');
      for (let position = 0; position < body.length; position++) {
        seen[position]?.add(body[position] as string);
      }
    }
    for (const alphabetAtPosition of seen) {
      expect(alphabetAtPosition.size).toBeGreaterThan(1);
    }
  });

  it('expires seven days out', async () => {
    const { service } = build();
    const { expiresAt } = await service.invite(OWNER, 'f0000000-0000-4000-8000-000000000001');
    expect(new Date(expiresAt).getTime() - new Date('2026-08-06T00:00:00Z').getTime()).toBe(
      INVITATION_TTL_MS,
    );
  });
});

/**
 * The M13 security review's confirmed finding, pinned: the owner notification
 * must not be skippable by an audit failure, and its outcome must be recorded.
 */
describe('a claimed link is never silently unnotified', () => {
  const CONTACT = 'f0000000-0000-4000-8000-000000000001';

  function buildRedeem(options: { notifyFails?: boolean; auditFails?: boolean }): {
    service: ContactLinksService;
    notified: string[];
    claims: Array<{ actor: string; ownerNotified: string }>;
  } {
    const invitation = {
      id: 'i-1',
      owner_user_id: OWNER,
      contact_id: CONTACT,
      expires_at: new Date('2026-08-13T00:00:00Z'),
      attempts: 0,
      redeemed_at: null,
      revoked_at: null,
    };
    const links = {
      findByCode: () => Promise.resolve(invitation),
      countAttempt: () => Promise.resolve(),
      redeem: () => Promise.resolve(true),
    };
    const notified: string[] = [];
    const notifier = {
      channel: 'stub',
      deliversToRealChannels: false,
      notify: (n: { ownerUserId: string }) => {
        if (options.notifyFails === true) {
          return Promise.reject(new Error('carrier down'));
        }
        notified.push(n.ownerUserId);
        return Promise.resolve();
      },
    };
    const claims: Array<{ actor: string; ownerNotified: string }> = [];
    const events = {
      contactLinkClaimed: (actor: string, _contact: string, ownerNotified: string) => {
        if (options.auditFails === true) {
          return Promise.reject(new Error('broker down'));
        }
        claims.push({ actor, ownerNotified });
        return Promise.resolve();
      },
      contactLinkNotificationsRefused: () => Promise.resolve(),
    };
    const service = new ContactLinksService(
      links as never,
      { findById: () => Promise.resolve(null) } as never,
      new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
      events as never,
      notifier,
      { nodeEnv: 'test' } as ProfileConfig,
      () => new Date('2026-08-06T00:00:00Z'),
    );
    return { service, notified, claims };
  }

  const REDEEMER = 'b2222222-2222-4222-8222-222222222222';

  it('records delivered on the claim event when the owner was told', async () => {
    const { service, notified, claims } = buildRedeem({});
    await service.redeem(REDEEMER, 'ESL1-GOOD');
    expect(notified).toEqual([OWNER]);
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'delivered' }]);
  });

  it('records FAILED on the claim event when the send did not happen — never silence', async () => {
    const { service, claims } = buildRedeem({ notifyFails: true });
    await service.redeem(REDEEMER, 'ESL1-GOOD'); // the link stands (M6 rule)...
    // ...and the non-delivery is a recorded fact an operator can re-drive from,
    // not an empty catch. The finding: a network-level failure previously left
    // NO record anywhere — no notifications-service row (never reached it), no
    // profile-side fact, nothing.
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'failed' }]);
  });

  it('notifies the owner even when the audit broker is down', async () => {
    // The ordering half: the audit emit propagates broker failures LOUDLY (the
    // M8 rule) — but it must not be able to cancel the owner notification,
    // because the code is spent and no retry will ever re-send it.
    const { service, notified } = buildRedeem({ auditFails: true });
    await expect(service.redeem(REDEEMER, 'ESL1-GOOD')).rejects.toThrow('broker down');
    expect(notified).toEqual([OWNER]);
  });
});

/**
 * The alphabet is chosen for being read aloud (no I, L, O, U). The M13 review
 * found redemption hashing the RAW submission, so every confusion the alphabet
 * exists to survive still failed with the uniform refusal.
 */
describe('a code survives being retyped by a human', () => {
  const MINTED = 'ESL1-V0GN-0G4N-BEZB-4WN3-100G-GM2H-SVJM-1R5T';

  it.each([
    ['lowercase', MINTED.toLowerCase()],
    ['no dashes', MINTED.replace(/-/g, '')],
    ['stray spaces', ` ${MINTED.replace(/-/g, ' ')} `],
    ['letter O typed for zero', MINTED.replace(/0/g, 'O')],
    ['letter l typed for one', MINTED.replace(/1/g, 'l')],
    ['letter I typed for one', MINTED.replace(/1/g, 'I')],
  ])('canonicalizes %s to the same value as the minted form', (_label, typed) => {
    expect(canonicalCode(typed)).toBe(canonicalCode(MINTED));
  });

  it('is a strict fold onto the minted alphabet — different codes never collide', () => {
    // The fold only maps characters the generator NEVER emits (I, L, O and case)
    // onto ones it does, so it cannot merge two codes the mint could produce.
    const a = 'ESL1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAB';
    const b = 'ESL1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAC';
    expect(canonicalCode(a)).not.toBe(canonicalCode(b));
    // And the canonical form of a minted code contains nothing outside it.
    expect(canonicalCode(MINTED)).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/);
  });
});

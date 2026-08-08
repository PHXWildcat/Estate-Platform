import {
  canonicalCode,
  ContactLinksService,
  INVITATION_TTL_MS,
} from '../src/contact-links.service';
import { CANONICAL_CODE_LENGTH, CODE_RANDOM_BYTES } from '../src/contact-links.service';
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
    const lookups: Buffer[] = [];
    const links = {
      revokeLive: () => Promise.resolve(null),
      insert: (input: { codeSha256: Buffer }) => {
        inserted.push(input);
        return Promise.resolve('i-1');
      },
      findByCode: (codeSha256: Buffer) => {
        lookups.push(codeSha256);
        return Promise.resolve(null);
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
    return { service, inserted, codes, lookups };
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

  function buildRedeem(options: {
    notifyFails?: boolean;
    auditFails?: boolean;
    /** M14: whether the OWNER has proved the address the claim is announced to. */
    ownerVerified?: boolean;
    notifyUndelivered?: boolean;
  }): {
    service: ContactLinksService;
    notified: string[];
    claims: Array<{ actor: string; ownerNotified: string }>;
    lookups: number[];
    unverified: string[];
    order: string[];
  } {
    const lookups: number[] = [];
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
      findByCode: () => {
        lookups.push(1);
        return Promise.resolve(invitation);
      },
      countAttempt: () => Promise.resolve(),
      redeem: () => Promise.resolve(true),
    };
    const notified: string[] = [];
    const notifier = {
      channel: 'stub',
      deliversToRealChannels: false,
      recipientVerified: () => Promise.resolve(options.ownerVerified === true),
      notify: (n: { ownerUserId: string }) => {
        if (options.notifyFails === true) {
          return Promise.reject(new Error('carrier down'));
        }
        notified.push(n.ownerUserId);
        return Promise.resolve({
          delivered: options.notifyUndelivered !== true,
          recipientVerified: options.ownerVerified === true,
        });
      },
    };
    const claims: Array<{ actor: string; ownerNotified: string }> = [];
    const unverified: string[] = [];
    const order: string[] = [];
    const events = {
      contactLinkClaimed: (actor: string, _contact: string, ownerNotified: string) => {
        if (options.auditFails === true) {
          return Promise.reject(new Error('broker down'));
        }
        claims.push({ actor, ownerNotified });
        order.push('claimed');
        return Promise.resolve();
      },
      contactLinkNotificationsRefused: () => Promise.resolve(),
      contactLinkUnverifiedRecipient: (owner: string, _redeemer: string, contactId: string) => {
        order.push('unverified');
        // The contact id is asserted because it was NULL until the M14 review:
        // without it an investigator cannot attach "the owner was told at an
        // unproved address" to the authorization edge that was created.
        unverified.push(`${owner}:${contactId}`);
        return Promise.resolve();
      },
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
    return { service, notified, claims, lookups, unverified, order };
  }

  const REDEEMER = 'b2222222-2222-4222-8222-222222222222';
  /**
   * A WELL-SHAPED code, because redemption now checks the canonical length before
   * it looks anything up. The old fixture was 'ESL1-GOOD', which the guard refuses
   * — and the three tests below going red on that is the guard working: a fake
   * repo will hand back an invitation for any string you ask it about, so a test
   * that submits an implausible code proves the notify/audit ordering against a
   * request the real service would have refused two steps earlier.
   */
  const CODE = 'ESL1-V0GN-0G4N-BEZB-4WN3-100G-GM2H-SVJM-1R5T';

  it('refuses a wrongly-shaped submission before it looks anything up', async () => {
    const { service, lookups, notified, claims } = buildRedeem({});
    // 'ESL1-GOOD' is what this fixture used to submit: short enough that no mint
    // could have produced it. The guard measures the CANONICAL form, so a body of
    // pure separators — which satisfies RedeemLinkSchema's raw min(8) and folds to
    // the empty string — is refused on the same terms.
    for (const submitted of ['ESL1-GOOD', '--------']) {
      await expect(service.redeem(REDEEMER, submitted)).rejects.toMatchObject({
        response: { error: 'invalid_code' },
      });
    }
    // Nothing was queried, nobody was notified, nothing was audited as a claim.
    expect(lookups).toEqual([]);
    expect(notified).toEqual([]);
    expect(claims).toEqual([]);
  });

  it('records delivered on the claim event when the owner was told', async () => {
    const { service, notified, claims } = buildRedeem({});
    await service.redeem(REDEEMER, CODE);
    expect(notified).toEqual([OWNER]);
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'delivered' }]);
  });

  it('records FAILED on the claim event when the send did not happen — never silence', async () => {
    const { service, claims } = buildRedeem({ notifyFails: true });
    await service.redeem(REDEEMER, CODE); // the link stands (M6 rule)...
    // ...and the non-delivery is a recorded fact an operator can re-drive from,
    // not an empty catch. The finding: a network-level failure previously left
    // NO record anywhere — no notifications-service row (never reached it), no
    // profile-side fact, nothing.
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'failed' }]);
  });

  it('PROCEEDS on an unverified owner address, and records that it did (M14)', async () => {
    // The mirror of the mint gate. Redemption is driven by the CONTACT, so
    // refusing on the OWNER's unverified address would let an owner's own typo
    // permanently deny somebody they deliberately invited — the M6 rule pointed
    // the wrong way. The link stands.
    //
    // But `ownerNotified: 'delivered'` alone would overstate it: §6g's whole
    // argument for this ceremony is that a claim is auditable BY THE OWNER, and
    // a message to a mailbox nobody confirmed is a weaker version of that. So
    // the fact lands beside it rather than instead of it.
    const { service, claims, unverified, order } = buildRedeem({ ownerVerified: false });
    await service.redeem(REDEEMER, CODE);
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'delivered' }]);
    expect(unverified).toEqual([`${OWNER}:${CONTACT}`]);
    // THE CLAIM GOES FIRST. Round 2 of the M14 review found the ordering half
    // unpinned: both emits propagate broker failures, so putting the SECONDARY
    // fact first meant a failure on it could suppress the record of the claim
    // itself — the link standing, the code spent, and the owner's trail holding
    // neither event.
    expect(order).toEqual(['claimed', 'unverified']);
  });

  it('records NOTHING extra once the owner has proved their address', async () => {
    // Otherwise the event above would be noise on every claim rather than a
    // signal about the ones that matter.
    const { service, claims, unverified } = buildRedeem({ ownerVerified: true });
    await service.redeem(REDEEMER, CODE);
    expect(claims).toEqual([{ actor: REDEEMER, ownerNotified: 'delivered' }]);
    expect(unverified).toEqual([]);
  });

  it('notifies the owner even when the audit broker is down', async () => {
    // The ordering half: the audit emit propagates broker failures LOUDLY (the
    // M8 rule) — but it must not be able to cancel the owner notification,
    // because the code is spent and no retry will ever re-send it.
    const { service, notified } = buildRedeem({ auditFails: true });
    await expect(service.redeem(REDEEMER, CODE)).rejects.toThrow('broker down');
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

  it('the minted code folds to exactly CANONICAL_CODE_LENGTH', () => {
    expect(canonicalCode(MINTED)).toHaveLength(CANONICAL_CODE_LENGTH);
    // Derived from the mint, never a hand-counted 36.
    expect(CANONICAL_CODE_LENGTH).toBe(canonicalCode('ESL1-').length + 32);
  });

  it('submissions that fold to the wrong length are not codes at all', () => {
    // Each satisfies RedeemLinkSchema's raw min(8) while carrying no code —
    // separators only folds to the empty string. Redemption measures the CANONICAL
    // form for exactly this reason, and answers the uniform `invalid_code` so the
    // shape check is not a free oracle for the format.
    for (const submitted of ['--------', '- - - - - - - -', 'ESL1-K7MN-QRST']) {
      expect(canonicalCode(submitted).length).not.toBe(CANONICAL_CODE_LENGTH);
    }
  });

  it('is a strict fold onto the minted alphabet — different codes never collide', () => {
    // The fold is INJECTIVE ON MINTED CODES: the `ESL1-` prefix is constant, so it
    // folds identically for every code and distinguishes nothing, and within the
    // 32-character body the alphabet excludes I, L, O and U so the fold is the
    // identity. Two minted codes therefore differ in their bodies either way.
    const a = 'ESL1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAB';
    const b = 'ESL1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAC';
    expect(canonicalCode(a)).not.toBe(canonicalCode(b));
    // And the canonical form of a minted code contains nothing outside it.
    expect(canonicalCode(MINTED)).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/);
  });
});

/**
 * THE MINT GATE (M14), and the asymmetry that decides it.
 *
 * Minting hands out a capability whose redemption makes somebody able to open a
 * death case against this owner (docs/03 §6b), and the only thing that makes
 * that safe after the fact is the owner HEARING about the claim. Before M14
 * this route had no notification precondition at all — redemption had one,
 * minting did not — so M14 adds a gate here rather than tightening one.
 *
 * Minting refuses and redemption does not, because in one the actor and the
 * recipient are the same person and in the other they are not.
 */
describe('minting a link code requires a reachable owner', () => {
  const CONTACT = 'f0000000-0000-4000-8000-000000000001';

  function mintHarness(options: { nodeEnv: 'production' | 'test'; ownerVerified: boolean }): {
    service: ContactLinksService;
    asked: string[];
    refusals: string[];
    minted: number;
  } {
    const asked: string[] = [];
    const refusals: string[] = [];
    const counters = { minted: 0 };
    const links = {
      revokeLive: () => Promise.resolve(null),
      insert: () => {
        counters.minted += 1;
        return Promise.resolve('i-1');
      },
    };
    const service = new ContactLinksService(
      links as never,
      {
        findById: () =>
          Promise.resolve({ id: CONTACT, owner_user_id: OWNER, linked_user_id: null }),
      } as never,
      new ProfileAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
      {
        contactLinkInvited: () => Promise.resolve(),
        contactLinkInvitationRevoked: () => Promise.resolve(),
        contactLinkNotificationsRefused: (owner: string) => {
          refusals.push(owner);
          return Promise.resolve();
        },
      } as never,
      {
        channel: 'email',
        deliversToRealChannels: true,
        recipientVerified: (ownerUserId: string) => {
          asked.push(ownerUserId);
          return Promise.resolve(options.ownerVerified);
        },
        notify: () =>
          Promise.resolve({ delivered: true, recipientVerified: options.ownerVerified }),
      },
      { nodeEnv: options.nodeEnv } as ProfileConfig,
      () => new Date('2026-08-06T00:00:00Z'),
    );
    return { service, asked, refusals, minted: counters.minted };
  }

  it('REFUSES in production when the owner never proved their address', async () => {
    const h = mintHarness({ nodeEnv: 'production', ownerVerified: false });
    await expect(h.service.invite(OWNER, CONTACT)).rejects.toMatchObject({
      response: { error: 'recipient_unverified' },
    });
    // Asked about the OWNER, and the refusal is recorded — a control firing
    // must never read as an outage (the M9 rule).
    expect(h.asked).toEqual([OWNER]);
    expect(h.refusals).toEqual([OWNER]);
  });

  it('mints for a PROVED owner, so the refusal above is not vacuous', async () => {
    const h = mintHarness({ nodeEnv: 'production', ownerVerified: true });
    const { code } = await h.service.invite(OWNER, CONTACT);
    expect(code.startsWith('ESL1-')).toBe(true);
    expect(h.asked).toEqual([OWNER]);
    expect(h.refusals).toEqual([]);
  });

  it('does not ask outside production, where the stub is the intended adapter', async () => {
    const h = mintHarness({ nodeEnv: 'test', ownerVerified: false });
    const minted = await h.service.invite(OWNER, CONTACT);
    expect(minted.code.startsWith('ESL1-')).toBe(true);
    expect(h.asked).toEqual([]);
  });
});

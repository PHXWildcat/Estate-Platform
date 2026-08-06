import { ContactLinksService, INVITATION_TTL_MS } from '../src/contact-links.service';
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

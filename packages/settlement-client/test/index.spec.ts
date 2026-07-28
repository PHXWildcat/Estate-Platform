// Import through the barrel so the public surface (index.ts re-exports) is
// itself covered — a symbol dropped from index.ts breaks this suite.
import * as settlementClient from '../src';

describe('@estate/settlement-client public surface', () => {
  it('re-exports the client, its DI token, and the authority types', () => {
    expect(settlementClient.HttpSettlementAuthority).toBeDefined();
    expect(typeof settlementClient.SETTLEMENT_AUTHORITY).toBe('symbol');
  });

  it('defaults to the global fetch transport when none is injected', async () => {
    // The default arrow in the constructor is the real production transport;
    // exercise it against a stubbed global so the wiring is proven without a
    // network call.
    const original = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = ((url: string): Promise<Response> => {
      calls.push(url);
      return Promise.resolve({
        ok: false,
        status: 503,
        json: () => Promise.resolve({}),
      } as unknown as Response);
    }) as typeof globalThis.fetch;
    try {
      const client = new settlementClient.HttpSettlementAuthority({
        settlementUrl: 'http://settlement.internal',
      });
      // Fails closed on the stubbed 503, and proves the default transport ran.
      await expect(
        client.checkEvidenceRead({
          bearerToken: 'token',
          documentId: '11111111-1111-4111-8111-111111111111',
          version: 1,
        }),
      ).resolves.toEqual({ allowed: false });
      expect(calls).toHaveLength(1);
      expect(calls[0]).toContain('/v1/settlement/authority/evidence-read');
    } finally {
      globalThis.fetch = original;
    }
  });
});

import { computeEventHash, GENESIS_HASH, HASH_LENGTH } from '../src/chain';
import { makeEvent } from './helpers';

describe('chain hashing', () => {
  it('GENESIS_HASH is 32 zero bytes', () => {
    expect(GENESIS_HASH.length).toBe(HASH_LENGTH);
    expect(GENESIS_HASH.equals(Buffer.alloc(32, 0))).toBe(true);
  });

  it('is deterministic for identical input', () => {
    const event = makeEvent({ eventId: '11111111-1111-4111-8111-111111111111' });
    const h1 = computeEventHash(GENESIS_HASH, event);
    const h2 = computeEventHash(GENESIS_HASH, { ...event });
    expect(h1.length).toBe(HASH_LENGTH);
    expect(h1.equals(h2)).toBe(true);
  });

  it('avalanches: changing one field changes the hash', () => {
    const event = makeEvent({ detail: { attempt: 1 } });
    const h1 = computeEventHash(GENESIS_HASH, event);
    const h2 = computeEventHash(GENESIS_HASH, { ...event, detail: { attempt: 2 } });
    expect(h1.equals(h2)).toBe(false);
  });

  it('depends on prev_hash (chain linkage)', () => {
    const event = makeEvent();
    const h1 = computeEventHash(GENESIS_HASH, event);
    const h2 = computeEventHash(Buffer.alloc(32, 1), event);
    expect(h1.equals(h2)).toBe(false);
  });

  it('rejects a prev_hash that is not 32 bytes', () => {
    expect(() => computeEventHash(Buffer.alloc(31, 0), makeEvent())).toThrow('32 bytes');
  });
});

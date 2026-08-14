import { commandEventId } from './command-id';

describe('commandEventId', () => {
  it('holds the SAME id across retries of an identical payload', () => {
    const first = commandEventId(null, 'k1');
    const retry = commandEventId(first, 'k1');
    expect(retry.id).toBe(first.id);
  });

  it('mints a FRESH id the moment the payload changes', () => {
    // The dangerous case: attempt 1 may have committed server-side even
    // though the client saw a failure. An edited payload reusing the old id
    // would be answered with the ORIGINAL ack and the edit silently dropped.
    const first = commandEventId(null, 'k1');
    const edited = commandEventId(first, 'k2');
    expect(edited.id).not.toBe(first.id);
    expect(edited.key).toBe('k2');
  });

  it('mints distinct ids for distinct fresh commands', () => {
    expect(commandEventId(null, 'a').id).not.toBe(commandEventId(null, 'a').id);
  });
});

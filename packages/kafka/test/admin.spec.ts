import { ensureTopics, type AdminLike } from '../src';

type Created = { topic: string; numPartitions: number; replicationFactor: number };

/** An admin double over an in-memory topic list. */
function fakeAdmin(
  initial: string[],
  hooks: { onCreate?: () => void } = {},
): AdminLike & { topics: Set<string>; created: Created[]; connects: number; disconnects: number } {
  const fake = {
    topics: new Set(initial),
    created: [] as Created[],
    connects: 0,
    disconnects: 0,
    connect(): Promise<void> {
      fake.connects += 1;
      return Promise.resolve();
    },
    disconnect(): Promise<void> {
      fake.disconnects += 1;
      return Promise.resolve();
    },
    listTopics(): Promise<string[]> {
      return Promise.resolve([...fake.topics]);
    },
    createTopics(options: { topics: Created[] }): Promise<boolean> {
      hooks.onCreate?.();
      for (const spec of options.topics) {
        fake.created.push(spec);
        fake.topics.add(spec.topic);
      }
      return Promise.resolve(true);
    },
  };
  return fake;
}

const BASE = { clientId: 'stack-provisioner', brokers: ['redpanda:29092'] };

describe('ensureTopics', () => {
  it('creates missing topics with explicit, reviewed defaults', async () => {
    const admin = fakeAdmin([]);
    const result = await ensureTopics({
      ...BASE,
      admin,
      topics: [{ topic: 'estate.audit.events.v1' }],
    });
    expect(result).toEqual({ created: ['estate.audit.events.v1'], existing: [] });
    // Explicit, not "whatever auto-create decides".
    expect(admin.created).toEqual([
      { topic: 'estate.audit.events.v1', numPartitions: 1, replicationFactor: 1 },
    ]);
  });

  it('honours per-topic partition and replication overrides', async () => {
    const admin = fakeAdmin([]);
    await ensureTopics({
      ...BASE,
      admin,
      topics: [{ topic: 't', numPartitions: 6, replicationFactor: 3 }],
    });
    expect(admin.created).toEqual([{ topic: 't', numPartitions: 6, replicationFactor: 3 }]);
  });

  it('is idempotent: an existing topic is reported, never recreated', async () => {
    const admin = fakeAdmin(['estate.audit.events.v1']);
    const result = await ensureTopics({
      ...BASE,
      admin,
      topics: [{ topic: 'estate.audit.events.v1' }],
    });
    expect(result).toEqual({ created: [], existing: ['estate.audit.events.v1'] });
    expect(admin.created).toHaveLength(0);
  });

  it('creates only the missing half of a mixed set', async () => {
    const admin = fakeAdmin(['a']);
    const result = await ensureTopics({ ...BASE, admin, topics: [{ topic: 'a' }, { topic: 'b' }] });
    expect(result).toEqual({ created: ['b'], existing: ['a'] });
  });

  it('tolerates a concurrent provisioner winning the create race', async () => {
    // Two stack starts can race. If createTopics fails but the topic exists
    // afterwards, that is success — the goal is the topic, not the winning.
    // The racer's creation must land BETWEEN our list and our create, which is
    // the only window that produces the error this branch handles.
    const admin = fakeAdmin([]);
    admin.createTopics = (): Promise<boolean> => {
      admin.topics.add('b');
      return Promise.reject(new Error('TOPIC_ALREADY_EXISTS'));
    };
    const result = await ensureTopics({ ...BASE, admin, topics: [{ topic: 'b' }] });
    expect(result.created).toEqual(['b']);
  });

  it('rethrows when the create genuinely failed', async () => {
    const admin = fakeAdmin([], {
      onCreate: () => {
        throw new Error('INVALID_REPLICATION_FACTOR');
      },
    });
    await expect(ensureTopics({ ...BASE, admin, topics: [{ topic: 'b' }] })).rejects.toThrow(
      'INVALID_REPLICATION_FACTOR',
    );
  });

  it('always disconnects, including on failure', async () => {
    const ok = fakeAdmin([]);
    await ensureTopics({ ...BASE, admin: ok, topics: [{ topic: 'a' }] });
    expect(ok.connects).toBe(1);
    expect(ok.disconnects).toBe(1);

    const bad = fakeAdmin([], {
      onCreate: () => {
        throw new Error('nope');
      },
    });
    await expect(ensureTopics({ ...BASE, admin: bad, topics: [{ topic: 'a' }] })).rejects.toThrow();
    expect(bad.disconnects).toBe(1);
  });

  it('short-circuits without creating when every topic exists', async () => {
    const admin = fakeAdmin(['a', 'b']);
    const result = await ensureTopics({ ...BASE, admin, topics: [{ topic: 'a' }, { topic: 'b' }] });
    expect(result).toEqual({ created: [], existing: ['a', 'b'] });
    expect(admin.disconnects).toBe(1);
  });
});

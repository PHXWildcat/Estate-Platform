import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AuditEventSchema, DECRYPT_FIELD_PREFIXES, TOPICS } from '@estate/contracts';
import {
  boundFor,
  DECRYPT_RATE_BOUNDS,
  DECRYPT_WINDOW_SECONDS,
  ENCRYPT_ONLY_PREFIXES,
  principalClassOf,
  SENTINEL_ACTOR_ID,
  undecidedPrefixes,
} from '../src/decrypt-rate-bounds';
import {
  DecryptRateDetector,
  evaluateDecryptRates,
  type DecryptRateObservation,
  type DetectorDb,
} from '../src/decrypt-rate-detector';

/**
 * Unit layer for the M18 detector: the BOUNDS TABLE as reviewed data, the
 * pure evaluator's boundary semantics, and the detector's episode/fault
 * behaviour over fakes. The int spec proves the same machinery over real
 * Postgres through the real ingestor; this layer is what pins the DECISIONS
 * (the M14 round-2 rule: prove the decision, not just the primitive).
 */

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';

function obs(over: Partial<DecryptRateObservation>): DecryptRateObservation {
  return { prefix: 'doc', actorType: 'user', actorId: USER_A, count: 1, ...over };
}

describe('the bounds table (reviewed data)', () => {
  it('every registered prefix carries a VISIBLE decision (bound row or encrypt-only reason)', () => {
    expect(undecidedPrefixes()).toEqual([]);
  });

  it('models BOTH of the projection rebuild s sentinel decrypt sites', () => {
    // rebuild.service.ts decrypts twice as the sentinel: ledger payloads
    // (asset_event.payload.<id>) and the live-view diff (asset.<id>.<col>).
    // The M18 review found only the first modelled, so every rebuild of a
    // valued estate fired unmodeled_principal — the loudest class in the
    // table, raised by a reviewed path, which is how an alarm stops being
    // read.
    expect(boundFor('asset_event', 'sentinel').name).toBe('asset_event_sentinel');
    expect(boundFor('asset', 'sentinel').name).toBe('asset_sentinel');
    expect(boundFor('asset', 'sentinel').maxPerWindow).toBeGreaterThan(0);
  });

  it('every bound row names a registered prefix and a real principal class', () => {
    const prefixes = new Set(Object.keys(DECRYPT_FIELD_PREFIXES));
    const classes = new Set(['user', 'service', 'operator', 'system', 'sentinel']);
    for (const row of DECRYPT_RATE_BOUNDS) {
      expect(prefixes.has(row.prefix)).toBe(true);
      expect(classes.has(row.principal)).toBe(true);
    }
  });

  it('no bound sits at or under the measured sustained rate', () => {
    // The gate must never fire on the legitimate peak PR1 measured: every
    // bound strictly exceeds measured-per-minute sustained across the window.
    for (const row of DECRYPT_RATE_BOUNDS) {
      expect(row.maxPerWindow).toBeGreaterThan(
        row.measuredPerMinute * (DECRYPT_WINDOW_SECONDS / 60),
      );
    }
  });

  it('encrypt-only prefixes have no bound row (one decision per prefix, never two)', () => {
    for (const prefix of Object.keys(ENCRYPT_ONLY_PREFIXES)) {
      expect(DECRYPT_RATE_BOUNDS.some((b) => b.prefix === prefix)).toBe(false);
    }
  });

  it('boundFor is total, and everything outside the table resolves to 0', () => {
    expect(boundFor('doc', 'user').name).toBe('doc_user');
    expect(boundFor('doc', 'user').maxPerWindow).toBeGreaterThan(0);
    // Registered prefix, principal the table never modelled: loud zero.
    expect(boundFor('doc', 'sentinel')).toEqual({ name: 'unmodeled_principal', maxPerWindow: 0 });
    // Encrypt-only: the first decrypt ever is the anomaly.
    expect(boundFor('distributions', 'user')).toEqual({ name: 'encrypt_only', maxPerWindow: 0 });
    // Unregistered prefix: the detector is where a new prefix becomes loud.
    expect(boundFor('trust', 'user')).toEqual({ name: 'unknown_prefix', maxPerWindow: 0 });
    // Prototype keys must classify as unknown, never resolve through Object.
    expect(boundFor('constructor', 'user')).toEqual({ name: 'unknown_prefix', maxPerWindow: 0 });
    expect(boundFor('toString', 'sentinel')).toEqual({ name: 'unknown_prefix', maxPerWindow: 0 });
  });

  it('the nil-UUID sentinel is its own principal class for BOTH actor types that ride it', () => {
    expect(principalClassOf('service', SENTINEL_ACTOR_ID)).toBe('sentinel');
    expect(principalClassOf('system', SENTINEL_ACTOR_ID)).toBe('sentinel');
    expect(principalClassOf('service', USER_A)).toBe('service');
    expect(principalClassOf('user', USER_A)).toBe('user');
    expect(principalClassOf('user', null)).toBe('user');
  });
});

describe('evaluateDecryptRates (pure)', () => {
  const docMax = boundFor('doc', 'user').maxPerWindow;

  it('AT the bound is not a breach; ONE over is (the off-by-one pin)', () => {
    expect(evaluateDecryptRates([obs({ count: docMax })])).toEqual([]);
    const breaches = evaluateDecryptRates([obs({ count: docMax + 1 })]);
    expect(breaches).toHaveLength(1);
    expect(breaches[0]).toMatchObject({
      boundName: 'doc_user',
      prefix: 'doc',
      principal: 'user',
      count: docMax + 1,
      maxPerWindow: docMax,
    });
  });

  it('never aggregates across principals — the grain is per actorId', () => {
    const half = Math.ceil(docMax / 2) + 1;
    // Two actors together far exceed the bound; neither alone does.
    const rows = [obs({ actorId: USER_A, count: half }), obs({ actorId: USER_B, count: half })];
    expect(evaluateDecryptRates(rows)).toEqual([]);
  });

  it('the sentinel rides its own bound, never the unmodeled zero of its actor type', () => {
    const sentinelMax = boundFor('notification_recipient', 'sentinel').maxPerWindow;
    expect(sentinelMax).toBeGreaterThan(0);
    // Under the sentinel bound: silent. If the sentinel were folded into
    // 'service' (the mutation this pins), this row would resolve to
    // unmodeled_principal/0 and breach at count 1.
    const quiet = obs({
      prefix: 'notification_recipient',
      actorType: 'service',
      actorId: SENTINEL_ACTOR_ID,
      count: sentinelMax,
    });
    expect(evaluateDecryptRates([quiet])).toEqual([]);
    // A REAL service principal under the same prefix is unmodeled — loud at 1.
    const real = obs({ prefix: 'notification_recipient', actorType: 'service', count: 1 });
    expect(evaluateDecryptRates([real])).toMatchObject([
      { boundName: 'unmodeled_principal', principal: 'service' },
    ]);
  });

  it('an unregistered prefix breaches at the first decrypt', () => {
    expect(evaluateDecryptRates([obs({ prefix: 'trust', count: 1 })])).toMatchObject([
      { boundName: 'unknown_prefix', count: 1 },
    ]);
  });
});

/** DetectorDb whose rows are swapped per tick. */
class FakeDb implements DetectorDb {
  rows: Array<{ prefix: string | null; actor_type: string; actor_id: string | null; n: number }> =
    [];
  queries = 0;
  fail = false;
  query(
    _text: string,
    _values: unknown[],
  ): Promise<{
    rows: Array<{ prefix: string | null; actor_type: string; actor_id: string | null; n: number }>;
  }> {
    this.queries += 1;
    if (this.fail) {
      return Promise.reject(new Error('connection lost'));
    }
    return Promise.resolve({ rows: this.rows });
  }
}

function burstRow(n: number): FakeDb['rows'][number] {
  return { prefix: 'doc', actor_type: 'user', actor_id: USER_A, n };
}

/** The breaching principal an emitted anomaly is about — parsed through the
 * real schema, so a malformed emit fails here rather than reading as a
 * missing id. */
function subjectOf(value: string): string {
  return String(AuditEventSchema.parse(JSON.parse(value)).resourceId);
}

describe('DecryptRateDetector (episodes, faults, emit shape)', () => {
  const docMax = boundFor('doc', 'user').maxPerWindow;

  function build(producer: AuditProducer = new InMemoryAuditProducer()): {
    db: FakeDb;
    detector: DecryptRateDetector;
    producer: AuditProducer;
  } {
    const db = new FakeDb();
    return {
      db,
      producer,
      detector: new DecryptRateDetector(
        db,
        new AuditEmitter(producer),
        () => new Date('2026-08-13T12:00:00Z'),
      ),
    };
  }

  it('a sustained breach is ONE episode: emit on entry, silence while it holds, re-arm on clear', async () => {
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    db.rows = [burstRow(docMax + 1)];
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    await detector.tick(); // still breaching — no second event
    expect(mem.messages).toHaveLength(1);
    db.rows = []; // window cleared — the episode ends
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    db.rows = [burstRow(docMax + 1)]; // a NEW episode
    await detector.tick();
    expect(mem.messages).toHaveLength(2);
  });

  it('the emitted event is schema-valid, on the audit topic, about the breaching principal', async () => {
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    db.rows = [burstRow(docMax + 5)];
    await detector.tick();
    const [message] = mem.messages;
    expect(message?.topic).toBe(TOPICS.auditEvents);
    const event = AuditEventSchema.parse(JSON.parse(message?.value ?? ''));
    expect(event.action).toBe('crypto.decrypt_rate.exceeded');
    expect(event.actorType).toBe('system');
    expect(event.actorId).toBeNull();
    expect(event.resourceId).toBe(USER_A);
    expect(event.detail).toEqual({
      boundName: 'doc_user',
      principal: 'user',
      actorType: 'user',
      prefixClass: 'doc',
      count: docMax + 5,
      bound: docMax,
      windowSeconds: DECRYPT_WINDOW_SECONDS,
    });
  });

  it('a query fault is swallowed, counted, and emits nothing — never thrown', async () => {
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    db.fail = true;
    await expect(detector.tick()).resolves.toBeUndefined();
    expect(detector.faults).toBe(1);
    expect(mem.messages).toHaveLength(0);
  });

  it('a failed emit is retried next tick — the fail direction is a LATE event, never a lost one', async () => {
    const flaky: AuditProducer & { sent: number } = {
      sent: 0,
      send(): Promise<void> {
        this.sent += 1;
        return this.sent === 1
          ? Promise.reject(new Error('broker unavailable'))
          : Promise.resolve();
      },
    };
    const { db, detector } = build(flaky);
    db.rows = [burstRow(docMax + 1)];
    await detector.tick();
    expect(detector.faults).toBe(1); // the emit failure is a tick fault
    await detector.tick(); // key was never marked announced — retried
    expect(flaky.sent).toBe(2);
    await detector.tick(); // now announced — silent
    expect(flaky.sent).toBe(2);
  });

  it('ticks never overlap: a slow query holds the next tick to a no-op', async () => {
    const db = new FakeDb();
    let release: (v: { rows: FakeDb['rows'] }) => void = () => undefined;
    const hung = new Promise<{ rows: FakeDb['rows'] }>((resolve) => {
      release = resolve;
    });
    db.query = (): Promise<{ rows: FakeDb['rows'] }> => {
      db.queries += 1;
      return hung;
    };
    const detector = new DecryptRateDetector(db, new AuditEmitter(new InMemoryAuditProducer()));
    const first = detector.tick();
    await detector.tick(); // re-entrant — must return without querying again
    expect(db.queries).toBe(1);
    release({ rows: [] });
    await first;
  });

  it('an emit failure during a tick where ANOTHER episode clears never suppresses a later re-arm', async () => {
    // THE M18 REVIEW'S WORST FINDING, pinned. The prune that ends episodes
    // used to run after the emit loop inside one try, so a thrown emit
    // skipped it: principal A's cleared episode stayed marked announced, and
    // A's NEXT genuine breach was swallowed as a duplicate — a LOST anomaly
    // in a detector whose docs promised the fail direction is always an extra
    // event. Reproduced against the real class before the fix ([A, B] where
    // [A, B, A] was owed).
    const db = new FakeDb();
    const emitted: string[] = [];
    let brokerDown = false;
    const producer: AuditProducer = {
      send(message): Promise<void> {
        if (brokerDown) {
          return Promise.reject(new Error('broker down'));
        }
        emitted.push(subjectOf(message.value));
        return Promise.resolve();
      },
    };
    const detector = new DecryptRateDetector(db, new AuditEmitter(producer));

    db.rows = [burstRow(docMax + 1)]; // A breaches, announced
    await detector.tick();
    // A clears; B breaches; the broker is down so B's emit throws.
    db.rows = [{ prefix: 'doc', actor_type: 'user', actor_id: USER_B, n: docMax + 1 }];
    brokerDown = true;
    await detector.tick();
    // Broker back. A re-breaches — a genuinely NEW episode.
    brokerDown = false;
    db.rows = [
      burstRow(docMax + 1),
      { prefix: 'doc', actor_type: 'user', actor_id: USER_B, n: docMax + 1 },
    ];
    await detector.tick();

    expect(emitted.filter((id) => id === USER_A)).toHaveLength(2);
    // B's failed emit was retried on the next tick, not dropped.
    expect(emitted).toContain(USER_B);
  });

  it('one unemittable breach does not cancel its neighbours in the same tick', async () => {
    // Second harm of the same defect: the emit loop shared one try, so the
    // first throw abandoned every later breach in that tick.
    const db = new FakeDb();
    const emitted: string[] = [];
    const producer: AuditProducer = {
      send(message): Promise<void> {
        const id = subjectOf(message.value);
        if (id === USER_A) {
          return Promise.reject(new Error('unemittable'));
        }
        emitted.push(id);
        return Promise.resolve();
      },
    };
    const detector = new DecryptRateDetector(db, new AuditEmitter(producer));
    db.rows = [
      burstRow(docMax + 1),
      { prefix: 'doc', actor_type: 'user', actor_id: USER_B, n: docMax + 1 },
    ];
    await detector.tick();
    expect(emitted).toEqual([USER_B]);
    expect(detector.faults).toBe(1);
  });

  it('a query failure leaves episode memory untouched (nothing to reconcile against)', async () => {
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    db.rows = [burstRow(docMax + 1)];
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    db.fail = true; // the sweep cannot see the world at all
    await detector.tick();
    db.fail = false;
    await detector.tick(); // still breaching — must NOT re-announce
    expect(mem.messages).toHaveLength(1);
    expect(detector.faults).toBe(1);
  });

  it('merges the sentinel s two actor types onto one principal before evaluating', async () => {
    // The SQL groups by actor_type (a column) while the bound is keyed on the
    // principal CLASS, which folds ('service', nil) and ('system', nil)
    // together. Unmerged, each row sat under the bound while their sum
    // exceeded it — two disagreeing notions of "a principal" in one detector.
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    const half = Math.ceil(boundFor('notification_recipient', 'sentinel').maxPerWindow / 2) + 1;
    db.rows = [
      {
        prefix: 'notification_recipient',
        actor_type: 'service',
        actor_id: SENTINEL_ACTOR_ID,
        n: half,
      },
      {
        prefix: 'notification_recipient',
        actor_type: 'system',
        actor_id: SENTINEL_ACTOR_ID,
        n: half,
      },
    ];
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    const event = AuditEventSchema.parse(JSON.parse(mem.messages[0]?.value ?? ''));
    expect(event.detail).toMatchObject({ principal: 'sentinel', count: half * 2 });
  });

  it('a decrypt row with no field surfaces as an unknown-prefix breach, not an unemittable token', async () => {
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    db.rows = [{ prefix: null, actor_type: 'user', actor_id: USER_A, n: 1 }];
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    const event = AuditEventSchema.parse(JSON.parse(mem.messages[0]?.value ?? ''));
    expect(event.detail['prefixClass']).toBe('missing_field');
    expect(event.detail['boundName']).toBe('unknown_prefix');
  });
});

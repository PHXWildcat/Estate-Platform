import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { InMemoryAuditProducer } from '@estate/kafka';
import {
  AuditEventSchema,
  DECRYPT_FIELD_PREFIXES,
  DECRYPT_FIELD_SUBJECTS,
  TOPICS,
} from '@estate/contracts';
import {
  boundFor,
  DECRYPT_RATE_BOUNDS,
  DECRYPT_WINDOW_SECONDS,
  principalClassOf,
  SENTINEL_ACTOR_ID,
  undecidedPrefixes,
} from '../src/decrypt-rate-bounds';
import {
  DecryptRateDetector,
  distinctSubjectExpression,
  evaluateDecryptRates,
  mergeObservations,
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
  return {
    prefix: 'doc',
    actorType: 'user',
    actorId: USER_A,
    count: 1,
    distinctSubjects: 0,
    ...over,
  };
}

describe('the bounds table (reviewed data)', () => {
  it('every registered prefix carries a VISIBLE decision — a reviewed bound row', () => {
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
    // The gate must never fire on the legitimate peak a journey measured:
    // every bound strictly exceeds measured-per-minute sustained across the
    // window. Most peaks come from M18 PR1's journey; the two `distributions`
    // rows from M48 PR3's, which is why this reads the field rather than
    // naming the milestone that filled it.
    for (const row of DECRYPT_RATE_BOUNDS) {
      expect(row.maxPerWindow).toBeGreaterThan(
        row.measuredPerMinute * (DECRYPT_WINDOW_SECONDS / 60),
      );
    }
  });

  it('models BOTH principal classes that reach the distribution-amount decrypt', () => {
    // The encrypt-only class is GONE (M48 PR3): it held one member for its
    // whole life, and that member acquired a read route in M23 PR4b, so every
    // legitimate reveal breached at count 1. This is the replacement claim, in
    // the shape the asset/sentinel row above already needed — model every class
    // that reaches the site, or the unmodelled half is loud on a reviewed path.
    //
    // Derived from the SOURCE rather than restated: admin.service.ts passes
    // `isOperator ? 'operator' : 'user'`, so both arms must resolve to a
    // named bound. A test that listed them by hand would agree with itself.
    const src = readFileSync(
      join(__dirname, '..', '..', 'settlement', 'src', 'admin.service.ts'),
      'utf8',
    );
    const call = /decryptField\(\{[\s\S]*?DISTRIBUTION_AMOUNT_FIELD[\s\S]*?\}\)/.exec(src);
    expect(call).not.toBeNull();
    const arms = [...(call?.[0] as string).matchAll(/actorType: \w+ \? '(\w+)' : '(\w+)'/g)];
    expect(arms).toHaveLength(1);
    const classes = [arms[0]?.[1] as string, arms[0]?.[2] as string].sort();
    expect(classes).toEqual(['operator', 'user']);
    for (const cls of classes) {
      const bound = boundFor('distributions', cls as 'operator' | 'user');
      expect(bound.name).toBe(`distributions_${cls}`);
      expect(bound.maxPerWindow).toBeGreaterThan(0);
    }
    // The operator's reach is wider, so its ceiling is lower. Asserted as an
    // INEQUALITY rather than two numbers, which would just restate the table.
    expect(boundFor('distributions', 'operator').maxPerWindow).toBeLessThan(
      boundFor('distributions', 'user').maxPerWindow,
    );
  });

  it('boundFor is total, and everything outside the table resolves to 0', () => {
    expect(boundFor('doc', 'user').name).toBe('doc_user');
    expect(boundFor('doc', 'user').maxPerWindow).toBeGreaterThan(0);
    // Registered prefix, principal the table never modelled: loud zero.
    expect(boundFor('doc', 'sentinel')).toEqual({ name: 'unmodeled_principal', maxPerWindow: 0 });
    // Was 'encrypt_only' until M48 PR3; now a reviewed row like any other.
    expect(boundFor('distributions', 'user').name).toBe('distributions_user');
    // Still loud for a class the table does not model: deleting the encrypt-only
    // branch must not have widened anything.
    expect(boundFor('distributions', 'sentinel')).toEqual({
      name: 'unmodeled_principal',
      maxPerWindow: 0,
    });
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

describe('the distinct-subject condition', () => {
  const assetBound = boundFor('asset', 'user');
  const countMax = assetBound.maxPerWindow;
  const distinctMax = assetBound.maxDistinctSubjectsPerWindow as number;

  const asset = (count: number, distinctSubjects: number): DecryptRateObservation =>
    obs({ prefix: 'asset', count, distinctSubjects });

  it('the asset/user bound carries the condition and nothing else does', () => {
    // Adding it anywhere else is a deliberate narrowing that has to be
    // reviewed — it can only ever SUPPRESS. This is the whole blast radius of
    // the dimension, asserted as a set rather than described.
    const carriers = DECRYPT_RATE_BOUNDS.filter(
      (b) => b.maxDistinctSubjectsPerWindow !== undefined,
    ).map((b) => `${b.prefix}_${b.principal}`);
    expect(carriers).toEqual(['asset_user']);
  });

  it('a bound may only carry the condition for a prefix that declares a subject', () => {
    // Without a declared position every field yields NULL, so distinct is
    // always 0 — a condition on such a bound would suppress EVERY breach of
    // it, silently and permanently.
    for (const row of DECRYPT_RATE_BOUNDS) {
      if (row.maxDistinctSubjectsPerWindow === undefined) {
        continue;
      }
      expect(Object.keys(DECRYPT_FIELD_SUBJECTS)).toContain(row.prefix);
    }
  });

  it('NO NEW BLINDNESS: the distinct threshold never sits above the count threshold', () => {
    // The property that makes the AND safe. A principal touching N distinct
    // subjects has made at least N decrypts, so distinct <= count always;
    // with distinctMax <= countMax, anything clearing the count bound on
    // DISTINCT rows also clears the distinct bound. Were distinctMax the
    // larger, a mass read of countMax+1 DIFFERENT subjects would be
    // suppressed — the exfiltration this detector exists to catch.
    for (const row of DECRYPT_RATE_BOUNDS) {
      if (row.maxDistinctSubjectsPerWindow === undefined) {
        continue;
      }
      expect(row.maxDistinctSubjectsPerWindow).toBeLessThanOrEqual(row.maxPerWindow);
    }
  });

  it('the ZERO defaults never carry the condition (a loud bound must stay loud)', () => {
    // The corpus is the two zero-default classes that still EXIST, derived
    // rather than listed: an unregistered prefix and an unmodelled principal.
    // `distributions` stood here as the third until M48 PR3 gave it two
    // reviewed rows, at which point half this loop was asserting about a
    // 300-per-window bound under a test named for zero defaults — green, and
    // evidence of nothing. `unknownPrefix` is derived so a prefix added to the
    // registry cannot silently become this test's subject.
    const unknownPrefix = 'trust';
    expect(Object.keys(DECRYPT_FIELD_PREFIXES)).not.toContain(unknownPrefix);
    expect(boundFor(unknownPrefix, 'user').name).toBe('unknown_prefix');
    expect(boundFor(unknownPrefix, 'user').maxDistinctSubjectsPerWindow).toBeUndefined();

    expect(boundFor('doc', 'sentinel').name).toBe('unmodeled_principal');
    expect(boundFor('doc', 'sentinel').maxDistinctSubjectsPerWindow).toBeUndefined();
  });

  it('re-reading a bounded set of subjects is suppressed however high the count goes', () => {
    // THE MEASURED CASE: seven ordinary /assets loads of a 120-asset estate
    // produced 1680 decrypts over 120 subjects and raised the TB4 alarm on an
    // owner reading their own estate through the product's own pages.
    expect(evaluateDecryptRates([asset(1680, 120)])).toEqual([]);
    // Volume alone never breaches while the subject set stays small.
    expect(evaluateDecryptRates([asset(countMax * 100, 120)])).toEqual([]);
  });

  it('a mass read of DIFFERENT subjects still breaches — the positive control', () => {
    const breaches = evaluateDecryptRates([asset(countMax + 1, countMax + 1)]);
    expect(breaches).toHaveLength(1);
    expect(breaches[0]).toMatchObject({
      boundName: 'asset_user',
      count: countMax + 1,
      maxPerWindow: countMax,
      distinctSubjects: countMax + 1,
      maxDistinctSubjectsPerWindow: distinctMax,
    });
  });

  it('BOTH conditions are strict, and both must hold (the off-by-one on each axis)', () => {
    // At the count bound: silent whatever the subjects.
    expect(evaluateDecryptRates([asset(countMax, distinctMax + 1)])).toEqual([]);
    // Over the count bound, AT the distinct bound: still silent.
    expect(evaluateDecryptRates([asset(countMax + 1, distinctMax)])).toEqual([]);
    // Over both by one: breach.
    expect(evaluateDecryptRates([asset(countMax + 1, distinctMax + 1)])).toHaveLength(1);
  });

  it('a bound WITHOUT the condition ignores distinctSubjects entirely', () => {
    const docMax = boundFor('doc', 'user').maxPerWindow;
    // doc declares no subject, so its rows always report 0 distinct. If the
    // evaluator applied a distinct condition by default, this would be
    // suppressed — every un-conditioned bound in the table would go silent.
    const breaches = evaluateDecryptRates([obs({ count: docMax + 1, distinctSubjects: 0 })]);
    expect(breaches).toHaveLength(1);
    expect(breaches[0]?.distinctSubjects).toBeUndefined();
    expect(breaches[0]?.maxDistinctSubjectsPerWindow).toBeUndefined();
  });
});

describe('distinctSubjectExpression (the one place a query is built from a table)', () => {
  it('builds one CASE arm per declaration, at the declared segment', () => {
    expect(distinctSubjectExpression({ asset: 2 })).toBe(
      "CASE split_part(detail->>'field', '.', 1) WHEN 'asset' THEN split_part(detail->>'field', '.', 2) END",
    );
  });

  it('collapses to NULL with no declarations — `CASE END` is a syntax error', () => {
    // NULL keeps every distinct count at 0, which is the never-suppress
    // default: a bound with no distinct condition is unaffected, and one with
    // a condition would breach on count alone.
    expect(distinctSubjectExpression({})).toBe('NULL');
  });

  it.each([
    ['a prefix that is not an identifier', { "a'; DROP TABLE audit_events; --": 2 }],
    ['an uppercase prefix', { Asset: 2 }],
    ['a position of zero', { asset: 0 }],
    ['a fractional position', { asset: 1.5 }],
    ['a position past the end', { asset: 9 }],
    ['a declared-but-absent position', { asset: undefined }],
  ])('refuses %s rather than letting it become SQL', (_label, table) => {
    expect(() => distinctSubjectExpression(table)).toThrow(/decrypt-rate detector/);
  });
});

describe('mergeObservations (distinct counting)', () => {
  it('carries distinct_subjects through, and reads a missing column as 0', () => {
    const merged = mergeObservations([
      { prefix: 'asset', actor_type: 'user', actor_id: USER_A, n: 9, distinct_subjects: 4 },
      { prefix: 'doc', actor_type: 'user', actor_id: USER_B, n: 3 },
    ]);
    expect(merged).toEqual([
      { prefix: 'asset', actorType: 'user', actorId: USER_A, count: 9, distinctSubjects: 4 },
      { prefix: 'doc', actorType: 'user', actorId: USER_B, count: 3, distinctSubjects: 0 },
    ]);
  });

  it('SUMS distinct across merged rows — an upper bound, which fails toward breaching', () => {
    // The sentinel's two actor types merge onto one principal. Two rows may
    // have touched the same subject, so the sum over-counts; that errs toward
    // an alarm, which is the direction a SUPPRESSING condition must fail in.
    const merged = mergeObservations([
      {
        prefix: 'asset',
        actor_type: 'service',
        actor_id: SENTINEL_ACTOR_ID,
        n: 5,
        distinct_subjects: 5,
      },
      {
        prefix: 'asset',
        actor_type: 'system',
        actor_id: SENTINEL_ACTOR_ID,
        n: 7,
        distinct_subjects: 7,
      },
    ]);
    expect(merged).toEqual([
      {
        prefix: 'asset',
        actorType: 'service',
        actorId: SENTINEL_ACTOR_ID,
        count: 12,
        distinctSubjects: 12,
      },
    ]);
  });
});

/** DetectorDb whose rows are swapped per tick. */
class FakeDb implements DetectorDb {
  rows: Array<{
    prefix: string | null;
    actor_type: string;
    actor_id: string | null;
    n: number;
    distinct_subjects?: number;
  }> = [];
  queries = 0;
  fail = false;
  query(
    _text: string,
    _values: unknown[],
  ): Promise<{
    rows: FakeDb['rows'];
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

  it('the emitted detail carries the distinct numbers ONLY where the bound has them', async () => {
    // The doc case above asserts the detail with toEqual, so their ABSENCE is
    // already pinned there. This is the other half: a reader of the trail can
    // tell "read a lot" from "read a lot of DIFFERENT things", which is the
    // whole difference between a large estate and an exfiltration — and it is
    // counts and thresholds only, never the subjects themselves.
    const { db, detector, producer } = build();
    const mem = producer as InMemoryAuditProducer;
    const asset = boundFor('asset', 'user');
    const distinctMax = asset.maxDistinctSubjectsPerWindow as number;
    db.rows = [
      {
        prefix: 'asset',
        actor_type: 'user',
        actor_id: USER_A,
        n: asset.maxPerWindow + 2,
        distinct_subjects: distinctMax + 2,
      },
    ];
    await detector.tick();
    expect(mem.messages).toHaveLength(1);
    const event = AuditEventSchema.parse(JSON.parse(mem.messages[0]?.value ?? ''));
    expect(event.detail).toEqual({
      boundName: 'asset_user',
      principal: 'user',
      actorType: 'user',
      prefixClass: 'asset',
      count: asset.maxPerWindow + 2,
      bound: asset.maxPerWindow,
      windowSeconds: DECRYPT_WINDOW_SECONDS,
      distinctSubjects: distinctMax + 2,
      distinctBound: distinctMax,
    });
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

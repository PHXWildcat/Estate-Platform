import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { AUDIT_ACTIONS } from '@estate/contracts';

/**
 * M49 PR6 — WHICH ITEM-LADDER EVENTS OWE A PRIOR STATUS, DERIVED.
 *
 * M49 PR3 derived the rule from SQL: a status write whose `WHERE` pins one
 * prior owes nothing, one admitting more owes a `from`, one the scan cannot
 * read owes a `from` too. M49 PR4 found a service where every write is
 * `WHERE id = $1` and derived the same rule from the guard chain above the
 * write instead. THIS SERVICE NARROWS NOWHERE. Every write of
 * `plaid_items.status` is `WHERE id = $1 AND deleted_at IS NULL`, and the
 * service compares `.status` in no method that writes it — so PR3's reading
 * and PR4's reading AGREE, for the first time in the milestone, that all four
 * writes owe a `from`. This fence reads both and says so.
 *
 * WHAT THAT COSTS, STATED UP FRONT. PR3's fence had five single-prior
 * statements and PR4's had one, each a positive control the scan itself
 * produced: an exemption DERIVED from the corpus, proving the classifier can
 * answer "owes nothing". This corpus has none, so a fence over it that only
 * ever answers "owes" is indistinguishable from one that has stopped reading.
 * The controls below are therefore SYNTHETIC — a statement with a predicate
 * and a method with a guard, fed to the same classifiers the corpus goes
 * through — and each is labelled as such. A synthetic control proves the
 * classifier; only a corpus control would prove the classifier against this
 * service's own spelling, and there is nothing in the service to prove it on.
 *
 * WHAT IS DERIVED AND WHAT IS NOT. Derived: the status vocabulary (from every
 * `CHECK (status IN (…))` the migration SET contains, in order, the last one
 * winning as it does in the database — never from the `CREATE TABLE` body
 * alone, which is the one statement an append-only set can never change), the
 * writers and what each assigns (from the runtime
 * SQL, with a parameterised target resolved from the literals its call sites
 * pass), the status no lock can ever observe (as a difference: written only
 * beside `deleted_at`, and every writer filters `deleted_at IS NULL`), the
 * absence of a from-predicate — CTE INCLUDED, the bound PR5's fence recorded
 * and this one closes for this service — the absence of a guard chain, and
 * the pairing of each write with the emitter that follows it. Hand-named: the
 * two FILES the site half reads — `plaid.service.ts` and `events.service.ts`
 * — while `statusWriters()` reads every `.ts` under `src`. And one bound the
 * resolver imposes: a call site passing a VARIABLE as the target rather than a
 * literal is invisible to it, so the fence refuses such a call site rather
 * than under-reporting — see `parameterisedTargets`.
 *
 * Every expectation ABOUT THE CORPUS is a set or a keyed object, never an
 * ordered array, so that mis-attribution cannot preserve a passing count. The
 * synthetic controls below do compare ordered arrays, because what they assert
 * is the classifier's own output shape rather than a set of findings.
 *
 * WHAT THE PR'S REVIEW ADDED TO THIS FILE. Every mutation below went green
 * against some earlier draft of this file, and each is a control now: a writer
 * in a method the literal reader could not see, a fifth status added by a later
 * migration, a status write spelled as an upsert's conflict arm, a guard
 * written on a destructured `status`, a detail key renamed away from `from`, a
 * negated predicate read as a pin, a stale pre-read routed out through the
 * transaction's own return, the two statements of `revoke()` reversed, and a
 * SECOND writer in `src` injecting the same repository under another property
 * name. A fence that only ever reads what its author happened to write is a
 * fence sized to the draft it was written against; the count is deliberately
 * left to the tests below rather than restated here, where it would rot.
 */

const SRC = join(__dirname, '..', 'src');
const MIGRATIONS = join(__dirname, '..', 'migrations');
const TABLE = 'plaid_items';

const sourceFiles = (dir: string, ext: string): string[] =>
  readdirSync(dir, { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith(ext));

const read = (dir: string, file: string): string => readFileSync(join(dir, file), 'utf8');

/**
 * Block comments carry backticks (JSDoc quotes identifiers), and a backtick
 * inside a comment is not a template literal. Line comments are stripped only
 * where they START a line, so `--` inside SQL and `//` inside a string are left
 * alone. Nothing in this service puts a URL or a `/*` inside a literal; if
 * that changes, the corpus floor below is the first thing to move.
 */
function stripComments(source: string): string {
  // `^[ \t]*` and not `^\s*`: `\s` matches the newline itself, so on a file of
  // blank lines the second pattern backtracks across them — 50 KB of newlines
  // took 2.1 s in the review's timing harness. A fence's own execution is a
  // defect surface, not only its conclusions.
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

// --------------------------------------------------------------------------
// 1. THE VOCABULARY, FROM THE DDL
// --------------------------------------------------------------------------

/** The `CREATE TABLE plaid_items (...)` body, and only that table's. */
function itemsTableBody(): string {
  const bodies: string[] = [];
  for (const file of sourceFiles(MIGRATIONS, '.sql')) {
    for (const m of read(MIGRATIONS, file).matchAll(
      new RegExp(`CREATE TABLE\\s+${TABLE}\\s*\\(([\\s\\S]*?)\\n\\);`, 'gi'),
    )) {
      bodies.push(m[1] as string);
    }
  }
  expect(bodies).toHaveLength(1);
  return bodies[0] as string;
}

/**
 * Every statement in the migration set that DEFINES the status vocabulary — the
 * `CREATE TABLE` body and any later `ALTER TABLE … CHECK (status IN (…))` — in
 * migration order. Migrations are append-only, so a widened vocabulary arrives
 * as a new file rather than as an edit to the old one; a reader of the
 * `CREATE TABLE` alone reads the one statement that can never change. The
 * review proved that by adding a migration with a fifth status: the fence
 * stayed 14/14 green while the ladder had grown a rung.
 */
function statusCheckDefinitions(): string[][] {
  const out: string[][] = [];
  const files = sourceFiles(MIGRATIONS, '.sql').sort();
  for (const file of files) {
    const source = read(MIGRATIONS, file);
    const scopes = source.includes(`CREATE TABLE ${TABLE}`) ? [itemsTableBody()] : [];
    for (const alter of source.matchAll(
      new RegExp(`ALTER TABLE\\s+${TABLE}\\b[\\s\\S]*?;`, 'gi'),
    )) {
      scopes.push(alter[0]);
    }
    for (const scope of scopes) {
      for (const check of scope.matchAll(/CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)/gi)) {
        out.push((check[1] as string).split(',').map((v) => v.trim().replace(/^'|'$/g, '')));
      }
    }
  }
  return out;
}

function ddlStatuses(): string[] {
  const definitions = statusCheckDefinitions();
  expect(definitions.length).toBeGreaterThan(0);
  // The LAST definition wins, as it does in the database.
  return definitions[definitions.length - 1] as string[];
}

function ddlDefaultStatus(): string | null {
  const m = /\bstatus\s+TEXT[^,]*?DEFAULT\s+'([a-z_]+)'/i.exec(itemsTableBody());
  return m ? (m[1] as string) : null;
}

// --------------------------------------------------------------------------
// 2. THE WRITERS, FROM THE RUNTIME SQL
// --------------------------------------------------------------------------

interface Writer {
  file: string;
  method: string;
  /** A literal target, or the placeholder a caller fills in. */
  assigns: { literal: string } | { param: string };
  /** EVERY `WHERE` in the statement, the CTE's included. */
  predicates: string[];
  tombstones: boolean;
  /**
   * Sets `deleted_at = NULL` — a RESURRECTION, which would make a status this
   * fence derives as unobservable observable again. None today; read rather
   * than assumed, because the derivation of `livePriors()` depends on it.
   */
  untombstones: boolean;
  filtersDeleted: boolean;
}

/**
 * The class members of a file, by name, each with the text that runs until the
 * next member. Shared by the literal reader and the body readers so that a
 * method shape one of them can see is a method shape all of them can see.
 *
 * A first spelling anchored on `async\s+(\w+)\s*\(` and took ONE literal per
 * match: a writer in a non-`async` method was invisible, and so was a writer
 * whose method built any other template literal first. The review proved both
 * by adding a `forceStatus` writer behind a preceding literal and a new webhook
 * rung that called it with no event — the fence stayed 14/14 green. It reads
 * every member and every literal now, and `rawLadderStatements()` below is the
 * floor that makes an unattributable writer a FAILURE rather than an absence.
 */
function classMembers(source: string): Array<{ name: string; text: string }> {
  const clean = stripComments(source);
  const heads = [
    ...clean.matchAll(
      /^ {2}(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:async\s+)?(\w+)\s*\(/gm,
    ),
  ];
  return heads
    .map((h, i) => ({
      name: h[1] as string,
      text: clean.slice(h.index, i + 1 < heads.length ? heads[i + 1]!.index : clean.length),
    }))
    .filter((m) => m.name !== 'constructor');
}

/** The text of EVERY template literal in a file, comments stripped, with the method it sits in. */
function literalsByMethod(source: string): Array<{ method: string; sql: string }> {
  const out: Array<{ method: string; sql: string }> = [];
  for (const member of classMembers(source)) {
    for (const lit of member.text.matchAll(/`([^`]*)`/g)) {
      out.push({
        method: member.name,
        sql: (lit[1] as string)
          .replace(/--[^\n]*/g, ' ')
          .replace(/\s+/g, ' ')
          .trim(),
      });
    }
  }
  return out;
}

/**
 * What a SET clause does to `deleted_at`: writes a value (a tombstone), writes
 * NULL (a resurrection), or does not name it. Read by capturing the VALUE and
 * comparing it — a negative lookahead after `\\s*` can slide past the space and
 * match `= NULL` as "not NULL", which is how the first spelling of this read
 * classified an un-tombstoning upsert as a tombstone.
 */
function deletedAtWrite(setClause: string): 'tombstone' | 'resurrect' | 'none' {
  const m = /\bdeleted_at\s*=\s*([A-Za-z0-9_$'.]+)/i.exec(setClause);
  if (!m) return 'none';
  return /^null$/i.test(m[1] as string) ? 'resurrect' : 'tombstone';
}

/**
 * Every `UPDATE plaid_items` the source contains, counted RAW — no method
 * attribution, no literal parsing, just the statement keyword. The floor the
 * reader above must meet: a statement this count sees and `statusWriters()`
 * cannot attribute is a writer the fence would otherwise not know exists.
 */
function rawLadderStatements(): number {
  let n = 0;
  for (const file of sourceFiles(SRC, '.ts')) {
    const source = stripComments(read(SRC, file));
    n += (source.match(new RegExp(`UPDATE\\s+${TABLE}\\b`, 'gi')) ?? []).length;
    // AND THE UPSERT SPELLING. `INSERT INTO plaid_items … ON CONFLICT … DO
    // UPDATE SET status = …` writes the ladder without ever emitting the token
    // sequence `UPDATE plaid_items`, so a floor anchored on that sequence has
    // the blind spot of every reader it is supposed to backstop. M49 PR6's
    // review added a `relink` rung spelled that way — un-tombstoning a revoked
    // item straight to `healthy`, emitting no `from` — and the whole fence
    // stayed green. The idiom is already in this service: `accounts.repo.ts`
    // upserts exactly like that.
    for (const insert of source.matchAll(new RegExp(`INSERT\\s+INTO\\s+${TABLE}\\b`, 'gi'))) {
      const tail = source.slice(insert.index, insert.index + 2000);
      if (/\bON\s+CONFLICT\b[\s\S]{0,200}?\bDO\s+UPDATE\s+SET\b/i.test(tail)) n += 1;
    }
  }
  return n;
}

/**
 * Every `WHERE` clause in a statement, each cut at the next clause keyword at
 * the clause's own paren depth, or at the `)` that closes the CTE it sits in.
 * A first spelling cut at the first `)` it met, which truncated an
 * `IN ('a', 'b')` list — the synthetic control below caught it on the fence's
 * first run, which is the argument for having synthetic controls at all.
 */
function whereClauses(sql: string): string[] {
  const out: string[] = [];
  // Sticky, tested at an index: `stop.test(sql.slice(i))` allocated a fresh
  // suffix string per character, which is quadratic in the statement's length.
  const stop = /(?:FOR UPDATE|RETURNING|ORDER BY)\b/iy;
  for (const m of sql.matchAll(/\bWHERE\b/gi)) {
    let depth = 0;
    let i = m.index + m[0].length;
    const start = i;
    for (; i < sql.length; i += 1) {
      const ch = sql[i] as string;
      if (ch === '(') depth += 1;
      else if (ch === ')') {
        if (depth === 0) break;
        depth -= 1;
      } else if (depth === 0) {
        stop.lastIndex = i;
        if (stop.test(sql)) break;
      }
    }
    const clause = sql.slice(start, i).trim();
    if (clause.length > 0) out.push(clause);
  }
  return out;
}

function statusWriters(): Writer[] {
  const found: Writer[] = [];
  for (const file of sourceFiles(SRC, '.ts')) {
    for (const { method, sql } of literalsByMethod(read(SRC, file))) {
      const assign =
        new RegExp(
          `UPDATE\\s+${TABLE}\\b[\\s\\S]*?\\bSET\\s+([\\s\\S]*?)(?:\\bFROM\\b|\\bWHERE\\b|\\bRETURNING\\b|$)`,
          'i',
        ).exec(sql) ??
        // The upsert's conflict arm is a status write with no `UPDATE <table>`
        // in it. Same classification, second spelling — read, not assumed
        // absent (M49 PR6's review).
        new RegExp(
          `INSERT\\s+INTO\\s+${TABLE}\\b[\\s\\S]*?\\bON\\s+CONFLICT\\b[\\s\\S]*?\\bDO\\s+UPDATE\\s+SET\\s+([\\s\\S]*?)(?:\\bWHERE\\b|\\bRETURNING\\b|$)`,
          'i',
        ).exec(sql);
      if (!assign) continue;
      const setClause = assign[1] as string;
      const status = /(?:^|,)\s*status\s*=\s*(?:'([a-z_]+)'|(\$\d+))/i.exec(setClause);
      if (!status) continue;
      const predicates = whereClauses(sql);
      found.push({
        file,
        method,
        assigns: status[1] ? { literal: status[1] } : { param: status[2] as string },
        predicates,
        tombstones: deletedAtWrite(setClause) === 'tombstone',
        untombstones: deletedAtWrite(setClause) === 'resurrect',
        filtersDeleted: predicates.some((p) => /\bdeleted_at\s+IS\s+NULL\b/i.test(p)),
      });
    }
  }
  return found;
}

/**
 * The status the INSERT assigns, if any. It assigns none — `status` arrives by
 * column default — so creation is a statement and not a transition, and
 * `plaid.item.linked` is its record. Read rather than asserted, so an INSERT
 * that starts naming a status becomes a writer this fence has not paired.
 */
function insertAssignsStatus(): boolean {
  for (const file of sourceFiles(SRC, '.ts')) {
    for (const { sql } of literalsByMethod(read(SRC, file))) {
      const insert = new RegExp(`INSERT INTO\\s+${TABLE}\\s*\\(([^)]*)\\)`, 'i').exec(sql);
      if (insert && /\bstatus\b/i.test(insert[1] as string)) return true;
      // The conflict arm too: `DO UPDATE SET status = …` assigns a status from
      // an INSERT statement, which is the shape this reader is named for.
      const conflict = new RegExp(
        `INSERT\\s+INTO\\s+${TABLE}\\b[\\s\\S]*?\\bDO\\s+UPDATE\\s+SET\\s+([\\s\\S]*?)(?:\\bWHERE\\b|\\bRETURNING\\b|$)`,
        'i',
      ).exec(sql);
      if (conflict && /(?:^|,)\s*status\s*=/i.test(conflict[1] as string)) return true;
    }
  }
  return false;
}

/** From the first `(` at or after `from`, the call text up to its matching `)`. */
function balancedCall(source: string, from: number): string {
  const open = source.indexOf('(', from);
  if (open === -1) return '';
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i] as string;
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  return source.slice(open);
}

/**
 * Does the transaction callback containing this write return the write's own
 * answer, and only that? Derived from the callback text: the identifier the
 * writer's call is bound to, and every `return` in the callback compared
 * against it. An arrow that IS the call — `(tx) => this.items.setStatus(...)` —
 * returns the answer by construction.
 */
function answerFlows(callback: string, writer: string): boolean {
  const direct = new RegExp(`=>\\s*this\\.${REPO}\\.${writer}\\(`).test(callback);
  if (direct) return true;
  const bound = new RegExp(`const\\s+(\\w+)\\s*=\\s*await\\s+this\\.${REPO}\\.${writer}\\(`).exec(
    callback,
  );
  if (!bound) return false;
  const inner = bound[1] as string;
  const returns = [...callback.matchAll(/\breturn\s+([^;]+);/g)].map((r) =>
    (r[1] as string).trim(),
  );
  if (returns.length === 0) return false;
  return returns.every((r) => r === inner || r === 'null');
}

/**
 * The literal targets a parameterised writer's callers pass. Refuses a call
 * site that passes anything but a literal, because a target it cannot read
 * would otherwise be a transition it silently does not pair.
 */
function parameterisedTargets(method: string): string[] {
  const targets: string[] = [];
  for (const file of sourceFiles(SRC, '.ts')) {
    const clean = stripComments(read(SRC, file));
    for (const call of clean.matchAll(new RegExp(`this\\.${REPO}\\.${method}\\(([^)]*)\\)`, 'g'))) {
      const args = (call[1] as string).split(',').map((a) => a.trim());
      const literal = args.find((a) => /^'[a-z_]+'$/.test(a));
      expect({ file, call: call[0], readable: literal !== undefined }).toEqual({
        file,
        call: call[0],
        readable: true,
      });
      targets.push((literal as string).replace(/^'|'$/g, ''));
    }
  }
  return targets;
}

/** Every SELECT that reads the table, and whether it filters the tombstone. */
function liveReads(): Array<{ method: string; filtersDeleted: boolean }> {
  const out: Array<{ method: string; filtersDeleted: boolean }> = [];
  for (const file of sourceFiles(SRC, '.ts')) {
    for (const { method, sql } of literalsByMethod(read(SRC, file))) {
      if (!new RegExp(`^SELECT\\b[\\s\\S]*\\bFROM\\s+${TABLE}\\b`, 'i').test(sql)) continue;
      out.push({ method, filtersDeleted: /\bdeleted_at\s+IS\s+NULL\b/i.test(sql) });
    }
  }
  return out;
}

// --------------------------------------------------------------------------
// 3. THE PREDICATE CLASSIFIER, SHARED BY THE CORPUS AND ITS CONTROLS
// --------------------------------------------------------------------------

type Predicate =
  | { shape: 'none' }
  | { shape: 'single'; status: string }
  | { shape: 'multi'; statuses: string[] }
  | { shape: 'unreadable' };

/**
 * What a statement's own predicates say about the prior status. `none` is the
 * honest answer for this corpus; the other three shapes are exercised by the
 * synthetic controls below and exist so that a predicate ARRIVING here is
 * classified rather than ignored.
 */
function statusPredicateOf(predicates: string[]): Predicate {
  const mentions = predicates.filter((p) => /\bstatus\b/i.test(p));
  if (mentions.length === 0) return { shape: 'none' };
  const literals = new Set<string>();
  for (const p of mentions) {
    // A NEGATED equality admits every status BUT the named one, and reading it
    // as a pin on that one is the fail-OPEN direction: the classifier would
    // answer "owes nothing" for a statement that owes everything. The review
    // found `NOT (status = 'a')` classified as `single`.
    if (/\bNOT\b/i.test(p)) return { shape: 'unreadable' };
    const single = /\bstatus\s*=\s*'([a-z_]+)'/i.exec(p);
    const list = /\bstatus\s+IN\s*\(([^)]*)\)/i.exec(p);
    if (single && !/\bOR\b/i.test(p)) {
      literals.add(single[1] as string);
    } else if (list) {
      for (const s of (list[1] as string).split(',')) literals.add(s.trim().replace(/^'|'$/g, ''));
    } else {
      return { shape: 'unreadable' };
    }
  }
  return literals.size === 1
    ? { shape: 'single', status: [...literals][0] as string }
    : { shape: 'multi', statuses: [...literals] };
}

// --------------------------------------------------------------------------
// 4. THE SITES, FROM THE SERVICE — write, binding, guard, emitter
// --------------------------------------------------------------------------

const SERVICE_FILE = 'plaid.service.ts';
const EVENTS_FILE = 'events.service.ts';
const WRITER_CLASS = 'ItemsRepo';

/**
 * The property the service holds the writer repository on, read from the
 * CONSTRUCTOR PARAMETER whose TYPE is the repository class — what Nest wires,
 * rather than the name whoever wrote the parameter chose. A fence anchored on
 * the identifier `items` reports "nothing else calls a ladder writer" about a
 * spelling instead of about a fact, and a rename would make every site vanish
 * silently. M49 PR6's review found that anchoring; CLAUDE.md names the class.
 */
function repoProperty(file: string, className: string): string {
  const source = stripComments(read(SRC, file));
  const m = new RegExp(
    `(?:private|public|protected)\\s+readonly\\s+(\\w+)\\s*:\\s*${className}\\b`,
  ).exec(source);
  expect({ file, className, found: m !== null }).toEqual({ file, className, found: true });
  return (m as RegExpExecArray)[1] as string;
}

const REPO = repoProperty(SERVICE_FILE, WRITER_CLASS);
const CHILD_REPO = repoProperty(SERVICE_FILE, 'AccountsRepo');

/**
 * Every `withTransaction(` callback in the service, with the offsets at which
 * it first touches the ITEM row and the ACCOUNT rows. The lock order is a
 * property of the pair, not of one method: `revoke()` locks the item then its
 * accounts, and until M49 PR6 `syncItem` locked them the other way round, which
 * Postgres resolved with a 40P01 that killed the revoke — the protective action
 * — after Plaid had already dropped the token. Prose in two files said "the
 * item first, on both sides"; the review reversed revoke()'s two statements and
 * the whole suite stayed green, because the drive that proves the order
 * hand-rolls revoke's half rather than reading it. This reads it.
 */
function transactionLockOrder(): Array<{ method: string; item: number; child: number }> {
  const out: Array<{ method: string; item: number; child: number }> = [];
  for (const [method, body] of methodBodies(SERVICE_FILE)) {
    for (const open of body.matchAll(/this\.db\.withTransaction\(/g)) {
      const callback = balancedCall(body, open.index);
      const item = callback.search(new RegExp(`this\\.${REPO}\\.\\w+\\(`));
      const child = callback.search(new RegExp(`this\\.${CHILD_REPO}\\.\\w+\\(`));
      if (item === -1 || child === -1) continue;
      out.push({ method, item, child });
    }
  }
  return out;
}

/** Class methods of a file, by name, body only (from the opening brace). */
function methodBodies(file: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const member of classMembers(read(SRC, file))) {
    // The body begins after the return annotation; a method without one is
    // reported as unreadable rather than guessed at. `[^{;]{0,200}` bounds the
    // annotation — an unbounded `[^{]*` backtracks on a pathological input.
    const open = /\)\s*:\s*[^{;]{0,200}\{/.exec(member.text);
    out.set(member.name, open ? member.text.slice(open.index + open[0].length) : '');
  }
  return out;
}

type Narrowing =
  | { shape: 'none' }
  | { shape: 'refuse'; statuses: string[] }
  | { shape: 'allow'; statuses: string[] }
  | { shape: 'unreadable' };

/**
 * PR4's three readable shapes, on a service that exhibits none of them. A
 * comparison of `.status` guarding a `throw` is a refusal list (`!==` allows,
 * `===` refuses); one guarding anything else cannot be read as a narrowing
 * and owes a `from` — fail closed.
 */
function statusReadsNormalised(body: string): string {
  // `const { status } = item;` then `status !== 'healthy'` is the same read as
  // `item.status !== 'healthy'`, and the review proved a guard written that way
  // invisible to BOTH this classifier and the `.status` count that pins how
  // often the service reads the column. Rewriting the alias back to the member
  // access makes one spelling of the read out of two.
  let out = body;
  for (const d of body.matchAll(/const\s*\{\s*status(?:\s*:\s*(\w+))?\s*\}\s*=\s*(\w+)/g)) {
    const alias = d[1] ?? 'status';
    const object = d[2] as string;
    out = out.replace(new RegExp(`\\b${alias}\\b(?!\\s*[:(])`, 'g'), `${object}.status`);
  }
  return out;
}

function narrowingOf(source: string): Narrowing {
  const body = statusReadsNormalised(source);
  const comparisons = [...body.matchAll(/\.status\s*(===|!==)\s*'([a-z_]+)'([^;]*)/g)];
  if (comparisons.length === 0) return { shape: 'none' };
  const refuse: string[] = [];
  const allow: string[] = [];
  for (const c of comparisons) {
    const guardsThrow = /\bthrow\b/.test(c[3] as string);
    if (!guardsThrow) return { shape: 'unreadable' };
    (c[1] === '===' ? refuse : allow).push(c[2] as string);
  }
  if (allow.length > 0 && refuse.length > 0) return { shape: 'unreadable' };
  return allow.length > 0
    ? { shape: 'allow', statuses: allow }
    : { shape: 'refuse', statuses: refuse };
}

interface Site {
  /** `<method>:<target>` — `syncItem` writes twice, so the method alone is not a key. */
  key: string;
  writer: string;
  target: string;
  /** The identifier the write's answer was bound to, or null if discarded. */
  binding: string | null;
  emitter: string | null;
  /** The emitter receives the binding — the prior the WRITE answered, not a pre-read. */
  passesBinding: boolean;
  /**
   * And the binding's own value came from the WRITER's answer and nothing else:
   * every non-null thing the transaction callback returns is the identifier the
   * write was bound to. `return was ?? stale` satisfies `passesBinding` and is
   * exactly the stale pre-read this mechanism replaces — the review proved that
   * mutation green across all fourteen fence tests.
   */
  answerFlows: boolean;
  /**
   * A null check on the binding stands between the write and the emit — the
   * emit inside `if (<binding> !== null)`, or an `if (<binding> === null)` that
   * returns before it. Both are the same guard; the second is the shape a
   * transaction callback takes when the write is its FIRST statement.
   */
  guarded: boolean;
  narrowing: Narrowing;
}

function ladderSites(writers: Writer[]): Site[] {
  const writerNames = new Set(writers.map((w) => w.method));
  const sites: Site[] = [];
  for (const [method, body] of methodBodies(SERVICE_FILE)) {
    for (const write of body.matchAll(new RegExp(`this\\.${REPO}\\.(\\w+)\\(([^)]*)\\)`, 'g'))) {
      const writer = write[1] as string;
      if (!writerNames.has(writer)) continue;
      const literal = /'([a-z_]+)'/.exec(write[2] as string);
      const assigns = writers.find((w) => w.method === writer)?.assigns;
      const target =
        literal?.[1] ??
        (assigns !== undefined && 'literal' in assigns ? assigns.literal : undefined);
      if (!target) continue;
      const before = body.slice(0, write.index);
      const bindings = [
        ...before.matchAll(/const\s+(\w+)\s*=\s*await\s+this\.db\.withTransaction\(/g),
      ];
      const opened = bindings.length > 0 ? bindings[bindings.length - 1]! : null;
      const binding = opened ? (opened[1] as string) : null;
      // The transaction call in full, cut at the `)` that closes it rather than
      // at a fixed distance — the callback's own `return` is what the
      // answer-flow reading is about, and it sits after the write.
      const callback = opened ? balancedCall(body, opened.index) : '';
      const after = body.slice(write.index + write[0].length);
      const emit = /this\.events\.(\w+)\(([\s\S]*?)\);/.exec(after);
      const between = emit ? after.slice(0, emit.index) : after;
      sites.push({
        key: `${method}:${target}`,
        writer,
        target,
        binding,
        emitter: emit ? (emit[1] as string) : null,
        passesBinding:
          binding !== null &&
          emit !== null &&
          new RegExp(`\\b${binding}\\b`).test(emit[2] as string),
        guarded:
          binding !== null && new RegExp(`if \\(${binding} (?:!==|===) null\\)`).test(between),
        answerFlows: answerFlows(callback, writer),
        narrowing: narrowingOf(body),
      });
    }
  }
  return sites;
}

// --------------------------------------------------------------------------
// 5. THE EMITTERS, FROM THE EVENTS SERVICE
// --------------------------------------------------------------------------

interface Emitter {
  action: string;
  carriesFrom: boolean;
}

/**
 * Each emitter method's audit action, read off the emit itself — `this.item('…'`
 * or `action: '…'` — and whether the detail that emit builds names `from`.
 * The domain-event type strings in the same methods are not audit actions and
 * are not matched by either pattern.
 */
function emitters(): Map<string, Emitter> {
  const out = new Map<string, Emitter>();
  for (const [method, body] of methodBodies(EVENTS_FILE)) {
    const hit = /this\.item\(\s*'([a-z_.]+)'|action:\s*'([a-z_.]+)'/.exec(body);
    if (!hit) continue;
    const emitText = body.slice(hit.index, body.indexOf(');', hit.index));
    out.set(method, {
      action: (hit[1] ?? hit[2]) as string,
      // The KEY the wire carries, not the identifier the code passes:
      // `detail: { previous: from }` names `from` and carries `previous`, and
      // the review proved that rename green through fence and unit spec alike,
      // leaving only the CI-only integration drives to catch it. A property
      // begins at a `{` or a `,`, so a value in that position is not a key.
      carriesFrom: /[{,]\s*from\s*[,:}]/.test(emitText),
    });
  }
  return out;
}

// --------------------------------------------------------------------------

const DDL = ddlStatuses();
const WRITERS = statusWriters();
/**
 * `UPDATE plaid_items` statements the reader attributed to a method but that
 * assign no status — `setCursor` today. Derived, so that the raw floor above
 * compares like with like instead of carrying a hand-written allowance.
 */
const UPDATES_WITHOUT_STATUS = (() => {
  let n = 0;
  for (const file of sourceFiles(SRC, '.ts')) {
    for (const { sql } of literalsByMethod(read(SRC, file))) {
      if (!new RegExp(`UPDATE\\s+${TABLE}\\b`, 'i').test(sql)) continue;
      if (!/\bSET\b[\s\S]*?\bstatus\s*=/i.test(sql)) n += 1;
    }
  }
  return n;
})();
const SITES = ladderSites(WRITERS);
const EMITTERS = emitters();

/** Live priors: the DDL minus what is only ever written beside a tombstone. */
function livePriors(): string[] {
  const tombstoned = new Set(
    WRITERS.filter((w) => w.tombstones && 'literal' in w.assigns).map(
      (w) => (w.assigns as { literal: string }).literal,
    ),
  );
  return DDL.filter((s) => !tombstoned.has(s));
}

describe('the item ladder vocabulary, derived from the DDL and the writers', () => {
  it('reads a corpus big enough to be believed', () => {
    // Anti-vacuity at every LEVEL, not just the total: an empty directory and
    // a clean scan look identical otherwise.
    // AND THE RAW FLOOR: every `UPDATE plaid_items` the source contains, found
    // by keyword alone, against the ones the method-and-literal reader could
    // attribute. A writer the reader cannot see is a rung with no event, and
    // the difference between these two numbers is the only way the fence can
    // notice one. Three statements write the table; two of them write `status`.
    const attributed = WRITERS.length + UPDATES_WITHOUT_STATUS;
    expect({
      migrations: sourceFiles(MIGRATIONS, '.sql').length >= 2,
      srcFiles: sourceFiles(SRC, '.ts').length >= 20,
      ddlStatuses: DDL.length,
      ddlDefinitions: statusCheckDefinitions().length,
      writers: WRITERS.length,
      rawStatements: rawLadderStatements(),
      attributed,
      sites: SITES.length,
      emitters: EMITTERS.size,
      liveReads: liveReads().length,
    }).toEqual({
      migrations: true,
      srcFiles: true,
      ddlStatuses: 4,
      ddlDefinitions: 1,
      writers: 2,
      rawStatements: 3,
      attributed: 3,
      sites: 4,
      emitters: 7,
      liveReads: 3,
    });
  });

  it('DERIVES the status that is written but can never be a PRIOR', () => {
    // Two facts, both read: `revoked` is assigned only beside `deleted_at`, and
    // every status write AND every live read filters `deleted_at IS NULL`. So
    // no write can find a revoked row to move, and no `from` can ever say
    // `revoked`. The assertion is the SET of statements that fail to filter —
    // a count of the ones that do would survive a swap.
    expect({
      tombstoned: new Set(
        WRITERS.filter((w) => w.tombstones).map((w) =>
          'literal' in w.assigns ? w.assigns.literal : w.assigns.param,
        ),
      ),
      writersNotFiltering: WRITERS.filter((w) => !w.filtersDeleted).map((w) => w.method),
      // A write that CLEARS `deleted_at` would make `revoked` observable again
      // and break the difference this test derives. None; read, not assumed.
      untombstoning: WRITERS.filter((w) => w.untombstones).map((w) => w.method),
      readsNotFiltering: liveReads()
        .filter((r) => !r.filtersDeleted)
        .map((r) => r.method),
    }).toEqual({
      tombstoned: new Set(['revoked']),
      writersNotFiltering: [],
      untombstoning: [],
      readsNotFiltering: [],
    });
  });

  it('states the prior vocabulary as the difference, not as a list', () => {
    expect(new Set(livePriors())).toEqual(new Set(['healthy', 'login_required', 'error']));
    // The default is a live prior: a freshly linked item can be moved by
    // every writer, which is why `healthy → healthy` is one of the twelve edges.
    expect(livePriors()).toContain(ddlDefaultStatus());
  });

  it('finds every statement that writes the ladder, keyed on what it ASSIGNS', () => {
    // `setStatus` assigns `$2`; its three call sites pass three literals, and
    // the resolver refuses a fourth that passes a variable. So the ladder has
    // two statements and four targets, and every target in the DDL is written
    // by exactly one of them — nothing in the CHECK is dead.
    const assigned = new Map<string, string>();
    for (const w of WRITERS) {
      const targets = 'literal' in w.assigns ? [w.assigns.literal] : parameterisedTargets(w.method);
      for (const t of targets) assigned.set(`${TABLE}:${t}`, w.method);
    }
    expect(Object.fromEntries(assigned)).toEqual({
      'plaid_items:login_required': 'setStatus',
      'plaid_items:error': 'setStatus',
      'plaid_items:healthy': 'setStatus',
      'plaid_items:revoked': 'markRevoked',
    });
    expect(new Set([...assigned.keys()].map((k) => k.slice(TABLE.length + 1)))).toEqual(
      new Set(DDL),
    );
    // Creation is by column default — a statement, not a transition.
    expect(insertAssignsStatus()).toBe(false);
  });
});

describe('no statement pins a prior — not in SQL, and not in TypeScript', () => {
  it('finds NO status predicate in any status write, the CTE INCLUDED', () => {
    // THE BOUND PR5'S FENCE RECORDED, CLOSED HERE: `erasure-ladder-fence` read
    // one `WHERE` per statement and so never read the claim's, which had moved
    // into its CTE. `whereClauses` returns every `WHERE` in the statement, so
    // the pre-image's `WHERE id = $1 AND deleted_at IS NULL` is in this list
    // beside the UPDATE's own join predicate — two per writer, and neither
    // names a status. If either statement ever gains one, this reddens and the
    // obligation below stops being uniform.
    expect(
      Object.fromEntries(
        WRITERS.map((w) => [
          w.method,
          { clauses: w.predicates.length, predicate: statusPredicateOf(w.predicates) },
        ]),
      ),
    ).toEqual({
      setStatus: { clauses: 2, predicate: { shape: 'none' } },
      markRevoked: { clauses: 2, predicate: { shape: 'none' } },
    });
  });

  it('finds NO guard chain above any site', () => {
    // PR4's reading, applied and answering `none` four times: the service
    // reads `.status` in exactly one place, `toItemView`, which writes nothing.
    expect(Object.fromEntries(SITES.map((s) => [s.key, s.narrowing]))).toEqual({
      'handleWebhook:login_required': { shape: 'none' },
      'syncItem:error': { shape: 'none' },
      'syncItem:healthy': { shape: 'none' },
      'revoke:revoked': { shape: 'none' },
    });
    // Counted on the NORMALISED source, so that `const { status } = item` is
    // one read and not zero — the shape the review slipped a guard through.
    const service = statusReadsNormalised(stripComments(read(SRC, SERVICE_FILE)));
    expect(service.match(/\.status\b/g)).toHaveLength(1);
  });

  it('READS a predicate when one arrives — SYNTHETIC controls, because this corpus has none', () => {
    // A classifier that answered `none` for everything would pass the corpus
    // test above for the same reason it is wrong. These four shapes are the
    // ones PR3 and PR5 met in their corpora; none exists in this one, and the
    // header says what that means for the strength of the control.
    expect(
      statusPredicateOf(
        whereClauses("UPDATE t SET status = 'x' WHERE id = $1 AND status = 'healthy'"),
      ),
    ).toEqual({
      shape: 'single',
      status: 'healthy',
    });
    expect(
      statusPredicateOf(
        whereClauses("UPDATE t SET status = 'x' WHERE id = $1 AND status IN ('healthy', 'error')"),
      ),
    ).toEqual({ shape: 'multi', statuses: ['healthy', 'error'] });
    expect(
      statusPredicateOf(
        whereClauses('UPDATE t SET status = $2 WHERE id = $1 AND status = ANY($3)'),
      ),
    ).toEqual({
      shape: 'unreadable',
    });
    expect(
      statusPredicateOf(
        whereClauses("UPDATE t SET status = 'x' WHERE id = $1 AND (status = 'a' OR status = 'b')"),
      ),
    ).toEqual({ shape: 'unreadable' });
    // And the CTE bound, driven: a predicate that lives ONLY in the pre-image
    // is read, because every `WHERE` is.
    expect(
      statusPredicateOf(
        whereClauses(
          "WITH prior AS (SELECT id FROM t WHERE id = $1 AND status = 'error' FOR UPDATE) UPDATE t SET status = 'x' FROM prior WHERE t.id = prior.id RETURNING 1",
        ),
      ),
    ).toEqual({ shape: 'single', status: 'error' });
  });

  it('reads the UPSERT spelling of a status write — SYNTHETIC, and the shape the raw floor exists for', () => {
    // `INSERT INTO plaid_items … ON CONFLICT … DO UPDATE SET status = 'healthy'`
    // writes the ladder without ever emitting the token sequence `UPDATE
    // plaid_items`. M49 PR6's review added exactly that rung — un-tombstoning a
    // revoked item, emitting no `from` — and every one of the fence's tests
    // stayed green, the RAW floor included, because the floor shared the
    // blind spot of the readers it backstops. Three readers had to learn the
    // spelling; these are their controls.
    const upsert =
      "INSERT INTO plaid_items (id, status) VALUES ($1, 'healthy') ON CONFLICT (item_bidx) " +
      "DO UPDATE SET status = 'healthy', deleted_at = NULL RETURNING id";
    const setClause = /\bDO\s+UPDATE\s+SET\s+([\s\S]*?)(?:\bWHERE\b|\bRETURNING\b|$)/i.exec(upsert);
    expect({
      readsTheConflictArm: setClause !== null,
      assignsStatus: /(?:^|,)\s*status\s*=\s*'([a-z_]+)'/i.exec(setClause?.[1] ?? '')?.[1],
      untombstones: deletedAtWrite(setClause?.[1] ?? '') === 'resurrect',
      tombstones: deletedAtWrite(setClause?.[1] ?? '') === 'tombstone',
    }).toEqual({
      readsTheConflictArm: true,
      assignsStatus: 'healthy',
      untombstones: true,
      tombstones: false,
    });
  });

  it('reads a NEGATED predicate as unreadable, never as a pin — SYNTHETIC, and the fail-OPEN direction', () => {
    // `NOT (status = 'a')` admits every status but `a`. Read as `single`, it
    // would exempt from a `from` the one statement shape that most needs one,
    // which is why this control is worth more than its three lines: every other
    // misreading here fails CLOSED.
    expect(
      statusPredicateOf(
        whereClauses("UPDATE t SET status = 'x' WHERE id = $1 AND NOT (status = 'a')"),
      ),
    ).toEqual({ shape: 'unreadable' });
    expect(
      statusPredicateOf(whereClauses("UPDATE t SET status = 'x' WHERE id = $1 AND status <> 'a'")),
    ).toEqual({ shape: 'unreadable' });
  });

  it('reads a DESTRUCTURED status as a read of the column — SYNTHETIC', () => {
    // Both halves of PR4's reading are anchored on `.status`: the guard
    // classifier and the count that pins how often this service reads the
    // column. A destructured binding is the same read in a different spelling.
    expect(
      narrowingOf(`const { status } = item; if (status !== 'healthy') throw new Error();`),
    ).toEqual({ shape: 'allow', statuses: ['healthy'] });
    expect(
      narrowingOf(`const { status: was } = item; if (was === 'error') throw new Error();`),
    ).toEqual({ shape: 'refuse', statuses: ['error'] });
    expect(statusReadsNormalised(`const { status } = item; return status;`)).toContain(
      'item.status',
    );
  });

  it('classifies a guard shape it cannot READ as owing a `from` — SYNTHETIC', () => {
    expect(narrowingOf(`if (item.status !== 'healthy') throw new Error();`)).toEqual({
      shape: 'allow',
      statuses: ['healthy'],
    });
    expect(narrowingOf(`if (item.status === 'error') throw new Error();`)).toEqual({
      shape: 'refuse',
      statuses: ['error'],
    });
    expect(narrowingOf(`if (item.status === 'error') { proceed(); }`)).toEqual({
      shape: 'unreadable',
    });
    expect(narrowingOf(`return item.id;`)).toEqual({ shape: 'none' });
  });
});

describe('which emitters owe a prior status', () => {
  it('pairs every site with exactly one emitter, passing the prior the WRITE answered', () => {
    // `passesBinding` is anchored on WHICHEVER identifier the write's own
    // return value was bound to — not on its name, which a rename may change
    // without changing the property, and not on a property read at the top of
    // the method: the caller's `item.status` was read outside the transaction
    // and is the stale pre-read the whole mechanism exists to replace.
    expect(
      Object.fromEntries(
        SITES.map((s) => [
          s.key,
          {
            writer: s.writer,
            emitter: s.emitter,
            bound: s.binding !== null,
            passesBinding: s.passesBinding,
            answerFlows: s.answerFlows,
          },
        ]),
      ),
    ).toEqual({
      'handleWebhook:login_required': {
        writer: 'setStatus',
        emitter: 'itemLoginRequired',
        bound: true,
        passesBinding: true,
        answerFlows: true,
      },
      'syncItem:error': {
        writer: 'setStatus',
        emitter: 'itemErrored',
        bound: true,
        passesBinding: true,
        answerFlows: true,
      },
      'syncItem:healthy': {
        writer: 'setStatus',
        emitter: 'itemSynced',
        bound: true,
        passesBinding: true,
        answerFlows: true,
      },
      'revoke:revoked': {
        writer: 'markRevoked',
        emitter: 'itemRevoked',
        bound: true,
        passesBinding: true,
        answerFlows: true,
      },
    });
  });

  it('reads the detail KEY, not the identifier — SYNTHETIC', () => {
    // `detail: { previous: from }` names the binding and carries a key nothing
    // reads. The property is what reaches the wire, so the property is what is
    // read: a `from` in value position is not a `from` on the trail.
    const carries = (emit: string): boolean => /[{,]\s*from\s*[,:}]/.test(emit);
    expect({
      shorthand: carries("this.item('a', x, y, { from });"),
      explicit: carries("this.item('a', x, y, { from: prior });"),
      beside: carries("this.item('a', x, y, { accounts: n, from });"),
      renamedKey: carries("this.item('a', x, y, { previous: from });"),
      absent: carries("this.item('a', x, y, {});"),
    }).toEqual({
      shorthand: true,
      explicit: true,
      beside: true,
      renamedKey: false,
      absent: false,
    });
  });

  it('reads whether the write’s OWN answer reaches the emitter — SYNTHETIC', () => {
    // `passesBinding` proves the emitter receives the transaction's result;
    // this proves the transaction's result is the write's answer and nothing
    // else. `return was ?? stale` satisfies the first and defeats the second,
    // which is the stale pre-read the whole mechanism exists to replace.
    const arrow = "withTransaction(u, (tx) => this.items.setStatus(tx, id, 'healthy'))";
    const honest =
      "withTransaction(u, async (tx) => { const was = await this.items.setStatus(tx, id, 'healthy'); if (was === null) { return null; } return was; })";
    const laundered =
      "withTransaction(u, async (tx) => { const was = await this.items.setStatus(tx, id, 'healthy'); return was ?? stale; })";
    const unbound =
      "withTransaction(u, async (tx) => { await this.items.setStatus(tx, id, 'healthy'); return item.status; })";
    expect({
      arrow: answerFlows(arrow, 'setStatus'),
      honest: answerFlows(honest, 'setStatus'),
      laundered: answerFlows(laundered, 'setStatus'),
      unbound: answerFlows(unbound, 'setStatus'),
    }).toEqual({ arrow: true, honest: true, laundered: false, unbound: false });
  });

  it('DERIVES the obligation: three live priors, no narrowing, so every site owes a `from` and every emitter carries one', () => {
    const priors = livePriors();
    const admitted = (site: Site): number => {
      const sql = statusPredicateOf(WRITERS.find((w) => w.method === site.writer)!.predicates);
      if (sql.shape === 'single') return 1;
      if (sql.shape === 'multi') return sql.statuses.length;
      if (sql.shape === 'unreadable') return Number.POSITIVE_INFINITY;
      const n = site.narrowing;
      if (n.shape === 'allow') return n.statuses.length;
      if (n.shape === 'refuse') return priors.filter((s) => !n.statuses.includes(s)).length;
      if (n.shape === 'none') return priors.length;
      return Number.POSITIVE_INFINITY;
    };
    // Compared as SETS. `exempt` is empty and the header says why that is a
    // weaker result than PR3's or PR4's: nothing in this corpus can show the
    // classifier answering "owes nothing", only the synthetic controls above.
    expect({
      owes: new Set(SITES.filter((s) => admitted(s) > 1).map((s) => s.key)),
      exempt: new Set(SITES.filter((s) => admitted(s) === 1).map((s) => s.key)),
      owesButEmitterLacksFrom: SITES.filter(
        (s) => admitted(s) > 1 && !(s.emitter !== null && EMITTERS.get(s.emitter)?.carriesFrom),
      ).map((s) => s.key),
    }).toEqual({
      owes: new Set([
        'handleWebhook:login_required',
        'syncItem:error',
        'syncItem:healthy',
        'revoke:revoked',
      ]),
      exempt: new Set(),
      owesButEmitterLacksFrom: [],
    });
  });

  it('READS the compare-and-set at every site — a lost one files nothing', () => {
    // All four sites emit only when the write answered a prior: a status flip
    // filed for a row the statement did not touch is a false record (M49
    // PR5). An earlier draft made `synced` the exception, firing with `from`
    // absent because "the accounts moved anyway"; the PR's review found that
    // arm executed by no test, and the fix removed the arm rather than testing
    // it — `syncItem` now takes the status write FIRST and stops on null, so
    // the accounts do NOT move. One behaviour, one spelling, four sites.
    expect(Object.fromEntries(SITES.map((s) => [s.key, s.guarded]))).toEqual({
      'handleWebhook:login_required': true,
      'syncItem:error': true,
      'syncItem:healthy': true,
      'revoke:revoked': true,
    });
  });

  it('records every ladder action in the CLOSED vocabulary, and every plaid member has an emitter', () => {
    // Both directions. An action the emitter names that the vocabulary lacks
    // is dropped by the consumer as a schema violation; a member the vocabulary
    // carries that nothing emits is a zero-caller surface.
    const emitted = new Set([...EMITTERS.values()].map((e) => e.action));
    const members = new Set(AUDIT_ACTIONS.filter((a) => a.startsWith('plaid.')));
    expect(emitted).toEqual(members);
    expect(members).toContain('plaid.item.errored');
  });

  it('PINS the verb-to-target map, including the one that disagrees', () => {
    // No `to` key on the wire: four targets, four emitters, so `to` would be a
    // second copy of what the action id determines. The disagreement is
    // recorded HERE as data: `synced` names the ACT and writes `healthy`. That
    // is the emitter where the recovery lives, and the reason it does — the
    // event that ships every successful sync is the event that records the
    // write, so the edge belongs on it rather than on a second member guarded
    // by a comparison.
    expect(
      Object.fromEntries(
        SITES.map((s) => [
          EMITTERS.get(s.emitter as string)?.action.replace(/^plaid\.item\./, ''),
          s.target,
        ]),
      ),
    ).toEqual({
      login_required: 'login_required',
      errored: 'error',
      synced: 'healthy',
      revoked: 'revoked',
    });
  });

  it('PINS THE LOCK ORDER on BOTH sides of the pair — the item row before its accounts', () => {
    // Derived from the source, not asserted in prose: in every transaction that
    // touches both tables, the item statement is the first of the two. Reverse
    // either side and this reddens; the two-connection drive in
    // `plaid.int.spec.ts` proves what the order BUYS, and this proves the order
    // is still there. Two transactions qualify today — `revoke` and `syncItem`
    // — and the count is asserted so that a third arriving unread is a failure.
    const orders = transactionLockOrder();
    expect({
      transactions: orders.length,
      childBeforeItem: orders.filter((o) => o.child < o.item).map((o) => o.method),
      methods: new Set(orders.map((o) => o.method)),
    }).toEqual({
      transactions: 2,
      childBeforeItem: [],
      methods: new Set(['revoke', 'syncItem']),
    });
  });

  it('states its own reach — and PROVES the two hand-named files are the only ones', () => {
    // A first draft asserted `SERVICE_FILE === 'plaid.service.ts'` — an
    // expectation about a constant declared eleven lines above it, which is a
    // sentence and not a test. The property those two names stand for is that
    // NOTHING ELSE in `src` calls a ladder writer or emits a ladder action, and
    // that is derived here from every `.ts` under `src`. A write moved to a
    // third file reddens this rather than pairing with nothing in silence.
    // TWO READERS, because the attributing one has a receiver in it and the
    // property name is the author's choice. `attributed` resolves, IN EACH
    // FILE, whatever that file binds to a constructor parameter typed
    // `ItemsRepo` — so a second service class injecting the same repo as
    // `this.repo` is read, where a single name lifted out of `plaid.service.ts`
    // would have missed it. `raw` is the floor beside it: the writer's name
    // called on ANY receiver, which needs no injection at all to be true. The
    // repo's own definitions do not match — a definition has no leading dot.
    // The pairing is the rule docs/06 records for the statement readers, owed
    // here for the same reason: a reader that ATTRIBUTES can be escaped by
    // changing what it attributes to.
    const attributed = new Set<string>();
    const raw = new Set<string>();
    const emitterFiles = new Set<string>();
    const writerNames = WRITERS.map((w) => w.method);
    const ladderActions = new Set([...EMITTERS.values()].map((e) => e.action));
    for (const file of sourceFiles(SRC, '.ts')) {
      const source = stripComments(read(SRC, file));
      const bound = [
        ...source.matchAll(
          new RegExp(
            `(?:private|public|protected)\\s+readonly\\s+(\\w+)\\s*:\\s*${WRITER_CLASS}\\b`,
            'g',
          ),
        ),
      ].map((m) => m[1] as string);
      for (const prop of bound) {
        if (writerNames.some((m) => new RegExp(`this\\.${prop}\\.${m}\\(`).test(source))) {
          attributed.add(file);
        }
      }
      if (writerNames.some((m) => new RegExp(`\\.\\s*${m}\\s*\\(`).test(source))) {
        raw.add(file);
      }
      if ([...ladderActions].some((a) => source.includes(`'${a}'`))) emitterFiles.add(file);
    }
    expect({ attributed, raw, emitterFiles }).toEqual({
      attributed: new Set([SERVICE_FILE]),
      raw: new Set([SERVICE_FILE]),
      emitterFiles: new Set([EVENTS_FILE]),
    });

    // WHAT REMAINS OUT OF REACH, as data rather than as prose, each with the
    // layer that does catch it. The fence reads statements, not executions.
    expect([
      {
        bound: 'a status written by an INSERT rather than an UPDATE',
        caughtBy: 'insertAssignsStatus(), read above and false today',
      },
      {
        bound: 'a status written by SQL built outside a template literal',
        caughtBy: 'rawLadderStatements(), which counts the keyword in the raw source',
      },
      {
        bound: 'a call site passing a variable target rather than a literal',
        caughtBy: 'parameterisedTargets(), which REFUSES such a site',
      },
      {
        bound: 'an emitter that files the right key with the wrong VALUE',
        caughtBy: 'the integration drives, which compare twelve edges as sets',
      },
      {
        bound: 'a transaction whose statements run in an order that deadlocks',
        caughtBy: 'the two-connection drive in plaid.int.spec.ts',
      },
    ]).toHaveLength(5);
  });
});

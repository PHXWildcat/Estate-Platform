import { inspect } from 'node:util';
import { AssetsClient, DocumentsClient, ProfileClient } from '../src/clients';
import { assertEgressClean, EgressRefusedError, inspectEgress } from '../src/privacy/egress';
import * as tokenizerModule from '../src/privacy/tokenizer';
import {
  assertTokenizerCoversTools,
  isPlaceholder,
  Tokenizer,
  TokenizerCoverageError,
} from '../src/privacy/tokenizer';
import { AnalysisService } from '../src/analysis.service';
import { buildToolRegistry } from '../src/tools';

/** One asset row, in the shape `clients/assets.client.ts` actually returns. */
function asset(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    assetId: 'a1f3c2d4-9e6b-4a7c-8d5e-1b2c3f4a5d6e',
    category: 'real_estate',
    title: 'The Elm Street house',
    estValue: '1250000.00',
    valuationAsOf: '2026-01-15',
    ownershipPct: 100,
    inTrust: false,
    ...overrides,
  };
}

/** One document inventory row, in the shape `clients/documents.client.ts` returns. */
function doc(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    documentId: 'b2e4d3c5-8f7a-4b6d-9c4f-2a3b4c5d6e7f',
    docType: 'will',
    title: 'Last will and testament 2019',
    currentVersion: 3,
    executionStatus: 'executed',
    executedAt: '2019-06-01',
    sealed: false,
    updatedAt: '2026-02-02',
    ...overrides,
  };
}

describe('tokenizer — stable, meaningless placeholders', () => {
  it('maps the same value to the same placeholder', () => {
    const tok = new Tokenizer();
    const first = tok.tokenizeToolResult('list_assets', [asset()]) as Record<string, unknown>[];
    const second = tok.tokenizeToolResult('list_assets', [asset()]) as Record<string, unknown>[];
    expect(first[0]?.title).toBe('⟦ASSET_1⟧');
    // The point of stability: the model must be able to tell that a second
    // mention is the SAME house, across every iteration of the turn loop.
    expect(second[0]?.title).toBe('⟦ASSET_1⟧');
    expect(tok.size).toBe(1);
  });

  it('maps different values to different placeholders', () => {
    const tok = new Tokenizer();
    const rows = tok.tokenizeToolResult('list_assets', [
      asset({ title: 'The Elm Street house' }),
      asset({ title: 'Vanguard brokerage' }),
    ]) as Record<string, unknown>[];
    expect(rows[0]?.title).toBe('⟦ASSET_1⟧');
    expect(rows[1]?.title).toBe('⟦ASSET_2⟧');
    expect(tok.size).toBe(2);
  });

  it('numbers each kind separately, so a placeholder says what it stands for', () => {
    const tok = new Tokenizer();
    const assets = tok.tokenizeToolResult('list_assets', [asset()]) as Record<string, unknown>[];
    const docs = tok.tokenizeToolResult('list_documents', [doc()]) as Record<string, unknown>[];
    expect(assets[0]?.title).toBe('⟦ASSET_1⟧');
    expect(docs[0]?.title).toBe('⟦DOCUMENT_1⟧');
  });

  it('gives one label shared by two kinds two distinct placeholders', () => {
    // An asset and a document may both be titled "Family Trust". They are
    // different entities and the model must not conflate them.
    const tok = new Tokenizer();
    const a = tok.tokenizeToolResult('list_assets', [asset({ title: 'Family Trust' })]) as Record<
      string,
      unknown
    >[];
    const d = tok.tokenizeToolResult('list_documents', [doc({ title: 'Family Trust' })]) as Record<
      string,
      unknown
    >[];
    expect(a[0]?.title).toBe('⟦ASSET_1⟧');
    expect(d[0]?.title).toBe('⟦DOCUMENT_1⟧');
    expect(tok.size).toBe(2);
  });

  it('holds placeholders stable across the turns of one conversation', () => {
    const tok = new Tokenizer();
    // Turn 1 lists two assets.
    tok.tokenizeToolResult('list_assets', [
      asset({ title: 'The Elm Street house' }),
      asset({ title: 'Vanguard brokerage' }),
    ]);
    // Turn 2 re-reads, and a THIRD asset appears. The first two keep their
    // identities; only the newcomer takes a fresh index.
    const later = tok.tokenizeToolResult('list_assets', [
      asset({ title: 'Vanguard brokerage' }),
      asset({ title: 'The Elm Street house' }),
      asset({ title: 'Lake cabin' }),
    ]) as Record<string, unknown>[];
    expect(later[0]?.title).toBe('⟦ASSET_2⟧');
    expect(later[1]?.title).toBe('⟦ASSET_1⟧');
    expect(later[2]?.title).toBe('⟦ASSET_3⟧');
  });
});

describe('tokenizer — what it replaces and what it must not touch', () => {
  it('replaces the registered field and leaves every other field byte-identical', () => {
    const tok = new Tokenizer();
    const [row] = tok.tokenizeToolResult('list_assets', [asset()]) as Record<string, unknown>[];
    expect(row).toEqual({
      // Opaque ids are NOT tokenized: they are not user-authored, and the model
      // must hand `assetId` back as a tool argument to a schema demanding a UUID.
      assetId: 'a1f3c2d4-9e6b-4a7c-8d5e-1b2c3f4a5d6e',
      category: 'real_estate',
      title: '⟦ASSET_1⟧',
      // Amounts, dates, percentages, enums and booleans carry no identity.
      estValue: '1250000.00',
      valuationAsOf: '2026-01-15',
      ownershipPct: 100,
      inTrust: false,
    });
  });

  it('touches nothing in a result declared to carry no identifiers', () => {
    const tok = new Tokenizer();
    const summary = {
      totalValue: '1250000.00',
      assetCount: 3,
      valuedAssetCount: 2,
      inTrustValue: '0.00',
    };
    expect(tok.tokenizeToolResult('get_estate_summary', summary)).toEqual(summary);
    expect(tok.size).toBe(0);
  });

  it('does NOT tokenize document prose — the recorded gap, pinned so it stays a decision', () => {
    // `get_document_text` returns the user's own document text, which is not
    // field-structured. Closing this needs NER; the compensating controls are
    // the separate `assistant.documents.content` consent scope and untrusted
    // framing. If someone ever adds a rule for `text`, this test tells them
    // they are changing a documented position rather than fixing an oversight.
    const tok = new Tokenizer();
    const content = {
      documentId: 'b2e4d3c5-8f7a-4b6d-9c4f-2a3b4c5d6e7f',
      version: 3,
      mime: 'text/html',
      text: 'I, Jane Doe, of 14 Elm Street, leave my estate to my son Peter Doe.',
    };
    expect(tok.tokenizeToolResult('get_document_text', content)).toEqual(content);
    expect(tok.size).toBe(0);
  });

  it('does not mutate the input — the untokenized result is what gets persisted', () => {
    const tok = new Tokenizer();
    const input = [asset()];
    tok.tokenizeToolResult('list_assets', input);
    // `assistant_tool_calls` records what was RETRIEVED, not what was shipped.
    expect(input[0]?.title).toBe('The Elm Street house');
  });

  it('tokenizes a dormant PERSON field the moment a widened schema produces one', () => {
    // No shipped tool returns a name — the peer clients strip them first. These
    // rules exist so that widening a client schema cannot silently bypass the
    // privacy layer, which lives in a different file from the schema.
    const tok = new Tokenizer();
    const widened = {
      assetId: 'a1f3c2d4-9e6b-4a7c-8d5e-1b2c3f4a5d6e',
      beneficiaries: [
        { contactId: 'c3d5e4f6-7a8b-4c5d-8e6f-3b4c5d6e7f8a', name: 'Peter Doe', sharePct: 60 },
        { contactId: 'd4e6f5a7-6b9c-4d7e-9f5a-4c5d6e7f8a9b', name: 'Mary Doe', sharePct: 40 },
      ],
      totals: [{ designation: 'primary', sharePct: 100, designationComplete: true }],
    };
    const out = tok.tokenizeToolResult('get_asset_beneficiaries', widened) as {
      beneficiaries: Record<string, unknown>[];
      totals: Record<string, unknown>[];
    };
    expect(out.beneficiaries[0]?.name).toBe('⟦PERSON_1⟧');
    expect(out.beneficiaries[1]?.name).toBe('⟦PERSON_2⟧');
    // Contact ids and share percentages are untouched.
    expect(out.beneficiaries[0]?.contactId).toBe('c3d5e4f6-7a8b-4c5d-8e6f-3b4c5d6e7f8a');
    expect(out.totals[0]?.sharePct).toBe(100);
  });

  it('ignores an empty or whitespace-only value rather than burning an index', () => {
    const tok = new Tokenizer();
    const rows = tok.tokenizeToolResult('list_assets', [
      asset({ title: '' }),
      asset({ title: '   ' }),
      asset({ title: 'Lake cabin' }),
    ]) as Record<string, unknown>[];
    expect(rows[0]?.title).toBe('');
    expect(rows[1]?.title).toBe('   ');
    // A placeholder for nothing would tell the model a name exists where none does.
    expect(rows[2]?.title).toBe('⟦ASSET_1⟧');
  });
});

describe('tokenizer — detokenization of model output', () => {
  it('round-trips a mapped value back to the user', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [asset()]);
    expect(tok.detokenize('⟦ASSET_1⟧ is your largest holding.')).toBe(
      'The Elm Street house is your largest holding.',
    );
  });

  it('restores every occurrence, across kinds, in one reply', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [asset({ title: 'Lake cabin' })]);
    tok.tokenizeToolResult('list_documents', [doc({ title: 'Will 2019' })]);
    expect(
      tok.detokenize('⟦DOCUMENT_1⟧ does not mention ⟦ASSET_1⟧, and ⟦ASSET_1⟧ is untitled.'),
    ).toBe('Will 2019 does not mention Lake cabin, and Lake cabin is untitled.');
  });

  it('leaves an unmapped placeholder as a harmless literal', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [asset()]);
    // A model that invents an index it was never issued gets no answer. There
    // is no arithmetic on the number and no nearest-match: ⟦ASSET_9⟧ must never
    // resolve to ⟦ASSET_1⟧'s value.
    const out = tok.detokenize('⟦ASSET_9⟧ and ⟦PERSON_3⟧ and ⟦BOGUS_1⟧ are all unknown.');
    expect(out).toBe('⟦ASSET_9⟧ and ⟦PERSON_3⟧ and ⟦BOGUS_1⟧ are all unknown.');
    expect(out).not.toContain('Elm Street');
  });

  it('resolves nothing at all when nothing has been mapped', () => {
    const tok = new Tokenizer();
    expect(tok.detokenize('⟦ASSET_1⟧ ⟦PERSON_1⟧')).toBe('⟦ASSET_1⟧ ⟦PERSON_1⟧');
  });

  it('does not rescan what it just inserted', () => {
    // A restored value containing placeholder-shaped text must not be resolved
    // a second time — one pass, by construction.
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [
      asset({ title: 'see ⟦ASSET_2⟧' }),
      asset({ title: 'the cabin' }),
    ]);
    expect(tok.detokenize('⟦ASSET_1⟧')).toBe('see ⟦ASSET_2⟧');
  });

  it('recognizes a placeholder shape without consulting any map', () => {
    expect(isPlaceholder('⟦ASSET_1⟧')).toBe(true);
    expect(isPlaceholder('⟦PERSON_42⟧')).toBe(true);
    expect(isPlaceholder('⟦ASSET_1⟧ trailing')).toBe(false);
    expect(isPlaceholder('ASSET_1')).toBe(false);
  });
});

describe('tokenizer — free text, for history consistency across requests', () => {
  it('replaces mapped values where they appear in prose', () => {
    // The assistant's reply is STORED detokenized (it is the record the user
    // reads back), so on the next request the real title would otherwise travel
    // to the provider inside the replayed history.
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [asset()]);
    expect(tok.tokenizeText('The Elm Street house is worth 1250000.00.')).toBe(
      '⟦ASSET_1⟧ is worth 1250000.00.',
    );
  });

  it('prefers the longest mapped value when two overlap', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [
      asset({ title: 'Lake cabin' }),
      asset({ title: 'Lake cabin north lot' }),
    ]);
    expect(tok.tokenizeText('the Lake cabin north lot adjoins the Lake cabin')).toBe(
      'the ⟦ASSET_2⟧ adjoins the ⟦ASSET_1⟧',
    );
  });

  it('does not hunt very short values in prose', () => {
    // "IRA" is a real title and also three ordinary letters. Structured fields
    // are replaced at any length because the schema removes the ambiguity;
    // prose is not, because over-replacement there just mangles a sentence.
    const tok = new Tokenizer();
    const rows = tok.tokenizeToolResult('list_assets', [asset({ title: 'IRA' })]) as Record<
      string,
      unknown
    >[];
    expect(rows[0]?.title).toBe('⟦ASSET_1⟧');
    expect(tok.tokenizeText('your IRA is in good shape')).toBe('your IRA is in good shape');
  });

  it('is a no-op before anything has been mapped', () => {
    const tok = new Tokenizer();
    expect(tok.tokenizeText('The Elm Street house')).toBe('The Elm Street house');
  });
});

describe('tokenizer — it cannot weaken the egress assertion', () => {
  const DIRTY_TITLE = "dad's account 123-45-6789";

  it('uses fixtures that are themselves egress-clean', () => {
    // GUARD AGAINST A FALSE PASS, and not a hypothetical one: the first version
    // of this file used `11111111-1111-4111-8111-111111111111` as the asset id,
    // whose substring `11111111-1111-4111` is sixteen digits and Luhn-valid. The
    // order-independence test below therefore passed while the interlock it
    // exists to prove was deleted — the payload was refused for the id, not for
    // the SSN. Every fixture id must be clean or these assertions mean nothing.
    expect(inspectEgress(JSON.stringify([asset({ title: 'clean' })]))).toEqual({ clean: true });
    expect(inspectEgress(JSON.stringify([doc({ title: 'clean' })]))).toEqual({ clean: true });
  });

  it('leaves an egress-tripping value UNTOUCHED so the gate still fires', () => {
    // If the tokenizer replaced this title, `assertEgressClean` would then find
    // nothing, the turn would proceed, and a fail-closed control would have been
    // silenced by the privacy layer. The SSN must survive to reach the gate.
    const tok = new Tokenizer();
    const [row] = tok.tokenizeToolResult('list_assets', [asset({ title: DIRTY_TITLE })]) as Record<
      string,
      unknown
    >[];
    expect(row?.title).toBe(DIRTY_TITLE);
    expect(tok.size).toBe(0);
  });

  it('keeps the payload refusable whichever order the two run in', () => {
    // The property that matters is ORDER INDEPENDENCE: the wiring may tokenize
    // then assert, or assert then tokenize, and an SSN is refused either way.
    const tok = new Tokenizer();
    const raw = [asset({ title: DIRTY_TITLE })];
    const tokenized = tok.tokenizeToolResult('list_assets', raw);
    // Asserting the DETECTOR, not merely that something threw: a refusal for
    // the wrong reason is how the earlier version of this file passed with the
    // interlock removed.
    expect(inspectEgress(JSON.stringify(raw))).toEqual({ clean: false, detector: 'ssn' });
    expect(inspectEgress(JSON.stringify(tokenized))).toEqual({ clean: false, detector: 'ssn' });
    expect(() => assertEgressClean(JSON.stringify(tokenized))).toThrow(EgressRefusedError);
  });

  it('never puts an egress-tripping value in the reverse map', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [
      asset({ title: DIRTY_TITLE }),
      asset({ title: 'card 4242 4242 4242 4242' }),
      asset({ title: 'Lake cabin' }),
    ]);
    // Only the clean title was mapped, so no placeholder can resolve to an SSN
    // or a card number — the tokenizer is not a second home for them.
    expect(tok.size).toBe(1);
    expect(tok.detokenize('⟦ASSET_1⟧')).toBe('Lake cabin');
  });

  it('still refuses a clean title alongside a dirty one', () => {
    const tok = new Tokenizer();
    const out = tok.tokenizeToolResult('list_assets', [
      asset({ title: 'Lake cabin' }),
      asset({ title: DIRTY_TITLE }),
    ]) as Record<string, unknown>[];
    expect(out[0]?.title).toBe('⟦ASSET_1⟧');
    expect(out[1]?.title).toBe(DIRTY_TITLE);
    expect(() => assertEgressClean(JSON.stringify(out))).toThrow(EgressRefusedError);
  });
});

describe('tokenizer — no state outlives the turn', () => {
  it('shares nothing between instances', () => {
    const first = new Tokenizer();
    first.tokenizeToolResult('list_assets', [asset()]);
    // A second tokenizer is a second conversation. If any map were module-level,
    // one user's titles would be resolvable from another user's turn.
    const second = new Tokenizer();
    expect(second.size).toBe(0);
    expect(second.detokenize('⟦ASSET_1⟧')).toBe('⟦ASSET_1⟧');
    expect(second.tokenizeText('The Elm Street house')).toBe('The Elm Street house');
  });

  it('restarts numbering per instance, so an index means nothing globally', () => {
    const first = new Tokenizer();
    first.tokenizeToolResult('list_assets', [asset({ title: 'Lake cabin' })]);
    const second = new Tokenizer();
    const rows = second.tokenizeToolResult('list_assets', [
      asset({ title: 'Something else entirely' }),
    ]) as Record<string, unknown>[];
    expect(rows[0]?.title).toBe('⟦ASSET_1⟧');
  });

  it('exposes a count but never the mapped values', () => {
    const tok = new Tokenizer();
    tok.tokenizeToolResult('list_assets', [asset()]);
    expect(tok.size).toBe(1);
    // The mapping is the one artifact that turns a placeholder back into
    // someone's data, so it must not be reachable by the incidental routes:
    // a structured logger, an error serializer, a debug dump. This assertion
    // failed when the maps were TypeScript `private` (erased at compile time,
    // still own enumerable properties) and is what drove them to `#` fields.
    expect(JSON.stringify(tok)).not.toContain('Elm Street');
    expect(Object.values(tok as unknown as Record<string, unknown>)).toEqual([]);
    expect(Object.keys(tok as unknown as Record<string, unknown>)).toEqual([]);
    expect(JSON.stringify({ tokenizer: tok })).not.toContain('Elm Street');
    // `util.inspect` is what a structured logger reaches for, and unlike
    // JSON.stringify it DOES print private fields — so this asserts the weaker
    // but still necessary property that the values are not on the enumerable
    // surface, while the two checks above cover serialization.
    expect(inspect(tok, { showHidden: false, depth: 0 })).not.toContain('Elm Street');
  });

  it('exports no shared mutable state', () => {
    for (const [name, value] of Object.entries(tokenizerModule as Record<string, unknown>)) {
      expect(value instanceof Map).toBe(false);
      expect(value instanceof Set).toBe(false);
      expect(typeof value === 'function' || name === '__esModule').toBe(true);
    }
  });
});

describe('tokenizer — coverage fence', () => {
  /** The real tool surface. Clients need only a base URL to construct. */
  function realToolNames(): string[] {
    const assets = new AssetsClient('http://assets.invalid');
    const documents = new DocumentsClient('http://documents.invalid');
    const profile = new ProfileClient('http://profile.invalid');
    const registry = buildToolRegistry({
      assets,
      documents,
      profile,
      // The analysers are part of the real surface, so the coverage fence must
      // see them: a rule missing for an analyser is the same silent leak as a
      // rule missing for a retrieval.
      analysis: new AnalysisService(assets, documents, profile, { nodeEnv: 'test' } as never),
    });
    return registry.list().map((tool) => tool.name);
  }

  it('covers every tool the assistant can actually call', () => {
    // The load-bearing assertion in this file. A field-based tokenizer is only
    // as good as its list, so the list is checked against the real registry —
    // a new retrieval ships with a tokenization decision or this goes red.
    expect(() => assertTokenizerCoversTools(realToolNames())).not.toThrow();
    // Eleven since M10 PR3 (seven retrievals + four analysers). The count is
    // pinned so a tool that disappears from the surface — and takes its rule
    // with it — cannot leave the fence passing over a smaller world.
    expect(realToolNames()).toHaveLength(11);
  });

  it('refuses a tool with no tokenization decision', () => {
    expect(() => assertTokenizerCoversTools([...realToolNames(), 'get_contact_details'])).toThrow(
      TokenizerCoverageError,
    );
  });

  it('refuses rules left behind for a tool that no longer exists', () => {
    // Drift seen from the other side: the rules were last reviewed against a
    // different tool surface, which is exactly when a gap gets introduced.
    expect(() =>
      assertTokenizerCoversTools(realToolNames().filter((name) => name !== 'list_assets')),
    ).toThrow(TokenizerCoverageError);
  });

  it('names the offending tool so the failure is actionable at boot', () => {
    expect(() => assertTokenizerCoversTools([...realToolNames(), 'get_contact_details'])).toThrow(
      /get_contact_details/,
    );
  });
});

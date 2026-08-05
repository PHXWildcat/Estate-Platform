import { z } from 'zod';
import {
  assertScoped,
  assertSubjectFree,
  scopeToken,
  ToolContractError,
  ToolRegistry,
  type AssistantTool,
  type ToolOutcome,
} from '../src/tools/registry';

function tool(name: string, shape: z.ZodRawShape): AssistantTool {
  return {
    name,
    description: 'test tool',
    scopes: ['assistant.assets'],
    input: z.object(shape),
    execute: (): Promise<ToolOutcome> => Promise.resolve({ outcome: 'ok', data: null }),
  };
}

describe('the subject is never a tool parameter', () => {
  // This is the structural half of the prompt-injection defence (docs/03 risk
  // #6). Injected text can make the model call a tool; it must have no field in
  // which to say whose estate to read.
  it.each([
    'userId',
    'user_id',
    'ownerId',
    'ownerUserId',
    'subjectId',
    'principal',
    'actorId',
    'tenantId',
    'uid',
    'onBehalfOf',
    'impersonateUser',
    // Run-together lowercase spellings carry no boundary for the word splitter
    // to find — the form a developer writes when naming a parameter after a SQL
    // column. Found by the M10 PR1 review; this is the third spelling class this
    // fence has had to learn, after the anchored regex and camelCase compounds.
    'userid',
    'ownerid',
    'subjectid',
    'principalid',
    'actorid',
    'tenantid',
    'userids',
  ])('refuses a tool declaring %s', (param) => {
    expect(() => assertSubjectFree(tool('t', { [param]: z.string() }))).toThrow(ToolContractError);
  });

  it('refuses a camelCase compound that buries the subject word', () => {
    // An earlier anchored-regex version of this check admitted `ownerUserId`
    // because the subject word was neither at the start nor after an
    // underscore — exactly the parameter a future tool would plausibly add.
    expect(() => assertSubjectFree(tool('t', { ownerUserId: z.string() }))).toThrow(
      /subject-selecting parameter "ownerUserId"/,
    );
  });

  it.each([
    'assetId',
    'documentId',
    'version',
    'query',
    'state',
    'accountId',
    // These must NOT trip the check. `liquidity` contains "uid" and `factorId`
    // contains "actor", which is exactly why the fence matches whole words and
    // an `<word>id` suffix rather than substrings — a fence that refuses
    // plausible estate parameters is one someone deletes.
    'liquidityTier',
    'factorId',
    'documentIds',
  ])('allows the resource-selecting parameter %s', (param) => {
    expect(() => assertSubjectFree(tool('t', { [param]: z.string() }))).not.toThrow();
  });

  it('validates the whole set at construction, so a bad tool cannot boot', () => {
    expect(
      () =>
        new ToolRegistry([
          tool('good', { assetId: z.string() }),
          tool('bad', { userId: z.string() }),
        ]),
    ).toThrow(ToolContractError);
  });
});

describe('ToolRegistry', () => {
  it('refuses duplicate names', () => {
    // `assistant_tool_calls` records a name; two tools sharing one makes that
    // evidence ambiguous, which is the same as having none.
    expect(() => new ToolRegistry([tool('dup', {}), tool('dup', {})])).toThrow(
      /duplicate tool name/,
    );
  });

  it('returns null for an unknown name rather than throwing', () => {
    // A model may hallucinate a tool name. That is a refusal to be recorded,
    // not a crash in the turn loop.
    const registry = new ToolRegistry([tool('known', {})]);
    expect(registry.get('made_up')).toBeNull();
    expect(registry.get('known')?.name).toBe('known');
  });

  it('exposes every registered tool with at least one consent scope declared', () => {
    // There is no unscoped tool, and `scopes` is a SET since M10 PR3 — so the
    // assertion is non-emptiness, not mere presence. An empty array would make
    // "every declared scope is granted" vacuously true.
    const registry = new ToolRegistry([tool('a', {}), tool('b', { assetId: z.string() })]);
    expect(registry.list()).toHaveLength(2);
    for (const registered of registry.list()) {
      expect(registered.scopes.length).toBeGreaterThan(0);
    }
  });
});

describe('a tool with no consent scope cannot exist', () => {
  const unscoped: AssistantTool = { ...tool('unscoped', {}), scopes: [] };

  it('is refused at construction, so it is a boot failure', () => {
    // An empty set makes "every declared scope is granted" VACUOUSLY TRUE, so
    // the tool would run for a user who has granted nothing — a gate that reads
    // as present and is not. This codebase has shipped that shape three times
    // (the M4 legal-hold zero-callers, the M6 reset teardown, PR1's Cedar PEP),
    // which is why it is a boot check and not a review item.
    expect(() => new ToolRegistry([unscoped])).toThrow(ToolContractError);
    expect(() => assertScoped(unscoped)).toThrow(/declares no consent scope/);
  });

  it('accepts one scope or several', () => {
    expect(() => assertScoped(tool('a', {}))).not.toThrow();
    expect(() =>
      assertScoped({
        ...tool('b', {}),
        scopes: ['assistant.assets', 'assistant.profile'],
      }),
    ).not.toThrow();
  });
});

describe('scopeToken', () => {
  it('joins a set into one audit-safe token', () => {
    // `assistant_tool_calls.scope` is one TEXT column and audit detail values
    // must match SAFE_TOKEN_PATTERN, which admits ':' and rejects ','.
    expect(scopeToken(['assistant.assets'])).toBe('assistant.assets');
    expect(scopeToken(['assistant.profile', 'assistant.assets'])).toBe(
      'assistant.assets:assistant.profile',
    );
  });

  it('is stable regardless of declaration order, and de-duplicates', () => {
    // Evidence that changes spelling with declaration order is evidence someone
    // has to normalize before they can count it.
    expect(scopeToken(['assistant.profile', 'assistant.assets'])).toBe(
      scopeToken(['assistant.assets', 'assistant.profile']),
    );
    expect(scopeToken(['assistant.assets', 'assistant.assets'])).toBe('assistant.assets');
  });

  it('stays inside the 128-character audit token bound', () => {
    // Every scope in the vocabulary at once — wider than any real tool — still
    // has to fit, or the audit event would be rejected at the emitter.
    const token = scopeToken([
      'assistant.enabled',
      'assistant.assets',
      'assistant.profile',
      'assistant.documents.metadata',
      'assistant.documents.content',
    ]);
    expect(token.length).toBeLessThanOrEqual(128);
    expect(token).toMatch(/^[A-Za-z0-9_.:-]{1,128}$/);
  });
});

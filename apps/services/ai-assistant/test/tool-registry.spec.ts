import { z } from 'zod';
import {
  assertSubjectFree,
  ToolContractError,
  ToolRegistry,
  type AssistantTool,
  type ToolOutcome,
} from '../src/tools/registry';

function tool(name: string, shape: z.ZodRawShape): AssistantTool {
  return {
    name,
    description: 'test tool',
    scope: 'assistant.assets',
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

  it('exposes every registered tool with a consent scope declared', () => {
    // There is no unscoped tool. When the real tools land this same assertion
    // is what proves none of them shipped with its gate forgotten.
    const registry = new ToolRegistry([tool('a', {}), tool('b', { assetId: z.string() })]);
    expect(registry.list()).toHaveLength(2);
    for (const registered of registry.list()) {
      expect(registered.scope).toBeTruthy();
    }
  });
});

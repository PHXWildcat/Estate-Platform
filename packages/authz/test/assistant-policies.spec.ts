import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  loadBundledPolicies,
  PolicyDecisionPoint,
  ref,
  type AuthzRequest,
  type EntityInput,
} from '../src';

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const CONVERSATION = '33333333-3333-4333-8333-333333333333';

const pdp = new PolicyDecisionPoint(loadBundledPolicies());

function conversationEntity(): EntityInput {
  return {
    uid: { type: 'AssistantConversation', id: CONVERSATION },
    attrs: { subject: ref('User', OWNER) },
  };
}

function requestOf(principalId: string, action: string): AuthzRequest {
  return {
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource: { type: 'AssistantConversation', id: CONVERSATION },
    entities: [conversationEntity()],
  };
}

describe('assistant.cedar (owner-only, deny-by-default)', () => {
  it('lets the owner read, converse in, and delete their own conversation', () => {
    for (const action of ['read', 'converse', 'delete']) {
      expect(pdp.authorize(requestOf(OWNER, action)).decision).toBe('allow');
    }
  });

  it('denies every action to anyone who is not the owner', () => {
    // A transcript quotes whatever estate content the assistant retrieved, so
    // someone entitled to read one asset must not thereby read a conversation
    // that ranges over all of them.
    for (const action of ['read', 'converse', 'delete']) {
      expect(pdp.authorize(requestOf(OTHER, action)).decision).toBe('deny');
    }
  });

  it('denies an action the policy does not name, even for the owner', () => {
    // Deny-by-default is the "and nothing else" half of the rule; this pins it
    // so a later verb cannot appear without a decision to add it here.
    for (const action of ['export', 'share', 'manage', 'evidence_add']) {
      expect(pdp.authorize(requestOf(OWNER, action)).decision).toBe('deny');
    }
  });

  it('denies when the conversation carries no subject attribute at all', () => {
    // A PEP that forgot to resolve the subject must fail closed rather than
    // matching a permit with a missing attribute.
    expect(
      pdp.authorize({
        principal: { type: 'User', id: OWNER },
        action: { type: 'Action', id: 'read' },
        resource: { type: 'AssistantConversation', id: CONVERSATION },
        entities: [{ uid: { type: 'AssistantConversation', id: CONVERSATION } }],
      }).decision,
    ).toBe('deny');
  });

  it('grants nothing on any other resource type, in isolation from the bundle', () => {
    // Every service in the product loads this one shared bundle, so a permit
    // that forgot its `resource is AssistantConversation` scope would widen
    // decisions in assets, documents, vault and settlement at once.
    //
    // The bundle cannot prove this on its own — owner.cedar independently
    // permits an owner any action on anything carrying `owner`, so a scope slip
    // here would be invisible behind it. Isolating assistant.cedar is what
    // makes the assertion mean what its name says.
    const isolated = new PolicyDecisionPoint(
      readFileSync(join(__dirname, '..', 'policies', 'assistant.cedar'), 'utf8'),
    );
    for (const type of ['SettlementCase', 'Asset', 'Document', 'VaultItem', 'Profile']) {
      expect(
        isolated.authorize({
          principal: { type: 'User', id: OWNER },
          action: { type: 'Action', id: 'read' },
          resource: { type, id: CONVERSATION },
          entities: [{ uid: { type, id: CONVERSATION }, attrs: { subject: ref('User', OWNER) } }],
        }).decision,
      ).toBe('deny');
    }

    // …and still allows the resource it is scoped to, so the check above is
    // not passing merely because the isolated policy text failed to parse.
    expect(isolated.authorize(requestOf(OWNER, 'read')).decision).toBe('allow');
  });
});

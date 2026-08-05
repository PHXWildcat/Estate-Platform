// AI estate assistant conversations (M10, docs/01 §2.8).
//
// Every permit below is scoped with `resource is AssistantConversation` so
// nothing here can widen decisions for the other services that load this
// shared bundle (assets, documents, vault, profile, identity, settlement).
//
// The rule is deliberately the narrowest in the bundle: a conversation is
// visible to its OWNER and to nobody else, ever. There is no trustee permit,
// no executor permit, no beneficiary permit and no operator permit, and their
// absence is the security statement — a transcript quotes whatever estate
// content the assistant retrieved, so a role-holder who may read one asset
// must not thereby read a conversation that discusses every asset. Cedar
// cannot express "and nothing else"; deny-by-default does, and
// `assistant-policies.spec.ts` pins it so a later permit cannot be added
// without a test turning red.
//
// THE ATTRIBUTE IS `subject`, NOT `owner`, AND THAT IS THE WHOLE POINT.
// owner.cedar permits a principal ANY action on a resource carrying an
// `owner` attribute that equals them. Naming this one `owner` would therefore
// hand the conversation's owner every verb in the product implicitly —
// including ones that do not exist yet, such as an export or share added by a
// later milestone, which docs/01 §5 requires to be step-up gated rather than
// inherited. Under `subject`, this file is the only grant that matches, so the
// verb list below is exhaustive and adding to it is a deliberate edit.
// settlement.cedar avoids `owner` for the same mechanical reason.
//
// NOTE ON SETTLEMENT: a conversation must NOT become readable to an executor
// when the owner's estate enters settlement. Staged access (docs/03 §6a) grants
// inventory, then documents, then vault — conversations are in none of those
// rungs, and adding them would need its own milestone, its own threat-model
// delta, and a decision about content the owner may never have intended anyone
// to read.
permit (
  principal,
  action in [
    Action::"read",
    Action::"converse",
    Action::"delete"
  ],
  resource is AssistantConversation
)
when { resource has subject && resource.subject == principal };

import { z } from 'zod';
import type { ProfileClient } from '../clients';
import type { AssistantTool, ToolContext, ToolOutcome } from './registry';

/**
 * The single tool behind the `assistant.profile` consent scope.
 *
 * Estate-planning advice turns on two facts about a person — WHICH STATE they
 * live in and WHETHER THEY ARE MARRIED — plus one fact about their household:
 * IS THERE A MINOR CHILD, which is what makes guardianship a live question. The
 * `GET /v1/profile` row also carries legal name, date of birth, SSN last four,
 * address, phone and occupation, and the family listing carries names and birth
 * dates. None of that changes an answer, so none of it is fetched: the
 * ProfileClient schemas drop those fields before they exist as values in this
 * process (see clients/profile.client.ts, where the enforcement lives).
 *
 * Keeping the identifiers out of the PROCESS rather than out of the PROMPT is
 * what makes the property hold under this service's actual threat: the model's
 * context contains untrusted document text (docs/03 §4 TB5 risk #6), and an
 * injected instruction cannot exfiltrate a field the assistant never fetched.
 * It also keeps the assistant off the docs/03 §5.3 bulk-decrypt path — one
 * profile read per conversation, for the two least sensitive fields on the row.
 */

/** See estate.tools.ts: one refusal for every way a peer read can fail. */
const UPSTREAM_UNAVAILABLE: ToolOutcome = { outcome: 'error', reason: 'upstream_unavailable' };

/** No arguments — the profile is always the signed-in user's own. */
const NoArgs = z.object({});

/** profile's own relation vocabulary; guardianship turns on this one value. */
const CHILD_RELATION = 'child';

function getProfileFacts(profile: ProfileClient): AssistantTool {
  return {
    name: 'get_profile_facts',
    description:
      'Non-identifying planning facts about the signed-in user: state of ' +
      'residence, marital status, and how many minor children are on record. ' +
      'Deliberately returns no names, birth dates, addresses or identifiers of ' +
      'any kind — ask the user if a name is needed. Takes no arguments.',
    scope: 'assistant.profile',
    input: NoArgs,
    async execute(ctx: ToolContext): Promise<ToolOutcome> {
      // Two reads, and BOTH must succeed. A partial answer here is worse than
      // no answer: "no minor children" derived from a family read that failed
      // is how an assistant talks a user out of naming a guardian. The client's
      // null already means "this read did not happen", and it stays meaning
      // that all the way to the caller.
      const [facts, family] = await Promise.all([
        profile.facts(ctx.bearer),
        profile.family(ctx.bearer),
      ]);
      if (facts === null || family === null) {
        return UPSTREAM_UNAVAILABLE;
      }
      const children = family.filter((member) => member.relation === CHILD_RELATION);
      return {
        outcome: 'ok',
        data: {
          stateOfResidence: facts.stateOfResidence,
          maritalStatus: facts.maritalStatus,
          // COUNTS, never rows. The family list is fetched for this number and
          // nothing else, and the narrowed member shape could not carry a name
          // even if a future edit here wanted one.
          minorChildren: children.filter((member) => member.isMinor === true).length,
          // The honest complement: `isMinor` is null when a birth date is
          // unknown, and a bare zero would then read as "no minors" to a model
          // that has no way to tell the difference. Reporting the unknowns is
          // what lets the assistant ask instead of assert.
          childrenOfUnknownAge: children.filter((member) => member.isMinor === null).length,
        },
      };
    },
  };
}

/** Every `assistant.profile` tool. */
export function profileTools(profile: ProfileClient): readonly AssistantTool[] {
  return [getProfileFacts(profile)];
}

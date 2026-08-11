import type { SessionAudience } from '../graphql/client';

/**
 * What a session's AUDIENCE means, in words a person can act on (M16).
 *
 * The audience is the only thing distinguishing one row of the paired-devices
 * list from another — `sessions` deliberately returns no IP and no device name,
 * because the columns exist and nothing writes them, so returning them would be
 * a promise the data cannot keep. That makes this table the whole of what a row
 * says, and the question it has to answer is the one somebody opens this page
 * with: which of these is not me, and what could it do?
 *
 * So `detail` states the REACH, not the technology. An extension credential is
 * the only one here that outlives the browser session, and the useful fact
 * about it is not that it is an extension but that it cannot destroy a vault —
 * which is precisely the boundary M16 exists to create, said once where a user
 * will read it.
 */
export interface AudienceCopy {
  /** The row's heading. */
  readonly label: string;
  /** One sentence on what a credential of this kind can reach. */
  readonly detail: string;
}

/**
 * TOTAL over the audience union, so a fourth audience is a COMPILE ERROR here
 * rather than a row that renders blank — the same shape as the BFF's own
 * `AUDIENCE_GQL`, and for the same reason.
 */
export const AUDIENCE_COPY: Record<SessionAudience, AudienceCopy> = {
  ACCOUNT: {
    label: 'Signed-in browser',
    detail: 'A normal sign-in. It can reach everything in your account.',
  },
  VAULT: {
    label: 'Vault',
    detail:
      'Opened from Estate to reach the vault. It expires on its own after 15 minutes and cannot be renewed — and on its own it opens nothing, because unlocking a vault needs your vault password and Secret Key.',
  },
  EXTENSION: {
    label: 'Browser extension',
    detail:
      'A paired browser extension. It can look up and unlock vault items, and nothing else: it cannot reset your vault, change your emergency contacts, delete an item, or reach the rest of your estate.',
  },
};

/**
 * The copy for an audience, TOLERANT of one this build has never heard of.
 *
 * The Record above makes a new audience a compile error in this app; it does
 * nothing about a BFF DEPLOYED AHEAD OF IT, which would send a token this
 * build cannot look up and blank — or crash — the row. `lib/findings.ts`
 * settled that rule already: a service deployed ahead of the app must not blank
 * the page. So an unknown audience renders as an unrecognised credential, which
 * is honest and still revocable, and revoking is the action that matters on a
 * row you do not recognise.
 */
export function audienceCopy(audience: string): AudienceCopy {
  return (
    AUDIENCE_COPY[audience as SessionAudience] ?? {
      label: 'Unrecognised credential',
      detail:
        'This app does not recognise what kind of credential this is. If you did not expect it, revoke it.',
    }
  );
}

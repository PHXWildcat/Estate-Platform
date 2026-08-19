import type { ReactElement } from 'react';
import { OperatorLaunch } from '../../../components/OperatorLaunch';

/**
 * The operator interstitial (M21 PR3a).
 *
 * The only operator route this app has, and the only one it will ever have: the
 * console lives on an isolated origin (docs/03 TB7), so everything past this
 * page runs on a different host under a different CSP with a different session
 * cookie. The vault interstitial's shape exactly.
 *
 * DELIBERATELY NOT IN `AppNav`, and the reason is not discoverability
 * machinery. Minting the handoff is role-blind, so this page WORKS for every
 * signed-in account — which is right, because the audience restricts where a
 * credential may be spent rather than asserting who holds it, and the console
 * itself says so. But a product for ten million people should not put "open the
 * operator console" in the navigation of an estate: the people who need this
 * address are told it, the same way they are told they are on the allowlist.
 *
 * Whether it earns a nav entry is M21 PR3b's question, once there is a surface
 * behind it. Adding one now would be a decision taken on an empty room.
 */
export default function OperatorPage(): ReactElement {
  return <OperatorLaunch />;
}

import type { ReactElement } from 'react';
import { VaultLaunch } from '../../../components/VaultLaunch';

/**
 * The vault interstitial (M15).
 *
 * The ONLY vault route this app has, and the only one it will ever have: Zone A
 * lives on an isolated origin (docs/03 TB6), so everything past this page runs
 * on a different host under a different CSP with a different session cookie.
 * `AppNav` has committed to that since the Evergreen-rail redesign — its Vault
 * entry was an inert "Soon" preview precisely because the destination was
 * always going to be outbound rather than an in-app route.
 */
export default function VaultPage(): ReactElement {
  return <VaultLaunch />;
}

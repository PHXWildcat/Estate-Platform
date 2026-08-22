import type { ReactElement } from 'react';
import { Dashboard } from '../../components/Dashboard';

/**
 * The home page IS the dashboard (M24 PR3). `Dashboard` owns the whole
 * surface, including the SettlingEstatesPanel placement rule (M23 PR2: above
 * the account content, self-hiding) and the signed-out hero.
 */
export default function HomePage(): ReactElement {
  return <Dashboard />;
}

import type { ReactElement, ReactNode } from 'react';
import { AppShell } from '../../components/AppShell';

export default function AppLayout({ children }: { children: ReactNode }): ReactElement {
  return <AppShell>{children}</AppShell>;
}

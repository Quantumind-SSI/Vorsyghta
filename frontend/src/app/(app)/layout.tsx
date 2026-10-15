import type { ReactNode } from 'react';

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="application-shell">
      <header className="app-header">
        <div className="app-header__inner page-width">
          <div className="wordmark">VORSYGHTA</div>
          <nav>
            <a href="/app/engagements">Engagements</a>
            <a href="/app/findings">Findings</a>
            <a href="/app/reports">Reports</a>
          </nav>
        </div>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}

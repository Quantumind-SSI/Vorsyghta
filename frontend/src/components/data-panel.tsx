import { ReactNode } from 'react';

export function DataPanel({
  title,
  kicker,
  children,
  status,
}: {
  title: string;
  kicker?: string;
  children: ReactNode;
  status?: 'good' | 'warn' | 'bad' | 'idle';
}) {
  return (
    <section className="data-panel">
      <div className="data-panel__heading">
        {kicker && <p className="eyebrow">{kicker}</p>}
        <h2>{title}</h2>
        {status && <span className={`status-chip status-chip--${status}`}>{status}</span>}
      </div>
      <div>{children}</div>
    </section>
  );
}

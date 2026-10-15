'use client';
import React from 'react';

type MoodCardProps = {
  title: string;
  value: string;
  sub?: string;
  status?: 'good' | 'warn' | 'bad' | 'idle';
  accent?: 'orange' | 'cyan' | 'steel';
  children?: React.ReactNode;
};

export function MoodCard({ title, value, sub, status = 'idle', accent = 'orange', children }: MoodCardProps) {
  const accentColor = accent === 'cyan' ? 'var(--violet-mid)' : accent === 'steel' ? 'var(--violet-deep)' : 'var(--lime)';
  const statusColor =
    status === 'good' ? 'var(--green)' :
    status === 'warn' ? 'var(--amber)' :
    status === 'bad' ? 'var(--red)' : 'var(--muted-dark)';

  return (
    <article className="mood-card">
      <div className="mood-card__header">
        <h3>{title}</h3>
        <span className="mood-card__status" style={{ background: statusColor }} aria-hidden />
      </div>
      <div className="mood-card__value">{value}</div>
      {sub && <div className="mood-card__sub">{sub}</div>}
      {children && <div className="mood-card__body">{children}</div>}
      <div className="mood-card__accent" style={{ background: accentColor }} />
      <style jsx>{`
        .mood-card {
          position: relative;
          background: var(--paper);
          border: 1px solid var(--hairline-dark);
          border-radius: 12px;
          padding: 1.25rem;
          overflow: hidden;
        }
        .mood-card__header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 0.5rem;
        }
        .mood-card__header h3 {
          font-size: 0.875rem;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          color: var(--ink-violet);
          margin: 0;
        }
        .mood-card__status {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          display: inline-block;
        }
        .mood-card__value {
          font-family: var(--font-mono);
          font-size: 1.75rem;
          font-weight: 700;
          color: var(--midnight);
        }
        .mood-card__sub {
          color: var(--muted-light);
          font-size: 0.875rem;
          margin-top: 0.25rem;
        }
        .mood-card__body {
          margin-top: 1rem;
          border-top: 1px dashed var(--hairline-light);
          padding-top: 1rem;
          color: var(--ink-violet);
        }
        .mood-card__accent {
          position: absolute;
          top: 0;
          left: 0;
          width: 4px;
          height: 100%;
          opacity: 0.9;
        }
      `}</style>
    </article>
  );
}

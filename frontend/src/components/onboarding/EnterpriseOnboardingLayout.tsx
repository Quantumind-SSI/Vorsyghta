import { MoodNav } from '@/components/brand/MoodNav';
import Link from 'next/link';
import React from 'react';

type Props = {
  step: number;
  total: number;
  title: string;
  description?: string;
  children: React.ReactNode;
  backHref?: string;
  nextLabel?: string;
};

export function EnterpriseOnboardingLayout({ step, total, title, description, children, backHref, nextLabel }: Props) {
  return (
    <main>
      <MoodNav />
      <div className="page-width" style={{ padding: '2rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--muted-light)' }}>
          {Array.from({ length: total }).map((_, i) => (
            <span key={i} style={{ opacity: i < step ? 1 : 0.4, color: i < step ? 'var(--lime)' : undefined }}>{i+1}</span>
          ))}
        </div>
        <h1 style={{ fontSize: '2rem', margin: '0 0 0.5rem' }}>{title}</h1>
        {description && <p style={{ color: 'var(--muted-light)', marginBottom: '2rem' }}>{description}</p>}
        <section style={{ background: 'var(--paper)', border: '1px solid var(--hairline-dark)', borderRadius: 12, padding: '2rem' }}>
          {children}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2rem' }}>
            {backHref && <Link href={backHref} style={{ textDecoration: 'none', color: 'var(--violet-mid)' }}>Back</Link>}
            <div />
          </div>
        </section>
      </div>
    </main>
  );
}

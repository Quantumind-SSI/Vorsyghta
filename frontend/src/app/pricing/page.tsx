import { MoodNav } from '@/components/brand/MoodNav';
import { MoodCard } from '@/components/brand/MoodCard';

export default function PricingPage() {
  return (
    <main>
      <MoodNav />
      <section className="page-width" style={{ padding: '4rem 2rem' }}>
        <h1 style={{ fontSize: '3rem', marginBottom: '1rem' }}>Pricing</h1>
        <p style={{ color: 'var(--muted-light)', marginBottom: '3rem' }}>Industrial control-room pricing, orange primary, steel accents.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px,1fr))', gap: '1.5rem' }}>
          <MoodCard title="Team" value="$299/mo" sub="Up to 5 users" status="idle" accent="orange">
            <ul>
              <li>Self-hostable</li>
              <li>Local model support</li>
              <li>MITRE mapping</li>
            </ul>
          </MoodCard>
          <MoodCard title="Enterprise" value="Custom" sub="Unlimited users" status="good" accent="cyan">
            <ul>
              <li>SSO & audit logs</li>
              <li>Dedicated support</li>
              <li>On-prem deployment</li>
            </ul>
          </MoodCard>
          <MoodCard title="Mission" value="Contact us" sub="Gov / critical infra" status="warn" accent="steel">
            <ul>
              <li>Air-gapped</li>
              <li>Custom compliance</li>
              <li>24/7 ops</li>
            </ul>
          </MoodCard>
        </div>
      </section>
    </main>
  );
}

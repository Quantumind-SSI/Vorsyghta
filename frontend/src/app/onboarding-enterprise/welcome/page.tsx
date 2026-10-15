import Link from 'next/link';
import { EnterpriseOnboardingLayout } from '@/components/onboarding/EnterpriseOnboardingLayout';

export default function OnboardingWelcome() {
  const steps = [
    ['Account verification','Email & legal acceptance'],
    ['Org & data residency','Profile, regions, residency'],
    ['Security & compliance','Frameworks, attestations'],
    ['Identity & SSO','SSO/SCIM setup'],
    ['Team & roles','Invites and permissions'],
    ['Environments','Connectors selection'],
    ['Integrations','Data sources'],
    ['Workspace','Project scaffolding'],
    ['First value','Guided exercise']
  ];
  return (
    <EnterpriseOnboardingLayout step={0} total={9} title="Welcome to Vorsyghta" description="Enterprise onboarding is 9 steps, ~12 minutes. Your answers configure compliance mapping, identity, environments and the first guided exercise.">
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(240px,1fr))', gap: '1rem' }}>
        {steps.map(([title,desc])=>(
          <div key={title} style={{ border:'1px solid var(--hairline-dark)', borderRadius:12, padding:'1rem', background:'var(--paper)' }}>
            <h3 style={{ margin:'0 0 .5rem' }}>{title}</h3>
            <p style={{ margin:0, color:'var(--muted-light)', fontSize:'0.9rem' }}>{desc}</p>
          </div>
        ))}
      </div>
      <div style={{ marginTop:'2rem' }}>
        <Link href="/onboarding-enterprise/verify" style={{ background:'var(--lime)', color:'var(--midnight)', padding:'0.75rem 1.5rem', borderRadius:8, textDecoration:'none', fontWeight:800, textTransform:'uppercase' }}>Start onboarding</Link>
      </div>
    </EnterpriseOnboardingLayout>
  );
}

import { EnterpriseOnboardingLayout } from '@/components/onboarding/EnterpriseOnboardingLayout';

export default function OnboardingVerify() {
  return (
    <EnterpriseOnboardingLayout step={1} total={9} title="Verify account & accept legal" description="Confirm your account and accept the legal documents.">
      <form style={{ maxWidth:600 }}>
        <label style={{ display:'block', marginBottom:'0.5rem' }}>Email verification code</label>
        <input name="code" placeholder="Enter code sent to email" style={{ width:'100%', padding:'0.75rem', margin:'0.5rem 0 1rem', border:'1px solid var(--hairline-dark)', borderRadius:8 }} />
        <label><input type="checkbox" required /> I accept Terms of Service</label>
        <br/>
        <label><input type="checkbox" required /> I accept Privacy Notice</label>
        <div style={{ marginTop:'1.5rem' }}>
          <button type="submit" style={{ background:'var(--lime)', color:'var(--midnight)', padding:'0.75rem 1.5rem', border:'none', borderRadius:8, fontWeight:800, textTransform:'uppercase' }}>Continue</button>
        </div>
      </form>
    </EnterpriseOnboardingLayout>
  );
}

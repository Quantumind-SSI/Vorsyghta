const repositoryBase = "https://github.com/QuantmindSSI/Vorsyghta/blob/master";

export function LegalLinks() {
  return (
    <nav className="legal-links" aria-label="Policies and license material">
      <a href={`${repositoryBase}/docs/compliance/gdpr/privacy-notice.md`}>Privacy notice</a>
      <a href={`${repositoryBase}/docs/compliance/policies/acceptable-use-policy.md`}>Acceptable use</a>
      <a href={`${repositoryBase}/LICENSE`}>Open-core license</a>
      <a href={`${repositoryBase}/docs/licensing/COMPONENT_MATRIX.md`}>Component terms</a>
    </nav>
  );
}

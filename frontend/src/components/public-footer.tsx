import Link from "next/link";

export function PublicFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer__rule" aria-hidden="true" />
      <div className="site-footer__inner">
        <div>
          <Link className="wordmark wordmark--footer" href="/">Vorsyghta</Link>
          <p>Evidence-first tooling for authorized security validation.</p>
        </div>
        <nav aria-label="Footer navigation">
          <Link href="/pricing">Pricing</Link>
          <a href="mailto:commercial@vorsyghta.io">Request demo</a>
          <a href="https://github.com/QuantmindSSI/Vorsyghta/tree/master/docs">Documentation</a>
          <a href="https://github.com/QuantmindSSI/Vorsyghta">GitHub</a>
        </nav>
      </div>
    </footer>
  );
}

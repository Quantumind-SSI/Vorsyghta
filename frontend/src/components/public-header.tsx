import Link from "next/link";

const navigation = [
  { href: "/#workflow", label: "Workflow" },
  { href: "/#evidence", label: "Evidence" },
  { href: "/#safety", label: "Safety" },
  { href: "/pricing", label: "Pricing" },
  {
    href: "https://github.com/QuantmindSSI/Vorsyghta/tree/master/docs",
    label: "Docs",
  },
];

function NavigationLinks() {
  return (
    <>
      {navigation.map((item) => (
        <Link href={item.href} key={item.href}>
          {item.label}
        </Link>
      ))}
    </>
  );
}

export function PublicHeader() {
  return (
    <header className="site-header">
      <div className="site-header__inner">
        <Link className="wordmark" href="/" aria-label="Vorsyghta home">
          <span className="wordmark__mark" aria-hidden="true">V</span>
          <span>Vorsyghta</span>
        </Link>

        <nav className="desktop-nav" aria-label="Primary navigation">
          <NavigationLinks />
        </nav>

        <div className="desktop-actions">
          <Link className="text-link" href="/sign-in">Sign in</Link>
          <Link className="button button--small button--light" href="/start-trial">
            Start trial
          </Link>
        </div>

        <details className="mobile-nav">
          <summary>Menu</summary>
          <nav aria-label="Mobile navigation">
            <NavigationLinks />
            <Link href="/sign-in">Sign in</Link>
            <Link href="/start-trial">Start trial</Link>
          </nav>
        </details>
      </div>
    </header>
  );
}

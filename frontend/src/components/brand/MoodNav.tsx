'use client';
import React from 'react';

export function MoodNav() {
  return (
    <header className="mood-nav">
      <div className="mood-nav__inner">
        <a href="/" className="mood-nav__brand">VORSYHTA</a>
        <nav className="mood-nav__links">
          <a href="#solutions">Solutions</a>
          <a href="#validation">Validation</a>
          <a href="#compliance">Compliance</a>
          <a href="#resources">Resources</a>
        </nav>
        <div className="mood-nav__actions">
          <a href="#login" className="pill">Sign in</a>
          <a href="#start" className="button button--primary">Start trial</a>
        </div>
      </div>
      <style jsx>{`
        .mood-nav {
          position: sticky;
          top: 0;
          z-index: 100;
          background: rgba(11,15,20,0.85);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid var(--hairline-dark);
          color: var(--white);
        }
        .mood-nav__inner {
          max-width: 1280px;
          margin: 0 auto;
          padding: 0.75rem 2rem;
          display: flex;
          align-items: center;
          gap: 2rem;
        }
        .mood-nav__brand {
          font-weight: 900;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: var(--white);
          text-decoration: none;
        }
        .mood-nav__links {
          display: flex;
          gap: 1.5rem;
          margin-left: auto;
        }
        .mood-nav__links a {
          color: var(--violet-soft);
          text-decoration: none;
          font-weight: 600;
          text-transform: uppercase;
          font-size: 0.875rem;
          letter-spacing: 0.06em;
        }
        .mood-nav__actions {
          display: flex;
          gap: 0.75rem;
        }
        .pill {
          color: var(--white);
          text-decoration: none;
          padding: 0.5rem 1rem;
          border: 1px solid var(--hairline-dark);
          border-radius: 999px;
          font-weight: 700;
          text-transform: uppercase;
          font-size: 0.75rem;
        }
        .button--primary {
          background: var(--lime);
          color: var(--midnight);
          text-decoration: none;
          padding: 0.5rem 1rem;
          border-radius: 8px;
          font-weight: 800;
          text-transform: uppercase;
          font-size: 0.75rem;
        }
        @media (max-width: 900px) {
          .mood-nav__links { display: none; }
        }
      `}</style>
    </header>
  );
}

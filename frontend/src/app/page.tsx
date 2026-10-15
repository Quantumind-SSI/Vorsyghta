import Link from "next/link";

import { PublicFooter } from "@/components/public-footer";
import { PublicHeader } from "@/components/public-header";

const workflow = [
  ["01", "Scope", "Define the permitted target, exclusions, and assessment window."],
  ["02", "Authorize", "Keep human approval separate from technical execution."],
  ["03", "Execute", "Use bounded orchestration and command-safety checks."],
  ["04", "Observe", "Preserve source, timestamps, outcomes, and dependency state."],
  ["05", "Improve", "Review findings before publishing reports or remediation guidance."],
] as const;

const provenance = [
  ["Measured", "A named tool or data source produced the record."],
  ["Simulated", "A deterministic scenario produced the result."],
  ["Generated", "A model generated or summarized the content."],
  ["Validated", "An analyst reviewed the evidence and disposition."],
  ["Unavailable", "A dependency failed or did not return valid data."],
] as const;

export default function HomePage() {
  return (
    <div className="marketing-shell">
      <PublicHeader />
      <main id="main-content">
        <section className="hero section-dark">
          <div className="hero__grid" aria-hidden="true" />
          <video
            className="hero__video"
            autoPlay
            muted
            loop
            playsInline
            aria-hidden="true"
            poster="/videos/hero-poster.jpg"
          >
            <source src="/videos/hero.mp4" type="video/mp4" />
          </video>
          <div className="hero__content page-width">
            <div className="hero__copy">
              <p className="eyebrow"><span>Authorized use</span> / evidence first</p>
              <h1>
                Run authorized security validation. Keep the <mark>evidence.</mark>
              </h1>
              <p className="hero__lead">
                Vorsyghta helps security teams scope, execute, observe, and report controlled
                adversarial assessments with human approval and explicit result provenance.
              </p>
              <div className="button-row">
                <Link className="button button--light" href="/start-trial">Start trial</Link>
                <a className="button button--outline-dark" href="mailto:commercial@vorsyghta.io">
                  Request demo
                </a>
              </div>
              <div className="hero__links">
                <a href="https://github.com/QuantmindSSI/Vorsyghta">View source on GitHub</a>
                <a href="https://github.com/QuantmindSSI/Vorsyghta/tree/master/docs">Read documentation</a>
              </div>
            </div>

            <aside className="evidence-contract" aria-label="Evidence contract">
              <div className="evidence-contract__topline">
                <span>Evidence contract</span>
                <span className="live-dot">Explicit states</span>
              </div>
              <dl>
                <div><dt>Scope</dt><dd>Required before execution</dd></div>
                <div><dt>Provenance</dt><dd>Named on every result view</dd></div>
                <div><dt>Model output</dt><dd>Not treated as evidence</dd></div>
                <div><dt>Dependency failure</dt><dd>Reported as unavailable</dd></div>
              </dl>
              <p className="evidence-contract__note">
                Interface contract, not a simulated assessment.
              </p>
            </aside>
          </div>
        </section>

        <section className="principle-strip" aria-label="Platform principles">
          <div className="page-width principle-strip__inner">
            <span>Self-hostable</span>
            <span>Local model support</span>
            <span>MITRE ATT&amp;CK mapping</span>
            <span>Open-core repository</span>
          </div>
        </section>

        <section className="section-light editorial-section" id="workflow">
          <div className="page-width split-heading">
            <div>
              <p className="eyebrow eyebrow--ink">The operating loop</p>
              <h2>Control the work before interpreting the result.</h2>
            </div>
            <p>
              Point-in-time testing often separates authorization, execution, and reporting.
              Vorsyghta keeps those concerns visible as one reviewable workflow.
            </p>
          </div>
          <ol className="page-width workflow-grid">
            {workflow.map(([number, title, description]) => (
              <li key={number}>
                <span className="workflow-grid__number">{number}</span>
                <h3>{title}</h3>
                <p>{description}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="section-dark evidence-section" id="evidence">
          <div className="page-width evidence-layout">
            <div className="evidence-layout__intro">
              <p className="eyebrow">A vocabulary for proof</p>
              <h2>Results do not all mean the same thing.</h2>
              <p>
                The product distinguishes recorded activity, deterministic simulation,
                model-generated material, analyst review, and missing dependencies.
              </p>
            </div>
            <div className="provenance-list">
              {provenance.map(([title, description], index) => (
                <article key={title}>
                  <span className={`provenance-list__marker marker-${index + 1}`} aria-hidden="true" />
                  <div><h3>{title}</h3><p>{description}</p></div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section-warm capability-section">
          <div className="page-width">
            <p className="eyebrow eyebrow--ink">Current platform surface</p>
            <h2>Built around controls already present in the repository.</h2>
            <div className="capability-grid">
              <article>
                <span>01 / Boundaries</span>
                <h3>Engagement and command safety</h3>
                <p>Authorization, lab-network checks, role controls, and command validation remain separate gates.</p>
              </article>
              <article>
                <span>02 / Evidence</span>
                <h3>Tracking and structured reporting</h3>
                <p>Recorded tool usage, findings, vulnerability reports, and audit primitives preserve review context.</p>
              </article>
              <article>
                <span>03 / Choice</span>
                <h3>Provider and deployment control</h3>
                <p>Self-hosting and configurable model providers let operators choose their infrastructure boundary.</p>
              </article>
            </div>
          </div>
        </section>

        <section className="section-light safety-section" id="safety">
          <div className="page-width safety-card">
            <div>
              <p className="eyebrow eyebrow--ink">Responsible operation</p>
              <h2>Authorization is a product boundary.</h2>
            </div>
            <div>
              <p>
                Vorsyghta is for sanctioned targets and configured lab networks. The frontend
                foundation is deliberately read-only and exposes no attack execution controls.
              </p>
              <ul className="check-list">
                <li>Human approval remains explicit</li>
                <li>External destinations fail closed</li>
                <li>Unavailable data is never replaced with synthetic success</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="final-cta section-dark">
          <div className="page-width final-cta__inner">
            <div>
              <p className="eyebrow">Start with the evidence</p>
              <h2>Make every security result answerable.</h2>
            </div>
            <div className="button-row">
              <Link className="button button--light" href="/start-trial">Start trial</Link>
              <Link className="button button--outline-dark" href="/pricing">View pricing</Link>
            </div>
          </div>
        </section>
      </main>
      <PublicFooter />
    </div>
  );
}

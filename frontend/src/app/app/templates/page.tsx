import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { fetchBillingStatus, fetchTemplateCatalog } from "@/lib/api/client";
import type { ApiResult } from "@/lib/api/client";
import type { TemplateCatalog } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Scenario templates",
  description: "Browse and validate threat-scenario templates. No execution here.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function severityClass(severity: string | null): string {
  if (severity === "critical" || severity === "high") return "status-chip--bad";
  if (severity === "medium") return "status-chip--warn";
  if (severity === null) return "status-chip--idle";
  return "status-chip--good";
}

function TemplateCatalogPanel({ catalog }: { catalog: TemplateCatalog }) {
  const categories = Object.entries(catalog.categories).sort(([a], [b]) => a.localeCompare(b));
  if (categories.length === 0) {
    return <p className="empty-state">No templates were returned by the API.</p>;
  }
  return (
    <>
      {categories.map(([category, templates]) => (
        <section className="data-panel" aria-labelledby={`tpl-${category}-heading`} key={category}>
          <div className="data-panel__heading">
            <div>
              <p className="card-kicker">{templates.length} template{templates.length === 1 ? "" : "s"}</p>
              <h2 id={`tpl-${category}-heading`}>{category === "root" ? "Top-level templates" : category}</h2>
            </div>
            <span className="source-label">Source: templates router</span>
          </div>
          <div className="table-scroll" role="region" aria-label={`Templates in ${category}`} tabIndex={0}>
            <table>
              <caption className="visually-hidden">Templates in {category}</caption>
              <thead>
                <tr>
                  <th>Template</th>
                  <th>Threat type</th>
                  <th>Severity</th>
                  <th>Target role</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {[...templates]
                  .sort((a, b) => {
                    const ai = SEVERITY_ORDER.indexOf((a.severity ?? "") as typeof SEVERITY_ORDER[number]);
                    const bi = SEVERITY_ORDER.indexOf((b.severity ?? "") as typeof SEVERITY_ORDER[number]);
                    const av = ai === -1 ? SEVERITY_ORDER.length : ai;
                    const bv = bi === -1 ? SEVERITY_ORDER.length : bi;
                    return av - bv || a.name.localeCompare(b.name);
                  })
                  .map((template) => (
                    <tr key={template.file}>
                      <td><strong>{template.name}</strong><span className="table-id">{template.file}</span></td>
                      <td>{template.threat_type ?? "Not stated"}</td>
                      <td>
                        <span className={`status-chip ${severityClass(template.severity)}`}>
                          {template.severity ?? "Not stated"}
                        </span>
                      </td>
                      <td>{template.target_role ?? "Not stated"}</td>
                      <td>
                        <Link className="button button--small button--outline-dark" href={`/app/templates/${category}/${template.name}`}>
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}

function UnavailablePanel({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="data-panel data-panel--unavailable" role="status">
      <p className="card-kicker">Dependency unavailable</p>
      <h2>{title}</h2>
      <p>{detail}</p>
    </section>
  );
}

export default async function TemplatesPage() {
  const session = await requireSession("/app/templates");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so template data remains hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Ftemplates");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Template data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const catalog: ApiResult<TemplateCatalog> = await fetchTemplateCatalog(session.token);
  if (!catalog.ok && (catalog.kind === "unauthorized" || catalog.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Ftemplates");

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #1 — Colour-team operations</p>
          <h1>Scenario templates</h1>
          <p>
            Version-controllable YAML threat scenarios. Browse and preview only — this screen
            never executes a scenario, provisions infrastructure, or contacts a target.
          </p>
        </div>
        {catalog.ok ? (
          <dl className="identity-card">
            <div><dt>Templates</dt><dd>{catalog.data.total.toLocaleString("en-GB")}</dd></div>
            <div><dt>Categories</dt><dd>{Object.keys(catalog.data.categories).length.toLocaleString("en-GB")}</dd></div>
          </dl>
        ) : null}
      </div>

      {!catalog.ok ? (
        <UnavailablePanel
          title="Templates unavailable"
          detail="The templates endpoint did not return valid data. No substitute data is shown."
        />
      ) : (
        <TemplateCatalogPanel catalog={catalog.data} />
      )}
      <p className="panel-footnote">
        Template execution, assessment creation, and target contact require an approved
        engagement and the canonical safety path — they are not available in this release.
      </p>
    </main>
  );
}

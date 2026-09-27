import type { Metadata } from "next";
import { redirect } from "next/navigation";

import {
  fetchBillingStatus,
  fetchThreatIntel,
} from "@/lib/api/client";
import type { ThreatActor, ThreatCampaign, ThreatIndicator, ThreatTtp } from "@/lib/api/schemas";
import { hasProductAccess } from "@/lib/billing";
import { formatDateTime } from "@/lib/format";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Threat intelligence",
  description: "CVE actors, campaigns, indicators, and TTP records for this tenant.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

function CountChip({ label, count }: { label: string; count: number }) {
  return (
    <div className="intel-count">
      <dt>{label}</dt>
      <dd>{count.toLocaleString("en-GB")}</dd>
    </div>
  );
}

function ActorsTable({ actors }: { actors: ThreatActor[] }) {
  if (actors.length === 0) {
    return <p className="empty-state">No threat actor records exist for this tenant.</p>;
  }
  return (
    <div className="table-scroll" role="region" aria-label="Threat actors" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Threat actor records for this tenant</caption>
        <thead>
          <tr>
            <th>Actor</th>
            <th>Type</th>
            <th>Targets</th>
            <th>Motivation</th>
            <th>Confidence</th>
            <th>Active</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {actors.map((actor) => (
            <tr key={actor.actor_id}>
              <td><strong>{actor.name}</strong><span className="table-id">{actor.actor_id}</span></td>
              <td>{actor.actor_type}</td>
              <td>{[...actor.target_industries, ...actor.target_regions].slice(0, 3).join(", ") || "Not reported"}</td>
              <td>{actor.primary_motivation ?? "Not reported"}</td>
              <td><span className="table-id">{actor.confidence_level}</span></td>
              <td>
                <span className={`status-chip ${actor.is_active ? "status-chip--warn" : "status-chip--idle"}`}>
                  {actor.is_active ? "Active" : "Inactive"}
                </span>
              </td>
              <td>{actor.last_seen ? formatDateTime(actor.last_seen) : "Not reported"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CampaignsTable({ campaigns }: { campaigns: ThreatCampaign[] }) {
  if (campaigns.length === 0) {
    return <p className="empty-state">No campaign records exist for this tenant.</p>;
  }
  return (
    <div className="table-scroll" role="region" aria-label="Threat campaigns" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Threat campaign records for this tenant</caption>
        <thead>
          <tr>
            <th>Campaign</th>
            <th>Status</th>
            <th>Targets</th>
            <th>MITRE techniques</th>
            <th>Confidence</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((campaign) => (
            <tr key={campaign.campaign_id}>
              <td><strong>{campaign.name}</strong><span className="table-id">{campaign.campaign_id}</span></td>
              <td><span className="table-id">{campaign.campaign_status}</span></td>
              <td>{[...campaign.target_organizations, ...campaign.target_sectors].slice(0, 3).join(", ") || "Not reported"}</td>
              <td>{campaign.mitre_techniques.slice(0, 4).join(", ") || "Not reported"}</td>
              <td><span className="table-id">{campaign.confidence_level}</span></td>
              <td>{campaign.start_date ? formatDateTime(campaign.start_date) : "Not reported"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IndicatorsTable({ indicators }: { indicators: ThreatIndicator[] }) {
  if (indicators.length === 0) {
    return <p className="empty-state">No indicator records exist for this tenant.</p>;
  }
  return (
    <div className="table-scroll" role="region" aria-label="Threat indicators" tabIndex={0}>
      <table>
        <caption className="visually-hidden">Threat indicator records for this tenant</caption>
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>State</th>
            <th>Score</th>
            <th>Technique</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {indicators.map((indicator) => (
            <tr key={indicator.indicator_id}>
              <td><strong>{indicator.indicator_value}</strong><span className="table-id">{indicator.indicator_id}</span></td>
              <td>{indicator.indicator_type}</td>
              <td><span className="table-id">{indicator.indicator_state}</span></td>
              <td>{indicator.threat_score ?? "Not scored"}</td>
              <td>{indicator.mitre_technique ?? "Not mapped"}</td>
              <td>{indicator.last_seen ? formatDateTime(indicator.last_seen) : "Not reported"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TtpsTable({ ttps }: { ttps: ThreatTtp[] }) {
  if (ttps.length === 0) {
    return <p className="empty-state">No TTP records exist for this tenant.</p>;
  }
  return (
    <div className="table-scroll" role="region" aria-label="TTP records" tabIndex={0}>
      <table>
        <caption className="visually-hidden">TTP records for this tenant</caption>
        <thead>
          <tr>
            <th>TTP</th>
            <th>Technique</th>
            <th>Tactic</th>
            <th>Category</th>
            <th>Confidence</th>
            <th>Recorded</th>
          </tr>
        </thead>
        <tbody>
          {ttps.map((ttp) => (
            <tr key={ttp.ttp_id}>
              <td><strong>{ttp.ttp_name}</strong><span className="table-id">{ttp.ttp_id}</span></td>
              <td>{ttp.mitre_technique_id ?? "Not mapped"}</td>
              <td>{ttp.mitre_tactic ?? "Not reported"}</td>
              <td>{ttp.ttp_category}</td>
              <td><span className="table-id">{ttp.confidence_level}</span></td>
              <td>{formatDateTime(ttp.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

export default async function ThreatIntelPage() {
  const session = await requireSession("/app/intelligence");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so intelligence data remains hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fintelligence");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Intelligence data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const intel = await fetchThreatIntel(session.token);
  if (!intel.ok && (intel.kind === "unauthorized" || intel.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fintelligence");

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #2 — Intelligence stack</p>
          <h1>Threat intelligence</h1>
          <p>
            Live CVE actors, campaigns, indicators, and TTP records scoped to this tenant.
            Read-only: hunt authoring and hunt execution are not exposed here.
          </p>
        </div>
        {!intel.ok ? null : (
          <dl className="identity-card">
            <CountChip label="Actors" count={intel.data.actors.length} />
            <CountChip label="Campaigns" count={intel.data.campaigns.length} />
            <CountChip label="Indicators" count={intel.data.indicators.length} />
            <CountChip label="TTPs" count={intel.data.ttps.length} />
          </dl>
        )}
      </div>

      {!intel.ok ? (
        <UnavailablePanel
          title="Threat intelligence unavailable"
          detail="The intelligence endpoints did not return valid data. No substitute data is shown."
        />
      ) : (
        <div className="dashboard-grid">
          <section className="data-panel" aria-labelledby="intel-actors-heading">
            <div className="data-panel__heading">
              <div><p className="card-kicker">Most recent 50</p><h2 id="intel-actors-heading">Threat actors</h2></div>
              <span className="source-label">Source: threat-intel</span>
            </div>
            <ActorsTable actors={intel.data.actors} />
          </section>
          <section className="data-panel" aria-labelledby="intel-campaigns-heading">
            <div className="data-panel__heading">
              <div><p className="card-kicker">Most recent 50</p><h2 id="intel-campaigns-heading">Campaigns</h2></div>
              <span className="source-label">Source: threat-intel</span>
            </div>
            <CampaignsTable campaigns={intel.data.campaigns} />
          </section>
          <section className="data-panel" aria-labelledby="intel-indicators-heading">
            <div className="data-panel__heading">
              <div><p className="card-kicker">Most recent 50</p><h2 id="intel-indicators-heading">Indicators</h2></div>
              <span className="source-label">Source: threat-intel</span>
            </div>
            <IndicatorsTable indicators={intel.data.indicators} />
          </section>
          <section className="data-panel" aria-labelledby="intel-ttps-heading">
            <div className="data-panel__heading">
              <div><p className="card-kicker">Most recent 50</p><h2 id="intel-ttps-heading">TTPs</h2></div>
              <span className="source-label">Source: threat-intel</span>
            </div>
            <TtpsTable ttps={intel.data.ttps} />
          </section>
        </div>
      )}
      <p className="panel-footnote">
        Intelligence records inform simulation and detection design. They are not evidence that
        an attack or detection occurred in your environment.
      </p>
    </main>
  );
}

import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { fetchBillingStatus } from "@/lib/api/client";
import { hasProductAccess } from "@/lib/billing";
import { requireSession } from "@/lib/session";

export const metadata: Metadata = {
  title: "Environments",
  description: "Connect the environments Vorsyghta works with: containers, cloud, files, web apps and APIs, external infrastructure, images, and media.",
  robots: { index: false, follow: false },
};

export const dynamic = "force-dynamic";

type AdapterCategory = {
  readonly id: string;
  readonly name: string;
  readonly sources: readonly string[];
  readonly detail: string;
};

// Adapter categories mirror the ingestion surface implemented in
// vorsyghta/client_data/sources/ — not invented categories.
const ADAPTER_CATEGORIES: readonly AdapterCategory[] = [
  {
    id: "containers",
    name: "Containers",
    sources: ["Docker / Compose clusters", "Container images"],
    detail: "Cluster connections and container images as assessable artifacts.",
  },
  {
    id: "cloud",
    name: "Cloud",
    sources: ["AWS S3", "Azure Blob", "GCP GCS", "IAM policies", "Security groups", "VPC / VNet topology", "Compute", "Kubernetes (EKS/AKS/GKE)", "Serverless", "API gateway", "Logging", "Secrets", "CDN / WAF"],
    detail: "Account structure, network topology, and posture data from AWS, Azure, and GCP.",
  },
  {
    id: "files",
    name: "Files",
    sources: ["OneDrive", "SharePoint", "Google Drive"],
    detail: "Document inventories: policies, architecture diagrams, configurations.",
  },
  {
    id: "web-apps-apis",
    name: "Web apps & APIs",
    sources: ["REST / GraphQL endpoints", "OpenAPI / Swagger specs", "Webhook inventories"],
    detail: "Target application and API surfaces for assessment scoping.",
  },
  {
    id: "external-infrastructure",
    name: "External infrastructure",
    sources: ["GNS3 topology exports", "Firewall rules", "Router tables", "DNS configuration", "VPN configuration", "Asset inventories", "Exposed services"],
    detail: "On-premises and hybrid network topology, segmentation, and asset data.",
  },
  {
    id: "directories-crm",
    name: "Directories & CRM",
    sources: ["Microsoft 365", "Entra ID", "Salesforce", "HubSpot", "Google Workspace"],
    detail: "Employee and org-structure data feeding OSINT-enriched simulation.",
  },
  {
    id: "media",
    name: "Media & other formats",
    sources: ["Container images", "VM images", "Packet captures", "Forensic artifacts"],
    detail: "Any additional adapter registered against the ClientDataSource base class.",
  },
] as const;

function AdapterGrid({ mayManage }: { mayManage: boolean }) {
  return (
    <div className="dashboard-grid">
      {ADAPTER_CATEGORIES.map((category) => (
        <section className="data-panel" aria-labelledby={`env-${category.id}-heading`} key={category.id}>
          <div className="data-panel__heading">
            <div>
              <p className="card-kicker">{category.sources.length} source type{category.sources.length === 1 ? "" : "s"}</p>
              <h2 id={`env-${category.id}-heading`}>{category.name}</h2>
            </div>
            <span className="status-chip status-chip--idle">Not connected</span>
          </div>
          <p>{category.detail}</p>
          <ul className="health-list">
            {category.sources.map((source) => (
              <li key={source}>{source}</li>
            ))}
          </ul>
          {mayManage ? (
            <p className="panel-footnote">Connection requires a durable, tenant-bound connection record — not available in this release.</p>
          ) : (
            <p className="panel-footnote">Environment connections are managed by administrator-capable roles.</p>
          )}
        </section>
      ))}
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

export default async function EnvironmentsPage() {
  const session = await requireSession("/app/environments");
  if (session.state === "unavailable") {
    return <UnavailablePanel title="Identity service unavailable" detail="The session could not be verified, so environment data remains hidden." />;
  }

  const billing = await fetchBillingStatus(session.token);
  if (!billing.ok && (billing.kind === "unauthorized" || billing.kind === "forbidden")) redirect("/sign-in?next=%2Fapp%2Fenvironments");
  if (!billing.ok) {
    return <UnavailablePanel title="Entitlement unavailable" detail="Billing status could not be verified. Environment data remains hidden." />;
  }
  if (!hasProductAccess(billing.data)) redirect("/start-trial?reason=not-entitled");

  const mayManage = session.user.role === "admin";

  return (
    <main className="app-main" id="main-content">
      <div className="app-page-heading">
        <div>
          <p className="eyebrow">Capability #2 — Intelligence stack · client data</p>
          <h1>Environments</h1>
          <p>
            Connect the environments Vorsyghta works with: containers, cloud, files, web apps
            and APIs, external infrastructure, images, and media. Connections are tenant-bound
            and credentials never pass through the browser.
          </p>
        </div>
        <dl className="identity-card">
          <div><dt>Adapter categories</dt><dd>{ADAPTER_CATEGORIES.length.toLocaleString("en-GB")}</dd></div>
          <div><dt>Connections</dt><dd>0</dd></div>
        </dl>
      </div>

      <AdapterGrid mayManage={mayManage} />
      <p className="panel-footnote">
        No connections exist yet because durable tenant-bound connection storage is not
        available in this release. This hub shows the adapter surface and the connect path;
        it never fabricates a connected state.
      </p>
    </main>
  );
}

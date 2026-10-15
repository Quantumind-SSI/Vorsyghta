import { DataPanel } from '@/components/data-panel';
import { BadgeProvenance } from '@/components/badge-provenance';

export default function Dashboard() {
  return (
    <div>
      <div className="app-page-heading">
        <h1>Command Dashboard</h1>
        <p>Multi-monitor view of engagements, findings and evidence provenance.</p>
      </div>

      <div className="dashboard-grid">
        <DataPanel title="Active Engagements" kicker="Scope" status="good">
          <p>No new engagements pending review.</p>
        </DataPanel>
        <DataPanel title="Findings" kicker="Evidence" status="warn">
          <ul>
            <li>
              IDOR on profile endpoint <BadgeProvenance state="Measured" />
            </li>
            <li>
              SSRF in web preview <BadgeProvenance state="Simulated" />
            </li>
          </ul>
        </DataPanel>
        <DataPanel title="Reports" kicker="Provenance">
          <p>Last report generated 2025-10-07. All results tagged.</p>
        </DataPanel>
      </div>
    </div>
  );
}

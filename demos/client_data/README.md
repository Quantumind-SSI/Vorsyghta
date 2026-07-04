# Ciicerone Client Data Demo

This demo shows how Ciicerone can ingest client data from multiple sources and use it to enrich threat scenarios and target profiles.

For a walkthrough of **all** Ciicerone features (red team, blue team, intel, RAG, etc.), see [`demos/full_platform/`](../full_platform).

## What it demonstrates

1. **Multi-source client data ingestion** via the local demo API and a GNS3 network topology file.
2. **Tenant-scoped sync** with the `client-data sync` CLI.
3. **Profile inspection** with `client-data show`.
4. **Scenario enrichment** with `client-data enrich`, which maps real employees to target profiles and adds network topology/assets.
5. **Optional company recon** (`--recon`) using the OSINT agent (requires internet).

## Files

- `demo_config.yaml` — demo configuration (no API keys required).
- `demo_client_api.json` — sample employee directory served by the local demo server.
- `demo_network.gns3` — sample network topology file.
- `demo_scenario.yaml` — sample threat scenario to enrich.
- `serve_demo_data.py` — tiny local HTTP server.
- `run_demo.sh` — orchestrates the full demo end-to-end.

## Run the demo

```bash
cd /Users/startferanmi/Documents/Ciicerone/Ciicerone/demos/client_data
bash run_demo.sh
```

The script will:

1. Start a local HTTP server on `localhost:8765`.
2. List configured client data sources.
3. Sync data for tenant `acme-demo`.
4. Show the synced client profile.
5. Enrich `demo_scenario.yaml` and save the result to `enriched_scenario.json`.

## Run with company recon (optional, requires internet)

```bash
bash run_demo.sh --recon
```

This triggers the `CompanyReconAgent` to gather OSINT on the target domain derived from the employee email domain.

## Run the API server demo

```bash
python -m ciicerone.api.main --config demos/client_data/demo_config.yaml
```

Then use the client-data endpoints:

```bash
# List sources
curl http://localhost:8000/client-data/sources?tenant_id=acme-demo

# Sync
curl -X POST http://localhost:8000/client-data/sync?tenant_id=acme-demo

# Show profile
curl http://localhost:8000/client-data/profile/acme-demo

# Enrich scenario
curl -X POST http://localhost:8000/client-data/enrich/acme-demo \
  -H "Content-Type: application/json" \
  -d @demo_scenario.yaml
```

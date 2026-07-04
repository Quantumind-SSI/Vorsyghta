# Ciicerone Full-Platform Demo

This demo walks through all major Ciicerone feature areas in one script. It uses the same offline client-data demo server as `demos/client_data/`, so no API keys or cloud credentials are required (except for the optional `--recon` flag).

## What it demonstrates

1. **Platform status** (`status`)
2. **Scenario templates** (`templates list-all`)
3. **Playbook validation** (`validate playbook`) using a production-grade markdown playbook
4. **Ciicerone Attack scenario-to-task mapping** — demonstrates how the playbook maps to autonomous red-team tasks
5. **Client data ingestion & enrichment** (`client-data sync`, `show`, `enrich`)
6. **Red team / Ciicerone Attack integration** (`red-team health`)
6. **Blue team defensive operations** (`blue-team dashboard`, `ids`, `edr`, `incident`)
7. **Intelligence / OSINT** (`intel sources`)
8. **Detection engineering** (`detect list-formats`)
9. **RAG system** (`rag status`)
10. **Feedback loop** (`feedback status`)
11. **Dataset catalog** (`datasets list`)
12. **VM lab** (`vm status`)
13. **MCP server** (`mcp status`)
14. **Simulation logs** (`logs list`)
15. **Safety controls** (`safety`)

## Run the demo

```bash
cd /Users/startferanmi/Documents/Ciicerone/Ciicerone/demos/full_platform
bash run_full_demo.sh
```

With optional company recon (requires internet):

```bash
bash run_full_demo.sh --recon
```

## Notes

- Some commands (e.g., `red-team status`, `rag status`) may report "not configured" because they depend on external services or LLM providers. This is expected and still demonstrates the CLI surface.
- The demo server runs on `localhost:8765`. If the port is busy, the script will attempt to clean it up.
- The enriched scenario is saved to `enriched_scenario.json` in this directory.

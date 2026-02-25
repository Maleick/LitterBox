# Integrations

**Analysis Date:** 2026-02-25

## APIs & External Services

- Primary service interface is the local Flask API in `app/routes.py`:
  - Upload and analysis: `/upload`, `/analyze/<analysis_type>/<target>`, `/holygrail`.
  - Results APIs: `/api/results/<target>/*`, `/api/report/<target>`.
  - Operational endpoints: `/health`, `/cleanup`, `/files`.
- MCP exposure layer in `GrumpyCats/LitterBoxMCP.py` wraps the HTTP API for LLM tool usage.
- Python client in `GrumpyCats/grumpycat.py` calls local API endpoints via `requests`.
- No mandatory outbound SaaS API dependency in core app runtime.

## Data Storage

- Filesystem-backed storage only (no SQL/NoSQL service):
  - Uploads: `Uploads/`.
  - Analysis result trees: `Results/`.
  - Fuzzy/Blender DB data: `Utils/DoppelgangerDB/`.
  - Scanner-specific output paths: `Scanners/*/Analysis` and HolyGrail output path from config.
- Persistent metadata and result objects are JSON files (`file_info.json`, `static_analysis_results.json`, `dynamic_analysis_results.json`, `byovd_results.json`).

## Authentication & Identity

- No authentication middleware in `app/routes.py`.
- No API key, token validation, or user/session management in active Flask endpoints.
- MCP and Python client assume trusted local/isolated network context.

## Monitoring & Observability

- Health checks via `/health` route in `app/routes.py`.
- Application logging uses Flask logger + optional colored formatter in `app/__init__.py`.
- Analyzer wrappers return structured `status`/`error` fields for operational diagnostics.
- No centralized metrics backend (Prometheus/OTel/ELK) configured in repo.

## CI/CD & Deployment

- Docker deployment helper files in `Docker/`:
  - `Docker/docker-compose.yml` for Windows sandbox container provisioning.
  - `Docker/setup.sh` and `Docker/install.ps1` for host/guest bootstrap.
- No GitHub Actions, GitLab CI, or other CI manifests tracked in repository.
- Deploy model is operator-driven setup and local runtime execution.

## Environment Configuration

- Main integration and tool configuration file: `Config/config.yaml`.
- Per-tool enablement and command templates are controlled under:
  - `analysis.static.*`
  - `analysis.dynamic.*`
  - `analysis.holygrail`
  - `analysis.doppelganger`
- Docker environment variables control VM resources and credentials in `Docker/docker-compose.yml`.

## Webhooks & Callbacks

- No inbound webhook receivers or callback signature validation paths are implemented.
- No asynchronous callback registration with external SaaS providers detected.
- Internal workflows are synchronous request/response operations triggered by API calls.

---

*Integrations analysis: 2026-02-25*
*Update when external services or trust boundaries change*

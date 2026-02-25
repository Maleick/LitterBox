# Technology Stack

**Analysis Date:** 2026-02-25

## Languages

**Primary:**
- Python 3.11+ - Core web app, analyzers, utilities, and client tooling in `app/`, `litterbox.py`, and `GrumpyCats/`.

**Secondary:**
- HTML/Jinja templates - UI rendering in `app/templates/`.
- YAML - Runtime configuration in `Config/config.yaml`.
- PowerShell - Windows bootstrap in `Docker/install.ps1`.
- Bash - Linux/Docker setup in `Docker/setup.sh`.

## Runtime

**Environment:**
- Flask web server runtime from `litterbox.py` and `app/__init__.py`.
- Analyzer execution depends on local scanner binaries under `Scanners/` configured via `Config/config.yaml`.
- Dynamic analysis paths assume Windows-style tooling and admin/elevated execution for process inspection.

**Package Manager:**
- `pip` with pinned dependencies in `requirements.txt`.
- Lockfile: not present.

## Frameworks

**Core:**
- Flask 3.1.0 - HTTP API + template rendering (`app/routes.py`, `app/templates/*.html`).
- Jinja2 3.1.6 - HTML views (`app/templates/*.html`).

**Testing:**
- No test framework configured in repo (`pytest`, `unittest` suites, and test directories are absent).

**Build/Dev:**
- Docker Compose for sandbox host/bootstrap orchestration in `Docker/docker-compose.yml`.
- No dedicated Python build system (`pyproject.toml`/`setup.py` absent).

## Key Dependencies

**Critical:**
- `Flask` - App server and routing.
- `PyYAML` - Loads runtime scanner and app configuration.
- `psutil` - PID/process validation and runtime process checks.
- `pefile` - PE metadata parsing for file intelligence.
- `oletools` / `msoffcrypto-tool` - Office/macro-oriented parsing and analysis.
- `pyssdeep` - Fuzzy hash comparisons in `app/analyzers/fuzzy.py`.

**Infrastructure:**
- Scanner executables in `Scanners/` (YARA, PE-Sieve, Moneta, Patriot, RedEdr, HolyGrail, etc.) launched via subprocess wrappers.
- MCP server framework in `GrumpyCats/LitterBoxMCP.py` (`mcp.server.fastmcp`).
- HTTP client stack in `GrumpyCats/grumpycat.py` (`requests`, retry adapter).

## Configuration

**Environment:**
- Main app config in `Config/config.yaml` (host/port, folders, tool paths, timeouts, enabled flags).
- Runtime writes data into `Uploads/`, `Results/`, and `Utils/DoppelgangerDB/*`.
- No auth/environment variable guardrails for API endpoints by default.

**Build:**
- Container profile and resource sizing in `Docker/docker-compose.yml`.
- No CI config or formal build pipeline files in repo root.

## Platform Requirements

**Development:**
- Python 3.11+ with dependencies from `requirements.txt`.
- Access to platform-specific scanner executables referenced in `Config/config.yaml`.
- Elevated privileges are expected by `litterbox.py` for full runtime capabilities.

**Production:**
- Intended to run inside isolated malware-analysis sandbox environments.
- Docker path provisions a Windows guest container (`dockurr/windows`) exposing RDP and app ports.
- Runtime behavior is tightly coupled to local filesystem layout and scanner binary paths.

---

*Stack analysis: 2026-02-25*
*Update after dependency/runtime changes*

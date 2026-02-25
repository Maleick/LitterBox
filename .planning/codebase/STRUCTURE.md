# Structure

**Analysis Date:** 2026-02-25

## Directory Layout

```text
/opt/LitterBox
|- Config/
|- Docker/
|- GrumpyCats/
|- Scanners/
|- Screenshots/
|- Utils/
|- app/
|- litterbox.py
|- requirements.txt
|- README.md
`- .planning/codebase/   (generated mapping docs)
```

## Directory Purposes

- `Config/` - central YAML runtime configuration (`config.yaml`) for app behavior and scanner commands.
- `Docker/` - containerized Windows sandbox setup, compose manifest, and installer scripts.
- `GrumpyCats/` - Python client (`grumpycat.py`) and MCP tool server (`LitterBoxMCP.py`).
- `Scanners/` - third-party scanner executables/rules and output folders.
- `Utils/` - static support assets such as `malapi.json` and doppelganger DB base path.
- `app/` - Flask application package (routes, analyzers, templates, static assets, utilities).
- `Screenshots/` - repository media assets.

## Key File Locations

- Startup executable: `litterbox.py`.
- Flask app factory/config load: `app/__init__.py`.
- Route and API surface: `app/routes.py`.
- Utility and report logic: `app/utils.py`.
- Analyzer coordination: `app/analyzers/manager.py`.
- Analyzer implementations:
  - Static: `app/analyzers/static/*.py`
  - Dynamic: `app/analyzers/dynamic/*.py`
  - Specialty: `app/analyzers/blender.py`, `fuzzy.py`, `holygrail.py`
- Runtime config: `Config/config.yaml`.
- Dependency list: `requirements.txt`.

## Naming Conventions

- Python modules: snake_case filenames (for example `stringnalyzer_analyzer.py`).
- Class names: PascalCase (for example `AnalysisManager`, `HolyGrailAnalyzer`).
- Route handler functions: snake_case and colocated in `app/routes.py`.
- JSON result artifacts use predictable names:
  - `file_info.json`
  - `static_analysis_results.json`
  - `dynamic_analysis_results.json`
  - `byovd_results.json`

## Where to Add New Code

- New HTTP endpoints: extend `register_routes` in `app/routes.py`; keep helper logic in `RouteHelpers` or `app/utils.py`.
- New analyzer integration:
  1. add adapter in `app/analyzers/static/` or `app/analyzers/dynamic/`,
  2. wire into `AnalysisManager.STATIC_ANALYZERS` or `DYNAMIC_ANALYZERS`,
  3. add config section in `Config/config.yaml`.
- Shared domain logic (hashing, metadata, risk/report utilities): `app/utils.py`.
- Client/MCP features: `GrumpyCats/`.
- Deployment/runtime setup changes: `Docker/` and `Config/config.yaml`.

## Special Directories

- `Scanners/*/Analysis` - tool-generated runtime artifacts (often large and environment-specific).
- `Uploads/` and `Results/` - created at runtime; not tracked as source.
- `Utils/DoppelgangerDB/*` - fuzzy/blender data store paths expected by doppelganger analyzers.
- `.planning/` - planning artifacts used by GSD workflows; downstream commands read these docs.

---

*Structure analysis: 2026-02-25*
*Update when directories, entrypoints, or analyzer placement changes*

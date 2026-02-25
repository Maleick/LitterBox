# Architecture

**Analysis Date:** 2026-02-25

## Pattern Overview

**Overall:** Monolithic Flask service for malware/payload analysis with adapter-based analyzer orchestration.

**Key Characteristics:**
- Single process web app serving both HTML pages and JSON APIs.
- Analyzer abstraction over multiple external scanner executables.
- Filesystem-centric persistence model (uploads/results/DB artifacts).
- Optional adjunct MCP and Python client layers in `GrumpyCats/`.

## Layers

**Entry/Application Layer:**
- Purpose: initialize config, logging, Flask app, and host binding.
- Contains: `litterbox.py`, `app/__init__.py`.
- Depends on: YAML config and route registration.
- Used by: local operator or container startup flow.

**Routing/Orchestration Layer:**
- Purpose: handle HTTP endpoints, input validation, route-level control flow.
- Contains: `app/routes.py` (`register_routes`, `RouteHelpers`, route handlers).
- Depends on: `Utils`, `AnalysisManager`, specialized analyzers.
- Used by: browser UI, API clients, MCP tool calls.

**Utility/Domain Services Layer:**
- Purpose: file handling, risk calculation, hashing, report generation, type detection.
- Contains: `app/utils.py`.
- Depends on: stdlib + analysis libraries (`psutil`, `pefile`, `oletools`).
- Used by: routes and analyzers.

**Analyzer Adapter Layer:**
- Purpose: normalize scanner execution and result shape.
- Contains: `app/analyzers/manager.py`, `app/analyzers/*`, `app/analyzers/static/*`, `app/analyzers/dynamic/*`.
- Depends on: command templates and enabled flags in `Config/config.yaml`.
- Used by: route analysis workflows and doppelganger modules.

**Presentation Layer:**
- Purpose: render result pages and reports.
- Contains: `app/templates/*.html`, `app/static/*`.
- Depends on: route-provided context and generated JSON result files.
- Used by: operator browser workflows.

## Data Flow

**File Analysis Flow (static/dynamic):**
1. Client uploads file to `/upload`.
2. `Utils.save_uploaded_file` stores sample and metadata.
3. `/analyze/<type>/<hash>` locates uploaded sample by hash.
4. `AnalysisManager` dispatches enabled analyzer adapters.
5. Adapters run scanner tools via subprocess and parse output.
6. JSON results are saved into `Results/<hash>/...`.
7. `/results/*` and `/api/results/*` render/read persisted artifacts.

**PID Dynamic Analysis Flow:**
1. Client validates PID via `/validate/<pid>`.
2. `/analyze/dynamic/<pid>` starts PID-focused dynamic checks.
3. Results saved under `Results/dynamic_<pid>/dynamic_analysis_results.json`.
4. UI/API endpoints consume PID result folder similarly.

**BYOVD Driver Flow:**
1. Driver upload to `/holygrail` (POST).
2. GET `/holygrail?hash=<md5>` triggers `HolyGrailAnalyzer`.
3. Findings saved as `byovd_results.json` in the result folder.
4. BYOVD views/API endpoints present results.

**State Management:**
- Request handling is mostly stateless.
- Durable state is represented by files/folders on disk.
- No transactional datastore or queueing layer.

## Key Abstractions

**AnalysisManager:**
- Purpose: lifecycle and dispatch for static/dynamic analyzer sets.
- Examples: `run_static_analysis`, `run_dynamic_analysis` in `app/analyzers/manager.py`.
- Pattern: strategy map (`STATIC_ANALYZERS`/`DYNAMIC_ANALYZERS`) with shared base interface.

**Analyzer Base Classes:**
- Purpose: common analyzer contract and result retrieval.
- Examples: `app/analyzers/base.py`, `app/analyzers/static/base.py`, `app/analyzers/dynamic/base.py`.
- Pattern: abstract base class + specialized wrappers per scanner.

**RouteHelpers:**
- Purpose: deduplicate route-level data loading, risk annotation, cleanup behavior.
- Examples: methods in `app/routes.py` (`load_analysis_data`, `save_analysis_results`, `process_file_cleanup`).
- Pattern: helper/service object used across handlers.

## Entry Points

**CLI/App Startup:**
- Location: `litterbox.py`.
- Triggers: direct script execution.
- Responsibilities: admin check, arg parsing, app bootstrap, host/port launch.

**App Factory:**
- Location: `app/__init__.py#create_app`.
- Triggers: called by startup path.
- Responsibilities: config load, directory creation, route registration.

**HTTP Surface:**
- Location: `app/routes.py`.
- Triggers: browser/API requests.
- Responsibilities: upload, analyze, retrieve, report, cleanup, health.

## Error Handling

**Strategy:** Route-level decorator catches unhandled exceptions and returns JSON errors; analyzer wrappers return structured status dicts.

**Patterns:**
- `@error_handler` in `app/routes.py` logs traceback and returns 500 JSON payload.
- Route branches return 4xx for validation/not-found conditions.
- Analyzer failures are captured in per-tool result objects (`status`, `error`, `stderr`).

## Cross-Cutting Concerns

**Logging:**
- Flask logger and debug statements across routes/analyzers.
- Optional colored formatting in debug mode (`app/__init__.py`).

**Validation:**
- Allowed file extension checks and PID checks before analysis.
- Basic command-argument sanitization in `_extract_and_validate_args`.

**Security/Isolation:**
- Assumes sandboxed environment due malware-focused workflows.
- No built-in auth boundary on HTTP routes; access control is environmental.

---

*Architecture analysis: 2026-02-25*
*Update when architectural boundaries or execution flow change*

# Conventions

**Analysis Date:** 2026-02-25

## Naming Patterns

- Python functions and modules use snake_case (`register_routes`, `save_uploaded_file`, `yara_analyzer.py`).
- Classes use PascalCase (`RouteHelpers`, `FuzzyHashAnalyzer`, `HolyGrailAnalyzer`).
- Route paths are lowercase and action-oriented (`/upload`, `/analyze/...`, `/cleanup`, `/health`).
- Result file names are standardized JSON labels consumed by both UI and API routes.

## Code Style

- Style is pragmatic Python with moderate use of type hints (stronger in analyzers and client code than in route code).
- Large procedural route module in `app/routes.py` combines nested helper functions and endpoint handlers.
- Debug logging strings are explicit and verbose, often prefixed with operation context.
- Docstrings exist on many helper methods, but coverage is inconsistent.

## Import Organization

- Stdlib imports are generally grouped first, then third-party, then local imports.
- Some modules mix import ordering and include duplicate or broad imports due growth over time.
- Analyzer modules tend to keep tighter import scope than `app/routes.py` and `app/utils.py`.

## Error Handling

- Route handlers rely on `@error_handler` for broad exception wrapping and JSON 500 responses.
- Input and state errors are handled with explicit 4xx responses in-route (missing file, bad PID, invalid type).
- Analyzer wrappers capture subprocess/runtime exceptions and return status dictionaries.
- Error model is convention-based (`status` + `error`) rather than strongly typed exceptions across boundaries.

## Logging

- Central app logger is used across layers (`app.logger` and module loggers).
- Debug mode can enable colored output via `setup_logging` in `app/__init__.py`.
- Analyzer executions log tool startup, completion, parse failures, and timeouts.
- Current logging favors diagnosability over structured machine-ingest formats.

## Comments

- Comments emphasize operational context and scanner-specific rationale.
- Several files include maintenance notes and inline caveats (for example timeout behavior, output handling).
- There is limited use of high-level module docs describing architectural intent.

## Function Design

- Functions in analyzer modules are generally focused and tool-specific.
- Route-level helpers are relatively cohesive, but `register_routes` hosts many responsibilities in one file.
- Reused behaviors are centralized in `RouteHelpers` and `Utils`, reducing duplication in endpoint bodies.

## Module Design

- `app/analyzers/` follows an adapter-per-tool structure plus a coordinating manager.
- `app/routes.py` acts as both routing module and orchestration/service layer.
- `app/utils.py` is a broad utility module containing file IO, type detection, scoring, and report logic.
- `GrumpyCats/` keeps client and MCP interfaces separate from core Flask runtime modules.

---

*Conventions analysis: 2026-02-25*
*Update when style guides or analyzer integration patterns are formalized*

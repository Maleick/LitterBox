# Concerns

**Analysis Date:** 2026-02-25

## Tech Debt

- `app/routes.py` is very large (single-file orchestration for many unrelated concerns), increasing change risk and review cost.
- `app/utils.py` mixes multiple domains (file detection, PE parsing, risk scoring, reporting, helpers), limiting maintainability.
- Analyzer interfaces are partially duplicated (`BaseAnalyzer` definition appears in multiple places/patterns).
- Some modules in `app/analyzers/` show signs of accumulated patching rather than cohesive refactors.

## Known Bugs

- Config path case mismatch risk: app factory loads `config/config.yaml` in `app/__init__.py`, but tracked directory is `Config/`.
  - Works on case-insensitive filesystems, fails on strict case-sensitive hosts.
- `app/analyzers/holygrail.py` contains duplicated/merged blocks and unreachable-looking segments, suggesting accidental code merge artifacts.
- Several runtime paths use relative assumptions (scanner/result folders) that can break when launched from unexpected working directories.

## Security Considerations

- No authentication or authorization on analysis, cleanup, delete, and report endpoints in `app/routes.py`.
- Dynamic analysis and multiple scanners use subprocess invocation with command templates; unsafe config/argument paths can raise command-injection risk.
- Service is designed for malware handling, but security hardening depends mostly on external sandbox/network isolation controls.
- Docker compose file includes default credentials (`USERNAME/PASSWORD`) suitable only for isolated environments.

## Performance Bottlenecks

- Dynamic analyzer runs are mostly sequential and often invoke heavy external binaries.
- Repeated filesystem scans and JSON loading in summary/report endpoints can become expensive as `Results/` grows.
- Some routes parse large payload structures in-process without caching or pagination.
- Report generation renders full analysis data synchronously on request.

## Fragile Areas

- Route-to-template coupling: many view routes assume exact JSON shapes from analyzer parsers.
- Scanner output parsing logic is format-sensitive; upstream tool output changes can silently break parsing.
- Cleanup paths perform recursive deletes across multiple directories; mistakes can remove needed forensic artifacts.
- Process-based analysis branches depend on local OS/process permissions and timing behavior.

## Scaling Limits

- Current architecture is single Flask process with filesystem state and no distributed coordination.
- No queue/job system for long-running analyses; request lifecycle can block on heavy scanner execution.
- No multi-tenant or quota boundaries; storage growth in `Uploads/` and `Results/` must be managed operationally.

## Dependencies at Risk

- Third-party scanner binaries under `Scanners/` are external operational dependencies not version-locked via package manager.
- Python dependency pins in `requirements.txt` are fixed, but no automated update/test pipeline validates upgrades.
- MCP integration depends on separate package/runtime availability (`mcp.server.fastmcp`) that is not represented in requirements.

## Missing Critical Features

- Endpoint authentication, authorization, and audit trail controls for sensitive operations.
- Formal asynchronous job handling for long-running analyzer execution.
- Structured config/schema validation with startup-time fail-fast checks.
- Guardrails for unsafe command template usage and stronger argument sanitization.

## Test Coverage Gaps

- No automated tests for:
  - route contracts and status code behavior,
  - analyzer parser correctness against fixture outputs,
  - risk scoring logic and report generation.
- No regression suite for large branch surface in `app/routes.py` and `app/utils.py`.
- No CI safety net to catch breakage from dependency or scanner output format changes.

---

*Concerns analysis: 2026-02-25*
*Update after major refactors, hardening, or testing improvements*

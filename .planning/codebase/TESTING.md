# Testing

**Analysis Date:** 2026-02-25

## Test Framework

- No dedicated automated test framework is configured in repository root.
- No `pytest.ini`, `tox.ini`, `pyproject.toml`, or `tests/` package detected.
- Current validation is primarily manual runtime testing through API/UI flows.

## Test File Organization

- There are no committed unit/integration test directories at this time.
- Behavioral validation is implied through:
  - endpoint exercise in `app/routes.py`,
  - analyzer execution against sample payloads,
  - manual result review in templates and JSON outputs.

## Test Structure

- Existing verification pattern is scenario-driven and environment-dependent:
  1. upload a sample or select PID,
  2. run static/dynamic/BYOVD analysis,
  3. inspect generated JSON and rendered pages.
- Route code currently lacks isolated seam tests for helper logic and branch coverage.

## Mocking

- No mocking infrastructure is present.
- Scanner subprocess calls are not abstracted behind mockable interfaces for automated tests.
- External tool behavior is currently validated by running real binaries in sandbox environment.

## Fixtures and Factories

- No fixture library or deterministic sample corpus is defined in repo.
- Test data generation is ad hoc (manual upload of payloads/drivers/process IDs).
- Runtime folders (`Uploads/`, `Results/`) are effectively transient fixture stores.

## Coverage

- No coverage tooling/configuration (`coverage.py`, CI coverage gates) is tracked.
- Practical coverage is unknown and likely low for edge/error branches in large route handlers.

## Test Types

- Effective current test types:
  - manual end-to-end API checks,
  - manual UI route validation,
  - operational checks via `/health`,
  - analyzer smoke tests with real tools.
- Missing formalized types:
  - unit tests for utility and parser functions,
  - integration tests with mocked analyzer adapters,
  - regression suite for route contract stability.

## Common Patterns

- Current operator workflow is "run and inspect artifacts" rather than assertive automation.
- Error handling paths are validated opportunistically during manual use.
- Analyzer reliability depends on local environment and tool availability, increasing test nondeterminism.
- Recommended baseline pattern for future automation:
  - isolate `RouteHelpers` and `Utils` pure logic for unit tests first,
  - mock `AnalysisManager` in route tests,
  - add a minimal golden-sample integration suite for JSON result contracts.

---

*Testing analysis: 2026-02-25*
*Update after introducing automated test suites or CI gates*

# Stack Research

**Domain:** Malware analysis sandbox platform (security testing and payload triage)
**Researched:** 2026-02-25
**Confidence:** MEDIUM

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Python | 3.11+ | Primary application/runtime language | Existing codebase, broad ecosystem for parsing/security tooling, strong subprocess/file handling |
| Flask | 3.1.x | API + HTML UI surface | Already in production path, low migration risk for brownfield hardening |
| Scanner Adapter Layer (internal) | Current | Unified execution of YARA/PE-Sieve/Moneta/HolyGrail/etc. | Keeps external tool integration swappable and supports per-tool failure isolation |
| Job Queue Backend (Redis + RQ/Celery candidate) | Current stable | Asynchronous long-running analysis orchestration | Avoids request blocking and improves reliability for heavy scans |
| Structured Storage Split (filesystem + metadata store) | Current + incremental | Retain large artifacts on disk, track jobs/events in DB | Preserves existing artifact model while enabling queryable operational state |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Pydantic | 2.x | Strong config/request/result schema validation | Add during API contract hardening and config safety work |
| SQLAlchemy | 2.x | Metadata/audit persistence for jobs and actions | Use when introducing durable job states and audit trail |
| Redis client (`redis`/`rq`) | Current stable | Queueing and worker communication | Use once asynchronous execution replaces in-request long scans |
| structlog / standard JSON logging stack | Current stable | Structured observability | Use when implementing request-id/job-id logging contracts |
| pytest | 8.x | Automated tests for API + utility layers | Use when introducing CI-backed regression protection |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| Docker Compose | Repeatable sandbox host setup | Keep `Docker/docker-compose.yml` as reproducible entry for isolated environments |
| Ruff + mypy (recommended) | Linting and type hygiene | Add gradually for brownfield refactors to reduce churn |
| GitHub Actions (recommended) | CI gate for tests/checks | Introduce once minimum test baseline exists |

## Installation

```bash
# Core runtime
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Recommended quality/runtime additions for vNext
pip install pytest ruff mypy pydantic sqlalchemy redis rq
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Flask monolith + incremental modularization | Full rewrite to FastAPI/microservices | Only if compatibility constraints are removed and dedicated migration budget exists |
| Redis-backed queue workers | In-process background threads | Acceptable only for small labs with low concurrency and short-running jobs |
| Filesystem artifact storage + metadata DB | All-in database blob storage | Use only if strict centralized retention/governance requirements outweigh IO cost |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| Blocking long scans inside request lifecycle | Timeouts, worker starvation, poor UX | Async job queue with status polling |
| Ad hoc endpoint-specific schema drift | Client breakage and hard-to-debug regressions | Versioned response envelopes and schema validation |
| Unsafe shell string interpolation for tool commands | Command injection and execution risk | Explicit argument arrays + validated command builders |

## Stack Patterns by Variant

**If running isolated single-operator lab mode:**
- Keep Flask monolith + local filesystem artifacts
- Add minimal queue worker and structured logs for reliability

**If running shared team sandbox mode:**
- Add authn/authz + audit store + retention policies early
- Separate API process and worker process for predictable scan throughput

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| Flask 3.1.x | Werkzeug 3.1.x | Matches current requirements pins |
| Python 3.11+ | `pefile`, `oletools`, `pyssdeep` | Validate scanner wrapper behavior across host OS variants |
| Redis queue clients | Flask app factory pattern | Prefer app-context-safe worker bootstrap |

## Sources

- `/opt/LitterBox/README.md` — product scope and existing endpoint surface
- `/opt/LitterBox/requirements.txt` — current dependency baseline
- `/opt/LitterBox/.planning/codebase/STACK.md` — codebase stack map
- `/opt/LitterBox/.planning/codebase/ARCHITECTURE.md` — runtime architecture context
- `/opt/LitterBox/Config/config.yaml` — scanner runtime/config contracts

---
*Stack research for: malware analysis sandbox platform*
*Researched: 2026-02-25*

# Project Research Summary

**Project:** LitterBox vNext
**Domain:** Malware analysis sandbox platform modernization
**Researched:** 2026-02-25
**Confidence:** HIGH

## Executive Summary

LitterBox already delivers broad malware-analysis functionality (upload, static analysis, dynamic analysis, BYOVD, doppelganger workflows, reporting, and client/MCP integrations). The research outcome for this cycle is not a greenfield feature chase; it is a brownfield hardening and reliability program that preserves operator-facing behavior while reducing operational and security risk.

The recommended approach is an incremental architecture evolution: enforce access controls first, move long-running scan work to explicit job orchestration, stabilize API contracts, then modularize oversized code paths and add regression coverage. This ordering keeps existing workflows usable while creating a safer and more maintainable base.

Top risks are unauthorized route exposure, request-lifecycle collapse for heavy analysis, and compatibility regressions during refactor. These are mitigated by early auth/authz controls, queue-backed job states, and contract-first testing before structural decomposition.

## Key Findings

### Recommended Stack

Research points to a conservative stack evolution: keep Python + Flask + scanner adapters, then add queue/state and schema discipline rather than rewriting frameworks.

**Core technologies:**
- Python 3.11+ and Flask 3.1.x: preserve existing runtime and minimize migration risk.
- Queue-backed orchestration (Redis + RQ/Celery candidate): stabilize long-running analysis execution.
- Schema/contract validation (Pydantic + versioned envelopes): protect API/MCP/client compatibility.
- Filesystem artifacts + metadata store split: maintain current artifact model while enabling operational introspection.

### Expected Features

**Must have (table stakes):**
- Isolated sample upload + metadata extraction and safe artifact handling.
- Stable static/dynamic/BYOVD workflows with retrievable JSON and report outputs.
- Health, cleanup, and operational controls with clear status/error behavior.

**Should have (competitive):**
- Strong BYOVD and doppelganger workflows maintained as first-class differentiators.
- MCP-friendly API contracts and predictable orchestration state for analyst automation.

**Defer (v2+):**
- Multi-tenant or distributed orchestration beyond current isolated deployment model.

### Architecture Approach

Use a layered brownfield refactor: API/control plane, analysis orchestration services, scanner adapters, and artifact/metadata persistence boundaries. Keep scanner integration adapters in place, but move orchestration and policy logic out of monolithic route modules.

**Major components:**
1. Access/control plane — authn/authz, routing, compatibility-safe responses.
2. Analysis orchestration plane — queued jobs, status transitions, per-tool isolation.
3. Tool/data plane — scanner wrappers, artifact storage, metadata/audit records.

### Critical Pitfalls

1. **Unsafe execution boundary** — enforce auth/authz before further expansion.
2. **Long-running request collapse** — shift heavy analysis to queued job lifecycle.
3. **API contract drift** — add compatibility tests and versioned response envelopes.
4. **Monolithic route entropy** — split by domain with behavioral regression tests.
5. **Artifact sprawl and unsafe cleanup** — retention policy + dry-run safety controls.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: Secure Access and Safety Guardrails
**Rationale:** Reduces highest-risk exposure before internal changes.
**Delivers:** Auth/authz boundaries, access-aware auditing, safer command invocation.
**Addresses:** Security and cleanup-risk features.
**Avoids:** Unauthorized operation and command misuse pitfalls.

### Phase 2: Analysis Job Orchestration and API Compatibility
**Rationale:** Stabilizes core runtime behavior while protecting existing clients.
**Delivers:** Queue-driven job state model, compatible response contracts.
**Uses:** Existing analyzer adapters plus lifecycle metadata.
**Implements:** Orchestration/service boundary for long-running workloads.

### Phase 3: Modularization and Test Baseline
**Rationale:** Structural refactor is safer after contract and lifecycle stabilization.
**Delivers:** Route/service decomposition, utility/parser regression tests, CI baseline.

### Phase 4: Observability and Retention Hardening
**Rationale:** Finalize operational confidence once behavior and structure stabilize.
**Delivers:** Enhanced health/readiness, structured logs, enforceable retention policies.

### Phase Ordering Rationale

- Security and safety controls come first because they gate all other work safely.
- Async orchestration precedes modular refactor to lock expected behavior under load.
- Refactor follows compatibility safeguards to minimize regression risk.
- Observability/retention close the loop for sustained operations.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 2:** queue technology choice and migration strategy for existing synchronous analysis paths.
- **Phase 4:** retention policy defaults and archival boundaries for different operator contexts.

Phases with standard patterns (skip research-phase):
- **Phase 1:** endpoint auth/authz guardrails and audit logging conventions.
- **Phase 3:** modular route/service refactor with regression test harness.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Internal evidence is strong; queue/state specifics need implementation-level validation |
| Features | HIGH | Existing codebase and docs clearly establish table stakes and differentiators |
| Architecture | HIGH | Monolith boundaries and refactor path are directly observable in current code |
| Pitfalls | HIGH | Risks are corroborated by codebase concerns and operational patterns |

**Overall confidence:** HIGH

### Gaps to Address

- Queue backend and worker topology final choice (`RQ` vs `Celery`) during phase planning.
- Auth mechanism selection (session-based internal auth vs token-based) based on deployment environment.
- Migration plan for compatibility-safe response versioning.

## Sources

### Primary (HIGH confidence)
- `/opt/LitterBox/.planning/codebase/*.md` — architecture/stack/concerns baseline
- `/opt/LitterBox/README.md` — capability and endpoint surface
- `/opt/LitterBox/Config/config.yaml` — scanner/runtime contracts

### Secondary (MEDIUM confidence)
- `/opt/LitterBox/requirements.txt` — dependency baseline for stack evolution decisions

### Tertiary (LOW confidence)
- Domain best-practice inference from existing architecture patterns (validate during phase planning)

---
*Research completed: 2026-02-25*
*Ready for roadmap: yes*

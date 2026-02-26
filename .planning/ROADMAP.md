# Roadmap: LitterBox vNext

## Overview

This roadmap evolves LitterBox from a capable brownfield sandbox into a safer, more reliable, and more maintainable platform without breaking current operator workflows. The sequence prioritizes risk reduction first (access/safety), then runtime reliability (job lifecycle + compatibility), then structural maintainability (modularization + tests), and finally operational hardening (observability + retention).

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, 4): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Secure Access and Safety Guardrails** - Protect high-risk operations and establish safe execution boundaries
- [ ] **Phase 2: Analysis Job Orchestration and API Compatibility** - Stabilize long-running analysis workflows without breaking clients
- [ ] **Phase 2.1 [INSERTED]: Remote Windows Execution Over Tailscale** - Execute scanners remotely over SSH without adding custom agent services
- [ ] **Phase 2.2 [INSERTED]: WinRM Runtime Path and Domain Target Migration** - Add credential-backed WinRM transport with explicit domain controller target routing
- [ ] **Phase 3: Modularization and Regression Test Baseline** - Decompose high-risk modules and add automated coverage
- [ ] **Phase 4: Observability and Retention Hardening** - Strengthen operational visibility and lifecycle controls

## Phase Details

### Phase 1: Secure Access and Safety Guardrails
**Goal**: Enforce authenticated/authorized control and safer command/cleanup execution boundaries.
**Depends on**: Nothing (first phase)
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, OPS-03
**Success Criteria** (what must be TRUE):
  1. Unauthorized requests cannot trigger upload/analyze/cleanup/delete operations.
  2. Authorized actions produce audit records with actor, target, and outcome.
  3. Scanner command invocation paths enforce centralized argument safety checks.
  4. Cleanup supports dry-run preview and bounded-deletion confirmation behavior.
**Plans**: 3 plans

Plans:
- [ ] 01-01: Implement authentication and authorization enforcement across high-impact endpoints
- [ ] 01-02: Add audit trail and action logging for sensitive operations
- [ ] 01-03: Centralize safe command/cleanup guards and dry-run flow

### Phase 2: Analysis Job Orchestration and API Compatibility
**Goal**: Move long-running analysis to explicit job lifecycle while preserving client/API compatibility.
**Depends on**: Phase 1
**Requirements**: API-01, API-02, API-03, ANL-01, ANL-02, ANL-03, ANL-04
**Success Criteria** (what must be TRUE):
  1. Analysis requests return durable job identifiers for asynchronous tracking.
  2. Job status endpoints expose pending/running/completed/failed/timeout states.
  3. Per-analyzer failures are visible without dropping successful analyzer outputs.
  4. Existing client workflows continue functioning against compatibility-safe endpoints.
**Plans**: 3 plans

Plans:
- [ ] 02-01: Introduce job model, queue worker lifecycle, and state persistence
- [ ] 02-02: Add async analysis and status retrieval endpoints with stable transitions
- [ ] 02-03: Enforce response envelope/version compatibility and client regression checks

### Phase 2.1 [INSERTED]: Remote Windows Execution Over Tailscale
**Goal**: Support Linux-hosted LitterBox with SSH-based scanner execution on remote Windows targets over Tailscale.
**Depends on**: Phase 2
**Requirements**: REM-01, REM-02, REM-03, REM-04, REM-05
**Success Criteria** (what must be TRUE):
  1. Analysis routes can select remote target by default or per-request `execution_target` override.
  2. Uploaded samples are staged to remote Windows workdir, analyzed, and remote artifacts are retrieved to local `Results/`.
  3. Remote execution failures honor configurable local fallback policy without breaking response compatibility.
  4. Health endpoint reports remote target preflight status (tailscale, SSH auth, scanner path checks).
**Plans**: 4 plans

Plans:
- [ ] 02-04: Add execution runner abstraction with local and SSH remote implementations
- [ ] 02-05: Implement remote target routing, staging/retrieval workflow, and fallback policy
- [ ] 02-06: Extend `/analyze/*` and `/holygrail` with optional `execution_target` override
- [ ] 02-07: Add remote setup runbook and health diagnostics for operational readiness

### Phase 2.2 [INSERTED]: WinRM Runtime Path and Domain Target Migration
**Goal**: Add WinRM transport support and migrate domain-controller execution to an explicit `domain` target while preserving SSH compatibility.
**Depends on**: Phase 2.1
**Requirements**: WRM-01, WRM-02, WRM-03, WRM-04, WRM-05
**Success Criteria** (what must be TRUE):
  1. Config supports default remote transport semantics and dedicated `domain` target definition.
  2. Execution routing selects SSH or WinRM per target without breaking existing SSH target behavior.
  3. Runtime consumes `.env.remote` credentials safely for domain and local account modes.
  4. Health endpoint reports WinRM preflight status (reachability, auth, scanner path checks).
  5. Temporary `server2025` domain-host mapping is migrated to `domain` target with documented compatibility behavior.
**Plans**: 4 plans

Plans:
- [ ] 02-08: Extend remote config schema (`transport`, WinRM target fields) and add dedicated `domain` target
- [ ] 02-09: Implement `WinRmRemoteRunner` and transport-aware runner selection
- [ ] 02-10: Add runtime credential loading from `.env.remote` with account-mode normalization (`DOMAIN\\user` and local forms)
- [ ] 02-11: Expand `/health` with WinRM diagnostics and publish migration/troubleshooting runbook

### Phase 3: Modularization and Regression Test Baseline
**Goal**: Reduce maintenance risk by splitting monolithic modules and establishing automated tests.
**Depends on**: Phase 2.2
**Requirements**: QLT-01, QLT-02, QLT-03, QLT-04
**Success Criteria** (what must be TRUE):
  1. Route/orchestration logic is split into maintainable modules without behavior regressions.
  2. Unit tests cover key utility/parser behavior used in analysis flows.
  3. Integration tests cover critical route contracts and major error paths.
  4. CI-quality command is documented and blocks regressions before merge.
**Plans**: 3 plans

Plans:
- [ ] 03-01: Refactor route/service boundaries and preserve endpoint behavior
- [ ] 03-02: Add utility/parser unit tests for core analysis logic
- [ ] 03-03: Add integration tests plus CI-ready verification command

### Phase 4: Observability and Retention Hardening
**Goal**: Improve operational diagnostics and enforce artifact lifecycle controls.
**Depends on**: Phase 3
**Requirements**: OPS-01, OPS-02, OPS-04
**Success Criteria** (what must be TRUE):
  1. Health endpoint reports actionable readiness for analyzer/tooling dependencies.
  2. Structured logs include correlation identifiers for request and analysis job tracing.
  3. Retention policies for uploads/results are configurable and enforceable.
**Plans**: 2 plans

Plans:
- [ ] 04-01: Implement enhanced health/readiness and structured logging contracts
- [ ] 04-02: Implement retention policy engine and operational controls

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 2.1 → 2.2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Secure Access and Safety Guardrails | 0/3 | Not started | - |
| 2. Analysis Job Orchestration and API Compatibility | 0/3 | Not started | - |
| 2.1 [INSERTED] Remote Windows Execution Over Tailscale | 0/4 | Not started | - |
| 2.2 [INSERTED] WinRM Runtime Path and Domain Target Migration | 0/4 | Not started | - |
| 3. Modularization and Regression Test Baseline | 0/3 | Not started | - |
| 4. Observability and Retention Hardening | 0/2 | Not started | - |

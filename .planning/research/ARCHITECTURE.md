# Architecture Research

**Domain:** Malware analysis sandbox platform
**Researched:** 2026-02-25
**Confidence:** HIGH

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Access / Control Plane                    │
├─────────────────────────────────────────────────────────────┤
│  API/UI Ingress  AuthZ Guard  Request Router  Report Views  │
├─────────────────────────────────────────────────────────────┤
│                    Analysis Orchestration                    │
├─────────────────────────────────────────────────────────────┤
│  Job Queue  Worker Runtime  Analyzer Adapter  Result Normal │
├─────────────────────────────────────────────────────────────┤
│                    Tooling & Data Plane                      │
│  Scanner Binaries  Artifact Store  Metadata Store  Logs      │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|------------------------|
| API/UI ingress | Accept requests, enforce auth, route actions | Flask routes/blueprints with request validation |
| Analysis orchestrator | Schedule work, track status, isolate failures | Queue-backed job manager + worker pool |
| Analyzer adapters | Invoke external scanners safely | Wrapper classes with strict command builders |
| Result normalizer | Stabilize output schemas | Shared serializer + versioned envelopes |
| Artifact/metadata layer | Persist files, results, and audit records | Filesystem artifacts + relational metadata DB |

## Recommended Project Structure

```
app/
├── api/                 # Route blueprints by domain (upload, analyze, results, ops)
│   ├── upload.py
│   ├── analyze.py
│   ├── results.py
│   └── operations.py
├── services/            # Orchestration, job state, retention, audit
│   ├── analysis_service.py
│   ├── job_service.py
│   ├── retention_service.py
│   └── auth_service.py
├── analyzers/           # Scanner adapters (existing split preserved)
│   ├── static/
│   ├── dynamic/
│   └── manager.py
├── schemas/             # Request/response/result contracts
├── utils/               # Focused utility modules (hashing, parsing, risk, report)
└── app_factory.py       # create_app and wiring
```

### Structure Rationale

- **`api/` boundaries:** shrink oversized route file and isolate endpoint concerns.
- **`services/` boundaries:** keep orchestration and policy logic testable outside HTTP handlers.
- **`schemas/` contracts:** protect compatibility across UI/API/MCP clients.

## Architectural Patterns

### Pattern 1: Analyzer Adapter Pattern

**What:** Each scanner has a dedicated wrapper with a shared interface.
**When to use:** Any external tool integration with independent failure modes.
**Trade-offs:** More wrapper code, but clear boundaries and safer error handling.

### Pattern 2: Queue-Driven Long Job Pattern

**What:** Convert long scans into queued jobs with explicit status tracking.
**When to use:** Dynamic analysis and heavyweight scanner pipelines.
**Trade-offs:** Adds queue infrastructure, but eliminates request timeouts and improves observability.

### Pattern 3: Contract-First API Response Pattern

**What:** Normalize every response into stable envelopes with version markers.
**When to use:** Brownfield APIs with multiple dependent clients.
**Trade-offs:** Some migration overhead, but strong backward compatibility guarantees.

## Data Flow

### Request Flow

```
[Operator/API Client]
    ↓
[Auth + Route Validation]
    ↓
[Job Submission / Immediate Action]
    ↓
[Analyzer Worker(s)]
    ↓
[Result Normalization + Persistence]
    ↓
[Status/Result Retrieval + Report Rendering]
```

### State Management

```
[Job/Action Metadata Store]
    ↓
[API Status Endpoints] ←→ [Worker Updates]
    ↓
[UI/MCP/Python Client Polling]
```

### Key Data Flows

1. **Sample analysis flow:** upload → queue/execute → scanner adapters → persisted artifacts → API/UI consumption.
2. **PID dynamic flow:** validate pid → queue dynamic run → tool outputs + metadata → dynamic results endpoint/report.
3. **Operational safety flow:** cleanup request → policy checks/dry-run → bounded deletion → audit entry.

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 0-10 operators | Single API process + 1 worker + filesystem artifacts |
| 10-50 operators | Separate API and worker pools, add metadata DB indexing |
| 50+ operators | Split queues by analysis type and isolate heavy scanners |

### Scaling Priorities

1. **First bottleneck:** long-running dynamic scans blocking throughput — resolve with queue workers and per-job lifecycle.
2. **Second bottleneck:** artifact and metadata lookup latency — resolve with indexed metadata store and retention policy.

## Anti-Patterns

### Anti-Pattern 1: Monolithic Route Explosion

**What people do:** Keep adding workflow logic to one route module.
**Why it's wrong:** Regression risk and review complexity grow superlinearly.
**Do this instead:** Extract blueprint + service boundaries per domain.

### Anti-Pattern 2: Opaque Scanner Failures

**What people do:** Return generic analysis failure without per-tool context.
**Why it's wrong:** Operators cannot triage broken scanners quickly.
**Do this instead:** Preserve per-analyzer status and error envelopes.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| Scanner executables | Local process execution via adapter wrappers | Enforce argument safety + timeout controls |
| MCP consumers | HTTP API wrapped by `GrumpyCats/LitterBoxMCP.py` | API compatibility is critical |
| Docker sandbox runtime | Compose-managed host/guest orchestration | Keep hardening aligned with isolation assumptions |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| API routes ↔ services | direct function calls (app context) | Keep IO and policy logic out of route handlers |
| Services ↔ analyzer adapters | typed method contracts | normalize result envelopes centrally |
| Services ↔ stores | repository/service layer | isolate storage mechanism changes |

## Sources

- `/opt/LitterBox/.planning/codebase/ARCHITECTURE.md`
- `/opt/LitterBox/.planning/codebase/STRUCTURE.md`
- `/opt/LitterBox/.planning/codebase/CONCERNS.md`
- `/opt/LitterBox/README.md`

---
*Architecture research for: malware analysis sandbox platform*
*Researched: 2026-02-25*

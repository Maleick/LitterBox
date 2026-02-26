# LitterBox vNext

## What This Is

LitterBox is a controlled malware-analysis sandbox for security teams to upload payloads and drivers, run static and dynamic scanners, and review results through API, HTML reports, and MCP tooling. The existing platform already provides broad analysis coverage across PE files, Office documents, process telemetry, and BYOVD workflows. This project initializes the next iteration of LitterBox focused on hardening, reliability, and maintainable evolution without breaking the current operator workflow.

## Core Value

Security teams can safely and quickly assess suspicious payload behavior in an isolated environment and get actionable static, dynamic, and BYOVD intelligence.

## Requirements

### Validated

- ✓ Upload files and compute malware-relevant metadata (hashes, entropy, type details) — existing
- ✓ Run static analysis pipelines (YARA, CheckPlz, Stringnalyzer) through API and UI — existing
- ✓ Run dynamic analysis for both file targets and live PIDs with multiple scanners — existing
- ✓ Execute HolyGrail BYOVD analysis for kernel drivers and persist byovd results — existing
- ✓ Run Doppelganger workflows (Blender and FuzzyHash) for behavioral/similarity comparison — existing
- ✓ Retrieve JSON results and downloadable HTML reports for completed analyses — existing
- ✓ Access the platform through MCP and Python client integrations in `GrumpyCats/` — existing

### Active

- [ ] Add authenticated/authorized access controls for sensitive API operations
- [ ] Preserve backward-compatible API behavior for existing clients while improving contract clarity
- [ ] Introduce resilient job-state handling for long-running analysis workflows
- [ ] Refactor oversized routing/orchestration modules into maintainable boundaries
- [ ] Add automated test coverage for critical route contracts and parser/utility logic
- [ ] Strengthen observability, cleanup safety, and retention controls for operational reliability

### Out of Scope

- Full microservice rewrite in this cycle — would delay core hardening and stabilization goals
- Multi-tenant SaaS control-plane architecture — not required for current isolated lab deployment model
- Replacing existing scanner engines wholesale — objective is safe integration and reliability improvements first

## Context

The repository is a brownfield Python/Flask codebase with runtime scanner execution through subprocess wrappers and filesystem-backed artifact persistence. Current architecture centralizes much behavior in `app/routes.py` and `app/utils.py`, which accelerates iteration but increases change risk. The platform targets red and blue team analysis workflows, including local sandbox operations and MCP-assisted usage. Existing `.planning/codebase/` maps were generated immediately before initialization and are treated as source-of-truth for current capabilities and concerns.

## Constraints

- **Compatibility**: Keep existing endpoint behavior stable for current UI, API, and `GrumpyCats` clients — avoid breaking established workflows
- **Security**: Do not expose analysis actions outside trusted boundaries — hardening must reduce operational risk in malware-handling environments
- **Runtime Coupling**: Scanner execution depends on local tool paths and OS-specific behavior from `Config/config.yaml` — improvements must respect this coupling
- **Incremental Delivery**: Brownfield improvements must ship in small validated phases — large rewrites are deferred
- **Planning Depth**: Auto mode selected with quick depth — produce 3-5 focused phases for near-term execution

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Initialize as brownfield modernization (not greenfield rebuild) | Existing code and mapped capabilities are already substantial and usable | ✓ Good |
| Use recommended auto-mode defaults (`quick`, `balanced`, research/plan-check/verifier enabled) | Keep planning flow fast while retaining quality gates | ✓ Good |
| Infer brief from repository context because `--auto` prompt had no explicit `@idea` document | User explicitly requested auto execution; README + codebase map provide sufficient intent baseline | ⚠️ Revisit |
| Keep API contract compatibility as a first-class requirement | Existing MCP/client integrations depend on stable route behavior | — Pending |
| Use SSH remoting over Tailscale for remote Windows execution (no custom agent daemon) | Reduces deployment complexity and aligns with existing Windows OpenSSH support | ✓ Good |
| Lock next remote phase to WinRM runtime path with explicit `domain` target | Domain-controller host requirements and credentialed execution need a transport model beyond SSH-key-only assumptions | ✓ Good |

---
*Last updated: 2026-02-25 after operational wizard/smoke execution and phase 2.2 lock*

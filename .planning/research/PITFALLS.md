# Pitfalls Research

**Domain:** Malware analysis sandbox platform
**Researched:** 2026-02-25
**Confidence:** HIGH

## Critical Pitfalls

### Pitfall 1: Unsafe Execution Boundary

**What goes wrong:**
Sensitive analysis operations are exposed without strong authentication/authorization.

**Why it happens:**
Teams rely on network isolation assumptions and postpone access controls.

**How to avoid:**
Enforce authn/authz on all mutating and analysis-triggering endpoints before deeper feature expansion.

**Warning signs:**
Anyone on reachable network can trigger `/cleanup`, `/analyze/*`, or delete artifacts.

**Phase to address:**
Phase 1

---

### Pitfall 2: Long-Running Request Collapse

**What goes wrong:**
Dynamic scans run inside request lifecycle, causing timeout/worker starvation under load.

**Why it happens:**
Synchronous implementation is simpler early and grows with added scanners.

**How to avoid:**
Introduce queue-backed job orchestration with explicit lifecycle states and status polling.

**Warning signs:**
Frequent client timeouts, hanging requests, and inconsistent partial result artifacts.

**Phase to address:**
Phase 2

---

### Pitfall 3: API Contract Drift During Refactor

**What goes wrong:**
Client and MCP integrations break after internal restructuring.

**Why it happens:**
Route refactors proceed without explicit compatibility guardrails and schema tests.

**How to avoid:**
Freeze endpoint contracts, add compatibility tests, and version response envelopes.

**Warning signs:**
GrumpyCats workflows fail after internal code reorganization.

**Phase to address:**
Phase 2 and Phase 3

---

### Pitfall 4: Monolithic Module Entropy

**What goes wrong:**
Large route/utility files become too risky to modify; bug rate increases.

**Why it happens:**
Feature pressure favors incremental additions over boundary-setting refactors.

**How to avoid:**
Refactor by domain boundaries with tests before behavior changes.

**Warning signs:**
Small edits require touching many unrelated sections or repeatedly regress existing paths.

**Phase to address:**
Phase 3

---

### Pitfall 5: Artifact Sprawl and Unsafe Cleanup

**What goes wrong:**
Storage grows unbounded or cleanup removes needed artifacts unexpectedly.

**Why it happens:**
No retention policy, weak safety checks, and destructive operations without dry-run.

**How to avoid:**
Add retention controls, bounded deletion rules, and explicit dry-run previews.

**Warning signs:**
Rapid disk growth, accidental data loss, or operators avoiding cleanup endpoint usage.

**Phase to address:**
Phase 4

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Keep all orchestration in one routes file | Fast feature addition | High regression risk and poor testability | Only for short-lived prototypes |
| Return raw scanner output shapes directly | Faster tool integration | Contract instability for clients | Never for shared API contracts |
| Manual ad hoc cleanup scripts | Quick space recovery | Irreproducible operations and accidental deletions | Emergency-only with explicit approval |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Scanner command templates | String-concatenated shell arguments | Strict argument building + allowlist validation |
| MCP wrappers | Assuming endpoint payloads never change | Add compatibility contract tests and versioning |
| Docker sandbox setup | Treating default credentials as acceptable production posture | Rotate credentials and restrict exposure by environment |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Synchronous dynamic scans | Request hangs, retries, user confusion | Queue jobs + status endpoint | Moderate concurrent usage |
| Full directory scans on summary endpoints | Slow UI and API listing | Incremental metadata indexing/caching | Large `Results/` sets |
| Unbounded report rendering payloads | High memory and latency spikes | Paginated/filtered report data paths | Large analysis artifact sets |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| No auth on high-impact routes | Unauthorized analysis/deletion operations | Enforce authn/authz + audit logging |
| Weak command sanitization | Command injection in analyzer invocation | Centralized validated command builder |
| Shared broad credentials in deployment files | Environment compromise amplification | Use environment-specific secrets and least privilege |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Ambiguous job progress | Operators cannot tell if scans are stuck or running | Explicit job states with timestamps |
| Inconsistent error payloads | Hard troubleshooting and automation breaks | Standard error schema with tool-level detail |
| Hidden cleanup consequences | Fear of running maintenance actions | Dry-run preview and explicit scope confirmation |

## "Looks Done But Isn't" Checklist

- [ ] **Auth hardening:** verify all mutating routes enforce access checks, not just UI paths
- [ ] **Async jobs:** verify timeout/failure states propagate to status endpoints and reports
- [ ] **Refactor:** verify backward API compatibility with client/MCP regression tests
- [ ] **Retention:** verify policy execution does not delete active or referenced artifacts

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Unauthorized route exposure | HIGH | Disable external access, rotate credentials, add auth gate and audit review |
| Broken API contract after refactor | MEDIUM | Restore compatibility shim, patch schema, add regression tests |
| Accidental cleanup deletion | HIGH | Recover from backups/snapshots, patch cleanup safeguards, require dry-run confirmation |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Unsafe execution boundary | Phase 1 | Access tests reject unauthorized actions |
| Long-running request collapse | Phase 2 | Load tests show stable async job completion |
| API contract drift | Phase 2/3 | Compatibility tests pass for existing clients |
| Monolithic module entropy | Phase 3 | Route modules split with unchanged behavior tests |
| Artifact sprawl/unsafe cleanup | Phase 4 | Retention + dry-run controls validated |

## Sources

- `/opt/LitterBox/.planning/codebase/CONCERNS.md`
- `/opt/LitterBox/.planning/codebase/ARCHITECTURE.md`
- `/opt/LitterBox/.planning/codebase/INTEGRATIONS.md`
- `/opt/LitterBox/README.md`

---
*Pitfalls research for: malware analysis sandbox platform*
*Researched: 2026-02-25*

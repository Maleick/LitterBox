# M001 — LitterBox Platform Assessment & Remote Execution Validation

## Objective
Assess the current state of the LitterBox malware analysis sandbox, validate the remote execution framework, understand the architecture constraints, and evaluate LLM/Copilot integration opportunities.

## Slices

| Slice | Description | Status |
|-------|-------------|--------|
| S01 | Upstream sync & divergence analysis | ✅ Complete |
| S02 | Architecture assessment — how LitterBox works | ✅ Complete |
| S03 | Remote execution validation (WinRM/SSH) | 🔲 Pending verification |
| S04 | LLM/Copilot integration opportunities | ✅ Assessed |

## Key Decisions Needed
- Whether to merge upstream v4.1.0 changes (analyzer refactors) into our fork
- Which LLM integration path to pursue (fix MCP, build Copilot extension, or both)
- Whether to validate remote execution against live Windows targets now or defer

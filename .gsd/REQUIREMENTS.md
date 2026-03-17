# Requirements

This file is the explicit capability and coverage contract for the project.

## Active

### R001 — Infrastructure: Docker Server 2025 + Remove MCP + API Skill
- Class: launchability
- Status: active
- Description: Switch Docker compose from Windows 10 to Server 2025 (`VERSION: "2025"`), remove the obsolete MCP server (`LitterBoxMCP.py`), and write a LitterBox API skill file documenting all available endpoints and tool definitions for agent consumption
- Why it matters: Server 2025 aligns with the domain-controller deployment model; MCP is replaced by the embedded agent; the skill file becomes the source of truth for agent tool definitions
- Source: user
- Primary owning slice: M002/S01
- Supporting slices: none
- Validation: unmapped
- Notes: The skill file covers all endpoints from GrumpyCats client and REST API

### R002 — Multi-Provider LLM Adapter with Trust-Aware Routing
- Class: core-capability
- Status: active
- Description: A litellm-based adapter that provides a unified interface to OpenAI, Anthropic, and Ollama, with trust-aware data routing — cloud providers receive results JSON only, local/Ollama models can receive raw payload bytes and binary data
- Why it matters: Foundation for all AI features; enables both cloud convenience and air-gapped OPSEC workflows
- Source: user
- Primary owning slice: M002/S02
- Supporting slices: none
- Validation: unmapped
- Notes: Trust level per provider — `cloud` (restricted) vs `local` (unrestricted: raw bytes, binary data, full sample content). Shapes adapter design from day one.

### R003 — Agent Tool Router
- Class: core-capability
- Status: active
- Description: Maps LLM function-calling tool definitions to GrumpyCats `LitterBoxClient` methods — upload, analyze, get results, compare, schedule. Tool definitions sourced from the API skill file.
- Why it matters: The bridge between natural language intents and LitterBox API actions
- Source: user
- Primary owning slice: M002/S02
- Supporting slices: M002/S03, M002/S04
- Validation: unmapped
- Notes: Tool definitions must match the OpenAI function-calling schema; litellm normalizes across providers

### R004 — Web Chat UI with Streaming Responses
- Class: primary-user-loop
- Status: active
- Description: A chat panel in the LitterBox web UI (`/chat`) where operators type natural language and get streaming LLM responses via WebSocket (Flask-SocketIO)
- Why it matters: Primary interaction surface — this is how operators talk to the AI copilot
- Source: user
- Primary owning slice: M002/S03
- Supporting slices: none
- Validation: unmapped
- Notes: Must match existing dark theme (Tailwind CSS, sidebar nav pattern); streaming is essential for UX during long analysis narrations

### R005 — Conversational Job Scheduling
- Class: core-capability
- Status: active
- Description: The chat agent can create scheduled analysis jobs from natural language ("re-scan these payloads every night at 2am") using APScheduler with SQLite jobstore
- Why it matters: Transforms one-shot analysis into continuous regression testing workflows
- Source: user
- Primary owning slice: M002/S04
- Supporting slices: M002/S03
- Validation: unmapped
- Notes: Chat-driven creation, `/jobs` page for management

### R006 — Jobs Dashboard Page
- Class: primary-user-loop
- Status: active
- Description: A `/jobs` page in the LitterBox web UI listing all scheduled jobs with next run time, run history, and results; supports edit/delete
- Why it matters: Operators need visibility into what's scheduled and what's happened
- Source: user
- Primary owning slice: M002/S04
- Supporting slices: none
- Validation: unmapped
- Notes: Must match existing LitterBox UI patterns (sidebar nav, dark theme)

### R007 — Iterative Evasion Comparison
- Class: differentiator
- Status: active
- Description: Compare two analysis runs (before/after payload modification) and produce an LLM-narrated delta report showing what detections changed
- Why it matters: The core evasion coaching loop — upload → analyze → modify → re-analyze → compare
- Source: user
- Primary owning slice: M002/S05
- Supporting slices: M002/S02, M002/S03
- Validation: unmapped
- Notes: Delta computed from scanner result JSON; LLM narrates the significance

### R008 — Trust-Aware OPSEC Data Boundary
- Class: compliance/security
- Status: active
- Description: Cloud LLMs (OpenAI, Anthropic) receive only analysis result JSON — never raw payload bytes. Local/Ollama models can receive everything including raw binary data and sample content — everything stays on-network.
- Why it matters: Prevents payload exposure to external services while enabling deep analysis with local models
- Source: user
- Primary owning slice: M002/S02
- Supporting slices: none
- Validation: unmapped
- Notes: Adapter layer enforces `trust_level` per provider — `cloud` (restricted) vs `local` (unrestricted)

### R009 — Job Persistence Across Restarts
- Class: continuity
- Status: active
- Description: Scheduled jobs survive LitterBox server restarts via APScheduler SQLite jobstore
- Why it matters: Cron jobs are useless if they vanish when the server reboots
- Source: inferred
- Primary owning slice: M002/S04
- Supporting slices: none
- Validation: unmapped
- Notes: SQLite file stored alongside LitterBox data

### R010 — Agent Conversation Context
- Class: quality-attribute
- Status: active
- Description: The agent maintains analysis history within a chat session — remembers which payloads were discussed, what results were retrieved, what advice was given
- Why it matters: Without session context the iterative evasion loop breaks — the agent can't compare "this build vs that build" if it forgets the first one
- Source: inferred
- Primary owning slice: M002/S03
- Supporting slices: M002/S02
- Validation: unmapped
- Notes: Session-scoped, not persisted across server restarts (initial version)

## Deferred

### R020 — Slack Bot Integration
- Class: integration
- Status: deferred
- Description: `@litterbox analyze this` in Slack with file attachment, threaded follow-ups, alert channel for cron results
- Why it matters: Team-wide access to LitterBox analysis without opening the web UI
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to future milestone; agent backend from M002 is the foundation

### R021 — Discord Webhook Integration
- Class: integration
- Status: deferred
- Description: Similar to Slack but via Discord webhooks/bot
- Why it matters: Alternative team communication platform
- Source: inferred
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to future milestone

### R023 — YARA Rule Authoring via LLM
- Class: differentiator
- Status: deferred
- Description: Agent suggests YARA rules from analyzed samples, tests against sample set, iterates
- Why it matters: Accelerates detection engineering workflow
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to future milestone; requires solid agent foundation first

### R024 — Cross-Analysis Intelligence and Trending
- Class: differentiator
- Status: deferred
- Description: Detection trend analysis across multiple payloads, clustering by detection profile
- Why it matters: Strategic view of evasion effectiveness over time
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to future milestone

## Out of Scope

### R030 — Raw Payload Bytes to Cloud LLMs
- Class: anti-feature
- Status: out-of-scope
- Description: Sending raw payload binary data to cloud-hosted LLM APIs (OpenAI, Anthropic, Copilot) is explicitly prohibited
- Why it matters: Prevents payload exposure to external services; critical OPSEC boundary
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: n/a
- Notes: Local/Ollama models are exempt — they can receive raw payload data because everything stays on-network

### R031 — LangChain / Heavy Agent Framework Dependency
- Class: anti-feature
- Status: out-of-scope
- Description: No dependency on LangChain, CrewAI, or similar heavy agent frameworks
- Why it matters: Keeps the agent lightweight — litellm for LLM calls, direct function calling for tool routing, no abstraction layers that obscure behavior
- Source: inferred
- Primary owning slice: none
- Supporting slices: none
- Validation: n/a
- Notes: litellm is a thin adapter, not a framework

## Traceability

| ID | Class | Status | Primary owner | Supporting | Proof |
|---|---|---|---|---|---|
| R001 | launchability | active | M002/S01 | none | unmapped |
| R002 | core-capability | active | M002/S02 | none | unmapped |
| R003 | core-capability | active | M002/S02 | M002/S03, M002/S04 | unmapped |
| R004 | primary-user-loop | active | M002/S03 | none | unmapped |
| R005 | core-capability | active | M002/S04 | M002/S03 | unmapped |
| R006 | primary-user-loop | active | M002/S04 | none | unmapped |
| R007 | differentiator | active | M002/S05 | M002/S02, M002/S03 | unmapped |
| R008 | compliance/security | active | M002/S02 | none | unmapped |
| R009 | continuity | active | M002/S04 | none | unmapped |
| R010 | quality-attribute | active | M002/S03 | M002/S02 | unmapped |
| R020 | integration | deferred | none | none | unmapped |
| R021 | integration | deferred | none | none | unmapped |
| R023 | differentiator | deferred | none | none | unmapped |
| R024 | differentiator | deferred | none | none | unmapped |
| R030 | anti-feature | out-of-scope | none | none | n/a |
| R031 | anti-feature | out-of-scope | none | none | n/a |

## Coverage Summary

- Active requirements: 10
- Mapped to slices: 10
- Validated: 0
- Unmapped active requirements: 0

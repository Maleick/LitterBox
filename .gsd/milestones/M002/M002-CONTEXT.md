# M002: AI Copilot Agent

**Gathered:** 2026-03-17
**Status:** Ready for planning

## Project Description

LitterBox is a malware analysis sandbox that runs static and dynamic analysis via Windows-native scanner tools. This milestone adds an embedded AI copilot agent that operators interact with through a web chat UI. The agent can interpret analysis results in natural language, coach operators on evasion improvements, schedule recurring analysis jobs, and compare before/after payload modifications.

## Why This Milestone

LitterBox currently requires operators to manually read scanner JSON output and mentally translate it into "what do I need to change." The AI copilot closes that loop — it reads results, explains what's detected and why, suggests specific modifications, tracks whether changes worked, and automates recurring regression testing. This transforms LitterBox from a passive scanning tool into an active analysis platform.

## User-Visible Outcome

### When this milestone is complete, the user can:

- Open the LitterBox web UI and click into a `/chat` panel
- Type "analyze beacon.exe" and get an LLM-narrated report with actionable evasion advice, streamed in real time
- Upload a modified build and ask "compare this to the last version" to get a delta of what detections changed
- Say "schedule a nightly re-scan of all payloads" and have a cron job created automatically
- Open `/jobs` to see scheduled jobs, their next run times, and past results
- Switch between cloud LLMs (OpenAI, Anthropic) and local Ollama via config — with trust-aware data routing

### Entry point / environment

- Entry point: `http://127.0.0.1:1337/chat` (web UI) and `http://127.0.0.1:1337/jobs` (dashboard)
- Environment: Browser connected to running LitterBox Flask server
- Live dependencies involved: LLM API (OpenAI/Anthropic cloud or Ollama local), LitterBox REST API (self), APScheduler with SQLite

## Completion Class

- Contract complete means: Agent responds to tool-calling prompts with correct LitterBox API calls, verified by test harness with mock LLM responses
- Integration complete means: Chat UI streams real LLM responses, agent executes real LitterBox API calls, results display in chat
- Operational complete means: Scheduled jobs persist across server restarts, cron jobs execute on time, results are retrievable

## Final Integrated Acceptance

To call this milestone complete, we must prove:

- A user can open `/chat`, ask "what payloads have been analyzed?", and get a real answer from the LLM using data from the LitterBox API
- A user can upload two versions of a payload and get an LLM-narrated comparison of detection differences
- A user can create a scheduled job from chat and see it listed on `/jobs` with correct next-run time
- After restarting the LitterBox server, previously scheduled jobs are still present and execute on schedule

## Risks and Unknowns

- **litellm function calling reliability** — if tool calling is unreliable across providers, the agent can't dispatch actions correctly; this is the highest-risk dependency
- **Flask-SocketIO + litellm streaming** — Flask is synchronous; streaming LLM responses through WebSocket requires async bridging that could be fragile
- **Trust-aware data routing** — the adapter must reliably enforce OPSEC boundaries per provider; a bug here could leak payload data to cloud APIs
- **APScheduler in Flask process** — scheduler runs in the same process as Flask; heavy analysis jobs could block the web server

## Existing Codebase / Prior Art

- `GrumpyCats/grumpycat.py` — `LitterBoxClient` class with all API methods (upload, analyze, results, health, etc.)
- `GrumpyCats/LitterBoxMCP.py` — existing MCP server with 25 tool definitions and 5 OPSEC prompts (being removed, but tool definitions are reference material for the skill file)
- `app/routes.py` — all existing Flask routes; new `/chat` and `/jobs` routes will be added here or in a new blueprint
- `app/templates/base.html` — base template with sidebar nav (Tailwind CSS, dark theme); new pages extend this
- `app/static/js/` — per-page JavaScript files; chat UI will need `chat.js`
- `Config/config.yaml` — application config; will add `ai` section for LLM provider settings

> See `.gsd/DECISIONS.md` for all architectural and pattern decisions — it is an append-only register; read it during planning, append to it during execution.

## Relevant Requirements

- R001 — Infrastructure fixes (Docker Server 2025, remove MCP, write skill)
- R002 — Multi-provider LLM adapter with trust-aware routing
- R003 — Agent tool router (function calling → LitterBox API)
- R004 — Web chat UI with streaming responses
- R005 — Conversational job scheduling
- R006 — Jobs dashboard page
- R007 — Iterative evasion comparison
- R008 — Trust-aware OPSEC data boundary (cloud restricted, local unrestricted)
- R009 — Job persistence across restarts
- R010 — Agent conversation context

## Scope

### In Scope

- Embedded AI agent with web chat UI
- Multi-provider LLM adapter (litellm) with trust-aware data routing
- Function-calling tool router mapping to LitterBox API
- Streaming responses via Flask-SocketIO
- Chat-driven job scheduling with APScheduler + SQLite
- Jobs management dashboard (`/jobs`)
- Iterative evasion comparison with LLM-narrated deltas
- LitterBox API skill file for agent consumption
- Docker compose switch to Server 2025
- Removal of obsolete MCP server

### Out of Scope / Non-Goals

- Slack/Discord integration (deferred to future milestone)
- YARA rule authoring via LLM (deferred)
- Cross-analysis intelligence and trending (deferred)
- Raw payload bytes to cloud LLMs (explicit anti-feature)
- LangChain or heavy agent framework dependencies (anti-feature)

## Technical Constraints

- Flask is synchronous — WebSocket streaming requires Flask-SocketIO with eventlet or gevent
- LitterBox requires admin/root to run (`is_running_as_admin()` check in `litterbox.py`)
- Scanner tools are Windows executables — agent can trigger analysis but results depend on Windows target availability
- Existing UI uses Tailwind CSS with inline `<script>` blocks and per-page JS files — new pages must follow this pattern

## Integration Points

- **LLM APIs** — OpenAI, Anthropic via litellm; Ollama for local models
- **LitterBox REST API** — agent calls its own server's API (localhost:1337) via GrumpyCats client
- **APScheduler** — runs in-process with Flask; SQLite jobstore for persistence
- **Flask-SocketIO** — WebSocket layer for chat streaming; requires `socketio.run(app)` instead of `app.run()`

## Open Questions

- **eventlet vs gevent for Flask-SocketIO** — need to verify which async backend works best with litellm's streaming; leaning eventlet as it's Flask-SocketIO's default
- **Agent system prompt** — the OPSEC analysis prompts from the existing MCP server are solid reference material; need to decide if they become the default system prompt or are selectable modes

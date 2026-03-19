# M002: AI Copilot Agent

**Vision:** Embed an LLM-driven copilot directly into LitterBox that operators talk to through a web chat UI. The agent interprets analysis results, coaches on evasion improvements, compares before/after payload builds, and schedules recurring analysis jobs — turning LitterBox from a passive scanning tool into an active analysis platform.

## Success Criteria

- Operator can open `/chat` in LitterBox and have a streaming conversation with the AI agent about analysis results
- Agent can call LitterBox API tools (upload, analyze, get results) via LLM function calling
- Operator can ask the agent to compare two analysis runs and get a narrated delta of detection changes
- Operator can tell the agent to schedule a recurring analysis job and see it on the `/jobs` dashboard
- Scheduled jobs persist across server restarts
- Cloud LLMs never receive raw payload bytes; local/Ollama models can receive everything

## Key Risks / Unknowns

- **litellm function calling across providers** — if tool calling is unreliable or inconsistent between OpenAI and Anthropic, the agent can't dispatch actions correctly
- **Flask-SocketIO streaming bridge** — Flask is synchronous; streaming litellm responses through WebSocket requires async bridging
- **Trust-aware data routing correctness** — a bug in the OPSEC boundary could leak payload data to cloud APIs

## Proof Strategy

- litellm function calling reliability → retire in S02 by proving a test harness can send a natural language message, get back correct tool calls with valid params, and execute them against a mock LitterBox API
- Flask-SocketIO streaming → retire in S03 by proving LLM response tokens stream to the browser in real time via WebSocket
- Trust-aware routing → retire in S02 by proving cloud provider config strips raw binary data from context while local provider config passes it through

## Verification Classes

- Contract verification: pytest tests for adapter, tool router, job scheduler; mock LLM responses for deterministic testing
- Integration verification: real LLM API call → real LitterBox API call → real result displayed in chat UI
- Operational verification: server restart → jobs still present → next scheduled job fires on time
- UAT / human verification: operator has a real conversation with the agent about a real payload analysis

## Milestone Definition of Done

This milestone is complete only when all are true:

- All six slice deliverables are complete and verified
- Agent, chat UI, and job scheduler are wired together in a running LitterBox instance
- `/chat` endpoint exists and serves a streaming chat interface
- `/jobs` endpoint exists and shows scheduled jobs with run history
- The full demo flow works: chat → analyze → AI coaches → schedule regression → `/jobs` shows results
- Success criteria are re-checked against live behavior, not just test fixtures
- Final integrated acceptance scenarios pass against a running LitterBox server

## Requirement Coverage

- Covers: R001, R002, R003, R004, R005, R006, R007, R008, R009, R010
- Partially covers: none
- Leaves for later: R020, R021, R023, R024

## Slices

- [x] **S01: Infrastructure & API Skill** `risk:low` `depends:[]`
  > After this: Docker compose targets Server 2025, MCP server is removed, and a LitterBox API skill file documents all available endpoints for agent tool definitions.

- [x] **S02: LLM Adapter & Agent Tool Router** `risk:high` `depends:[S01]`
  > After this: A Python test harness sends a natural language message, litellm calls the configured LLM, the LLM returns function-calling tool invocations, and the tool router executes the correct GrumpyCats client methods with valid parameters. Trust-aware routing proven: cloud config strips binary data, local config passes it through.

- [ ] **S03: Chat UI & WebSocket Streaming** `risk:high` `depends:[S02]`
  > After this: Open LitterBox at `/chat`, type a message, see streaming LLM response tokens appear in real time. The agent maintains conversation context within a session — it remembers what payloads were discussed.

- [ ] **S04: Job Scheduling & Dashboard** `risk:medium` `depends:[S02,S03]`
  > After this: In chat, say "re-scan all payloads every night at 2am" — a job is created. Open `/jobs` to see it listed with next run time. Restart the server — the job is still there. When the job fires, results are stored and visible on the dashboard.

- [ ] **S05: Iterative Evasion Comparison** `risk:medium` `depends:[S02,S03]`
  > After this: Upload two payload versions, ask the chat agent "compare detections between these builds", get an LLM-narrated delta report showing which detections appeared, disappeared, or changed.

- [ ] **S06: End-to-End Integration Proof** `risk:low` `depends:[S03,S04,S05]`
  > After this: The full demo flow works in a running LitterBox instance: chat → analyze payload → AI interprets results and coaches → schedule a regression job → `/jobs` shows the job and its results. All wired, all real, all verified.

## Boundary Map

### S01 → S02

Produces:
- `app/agent/skill.py` or `.gsd/agents/litterbox-api/SKILL.md` — complete API endpoint catalog with parameter schemas, used as source of truth for tool definitions
- `Config/config.yaml` updated with `ai:` section schema (provider, model, api_key, trust_level)
- Docker compose at `VERSION: "2025"`

Consumes:
- nothing (first slice)

### S02 → S03

Produces:
- `app/agent/adapter.py` — `LLMAdapter` class wrapping litellm with trust-aware data filtering
- `app/agent/tools.py` — tool definitions list (OpenAI function-calling schema) and `execute_tool()` dispatcher
- `app/agent/engine.py` — `AgentEngine.chat(message, context)` → returns response with any tool results; supports streaming via callback

Consumes from S01:
- API skill file for tool definition schemas
- `Config/config.yaml` `ai:` section for provider config

### S02 → S04

Produces:
- `app/agent/tools.py` — includes `schedule_job` and `list_jobs` tool definitions
- `app/agent/engine.py` — `AgentEngine` interface that S04 wires to scheduler actions

Consumes from S01:
- Same as S02 → S03

### S02 → S05

Produces:
- `app/agent/tools.py` — includes `compare_analyses` tool definition
- `app/agent/engine.py` — engine interface for comparison requests

Consumes from S01:
- Same as S02 → S03

### S03 → S04

Produces:
- `app/templates/chat.html` — chat UI template (S04 adds job-related message rendering)
- Flask-SocketIO integration in `app/__init__.py` — WebSocket infrastructure reused by job notifications
- `app/static/js/chat.js` — client-side chat logic

Consumes from S02:
- `AgentEngine.chat()` with streaming callback

### S03 → S05

Produces:
- Chat UI infrastructure (S05 renders comparison results in chat)
- Conversation context (S05 uses it to track which two analyses to compare)

Consumes from S02:
- `AgentEngine.chat()` with streaming callback

### S04 → S06

Produces:
- `app/agent/scheduler.py` — APScheduler wrapper with SQLite jobstore, `create_job()`, `list_jobs()`, `delete_job()`
- `app/templates/jobs.html` — jobs dashboard template
- `app/static/js/jobs.js` — jobs page client logic
- Job execution results stored in `Results/` or SQLite

Consumes from S02:
- Tool router for `schedule_job` tool
Consumes from S03:
- Flask-SocketIO for job completion notifications in chat

### S05 → S06

Produces:
- `app/agent/comparison.py` — `compare_analyses(hash_a, hash_b)` → structured delta dict
- LLM narration prompt for delta interpretation

Consumes from S02:
- `AgentEngine` for LLM narration
- GrumpyCats client for fetching analysis results
Consumes from S03:
- Chat UI for rendering comparison results

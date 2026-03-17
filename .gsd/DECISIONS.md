# Decisions Register

<!-- Append-only. Never edit or remove existing rows.
     To reverse a decision, add a new row that supersedes it.
     Read this file at the start of any planning or research phase. -->

| # | When | Scope | Decision | Choice | Rationale | Revisable? |
|---|------|-------|----------|--------|-----------|------------|
| D001 | M001 | scope | GSD milestone structure for LitterBox | Single assessment milestone (M001) with assessment, research, summary artifacts | Mirrors Nemesis GSD pattern; fork assessment fits in one milestone | No |
| D002 | M001 | arch | Remote execution architecture viability | Architecturally validated; SSH and WinRM runners are complete | Code review of runner.py (761 lines), context.py (224 lines), and 844 lines of tests confirms structural soundness | Yes — needs live validation |
| D003 | M001 | arch | Docker VM OS version | Server 2025 via dockur/windows (`VERSION: "2025"`) | install.ps1 already handles Server SKUs; aligns with domain-controller deployment model; supports Ansible DC promotion | Yes |
| D004 | M002 | arch | LLM integration strategy | Embedded multi-provider agent with web chat, not MCP | MCP is Claude Desktop-only and requires separate client; embedded agent uses same REST API, supports any LLM via litellm, enables chat UI + cron jobs + Slack | No |
| D005 | M002 | library | LLM adapter library | litellm | Thin adapter, not a framework; unified OpenAI-compatible interface to 100+ providers; supports function calling across providers | No |
| D006 | M002 | library | WebSocket library for Flask chat | Flask-SocketIO | Proven Flask extension for WebSocket; supports eventlet/gevent async; well-documented streaming pattern | Yes — if Flask is replaced |
| D007 | M002 | library | Job scheduler | APScheduler with SQLite jobstore via Flask-APScheduler | Flask-native integration; persistent jobs survive restarts; cron expression support; no external service dependency | No |
| D008 | M002 | arch | OPSEC data boundary — trust-aware routing | Cloud LLMs: results JSON only, never raw payload bytes. Local/Ollama: unrestricted, can receive raw binary data | Cloud APIs are external trust boundary; local models stay on-network; adapter enforces trust_level per provider | No |
| D009 | M002 | scope | MCP server disposition | Remove LitterBoxMCP.py, replace with API skill file | MCP is redundant with embedded agent; skill file documents all endpoints for agent tool definitions | No |
| D010 | M002 | arch | Chat interaction model | Web chat first (primary), Slack deferred to future milestone | User preference; web chat is the primary surface; Slack shares the same agent backend when built | Yes — if Slack prioritized |
| D011 | M002 | arch | Job creation model | Chat-driven scheduling with /jobs dashboard for management | Natural language creates jobs; dedicated UI lists/edits/deletes them | No |
| D012 | M002 | arch | Agent framework | No LangChain/CrewAI — litellm + direct function calling + GrumpyCats client | Keep agent lightweight; no abstraction layers that obscure behavior | No |

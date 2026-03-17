# M001 — LitterBox Platform Assessment

## Overview

LitterBox is a **malware analysis sandbox** by BlackSnufkin designed for red teams to test payloads against detection engines in a controlled environment. It provides static analysis (YARA, CheckPlz, Stringnalyzer), dynamic analysis (PE-Sieve, Moneta, Patriot, RedEdr, Hunt-Sleeping-Beacons, Hollows-Hunter), BYOVD driver analysis (HolyGrail), and similarity analysis (Blender + FuzzyHash). The platform runs as a Flask web app on port 1337.

**Current version**: 4.1.0  
**Fork**: `Maleick/LitterBox` (11 commits ahead of `BlackSnufkin/LitterBox`)

---

## Architecture — How LitterBox Actually Works

### Core Runtime Model

LitterBox is a **Flask web application** (`litterbox.py` → `app/create_app()`). It is NOT a standalone binary or agent — it is a Python server that:

1. **Accepts file uploads** via web UI or API (`POST /upload`)
2. **Stores samples** locally in `Uploads/` with hash-based naming
3. **Executes scanner tools** by shelling out to Windows-native `.exe` binaries (YARA, PE-Sieve, Moneta, etc.)
4. **Collects and parses results** back into JSON for API/UI consumption
5. **Stores results** in `Results/<hash>/` directories

### The Windows Requirement — Why It Matters

**LitterBox's scanner tools are Windows executables.** Every scanner in the config (`yara64.exe`, `pe-sieve.exe`, `moneta64.exe`, `patriot.exe`, etc.) is a Windows PE binary. This means:

| Deployment Mode | How It Works | Windows Needed? |
|----------------|--------------|-----------------|
| **Native Windows** | LitterBox + scanners run directly | Yes — the host IS Windows |
| **Docker (dockur/windows)** | Full Windows VM inside Docker via KVM/QEMU | Yes — VM inside container |
| **Remote execution (our fork)** | Flask on Linux, scanners on remote Windows via SSH/WinRM | Yes — on a separate remote machine |

**Key insight**: There is no way to run LitterBox's analysis without Windows somewhere. The Docker approach creates a local Windows VM. Our fork's approach uses a remote Windows machine instead.

### Docker VM — Windows 10 vs Server 2025

The current `docker-compose.yml` sets `VERSION: "10"` for Windows 10. **This is a single-line change to switch.**

The `dockur/windows` project supports Windows versions from 2000 through 11 and Server editions from 2003 through 2025. To switch to Server 2025, change the environment variable:

```yaml
environment:
  VERSION: "2025"    # was "10"
  RAM_SIZE: "8G"
  CPU_CORES: "4"
  DISK_SIZE: "75G"
```

The `install.ps1` already handles Server SKUs — the `Test-IsServerSKU` function detects Server editions and skips consumer-only debloat scripts, noting that server hardening is handled by Ansible CIS playbooks post-boot. WinRM is also enabled automatically (`Enable-WinRM` function), so the Docker VM could serve double duty as both a local analysis host AND a remote WinRM target.

**Domain-joined VM**: Yes, the Docker VM can be domain-joined. The `install.ps1` clones from the Maleick fork and installs LitterBox inside the VM. Post-boot, the Ansible `setup-dc.yml` playbook can promote it to a domain controller or join it to an existing domain. This is already designed into the workflow — the ansible directory has `setup-dc.yml` and `cis-harden.yml` playbooks ready.

### Execution Runner Architecture (Our Fork)

Three runner implementations in `app/execution/runner.py`:

| Runner | Transport | File Staging | Command Execution |
|--------|-----------|-------------|-------------------|
| `LocalRunner` | subprocess | Local filesystem | `subprocess.run()` |
| `SshRemoteRunner` | SSH+SCP | `scp` to remote path | `ssh` → PowerShell |
| `WinRmRemoteRunner` | WinRM/NTLM | Base64 chunked via PS | `pywinrm` `run_ps()` |

**Remote execution flow:**
```
Linux Host                          Remote Windows Host
─────────────                       ───────────────────
1. Upload file (web/API)
2. resolve_execution_context()
   → pick target from config
3. stage_file()
   → SCP or WinRM transfer    ────→  C:\LitterBox\RemoteExecution\runs\<session>\samples\
4. run_command()
   → scanner commands          ────→  Execute yara64.exe, pe-sieve.exe, etc.
5. fetch_artifacts()           ←────  Copy results back
6. Parse results locally
7. Return JSON via API
```

---

## Upstream vs Fork Delta

### Upstream (BlackSnufkin/LitterBox) at v4.1.0 (`cca7406`):
- Core analysis engine, all scanners
- Refactored `holygrail.py` (significant changes)
- Refactored `manager.py` (simplified)
- GrumpyCats + MCP server
- Docker Windows VM deployment
- **No remote execution** — purely local or Docker VM

### Our fork adds (+6,645 lines / -668 lines):
| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Execution runners | `app/execution/runner.py` | 761 | Local, SSH, WinRM runners |
| Execution context | `app/execution/context.py` | 224 | Target resolution, staging, artifacts |
| Credential mgmt | `app/remote_credentials.py` | 259 | `.env.remote` read/write/migrate |
| Remote targets | `app/remote_targets.py` | 234 | Add/delete hosts in config |
| Extended routes | `app/routes.py` | +502 | Wizard, health, target override |
| Credential wizard | `app/templates/remote_credentials.html` | 422 | Web UI for WinRM credentials |
| Documentation | `docs/REMOTE_WINDOWS_TAILSCALE.md` | 135 | Setup + troubleshooting guide |
| AGENTS guide | `AGENTS.md` | 147 | Operational runbook |
| Ansible | `ansible/` | ~300 | DC setup + CIS hardening |
| Tests | `tests/` | 844 | 8 test files covering all new code |
| Config | `Config/config.yaml` | +107 | 3 remote targets |

### Merge Risk Assessment
- **`app/analyzers/manager.py`**: Both sides modified — upstream simplified, our fork added execution imports
- **`app/routes.py`**: Our fork significantly extends; upstream simplified
- **`app/__init__.py`**: Both modified
- **`requirements.txt`**: Both modified (we added `pywinrm`)
- **Verdict**: Medium-risk merge. Core conflict is `manager.py` imports from `app.execution` which upstream deleted.

---

## Remote Execution — Does It Work?

### Architectural completeness: ✅ YES
The code is structurally complete. All three runners implement the full `ExecutionRunner` ABC with file staging, artifact retrieval, credential management, and fallback.

### End-to-end verification: ❓ UNTESTED
No Windows targets currently online on the tailnet. `.env.remote` is empty.

### Does it need a local VM?
**NO.** Remote execution eliminates the need. Linux hosts the server, remote Windows runs scanners.

### Does Windows need LitterBox installed?
**NO.** Only scanner binaries at configured paths + a working directory.

### Can it work with the remote machine?
**YES.** That's the entire purpose of the fork's additions.

### Can the Docker VM be Server 2025?
**YES.** Change `VERSION: "10"` to `VERSION: "2025"` in `docker-compose.yml`. The install script already handles Server SKUs. It can also be domain-joined via the existing Ansible playbooks.

---

## LLM / Copilot Integration — Architecture

### Current State: LitterBoxMCP

The existing MCP server (`GrumpyCats/LitterBoxMCP.py`) has 25 tools and 5 OPSEC prompts for Claude Desktop. Known bug: imports `optimized_litterbox_client` which doesn't exist (should be `grumpycat`).

### Copilot Agent Mode — High Value Architecture

The vision: an LLM agent embedded directly in LitterBox that can be driven from the GUI, Slack, or cron — not just Claude Desktop.

#### Architecture: LitterBox AI Agent

```
┌─────────────────────────────────────────────────────────┐
│                    LitterBox Flask App                   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
│  │  Web UI   │  │ REST API │  │  AI Agent Engine       │  │
│  │  /chat    │  │ /api/*   │  │  ┌─────────────────┐  │  │
│  │  /jobs    │  │          │  │  │ LLM Adapter      │  │  │
│  │           │  │          │  │  │ ├─ OpenAI/GPT    │  │  │
│  └─────┬─────┘ └────┬─────┘  │  │ ├─ Anthropic     │  │  │
│        │             │        │  │ ├─ GitHub Copilot│  │  │
│        │             │        │  │ └─ Local (Ollama)│  │  │
│        ▼             ▼        │  └────────┬────────┘  │  │
│  ┌──────────────────────────┐ │           │           │  │
│  │    Analysis Manager      │ │  ┌────────▼────────┐  │  │
│  │    (existing scanners)   │◄├──┤ Tool Router     │  │  │
│  └──────────────────────────┘ │  │ (maps intents   │  │  │
│                               │  │  to API calls)  │  │  │
│  ┌──────────────────────────┐ │  └────────┬────────┘  │  │
│  │    Job Scheduler         │ │           │           │  │
│  │    (cron / intervals)    │◄├───────────┘           │  │
│  └──────────────────────────┘ │                       │  │
│                               └───────────────────────┘  │
│  ┌──────────────────────────┐                            │
│  │    Integrations          │                            │
│  │    ├─ Slack webhook/bot  │                            │
│  │    ├─ Discord webhook    │                            │
│  │    └─ Teams connector    │                            │
│  └──────────────────────────┘                            │
└──────────────────────────────────────────────────────────┘
```

#### Key Features the Agent Would Provide

**1. Conversational Analysis in the GUI (`/chat`)**
- Chat panel in the LitterBox web UI
- "Upload beacon.exe and tell me what's detected"
- "Compare this against last week's build"
- "What do I need to change to bypass the YARA hits?"
- Agent calls the same REST API endpoints that GrumpyCats uses

**2. Scheduled / Cron Jobs (`/jobs`)**
- "Every night at 2am, re-scan all payloads against updated YARA rules"
- "Run a regression test on these 5 payloads after I update the evasion"
- "Monitor this PID for 30 minutes and alert if detection changes"
- Jobs stored in SQLite or config, executed by APScheduler/Celery
- Results posted to Slack/chat/webhook

**3. Slack/Discord Integration**
- Bot in a channel: `@litterbox analyze this` (with file attachment)
- Results posted back as formatted messages
- Threaded conversations for follow-up questions
- Alert channel for cron job results and detection changes

**4. Iterative Evasion Loop**
```
User: "Help me get beacon.exe past Moneta"
Agent: [uploads → runs static + dynamic → reads results]
Agent: "Moneta flags memory regions at 0x7FF... with IOC type 'Private Executable'.
        This is likely your shellcode allocation. Options:
        1. Use indirect syscalls to avoid the hooked allocation path
        2. Map as SEC_IMAGE to look like a legitimate DLL load
        3. Use module stomping to overwrite a legitimate module's memory"
User: "Try option 2, here's the updated build" [uploads new file]
Agent: [re-analyzes → compares → reports delta]
Agent: "Moneta no longer flags the allocation. But PE-Sieve now detects
        a replaced module. The stomping left the PE header intact —
        consider erasing the DOS header after mapping."
```

**5. YARA Rule Authoring**
- "Write a YARA rule that catches this family but not my legitimate tools"
- Agent reads static analysis results, string extractions, behavioral patterns
- Generates rule, tests it against the sample set, iterates

**6. Cross-Analysis Intelligence**
- "Which of my last 10 payloads would survive this new YARA ruleset?"
- "What's the detection trend — am I getting better or worse?"
- "Cluster my payloads by detection profile"

#### Implementation Approach

| Component | Technology | Effort | Notes |
|-----------|-----------|--------|-------|
| LLM Adapter | `litellm` or direct API | Low | Wraps OpenAI/Anthropic/Copilot/Ollama with common interface |
| Tool Router | Function calling / tool use | Medium | Maps LLM tool calls → GrumpyCats `LitterBoxClient` methods |
| Chat UI | WebSocket + existing Flask templates | Medium | Chat panel in LitterBox web UI |
| Job Scheduler | APScheduler (already Python) | Medium | Cron expressions, job queue, result storage |
| Slack Bot | `slack-bolt` | Low | Webhook receiver + message formatter |
| Result Narrator | LLM prompt chain | Low | Takes scanner JSON → produces human analysis |

**Key design decision**: The agent uses the **same REST API** that external clients use. No special internal coupling. This means:
- Slack bot and web chat use identical code paths
- Cron jobs are just scheduled API calls + LLM interpretation
- Any LLM provider works (swap via config)
- The agent can run against a remote LitterBox instance too

#### LLM Provider Options

| Provider | Model | Best For | Cost |
|----------|-------|----------|------|
| GitHub Copilot | GPT-4o via Copilot API | VS Code integration, code-aware analysis | Copilot subscription |
| OpenAI | GPT-4o / GPT-4.1 | Best tool-use, fast iteration | API pricing |
| Anthropic | Claude 3.5/4 | Deep analysis, long context for report generation | API pricing |
| Ollama (local) | Llama 3.3 / Qwen 2.5 | Air-gapped / OPSEC-sensitive environments | Free (GPU) |
| GitHub Models | Various | Free tier for experimentation | Free/limited |

**OPSEC note**: For sensitive payloads, local models via Ollama avoid sending analysis data to cloud APIs. The adapter pattern makes this a config switch, not a code change.

---

## Recommendations

### Immediate
1. ✅ GSD milestone structure created
2. ✅ Upstream checked — no new changes, we're 11 commits ahead
3. ✅ Architecture fully documented
4. ✅ Docker VM can be switched to Server 2025 (one-line change)

### Short-term
1. Fix MCP server import bug (`optimized_litterbox_client` → `grumpycat`)
2. Switch Docker compose to Server 2025 (`VERSION: "2025"`)
3. Bring a Windows target online (Docker VM or dedicated host)
4. Run end-to-end remote execution validation

### Medium-term (Copilot Agent Mode)
1. Build LLM adapter layer with `litellm` (multi-provider)
2. Build tool router mapping LLM function calls → GrumpyCats client
3. Add `/chat` endpoint and WebSocket chat UI to Flask app
4. Add APScheduler for cron-style recurring analysis jobs
5. Build Slack bot integration with `slack-bolt`
6. Add job management UI (`/jobs`) for scheduling and monitoring

### Longer-term
1. Iterative evasion loop with delta comparison
2. YARA rule authoring assistance
3. Cross-analysis intelligence and trending
4. Multi-model orchestration (Claude for deep analysis, GPT for fast iteration, local for OPSEC)

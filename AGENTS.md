# AGENTS.md

## Purpose

This file is the primary operational guide for agents working in `/opt/LitterBox`.
Use it to verify runtime context, execute safe local/container workflows, and follow the next-run VanguardForge validation checklist.

## Runtime Truth Check

Always confirm where LitterBox is running before testing:

```bash
cd /opt/LitterBox
pwd
lsof -nP -iTCP:1337 -sTCP:LISTEN || true
docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}'
tailscale serve status || true
```

Interpretation:
- `127.0.0.1:1337` listener from Python process => local host runtime.
- Container name/port mapping for LitterBox => container runtime.
- Tailscale serve shows what endpoint is being published and where it proxies.

## Preflight

Run before changes or remote validation:

```bash
cd /opt/LitterBox
git status --short --branch
git remote -v
tailscale status || true
```

## Run Modes

### Local Dev Run

```bash
cd /opt/LitterBox
source .venv/bin/activate
export LITTERBOX_WIZARD_TOKEN="$(openssl rand -hex 32)"
python3 litterbox.py --debug
```

### Container/VanguardForge Run Expectations

- App root remains `/opt/LitterBox`.
- Wizard credential storage remains local to that running instance at `/opt/LitterBox/.env.remote`.
- Do not move production workflows; validate behavior first in RT/PT container context.

## Tailscale Serve

Standard mapping:

```bash
tailscale serve reset
tailscale serve --bg --yes --https=7443 http://127.0.0.1:1337
tailscale serve status
```

Expected:
- `https://<node>.nuthatch-chickadee.ts.net:7443`
- `/` proxies to `http://127.0.0.1:1337`

## Wizard Usage

- Route: `/setup/remote-credentials`
- Setup token is required for save/delete/add-host/delete-host actions.
- Never log raw token/password/domain credentials in notes, prompts, or output.

Token helper:

```bash
echo "$LITTERBOX_WIZARD_TOKEN"
```

## Remote Host Target Management

- Host catalog source: `Config/config.yaml` (`analysis.remote.targets`, WinRM targets).
- In wizard:
  - `Add Host` creates a WinRM target cloned from `domain`.
  - `Delete Host` removes target from config and deletes corresponding `.env.remote` credential keys.
  - `Delete Credentials` removes only credential keys for a target.
- Target ID is derived from first hostname label (example: `server01.example.ts.net` -> `server01`).

## WinRM Smoke Test (Env Vars Only)

Do not paste credentials in chat or files. Set env vars in-shell only:

```bash
export WINRM_USER="VANGUARD\\localuser"
export WINRM_PASS="<redacted>"
python3 - <<'PY'
import os, winrm
host = "domain.nuthatch-chickadee.ts.net"
s = winrm.Session(
    f"https://{host}:5986/wsman",
    auth=(os.environ["WINRM_USER"], os.environ["WINRM_PASS"]),
    transport="ntlm",
    server_cert_validation="ignore",
)
r = s.run_ps("whoami")
print("status:", r.status_code)
print("stdout:", r.std_out.decode(errors="replace").strip())
print("stderr:", r.std_err.decode(errors="replace").strip())
PY
```

Pass criteria:
- `status: 0`
- `stdout` returns expected principal (domain or local account format).

## Cleanup

Stop local test runtime and unpublish endpoint:

```bash
PID="$(lsof -ti tcp:1337)"
[ -n "$PID" ] && kill "$PID"
tailscale serve reset
lsof -nP -iTCP:1337 -sTCP:LISTEN || true
tailscale serve status || true
```

## Next-Run Checklist (VanguardForge RT/PT)

Goal: Validate remote credential + WinRM flow in VanguardForge container context (not only local Mac).

Required checks:
1. Confirm runtime location (container host vs local host).
2. Confirm Tailscale serve URL and backend mapping.
3. Open wizard and verify:
   - host-centric target dropdown
   - add host works
   - delete host works
   - delete credentials works
4. Confirm `/opt/LitterBox/.env.remote` exists and is mode `0600`.
5. Run WinRM smoke test to `domain.nuthatch-chickadee.ts.net`.
6. Report pass/fail plus exact failing command (redacted) for blockers.

## Git Policy

- Push only to fork remote (`origin` here).
- Do not open or target upstream PRs by default.
- Keep commits atomic and include verification notes in handoff summaries.

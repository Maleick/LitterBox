# Remote Windows Execution Over Tailscale

This guide configures a Linux-hosted LitterBox server to run scanners on remote Windows hosts over Tailscale using transport-aware remoting (`ssh` and `winrm`).

## Architecture

- LitterBox API/UI runs on Linux.
- Uploaded files remain on Linux in `Uploads/` and `Results/`.
- At analysis time, files are staged to a remote Windows target via SSH/SCP or WinRM transfer (depending on target transport).
- Scanner commands execute on Windows over PowerShell through SSH or WinRM.
- Remote run artifacts are copied back into local `Results/<hash>/remote_artifacts/`.
- No custom background agent/service is required.

## Windows Target Prerequisites

Run on each target (Windows 11 Enterprise or Windows Server 2025):

1. Choose transport per target:
   - `ssh`: OpenSSH Server
   - `winrm`: WinRM (HTTPS 5986 recommended)

2. For SSH targets, install and start OpenSSH Server:
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```
3. For WinRM targets, enable WinRM HTTPS listener and allow NTLM auth in lab context:
```powershell
winrm quickconfig -q
winrm set winrm/config/service/auth '@{NTLM="true"}'
```
4. Authorize Linux host public key in `%ProgramData%\ssh\administrators_authorized_keys` (admin context) or user `authorized_keys` for SSH targets.
5. Install and connect Tailscale to the same tailnet.
6. Ensure scanner binaries exist at paths referenced in `analysis.remote.targets.<id>.scanner_paths`.

## Linux Host Prerequisites

1. Install OpenSSH client and Tailscale.
2. Add private keys referenced by `analysis.remote.targets.<id>.ssh_key_path` (SSH targets only).
3. For WinRM targets, populate credentials in `.env.remote` using `/setup/remote-credentials`.
4. Verify connectivity before running analyses:
```bash
tailscale status
ssh -o BatchMode=yes <user>@<target-host>.ts.net true
```

## LitterBox Configuration

Edit `Config/config.yaml`:

- `analysis.remote.enabled`: enable remote routing.
- `analysis.remote.transport`: default transport (`ssh` or `winrm`).
- `analysis.remote.default_target`: default target id (for example `win11`).
- `analysis.remote.local_fallback`: use local analyzer execution if remote is unavailable.
- `analysis.remote.targets`: per-target connection and scanner-path mapping.

Target schema:

```yaml
analysis:
  remote:
    enabled: true
    transport: "ssh"
    default_target: "win11"
    local_fallback: true
    targets:
      win11:
        transport: "ssh"
        host: "win11.nuthatch-chickadee.ts.net"
        port: 22
        user: "analyst"
        ssh_key_path: "~/.ssh/litterbox-win11"
        platform: "windows11-enterprise"
        role: "analysis"
        remote_workdir: "C:\\LitterBox\\RemoteExecution"
        scanner_paths:
          yara:
            tool_path: "C:\\LitterBox\\Scanners\\Yara\\yara64.exe"
            rules_path: "C:\\LitterBox\\Scanners\\Yara\\LitterBox.yar"
      domain:
        transport: "winrm"
        host: "domain.nuthatch-chickadee.ts.net"
        winrm_port: 5986
        winrm_scheme: "https"
        auth_mode: "ntlm"
        server_cert_validation: false
        remote_workdir: "C:\\LitterBox\\RemoteExecution"
```

Notes:
- The same model supports Windows Server 2025 targets, including domain controller hosts.
- WinRM targets consume credentials from `.env.remote`:
  - `LB_REMOTE_TARGET_<ID>_ACCOUNT_TYPE`, `_DOMAIN`, `_USERNAME`, `_PASSWORD`
- If `domain` credentials are missing and `server2025` points to the same host, LitterBox auto-migrates `server2025` credentials to `domain`.
- No additional domain-controller guardrail is enforced by this phase.

## Per-Request Target Override

Use `execution_target` for deterministic routing:

```bash
curl -X POST "http://127.0.0.1:1337/analyze/dynamic/<hash>?execution_target=server2025" \
  -H "Content-Type: application/json" \
  -d '{"args":[]}'
```

```bash
curl "http://127.0.0.1:1337/holygrail?hash=<hash>&execution_target=win11"
```

## Health Checks

`GET /health` now includes remote target checks:

- Tailscale hostname presence (`tailscale status`)
- Transport authentication/reachability (`ssh_auth` or `winrm_auth`)
- Remote scanner path existence (`Test-Path`)

## Fallback Behavior

- If remote is enabled and reachable: remote execution is primary.
- If remote fails and `local_fallback=true`: analysis falls back to local runner.
- If remote fails and `local_fallback=false`: request returns an explicit error.

## Troubleshooting Matrix

| Symptom | Likely cause | Action |
|---|---|---|
| `Remote target ... unreachable over SSH` | Host offline, SSH blocked, key mismatch | Verify `tailscale status`, `ssh -o BatchMode=yes`, firewall and key path |
| `Remote target ... unreachable over winrm` | WinRM listener/auth config mismatch or blocked port | Verify WinRM listener/5986, auth mode, and target transport credentials in `.env.remote` |
| `Scanner path not found` in `/health` | Incorrect `scanner_paths` value | Fix path in `Config/config.yaml` and validate with `/health` |
| Remote run falls back to local unexpectedly | Remote preflight failed and fallback is enabled | Inspect `analysis_metadata.execution_warnings` and `/health` details |
| PID analysis fails remotely | PID does not exist on remote host | Validate process on target host (`Get-Process -Id <pid>`) |
| No remote artifacts copied | Scanner produced no files or transfer failed | Check `analysis_metadata.remote_artifacts` and transport connectivity (SSH/WinRM) |

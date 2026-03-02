# LitterBox — Ansible DC + CIS Hardening

Promotes the LitterBox Windows Server 2025 VM to a domain controller and applies the CIS Level 1 benchmark via [ansible-lockdown/Windows-2025-CIS](https://github.com/ansible-lockdown/Windows-2025-CIS).

## Architecture

```
docker01 (Ansible control node)
  │
  │  WinRM HTTP  127.0.0.1:5985
  ▼
dockurr/windows container
  │
  │  KVM port-forward → VM port 5985
  ▼
Windows Server 2025 VM (vf-arsenal-litterbox)
  ├── LitterBox malware analysis platform (port 1337)
  └── Active Directory Domain Services (corp.vanguardforge.local)
```

## Prerequisites

1. **LitterBox first-boot complete** — install.ps1 must have run and WinRM must be enabled.
   Check: `curl -s http://127.0.0.1:1337/api/status` from docker01 returns JSON.

2. **Ansible installed** on docker01 (or wherever you run playbooks):
   ```bash
   pip install ansible pywinrm
   ```

3. **Galaxy dependencies**:
   ```bash
   ansible-galaxy install -r requirements.yml
   ```

4. **Inventory configured** — copy and populate:
   ```bash
   cp inventory.example.yml inventory.yml
   # Edit inventory.yml: set ansible_host, ansible_password, dc_domain_name
   ```

## From VanguardForge (recommended)

The kara script handles secrets and runs the full playbook automatically:

```bash
/opt/VanguardForge/scripts/kara/run_litterbox_dc.sh
```

Add `--dry-run` to preview without making changes.

## Manual Usage

```bash
cd /opt/LitterBox/ansible

# Install dependencies
ansible-galaxy install -r requirements.yml

# Test connectivity
ansible -i inventory.yml litterbox -m ansible.windows.win_ping

# Dry-run full setup (DC + CIS)
ansible-playbook -i inventory.yml playbooks/site.yml --check --diff \
  -e "dc_safe_mode_password=<DSRM_password>"

# Apply DC promotion only
ansible-playbook -i inventory.yml playbooks/setup-dc.yml \
  -e "dc_safe_mode_password=<DSRM_password>"

# Apply CIS hardening only (after DC is up)
ansible-playbook -i inventory.yml playbooks/cis-harden.yml
```

## CIS Level

- **Level 1** (default): Baseline controls — recommended; compatible with LitterBox operation.
- **Level 2**: Strict — may restrict some sandbox analysis features. Review with `--check --diff` first.

Set `win_cis_level: "2"` in `group_vars/windows.yml` to enable Level 2.

## Idempotency

All playbooks are safe to re-run. DC promotion is skipped if the domain already exists.

## Domain

Default: `corp.vanguardforge.local` (NetBIOS: `CORP`)

Override at runtime: `-e "dc_domain_name=your.domain.local"`

## Secrets

Store secrets in ansible-vault:
```bash
ansible-vault create group_vars/windows.yml
# Add: vault_litterbox_password: <password>
# Add: vault_dc_safe_mode_password: <DSRM_password>
```

Files listed in `.gitignore` are never committed to git.

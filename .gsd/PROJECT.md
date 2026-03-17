# LitterBox

## What This Is

LitterBox is a malware analysis sandbox for red teams, forked from BlackSnufkin/LitterBox. It provides static analysis (YARA, CheckPlz, Stringnalyzer), dynamic analysis (PE-Sieve, Moneta, Patriot, RedEdr, Hunt-Sleeping-Beacons, Hollows-Hunter), BYOVD driver analysis (HolyGrail), and similarity analysis (Blender + FuzzyHash). The platform runs as a Flask web app on port 1337 and executes Windows-native scanner binaries either locally, via Docker VM, or on remote Windows hosts over SSH/WinRM through Tailscale.

## Core Value

An LLM-driven copilot embedded in LitterBox that interprets analysis results, coaches operators on evasion improvements, and automates recurring analysis workflows — turning LitterBox from a passive scanning tool into an active analysis platform.

## Current State

- Flask web app with full static/dynamic/BYOVD analysis pipeline (v4.1.0)
- Fork is 11 commits ahead of upstream with remote execution framework (SSH + WinRM runners), credential wizard, Ansible playbooks, and 844 lines of tests
- GrumpyCats Python client library (`grumpycat.py`) provides programmatic access to all LitterBox API endpoints
- Docker setup uses Windows 10 VM via dockur/windows (switchable to Server 2025)
- Remote execution is architecturally complete but untested (no Windows targets on tailnet)
- M001 assessment milestone complete

## Architecture / Key Patterns

- **Flask app**: `litterbox.py` → `app/create_app()` → `app/routes.py`
- **Templates**: Jinja2 with Tailwind CSS, sidebar nav, dark theme
- **Scanners**: Windows `.exe` binaries called via `subprocess` or remote SSH/WinRM
- **Execution runners**: `LocalRunner`, `SshRemoteRunner`, `WinRmRemoteRunner` in `app/execution/runner.py`
- **Config**: `Config/config.yaml` (YAML safe dump)
- **Client library**: `GrumpyCats/grumpycat.py` (`LitterBoxClient` class)
- **Static assets**: `app/static/css/` (tailwind.min.css, style.css), `app/static/js/` (per-page JS)

## Capability Contract

See `.gsd/REQUIREMENTS.md` for the explicit capability contract, requirement status, and coverage mapping.

## Milestone Sequence

- [x] M001: Platform Assessment — Assess architecture, upstream delta, remote execution viability, and LLM integration opportunities
- [ ] M002: AI Copilot Agent — Embedded LLM agent with web chat, iterative evasion coaching, and scheduled analysis jobs

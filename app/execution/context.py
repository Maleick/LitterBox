import os
import uuid
from typing import Optional

from app.remote_credentials import (
    build_remote_identity,
    get_target_credentials,
    migrate_target_credentials,
    resolve_remote_env_path,
)

from .runner import SshRemoteRunner, WinRmRemoteRunner

DEFAULT_REMOTE_ENV_PATH = resolve_remote_env_path()


def resolve_target_transport(remote_config: dict, target_config: dict) -> str:
    configured = (target_config.get("transport") or remote_config.get("transport") or "ssh").strip().lower()
    return configured or "ssh"


def create_runner_for_target(
    target_id: str,
    target_config: dict,
    remote_config: dict,
    logger=None,
    remote_env_path: Optional[str] = None,
):
    transport = resolve_target_transport(remote_config, target_config)

    if transport == "ssh":
        return SshRemoteRunner(target_id=target_id, target_config=target_config, logger=logger)
    if transport != "winrm":
        raise ValueError(f"Unsupported remote transport '{transport}' for target '{target_id}'")

    env_path = resolve_remote_env_path(remote_env_path)
    _auto_migrate_domain_credentials(remote_config, env_path)

    credentials = get_target_credentials(env_path, target_id)
    remote_username = build_remote_identity(
        credentials.get("account_type", ""),
        credentials.get("username", ""),
        credentials.get("domain", ""),
    )
    remote_password = (credentials.get("password") or "").strip()
    remote_host = (credentials.get("host") or target_config.get("host") or "").strip()

    if not remote_host:
        raise RuntimeError(f"Remote target '{target_id}' is missing host configuration")
    if not remote_username or not remote_password:
        raise RuntimeError(
            f"Remote target '{target_id}' is missing WinRM credentials in .env.remote"
        )

    merged_target_config = dict(target_config)
    merged_target_config["host"] = remote_host

    return WinRmRemoteRunner(
        target_id=target_id,
        target_config=merged_target_config,
        username=remote_username,
        password=remote_password,
        logger=logger,
    )


def resolve_execution_context(
    config: dict,
    local_runner,
    execution_target: Optional[str] = None,
    file_path: Optional[str] = None,
    logger=None,
    remote_env_path: Optional[str] = None,
) -> dict:
    analysis_config = config.get("analysis", {})
    remote_config = analysis_config.get("remote", {})
    remote_enabled = bool(remote_config.get("enabled", False))
    local_fallback = bool(remote_config.get("local_fallback", True))

    context = {
        "runner": local_runner,
        "is_remote": False,
        "requested_target": execution_target,
        "active_target": "local",
        "scanner_paths": {},
        "staged_targets": {},
        "fallback_used": False,
        "warnings": [],
        "remote_session_dir": None,
        "transport": "local",
    }

    if not remote_enabled:
        return context

    target_id = execution_target or remote_config.get("default_target")
    if not target_id:
        context["warnings"].append(
            "Remote execution is enabled but no execution target was provided; using local execution"
        )
        context["fallback_used"] = True
        return context

    targets = remote_config.get("targets", {}) or {}
    target_config = targets.get(target_id)
    if not target_config:
        message = f"Remote execution target '{target_id}' is not configured"
        if local_fallback:
            context["warnings"].append(f"{message}; using local fallback")
            context["fallback_used"] = True
            return context
        raise ValueError(message)

    transport = resolve_target_transport(remote_config, target_config)

    try:
        runner = create_runner_for_target(
            target_id=target_id,
            target_config=target_config,
            remote_config=remote_config,
            logger=logger,
            remote_env_path=remote_env_path,
        )
    except Exception as exc:
        message = f"Remote target '{target_id}' initialization failed ({transport}): {str(exc)}"
        if local_fallback:
            context["warnings"].append(f"{message}; using local fallback")
            context["fallback_used"] = True
            return context
        raise RuntimeError(message)

    if not runner.check_connectivity():
        message = f"Remote target '{target_id}' is unreachable over {transport}"
        if local_fallback:
            context["warnings"].append(f"{message}; using local fallback")
            context["fallback_used"] = True
            return context
        raise RuntimeError(message)

    remote_workdir = target_config.get("remote_workdir", getattr(runner, "remote_workdir", "C:\\LitterBox\\RemoteExecution"))
    session_id = uuid.uuid4().hex[:12]
    session_dir = runner.join_path(remote_workdir, "runs", session_id)
    runner.ensure_directory(session_dir)

    context.update(
        {
            "runner": runner,
            "is_remote": True,
            "requested_target": execution_target or target_id,
            "active_target": target_id,
            "scanner_paths": target_config.get("scanner_paths", {}) or {},
            "remote_session_dir": session_dir,
            "transport": transport,
        }
    )

    if file_path:
        staged_file = runner.stage_file(
            local_path=file_path,
            remote_directory=runner.join_path(session_dir, "samples"),
        )
        context["staged_targets"][file_path] = staged_file

    return context


def execution_metadata(context: dict) -> dict:
    return {
        "execution_mode": "remote" if context.get("is_remote") else "local",
        "execution_target_requested": context.get("requested_target"),
        "execution_target_active": context.get("active_target"),
        "execution_fallback_used": context.get("fallback_used", False),
        "execution_warnings": context.get("warnings", []),
        "execution_transport": context.get("transport", "local"),
    }


def sync_remote_artifacts(context: dict, artifact_destination: Optional[str]):
    if not context.get("is_remote") or not artifact_destination:
        return None

    remote_directory = context.get("remote_session_dir")
    if not remote_directory:
        return None

    local_directory = os.path.join(artifact_destination, "remote_artifacts")
    copied_files = context["runner"].fetch_artifacts(
        remote_directory=remote_directory,
        local_directory=local_directory,
    )
    return {
        "remote_directory": remote_directory,
        "local_directory": local_directory,
        "copied_files": copied_files,
    }


def _auto_migrate_domain_credentials(remote_config: dict, env_path: str):
    targets = remote_config.get("targets", {}) or {}
    domain_target = targets.get("domain") or {}
    server_target = targets.get("server2025") or {}

    domain_host = (domain_target.get("host") or "").strip().lower()
    if not domain_host:
        return

    server_credentials = get_target_credentials(env_path, "server2025")
    server_host_candidates = {
        (server_target.get("host") or "").strip().lower(),
        (server_credentials.get("host") or "").strip().lower(),
    }
    if domain_host not in server_host_candidates:
        return

    domain_credentials = get_target_credentials(env_path, "domain")
    if (domain_credentials.get("username") or "").strip() and (domain_credentials.get("password") or "").strip():
        return

    migrate_target_credentials(
        path=env_path,
        from_target_id="server2025",
        to_target_id="domain",
        overwrite=False,
    )

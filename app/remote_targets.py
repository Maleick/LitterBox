import copy
import os
import re
import tempfile
from typing import Dict, List, Tuple

import yaml


ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
DEFAULT_CONFIG_CANDIDATES = [
    os.path.join(ROOT_DIR, "Config", "config.yaml"),
    os.path.join(ROOT_DIR, "config", "config.yaml"),
]


def resolve_config_path(path: str = "") -> str:
    requested = (path or "").strip()
    if requested:
        candidate_paths = [requested]
    else:
        env_path = (os.environ.get("LITTERBOX_CONFIG_PATH") or "").strip()
        candidate_paths = [env_path] if env_path else list(DEFAULT_CONFIG_CANDIDATES)

    for candidate in candidate_paths:
        expanded = os.path.abspath(os.path.expanduser(candidate))
        if os.path.exists(expanded):
            return expanded

    raise FileNotFoundError("Could not locate Config/config.yaml")


def load_config(path: str = "") -> Tuple[str, Dict]:
    resolved_path = resolve_config_path(path)
    with open(resolved_path, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}
    if not isinstance(config, dict):
        raise ValueError("Config root must be a mapping")
    return resolved_path, config


def save_config(path: str, config: Dict) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            yaml.safe_dump(config, temp_file, sort_keys=False)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def resolve_target_transport(remote_config: Dict, target_config: Dict) -> str:
    configured = (target_config.get("transport") or remote_config.get("transport") or "ssh").strip().lower()
    return configured or "ssh"


def list_winrm_targets(config: Dict) -> List[Dict[str, str]]:
    remote, targets = _remote_sections(config)
    items: List[Dict[str, str]] = []
    for target_id, target_cfg in targets.items():
        if not isinstance(target_cfg, dict):
            continue
        if resolve_target_transport(remote, target_cfg) != "winrm":
            continue
        host = ((target_cfg or {}).get("host") or "").strip()
        normalized_target = str(target_id).strip()
        items.append(
            {
                "target_id": normalized_target,
                "host": host,
                "label": host or normalized_target,
            }
        )
    return items


def derive_target_id_from_host(host: str) -> str:
    normalized_host = _normalize_host(host)
    first_label = normalized_host.split(".", 1)[0]
    target_id = re.sub(r"[^a-z0-9]+", "-", first_label).strip("-")
    if not target_id:
        raise ValueError("host does not produce a valid target_id")
    return target_id


def add_winrm_host_target(host: str, config_path: str = "") -> Dict:
    resolved_path, config = load_config(config_path)
    remote, targets = _remote_sections(config)

    template = targets.get("domain")
    if not isinstance(template, dict):
        raise ValueError("Cannot add host: domain target template is missing")

    normalized_host = _normalize_host(host)
    target_id = derive_target_id_from_host(normalized_host)

    existing_hosts = {
        ((target_cfg or {}).get("host") or "").strip().lower()
        for target_cfg in targets.values()
        if isinstance(target_cfg, dict)
    }
    if normalized_host in existing_hosts:
        raise ValueError(f"host '{normalized_host}' already exists")
    if target_id in targets:
        raise ValueError(f"target_id '{target_id}' already exists")

    cloned_target = copy.deepcopy(template)
    cloned_target["host"] = normalized_host
    targets[target_id] = cloned_target

    _ensure_default_target(remote, targets, preferred_target=target_id)
    save_config(resolved_path, config)

    return {
        "config_path": resolved_path,
        "config": config,
        "target": {
            "target_id": target_id,
            "host": normalized_host,
            "label": normalized_host,
        },
    }


def delete_winrm_host_target(target_id: str, config_path: str = "") -> Dict:
    resolved_path, config = load_config(config_path)
    remote, targets = _remote_sections(config)

    normalized_target = (target_id or "").strip()
    if not normalized_target:
        raise ValueError("target_id is required")
    if normalized_target not in targets:
        raise ValueError("Unknown target_id")

    target_cfg = targets.get(normalized_target) or {}
    if not isinstance(target_cfg, dict):
        raise ValueError("Target configuration is invalid")
    if resolve_target_transport(remote, target_cfg) != "winrm":
        raise ValueError("Only WinRM targets can be deleted from this wizard")

    winrm_target_ids = _sorted_winrm_target_ids(remote, targets)
    if len(winrm_target_ids) <= 1:
        raise ValueError("Cannot delete the last WinRM host target")

    removed_target = targets.pop(normalized_target, {})

    if (remote.get("default_target") or "").strip() == normalized_target:
        remaining_winrm = _sorted_winrm_target_ids(remote, targets)
        remote["default_target"] = remaining_winrm[0] if remaining_winrm else ""
    else:
        _ensure_default_target(remote, targets)

    save_config(resolved_path, config)

    return {
        "config_path": resolved_path,
        "config": config,
        "target": {
            "target_id": normalized_target,
            "host": ((removed_target or {}).get("host") or "").strip(),
            "label": ((removed_target or {}).get("host") or "").strip() or normalized_target,
        },
    }


def _remote_sections(config: Dict) -> Tuple[Dict, Dict]:
    analysis = config.setdefault("analysis", {})
    if not isinstance(analysis, dict):
        raise ValueError("analysis configuration must be a mapping")

    remote = analysis.setdefault("remote", {})
    if not isinstance(remote, dict):
        raise ValueError("analysis.remote configuration must be a mapping")

    targets = remote.setdefault("targets", {})
    if not isinstance(targets, dict):
        raise ValueError("analysis.remote.targets configuration must be a mapping")

    return remote, targets


def _normalize_host(host: str) -> str:
    normalized = (host or "").strip().lower()
    if not normalized:
        raise ValueError("host is required")
    if "://" in normalized or "/" in normalized or " " in normalized:
        raise ValueError("host must be a hostname without scheme, path, or spaces")
    return normalized


def _sorted_winrm_target_ids(remote: Dict, targets: Dict) -> List[str]:
    winrm_ids = []
    for target_id, target_cfg in targets.items():
        if not isinstance(target_cfg, dict):
            continue
        if resolve_target_transport(remote, target_cfg) == "winrm":
            winrm_ids.append(str(target_id).strip())
    return sorted([target_id for target_id in winrm_ids if target_id])


def _ensure_default_target(remote: Dict, targets: Dict, preferred_target: str = "") -> None:
    current_default = (remote.get("default_target") or "").strip()
    normalized_preferred = (preferred_target or "").strip()

    if normalized_preferred and normalized_preferred in targets:
        if not current_default or current_default not in targets:
            remote["default_target"] = normalized_preferred
            return

    if current_default and current_default in targets:
        return

    winrm_ids = _sorted_winrm_target_ids(remote, targets)
    if winrm_ids:
        remote["default_target"] = winrm_ids[0]
        return

    sorted_targets = sorted([str(target_id).strip() for target_id in targets.keys() if str(target_id).strip()])
    remote["default_target"] = sorted_targets[0] if sorted_targets else ""

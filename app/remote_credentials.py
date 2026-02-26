import os
import re
import tempfile
from datetime import datetime, timezone
from typing import Dict, Optional

TARGET_PREFIX = "LB_REMOTE_TARGET_"
TARGET_FIELDS = {
    "HOST": "host",
    "DOMAIN": "domain",
    "ACCOUNT_TYPE": "account_type",
    "USERNAME": "username",
    "PASSWORD": "password",
    "UPDATED_AT": "updated_at",
}
TARGET_KEY_PATTERN = re.compile(
    r"^LB_REMOTE_TARGET_([A-Z0-9_]+)_(HOST|DOMAIN|ACCOUNT_TYPE|USERNAME|PASSWORD|UPDATED_AT)$"
)
DEFAULT_REMOTE_ENV_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env.remote")
)


def resolve_remote_env_path(path: Optional[str] = None) -> str:
    candidate = ""
    if isinstance(path, str):
        candidate = path.strip()
    if not candidate:
        candidate = (os.environ.get("LITTERBOX_REMOTE_ENV_PATH") or "").strip()
    if not candidate:
        candidate = DEFAULT_REMOTE_ENV_PATH

    expanded = os.path.expanduser(candidate)
    if os.path.isabs(expanded):
        return os.path.abspath(expanded)
    return os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), expanded))


def normalize_target_id(target_id):
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", (target_id or "")).strip("_").upper()
    if not normalized:
        raise ValueError("target_id must contain at least one alphanumeric character")
    return normalized


def load_env_file(path):
    values = {}
    if not os.path.exists(path):
        return values

    with open(path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("export "):
                line = line[len("export ") :].strip()

            if "=" not in line:
                continue

            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            values[key] = _parse_env_value(raw_value.strip())

    return values


def upsert_target_credentials(path, target_id, payload):
    env_values = load_env_file(path)
    normalized_target = normalize_target_id(target_id)
    prefix = f"{TARGET_PREFIX}{normalized_target}_"

    env_values[f"{prefix}HOST"] = (payload.get("host") or "").strip()
    env_values[f"{prefix}DOMAIN"] = (payload.get("domain") or "").strip()
    env_values[f"{prefix}ACCOUNT_TYPE"] = (payload.get("account_type") or "").strip().lower()
    env_values[f"{prefix}USERNAME"] = (payload.get("username") or "").strip()
    env_values[f"{prefix}PASSWORD"] = payload.get("password") or ""
    env_values[f"{prefix}UPDATED_AT"] = datetime.now(timezone.utc).isoformat()

    _atomic_write_env_file(path, env_values)


def list_target_credentials(path):
    env_values = load_env_file(path)
    targets = {}

    for key, value in env_values.items():
        match = TARGET_KEY_PATTERN.match(key)
        if not match:
            continue

        target_id = match.group(1)
        field_key = match.group(2)
        field_name = TARGET_FIELDS[field_key]
        target_entry = targets.setdefault(
            target_id,
            {
                "host": "",
                "domain": "",
                "account_type": "",
                "username": "",
                "password": "",
                "updated_at": "",
            },
        )

        if field_name == "account_type" or field_name == "updated_at":
            target_entry[field_name] = value or ""
        elif field_name == "password":
            target_entry["password"] = "********" if value else ""
        else:
            target_entry[field_name] = _mask_value(value or "")

    return targets


def get_target_credentials(path, target_id):
    env_values = load_env_file(path)
    normalized_target = normalize_target_id(target_id)
    prefix = f"{TARGET_PREFIX}{normalized_target}_"
    return {
        "host": env_values.get(f"{prefix}HOST", ""),
        "domain": env_values.get(f"{prefix}DOMAIN", ""),
        "account_type": env_values.get(f"{prefix}ACCOUNT_TYPE", ""),
        "username": env_values.get(f"{prefix}USERNAME", ""),
        "password": env_values.get(f"{prefix}PASSWORD", ""),
        "updated_at": env_values.get(f"{prefix}UPDATED_AT", ""),
    }


def build_remote_identity(account_type, username, domain):
    normalized_account_type = (account_type or "").strip().lower()
    normalized_username = (username or "").strip()
    normalized_domain = (domain or "").strip()

    if not normalized_username:
        return ""
    if "\\" in normalized_username:
        return normalized_username
    if normalized_account_type == "domain":
        if normalized_domain:
            return f"{normalized_domain}\\{normalized_username}"
        return normalized_username
    return f".\\{normalized_username}"


def migrate_target_credentials(path, from_target_id, to_target_id, overwrite=False):
    from_data = get_target_credentials(path, from_target_id)
    if not _has_auth_material(from_data):
        return False

    to_data = get_target_credentials(path, to_target_id)
    if _has_auth_material(to_data) and not overwrite:
        return False

    payload = {
        "host": from_data.get("host", ""),
        "domain": from_data.get("domain", ""),
        "account_type": from_data.get("account_type", ""),
        "username": from_data.get("username", ""),
        "password": from_data.get("password", ""),
    }
    upsert_target_credentials(path, to_target_id, payload)
    return True


def delete_target_credentials(path, target_id):
    env_values = load_env_file(path)
    normalized_target = normalize_target_id(target_id)
    prefix = f"{TARGET_PREFIX}{normalized_target}_"
    keys_to_delete = [key for key in env_values if key.startswith(prefix)]

    if not keys_to_delete:
        return False

    for key in keys_to_delete:
        env_values.pop(key, None)
    _atomic_write_env_file(path, env_values)
    return True


def _has_auth_material(data: Dict[str, str]) -> bool:
    return bool((data.get("username") or "").strip() and (data.get("password") or "").strip())


def _atomic_write_env_file(path, env_values):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    lines = []
    for key in sorted(env_values.keys()):
        value = env_values[key]
        lines.append(f"{key}={_quote_env_value(value)}")
    output = "\n".join(lines) + ("\n" if lines else "")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            temp_file.write(output)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            try:
                os.fchmod(temp_file.fileno(), 0o600)
            except AttributeError:
                pass

        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _parse_env_value(raw_value):
    if not raw_value:
        return ""

    if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {"'", '"'}:
        body = raw_value[1:-1]
        if raw_value[0] == '"':
            body = (
                body.replace(r"\\", "\\")
                .replace(r"\"", '"')
                .replace(r"\n", "\n")
                .replace(r"\r", "\r")
                .replace(r"\t", "\t")
            )
        else:
            body = body.replace(r"\\", "\\").replace(r"\'", "'")
        return body

    return raw_value


def _quote_env_value(value):
    escaped = str(value).replace("\\", r"\\").replace('"', r"\"")
    escaped = escaped.replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")
    return f'"{escaped}"'


def _mask_value(value):
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"

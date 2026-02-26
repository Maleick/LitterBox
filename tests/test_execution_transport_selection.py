from app.execution import LocalRunner
from app.execution.context import create_runner_for_target, resolve_execution_context, resolve_target_transport
from app.remote_credentials import get_target_credentials, upsert_target_credentials


class DummyRemoteRunner:
    def __init__(self, connected=True):
        self.connected = connected

    def check_connectivity(self):
        return self.connected

    def join_path(self, *parts):
        return "\\".join([str(part).strip("\\") for part in parts if part])

    def ensure_directory(self, path):
        _ = path

    def stage_file(self, local_path, remote_directory):
        return f"{remote_directory}\\{local_path.split('/')[-1]}"


class DummyWinRmRunner:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_resolve_target_transport_prefers_target_override():
    remote_cfg = {"transport": "ssh"}
    target_cfg = {"transport": "winrm"}
    assert resolve_target_transport(remote_cfg, target_cfg) == "winrm"


def test_resolve_execution_context_local_when_remote_disabled():
    config = {"analysis": {"remote": {"enabled": False}}}
    context = resolve_execution_context(
        config=config,
        local_runner=LocalRunner(),
        execution_target=None,
        file_path=None,
    )
    assert context["is_remote"] is False
    assert context["active_target"] == "local"


def test_resolve_execution_context_remote_with_staging(monkeypatch):
    config = {
        "analysis": {
            "remote": {
                "enabled": True,
                "transport": "winrm",
                "default_target": "domain",
                "local_fallback": True,
                "targets": {
                    "domain": {
                        "transport": "winrm",
                        "host": "domain.nuthatch-chickadee.ts.net",
                        "remote_workdir": "C:\\LitterBox\\RemoteExecution",
                        "scanner_paths": {"yara": {"tool_path": "C:\\Yara\\yara64.exe"}},
                    }
                },
            }
        }
    }

    monkeypatch.setattr(
        "app.execution.context.create_runner_for_target",
        lambda **kwargs: DummyRemoteRunner(connected=True),
    )

    context = resolve_execution_context(
        config=config,
        local_runner=LocalRunner(),
        execution_target="domain",
        file_path="/tmp/sample.bin",
    )
    assert context["is_remote"] is True
    assert context["active_target"] == "domain"
    assert context["transport"] == "winrm"
    assert context["staged_targets"]["/tmp/sample.bin"].endswith("sample.bin")


def test_resolve_execution_context_falls_back_on_init_error(monkeypatch):
    config = {
        "analysis": {
            "remote": {
                "enabled": True,
                "default_target": "domain",
                "local_fallback": True,
                "targets": {"domain": {"host": "domain.nuthatch-chickadee.ts.net", "transport": "winrm"}},
            }
        }
    }

    def _raise(**kwargs):
        _ = kwargs
        raise RuntimeError("missing credentials")

    monkeypatch.setattr("app.execution.context.create_runner_for_target", _raise)

    context = resolve_execution_context(
        config=config,
        local_runner=LocalRunner(),
        execution_target="domain",
        file_path=None,
    )
    assert context["is_remote"] is False
    assert context["fallback_used"] is True
    assert "using local fallback" in " ".join(context["warnings"])


def test_create_runner_auto_migrates_domain_creds_from_env_mapping(monkeypatch, tmp_path):
    env_path = tmp_path / ".env.remote"
    upsert_target_credentials(
        str(env_path),
        "server2025",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "VANGUARD",
            "account_type": "domain",
            "username": "localuser",
            "password": "temporary-password",
        },
    )

    remote_config = {
        "transport": "winrm",
        "targets": {
            "domain": {"host": "domain.nuthatch-chickadee.ts.net", "transport": "winrm"},
            "server2025": {"host": "server2025.nuthatch-chickadee.ts.net", "transport": "ssh"},
        },
    }
    target_config = {
        "host": "domain.nuthatch-chickadee.ts.net",
        "transport": "winrm",
        "winrm_port": 5986,
        "winrm_scheme": "https",
    }

    monkeypatch.setattr("app.execution.context.WinRmRemoteRunner", DummyWinRmRunner)

    runner = create_runner_for_target(
        target_id="domain",
        target_config=target_config,
        remote_config=remote_config,
        remote_env_path=str(env_path),
    )
    migrated = get_target_credentials(str(env_path), "domain")

    assert isinstance(runner, DummyWinRmRunner)
    assert migrated["username"] == "localuser"
    assert migrated["password"] == "temporary-password"

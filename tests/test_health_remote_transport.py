from app import create_app


class DummyHealthRunner:
    def check_connectivity(self):
        return True

    def path_exists(self, path, is_dir=False):
        _ = path
        _ = is_dir
        return True


def test_health_reports_transport_specific_auth(monkeypatch):
    app = create_app()

    app.config["analysis"]["remote"] = {
        "enabled": True,
        "transport": "ssh",
        "default_target": "ssh_target",
        "local_fallback": False,
        "targets": {
            "ssh_target": {
                "transport": "ssh",
                "host": "ssh-target.local",
                "port": 22,
                "user": "analyst",
                "scanner_paths": {"yara": {"tool_path": "C:\\Tools\\yara64.exe"}},
            },
            "domain": {
                "transport": "winrm",
                "host": "domain-target.local",
                "winrm_port": 5986,
                "auth_mode": "ntlm",
                "scanner_paths": {"holygrail": {"tool_path": "C:\\Tools\\HolyGrail.exe"}},
            },
        },
    }

    monkeypatch.setattr("app.routes.create_runner_for_target", lambda **kwargs: DummyHealthRunner())

    client = app.test_client()
    response = client.get("/health")
    payload = response.get_json()
    remote_status = payload["configuration"]["remote_execution"]
    ssh_target = remote_status["targets"]["ssh_target"]
    winrm_target = remote_status["targets"]["domain"]

    assert ssh_target["transport"] == "ssh"
    assert ssh_target["ssh_auth"] is True
    assert ssh_target["winrm_auth"] is None

    assert winrm_target["transport"] == "winrm"
    assert winrm_target["winrm_auth"] is True
    assert winrm_target["ssh_auth"] is None

    assert ssh_target["scanner_paths"]["yara.tool_path"]["exists"] is True
    assert winrm_target["scanner_paths"]["holygrail.tool_path"]["exists"] is True

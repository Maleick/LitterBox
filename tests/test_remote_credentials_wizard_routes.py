import shutil

import yaml

from app import create_app
from app.remote_credentials import get_target_credentials


PROJECT_CONFIG_PATH = "/opt/LitterBox/Config/config.yaml"


def _localhost():
    return {"REMOTE_ADDR": "127.0.0.1"}


def _make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("LITTERBOX_WIZARD_TOKEN", "wizard-token")

    config_path = tmp_path / "config.yaml"
    shutil.copy(PROJECT_CONFIG_PATH, config_path)
    monkeypatch.setenv("LITTERBOX_CONFIG_PATH", str(config_path))

    env_path = tmp_path / ".env.remote"

    import app.routes as routes_module

    original_resolve_remote_env_path = routes_module.resolve_remote_env_path

    def _patched_resolve_remote_env_path(path=None):
        if path == "/opt/LitterBox/.env.remote":
            return str(env_path)
        return original_resolve_remote_env_path(path)

    monkeypatch.setattr(routes_module, "resolve_remote_env_path", _patched_resolve_remote_env_path)

    app = create_app()
    app.config["TESTING"] = True
    return app.test_client(), env_path, config_path


def _load_config(path):
    with open(path, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def test_wizard_get_shows_host_selector_without_env_path_ui(monkeypatch, tmp_path):
    client, env_path, _ = _make_client(monkeypatch, tmp_path)

    response = client.get("/setup/remote-credentials", environ_overrides=_localhost())
    assert response.status_code == 200

    body = response.get_data(as_text=True)
    assert str(env_path) not in body
    assert "Host Target" in body
    assert "Credential ENV Path" not in body
    assert "stored automatically by this LitterBox instance" in body
    assert 'option value="domain"' in body
    assert 'option value="win11"' not in body
    assert 'option value="server2025"' not in body


def test_wizard_save_and_delete_credentials_use_selected_host(monkeypatch, tmp_path):
    client, env_path, _ = _make_client(monkeypatch, tmp_path)

    save_response = client.post(
        "/setup/remote-credentials",
        data={
            "target_id": "domain",
            "domain": "VANGUARD",
            "account_type": "domain",
            "username": "domainuser",
            "password": "secret-password",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert save_response.status_code == 200

    saved_creds = get_target_credentials(str(env_path), "domain")
    assert saved_creds["host"] == "domain.nuthatch-chickadee.ts.net"
    assert saved_creds["username"] == "domainuser"
    assert saved_creds["password"] == "secret-password"

    delete_response = client.post(
        "/setup/remote-credentials/delete",
        data={
            "target_id": "domain",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert delete_response.status_code == 200

    deleted_creds = get_target_credentials(str(env_path), "domain")
    assert deleted_creds["username"] == ""
    assert deleted_creds["password"] == ""


def test_add_host_creates_target_and_rejects_duplicates(monkeypatch, tmp_path):
    client, _, config_path = _make_client(monkeypatch, tmp_path)

    add_response = client.post(
        "/setup/remote-credentials/hosts",
        data={
            "host": "server01.nuthatch-chickadee.ts.net",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert add_response.status_code == 200
    payload = add_response.get_json()
    assert payload["target"]["target_id"] == "server01"

    config = _load_config(config_path)
    targets = config["analysis"]["remote"]["targets"]
    assert "server01" in targets
    assert targets["server01"]["host"] == "server01.nuthatch-chickadee.ts.net"
    assert targets["server01"]["transport"] == "winrm"

    duplicate_host_response = client.post(
        "/setup/remote-credentials/hosts",
        data={
            "host": "server01.nuthatch-chickadee.ts.net",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert duplicate_host_response.status_code == 400

    duplicate_id_response = client.post(
        "/setup/remote-credentials/hosts",
        data={
            "host": "server01.other-zone.ts.net",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert duplicate_id_response.status_code == 400


def test_delete_host_removes_target_and_credentials(monkeypatch, tmp_path):
    client, env_path, config_path = _make_client(monkeypatch, tmp_path)

    add_response = client.post(
        "/setup/remote-credentials/hosts",
        data={
            "host": "server01.nuthatch-chickadee.ts.net",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert add_response.status_code == 200

    save_response = client.post(
        "/setup/remote-credentials",
        data={
            "target_id": "server01",
            "domain": "VANGUARD",
            "account_type": "local",
            "username": "localuser",
            "password": "secret-password",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert save_response.status_code == 200

    delete_response = client.post(
        "/setup/remote-credentials/hosts/delete",
        data={
            "target_id": "server01",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert delete_response.status_code == 200
    payload = delete_response.get_json()
    assert payload["deleted_credentials"] is True

    deleted_creds = get_target_credentials(str(env_path), "server01")
    assert deleted_creds["username"] == ""
    assert deleted_creds["password"] == ""

    config = _load_config(config_path)
    assert "server01" not in config["analysis"]["remote"]["targets"]


def test_delete_current_default_switches_to_remaining_winrm_target(monkeypatch, tmp_path):
    client, _, config_path = _make_client(monkeypatch, tmp_path)

    add_response = client.post(
        "/setup/remote-credentials/hosts",
        data={
            "host": "server01.nuthatch-chickadee.ts.net",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert add_response.status_code == 200

    config = _load_config(config_path)
    config["analysis"]["remote"]["default_target"] = "server01"
    with open(config_path, "w", encoding="utf-8") as config_file:
        yaml.safe_dump(config, config_file, sort_keys=False)

    delete_response = client.post(
        "/setup/remote-credentials/hosts/delete",
        data={
            "target_id": "server01",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert delete_response.status_code == 200

    updated_config = _load_config(config_path)
    assert updated_config["analysis"]["remote"]["default_target"] == "domain"


def test_delete_last_winrm_host_is_blocked(monkeypatch, tmp_path):
    client, _, _ = _make_client(monkeypatch, tmp_path)

    response = client.post(
        "/setup/remote-credentials/hosts/delete",
        data={
            "target_id": "domain",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert response.status_code == 400


def test_wizard_delete_rejects_unknown_target(monkeypatch, tmp_path):
    client, _, _ = _make_client(monkeypatch, tmp_path)

    response = client.post(
        "/setup/remote-credentials/delete",
        data={
            "target_id": "unknown-target",
            "token": "wizard-token",
        },
        environ_overrides=_localhost(),
    )
    assert response.status_code == 400

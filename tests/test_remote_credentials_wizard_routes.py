from app import create_app
from app.remote_credentials import get_target_credentials, upsert_target_credentials


def _make_client(monkeypatch):
    monkeypatch.setenv("LITTERBOX_WIZARD_TOKEN", "wizard-token")
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _localhost():
    return {"REMOTE_ADDR": "127.0.0.1"}


def test_wizard_get_uses_custom_env_path(monkeypatch, tmp_path):
    client = _make_client(monkeypatch)
    env_path = tmp_path / ".env.remote.custom"
    upsert_target_credentials(
        str(env_path),
        "win11",
        {
            "host": "win11.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "localuser",
            "password": "pw",
        },
    )

    response = client.get(
        "/setup/remote-credentials",
        query_string={"env_path": str(env_path)},
        environ_overrides=_localhost(),
    )
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert str(env_path) in body
    assert "Remote Credential Setup" in body


def test_wizard_save_and_delete_with_custom_env_path(monkeypatch, tmp_path):
    client = _make_client(monkeypatch)
    env_path = tmp_path / ".env.remote.custom"

    save_response = client.post(
        "/setup/remote-credentials",
        data={
            "target_id": "domain",
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "localuser",
            "password": "secret-password",
            "token": "wizard-token",
            "env_path": str(env_path),
        },
        environ_overrides=_localhost(),
    )
    assert save_response.status_code == 200
    saved_creds = get_target_credentials(str(env_path), "domain")
    assert saved_creds["username"] == "localuser"
    assert saved_creds["password"] == "secret-password"

    delete_response = client.post(
        "/setup/remote-credentials/delete",
        data={
            "target_id": "domain",
            "token": "wizard-token",
            "env_path": str(env_path),
        },
        environ_overrides=_localhost(),
    )
    assert delete_response.status_code == 200
    deleted_creds = get_target_credentials(str(env_path), "domain")
    assert deleted_creds["username"] == ""
    assert deleted_creds["password"] == ""


def test_wizard_delete_rejects_unknown_target(monkeypatch, tmp_path):
    client = _make_client(monkeypatch)
    env_path = tmp_path / ".env.remote.custom"

    response = client.post(
        "/setup/remote-credentials/delete",
        data={
            "target_id": "unknown-target",
            "token": "wizard-token",
            "env_path": str(env_path),
        },
        environ_overrides=_localhost(),
    )
    assert response.status_code == 400

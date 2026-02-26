from app.remote_credentials import (
    build_remote_identity,
    delete_target_credentials,
    get_target_credentials,
    migrate_target_credentials,
    resolve_remote_env_path,
    upsert_target_credentials,
)


def test_build_remote_identity_domain_and_local():
    assert build_remote_identity("domain", "analyst", "LAB") == "LAB\\analyst"
    assert build_remote_identity("local", "analyst", "") == ".\\analyst"
    assert build_remote_identity("domain", "LAB\\analyst", "LAB") == "LAB\\analyst"


def test_get_target_credentials_round_trip(tmp_path):
    env_path = tmp_path / ".env.remote"
    upsert_target_credentials(
        str(env_path),
        "domain",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "localuser",
            "password": "temp-password",
        },
    )

    creds = get_target_credentials(str(env_path), "domain")
    assert creds["host"] == "domain.nuthatch-chickadee.ts.net"
    assert creds["domain"] == "LAB"
    assert creds["account_type"] == "domain"
    assert creds["username"] == "localuser"
    assert creds["password"] == "temp-password"
    assert creds["updated_at"]


def test_migrate_target_credentials_preserves_source(tmp_path):
    env_path = tmp_path / ".env.remote"
    upsert_target_credentials(
        str(env_path),
        "server2025",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "VANGUARD",
            "account_type": "domain",
            "username": "localuser",
            "password": "initial-password",
        },
    )

    migrated = migrate_target_credentials(
        str(env_path),
        from_target_id="server2025",
        to_target_id="domain",
        overwrite=False,
    )
    assert migrated is True

    source = get_target_credentials(str(env_path), "server2025")
    dest = get_target_credentials(str(env_path), "domain")

    assert source["username"] == "localuser"
    assert dest["username"] == "localuser"
    assert dest["password"] == "initial-password"


def test_migrate_does_not_overwrite_without_flag(tmp_path):
    env_path = tmp_path / ".env.remote"
    upsert_target_credentials(
        str(env_path),
        "server2025",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "source-user",
            "password": "source-password",
        },
    )
    upsert_target_credentials(
        str(env_path),
        "domain",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "dest-user",
            "password": "dest-password",
        },
    )

    migrated = migrate_target_credentials(
        str(env_path),
        from_target_id="server2025",
        to_target_id="domain",
        overwrite=False,
    )
    assert migrated is False
    dest = get_target_credentials(str(env_path), "domain")
    assert dest["username"] == "dest-user"


def test_delete_target_credentials_removes_only_selected_target(tmp_path):
    env_path = tmp_path / ".env.remote"
    upsert_target_credentials(
        str(env_path),
        "win11",
        {
            "host": "win11.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "alpha",
            "password": "pass-one",
        },
    )
    upsert_target_credentials(
        str(env_path),
        "domain",
        {
            "host": "domain.nuthatch-chickadee.ts.net",
            "domain": "LAB",
            "account_type": "domain",
            "username": "beta",
            "password": "pass-two",
        },
    )

    deleted = delete_target_credentials(str(env_path), "domain")
    assert deleted is True

    domain_creds = get_target_credentials(str(env_path), "domain")
    win11_creds = get_target_credentials(str(env_path), "win11")
    assert domain_creds["username"] == ""
    assert domain_creds["password"] == ""
    assert win11_creds["username"] == "alpha"
    assert win11_creds["password"] == "pass-one"


def test_resolve_remote_env_path_prefers_explicit_over_env(monkeypatch, tmp_path):
    env_default = tmp_path / "from-env.env"
    explicit_path = tmp_path / "explicit.env"
    monkeypatch.setenv("LITTERBOX_REMOTE_ENV_PATH", str(env_default))

    assert resolve_remote_env_path() == str(env_default.resolve())
    assert resolve_remote_env_path(str(explicit_path)) == str(explicit_path.resolve())

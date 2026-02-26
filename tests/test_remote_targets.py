import shutil

import yaml

from app.remote_targets import (
    add_winrm_host_target,
    delete_winrm_host_target,
    derive_target_id_from_host,
    load_config,
)


PROJECT_CONFIG_PATH = "/opt/LitterBox/Config/config.yaml"


def _copy_config(tmp_path):
    config_path = tmp_path / "config.yaml"
    shutil.copy(PROJECT_CONFIG_PATH, config_path)
    return config_path


def _save_config(path, config):
    with open(path, "w", encoding="utf-8") as config_file:
        yaml.safe_dump(config, config_file, sort_keys=False)


def test_derive_target_id_from_first_label():
    assert derive_target_id_from_host("domain.nuthatch-chickadee.ts.net") == "domain"
    assert derive_target_id_from_host("server-01.lab.local") == "server-01"


def test_add_host_clones_domain_template_and_sets_default_if_invalid(tmp_path):
    config_path = _copy_config(tmp_path)
    _, config = load_config(str(config_path))
    config["analysis"]["remote"]["default_target"] = "missing-target"
    _save_config(config_path, config)

    result = add_winrm_host_target("server01.nuthatch-chickadee.ts.net", config_path=str(config_path))
    target = result["target"]
    assert target["target_id"] == "server01"

    _, updated_config = load_config(str(config_path))
    remote = updated_config["analysis"]["remote"]
    targets = remote["targets"]

    assert remote["default_target"] == "server01"
    assert targets["server01"]["host"] == "server01.nuthatch-chickadee.ts.net"
    assert targets["server01"]["transport"] == "winrm"
    assert targets["server01"]["scanner_paths"] == targets["domain"]["scanner_paths"]


def test_delete_host_switches_default_to_remaining_winrm_target(tmp_path):
    config_path = _copy_config(tmp_path)
    add_winrm_host_target("server01.nuthatch-chickadee.ts.net", config_path=str(config_path))

    _, config = load_config(str(config_path))
    config["analysis"]["remote"]["default_target"] = "server01"
    _save_config(config_path, config)

    delete_winrm_host_target("server01", config_path=str(config_path))
    _, updated_config = load_config(str(config_path))

    assert updated_config["analysis"]["remote"]["default_target"] == "domain"
    assert "server01" not in updated_config["analysis"]["remote"]["targets"]


def test_delete_last_winrm_target_is_rejected(tmp_path):
    config_path = _copy_config(tmp_path)

    try:
        delete_winrm_host_target("domain", config_path=str(config_path))
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "last WinRM host target" in str(exc)

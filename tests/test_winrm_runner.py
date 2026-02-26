import base64
import re

from app.execution import runner as runner_module
from app.execution.runner import CommandResult, WinRmRemoteRunner


class FakeWinRmResponse:
    def __init__(self, status_code=0, std_out=b"", std_err=b""):
        self.status_code = status_code
        self.std_out = std_out
        self.std_err = std_err


class FakeWinRmSession:
    def __init__(self, endpoint, auth, transport, server_cert_validation):
        self.endpoint = endpoint
        self.auth = auth
        self.transport = transport
        self.server_cert_validation = server_cert_validation
        self.scripts = []

    def run_ps(self, script):
        self.scripts.append(script)
        if "Write-Output 'ok'" in script:
            return FakeWinRmResponse(status_code=0, std_out=b"ok\n")
        return FakeWinRmResponse(status_code=0, std_out=b"done\n")


def test_run_command_uses_pywinrm_session(monkeypatch):
    class FakeWinRmModule:
        Session = FakeWinRmSession

    monkeypatch.setattr(runner_module, "winrm", FakeWinRmModule)

    runner = WinRmRemoteRunner(
        target_id="domain",
        target_config={"host": "domain.nuthatch-chickadee.ts.net", "winrm_scheme": "https"},
        username="LAB\\localuser",
        password="temp-password",
    )

    result = runner.run_command("Write-Output 'ok'", cwd="C:\\LitterBox")
    assert result.returncode == 0
    assert "ok" in result.stdout
    assert runner._session.endpoint == "https://domain.nuthatch-chickadee.ts.net:5986/wsman"
    assert runner._session.auth == ("LAB\\localuser", "temp-password")


def test_path_and_pid_process_helpers(monkeypatch):
    class FakeWinRmModule:
        Session = FakeWinRmSession

    monkeypatch.setattr(runner_module, "winrm", FakeWinRmModule)
    runner = WinRmRemoteRunner(
        target_id="domain",
        target_config={"host": "domain.nuthatch-chickadee.ts.net", "winrm_scheme": "https"},
        username="LAB\\localuser",
        password="temp-password",
    )

    def fake_run_command(command, timeout=None, shell=True, cwd=None):
        _ = timeout
        _ = shell
        _ = cwd
        if "Test-Path" in command:
            return CommandResult(stdout="", stderr="", returncode=0)
        if "Get-Process" in command:
            return CommandResult(stdout="", stderr="", returncode=0)
        if "Start-Process" in command:
            return CommandResult(stdout="1234\n", stderr="", returncode=0)
        if "Stop-Process" in command:
            return CommandResult(stdout="", stderr="", returncode=0)
        return CommandResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(runner, "run_command", fake_run_command)
    assert runner.path_exists("C:\\LitterBox\\tool.exe") is True
    assert runner.validate_pid(1234) is True
    started = runner.start_process("C:\\LitterBox\\sample.exe", args=["--x"], cwd="C:\\LitterBox")
    assert started["pid"] == 1234
    runner.terminate_process({"pid": 1234})


def test_stage_and_fetch_artifacts_chunked(monkeypatch, tmp_path):
    class FakeWinRmModule:
        Session = FakeWinRmSession

    monkeypatch.setattr(runner_module, "winrm", FakeWinRmModule)
    runner = WinRmRemoteRunner(
        target_id="domain",
        target_config={"host": "domain.nuthatch-chickadee.ts.net", "winrm_scheme": "https"},
        username="LAB\\localuser",
        password="temp-password",
    )

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcdef")

    artifact_payload = b"hello world"
    remote_artifact = "C:\\LitterBox\\RemoteExecution\\runs\\abc\\out.txt"

    def fake_run_command(command, timeout=None, shell=True, cwd=None):
        _ = timeout
        _ = shell
        _ = cwd

        if "Get-ChildItem -LiteralPath" in command:
            return CommandResult(
                stdout=f"{remote_artifact}|{len(artifact_payload)}\n",
                stderr="",
                returncode=0,
            )
        if "[Convert]::ToBase64String" in command:
            match = re.search(r"\$offset = (\d+)", command)
            offset = int(match.group(1)) if match else 0
            match = re.search(r"\$length = (\d+)", command)
            length = int(match.group(1)) if match else len(artifact_payload)
            chunk = artifact_payload[offset : offset + length]
            return CommandResult(stdout=base64.b64encode(chunk).decode("ascii"), stderr="", returncode=0)

        return CommandResult(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(runner, "run_command", fake_run_command)

    remote_path = runner.stage_file(str(sample), "C:\\LitterBox\\RemoteExecution\\runs\\abc\\samples")
    assert remote_path.endswith("sample.bin")

    copied = runner.fetch_artifacts("C:\\LitterBox\\RemoteExecution\\runs\\abc", str(tmp_path / "artifacts"))
    assert len(copied) == 1
    assert open(copied[0], "rb").read() == artifact_payload

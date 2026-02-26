import base64
import os
import re
import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import psutil
try:
    import winrm
except Exception:  # pragma: no cover - tested via fallback branch
    winrm = None


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class ExecutionRunner(ABC):
    def __init__(self, logger=None):
        self.logger = logger

    @property
    @abstractmethod
    def mode(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run_command(
        self,
        command: Any,
        timeout: Optional[float] = None,
        shell: bool = True,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        raise NotImplementedError

    def check_connectivity(self) -> bool:
        return True

    def join_path(self, *parts: str) -> str:
        return os.path.join(*parts)

    def ensure_directory(self, path: str):
        os.makedirs(path, exist_ok=True)

    def stage_file(self, local_path: str, remote_directory: str) -> str:
        return local_path

    def fetch_artifacts(self, remote_directory: str, local_directory: str) -> List[str]:
        return []

    @abstractmethod
    def path_exists(self, path: str, is_dir: bool = False) -> bool:
        raise NotImplementedError

    @abstractmethod
    def validate_pid(self, pid: int) -> bool:
        raise NotImplementedError

    @abstractmethod
    def start_process(self, executable: str, args: Optional[Sequence[str]] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def collect_process_output(self, handle: Dict[str, Any], timeout: float = 1) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def terminate_process(self, handle: Dict[str, Any]):
        raise NotImplementedError


class LocalRunner(ExecutionRunner):
    @property
    def mode(self) -> str:
        return "local"

    def run_command(
        self,
        command: Any,
        timeout: Optional[float] = None,
        shell: bool = True,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        completed = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return CommandResult(
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            returncode=completed.returncode,
        )

    def path_exists(self, path: str, is_dir: bool = False) -> bool:
        if is_dir:
            return os.path.isdir(path)
        return os.path.isfile(path)

    def validate_pid(self, pid: int) -> bool:
        try:
            process = psutil.Process(int(pid))
            return process.is_running()
        except (psutil.NoSuchProcess, ValueError):
            return False

    def start_process(self, executable: str, args: Optional[Sequence[str]] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
        command = [executable]
        if args:
            command.extend(args)

        popen_kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "bufsize": 1,
            "text": True,
            "cwd": cwd,
        }

        if os.name == "nt" and hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            popen_kwargs["startupinfo"] = startupinfo

        process = subprocess.Popen(command, **popen_kwargs)
        return {"process": process, "pid": process.pid}

    def collect_process_output(self, handle: Dict[str, Any], timeout: float = 1) -> Dict[str, Any]:
        process = handle.get("process")
        if process is None:
            return {
                "stdout": "",
                "stderr": "",
                "had_output": False,
                "output_truncated": False,
                "error": "No process handle available",
            }

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            stdout = stdout or ""
            stderr = stderr or ""
            return {
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "had_output": bool(stdout.strip() or stderr.strip()),
                "output_truncated": False,
            }
        except subprocess.TimeoutExpired:
            self.terminate_process(handle)
            stdout, stderr = process.communicate()
            stdout = stdout or ""
            stderr = stderr or ""
            return {
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "had_output": bool(stdout.strip() or stderr.strip()),
                "output_truncated": False,
                "note": "Process killed after timeout",
            }

    def terminate_process(self, handle: Dict[str, Any]):
        process = handle.get("process")
        pid = handle.get("pid")

        if pid is None and process is not None:
            pid = process.pid
        if pid is None:
            return

        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        _, alive = psutil.wait_procs(children, timeout=3)
        for child in alive:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        try:
            parent.terminate()
            parent.wait(timeout=3)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except psutil.TimeoutExpired:
            try:
                parent.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


class SshRemoteRunner(ExecutionRunner):
    def __init__(self, target_id: str, target_config: Dict[str, Any], logger=None):
        super().__init__(logger=logger)
        self.target_id = target_id
        self.target_config = target_config
        self.host = target_config.get("host")
        self.port = int(target_config.get("port", 22))
        self.user = target_config.get("user")
        self.ssh_key_path = target_config.get("ssh_key_path")
        self.remote_workdir = target_config.get("remote_workdir", "C:\\LitterBox\\RemoteExecution")

        if not self.host or not self.user:
            raise ValueError(f"Remote target '{target_id}' is missing required host/user configuration")

    @property
    def mode(self) -> str:
        return "remote"

    def join_path(self, *parts: str) -> str:
        cleaned: List[str] = []
        for index, part in enumerate(parts):
            if not part:
                continue
            normalized = str(part).replace("/", "\\")
            if index == 0:
                cleaned.append(normalized.rstrip("\\"))
            else:
                cleaned.append(normalized.strip("\\"))
        return "\\".join(cleaned)

    def _ssh_base(self) -> List[str]:
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=8",
            "-p",
            str(self.port),
        ]
        if self.ssh_key_path:
            command.extend(["-i", self.ssh_key_path])
        command.append(f"{self.user}@{self.host}")
        return command

    def _scp_base(self) -> List[str]:
        command = [
            "scp",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=8",
            "-P",
            str(self.port),
        ]
        if self.ssh_key_path:
            command.extend(["-i", self.ssh_key_path])
        return command

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _to_scp_path(path: str) -> str:
        normalized = path.replace("\\", "/")
        drive_match = re.match(r"^([A-Za-z]):/(.*)$", normalized)
        if drive_match:
            drive = drive_match.group(1)
            remainder = drive_match.group(2)
            if remainder:
                return f"/{drive}:/{remainder}"
            return f"/{drive}:/"
        return normalized

    @staticmethod
    def _normalize_command(command: Any, shell: bool) -> str:
        if isinstance(command, str):
            return command
        if isinstance(command, (list, tuple)):
            if shell:
                return " ".join(command)
            return " ".join(shlex.quote(str(item)) for item in command)
        return str(command)

    def run_command(
        self,
        command: Any,
        timeout: Optional[float] = None,
        shell: bool = True,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        script = self._normalize_command(command, shell=shell)
        if cwd:
            script = f"Set-Location -LiteralPath {self._ps_quote(cwd)}; {script}"

        remote_command = (
            "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
            + shlex.quote(script)
        )
        completed = subprocess.run(
            self._ssh_base() + [remote_command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            returncode=completed.returncode,
        )

    def check_connectivity(self) -> bool:
        try:
            result = self.run_command("Write-Output 'ok'", timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def ensure_directory(self, path: str):
        result = self.run_command(
            f"New-Item -ItemType Directory -Path {self._ps_quote(path)} -Force | Out-Null",
            timeout=20,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to create remote directory '{path}' on target '{self.target_id}': {result.stderr.strip()}"
            )

    def stage_file(self, local_path: str, remote_directory: str) -> str:
        self.ensure_directory(remote_directory)
        file_name = os.path.basename(local_path)
        remote_path = self.join_path(remote_directory, file_name)
        destination = f"{self.user}@{self.host}:{self._to_scp_path(remote_path)}"
        completed = subprocess.run(
            self._scp_base() + [local_path, destination],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"Failed to stage file to '{self.target_id}': {completed.stderr.strip() or completed.stdout.strip()}"
            )
        return remote_path

    def fetch_artifacts(self, remote_directory: str, local_directory: str) -> List[str]:
        os.makedirs(local_directory, exist_ok=True)
        source = f"{self.user}@{self.host}:{self._to_scp_path(remote_directory)}/*"
        completed = subprocess.run(
            self._scp_base() + ["-r", source, local_directory],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            if self.logger:
                self.logger.debug(
                    "Artifact sync skipped for target %s: %s",
                    self.target_id,
                    completed.stderr.strip() or completed.stdout.strip(),
                )
            return []

        copied_files: List[str] = []
        for root, _, files in os.walk(local_directory):
            for filename in files:
                copied_files.append(os.path.join(root, filename))
        return copied_files

    def path_exists(self, path: str, is_dir: bool = False) -> bool:
        path_type = "Container" if is_dir else "Leaf"
        result = self.run_command(
            (
                f"if (Test-Path -Path {self._ps_quote(path)} -PathType {path_type}) "
                "{ exit 0 } else { exit 1 }"
            ),
            timeout=15,
        )
        return result.returncode == 0

    def validate_pid(self, pid: int) -> bool:
        result = self.run_command(
            f"if (Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
            timeout=15,
        )
        return result.returncode == 0

    def start_process(self, executable: str, args: Optional[Sequence[str]] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
        escaped_args = [self._ps_quote(str(item)) for item in (args or [])]
        args_array = "@(" + ", ".join(escaped_args) + ")"

        parts: List[str] = []
        if cwd:
            parts.append(f"Set-Location -LiteralPath {self._ps_quote(cwd)}")
        parts.extend(
            [
                f"$p = Start-Process -FilePath {self._ps_quote(executable)} -ArgumentList {args_array} -PassThru",
                "Start-Sleep -Milliseconds 250",
                "if ($null -eq $p -or $null -eq $p.Id) { exit 1 }",
                "Write-Output $p.Id",
            ]
        )

        result = self.run_command("; ".join(parts), timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Unable to start remote process")

        pid = None
        for line in (result.stdout or "").splitlines():
            stripped = line.strip()
            if stripped.isdigit():
                pid = int(stripped)
        if pid is None:
            raise RuntimeError(f"Unable to parse remote process PID from output: {result.stdout.strip()}")

        return {"pid": pid}

    def collect_process_output(self, handle: Dict[str, Any], timeout: float = 1) -> Dict[str, Any]:
        _ = timeout
        return {
            "stdout": "",
            "stderr": "",
            "had_output": False,
            "output_truncated": False,
            "note": "Remote process output streaming is not available for detached execution",
        }

    def terminate_process(self, handle: Dict[str, Any]):
        pid = handle.get("pid")
        if pid is None:
            return
        self.run_command(
            f"Stop-Process -Id {int(pid)} -Force -ErrorAction SilentlyContinue",
            timeout=15,
        )


class WinRmRemoteRunner(ExecutionRunner):
    TRANSFER_CHUNK_SIZE = 8192

    def __init__(
        self,
        target_id: str,
        target_config: Dict[str, Any],
        username: str,
        password: str,
        logger=None,
    ):
        super().__init__(logger=logger)
        self.target_id = target_id
        self.target_config = target_config
        self.host = target_config.get("host")
        self.port = int(target_config.get("winrm_port", target_config.get("port", 5986)))
        self.scheme = (target_config.get("winrm_scheme") or "https").strip().lower()
        self.auth_mode = (target_config.get("auth_mode") or "ntlm").strip().lower()
        self.server_cert_validation = bool(target_config.get("server_cert_validation", False))
        self.remote_workdir = target_config.get("remote_workdir", "C:\\LitterBox\\RemoteExecution")
        self.username = username
        self.password = password
        self._session = None

        if not self.host:
            raise ValueError(f"Remote target '{target_id}' is missing required host configuration")
        if not self.username or not self.password:
            raise ValueError(f"Remote target '{target_id}' is missing WinRM credentials")
        if self.scheme not in {"http", "https"}:
            raise ValueError(f"Remote target '{target_id}' has invalid WinRM scheme '{self.scheme}'")

    @property
    def mode(self) -> str:
        return "remote"

    def join_path(self, *parts: str) -> str:
        cleaned: List[str] = []
        for index, part in enumerate(parts):
            if not part:
                continue
            normalized = str(part).replace("/", "\\")
            if index == 0:
                cleaned.append(normalized.rstrip("\\"))
            else:
                cleaned.append(normalized.strip("\\"))
        return "\\".join(cleaned)

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def _normalize_command(command: Any, shell: bool) -> str:
        if isinstance(command, str):
            return command
        if isinstance(command, (list, tuple)):
            if shell:
                return " ".join(str(item) for item in command)
            return " ".join(shlex.quote(str(item)) for item in command)
        return str(command)

    @property
    def endpoint(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/wsman"

    def _session_or_raise(self):
        if winrm is None:
            raise RuntimeError("pywinrm is not installed; install dependency to use WinRM transport")
        if self._session is None:
            cert_validation = "validate" if self.server_cert_validation else "ignore"
            self._session = winrm.Session(
                self.endpoint,
                auth=(self.username, self.password),
                transport=self.auth_mode,
                server_cert_validation=cert_validation,
            )
        return self._session

    def run_command(
        self,
        command: Any,
        timeout: Optional[float] = None,
        shell: bool = True,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        _ = timeout
        script = self._normalize_command(command, shell=shell)
        if cwd:
            script = f"Set-Location -LiteralPath {self._ps_quote(cwd)}; {script}"

        session = self._session_or_raise()
        result = session.run_ps(script)

        stdout = result.std_out.decode("utf-8", errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out or "")
        stderr = result.std_err.decode("utf-8", errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err or "")
        return CommandResult(stdout=stdout, stderr=stderr, returncode=int(result.status_code))

    def check_connectivity(self) -> bool:
        try:
            result = self.run_command("Write-Output 'ok'")
            return result.returncode == 0
        except Exception:
            return False

    def ensure_directory(self, path: str):
        result = self.run_command(
            f"New-Item -ItemType Directory -Path {self._ps_quote(path)} -Force | Out-Null",
            timeout=20,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to create remote directory '{path}' on target '{self.target_id}': {result.stderr.strip()}"
            )

    def stage_file(self, local_path: str, remote_directory: str) -> str:
        self.ensure_directory(remote_directory)
        file_name = os.path.basename(local_path)
        remote_path = self.join_path(remote_directory, file_name)
        quoted_remote = self._ps_quote(remote_path)

        initialize_result = self.run_command(
            (
                f"$path = {quoted_remote}; "
                "$parent = [System.IO.Path]::GetDirectoryName($path); "
                "if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }; "
                "[System.IO.File]::WriteAllBytes($path, [byte[]]@())"
            ),
            timeout=60,
        )
        if initialize_result.returncode != 0:
            raise RuntimeError(
                f"Failed to initialize remote file on '{self.target_id}': "
                f"{initialize_result.stderr.strip() or initialize_result.stdout.strip()}"
            )

        with open(local_path, "rb") as local_file:
            while True:
                chunk = local_file.read(self.TRANSFER_CHUNK_SIZE)
                if not chunk:
                    break
                b64_chunk = base64.b64encode(chunk).decode("ascii")
                write_result = self.run_command(
                    (
                        f"$bytes = [Convert]::FromBase64String({self._ps_quote(b64_chunk)}); "
                        f"$stream = [System.IO.File]::Open({quoted_remote}, [System.IO.FileMode]::Append, "
                        "[System.IO.FileAccess]::Write, [System.IO.FileShare]::Read); "
                        "$stream.Write($bytes, 0, $bytes.Length); "
                        "$stream.Close()"
                    ),
                    timeout=60,
                )
                if write_result.returncode != 0:
                    raise RuntimeError(
                        f"Failed to upload file chunk to '{self.target_id}': "
                        f"{write_result.stderr.strip() or write_result.stdout.strip()}"
                    )
        return remote_path

    def fetch_artifacts(self, remote_directory: str, local_directory: str) -> List[str]:
        os.makedirs(local_directory, exist_ok=True)
        list_result = self.run_command(
            (
                f"Get-ChildItem -LiteralPath {self._ps_quote(remote_directory)} -Recurse -File "
                "| ForEach-Object { \"$($_.FullName)|$($_.Length)\" }"
            ),
            timeout=120,
        )
        if list_result.returncode != 0:
            if self.logger:
                self.logger.debug(
                    "Artifact listing skipped for target %s: %s",
                    self.target_id,
                    list_result.stderr.strip() or list_result.stdout.strip(),
                )
            return []

        copied_files: List[str] = []
        prefix = remote_directory.rstrip("\\/")
        normalized_prefix = prefix.lower()
        entries = [line.strip() for line in (list_result.stdout or "").splitlines() if line.strip()]
        for entry in entries:
            if "|" not in entry:
                continue
            remote_file, length_str = entry.rsplit("|", 1)
            remote_file = remote_file.strip()
            if not remote_file:
                continue

            try:
                total_size = int(length_str.strip())
            except ValueError:
                continue

            relative = remote_file
            if remote_file.lower().startswith(normalized_prefix):
                relative = remote_file[len(prefix):].lstrip("\\/")
            local_path = os.path.join(local_directory, relative.replace("\\", os.sep))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            with open(local_path, "wb") as destination:
                offset = 0
                while offset < total_size:
                    length = min(self.TRANSFER_CHUNK_SIZE, total_size - offset)
                    chunk_result = self.run_command(
                        (
                            f"$path = {self._ps_quote(remote_file)}; "
                            f"$offset = {offset}; "
                            f"$length = {length}; "
                            "$stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, "
                            "[System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); "
                            "$stream.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null; "
                            "$buffer = New-Object byte[] $length; "
                            "$read = $stream.Read($buffer, 0, $length); "
                            "$stream.Close(); "
                            "if ($read -le 0) { Write-Output ''; exit 0 }; "
                            "if ($read -lt $length) { $buffer = $buffer[0..($read - 1)] }; "
                            "[Convert]::ToBase64String($buffer)"
                        ),
                        timeout=60,
                    )
                    if chunk_result.returncode != 0:
                        if self.logger:
                            self.logger.debug(
                                "Artifact chunk download failed for target %s (%s): %s",
                                self.target_id,
                                remote_file,
                                chunk_result.stderr.strip() or chunk_result.stdout.strip(),
                            )
                        break

                    b64_output = (chunk_result.stdout or "").strip()
                    if not b64_output:
                        break
                    destination.write(base64.b64decode(b64_output))
                    offset += length

            if os.path.isfile(local_path):
                copied_files.append(local_path)
        return copied_files

    def path_exists(self, path: str, is_dir: bool = False) -> bool:
        path_type = "Container" if is_dir else "Leaf"
        result = self.run_command(
            (
                f"if (Test-Path -Path {self._ps_quote(path)} -PathType {path_type}) "
                "{ exit 0 } else { exit 1 }"
            ),
            timeout=15,
        )
        return result.returncode == 0

    def validate_pid(self, pid: int) -> bool:
        result = self.run_command(
            f"if (Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
            timeout=15,
        )
        return result.returncode == 0

    def start_process(self, executable: str, args: Optional[Sequence[str]] = None, cwd: Optional[str] = None) -> Dict[str, Any]:
        escaped_args = [self._ps_quote(str(item)) for item in (args or [])]
        args_array = "@(" + ", ".join(escaped_args) + ")"

        parts: List[str] = []
        if cwd:
            parts.append(f"Set-Location -LiteralPath {self._ps_quote(cwd)}")
        parts.extend(
            [
                f"$p = Start-Process -FilePath {self._ps_quote(executable)} -ArgumentList {args_array} -PassThru",
                "Start-Sleep -Milliseconds 250",
                "if ($null -eq $p -or $null -eq $p.Id) { exit 1 }",
                "Write-Output $p.Id",
            ]
        )

        result = self.run_command("; ".join(parts), timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Unable to start remote process")

        pid = None
        for line in (result.stdout or "").splitlines():
            stripped = line.strip()
            if stripped.isdigit():
                pid = int(stripped)
        if pid is None:
            raise RuntimeError(f"Unable to parse remote process PID from output: {result.stdout.strip()}")

        return {"pid": pid}

    def collect_process_output(self, handle: Dict[str, Any], timeout: float = 1) -> Dict[str, Any]:
        _ = handle
        _ = timeout
        return {
            "stdout": "",
            "stderr": "",
            "had_output": False,
            "output_truncated": False,
            "note": "Remote process output streaming is not available for detached execution",
        }

    def terminate_process(self, handle: Dict[str, Any]):
        pid = handle.get("pid")
        if pid is None:
            return
        self.run_command(
            f"Stop-Process -Id {int(pid)} -Force -ErrorAction SilentlyContinue",
            timeout=15,
        )

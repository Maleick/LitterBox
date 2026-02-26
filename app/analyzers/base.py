# app/analyzers/base.py
import copy
import os
import re
import subprocess
from abc import ABC, abstractmethod
from pathlib import PurePosixPath, PureWindowsPath

from app.execution import CommandResult


class BaseAnalyzer(ABC):
    def __init__(self, config):
        self.config = config
        self.results = {}

    @abstractmethod
    def analyze(self, target):
        """
        Perform the analysis
        :param target: Could be a file path or PID depending on analysis type
        """
        pass

    @abstractmethod
    def cleanup(self):
        """Cleanup after analysis"""
        pass

    def get_results(self):
        return self.results

    def _get_execution_context(self):
        return self.config.get("analysis", {}).get("_execution_context", {})

    def _get_runner(self):
        return self._get_execution_context().get("runner")

    def _resolve_tool_config(self, section: str, analyzer_name: str):
        tool_config = copy.deepcopy(self.config["analysis"][section][analyzer_name])
        scanner_paths = self._get_execution_context().get("scanner_paths", {})
        override = scanner_paths.get(analyzer_name)
        if override is None:
            override = scanner_paths.get(f"{section}.{analyzer_name}")

        if isinstance(override, str):
            tool_config["tool_path"] = override
        elif isinstance(override, dict):
            tool_config.update(override)

        return tool_config

    def _resolve_target_path(self, path: str) -> str:
        staged_targets = self._get_execution_context().get("staged_targets", {})
        return staged_targets.get(path, path)

    def _execute_command(
        self,
        command,
        timeout=None,
        shell=True,
        cwd=None,
    ) -> CommandResult:
        runner = self._get_runner()
        if runner:
            return runner.run_command(command=command, timeout=timeout, shell=shell, cwd=cwd)

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

    @staticmethod
    def _safe_dirname(path: str) -> str:
        if not path:
            return ""
        if "\\" in path or re.match(r"^[A-Za-z]:", path):
            parent = str(PureWindowsPath(path).parent)
        else:
            parent = str(PurePosixPath(path).parent)
        if parent in {"", ".", "\\"}:
            return os.getcwd()
        return parent

# app/analyzers/manager.py

import logging
import os
import subprocess
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Type

import psutil

from app.execution import LocalRunner
from app.execution.context import (
    execution_metadata,
    resolve_execution_context,
    sync_remote_artifacts,
)

# Import analyzers
from .dynamic.hsb_analyzer import HSBAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.rededr_analyzer import RedEdrAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .static.stringnalyzer_analyzer import StringsAnalyzer
from .static.yara_analyzer import YaraStaticAnalyzer


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, target):
        pass

    @abstractmethod
    def get_results(self):
        pass


class AnalysisManager:
    STATIC_ANALYZERS = {
        "yara": YaraStaticAnalyzer,
        "checkplz": CheckPlzAnalyzer,
        "stringnalyzer": StringsAnalyzer,
    }

    DYNAMIC_ANALYZERS = {
        "yara": YaraDynamicAnalyzer,
        "pe_sieve": PESieveAnalyzer,
        "moneta": MonetaAnalyzer,
        "patriot": PatriotAnalyzer,
        "hsb": HSBAnalyzer,
        "rededr": RedEdrAnalyzer,
    }

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.config = config
        self.static_analyzers: Dict[str, BaseAnalyzer] = {}
        self.dynamic_analyzers: Dict[str, BaseAnalyzer] = {}
        self.local_runner = LocalRunner(logger=self.logger)
        self._initialize_analyzers()

    def _initialize_analyzer(
        self,
        name: str,
        analyzer_class: Type[BaseAnalyzer],
        config_section: dict,
    ) -> Optional[BaseAnalyzer]:
        if not config_section.get("enabled", False):
            self.logger.debug("Analyzer %s is disabled in config", name)
            return None

        try:
            analyzer = analyzer_class(self.config)
            self.logger.debug("%s initialized successfully", name)
            return analyzer
        except Exception as exc:
            self.logger.error("Failed to initialize %s: %s", name, exc, exc_info=True)
            return None

    def _initialize_analyzers(self):
        static_config = self.config["analysis"]["static"]
        for name, analyzer_class in self.STATIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, static_config[name]):
                self.static_analyzers[name] = analyzer

        dynamic_config = self.config["analysis"]["dynamic"]
        for name, analyzer_class in self.DYNAMIC_ANALYZERS.items():
            if analyzer := self._initialize_analyzer(name, analyzer_class, dynamic_config[name]):
                self.dynamic_analyzers[name] = analyzer

    def _set_execution_context(self, context: dict):
        analysis_config = self.config.setdefault("analysis", {})
        previous = analysis_config.get("_execution_context")
        analysis_config["_execution_context"] = context
        return previous

    def _restore_execution_context(self, previous_context):
        analysis_config = self.config.setdefault("analysis", {})
        if previous_context is None:
            analysis_config.pop("_execution_context", None)
        else:
            analysis_config["_execution_context"] = previous_context

    def _resolve_execution_context(self, execution_target: Optional[str], file_path: Optional[str] = None) -> dict:
        return resolve_execution_context(
            config=self.config,
            local_runner=self.local_runner,
            execution_target=execution_target,
            file_path=file_path,
            logger=self.logger,
        )

    @staticmethod
    def _execution_metadata(context: dict) -> dict:
        return execution_metadata(context)

    def _sync_remote_artifacts(self, context: dict, artifact_destination: Optional[str]):
        return sync_remote_artifacts(context=context, artifact_destination=artifact_destination)

    def _run_analyzers(
        self,
        analyzers: Dict[str, BaseAnalyzer],
        target,
        analysis_type: str,
        execution_context: Optional[dict] = None,
    ) -> dict:
        results = {}
        if not analyzers:
            self.logger.warning("No %s analyzers are enabled", analysis_type)
            return results

        if analysis_type == "dynamic":
            if not self._validate_dynamic_target(target, execution_context):
                return {"status": "error", "error": "Process does not exist or is not running"}

        for name, analyzer in analyzers.items():
            try:
                analyzer.analyze(target)
                results[name] = analyzer.get_results()
            except Exception as exc:
                self.logger.error("Error in analyzer %s: %s", name, exc)
                results[name] = {"status": "error", "error": str(exc)}

        return results

    def _validate_dynamic_target(self, target, execution_context: Optional[dict] = None) -> bool:
        try:
            pid = int(target)
        except ValueError:
            return False

        if execution_context and execution_context.get("is_remote"):
            return execution_context["runner"].validate_pid(pid)

        try:
            process = psutil.Process(pid)
            return process.is_running()
        except psutil.NoSuchProcess:
            return False

    @staticmethod
    def _create_metadata(start_time: float, **kwargs) -> dict:
        metadata = {
            "total_duration": time.time() - start_time,
            "timestamp": time.time(),
        }
        metadata.update(kwargs)
        return metadata

    @staticmethod
    def _default_execution_context(requested_target: Optional[str] = None) -> dict:
        return {
            "runner": None,
            "is_remote": False,
            "requested_target": requested_target,
            "active_target": "local",
            "scanner_paths": {},
            "staged_targets": {},
            "fallback_used": False,
            "warnings": [],
            "remote_session_dir": None,
            "transport": "local",
        }

    def run_static_analysis(
        self,
        file_path: str,
        execution_target: Optional[str] = None,
        artifact_destination: Optional[str] = None,
    ) -> dict:
        start_time = time.time()
        context = self._default_execution_context(execution_target)
        previous_context = None
        context_applied = False

        try:
            context = self._resolve_execution_context(execution_target=execution_target, file_path=file_path)
            previous_context = self._set_execution_context(context)
            context_applied = True
            results = self._run_analyzers(
                self.static_analyzers,
                file_path,
                "static",
                execution_context=context,
            )
            metadata = self._create_metadata(start_time, **self._execution_metadata(context))
            artifacts = self._sync_remote_artifacts(context, artifact_destination)
            if artifacts:
                metadata["remote_artifacts"] = artifacts
            results["analysis_metadata"] = metadata
            return results
        except Exception as exc:
            self.logger.error("Error during static analysis: %s", exc, exc_info=True)
            return {
                "analysis_metadata": self._create_metadata(
                    start_time,
                    error=str(exc),
                    **self._execution_metadata(context),
                )
            }
        finally:
            if context_applied:
                self._restore_execution_context(previous_context)

    def run_dynamic_analysis(
        self,
        target,
        is_pid: bool = False,
        cmd_args: list = None,
        execution_target: Optional[str] = None,
        artifact_destination: Optional[str] = None,
    ) -> dict:
        start_time = time.time()
        target_file = None if is_pid else target
        context = self._default_execution_context(execution_target)
        previous_context = None
        context_applied = False

        try:
            context = self._resolve_execution_context(execution_target=execution_target, file_path=target_file)
            previous_context = self._set_execution_context(context)
            context_applied = True
            if context.get("is_remote"):
                return self._run_remote_dynamic_analysis(
                    context=context,
                    target=target,
                    is_pid=is_pid,
                    cmd_args=cmd_args,
                    start_time=start_time,
                    artifact_destination=artifact_destination,
                )

            if is_pid:
                return self._run_pid_analysis_local(target, start_time, cmd_args, context)
            return self._run_file_analysis_local(target, cmd_args, start_time, context)
        except Exception as exc:
            self.logger.error("Error during dynamic analysis: %s", exc, exc_info=True)
            return self._create_error_result(
                start_time=start_time,
                error_msg=str(exc),
                cmd_args=cmd_args,
                execution_context=context,
            )
        finally:
            if context_applied:
                self._restore_execution_context(previous_context)

    def _run_remote_dynamic_analysis(
        self,
        context: dict,
        target,
        is_pid: bool,
        cmd_args: Optional[list],
        start_time: float,
        artifact_destination: Optional[str],
    ) -> dict:
        runner = context["runner"]
        results: dict = {}
        process_handle = None

        try:
            if is_pid:
                pid = int(target)
                if not runner.validate_pid(pid):
                    raise Exception(f"Remote PID {pid} does not exist or is not running")
            else:
                staged_target = context.get("staged_targets", {}).get(target, target)
                process_handle = runner.start_process(
                    executable=staged_target,
                    args=cmd_args or [],
                    cwd=context.get("remote_session_dir"),
                )
                pid = process_handle["pid"]

                init_wait = self.config.get("analysis", {}).get("process", {}).get("init_wait_time", 5)
                time.sleep(init_wait)
                if not runner.validate_pid(pid):
                    raise Exception(f"Remote process {pid} terminated during initialization")

            analyzers = {name: analyzer for name, analyzer in self.dynamic_analyzers.items() if name != "rededr"}
            results.update(
                self._run_analyzers(
                    analyzers=analyzers,
                    target=pid,
                    analysis_type="dynamic",
                    execution_context=context,
                )
            )

            if "rededr" in self.dynamic_analyzers:
                results["rededr"] = {
                    "status": "skipped",
                    "error": "RedEdr live monitoring is not supported for remote execution",
                }

            results["process_output"] = (
                runner.collect_process_output(process_handle, timeout=1)
                if process_handle
                else {
                    "stdout": "",
                    "stderr": "",
                    "had_output": False,
                    "output_truncated": False,
                    "note": "PID-based remote analysis does not capture process output",
                }
            )

            metadata = self._create_metadata(
                start_time,
                cmd_args=cmd_args or [],
                **self._execution_metadata(context),
            )
            artifacts = self._sync_remote_artifacts(context, artifact_destination)
            if artifacts:
                metadata["remote_artifacts"] = artifacts
            results["analysis_metadata"] = metadata
            return results
        except Exception as exc:
            return self._create_error_result(
                start_time=start_time,
                error_msg=str(exc),
                cmd_args=cmd_args,
                execution_context=context,
            )
        finally:
            if process_handle:
                try:
                    runner.terminate_process(process_handle)
                except Exception as exc:
                    self.logger.debug("Remote process cleanup failed: %s", exc)

    def _run_pid_analysis_local(self, target: str, start_time: float, cmd_args: list, context: dict) -> dict:
        try:
            process, pid = self._validate_process(target, True)
            _ = process
            results = self._run_analyzers(
                self.dynamic_analyzers,
                pid,
                "dynamic",
                execution_context=context,
            )
            results["analysis_metadata"] = self._create_metadata(
                start_time,
                cmd_args=cmd_args or [],
                **self._execution_metadata(context),
            )
            return results
        except Exception as exc:
            return self._create_error_result(
                start_time=start_time,
                error_msg=str(exc),
                cmd_args=cmd_args,
                execution_context=context,
            )

    def _run_file_analysis_local(self, target: str, cmd_args: list, start_time: float, context: dict) -> dict:
        results = {}
        process = None
        rededr = None

        try:
            rededr = self._initialize_rededr(target, results)

            try:
                process, pid = self._validate_process(target, False, cmd_args)
            except Exception as exc:
                return self._handle_process_startup_error(exc, start_time, cmd_args, context)

            regular_analyzers = {
                analyzer_name: analyzer
                for analyzer_name, analyzer in self.dynamic_analyzers.items()
                if analyzer_name != "rededr"
            }
            results.update(
                self._run_analyzers(
                    regular_analyzers,
                    pid,
                    "dynamic",
                    execution_context=context,
                )
            )

            results["process_output"] = self._capture_process_output(process)

            if rededr:
                results["rededr"] = rededr.get_results()
                self._cleanup_rededr(rededr)

            results["analysis_metadata"] = self._create_metadata(
                start_time,
                early_termination=False,
                analysis_started=True,
                cmd_args=cmd_args or [],
                **self._execution_metadata(context),
            )
            return results
        except Exception as exc:
            return self._create_error_result(
                start_time=start_time,
                error_msg=str(exc),
                cmd_args=cmd_args,
                execution_context=context,
            )

    def _initialize_rededr(self, target: str, results: dict):
        rededr_config = self.config["analysis"]["dynamic"].get("rededr", {})
        if not rededr_config.get("enabled"):
            return None

        execution_context = self.config.get("analysis", {}).get("_execution_context", {})
        if execution_context.get("is_remote"):
            results["rededr"] = {
                "status": "skipped",
                "error": "RedEdr live monitoring is not supported for remote execution",
            }
            return None

        try:
            target_name = os.path.basename(target)
            rededr = RedEdrAnalyzer(self.config)
            if rededr.start_tool(target_name):
                etw_wait_time = rededr_config.get("etw_wait_time", 5)
                time.sleep(etw_wait_time)
                return rededr

            results["rededr"] = {"status": "error", "error": "Failed to start tool"}
            return None
        except Exception as exc:
            results["rededr"] = {"status": "error", "error": str(exc)}
            return None

    def _cleanup_rededr(self, rededr):
        try:
            rededr.cleanup()
        except Exception as exc:
            self.logger.error("Error cleaning up RedEdr: %s", exc)

    def _capture_process_output(self, process) -> dict:
        if not process:
            return {"had_output": False, "error": "No process to capture output from"}

        try:
            stdout, stderr = process.communicate(timeout=1)
            stdout = stdout or ""
            stderr = stderr or ""
            return {
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "had_output": bool(stdout.strip() or stderr.strip()),
                "output_truncated": False,
            }
        except subprocess.TimeoutExpired:
            self._cleanup_process(process, False)
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
        except Exception as exc:
            self.logger.error("Error capturing process output: %s", exc)
            return {"error": str(exc), "had_output": False, "output_truncated": False}

    def _handle_process_startup_error(
        self,
        error: Exception,
        start_time: float,
        cmd_args: list,
        execution_context: Optional[dict] = None,
    ) -> dict:
        error_msg = str(error)
        if "terminated after" in error_msg:
            init_wait = self.config.get("analysis", {}).get("process", {}).get("init_wait_time", 5)
            return {
                "status": "early_termination",
                "error": {
                    "message": f"Process terminated before initialization period ({init_wait}s)",
                    "details": error_msg,
                    "termination_time": error_msg.split("terminated after ")[1].split(" seconds")[0],
                    "cmd_args": cmd_args or [],
                },
                "analysis_metadata": self._create_metadata(
                    start_time,
                    early_termination=True,
                    analysis_started=False,
                    cmd_args=cmd_args or [],
                    **(self._execution_metadata(execution_context) if execution_context else {}),
                ),
            }

        return self._create_error_result(
            start_time=start_time,
            error_msg=error_msg,
            cmd_args=cmd_args,
            execution_context=execution_context,
        )

    def _create_error_result(
        self,
        start_time: float,
        error_msg: str,
        cmd_args: list = None,
        execution_context: Optional[dict] = None,
    ) -> dict:
        metadata = self._create_metadata(
            start_time,
            error=error_msg,
            early_termination=False,
            analysis_started=False,
            cmd_args=cmd_args or [],
            **(self._execution_metadata(execution_context) if execution_context else {}),
        )
        return {
            "status": "error",
            "error": {
                "message": "Analysis failed",
                "details": error_msg,
                "cmd_args": cmd_args or [],
            },
            "analysis_metadata": metadata,
        }

    def _validate_process(self, target, is_pid: bool, cmd_args: list = None) -> Tuple[subprocess.Popen, int]:
        if is_pid:
            return self._validate_existing_pid(target)
        return self._create_new_process(target, cmd_args)

    @staticmethod
    def _validate_existing_pid(target: str) -> Tuple[psutil.Process, int]:
        pid = int(target)
        process = psutil.Process(pid)
        if not process.is_running():
            raise Exception(f"Process with PID {pid} is not running")
        return process, pid

    def _create_new_process(self, target: str, cmd_args: list) -> Tuple[subprocess.Popen, int]:
        command = [target]
        if cmd_args:
            command.extend(cmd_args)

        startupinfo = None
        if os.name == "nt" and hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            bufsize=1,
            text=True,
        )
        pid = process.pid
        self._wait_for_process_initialization(process, pid, command)
        return process, pid

    def _wait_for_process_initialization(self, process: subprocess.Popen, pid: int, command: list):
        try:
            ps_process = psutil.Process(pid)
            if not ps_process.is_running():
                raise Exception(f"Process {pid} terminated immediately")

            init_wait = self.config.get("analysis", {}).get("process", {}).get("init_wait_time", 5)
            wait_interval = 0.1
            elapsed = 0
            while elapsed < init_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
                if not ps_process.is_running():
                    cmd_str = " ".join(command)
                    raise Exception(f"Process terminated after {elapsed:.1f} seconds (Command: {cmd_str})")

            if not ps_process.is_running():
                raise Exception("Process terminated during initialization")
        except psutil.NoSuchProcess:
            cmd_str = " ".join(command)
            raise Exception(f"Process {pid} terminated immediately after start (Command: {cmd_str})")
        except Exception:
            if process:
                try:
                    process.kill()
                except Exception:
                    pass
            raise

    def _cleanup_process(self, process, is_pid: bool):
        if process and not is_pid:
            try:
                try:
                    parent = psutil.Process(process.pid)
                    if not parent.is_running():
                        return
                except psutil.NoSuchProcess:
                    return

                try:
                    children = parent.children(recursive=True)
                    for child in children:
                        try:
                            if child.is_running():
                                child.terminate()
                                child.wait(timeout=3)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                            try:
                                if child.is_running():
                                    child.kill()
                            except psutil.NoSuchProcess:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                try:
                    if parent.is_running():
                        parent.terminate()
                        parent.wait(timeout=3)
                        if parent.is_running():
                            parent.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass
            except Exception as exc:
                self.logger.error("Error during process cleanup: %s", exc, exc_info=True)

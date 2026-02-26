import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

from .base import BaseAnalyzer
from app.execution import LocalRunner
from app.execution.context import (
    execution_metadata,
    resolve_execution_context,
    sync_remote_artifacts,
)


class HolyGrailAnalyzer(BaseAnalyzer):
    def __init__(self, config: dict, logger: Optional[logging.Logger] = None):
        super().__init__(config)
        self.logger = logger or logging.getLogger(__name__)
        self.local_runner = LocalRunner(logger=self.logger)

    def analyze(
        self,
        file_path: str,
        execution_target: Optional[str] = None,
        artifact_destination: Optional[str] = None,
    ) -> Dict[str, Any]:
        context = {"requested_target": execution_target, "is_remote": False, "transport": "local"}
        previous_context = None
        context_applied = False

        try:
            context = self._resolve_execution_context(execution_target=execution_target, file_path=file_path)
            previous_context = self._set_execution_context(context)
            context_applied = True

            holygrail_config = self._resolve_tool_config("holygrail")
            enabled = holygrail_config.get("enabled", False)
            timeout = holygrail_config.get("timeout", 120)
            command_template = holygrail_config.get("command", "")

            if not enabled:
                return {"status": "disabled", "error": "holygrail disabled"}

            analysis_target = self._resolve_target_path(file_path)
            if not self._get_execution_context().get("is_remote") and not os.path.exists(analysis_target):
                return {"status": "error", "error": f"File not found: {analysis_target}"}

            command = command_template.format(
                tool_path=holygrail_config.get("tool_path", ""),
                file_path=analysis_target,
                policies_path=holygrail_config.get("policies_path", ""),
                results_path=holygrail_config.get("results_path", ""),
            )

            result = self._execute_command(command, timeout=timeout, shell=True)
            if result.returncode != 0:
                return {
                    "status": "error",
                    "error": f"Tool failed with code {result.returncode}",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                }

            json_data = self._extract_json(result.stdout)
            if not json_data:
                return {
                    "status": "error",
                    "error": "No JSON found in output",
                    "raw_output": result.stdout,
                }

            metadata = self._execution_metadata(context)
            artifacts = self._sync_remote_artifacts(context, artifact_destination)
            if artifacts:
                metadata["remote_artifacts"] = artifacts

            return {
                "status": "completed",
                "findings": json_data,
                "timestamp": datetime.now().isoformat(),
                "analysis_metadata": metadata,
            }
        except Exception as exc:
            self.logger.error("HolyGrail analysis failed: %s", exc)
            return {
                "status": "error",
                "error": str(exc),
                "analysis_metadata": self._execution_metadata(context),
            }
        finally:
            if context_applied:
                self._restore_execution_context(previous_context)

    def _resolve_execution_context(self, execution_target: Optional[str], file_path: str) -> dict:
        return resolve_execution_context(
            config=self.config,
            local_runner=self.local_runner,
            execution_target=execution_target,
            file_path=file_path,
            logger=self.logger,
        )

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

    @staticmethod
    def _execution_metadata(context: dict) -> dict:
        return execution_metadata(context)

    def _sync_remote_artifacts(self, context: dict, artifact_destination: Optional[str]):
        return sync_remote_artifacts(context=context, artifact_destination=artifact_destination)

    def _resolve_tool_config(self, section_name: str):
        section = self.config.get("analysis", {}).get(section_name, {})
        tool_config = dict(section)
        scanner_paths = self._get_execution_context().get("scanner_paths", {})
        override = scanner_paths.get(section_name) or scanner_paths.get(f"analysis.{section_name}")
        if isinstance(override, dict):
            tool_config.update(override)
        elif isinstance(override, str):
            tool_config["tool_path"] = override
        return tool_config

    def _resolve_target_path(self, path: str) -> str:
        staged_targets = self._get_execution_context().get("staged_targets", {})
        return staged_targets.get(path, path)

    def _execute_command(self, command, timeout=None, shell=True, cwd=None):
        runner = self._get_execution_context().get("runner")
        if runner:
            return runner.run_command(command=command, timeout=timeout, shell=shell, cwd=cwd)
        return super()._execute_command(command=command, timeout=timeout, shell=shell, cwd=cwd)

    def _extract_json(self, output: str) -> Optional[Dict[str, Any]]:
        try:
            lines = output.strip().split("\n")
            for index, line in enumerate(lines):
                if line.strip().startswith("{"):
                    json_lines = []
                    brace_count = 0
                    for json_line in lines[index:]:
                        json_lines.append(json_line)
                        brace_count += json_line.count("{") - json_line.count("}")
                        if brace_count == 0:
                            break
                    return json.loads("\n".join(json_lines))
        except Exception as exc:
            self.logger.error("JSON extraction failed: %s", exc)
        return None

    def cleanup(self):
        pass

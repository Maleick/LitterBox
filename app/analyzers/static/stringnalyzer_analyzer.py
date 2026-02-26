import json
import os
from .base import StaticAnalyzer

class StringsAnalyzer(StaticAnalyzer):
    def analyze(self, file_path):
        """
        Analyzes a file using strings analysis tool specified in the config.
        """
        try:
            tool_config = self._resolve_tool_config('static', 'stringnalyzer')
            analysis_target = self._resolve_target_path(file_path)
            tool_path = tool_config['tool_path']

            if self._get_execution_context().get('is_remote'):
                formatted_tool_path = tool_path
                formatted_target = analysis_target
            else:
                formatted_tool_path = os.path.abspath(tool_path)
                formatted_target = os.path.abspath(analysis_target)

            command = tool_config['command'].format(
                tool_path=formatted_tool_path,
                file_path=formatted_target,
            )

            result = self._execute_command(
                command,
                timeout=tool_config.get('timeout', 300),
                shell=True,
                cwd=self._safe_dirname(tool_path),
            )
            
            # Parse the JSON output
            results = self._parse_output(result.stdout)
            
            self.results = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'scan_info': {
                    'target': file_path,
                    'tool': 'Stringnalyzer'
                },
                'findings': results,
                'errors': result.stderr if result.stderr else None
            }

        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def _parse_output(self, output):
        """
        Parse the strings tool JSON output into structured data.
        Returns a dictionary containing the parsed results.
        """
        try:
            # Try to parse the JSON output
            results = json.loads(output)
            
            # Ensure all expected fields are present, initialize if missing
            default_fields = {
                'file_path': None,
                'total_strings': 0,
                'all_strings': [],
                'found_error_messages': [],
                'found_functions': [],
                'found_url': [],
                'found_dll': [],
                'found_ip': [],
                'found_path': [],
                'found_file': [],
                'found_commands': [],
                'found_suspicious_strings': [],
                'found_suspicious_functions': [],
                'found_network_indicators': [],
                'found_registry_keys': [],
                'found_interesting_strings': [],
                'found_file_operations': [],
                'found_emails': [],
                'found_domains': []
            }

            # Update default fields with actual results
            for key in default_fields:
                if key not in results:
                    results[key] = default_fields[key]

            return results

        except json.JSONDecodeError as e:
            return {
                'error': f'Failed to parse JSON output: {str(e)}',
                **default_fields
            }
        except Exception as e:
            return {
                'error': f'Unexpected error parsing output: {str(e)}',
                **default_fields
            }

    def cleanup(self):
        """
        Cleanup any temporary files or processes.
        """
        pass

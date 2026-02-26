from app import load_config
from app.analyzers.manager import AnalysisManager


def test_run_static_analysis_handles_context_resolution_failure(monkeypatch, tmp_path):
    config = load_config()
    config["analysis"]["remote"]["enabled"] = True
    config["analysis"]["remote"]["local_fallback"] = False

    for analyzer_cfg in config["analysis"]["static"].values():
        analyzer_cfg["enabled"] = False
    for analyzer_cfg in config["analysis"]["dynamic"].values():
        analyzer_cfg["enabled"] = False

    manager = AnalysisManager(config)

    def _raise_context(*_args, **_kwargs):
        raise RuntimeError("forced context failure")

    monkeypatch.setattr("app.analyzers.manager.resolve_execution_context", _raise_context)

    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"sample")

    result = manager.run_static_analysis(str(sample_path), execution_target="domain")
    metadata = result.get("analysis_metadata", {})

    assert "error" in metadata
    assert "forced context failure" in metadata["error"]

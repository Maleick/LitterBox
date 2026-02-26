import sys
import types
from pathlib import Path


def pytest_configure(config):
    _ = config
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    if "pyssdeep" not in sys.modules:
        sys.modules["pyssdeep"] = types.SimpleNamespace(
            hash=lambda *_args, **_kwargs: "",
            hash_buf=lambda *_args, **_kwargs: "",
            compare=lambda *_args, **_kwargs: 0,
        )

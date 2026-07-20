"""Placeholder test - checks that pytest runs and package metadata is importable."""

import importlib.metadata as md


def test_package_metadata():
    """dfir-ai-assistant is installed and reports version 0.0.1."""
    assert md.version("dfir-ai-assistant") == "0.0.1"


def test_src_layout_importable():
    """The src/ packages exist and are importable."""
    import importlib
    for pkg in ("pipeline", "rag", "agents", "wiki"):
        mod = importlib.import_module(f"src.{pkg}")
        assert mod is not None
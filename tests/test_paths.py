"""
Tests for launcher/utils/paths.py — tool directory resolution.

Verifies:
  - BASE_DIR, NIDS_DIR, PAS_DIR, SMA_DIR are Path objects
  - Each tool directory is a child of BASE_DIR with the correct name
  - All three tool directories actually exist on disk
  - add_tools_to_path() adds each tool dir to sys.path exactly once (idempotent)
  - In PyInstaller frozen mode the base is taken from sys._MEIPASS
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import launcher.utils.paths as paths


class TestBaseDir:
    def test_base_dir_is_path(self):
        assert isinstance(paths.BASE_DIR, Path)

    def test_base_dir_is_absolute(self):
        assert paths.BASE_DIR.is_absolute()

    def test_base_dir_exists(self):
        assert paths.BASE_DIR.is_dir(), f"BASE_DIR does not exist: {paths.BASE_DIR}"


class TestToolDirNames:
    def test_nids_dir_name(self):
        assert paths.NIDS_DIR.name == "Network-Intrusion-Detection-System"

    def test_pas_dir_name(self):
        assert paths.PAS_DIR.name == "Password-Auditing-Suite"

    def test_sma_dir_name(self):
        assert paths.SMA_DIR.name == "Static-Malware-Analyzer"


class TestToolDirParents:
    def test_nids_under_base(self):
        assert paths.NIDS_DIR.parent == paths.BASE_DIR

    def test_pas_under_base(self):
        assert paths.PAS_DIR.parent == paths.BASE_DIR

    def test_sma_under_base(self):
        assert paths.SMA_DIR.parent == paths.BASE_DIR


class TestToolDirsExist:
    def test_nids_dir_exists(self):
        assert paths.NIDS_DIR.is_dir(), f"NIDS directory missing: {paths.NIDS_DIR}"

    def test_pas_dir_exists(self):
        assert paths.PAS_DIR.is_dir(), f"PAS directory missing: {paths.PAS_DIR}"

    def test_sma_dir_exists(self):
        assert paths.SMA_DIR.is_dir(), f"SMA directory missing: {paths.SMA_DIR}"

    def test_nids_has_main_py(self):
        assert (paths.NIDS_DIR / "main.py").is_file(), "NIDS/main.py missing"

    def test_pas_has_cli_py(self):
        # PAS uses cli.py (Click-based) as its entry point, not main.py
        assert (paths.PAS_DIR / "cli.py").is_file(), "PAS/cli.py missing"

    def test_sma_has_main_py(self):
        assert (paths.SMA_DIR / "main.py").is_file(), "SMA/main.py missing"


class TestAddToolsToPath:
    def test_adds_nids_to_sys_path(self):
        paths.add_tools_to_path()
        assert str(paths.NIDS_DIR) in sys.path

    def test_adds_pas_to_sys_path(self):
        paths.add_tools_to_path()
        assert str(paths.PAS_DIR) in sys.path

    def test_adds_sma_to_sys_path(self):
        paths.add_tools_to_path()
        assert str(paths.SMA_DIR) in sys.path

    def test_idempotent_no_duplicates(self):
        paths.add_tools_to_path()
        paths.add_tools_to_path()   # second call
        for d in (paths.NIDS_DIR, paths.PAS_DIR, paths.SMA_DIR):
            assert sys.path.count(str(d)) == 1, \
                f"Duplicate entry for {d.name} in sys.path"


class TestFrozenMode:
    def test_frozen_base_uses_meipass(self, monkeypatch, tmp_path):
        """When running inside a PyInstaller bundle, BASE_DIR must be sys._MEIPASS."""
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

        # Remove cached module so the reload picks up the monkeypatched values
        sys.modules.pop("launcher.utils.paths", None)
        reloaded = importlib.import_module("launcher.utils.paths")

        assert reloaded.BASE_DIR == tmp_path
        assert reloaded.NIDS_DIR == tmp_path / "Network-Intrusion-Detection-System"
        assert reloaded.PAS_DIR  == tmp_path / "Password-Auditing-Suite"
        assert reloaded.SMA_DIR  == tmp_path / "Static-Malware-Analyzer"

        # Restore original module
        sys.modules.pop("launcher.utils.paths", None)
        importlib.import_module("launcher.utils.paths")

"""
Tests for utility functions in launcher/pages/sma_page.py.

_fmt_size  — converts a byte count to a human-readable string
file-format detection — the suffix → format-label mapping used in _on_file_change
"""
from __future__ import annotations

import pytest

# conftest.py mocks customtkinter before this import
from launcher.pages.sma_page import _fmt_size


# ── _fmt_size ─────────────────────────────────────────────────────────────────

class TestFmtSize:
    def test_zero_bytes(self):
        assert _fmt_size(0) == "0.0 B"

    def test_small_bytes(self):
        assert _fmt_size(500) == "500.0 B"

    def test_exactly_1023_bytes(self):
        assert _fmt_size(1023) == "1023.0 B"

    def test_exactly_1024_is_kb(self):
        assert _fmt_size(1024) == "1.0 KB"

    def test_1_5_kb(self):
        assert _fmt_size(int(1.5 * 1024)) == "1.5 KB"

    def test_1_mb(self):
        assert _fmt_size(1024 ** 2) == "1.0 MB"

    def test_2_5_mb(self):
        result = _fmt_size(int(2.5 * 1024 ** 2))
        assert result == "2.5 MB"

    def test_1_gb(self):
        assert _fmt_size(1024 ** 3) == "1.0 GB"

    def test_large_gb(self):
        result = _fmt_size(50 * 1024 ** 3)
        # Anything >= 1 TB crosses into TB territory; 50 GB stays in GB
        assert "GB" in result

    def test_1_tb(self):
        assert _fmt_size(1024 ** 4) == "1.0 TB"

    def test_returns_string(self):
        assert isinstance(_fmt_size(12345), str)

    def test_unit_always_present(self):
        for n in (0, 100, 2000, 3_000_000, 5_000_000_000, 2_000_000_000_000):
            result = _fmt_size(n)
            assert any(result.endswith(u) for u in ("B", "KB", "MB", "GB", "TB")), \
                f"No unit found in result for n={n}: {result!r}"


# ── File-format label logic ───────────────────────────────────────────────────
# The format detection in _on_file_change is:
#   "PE (Windows)" if suffix in (".exe", ".dll", ".sys")
#   "ELF (Linux)"  if suffix in (".so", ".elf", "")
#   else suffix (fall through)
# We test this logic directly as a pure function.

def _fmt_label(suffix: str) -> str:
    """Mirror of the inline ternary in SMAPage._on_file_change."""
    suffix = suffix.lower()
    if suffix in (".exe", ".dll", ".sys"):
        return "PE (Windows)"
    if suffix in (".so", ".elf", ""):
        return "ELF (Linux)"
    return suffix


class TestFormatLabel:
    # PE formats
    def test_exe_is_pe(self):
        assert _fmt_label(".exe") == "PE (Windows)"

    def test_dll_is_pe(self):
        assert _fmt_label(".dll") == "PE (Windows)"

    def test_sys_is_pe(self):
        assert _fmt_label(".sys") == "PE (Windows)"

    def test_exe_uppercase(self):
        assert _fmt_label(".EXE") == "PE (Windows)"

    # ELF formats
    def test_so_is_elf(self):
        assert _fmt_label(".so") == "ELF (Linux)"

    def test_elf_extension(self):
        assert _fmt_label(".elf") == "ELF (Linux)"

    def test_no_extension_is_elf(self):
        # Executables without extension (e.g., Linux binaries)
        assert _fmt_label("") == "ELF (Linux)"

    # Unknown / pass-through
    def test_pdf_passthrough(self):
        assert _fmt_label(".pdf") == ".pdf"

    def test_bin_passthrough(self):
        assert _fmt_label(".bin") == ".bin"

    def test_unknown_extension_returned_as_is(self):
        assert _fmt_label(".xyz") == ".xyz"

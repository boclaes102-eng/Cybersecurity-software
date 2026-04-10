"""
Tests for App._classify_tag and _TAG_RULES in launcher/app.py.

_classify_tag is a @staticmethod that maps an output line to a colour tag
("error", "warning", "success", "info", or "" for plain text).
We call it directly without instantiating the App (no display needed).
"""
from __future__ import annotations

import pytest

# conftest.py mocks customtkinter before this import
from launcher.app import App, _TAG_RULES

classify = App._classify_tag


# ── Error tag ─────────────────────────────────────────────────────────────────

class TestErrorTag:
    def test_bracket_error(self):
        assert classify("[ERROR] file not found") == "error"

    def test_error_colon(self):
        assert classify("error: permission denied") == "error"

    def test_error_colon_mixed_case(self):
        assert classify("Error: something bad") == "error"

    def test_traceback(self):
        assert classify("Traceback (most recent call last):") == "error"

    def test_exception_colon(self):
        assert classify("Exception: unhandled state") == "error"

    def test_stopped_by_user(self):
        assert classify("[Stopped by user]") == "error"


# ── Warning tag ───────────────────────────────────────────────────────────────

class TestWarningTag:
    def test_bracket_warning(self):
        assert classify("[WARNING] low memory") == "warning"

    def test_warning_colon(self):
        assert classify("warning: deprecated flag") == "warning"

    def test_warn_colon(self):
        assert classify("warn: interface not found") == "warning"


# ── Success tag ───────────────────────────────────────────────────────────────

class TestSuccessTag:
    def test_finished(self):
        assert classify("[Finished — exit code 0]") == "success"

    def test_analysis_complete(self):
        assert classify("Analysis complete.") == "success"

    def test_done_bracket(self):
        assert classify("[done]") == "success"

    def test_clean(self):
        assert classify("No threats found — clean") == "success"

    def test_checkmark(self):
        assert classify("✓ All checks passed") == "success"


# ── Info tag ──────────────────────────────────────────────────────────────────

class TestInfoTag:
    def test_separator_line(self):
        assert classify("=" * 60) == "info"

    def test_separator_exact_minimum(self):
        # The rule checks for "=" * 10; exactly 10 should match
        assert classify("=" * 10) == "info"

    def test_run_arrow(self):
        assert classify("▶ NIDS  [--pcap replay.pcap]") == "info"

    def test_starting_keyword(self):
        assert classify("starting capture on eth0") == "info"


# ── No tag (plain text) ───────────────────────────────────────────────────────

class TestNoTag:
    def test_plain_output(self):
        assert classify("Packets captured: 1024") == ""

    def test_empty_string(self):
        assert classify("") == ""

    def test_numeric_line(self):
        assert classify("42") == ""

    def test_info_line_without_keywords(self):
        assert classify("Interface: eth0, Filter: tcp") == ""


# ── Priority (error beats warning) ────────────────────────────────────────────

class TestTagPriority:
    def test_error_takes_priority_over_warning(self):
        # A line containing both "error:" and "warning:" — error rule is first
        result = classify("error: caused a warning:")
        assert result == "error"

    def test_tag_rules_list_is_ordered(self):
        """Verify _TAG_RULES starts with error so it has highest priority."""
        assert _TAG_RULES[0][0] == "error"
        assert _TAG_RULES[1][0] == "warning"

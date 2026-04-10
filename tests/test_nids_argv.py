"""
Tests for NIDSPage._build_argv — argument list construction.

NIDSPage.__init__ creates CTk widgets we don't need for these tests.
We bypass it with object.__new__() and inject plain fake vars, then
call _build_argv() directly to verify the correct argv is produced for
each mode and combination of options.

No display, no CTk, no NIDS module loading required.
"""
from __future__ import annotations

import pytest

# conftest.py has already mocked 'customtkinter' before this import runs
from launcher.pages.nids_page import NIDSPage


# ── Helpers ────────────────────────────────────────────────────────────────────

class _Var:
    """Minimal StringVar / BooleanVar substitute."""
    def __init__(self, value): self._v = value
    def get(self): return self._v
    def set(self, v): self._v = v


def _make(**overrides) -> NIDSPage:
    """
    Construct a NIDSPage with fake vars, skipping CTk widget creation.
    Defaults represent the "Live Capture" form state.
    """
    defaults = dict(
        _mode_var     = _Var("Live Capture"),
        _iface_var    = _Var("eth0"),
        _filter_var   = _Var("tcp or udp"),
        _pcap_var     = _Var(""),
        _siem_var     = _Var("alerts.ndjson"),
        _headless_var = _Var(False),
        _verbose_var  = _Var(False),
    )
    defaults.update(overrides)

    obj = object.__new__(NIDSPage)
    obj._output_cb = lambda _: None      # silence error messages in tests
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


def _argv(**overrides) -> list[str]:
    """Build argv for the given overrides."""
    obj = _make(**overrides)
    return obj._build_argv(obj._mode_var.get())


# ── List Interfaces ────────────────────────────────────────────────────────────

class TestListInterfaces:
    def test_returns_list_interfaces_flag(self):
        obj = _make(_mode_var=_Var("List Interfaces"))
        assert obj._build_argv("List Interfaces") == ["nids", "--list-interfaces"]

    def test_ignores_all_other_settings(self):
        obj = _make(
            _mode_var=_Var("List Interfaces"),
            _verbose_var=_Var(True),
            _iface_var=_Var("eth1"),
        )
        assert obj._build_argv("List Interfaces") == ["nids", "--list-interfaces"]


# ── Live Capture ───────────────────────────────────────────────────────────────

class TestLiveCapture:
    def test_starts_with_nids(self):
        obj = _make()
        assert obj._build_argv("Live Capture")[0] == "nids"

    def test_interface_included(self):
        obj = _make(_iface_var=_Var("eth0"))
        argv = obj._build_argv("Live Capture")
        assert "-i" in argv
        assert argv[argv.index("-i") + 1] == "eth0"

    def test_interface_skipped_when_placeholder(self):
        obj = _make(_iface_var=_Var("(scapy not installed — install dependencies first)"))
        argv = obj._build_argv("Live Capture")
        assert "-i" not in argv

    def test_interface_skipped_when_empty(self):
        obj = _make(_iface_var=_Var(""))
        argv = obj._build_argv("Live Capture")
        assert "-i" not in argv

    def test_filter_included(self):
        obj = _make(_filter_var=_Var("icmp"))
        argv = obj._build_argv("Live Capture")
        assert "--filter" in argv
        assert argv[argv.index("--filter") + 1] == "icmp"

    def test_siem_included(self):
        obj = _make(_siem_var=_Var("my_alerts.ndjson"))
        argv = obj._build_argv("Live Capture")
        assert "--siem" in argv
        assert argv[argv.index("--siem") + 1] == "my_alerts.ndjson"

    def test_headless_flag_when_true(self):
        obj = _make(_headless_var=_Var(True))
        assert "--no-ui" in obj._build_argv("Live Capture")

    def test_headless_flag_absent_when_false(self):
        obj = _make(_headless_var=_Var(False))
        assert "--no-ui" not in obj._build_argv("Live Capture")

    def test_verbose_flag_when_true(self):
        obj = _make(_verbose_var=_Var(True))
        assert "--verbose" in obj._build_argv("Live Capture")

    def test_verbose_flag_absent_when_false(self):
        obj = _make(_verbose_var=_Var(False))
        assert "--verbose" not in obj._build_argv("Live Capture")

    def test_all_flags_combined(self):
        obj = _make(
            _iface_var=_Var("eth1"),
            _filter_var=_Var("tcp"),
            _siem_var=_Var("out.ndjson"),
            _headless_var=_Var(True),
            _verbose_var=_Var(True),
        )
        argv = obj._build_argv("Live Capture")
        assert "-i" in argv and "eth1" in argv
        assert "--filter" in argv and "tcp" in argv
        assert "--siem" in argv and "out.ndjson" in argv
        assert "--no-ui" in argv
        assert "--verbose" in argv


# ── PCAP Replay ────────────────────────────────────────────────────────────────

class TestPCAPReplay:
    def test_pcap_flag_included(self):
        obj = _make(_pcap_var=_Var("/tmp/test.pcap"))
        argv = obj._build_argv("PCAP Replay")
        assert "--pcap" in argv
        assert argv[argv.index("--pcap") + 1] == "/tmp/test.pcap"

    def test_siem_flag_included(self):
        obj = _make(
            _pcap_var=_Var("/tmp/test.pcap"),
            _siem_var=_Var("alerts.ndjson"),
        )
        argv = obj._build_argv("PCAP Replay")
        assert "--siem" in argv

    def test_verbose_flag_included(self):
        obj = _make(
            _pcap_var=_Var("/tmp/test.pcap"),
            _verbose_var=_Var(True),
        )
        assert "--verbose" in obj._build_argv("PCAP Replay")

    def test_no_interface_flag_in_replay(self):
        obj = _make(_pcap_var=_Var("/tmp/test.pcap"), _iface_var=_Var("eth0"))
        argv = obj._build_argv("PCAP Replay")
        assert "-i" not in argv

    def test_empty_pcap_returns_fallback(self):
        """When no PCAP is selected we return the bare ['nids'] fallback."""
        obj = _make(_pcap_var=_Var(""))
        argv = obj._build_argv("PCAP Replay")
        assert argv == ["nids"]

    def test_no_headless_flag_in_replay(self):
        """--no-ui makes no sense in PCAP replay; must not appear."""
        obj = _make(
            _pcap_var=_Var("/tmp/test.pcap"),
            _headless_var=_Var(True),
        )
        argv = obj._build_argv("PCAP Replay")
        assert "--no-ui" not in argv


# ── Mode Hints ─────────────────────────────────────────────────────────────────

class TestModeHints:
    def test_all_modes_have_hints(self):
        from launcher.pages.nids_page import _MODES, _MODE_HINTS
        for mode in _MODES:
            assert mode in _MODE_HINTS, f"No hint defined for mode '{mode}'"
            assert _MODE_HINTS[mode].strip(), f"Empty hint for mode '{mode}'"

    def test_interactive_menu_not_in_modes(self):
        """Interactive menu was removed because it requires stdin; verify it's gone."""
        from launcher.pages.nids_page import _MODES
        assert "Interactive Menu" not in _MODES

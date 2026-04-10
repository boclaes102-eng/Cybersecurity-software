"""
Shared pytest configuration.

Mocks customtkinter and tkinter dialogs **before** any launcher page
modules are imported so tests run headlessly without a display.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock


# ── Minimal CTk widget stub ────────────────────────────────────────────────────
# Each class must be a real Python class (not a MagicMock instance) so that
# page classes can safely inherit from them, e.g. `class NIDSPage(ctk.CTkFrame)`.

class _W:
    """Fake CTk widget — absorbs all constructor, layout, and config calls."""
    def __init__(self, *a, **kw): pass
    def configure(self, **kw): pass
    def cget(self, key): return None
    def pack(self, **kw): pass
    def pack_forget(self): pass
    def grid(self, **kw): pass
    def grid_remove(self): pass
    def grid_columnconfigure(self, *a, **kw): pass
    def grid_rowconfigure(self, *a, **kw): pass
    def grid_propagate(self, *a): pass
    def after(self, delay, fn=None, *a): pass


class _StringVar:
    def __init__(self, value="", *a, **kw): self._v = value
    def get(self): return self._v
    def set(self, v): self._v = v
    def trace_add(self, *a, **kw): pass


class _BooleanVar:
    def __init__(self, value=False, *a, **kw): self._v = bool(value)
    def get(self): return self._v
    def set(self, v): self._v = bool(v)


class _IntVar:
    def __init__(self, value=0, *a, **kw): self._v = int(value)
    def get(self): return self._v
    def set(self, v): self._v = int(v)


class _Font:
    def __init__(self, *a, **kw): pass


# ── Assemble the mock module ───────────────────────────────────────────────────
_ctk = MagicMock()

# Widget classes
_ctk.CTkFrame          = _W
_ctk.CTkScrollableFrame = _W
_ctk.CTkLabel          = _W
_ctk.CTkButton         = _W
_ctk.CTkComboBox       = _W
_ctk.CTkEntry          = _W
_ctk.CTkCheckBox       = _W
_ctk.CTkTabview        = _W
_ctk.CTkTextbox        = _W
_ctk.CTkRadioButton    = _W
_ctk.CTkSwitch         = _W
_ctk.CTkSlider         = _W
_ctk.CTkProgressBar    = _W
_ctk.CTk               = _W   # App base class

# Variable types
_ctk.StringVar  = _StringVar
_ctk.BooleanVar = _BooleanVar
_ctk.IntVar     = _IntVar

# Font
_ctk.CTkFont = _Font

# Module-level functions
_ctk.set_appearance_mode      = lambda *a, **kw: None
_ctk.set_default_color_theme  = lambda *a, **kw: None

sys.modules["customtkinter"] = _ctk

# tkinter.filedialog is used in nids_page and sma_page browse buttons;
# patch it so importing doesn't fail if no display is present.
sys.modules.setdefault("tkinter.filedialog", MagicMock())

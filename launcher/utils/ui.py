"""Shared UI component helpers for CyberSuite Pro pages."""
from __future__ import annotations

import tkinter as tk
from typing import Optional

import customtkinter as ctk

from .colors import (
    SURFACE, RAISED, BORDER, TEXT_HI, TEXT_LO, GREEN, GREEN_H, CYAN
)

# ── Typography constants ──────────────────────────────────────────────────────
FONT_TITLE   = lambda: ctk.CTkFont(size=22, weight="bold")
FONT_SECTION = lambda: ctk.CTkFont(size=10, weight="bold")
FONT_LABEL   = lambda: ctk.CTkFont(family="Consolas", size=11)
FONT_INPUT   = lambda: ctk.CTkFont(family="Consolas", size=12)
FONT_BODY    = lambda: ctk.CTkFont(size=12)
FONT_BTN     = lambda: ctk.CTkFont(size=13, weight="bold")
FONT_BTN_SM  = lambda: ctk.CTkFont(size=11)
FONT_MONO_SM = lambda: ctk.CTkFont(family="Consolas", size=10)

# ── Spacing ───────────────────────────────────────────────────────────────────
PAD_PAGE  = 24   # outer page padding
PAD_CARD  = 18   # inner card padding
PAD_INNER = 12   # tight inner padding
BTN_H     = 42   # standard button height
BTN_H_LG  = 46   # large action button height
CARD_R    = 8    # card corner radius


# ── Page header ───────────────────────────────────────────────────────────────

def page_header(parent: ctk.CTkFrame, title: str, subtitle: str) -> None:
    """Render the standard page title + subtitle bar."""
    hdr = ctk.CTkFrame(parent, fg_color="transparent")
    hdr.pack(fill="x", padx=PAD_PAGE, pady=(20, 10))

    ctk.CTkLabel(hdr, text=title,
                 font=FONT_TITLE(), text_color=TEXT_HI).pack(side="left")
    if subtitle:
        ctk.CTkLabel(hdr, text=f"  —  {subtitle}",
                     font=FONT_BODY(), text_color=TEXT_LO).pack(side="left")


# ── Card ──────────────────────────────────────────────────────────────────────

def card(parent, title: str = "", **grid_kw) -> ctk.CTkFrame:
    """
    Create a standard surface card with optional section title + divider.
    Uses grid() if row/column specified, otherwise pack().
    Returns the card frame (caller adds content to it).
    """
    c = ctk.CTkFrame(parent, fg_color=SURFACE, corner_radius=CARD_R,
                     border_width=1, border_color=BORDER)

    if "row" in grid_kw or "column" in grid_kw:
        c.grid(**grid_kw)
    else:
        c.pack(**grid_kw)

    if title:
        ctk.CTkLabel(c, text=title.upper(),
                     font=FONT_SECTION(), text_color=TEXT_LO
                     ).pack(anchor="w", padx=PAD_CARD, pady=(16, 0))
        divider(c)

    return c


def divider(parent: ctk.CTkFrame) -> None:
    """1px horizontal rule inside a card."""
    ctk.CTkFrame(parent, height=1, fg_color=BORDER).pack(
        fill="x", padx=PAD_CARD, pady=(6, 12))


# ── Toolbar ───────────────────────────────────────────────────────────────────

def toolbar(parent: ctk.CTkFrame) -> ctk.CTkFrame:
    """Standard single-row toolbar card."""
    tb = ctk.CTkFrame(parent, fg_color=SURFACE, corner_radius=CARD_R,
                      border_width=1, border_color=BORDER)
    tb.pack(fill="x", padx=PAD_PAGE, pady=(0, 8))
    return tb


def toolbar_label(parent: ctk.CTkFrame, text: str) -> None:
    ctk.CTkLabel(parent, text=text, text_color=TEXT_LO,
                 font=FONT_LABEL()).pack(side="left", padx=(14, 4), pady=8)


def toolbar_entry(parent: ctk.CTkFrame, var: ctk.StringVar,
                  width: int = 180) -> ctk.CTkEntry:
    e = ctk.CTkEntry(parent, textvariable=var, width=width, font=FONT_INPUT())
    e.pack(side="left", padx=4, pady=8)
    return e


def toolbar_combo(parent: ctk.CTkFrame, var: ctk.StringVar,
                  values: list[str], width: int = 140) -> ctk.CTkComboBox:
    cb = ctk.CTkComboBox(parent, variable=var, values=values,
                         state="readonly", width=width, font=FONT_INPUT())
    cb.pack(side="left", padx=4, pady=8)
    return cb


# ── Buttons ───────────────────────────────────────────────────────────────────

def btn_primary(parent, text: str, command, color: str = GREEN,
                hover: str = GREEN_H, width: int = 0,
                height: int = BTN_H) -> ctk.CTkButton:
    kw = {"height": height}
    if width:
        kw["width"] = width
    return ctk.CTkButton(parent, text=text, command=command,
                         fg_color=color, hover_color=hover,
                         font=FONT_BTN(), **kw)


def btn_ghost(parent, text: str, command,
              text_color: str = TEXT_HI,
              width: int = 0, height: int = BTN_H) -> ctk.CTkButton:
    kw = {"height": height}
    if width:
        kw["width"] = width
    return ctk.CTkButton(parent, text=text, command=command,
                         fg_color=SURFACE, hover_color=RAISED,
                         border_width=1, border_color=BORDER,
                         text_color=text_color,
                         font=FONT_BTN_SM(), **kw)


def btn_outline(parent, text: str, command,
                accent: str = CYAN, width: int = 0,
                height: int = BTN_H) -> ctk.CTkButton:
    kw = {"height": height}
    if width:
        kw["width"] = width
    return ctk.CTkButton(parent, text=text, command=command,
                         fg_color=SURFACE, hover_color=RAISED,
                         border_width=1, border_color=accent,
                         text_color=accent,
                         font=FONT_BTN_SM(), **kw)


# ── Form row helpers ──────────────────────────────────────────────────────────

def form_row(parent: ctk.CTkFrame, label: str,
             row: int, col_label: int = 0,
             col_widget: int = 1) -> None:
    """Render a right-aligned label in a grid form."""
    ctk.CTkLabel(parent, text=label, text_color=TEXT_LO,
                 font=FONT_LABEL(), anchor="e", width=100
                 ).grid(row=row, column=col_label,
                        sticky="e", padx=(PAD_CARD, 8), pady=5)


def status_dot(parent: ctk.CTkFrame, color: str = "#3fb950",
               size: int = 8) -> tk.Canvas:
    c = tk.Canvas(parent, width=size, height=size,
                  bg=SURFACE, highlightthickness=0)
    c.create_oval(1, 1, size - 1, size - 1, fill=color, outline="")
    return c

"""Shared colour palette for all CyberSuite Pro pages."""

# ── Background layers ─────────────────────────────────────────────────────────
BG      = "#0d1117"   # page background
SURFACE = "#161b22"   # card / panel background
RAISED  = "#1c2128"   # elevated element (hover, active row)
BORDER  = "#30363d"   # border / divider

# ── Text ──────────────────────────────────────────────────────────────────────
TEXT_HI = "#e6edf3"   # primary text
TEXT_LO = "#7d8590"   # muted / label text

# ── Accent ────────────────────────────────────────────────────────────────────
CYAN    = "#58a6ff"   # info / link
GREEN   = "#238636"   # success / start
GREEN_H = "#2ea043"   # green hover
RED     = "#da3633"   # danger / stop
RED_H   = "#b91c1c"   # red hover
ORANGE  = "#d97706"   # warning
PURPLE  = "#a78bfa"   # Apple / misc

# ── Severity ──────────────────────────────────────────────────────────────────
SEV = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# ── Node colours (NetMap) ─────────────────────────────────────────────────────
NODE_ROUTER  = "#1f6aa5"
NODE_HOST    = GREEN
NODE_WIN     = "#2563eb"
NODE_LINUX   = "#16a34a"
NODE_APPLE   = PURPLE
NODE_PHONE   = ORANGE
NODE_SELF    = "#4ade80"
NODE_SELECT  = "#f0883e"
NODE_OFFLINE = "#334155"
NODE_DANGER  = "#dc2626"
NODE_WARN    = ORANGE

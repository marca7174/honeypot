"""
bridge.py — Digital Mirror v2 — Python ↔ C++ ctypes bridge

Compile the shared library first:
  Linux/macOS : g++ -O2 -shared -fPIC -std=c++17 -o risk_engine.so risk_engine.cpp
  Windows     : g++ -O2 -shared -std=c++17 -o risk_engine.dll risk_engine.cpp

Falls back to pure Python implementation if C++ DLL is not available.
"""

import ctypes
import os
import platform
from dataclasses import dataclass
from typing import Optional
import datetime

# ── Try to load shared library, fall back to Python version ───────────────────

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LIB_NAME = "risk_engine.dll" if platform.system() == "Windows" else "risk_engine.so"
_LIB_PATH = os.path.join(_BASE_DIR, _LIB_NAME)

_USE_CPP_BRIDGE = False

try:
    _lib = ctypes.CDLL(_LIB_PATH)
    _USE_CPP_BRIDGE = True
    print("[bridge.py] ✓ Loaded C++ risk_engine library")
except OSError:
    print("[bridge.py] ⚠ C++ DLL not found, using pure Python fallback")
    # Will import Python fallback below

# ── Declare C function signatures (only if C++ bridge is available) ──────────

if _USE_CPP_BRIDGE:
    _lib.track_action.argtypes   = [ctypes.c_char_p, ctypes.c_char_p]
    _lib.track_action.restype    = None

    _lib.mark_employee.argtypes  = [ctypes.c_char_p]
    _lib.mark_employee.restype   = None

    _lib.is_banned.argtypes      = [ctypes.c_char_p]
    _lib.is_banned.restype       = ctypes.c_int

    _lib.get_risk_score.argtypes = [ctypes.c_char_p]
    _lib.get_risk_score.restype  = ctypes.c_int

    _lib.get_threat_level.argtypes = [ctypes.c_char_p]
    _lib.get_threat_level.restype  = ctypes.c_int

    _lib.get_record.argtypes     = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _lib.get_record.restype      = None

    _lib.get_all_records.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _lib.get_all_records.restype  = None

    _lib.dump_sessions.argtypes  = []
    _lib.dump_sessions.restype   = None

# ── Data models ───────────────────────────────────────────────────────────────

THREAT_LEVELS = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
THREAT_COLORS = {0: "#22c55e", 1: "#eab308", 2: "#f97316", 3: "#ef4444", 4: "#7c3aed"}


@dataclass
class SessionRecord:
    ip:             str
    risk_score:     int
    identity:       str        # UNKNOWN / EMPLOYEE / THREAT
    threat_level:   str        # NONE / LOW / MEDIUM / HIGH / CRITICAL
    is_banned:      bool
    ban_expiry:     int        # unix timestamp, 0 if not banned
    fa2_failures:   int
    otp_failures:   int
    first_seen:     datetime.datetime
    last_seen:      datetime.datetime
    last_action:    str

    @classmethod
    def from_raw(cls, raw: str) -> Optional["SessionRecord"]:
        """Parse a pipe-delimited record string from C++."""
        if not raw.strip():
            return None
        parts = raw.strip().split("|")
        if len(parts) < 11:
            return None
        try:
            return cls(
                ip=parts[0],
                risk_score=int(parts[1]),
                identity=parts[2],
                threat_level=parts[3],
                is_banned=parts[4] == "1",
                ban_expiry=int(parts[5]),
                fa2_failures=int(parts[6]),
                otp_failures=int(parts[7]),
                first_seen=datetime.datetime.fromtimestamp(int(parts[8])),
                last_seen=datetime.datetime.fromtimestamp(int(parts[9])),
                last_action=parts[10] if len(parts) > 10 else "",
            )
        except (ValueError, OSError):
            return None

# ── Public Python API ─────────────────────────────────────────────────────────

if _USE_CPP_BRIDGE:
    def track_action(ip: str, action: str) -> None:
        """Report an action from an IP to the C++ risk engine."""
        _lib.track_action(ip.encode("utf-8"), action.encode("utf-8"))


    def mark_employee(ip: str) -> None:
        """Mark an IP as a verified employee."""
        _lib.mark_employee(ip.encode("utf-8"))


    def is_banned(ip: str) -> bool:
        return bool(_lib.is_banned(ip.encode("utf-8")))


    def get_risk_score(ip: str) -> int:
        return int(_lib.get_risk_score(ip.encode("utf-8")))


    def get_threat_level(ip: str) -> str:
        lvl = int(_lib.get_threat_level(ip.encode("utf-8")))
        return THREAT_LEVELS.get(lvl, "NONE")


    def get_record(ip: str) -> Optional[SessionRecord]:
        buf = ctypes.create_string_buffer(1024)
        _lib.get_record(ip.encode("utf-8"), buf, 1024)
        return SessionRecord.from_raw(buf.value.decode("utf-8", errors="replace"))


    def get_all_records() -> list:
        buf = ctypes.create_string_buffer(65536)
        _lib.get_all_records(buf, 65536)
        raw = buf.value.decode("utf-8", errors="replace")
        records = []
        for line in raw.strip().splitlines():
            rec = SessionRecord.from_raw(line)
            if rec:
                records.append(rec)
        return records


    def dump_sessions() -> None:
        _lib.dump_sessions()

else:
    # Import Python fallback
    from bridge_python_fallback import (
        track_action,
        mark_employee,
        is_banned,
        get_risk_score,
        get_threat_level,
        get_record,
        get_all_records,
        dump_sessions
    )

"""
logger.py — Digital Mirror v3 — Structured JSON-line logger
New in v3: OTP_TIMEOUT, CHATBOT_OTP_SUCCESS, CHATBOT_OTP_FAILURE, AUTO_BAN events
"""

import json
import os
import datetime
import threading
from typing import Any, Optional

_LOG_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
_LOG_PATH = os.path.join(_LOG_DIR, "honeypot.log")
_OTP_LOG  = os.path.join(_LOG_DIR, "otp_events.log")
_BAN_LOG  = os.path.join(_LOG_DIR, "ban_events.log")

os.makedirs(_LOG_DIR, exist_ok=True)

_lock     = threading.Lock()
_otp_lock = threading.Lock()
_ban_lock = threading.Lock()


def _write(path: str, record: dict, lock: threading.Lock) -> None:
    line = json.dumps(record, default=str) + "\n"
    with lock:
        with open(path, "a") as f:
            f.write(line)


def log_event(
    event_type:   str,
    ip:           str,
    identity:     str     = "UNKNOWN",
    threat_level: str     = "NONE",
    details:      Optional[dict] = None,
) -> None:
    record = {
        "ts":           datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event":        event_type,
        "ip":           ip,
        "identity":     identity,
        "threat_level": threat_level,
        "details":      details or {},
    }
    _write(_LOG_PATH, record, _lock)


def log_otp_event(
    event_type: str,
    emp_id:     str,
    ip:         str,
    success:    bool,
    details:    Optional[dict] = None,
) -> None:
    record = {
        "ts":      datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event":   event_type,
        "emp_id":  emp_id,
        "ip":      ip,
        "success": success,
        "details": details or {},
    }
    _write(_OTP_LOG, record, _otp_lock)


def log_ban_event(
    ip:           str,
    reason:       str,
    risk_score:   int,
    threat_level: str,
    details:      Optional[dict] = None,
) -> None:
    record = {
        "ts":           datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "event":        "AUTO_BAN",
        "ip":           ip,
        "reason":       reason,
        "risk_score":   risk_score,
        "threat_level": threat_level,
        "details":      details or {},
    }
    _write(_BAN_LOG, record, _ban_lock)
    log_event("AUTO_BAN", ip, "THREAT", threat_level, {
        "reason": reason, "risk_score": risk_score, **(details or {})
    })


def read_logs(limit: int = 300) -> list[dict]:
    if not os.path.exists(_LOG_PATH):
        return []
    with open(_LOG_PATH) as f:
        lines = f.readlines()
    result = []
    for line in reversed(lines[-limit:]):
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result


def read_otp_logs(limit: int = 100) -> list[dict]:
    if not os.path.exists(_OTP_LOG):
        return []
    with open(_OTP_LOG) as f:
        lines = f.readlines()
    result = []
    for line in reversed(lines[-limit:]):
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result


def read_ban_logs(limit: int = 100) -> list[dict]:
    if not os.path.exists(_BAN_LOG):
        return []
    with open(_BAN_LOG) as f:
        lines = f.readlines()
    result = []
    for line in reversed(lines[-limit:]):
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result

"""
bridge_python_fallback.py — Pure Python implementation (no C++ DLL required)

This is a fallback when the C++ risk_engine.dll is not available.
Provides the same interface as the C++ bridge but implemented in pure Python.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict
import datetime
from enum import IntEnum

# ─────────────────────────────────────────────────────────────────────────────
#  Enums
# ─────────────────────────────────────────────────────────────────────────────

class ThreatLevel(IntEnum):
    NONE = 0       # score   0-19
    LOW = 1        # score  20-49
    MEDIUM = 2     # score  50-79
    HIGH = 3       # score  80-99
    CRITICAL = 4   # score 100+

class Identity(IntEnum):
    UNKNOWN = 0
    EMPLOYEE = 1
    THREAT = 2

# ─────────────────────────────────────────────────────────────────────────────
#  Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UserSession:
    """Tracks a single user/IP session"""
    ip: str
    risk_score: int = 0
    identity: Identity = Identity.UNKNOWN
    is_banned: bool = False
    ban_expiry: int = 0
    fa2_failures: int = 0
    otp_failures: int = 0
    first_seen: datetime.datetime = field(default_factory=datetime.datetime.now)
    last_seen: datetime.datetime = field(default_factory=datetime.datetime.now)
    last_action: str = "INIT"
    actions_log: list = field(default_factory=list)

    def add_risk_points(self, points: int, action: str) -> None:
        self.risk_score = min(self.risk_score + points, 150)
        self.last_action = action
        self.last_seen = datetime.datetime.now()
        self.actions_log.append(f"{action}({points})")
        
        # Auto-ban at critical
        if self.risk_score >= 100:
            self.is_banned = True
            self.ban_expiry = int((datetime.datetime.now() + datetime.timedelta(hours=24)).timestamp())

    def get_threat_level(self) -> ThreatLevel:
        if self.risk_score < 20:
            return ThreatLevel.NONE
        elif self.risk_score < 50:
            return ThreatLevel.LOW
        elif self.risk_score < 80:
            return ThreatLevel.MEDIUM
        elif self.risk_score < 100:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL

    def mark_employee(self) -> None:
        self.identity = Identity.EMPLOYEE
        self.risk_score = 0  # Reset risk for known employee

    def mark_threat(self, reason: str) -> None:
        self.identity = Identity.THREAT
        self.is_banned = True
        self.ban_expiry = int((datetime.datetime.now() + datetime.timedelta(days=7)).timestamp())

    def record_failed_2fa(self) -> None:
        self.fa2_failures += 1
        if self.fa2_failures >= 3:
            self.add_risk_points(50, "REPEATED_2FA_FAILURE")

    def record_otp_failure(self) -> None:
        self.otp_failures += 1
        if self.otp_failures >= 3:
            self.add_risk_points(60, "REPEATED_OTP_FAILURE")

    def is_banned_check(self) -> bool:
        if not self.is_banned:
            return False
        if self.ban_expiry > 0 and datetime.datetime.now().timestamp() > self.ban_expiry:
            self.is_banned = False
            self.ban_expiry = 0
            return False
        return self.is_banned

@dataclass
class SessionRecord:
    ip: str
    risk_score: int
    identity: str
    threat_level: str
    is_banned: bool
    ban_expiry: int
    fa2_failures: int
    otp_failures: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    last_action: str

# ─────────────────────────────────────────────────────────────────────────────
#  Risk Engine Singleton
# ─────────────────────────────────────────────────────────────────────────────

class RiskEngine:
    """Singleton risk analysis engine (pure Python version)"""
    _instance = None
    
    def __init__(self):
        self.active_sessions: Dict[str, UserSession] = {}
        print("[RiskEngine] Pure Python fallback initialized (no C++ DLL)")

    @staticmethod
    def get_instance() -> 'RiskEngine':
        if RiskEngine._instance is None:
            RiskEngine._instance = RiskEngine()
        return RiskEngine._instance

    def _get_or_create(self, ip: str) -> UserSession:
        if ip not in self.active_sessions:
            self.active_sessions[ip] = UserSession(ip=ip)
        return self.active_sessions[ip]

    def track_action(self, ip: str, action: str) -> None:
        session = self._get_or_create(ip)
        
        if action == "FAILED_LOGIN":
            session.add_risk_points(15, action)
            # Only mark as threat after multiple failures (not on first attempt)
            if session.otp_failures >= 3 or session.fa2_failures >= 3:
                session.mark_threat("REPEATED_LOGIN_FAILURE")
        elif action == "ACCESS_SENSITIVE_DIR":
            session.add_risk_points(60, action)
        elif action == "FAILED_2FA":
            session.record_failed_2fa()
        elif action == "FAILED_OTP":
            session.record_otp_failure()
        elif action == "PORT_SCAN":
            session.add_risk_points(40, action)
            session.mark_threat("PORT_SCAN")
        elif action == "SQL_INJECTION_ATTEMPT":
            session.add_risk_points(80, action)
            session.mark_threat("SQL_INJECTION")
        elif action == "XSS_ATTEMPT":
            session.add_risk_points(70, action)
            session.mark_threat("XSS_ATTEMPT")
        elif action == "BRUTE_FORCE":
            session.add_risk_points(50, action)
            session.mark_threat("BRUTE_FORCE")
        else:
            session.add_risk_points(5, action)

    def mark_employee(self, ip: str) -> None:
        session = self._get_or_create(ip)
        session.mark_employee()

    def check_ban_status(self, ip: str) -> bool:
        session = self.active_sessions.get(ip)
        return session.is_banned_check() if session else False

    def get_risk_score(self, ip: str) -> int:
        session = self.active_sessions.get(ip)
        return session.risk_score if session else 0

    def get_threat_level(self, ip: str) -> int:
        session = self.active_sessions.get(ip)
        if session:
            return int(session.get_threat_level())
        return 0

    def get_record(self, ip: str) -> SessionRecord:
        session = self.active_sessions.get(ip)
        if not session:
            return None
        
        identity_str = {
            Identity.UNKNOWN: "UNKNOWN",
            Identity.EMPLOYEE: "EMPLOYEE",
            Identity.THREAT: "THREAT"
        }.get(session.identity, "UNKNOWN")
        
        threat_level_str = {
            ThreatLevel.NONE: "NONE",
            ThreatLevel.LOW: "LOW",
            ThreatLevel.MEDIUM: "MEDIUM",
            ThreatLevel.HIGH: "HIGH",
            ThreatLevel.CRITICAL: "CRITICAL"
        }.get(session.get_threat_level(), "NONE")
        
        return SessionRecord(
            ip=session.ip,
            risk_score=session.risk_score,
            identity=identity_str,
            threat_level=threat_level_str,
            is_banned=session.is_banned,
            ban_expiry=session.ban_expiry,
            fa2_failures=session.fa2_failures,
            otp_failures=session.otp_failures,
            first_seen=session.first_seen,
            last_seen=session.last_seen,
            last_action=session.last_action
        )

    def get_all_records(self) -> list:
        records = []
        for ip in self.active_sessions:
            record = self.get_record(ip)
            if record:
                records.append(record)
        return records

    def dump_sessions(self) -> None:
        print("\n=== Session Dump ===")
        for ip, session in self.active_sessions.items():
            print(f"{ip}: risk={session.risk_score}, threat={session.get_threat_level().name}, banned={session.is_banned}")

# ─────────────────────────────────────────────────────────────────────────────
#  Public API (mimics bridge.py interface)
# ─────────────────────────────────────────────────────────────────────────────

_engine = RiskEngine.get_instance()

THREAT_LEVELS = {
    0: "NONE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL"
}

THREAT_COLORS = {
    0: "#22c55e",
    1: "#eab308",
    2: "#f97316",
    3: "#ef4444",
    4: "#7c3aed"
}

def track_action(ip: str, action: str) -> None:
    """Track a security action for an IP"""
    _engine.track_action(ip, action)

def mark_employee(ip: str) -> None:
    """Mark an IP as a known employee"""
    _engine.mark_employee(ip)

def is_banned(ip: str) -> bool:
    """Check if IP is currently banned"""
    return _engine.check_ban_status(ip)

def get_risk_score(ip: str) -> int:
    """Get current risk score for IP"""
    return _engine.get_risk_score(ip)

def get_threat_level(ip: str) -> int:
    """Get threat level (0-4) for IP"""
    return _engine.get_threat_level(ip)

def get_record(ip: str) -> SessionRecord:
    """Get full session record for IP"""
    return _engine.get_record(ip)

def get_all_records() -> list:
    """Get all session records"""
    return _engine.get_all_records()

def dump_sessions() -> None:
    """Dump all sessions to log"""
    _engine.dump_sessions()

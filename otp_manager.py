"""
otp_manager.py — Digital Mirror v3
OTP Management with:
  - 5-minute TTL (300 seconds)
  - Auto-generated OTP per login session (shown ONLY in admin panel)
  - Timer-based auto-ban if OTP not entered in time
  - TOTP (Google Authenticator) fallback
"""

import pyotp
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────

OTP_TTL_SECONDS = 60  # 1 minute — if not entered, attacker is auto-banned

# ── Session OTP (auto-generated on every login, shown in admin panel only) ────

@dataclass
class SessionOTP:
    emp_id:     str
    ip:         str
    code:       str
    issued_at:  float = field(default_factory=time.time)
    used:       bool  = False
    expired_ban_applied: bool = False  # True once we've applied the auto-ban

    def seconds_remaining(self) -> float:
        return max(0.0, OTP_TTL_SECONDS - (time.time() - self.issued_at))

    def is_expired(self) -> bool:
        return (time.time() - self.issued_at) > OTP_TTL_SECONDS

    def is_valid(self, code: str) -> bool:
        return (
            not self.used
            and not self.is_expired()
            and secrets.compare_digest(self.code.strip(), code.strip())
        )


# In-memory store: ip → SessionOTP (one active OTP per session IP)
_sessions: dict[str, SessionOTP] = {}
_lock_store: dict[str, float] = {}   # ip → timestamp of ban applied


def generate_session_otp(ip: str, emp_id: str = "UNKNOWN") -> str:
    """
    Called automatically when ANY user logs in.
    Generates a 6-digit OTP visible only to the admin.
    Returns the code (for admin panel display).
    """
    code = f"{secrets.randbelow(1_000_000):06d}"
    _sessions[ip] = SessionOTP(emp_id=emp_id, ip=ip, code=code)
    return code


def verify_chatbot_otp(ip: str, code: str) -> tuple[bool, str]:
    """
    Called when user types in the AI chatbot widget.
    Returns (success, reason).
    """
    session = _sessions.get(ip)
    if session is None:
        return False, "NO_SESSION"
    if session.used:
        return False, "ALREADY_USED"
    if session.is_expired():
        return False, "EXPIRED"
    if not secrets.compare_digest(session.code.strip(), code.strip()):
        return False, "WRONG_CODE"
    session.used = True
    return True, "OK"


def verify_totp_fallback(secret: str, code: str) -> bool:
    """TOTP (Google Authenticator) fallback verification."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)


def get_session_otp_info(ip: str) -> Optional[dict]:
    """Return OTP info for a given IP (for admin panel display)."""
    session = _sessions.get(ip)
    if session is None:
        return None
    return {
        "ip":         session.ip,
        "emp_id":     session.emp_id,
        "code":       session.code,
        "issued_at":  session.issued_at,
        "seconds_remaining": session.seconds_remaining(),
        "used":       session.used,
        "expired":    session.is_expired(),
        "expired_ban_applied": session.expired_ban_applied,
    }


def get_all_active_otps() -> list[dict]:
    """Return all non-used OTP sessions (for admin panel)."""
    result = []
    for ip, session in _sessions.items():
        if not session.used:
            result.append({
                "ip":               ip,
                "emp_id":           session.emp_id,
                "code":             session.code,
                "seconds_remaining": session.seconds_remaining(),
                "expired":          session.is_expired(),
                "expired_ban_applied": session.expired_ban_applied,
            })
    return result


def get_expired_unbanned_sessions() -> list[str]:
    """Return IPs whose OTP expired and ban hasn't been applied yet."""
    expired_ips = []
    for ip, session in _sessions.items():
        if (
            not session.used
            and session.is_expired()
            and not session.expired_ban_applied
        ):
            session.expired_ban_applied = True
            expired_ips.append(ip)
    return expired_ips


def clear_session(ip: str) -> None:
    """Remove OTP session after successful auth."""
    _sessions.pop(ip, None)


# ── Admin-issued manual OTPs (kept for compatibility) ─────────────────────────

def generate_otp_for_employee(emp_id: str) -> str:
    """Admin manually generates OTP — also stored as session-style OTP."""
    code = f"{secrets.randbelow(1_000_000):06d}"
    # We store with emp_id as 'ip' key for admin-issued ones
    _sessions[f"admin:{emp_id}"] = SessionOTP(emp_id=emp_id, ip="admin", code=code)
    return code


def verify_issued_otp(emp_id: str, code: str) -> tuple[bool, str]:
    """Verify admin-manually-issued OTP (legacy portal path)."""
    key = f"admin:{emp_id}"
    session = _sessions.get(key)
    if session is None:
        return False, "NO_OTP_ISSUED"
    if session.used:
        return False, "ALREADY_USED"
    if session.is_expired():
        return False, "EXPIRED"
    if not secrets.compare_digest(session.code.strip(), code.strip()):
        return False, "WRONG_CODE"
    session.used = True
    return True, "OK"


def list_pending_otps() -> list[dict]:
    """All pending non-expired OTPs for admin view."""
    now = time.time()
    result = []
    for key, session in _sessions.items():
        if not session.used and not session.is_expired():
            result.append({
                "emp_id":     session.emp_id,
                "ip":         session.ip,
                "issued_at":  session.issued_at,
                "expires_in": int(OTP_TTL_SECONDS - (now - session.issued_at)),
            })
    return result

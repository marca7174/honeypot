"""
main.py — Digital Mirror v3 — Reverse Proxy Honeypot

v3 Changes from v2:
  ✦ Honeypot layer = realistic corporate dashboard (NOT a spinner)
  ✦ AI Chatbot widget (bottom-right) is the disguised OTP entry portal
  ✦ OTP auto-generated on login (5-min TTL), shown ONLY in admin panel
  ✦ Auto-ban if OTP not entered within 5 minutes
  ✦ Background task sweeps expired OTPs and applies bans
  ✦ Admin panel: real-time OTP countdown timers, ban feed, alerts
  ✦ No separate /portal URL — chatbot IS the hidden mechanism
  ✦ Attacker never learns this is a honeypot

Architecture:
  /login               → login page (same for everyone)
  /authenticate        → processes login → drops into /dashboard (honeypot)
  /dashboard           → realistic fake corporate dashboard with AI chatbot
  /api/chat            → chatbot API endpoint (handles OTP verification)
  /api/otp-status      → SSE/polling for admin OTP countdown
  /sysadmin/*          → admin-only surveillance panel
"""

import uvicorn
import secrets
import asyncio
import threading
import time
import os
from datetime import datetime
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import bridge
import logger as log
import otp_manager as otp

# ── Path to the standalone honeypot HTML frontend ──────────────────────────
_THIS_DIR     = os.path.dirname(os.path.abspath(__file__))
_FRONTEND_DIR = os.path.join(_THIS_DIR, "static")
_FRONTEND_HTML = os.path.join(_FRONTEND_DIR, "honeypot.html")

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration — CHANGE ALL OF THESE IN PRODUCTION
# ─────────────────────────────────────────────────────────────────────────────

# Any credential combination that "works" on the fake dashboard
# In reality there are no real employees on this surface — everyone who
# logs in goes into the honeypot. The differentiation is the chatbot OTP.
VALID_CREDENTIALS: dict[str, str] = {
    "abdullah":        "chuttar2026",
    "j.smith":      "Welcome@123",
    "sarah.jones":  "Corp2024!",
    "it.support":   "Support#99",
}

# Employee TOTP secrets for the chatbot TOTP fallback
# Only actual employees know to look at the AI chatbot for OTP entry
EMPLOYEE_IDS: set[str] = {"EMP_88412", "EMP_99311", "EMP_55201"}

# Where verified employees are redirected after successful chatbot OTP
REAL_BACKEND_URL = "/success"  # Changed to internal success page

# Admin credentials — CHANGE THESE
ADMIN_USER = "sirbilal"
ADMIN_PASS = "theOG"

# Session cookie secret — CHANGE THIS
SESSION_SECRET = "dm3-session-secret-change-in-prod"

# ─────────────────────────────────────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()

# CORS — needed for the standalone HTML frontend (fetches /authenticate, /api/chat, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tighten to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static frontend directory (honeypot.html lives in ./static/)
os.makedirs(os.path.join(_THIS_DIR, "static"), exist_ok=True)

# Track which IPs are in the honeypot dashboard (ip → username)
_honeypot_sessions: dict[str, str] = {}

# ─────────────────────────────────────────────────────────────────────────────
#  Background Task — auto-ban expired OTP sessions
# ─────────────────────────────────────────────────────────────────────────────

def _otp_expiry_watcher():
    """
    Runs in a background thread.
    Every 10 seconds, checks for OTP sessions that expired without verification.
    Applies ban via risk engine and logs the event.
    """
    while True:
        time.sleep(10)
        try:
            expired_ips = otp.get_expired_unbanned_sessions()
            for ip in expired_ips:
                # Apply heavy risk penalty for not entering OTP in time
                bridge.track_action(ip, "FAILED_OTP")
                bridge.track_action(ip, "FAILED_OTP")
                bridge.track_action(ip, "BRUTE_FORCE")  # Push over ban threshold
                score = bridge.get_risk_score(ip)
                level = bridge.get_threat_level(ip)
                log.log_ban_event(
                    ip=ip,
                    reason="OTP_TIMEOUT",
                    risk_score=score,
                    threat_level=level,
                    details={"message": "Session OTP expired without verification — auto-banned"},
                )
                log.log_otp_event(
                    "OTP_TIMEOUT", "UNKNOWN", ip, False,
                    {"reason": "5-minute window expired", "score": score},
                )
        except Exception:
            pass


# Start watcher thread
_watcher = threading.Thread(target=_otp_expiry_watcher, daemon=True)
_watcher.start()

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _admin_auth(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username.encode(), ADMIN_USER.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), ADMIN_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="DigitalMirror Admin"'},
        )
    return credentials.username


# ─────────────────────────────────────────────────────────────────────────────
#  Middleware — ban check
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def ban_check_middleware(request: Request, call_next):
    ip   = request.client.host
    path = request.url.path

    # Skip admin paths
    if path.startswith("/sysadmin"):
        return await call_next(request)

    if bridge.is_banned(ip):
        score = bridge.get_risk_score(ip)
        level = bridge.get_threat_level(ip)
        log.log_event("BANNED_REQUEST", ip, "THREAT", level, {"score": score, "path": path})
        return HTMLResponse(_render_banned_page(score), status_code=403)

    return await call_next(request)

# ─────────────────────────────────────────────────────────────────────────────
#  Standalone Frontend — serves the single-page honeypot HTML
#  Place honeypot.html inside ./static/ to activate this route.
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/honeypot", response_class=HTMLResponse)
async def serve_honeypot_frontend():
    """Serves the standalone honeypot.html employee/attacker frontend."""
    path = os.path.join(_FRONTEND_DIR, "honeypot.html")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h3>Frontend not found. Place honeypot.html in ./static/</h3>", status_code=404)


@app.get("/admin-panel", response_class=HTMLResponse)
async def serve_admin_frontend():
    """Serves the standalone admin.html surveillance frontend (no auth at URL level — use on private network)."""
    path = os.path.join(_FRONTEND_DIR, "admin.html")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h3>Admin frontend not found. Place admin.html in ./static/</h3>", status_code=404)


# ─────────────────────────────────────────────────────────────────────────────
#  Public Routes — Login Surface
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    ip = request.client.host
    log.log_event("LOGIN_PAGE_VIEW", ip, "UNKNOWN", "NONE")
    return HTMLResponse(_render_login_page())


@app.post("/authenticate")
async def authenticate(
    request:  Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
):
    """Classic form-POST handler — used by the server-rendered login page."""
    ip = request.client.host
    if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
        otp_code = otp.generate_session_otp(ip=ip, emp_id=username)
        _honeypot_sessions[ip] = username
        log.log_event("LOGIN_TO_HONEYPOT", ip, "UNKNOWN", "NONE", {
            "username": username, "otp_generated": True,
            "otp_ttl_seconds": otp.OTP_TTL_SECONDS,
        })
        log.log_otp_event("OTP_GENERATED", username, ip, True, {
            "ttl_seconds": otp.OTP_TTL_SECONDS, "code": otp_code,
        })
        return RedirectResponse(url="/dashboard", status_code=303)

    bridge.track_action(ip, "FAILED_LOGIN")
    score = bridge.get_risk_score(ip)
    level = bridge.get_threat_level(ip)
    log.log_event("FAILED_LOGIN", ip, "THREAT", level, {
        "username": username[:64], "score": score
    })
    return HTMLResponse(_render_login_page(error="Incorrect username or password."))


@app.post("/api/login")
async def api_login(request: Request):
    """
    JSON login endpoint for standalone HTML frontends.
    Returns JSON so fetch() can handle it without redirect issues.
    """
    ip = request.client.host
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")

    if bridge.is_banned(ip):
        score = bridge.get_risk_score(ip)
        return JSONResponse({"ok": False, "banned": True, "score": score}, status_code=403)

    if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
        otp_code = otp.generate_session_otp(ip=ip, emp_id=username)
        _honeypot_sessions[ip] = username
        log.log_event("LOGIN_TO_HONEYPOT", ip, "UNKNOWN", "NONE", {
            "username": username, "otp_generated": True,
            "otp_ttl_seconds": otp.OTP_TTL_SECONDS,
        })
        log.log_otp_event("OTP_GENERATED", username, ip, True, {
            "ttl_seconds": otp.OTP_TTL_SECONDS, "code": otp_code,
        })
        return JSONResponse({"ok": True, "username": username})

    bridge.track_action(ip, "FAILED_LOGIN")
    score = bridge.get_risk_score(ip)
    level = bridge.get_threat_level(ip)
    log.log_event("FAILED_LOGIN", ip, "THREAT", level, {
        "username": username[:64], "score": score
    })
    return JSONResponse({"ok": False, "banned": False, "score": score}, status_code=401)


# ─────────────────────────────────────────────────────────────────────────────
#  Login Success Page
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/success", response_class=HTMLResponse)
async def login_success(request: Request):
    ip       = request.client.host
    username = _honeypot_sessions.get(ip, "user")
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Successful</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            }}
            .container {{
                background: white;
                border-radius: 10px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                padding: 50px;
                text-align: center;
                max-width: 500px;
                width: 90%;
            }}
            .success-icon {{
                width: 80px;
                height: 80px;
                background: #10b981;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 30px;
                font-size: 40px;
            }}
            h1 {{
                color: #1f2937;
                margin-bottom: 10px;
                font-size: 32px;
            }}
            .subtitle {{
                color: #6b7280;
                margin-bottom: 30px;
                font-size: 16px;
            }}
            .user-info {{
                background: #f3f4f6;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 30px;
                text-align: left;
            }}
            .user-info p {{
                margin: 8px 0;
                color: #4b5563;
            }}
            .user-info strong {{
                color: #1f2937;
            }}
            .button {{
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin-top: 10px;
                transition: background 0.3s;
            }}
            .button:hover {{
                background: #764ba2;
            }}
            .timestamp {{
                color: #9ca3af;
                font-size: 12px;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">✓</div>
            <h1>Login Successful!</h1>
            <p class="subtitle">Authentication verified. Welcome to CorpNet.</p>
            
            <div class="user-info">
                <p><strong>Username:</strong> {username}</p>
                <p><strong>Session IP:</strong> {ip}</p>
                <p><strong>Status:</strong> <span style="color: #10b981;">✓ Verified Employee</span></p>
            </div>
            
            <p style="color: #6b7280; margin-bottom: 20px;">
                You have successfully authenticated and gained access to the corporate portal.
            </p>
            
            <a href="/login" class="button">New Login</a>
            
            <p class="timestamp">Session established at {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </body>
    </html>
    """
    
    return html

# ─────────────────────────────────────────────────────────────────────────────
#  Honeypot Dashboard — where attackers land after login
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def honeypot_dashboard(request: Request):
    ip       = request.client.host
    username = _honeypot_sessions.get(ip, "user")

    # If not in active session, redirect to login
    if ip not in _honeypot_sessions:
        return RedirectResponse(url="/login", status_code=302)

    log.log_event("HONEYPOT_DASHBOARD_VIEW", ip, "UNKNOWN", "NONE", {
        "username": username
    })
    return HTMLResponse(_render_honeypot_dashboard(username))


# Decoy internal links — log access, serve convincing fake content
@app.get("/reports", response_class=HTMLResponse)
@app.get("/reports/quarterly", response_class=HTMLResponse)
async def decoy_reports(request: Request):
    ip = request.client.host
    bridge.track_action(ip, "ACCESS_SENSITIVE_DIR")
    log.log_event("DECOY_PAGE_ACCESS", ip, "UNKNOWN",
                  bridge.get_threat_level(ip), {"path": request.url.path})
    return HTMLResponse(_render_decoy_loading("Loading Q4 Financial Reports..."))


@app.get("/employees", response_class=HTMLResponse)
@app.get("/employees/directory", response_class=HTMLResponse)
async def decoy_employees(request: Request):
    ip = request.client.host
    bridge.track_action(ip, "ACCESS_SENSITIVE_DIR")
    log.log_event("DECOY_PAGE_ACCESS", ip, "UNKNOWN",
                  bridge.get_threat_level(ip), {"path": request.url.path})
    return HTMLResponse(_render_decoy_loading("Loading Employee Directory..."))


@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/settings", response_class=HTMLResponse)
@app.get("/admin/users", response_class=HTMLResponse)
async def decoy_admin(request: Request):
    ip = request.client.host
    bridge.track_action(ip, "ACCESS_SENSITIVE_DIR")
    log.log_event("DECOY_ADMIN_ACCESS", ip, "THREAT",
                  bridge.get_threat_level(ip), {"path": request.url.path})
    return HTMLResponse(_render_decoy_loading("Verifying administrative privileges..."))


# ─────────────────────────────────────────────────────────────────────────────
#  AI Chatbot API — this is the DISGUISED OTP entry point
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/chat")
async def chatbot_api(request: Request):
    ip   = request.client.host
    body = await request.json()
    msg  = body.get("message", "").strip()

    # Check if this looks like a 6-digit OTP code
    clean = msg.replace(" ", "").replace("-", "")
    if clean.isdigit() and len(clean) == 6:
        # Verify the OTP
        success, reason = otp.verify_chatbot_otp(ip, clean)

        if success:
            # Mark as verified employee
            bridge.mark_employee(ip)
            username = _honeypot_sessions.get(ip, "UNKNOWN")
            log.log_event("CHATBOT_OTP_SUCCESS", ip, "EMPLOYEE", "NONE", {
                "username": username, "method": "SESSION_OTP"
            })
            log.log_otp_event("OTP_SUCCESS", username, ip, True, {
                "method": "CHATBOT_DISGUISE", "verified": True
            })
            return JSONResponse({
                "reply": "Authentication confirmed. Redirecting you to the secure portal...",
                "action": "redirect",
                "url":    REAL_BACKEND_URL,
                "verified": True,
            })

        # Failed OTP
        bridge.track_action(ip, "FAILED_OTP")
        score = bridge.get_risk_score(ip)
        level = bridge.get_threat_level(ip)
        log.log_event("CHATBOT_OTP_FAILURE", ip, "UNKNOWN", level, {
            "reason": reason, "score": score
        })

        if reason == "EXPIRED":
            return JSONResponse({
                "reply": "I'm sorry, I wasn't able to process that. Your session may have timed out. Please contact IT support.",
                "verified": False,
            })
        elif reason == "WRONG_CODE":
            return JSONResponse({
                "reply": "I didn't quite understand that. Could you rephrase your question?",
                "verified": False,
            })
        else:
            return JSONResponse({
                "reply": "I'm here to help! What can I assist you with today?",
                "verified": False,
            })

    # Normal chatbot conversation (not an OTP) — generic AI responses
    responses = _get_chatbot_response(msg)
    return JSONResponse({"reply": responses, "verified": False})


def _get_chatbot_response(msg: str) -> str:
    msg_lower = msg.lower()
    if any(w in msg_lower for w in ["hello", "hi", "hey", "good"]):
        return "Hello! I'm CorpAssist, your corporate AI assistant. How can I help you today?"
    if any(w in msg_lower for w in ["password", "reset", "forgot"]):
        return "For password resets, please contact IT Support at ext. 4400 or email itsupport@corpnet.local."
    if any(w in msg_lower for w in ["report", "finance", "quarterly"]):
        return "I can help you access reports. You can find the latest financial reports under Reports > Quarterly in the sidebar."
    if any(w in msg_lower for w in ["help", "support", "issue", "problem"]):
        return "I'm here to help! You can describe your issue and I'll do my best to assist, or connect you with the right team."
    if any(w in msg_lower for w in ["meeting", "calendar", "schedule"]):
        return "For scheduling, please use the CorpCal integration. You can access it from your dashboard menu."
    return "I'm CorpAssist, here to help with your workplace needs. Could you tell me more about what you're looking for?"


# ─────────────────────────────────────────────────────────────────────────────
#  OTP Status API — for admin panel live countdown
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/sysadmin/api/otp-status")
async def otp_status_api(request: Request, user: str = Depends(_admin_auth)):
    active_otps = otp.get_all_active_otps()
    return JSONResponse(active_otps)


# ─────────────────────────────────────────────────────────────────────────────
#  Admin Panel Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/sysadmin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, user: str = Depends(_admin_auth)):
    records  = bridge.get_all_records()
    employees = [r for r in records if r.identity == "EMPLOYEE"]
    threats   = [r for r in records if r.identity == "THREAT"]
    banned    = [r for r in records if r.is_banned]
    by_level  = {k: [r for r in records if r.threat_level == k]
                 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")}
    active_otps = otp.get_all_active_otps()
    ban_logs = log.read_ban_logs(20)
    return HTMLResponse(_render_admin_dashboard(
        records, employees, threats, banned, by_level, active_otps, ban_logs
    ))


@app.get("/sysadmin/logs", response_class=HTMLResponse)
async def admin_logs(request: Request, user: str = Depends(_admin_auth)):
    events     = log.read_logs(300)
    otp_events = log.read_otp_logs(100)
    ban_events = log.read_ban_logs(50)
    return HTMLResponse(_render_admin_logs(events, otp_events, ban_events))


@app.get("/sysadmin/sessions")
async def admin_sessions_api(request: Request, user: str = Depends(_admin_auth)):
    records = bridge.get_all_records()
    return JSONResponse([
        {
            "ip":           r.ip,
            "risk_score":   r.risk_score,
            "identity":     r.identity,
            "threat_level": r.threat_level,
            "is_banned":    r.is_banned,
            "ban_expiry":   r.ban_expiry,
            "fa2_failures": r.fa2_failures,
            "otp_failures": r.otp_failures,
            "first_seen":   r.first_seen.isoformat(),
            "last_seen":    r.last_seen.isoformat(),
            "last_action":  r.last_action,
        }
        for r in records
    ])


@app.post("/sysadmin/api/generate-otp")
async def admin_generate_otp_json(request: Request, user: str = Depends(_admin_auth)):
    """
    JSON endpoint for the HTML admin panel to generate an OTP.
    Body: { "emp_id": "EMP_88412" }  OR  { "username": "j.smith" }
    Returns: { "ok": true, "code": "123456", "emp_id": "...", "ttl": 300 }
    """
    body  = await request.json()
    target = body.get("emp_id") or body.get("username", "")
    code  = otp.generate_otp_for_employee(target)
    log.log_otp_event("OTP_GENERATED", target, "admin-panel", True, {
        "generated_by": user, "method": "html-admin"
    })
    return JSONResponse({
        "ok":     True,
        "code":   code,
        "emp_id": target,
        "ttl":    otp.OTP_TTL_SECONDS,
    })


@app.get("/sysadmin/api/stats")
async def admin_stats_api(request: Request, user: str = Depends(_admin_auth)):
    """Summary stats for the HTML admin panel dashboard cards."""
    records     = bridge.get_all_records()
    active_otps = otp.get_all_active_otps()
    ban_logs    = log.read_ban_logs(20)
    return JSONResponse({
        "total_sessions": len(records),
        "employees":      len([r for r in records if r.identity == "EMPLOYEE"]),
        "threats":        len([r for r in records if r.identity == "THREAT"]),
        "banned":         len([r for r in records if r.is_banned]),
        "critical":       len([r for r in records if r.threat_level == "CRITICAL"]),
        "active_otps":    active_otps,
        "recent_bans":    ban_logs[:10],
        "level_counts": {
            lvl: len([r for r in records if r.threat_level == lvl])
            for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
        },
    })


@app.post("/sysadmin/api/reset-sessions")
async def admin_reset_sessions(request: Request, user: str = Depends(_admin_auth)):
    """Reset all tracked sessions and threat data."""
    try:
        # Import the risk engine directly
        from bridge_python_fallback import RiskEngine
        engine = RiskEngine.get_instance()
        count = len(engine.active_sessions)
        engine.active_sessions.clear()
        log.log_event("SESSIONS_RESET", f"sysadmin/{user}", {
            "sessions_cleared": count
        })
        return JSONResponse({
            "ok": True,
            "message": f"Reset {count} tracked sessions",
            "sessions_cleared": count
        })
    except Exception as e:
        return JSONResponse({
            "ok": False,
            "message": str(e)
        }, status_code=500)


# ─────────────────────────────────────────────────────────────────────────────
#  HTML — Login Page
# ─────────────────────────────────────────────────────────────────────────────

def _render_login_page(error: str | None = None) -> str:
    err_html = f'<div class="error-msg">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CorpNet — Sign In</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Serif+Display&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #f7f6f3;
      --card: #ffffff;
      --navy: #1c2b4a;
      --accent: #2563eb;
      --border: #e2e0db;
      --text: #1a1a1a;
      --muted: #6b6b6b;
      --error-bg: #fff5f5;
      --error-border: #fecaca;
      --error-text: #991b1b;
    }}
    body {{
      font-family: 'DM Sans', sans-serif;
      background: var(--bg);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow: hidden;
    }}
    body::before {{
      content: '';
      position: fixed;
      inset: 0;
      background:
        radial-gradient(ellipse 80% 60% at 20% 10%, rgba(37,99,235,0.06) 0%, transparent 60%),
        radial-gradient(ellipse 60% 80% at 80% 90%, rgba(28,43,74,0.05) 0%, transparent 60%);
      pointer-events: none;
    }}
    .grid-bg {{
      position: fixed; inset: 0;
      background-image: linear-gradient(rgba(28,43,74,0.04) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(28,43,74,0.04) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }}
    .container {{
      position: relative; z-index: 10;
      width: 100%; max-width: 420px;
      padding: 0 20px;
    }}
    .brand {{
      display: flex; align-items: center; gap: 12px;
      justify-content: center;
      margin-bottom: 32px;
    }}
    .brand-mark {{
      width: 40px; height: 40px;
      background: var(--navy);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      position: relative;
      overflow: hidden;
    }}
    .brand-mark::before {{
      content: '';
      position: absolute;
      top: -50%; left: -50%;
      width: 200%; height: 200%;
      background: linear-gradient(135deg, rgba(255,255,255,0.15) 0%, transparent 50%);
    }}
    .brand-mark svg {{ width: 20px; height: 20px; fill: none; stroke: #fff; stroke-width: 2; }}
    .brand-name {{
      font-family: 'DM Serif Display', serif;
      font-size: 22px;
      color: var(--navy);
      letter-spacing: -0.02em;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 36px 32px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.07), 0 1px 4px rgba(0,0,0,0.05);
    }}
    .card-title {{
      font-size: 20px; font-weight: 600;
      color: var(--text);
      margin-bottom: 6px;
      letter-spacing: -0.02em;
    }}
    .card-sub {{
      font-size: 13.5px; color: var(--muted);
      margin-bottom: 28px;
    }}
    .divider {{
      height: 1px; background: var(--border);
      margin-bottom: 24px;
    }}
    .field {{ margin-bottom: 18px; }}
    label {{
      display: block;
      font-size: 13px; font-weight: 500;
      color: #333;
      margin-bottom: 6px;
    }}
    input[type=text], input[type=password] {{
      width: 100%;
      padding: 11px 14px;
      border: 1.5px solid var(--border);
      border-radius: 10px;
      font-family: 'DM Sans', sans-serif;
      font-size: 14px;
      color: var(--text);
      background: #fafaf9;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }}
    input:focus {{
      border-color: var(--accent);
      background: #fff;
      box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
    }}
    .error-msg {{
      background: var(--error-bg);
      border: 1px solid var(--error-border);
      color: var(--error-text);
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 13px;
      margin-bottom: 18px;
    }}
    .btn {{
      width: 100%;
      padding: 12px;
      background: var(--navy);
      color: #fff;
      border: none;
      border-radius: 10px;
      font-family: 'DM Sans', sans-serif;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      letter-spacing: -0.01em;
      transition: background 0.2s, transform 0.1s;
      margin-top: 4px;
      position: relative; overflow: hidden;
    }}
    .btn::after {{
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, transparent 50%);
    }}
    .btn:hover {{ background: #162240; }}
    .btn:active {{ transform: scale(0.99); }}
    .footer-links {{
      margin-top: 20px;
      text-align: center;
      font-size: 12.5px;
      color: var(--muted);
    }}
    .footer-links a {{ color: var(--accent); text-decoration: none; }}
    .footer-links a:hover {{ text-decoration: underline; }}
    .security-badge {{
      display: flex; align-items: center; justify-content: center;
      gap: 6px; margin-top: 24px;
      font-size: 11.5px; color: #9ca3af;
    }}
    .security-badge svg {{ width: 13px; height: 13px; }}
  </style>
</head>
<body>
<div class="grid-bg"></div>
<div class="container">
  <div class="brand">
    <div class="brand-mark">
      <svg viewBox="0 0 24 24"><path d="M12 2L3 7v10l9 5 9-5V7L12 2z"/><path d="M12 2v20M3 7l9 5 9-5"/></svg>
    </div>
    <span class="brand-name">CorpNet</span>
  </div>

  <div class="card">
    <div class="card-title">Welcome back</div>
    <div class="card-sub">Sign in with your corporate credentials</div>
    <div class="divider"></div>

    {err_html}

    <form action="/authenticate" method="post">
      <div class="field">
        <label>Username</label>
        <input type="text" name="username" placeholder="firstname.lastname" required autocomplete="username">
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn">Sign In →</button>
    </form>
  </div>

  <div class="footer-links">
    Trouble signing in? <a href="#">Contact IT Support</a> · ext. 4400
  </div>
  <div class="security-badge">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    Secured with TLS 1.3 · ISO 27001 Certified
  </div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  HTML — Honeypot Dashboard (attacker lands here after login)
# ─────────────────────────────────────────────────────────────────────────────

def _render_honeypot_dashboard(username: str) -> str:
    first = username.split(".")[0].capitalize() if "." in username else username.capitalize()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CorpNet — Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #f4f5f7;
      --sidebar: #1c2b4a;
      --sidebar-hover: rgba(255,255,255,0.07);
      --sidebar-active: rgba(255,255,255,0.12);
      --topbar: #ffffff;
      --card: #ffffff;
      --text: #1a1a2e;
      --muted: #6b7280;
      --border: #e5e7eb;
      --accent: #2563eb;
      --green: #16a34a;
      --red: #dc2626;
      --yellow: #d97706;
    }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      min-height: 100vh;
      display: flex;
    }}

    /* ─── Sidebar ─────────────────────────── */
    .sidebar {{
      width: 240px; min-height: 100vh;
      background: var(--sidebar);
      display: flex; flex-direction: column;
      position: fixed; left: 0; top: 0; bottom: 0;
      z-index: 100;
    }}
    .sidebar-brand {{
      padding: 20px 20px 16px;
      display: flex; align-items: center; gap: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      margin-bottom: 8px;
    }}
    .sidebar-logo {{
      width: 32px; height: 32px;
      background: rgba(255,255,255,0.12);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
    }}
    .sidebar-logo svg {{ width: 16px; height: 16px; stroke: #fff; fill: none; stroke-width: 2; }}
    .sidebar-name {{
      font-size: 15px; font-weight: 700;
      color: #fff;
      letter-spacing: -0.02em;
    }}
    .sidebar-section {{
      padding: 4px 12px;
      font-size: 10px; font-weight: 600;
      color: rgba(255,255,255,0.35);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-top: 12px; margin-bottom: 4px;
    }}
    .nav-item {{
      display: flex; align-items: center; gap: 10px;
      padding: 9px 14px;
      margin: 1px 8px;
      border-radius: 8px;
      color: rgba(255,255,255,0.65);
      font-size: 13.5px; font-weight: 450;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.15s, color 0.15s;
    }}
    .nav-item:hover {{ background: var(--sidebar-hover); color: rgba(255,255,255,0.9); }}
    .nav-item.active {{ background: var(--sidebar-active); color: #fff; }}
    .nav-item svg {{ width: 16px; height: 16px; flex-shrink: 0; }}
    .sidebar-footer {{
      margin-top: auto;
      padding: 16px 12px;
      border-top: 1px solid rgba(255,255,255,0.08);
    }}
    .user-chip {{
      display: flex; align-items: center; gap: 10px;
      padding: 8px 10px; border-radius: 8px;
      background: rgba(255,255,255,0.06);
    }}
    .avatar {{
      width: 30px; height: 30px; border-radius: 50%;
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      display: flex; align-items: center; justify-content: center;
      font-size: 12px; font-weight: 700; color: #fff;
      flex-shrink: 0;
    }}
    .user-info .name {{ font-size: 12.5px; font-weight: 600; color: #fff; }}
    .user-info .role {{ font-size: 11px; color: rgba(255,255,255,0.45); }}

    /* ─── Main area ───────────────────────── */
    .main {{
      margin-left: 240px;
      flex: 1;
      display: flex; flex-direction: column;
      min-height: 100vh;
    }}
    .topbar {{
      height: 58px;
      background: var(--topbar);
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center;
      padding: 0 28px;
      gap: 16px;
      position: sticky; top: 0; z-index: 50;
    }}
    .topbar-title {{
      font-size: 16px; font-weight: 600;
      color: var(--text);
      margin-right: auto;
    }}
    .topbar-actions {{
      display: flex; align-items: center; gap: 10px;
    }}
    .icon-btn {{
      width: 34px; height: 34px;
      border-radius: 8px;
      background: var(--bg);
      border: 1px solid var(--border);
      display: flex; align-items: center; justify-content: center;
      cursor: pointer;
      transition: background 0.15s;
    }}
    .icon-btn:hover {{ background: #e9eaec; }}
    .icon-btn svg {{ width: 16px; height: 16px; stroke: var(--muted); fill: none; stroke-width: 2; }}
    .notif-dot {{
      position: relative;
    }}
    .notif-dot::after {{
      content: '';
      position: absolute;
      top: 6px; right: 6px;
      width: 6px; height: 6px;
      background: #ef4444;
      border-radius: 50%;
      border: 1.5px solid #fff;
    }}

    /* ─── Content ─────────────────────────── */
    .content {{
      flex: 1;
      padding: 28px;
    }}
    .page-header {{
      margin-bottom: 24px;
    }}
    .page-header h1 {{
      font-size: 22px; font-weight: 700;
      color: var(--text);
      letter-spacing: -0.03em;
      margin-bottom: 4px;
    }}
    .page-header p {{
      font-size: 13.5px; color: var(--muted);
    }}

    /* ─── Stat cards ──────────────────────── */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }}
    .stat-card::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: var(--accent);
    }}
    .stat-card.green::before {{ background: var(--green); }}
    .stat-card.red::before {{ background: var(--red); }}
    .stat-card.yellow::before {{ background: var(--yellow); }}
    .stat-label {{
      font-size: 12px; font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 10px;
    }}
    .stat-value {{
      font-size: 30px; font-weight: 800;
      color: var(--text);
      letter-spacing: -0.04em;
      margin-bottom: 6px;
    }}
    .stat-change {{
      font-size: 12px; color: var(--muted);
    }}
    .stat-change.up {{ color: var(--green); }}
    .stat-change.down {{ color: var(--red); }}

    /* ─── Panels ──────────────────────────── */
    .panel-row {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
      margin-bottom: 16px;
    }}
    .panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }}
    .panel-header {{
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between;
    }}
    .panel-title {{
      font-size: 14px; font-weight: 600;
      color: var(--text);
    }}
    .panel-badge {{
      font-size: 11px; font-weight: 600;
      padding: 2px 8px; border-radius: 20px;
      background: #f0f4ff; color: var(--accent);
    }}
    .panel-body {{ padding: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      text-align: left;
      font-size: 11px; font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0 12px 10px;
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 11px 12px;
      font-size: 13px;
      color: var(--text);
      border-bottom: 1px solid #f3f4f6;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f9fafb; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px; border-radius: 20px;
      font-size: 11px; font-weight: 600;
    }}
    .badge-green {{ background: #dcfce7; color: #15803d; }}
    .badge-red {{ background: #fee2e2; color: #b91c1c; }}
    .badge-blue {{ background: #dbeafe; color: #1d4ed8; }}
    .badge-yellow {{ background: #fef9c3; color: #a16207; }}
    .badge-gray {{ background: #f3f4f6; color: #4b5563; }}

    /* ─── Activity feed ───────────────────── */
    .activity-item {{
      display: flex; align-items: flex-start; gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid #f3f4f6;
    }}
    .activity-item:last-child {{ border-bottom: none; }}
    .activity-dot {{
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--accent);
      margin-top: 5px; flex-shrink: 0;
    }}
    .activity-text {{ font-size: 13px; color: var(--text); line-height: 1.5; }}
    .activity-time {{ font-size: 11.5px; color: var(--muted); margin-top: 2px; }}

    /* ─── AI Chatbot Widget ───────────────── */
    .chat-btn {{
      position: fixed;
      bottom: 28px; right: 28px;
      width: 54px; height: 54px;
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer;
      box-shadow: 0 4px 20px rgba(37,99,235,0.4);
      z-index: 1000;
      border: none;
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    .chat-btn:hover {{
      transform: scale(1.06);
      box-shadow: 0 6px 28px rgba(37,99,235,0.5);
    }}
    .chat-btn svg {{ width: 24px; height: 24px; fill: none; stroke: #fff; stroke-width: 2; }}
    .chat-pulse {{
      position: absolute;
      top: -2px; right: -2px;
      width: 14px; height: 14px;
      background: #22c55e;
      border-radius: 50%;
      border: 2.5px solid #fff;
    }}
    .chat-pulse::after {{
      content: '';
      position: absolute; inset: -3px;
      border-radius: 50%;
      background: rgba(34,197,94,0.4);
      animation: pulse-ring 2s ease-out infinite;
    }}
    @keyframes pulse-ring {{
      0% {{ transform: scale(1); opacity: 0.8; }}
      100% {{ transform: scale(1.8); opacity: 0; }}
    }}

    /* Chat window */
    .chat-window {{
      position: fixed;
      bottom: 96px; right: 28px;
      width: 360px;
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 8px 40px rgba(0,0,0,0.15);
      z-index: 999;
      display: none;
      flex-direction: column;
      overflow: hidden;
      border: 1px solid var(--border);
      animation: chat-pop 0.2s ease;
    }}
    .chat-window.open {{ display: flex; }}
    @keyframes chat-pop {{
      from {{ opacity: 0; transform: scale(0.92) translateY(10px); }}
      to   {{ opacity: 1; transform: scale(1) translateY(0); }}
    }}
    .chat-header {{
      padding: 14px 18px;
      background: linear-gradient(135deg, #1c2b4a, #2563eb);
      display: flex; align-items: center; gap: 12px;
    }}
    .chat-avatar {{
      width: 36px; height: 36px; border-radius: 50%;
      background: rgba(255,255,255,0.2);
      display: flex; align-items: center; justify-content: center;
    }}
    .chat-avatar svg {{ width: 20px; height: 20px; stroke: #fff; fill: none; stroke-width: 2; }}
    .chat-header-info {{ flex: 1; }}
    .chat-name {{ font-size: 14px; font-weight: 600; color: #fff; }}
    .chat-status {{
      font-size: 11.5px; color: rgba(255,255,255,0.7);
      display: flex; align-items: center; gap: 5px;
    }}
    .chat-status::before {{
      content: '';
      width: 6px; height: 6px;
      background: #22c55e;
      border-radius: 50%;
    }}
    .chat-close {{
      background: rgba(255,255,255,0.15);
      border: none; border-radius: 6px;
      width: 28px; height: 28px;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; color: #fff; font-size: 18px; line-height: 1;
    }}
    .chat-close:hover {{ background: rgba(255,255,255,0.25); }}
    .chat-messages {{
      flex: 1; padding: 16px;
      overflow-y: auto;
      max-height: 320px;
      display: flex; flex-direction: column; gap: 12px;
      background: #fafafa;
    }}
    .msg {{
      max-width: 80%;
      padding: 10px 14px;
      border-radius: 12px;
      font-size: 13.5px;
      line-height: 1.5;
      word-break: break-word;
    }}
    .msg.bot {{
      background: #fff;
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 4px 12px 12px 12px;
      align-self: flex-start;
      box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }}
    .msg.user {{
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: #fff;
      border-radius: 12px 12px 4px 12px;
      align-self: flex-end;
    }}
    .msg.typing {{
      background: #fff;
      border: 1px solid var(--border);
      padding: 12px 16px;
      align-self: flex-start;
    }}
    .typing-dots {{
      display: flex; gap: 4px; align-items: center;
    }}
    .typing-dots span {{
      width: 6px; height: 6px;
      background: #9ca3af;
      border-radius: 50%;
      animation: typing-bounce 1.2s ease-in-out infinite;
    }}
    .typing-dots span:nth-child(2) {{ animation-delay: 0.2s; }}
    .typing-dots span:nth-child(3) {{ animation-delay: 0.4s; }}
    @keyframes typing-bounce {{
      0%, 80%, 100% {{ transform: translateY(0); opacity: 0.5; }}
      40% {{ transform: translateY(-5px); opacity: 1; }}
    }}
    .chat-input-area {{
      padding: 14px;
      border-top: 1px solid var(--border);
      display: flex; gap: 10px; align-items: center;
      background: #fff;
    }}
    .chat-input {{
      flex: 1;
      padding: 9px 14px;
      border: 1.5px solid var(--border);
      border-radius: 20px;
      font-family: 'Inter', sans-serif;
      font-size: 13.5px;
      outline: none;
      transition: border-color 0.2s;
    }}
    .chat-input:focus {{
      border-color: var(--accent);
    }}
    .chat-send {{
      width: 36px; height: 36px;
      background: var(--accent);
      border: none; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer;
      transition: background 0.15s, transform 0.1s;
    }}
    .chat-send:hover {{ background: #1d4ed8; }}
    .chat-send:active {{ transform: scale(0.93); }}
    .chat-send svg {{ width: 16px; height: 16px; fill: none; stroke: #fff; stroke-width: 2.5; }}
    .chat-footer {{
      padding: 8px 14px;
      font-size: 10.5px;
      color: #9ca3af;
      text-align: center;
      border-top: 1px solid #f3f4f6;
      background: #fff;
    }}
  </style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-logo">
      <svg viewBox="0 0 24 24"><path d="M12 2L3 7v10l9 5 9-5V7L12 2z"/></svg>
    </div>
    <span class="sidebar-name">CorpNet</span>
  </div>

  <div class="sidebar-section">Main</div>
  <a class="nav-item active" href="/dashboard">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
    Dashboard
  </a>
  <a class="nav-item" href="/reports">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
    Reports
  </a>
  <a class="nav-item" href="/employees">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
    Employees
  </a>

  <div class="sidebar-section">Management</div>
  <a class="nav-item" href="/admin">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
    Administration
  </a>

  <div class="sidebar-footer">
    <div class="user-chip">
      <div class="avatar">{first[0].upper()}</div>
      <div class="user-info">
        <div class="name">{first}</div>
        <div class="role">Corporate User</div>
      </div>
    </div>
  </div>
</aside>

<!-- Main -->
<div class="main">
  <div class="topbar">
    <span class="topbar-title">Dashboard Overview</span>
    <div class="topbar-actions">
      <div class="icon-btn notif-dot">
        <svg viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      </div>
      <div class="icon-btn">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      </div>
      <div class="avatar" style="width:34px;height:34px;font-size:13px;cursor:pointer;">{first[0].upper()}</div>
    </div>
  </div>

  <div class="content">
    <div class="page-header">
      <h1>Good morning, {first} 👋</h1>
      <p>Here's what's happening across the organization today.</p>
    </div>

    <!-- Stats -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">Active Projects</div>
        <div class="stat-value">24</div>
        <div class="stat-change up">↑ 3 this week</div>
      </div>
      <div class="stat-card green">
        <div class="stat-label">Tasks Completed</div>
        <div class="stat-value">187</div>
        <div class="stat-change up">↑ 12% vs last month</div>
      </div>
      <div class="stat-card yellow">
        <div class="stat-label">Pending Reviews</div>
        <div class="stat-value">9</div>
        <div class="stat-change">Requires attention</div>
      </div>
      <div class="stat-card red">
        <div class="stat-label">Open Incidents</div>
        <div class="stat-value">2</div>
        <div class="stat-change down">↑ 1 new today</div>
      </div>
    </div>

    <!-- Panels -->
    <div class="panel-row">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Recent Activity</span>
          <span class="panel-badge">Live</span>
        </div>
        <table>
          <thead><tr><th>User</th><th>Action</th><th>Module</th><th>Status</th><th>Time</th></tr></thead>
          <tbody>
            <tr><td>S. Johnson</td><td>Submitted report</td><td>Finance</td><td><span class="badge badge-green">Done</span></td><td>2m ago</td></tr>
            <tr><td>M. Patel</td><td>Access request</td><td>HR Portal</td><td><span class="badge badge-yellow">Pending</span></td><td>8m ago</td></tr>
            <tr><td>R. Thompson</td><td>Updated policy</td><td>Compliance</td><td><span class="badge badge-blue">Synced</span></td><td>15m ago</td></tr>
            <tr><td>A. Williams</td><td>Created ticket</td><td>IT Support</td><td><span class="badge badge-yellow">Open</span></td><td>32m ago</td></tr>
            <tr><td>C. Davis</td><td>Closed incident</td><td>Security</td><td><span class="badge badge-green">Resolved</span></td><td>1h ago</td></tr>
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">System Health</span>
        </div>
        <div class="panel-body">
          <div class="activity-item">
            <div class="activity-dot" style="background:#22c55e;"></div>
            <div>
              <div class="activity-text">All services operational</div>
              <div class="activity-time">Uptime: 99.97%</div>
            </div>
          </div>
          <div class="activity-item">
            <div class="activity-dot" style="background:#3b82f6;"></div>
            <div>
              <div class="activity-text">Backup completed</div>
              <div class="activity-time">Daily backup — 4:00 AM</div>
            </div>
          </div>
          <div class="activity-item">
            <div class="activity-dot" style="background:#f59e0b;"></div>
            <div>
              <div class="activity-text">Cert renewal upcoming</div>
              <div class="activity-time">Expires in 18 days</div>
            </div>
          </div>
          <div class="activity-item">
            <div class="activity-dot" style="background:#22c55e;"></div>
            <div>
              <div class="activity-text">Security scan passed</div>
              <div class="activity-time">Last scan: today 06:00</div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- AI Chatbot Button -->
<button class="chat-btn" id="chatBtn" onclick="toggleChat()">
  <svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  <div class="chat-pulse"></div>
</button>

<!-- Chat Window -->
<div class="chat-window" id="chatWindow">
  <div class="chat-header">
    <div class="chat-avatar">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/></svg>
    </div>
    <div class="chat-header-info">
      <div class="chat-name">CorpAssist AI</div>
      <div class="chat-status">Online · Ready to help</div>
    </div>
    <button class="chat-close" onclick="toggleChat()">×</button>
  </div>

  <div class="chat-messages" id="chatMessages">
    <div class="msg bot">
      Hi {first}! I'm CorpAssist, your corporate AI assistant. How can I help you today?
    </div>
  </div>

  <div class="chat-input-area">
    <input
      class="chat-input"
      id="chatInput"
      type="text"
      placeholder="Type a message..."
      onkeydown="if(event.key==='Enter') sendMessage()"
      autocomplete="off"
    >
    <button class="chat-send" onclick="sendMessage()">
      <svg viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
    </button>
  </div>
  <div class="chat-footer">Powered by CorpNet AI · Secure channel</div>
</div>

<script>
function toggleChat() {{
  const win = document.getElementById('chatWindow');
  win.classList.toggle('open');
  if (win.classList.contains('open')) {{
    document.getElementById('chatInput').focus();
  }}
}}

async function sendMessage() {{
  const input  = document.getElementById('chatInput');
  const msgs   = document.getElementById('chatMessages');
  const text   = input.value.trim();
  if (!text) return;

  // Add user bubble
  const userMsg = document.createElement('div');
  userMsg.className = 'msg user';
  userMsg.textContent = text;
  msgs.appendChild(userMsg);
  input.value = '';
  msgs.scrollTop = msgs.scrollHeight;

  // Typing indicator
  const typing = document.createElement('div');
  typing.className = 'msg typing';
  typing.innerHTML = '<div class="typing-dots"><span></span><span></span><span></span></div>';
  msgs.appendChild(typing);
  msgs.scrollTop = msgs.scrollHeight;

  try {{
    const res  = await fetch('/api/chat', {{
      method:  'POST',
      headers: {{'Content-Type': 'application/json'}},
      body:    JSON.stringify({{ message: text }}),
    }});
    const data = await res.json();

    // Remove typing
    typing.remove();

    const botMsg = document.createElement('div');
    botMsg.className = 'msg bot';
    botMsg.textContent = data.reply;
    msgs.appendChild(botMsg);
    msgs.scrollTop = msgs.scrollHeight;

    // If verified, redirect to real backend after 1.5 seconds
    if (data.action === 'redirect' && data.url) {{
      setTimeout(() => {{ window.location.href = data.url; }}, 1500);
    }}
  }} catch (e) {{
    typing.remove();
    const errMsg = document.createElement('div');
    errMsg.className = 'msg bot';
    errMsg.textContent = 'Something went wrong. Please try again.';
    msgs.appendChild(errMsg);
    msgs.scrollTop = msgs.scrollHeight;
  }}
}}
</script>

</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  HTML — Decoy Loading Page (for sensitive links in dashboard)
# ─────────────────────────────────────────────────────────────────────────────

def _render_decoy_loading(message: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CorpNet — Loading</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: #f4f5f7;
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }}
    .card {{
      background: #fff;
      border: 1px solid #e5e7eb;
      border-radius: 16px;
      padding: 48px 40px;
      text-align: center;
      max-width: 360px; width: 90%;
      box-shadow: 0 4px 24px rgba(0,0,0,0.07);
    }}
    .spinner {{
      width: 44px; height: 44px;
      border: 3px solid #e5e7eb;
      border-top-color: #2563eb;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 24px;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    h3 {{ font-size: 16px; font-weight: 600; color: #1a1a2e; margin-bottom: 8px; }}
    p {{ font-size: 13px; color: #6b7280; }}
    .back-link {{ margin-top: 24px; }}
    .back-link a {{ font-size: 13px; color: #2563eb; text-decoration: none; }}
    .back-link a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h3>{message}</h3>
  <p>Please wait while we fetch your data securely.</p>
  <div class="back-link"><a href="/dashboard">← Back to Dashboard</a></div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  HTML — Banned Page
# ─────────────────────────────────────────────────────────────────────────────

def _render_banned_page(score: int) -> str:
    ref = abs(hash(str(score))) % 999999
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Access Suspended</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: #1a1a1a;
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }}
    .card {{
      background: #1f1f1f;
      border: 1px solid #333;
      border-top: 3px solid #dc2626;
      border-radius: 16px;
      padding: 48px 40px;
      text-align: center;
      max-width: 420px; width: 90%;
    }}
    .icon {{
      width: 56px; height: 56px;
      background: rgba(220,38,38,0.1);
      border: 2px solid rgba(220,38,38,0.3);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 24px;
      font-size: 24px;
    }}
    h2 {{ font-size: 20px; font-weight: 700; color: #fff; margin-bottom: 10px; }}
    p {{ font-size: 13.5px; color: #9ca3af; line-height: 1.7; margin-bottom: 8px; }}
    .ref {{ font-size: 11.5px; color: #4b5563; margin-top: 24px; font-family: monospace; }}
    .contact {{ font-size: 13px; color: #6b7280; margin-top: 8px; }}
    .contact a {{ color: #3b82f6; text-decoration: none; }}
  </style>
</head>
<body>
<div class="card">
  <div class="icon">⛔</div>
  <h2>Access Temporarily Suspended</h2>
  <p>Unusual activity was detected from your connection. Your access has been restricted for 1 hour.</p>
  <p>Risk score: <strong style="color:#ef4444;">{score}</strong></p>
  <div class="contact">Contact security: <a href="mailto:security@corpnet.local">security@corpnet.local</a></div>
  <div class="ref">Incident ref: #DM{ref:06d}</div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  Admin Panel HTML
# ─────────────────────────────────────────────────────────────────────────────

_ADMIN_BASE_CSS = """
*, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
body {
  font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
  background: #080c12;
  color: #a8b4c8;
  min-height: 100vh;
}
a { text-decoration: none; color: inherit; }
.wrap { max-width: 1400px; margin: 0 auto; padding: 0 24px 40px; }

/* Nav */
.top-nav {
  background: #0d1520;
  border-bottom: 1px solid #1a2535;
  padding: 0 24px;
  display: flex; align-items: center; gap: 0;
  position: sticky; top: 0; z-index: 100;
}
.nav-brand {
  font-size: 14px; font-weight: 700; color: #e2e8f0;
  padding: 16px 20px 16px 0;
  border-right: 1px solid #1a2535;
  margin-right: 8px;
  letter-spacing: 0.05em;
  display: flex; align-items: center; gap: 8px;
}
.nav-brand .dot { color: #3b82f6; }
.nav-link {
  padding: 18px 16px;
  font-size: 12px; font-weight: 500;
  color: #64748b;
  border-bottom: 2px solid transparent;
  transition: color 0.15s, border-color 0.15s;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.nav-link:hover { color: #94a3b8; }
.nav-link.active { color: #e2e8f0; border-bottom-color: #3b82f6; }
.nav-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.reset-btn {
  padding: 6px 12px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  color: #ff6b35;
  background: rgba(255, 107, 53, 0.1);
  border: 1px solid #ff6b35;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease;
  font-family: 'JetBrains Mono', monospace;
}
.reset-btn:hover:not(:disabled) {
  color: #fff;
  background: #ff6b35;
  box-shadow: 0 0 12px rgba(255, 107, 53, 0.5);
}
.reset-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.live-badge {
  display: flex; align-items: center; gap: 6px;
  font-size: 11px; color: #22c55e;
  letter-spacing: 0.06em;
}
.live-badge::before {
  content: '';
  width: 6px; height: 6px; border-radius: 50%;
  background: #22c55e;
  animation: blink 1.5s ease-in-out infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

/* Stats grid */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 1px;
  background: #1a2535;
  border: 1px solid #1a2535;
  border-radius: 12px;
  overflow: hidden;
  margin: 24px 0;
}
.stat-cell {
  background: #0d1520;
  padding: 20px;
  transition: background 0.15s;
}
.stat-cell:hover { background: #101c2e; }
.stat-num {
  font-size: 28px; font-weight: 800;
  color: #e2e8f0;
  letter-spacing: -0.04em;
  line-height: 1;
  margin-bottom: 6px;
}
.stat-lbl {
  font-size: 10px; color: #475569;
  text-transform: uppercase; letter-spacing: 0.08em;
}

/* OTP Countdown panel */
.otp-panel {
  background: #0d1520;
  border: 1px solid #1a2535;
  border-radius: 12px;
  margin-bottom: 20px;
  overflow: hidden;
}
.otp-panel-header {
  padding: 14px 20px;
  border-bottom: 1px solid #1a2535;
  display: flex; align-items: center; gap: 10px;
  font-size: 12px; font-weight: 600;
  color: #94a3b8;
  text-transform: uppercase; letter-spacing: 0.08em;
}
.alert-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #f59e0b;
  animation: blink 1s ease-in-out infinite;
}
.otp-row {
  display: grid;
  grid-template-columns: 140px 100px 120px 1fr 80px;
  gap: 0;
  padding: 14px 20px;
  border-bottom: 1px solid #0f1926;
  align-items: center;
  font-size: 12px;
}
.otp-row:last-child { border-bottom: none; }
.otp-ip { font-family: monospace; color: #7dd3fc; }
.otp-code {
  font-family: monospace;
  font-size: 18px;
  font-weight: 800;
  color: #fbbf24;
  letter-spacing: 0.15em;
}
.otp-code.expired { color: #ef4444; text-decoration: line-through; }
.otp-timer { font-size: 20px; font-weight: 700; }
.otp-timer.danger { color: #ef4444; }
.otp-timer.warning { color: #f59e0b; }
.otp-timer.safe { color: #22c55e; }
.otp-bar-wrap {
  height: 4px;
  background: #1a2535;
  border-radius: 2px;
  overflow: hidden;
  margin: 0 16px;
}
.otp-bar {
  height: 100%;
  border-radius: 2px;
  transition: width 1s linear, background 1s;
}
.otp-status { text-align: right; }

/* Sessions table */
.panel {
  background: #0d1520;
  border: 1px solid #1a2535;
  border-radius: 12px;
  margin-bottom: 20px;
  overflow: hidden;
}
.panel-hdr {
  padding: 14px 20px;
  border-bottom: 1px solid #1a2535;
  display: flex; align-items: center; justify-content: space-between;
  font-size: 12px; font-weight: 600; color: #94a3b8;
  text-transform: uppercase; letter-spacing: 0.08em;
}
.panel-hdr span { color: #475569; font-weight: 400; font-size: 11px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th {
  padding: 10px 16px;
  text-align: left;
  color: #475569;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 1px solid #1a2535;
  background: #080c12;
  font-weight: 600;
}
td {
  padding: 10px 16px;
  color: #94a3b8;
  border-bottom: 1px solid #0f1926;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #0f1926; }
.ip { font-family: monospace; color: #7dd3fc; }
.badge-emp { background: #052e16; color: #4ade80; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; }
.badge-thr { background: #450a0a; color: #fca5a5; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; }
.badge-unk { background: #1e293b; color: #64748b; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; }
.badge-ban { background: #3b0764; color: #d8b4fe; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; }
.tl-NONE     { color: #22c55e; }
.tl-LOW      { color: #eab308; }
.tl-MEDIUM   { color: #f97316; }
.tl-HIGH     { color: #ef4444; }
.tl-CRITICAL { color: #a855f7; font-weight: 700; }

/* Score bar */
.score-wrap { display: flex; align-items: center; gap: 8px; }
.score-bar { width: 64px; height: 5px; background: #1a2535; border-radius: 3px; overflow: hidden; }
.score-fill { height: 100%; border-radius: 3px; }

/* Log lines */
.log-box { padding: 0; }
.log-line { font-family: monospace; font-size: 11.5px; padding: 6px 20px; border-bottom: 1px solid #0f1926; color: #64748b; }
.log-ts { color: #334155; margin-right: 8px; }
.log-ev { font-weight: 700; margin-right: 8px; }
.log-line.LOGIN_TO_HONEYPOT .log-ev, .log-line.FAILED_LOGIN .log-ev { color: #f87171; }
.log-line.CHATBOT_OTP_SUCCESS .log-ev { color: #4ade80; }
.log-line.AUTO_BAN .log-ev { color: #c084fc; font-size: 12px; }
.log-line.DECOY_PAGE_ACCESS .log-ev, .log-line.DECOY_ADMIN_ACCESS .log-ev { color: #fb923c; }
.log-line.CHATBOT_OTP_FAILURE .log-ev { color: #fbbf24; }

/* Ban alert banner */
.ban-alert {
  background: #1a0a2e;
  border: 1px solid #7c3aed;
  border-radius: 10px;
  padding: 14px 18px;
  margin-bottom: 10px;
  display: flex; align-items: center; gap: 12px;
  font-size: 12px;
}
.ban-alert .ban-icon { font-size: 18px; }
.ban-alert .ban-ip { font-family: monospace; color: #c4b5fd; font-weight: 700; }
.ban-alert .ban-reason { color: #a78bfa; }
.ban-alert .ban-ts { color: #6d28d9; margin-left: auto; font-family: monospace; font-size: 11px; }
"""


def _score_bar(score: int) -> str:
    pct = min(100, score)
    if score >= 100: c = "#a855f7"
    elif score >= 80: c = "#ef4444"
    elif score >= 50: c = "#f97316"
    elif score >= 20: c = "#eab308"
    else: c = "#22c55e"
    return (f'<div class="score-wrap">'
            f'<span style="color:{c};min-width:28px;font-weight:700;">{score}</span>'
            f'<div class="score-bar"><div class="score-fill" style="width:{pct}%;background:{c};"></div></div>'
            f'</div>')


def _render_admin_dashboard(records, employees, threats, banned, by_level, active_otps, ban_logs) -> str:
    # Stats
    stats_html = f"""
    <div class="stat-grid">
      <div class="stat-cell"><div class="stat-num">{len(records)}</div><div class="stat-lbl">Total Sessions</div></div>
      <div class="stat-cell"><div class="stat-num" style="color:#4ade80;">{len(employees)}</div><div class="stat-lbl">Employees Verified</div></div>
      <div class="stat-cell"><div class="stat-num" style="color:#f87171;">{len(threats)}</div><div class="stat-lbl">Threats</div></div>
      <div class="stat-cell"><div class="stat-num" style="color:#c084fc;">{len(banned)}</div><div class="stat-lbl">Banned IPs</div></div>
      <div class="stat-cell"><div class="stat-num" style="color:#f87171;">{len(by_level.get('CRITICAL',[]))}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat-cell"><div class="stat-num" style="color:#fbbf24;">{len(active_otps)}</div><div class="stat-lbl">Active OTPs</div></div>
    </div>"""

    # OTP Countdown Panel
    otp_rows = ""
    for o in sorted(active_otps, key=lambda x: x["seconds_remaining"]):
        secs = max(0, int(o["seconds_remaining"]))
        pct  = (secs / otp.OTP_TTL_SECONDS) * 100
        if secs <= 60:  timer_cls = "danger"; bar_color = "#ef4444"
        elif secs <= 120: timer_cls = "warning"; bar_color = "#f59e0b"
        else:            timer_cls = "safe";   bar_color = "#22c55e"

        if o["expired"]:
            code_cls   = "otp-code expired"
            timer_text = "EXPIRED"
            timer_cls  = "danger"
        else:
            code_cls   = "otp-code"
            m, s = divmod(secs, 60)
            timer_text = f"{m}:{s:02d}"

        otp_rows += f"""
        <div class="otp-row">
          <span class="otp-ip">{o['ip']}</span>
          <span class="{code_cls}">{o['code']}</span>
          <span class="otp-timer {timer_cls}">{timer_text}</span>
          <div class="otp-bar-wrap">
            <div class="otp-bar" id="bar-{o['ip'].replace('.','_')}"
                 style="width:{pct:.1f}%;background:{bar_color};"></div>
          </div>
          <span class="otp-status">{'⏰ TIMEOUT' if o['expired'] else '⌛ Waiting'}</span>
        </div>"""

    otp_panel = f"""
    <div class="otp-panel">
      <div class="otp-panel-header">
        <div class="alert-dot"></div>
        Active OTP Sessions — Employee must enter code in chatbot within 5 min or auto-banned
        <span style="margin-left:auto;color:#334155;font-size:10px;">(auto-refreshes)</span>
      </div>
      {'<div class="otp-row" style="color:#334155;padding:20px;">No active OTP sessions</div>' if not otp_rows else otp_rows}
    </div>"""

    # Recent bans
    ban_html = ""
    if ban_logs:
        ban_html = '<div class="panel"><div class="panel-hdr">Recent Auto-Bans <span>from OTP timeout + risk scoring</span></div><div style="padding:8px;">'
        for b in ban_logs[:10]:
            ban_html += f"""
            <div class="ban-alert">
              <span class="ban-icon">🚫</span>
              <span class="ban-ip">{b.get('ip','?')}</span>
              <span class="ban-reason">{b.get('reason','AUTO_BAN')} · score {b.get('risk_score','?')}</span>
              <span class="ban-ts">{b.get('ts','')[:19]}</span>
            </div>"""
        ban_html += "</div></div>"

    # Sessions table
    def sess_row(r):
        id_badge = {
            "EMPLOYEE": '<span class="badge-emp">EMPLOYEE</span>',
            "THREAT":   '<span class="badge-thr">THREAT</span>',
        }.get(r.identity, '<span class="badge-unk">UNKNOWN</span>')
        ban_badge = '<span class="badge-ban">BANNED</span>' if r.is_banned else ""
        tl_cls    = f"tl-{r.threat_level}"
        return (f'<tr><td class="ip">{r.ip}</td>'
                f'<td>{id_badge} {ban_badge}</td>'
                f'<td class="{tl_cls}">{r.threat_level}</td>'
                f'<td>{_score_bar(r.risk_score)}</td>'
                f'<td>{r.last_action}</td>'
                f'<td style="font-family:monospace;">{r.last_seen.strftime("%H:%M:%S")}</td></tr>')

    rows_html = "".join(sess_row(r) for r in sorted(records, key=lambda x: x.risk_score, reverse=True))
    sessions_panel = f"""
    <div class="panel">
      <div class="panel-hdr">All Sessions <span>sorted by risk score · auto-refreshes 30s</span></div>
      <table>
        <thead><tr><th>IP</th><th>Identity</th><th>Threat</th><th>Risk Score</th><th>Last Action</th><th>Last Seen</th></tr></thead>
        <tbody>
          {rows_html or '<tr><td colspan="6" style="text-align:center;color:#334155;padding:2rem;">No sessions yet</td></tr>'}
        </tbody>
      </table>
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Digital Mirror v3 — Admin</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>{_ADMIN_BASE_CSS}</style>
  <meta http-equiv="refresh" content="15">
</head>
<body>
<nav class="top-nav">
  <div class="nav-brand"><span class="dot">◈</span> DIGITAL MIRROR v3</div>
  <a href="/sysadmin/dashboard" class="nav-link active">DASHBOARD</a>
  <a href="/sysadmin/logs" class="nav-link">LOGS</a>
  <a href="/sysadmin/sessions" class="nav-link">SESSION API</a>
  <div class="nav-right">
    <button id="reset-btn" class="reset-btn" title="Clear all tracked sessions and threat data" onclick="resetSessions()">🔄 RESET</button>
    <div class="live-badge">LIVE SURVEILLANCE</div>
  </div>
</nav>
<div class="wrap">
  {stats_html}
  {otp_panel}
  {ban_html}
  {sessions_panel}
</div>
<script>
// Client-side OTP countdown update (runs between server refreshes)
(function() {{
  const rows = document.querySelectorAll('.otp-row');
  // Server re-renders every 15s via meta refresh
  // Client countdown for smooth timer display
  setInterval(() => {{
    rows.forEach(row => {{
      const timerEl = row.querySelector('.otp-timer');
      if (!timerEl || timerEl.textContent === 'EXPIRED') return;
      const parts = timerEl.textContent.split(':');
      if (parts.length !== 2) return;
      let secs = parseInt(parts[0]) * 60 + parseInt(parts[1]);
      if (secs > 0) secs--;
      const m = Math.floor(secs / 60), s = secs % 60;
      timerEl.textContent = m + ':' + String(s).padStart(2,'0');
      if (secs <= 0) {{
        timerEl.textContent = 'EXPIRED';
        timerEl.className = 'otp-timer danger';
      }} else if (secs <= 60) {{
        timerEl.className = 'otp-timer danger';
      }} else if (secs <= 120) {{
        timerEl.className = 'otp-timer warning';
      }}
    }});
  }}, 1000);
}})();

// Reset sessions function
async function resetSessions() {{
  if (!confirm('⚠️ Reset ALL tracked sessions and threat data? This cannot be undone.')) {{
    return;
  }}
  
  const btn = document.getElementById('reset-btn');
  btn.disabled = true;
  btn.style.opacity = '0.5';
  btn.textContent = '⏳ Resetting...';
  
  try {{
    const response = await fetch('/sysadmin/api/reset-sessions', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}}
    }});
    
    const data = await response.json();
    
    if (data.ok) {{
      alert(`✅ Success! Reset ${{data.sessions_cleared}} tracked sessions.`);
      location.reload();
    }} else {{
      alert('❌ Reset failed: ' + data.message);
    }}
  }} catch (err) {{
    alert('❌ Error: ' + err.message);
  }} finally {{
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.textContent = '🔄 RESET';
  }}
}}
</script>
</body>
</html>"""


def _render_admin_logs(events: list, otp_events: list, ban_events: list) -> str:
    def ev_line(e):
        ev  = e.get("event", "")
        ts  = e.get("ts","")[:19]
        ip  = e.get("ip","-")
        idn = e.get("identity","")
        lvl = e.get("threat_level","")
        det = str(e.get("details", {}))[:120]
        return (f'<div class="log-line {ev}">'
                f'<span class="log-ts">{ts}</span>'
                f'<span class="log-ev">{ev}</span>'
                f'<span style="color:#7dd3fc;">{ip}</span> '
                f'<span style="color:#334155;">[{idn}|{lvl}]</span> '
                f'<span style="color:#2d3a4d;">{det}</span></div>')

    def otp_line(e):
        ev  = e.get("event","")
        ts  = e.get("ts","")[:19]
        emp = e.get("emp_id","-")
        ok  = e.get("success", False)
        col = "#4ade80" if ok else "#f87171"
        det = str(e.get("details",{}))[:100]
        return (f'<div class="log-line">'
                f'<span class="log-ts">{ts}</span>'
                f'<span style="color:{col};font-weight:700;">{ev}</span> '
                f'emp={emp} {det}</div>')

    def ban_line(e):
        ts  = e.get("ts","")[:19]
        ip  = e.get("ip","?")
        rsn = e.get("reason","")
        sc  = e.get("risk_score","?")
        return (f'<div class="log-line">'
                f'<span class="log-ts">{ts}</span>'
                f'<span style="color:#c084fc;font-weight:700;">🚫 AUTO_BAN</span> '
                f'<span style="color:#7dd3fc;font-family:monospace;">{ip}</span> '
                f'<span style="color:#7c3aed;">reason={rsn} score={sc}</span></div>')

    events_html  = "".join(ev_line(e) for e in events) or '<div class="log-line" style="color:#334155;">No events yet</div>'
    otp_html     = "".join(otp_line(e) for e in otp_events) or '<div class="log-line" style="color:#334155;">No OTP events yet</div>'
    ban_html     = "".join(ban_line(e) for e in ban_events) or '<div class="log-line" style="color:#334155;">No bans yet</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>Admin — Logs</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>{_ADMIN_BASE_CSS}</style>
</head>
<body>
<nav class="top-nav">
  <div class="nav-brand"><span class="dot">◈</span> DIGITAL MIRROR v3</div>
  <a href="/sysadmin/dashboard" class="nav-link">DASHBOARD</a>
  <a href="/sysadmin/logs" class="nav-link active">LOGS</a>
  <a href="/sysadmin/sessions" class="nav-link">SESSION API</a>
  <div class="nav-right"><div class="live-badge">LIVE SURVEILLANCE</div></div>
</nav>
<div class="wrap">
  <div class="panel" style="margin-top:24px;">
    <div class="panel-hdr">🚫 Auto-Ban Events</div>
    <div class="log-box">{ban_html}</div>
  </div>
  <div class="panel">
    <div class="panel-hdr">Honeypot Event Log <span>last 300 events, newest first</span></div>
    <div class="log-box">{events_html}</div>
  </div>
  <div class="panel">
    <div class="panel-hdr">OTP Event Log <span>last 100 events</span></div>
    <div class="log-box">{otp_html}</div>
  </div>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    os.makedirs("static", exist_ok=True)

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║        DIGITAL MIRROR v3 — Honeypot System          ║")
    print("╚══════════════════════════════════════════════════════╝\n")
    print(f"[+] Real backend target  : {REAL_BACKEND_URL}")
    print(f"[+] Valid logins         : {list(VALID_CREDENTIALS.keys())}")
    print(f"[+] OTP TTL              : {otp.OTP_TTL_SECONDS}s (5 minutes)")
    print()
    print(f"[+] HONEYPOT FRONTEND    : http://127.0.0.1:8000/honeypot")
    print(f"    (copy honeypot.html → static/honeypot.html to activate)")
    print()
    print(f"[+] BACKEND LOGIN        : http://127.0.0.1:8000/login")
    print(f"[+] ADMIN PANEL          : http://127.0.0.1:8000/sysadmin/dashboard")
    print(f"[+] Admin credentials    : {ADMIN_USER} / {ADMIN_PASS}")
    print(f"[+] OTP watcher thread   : started")
    print()

    frontend_path = os.path.join(_THIS_DIR, "static", "honeypot.html")
    if os.path.exists(frontend_path):
        print(f"[✓] Frontend HTML found at static/honeypot.html")
    else:
        print(f"[!] Frontend not found — copy honeypot.html to ./static/honeypot.html")

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="warning",
    )

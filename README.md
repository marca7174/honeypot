# Digital Mirror v3 — Reverse Proxy Honeypot

A honeypot where **the real secret is hidden in an AI chatbot** — not in the URL or the login page.

---

## How It Works

```
Attacker                          Employee
   │                                 │
   ▼                                 ▼
/login ─────────────────────────── /login
   │  (any valid-looking credential works)
   ▼
/dashboard  ◄──── HONEYPOT LAYER ────►  /dashboard
  [Looks like real corporate portal]      [Same page]
       │                                      │
       │                            Sees AI chatbot in bottom-right
       │                            Knows to type OTP code received
       │                            via admin panel out-of-band
       │                                      │
  [Browses around,                    Types 6-digit OTP
   triggers risk score]               in chatbot within 5 min
       │                                      │
  [5-min OTP expires]              [Chatbot verifies OTP]
       │                                      │
  AUTO-BANNED ✗                   REDIRECTED to real system ✓
```

---

## v3 vs v2 Changes

| Feature | v2 | v3 |
|---------|----|----|
| Honeypot layer | Spinner decoy | Full realistic corporate dashboard |
| OTP mechanism | Hidden URL `/portal?t=TOKEN` | AI chatbot widget (bottom-right) |
| OTP trigger | Admin manually generates | Auto-generated on every login |
| OTP TTL | 8 minutes | **1 minutes** |
| Auto-ban | Only by risk score | **Auto-ban on OTP timeout** |
| Admin OTP view | Generate page | **Live countdown in dashboard** |
| Ban logging | Main log | Dedicated `ban_events.log` |

---

## Setup

### 1. Prerequisites
- Python 3.10+
- g++ with C++17 support

### 2. Install
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Compile C++ engine
```bash
# Linux/macOS
g++ -O2 -shared -fPIC -std=c++17 -o risk_engine.so risk_engine.cpp
```

### 4. Configure `main.py`
```python
VALID_CREDENTIALS = {
    "abdullah": "chuttar2026",        # Any credential works — all go to honeypot
    "j.smith": "Welcome@123",
}

REAL_BACKEND_URL = "https://your-real-internal-portal.com"

ADMIN_USER = "sirbilal"
ADMIN_PASS = "theOG"
```

### 5. Run
```bash
python main.py
```

---

## URLs

| URL | Who | What |
|-----|-----|------|
| `/login` | Everyone | Login form |
| `/dashboard` | Everyone after login | Honeypot dashboard with hidden chatbot OTP |
| `/api/chat` | Chatbot widget | OTP verification disguised as AI chat |
| `/sysadmin/dashboard` | Admin only | Surveillance panel with OTP countdowns |
| `/sysadmin/logs` | Admin only | All event logs |

---

## The Key Insight

**Attackers do not know there is a 5-minute timer.**
They think they are in the real system. They browse, probe, or wait.
The moment 5 minutes pass, the background watcher applies a ban automatically.

**Employees know:**
- After logging in, look for the AI chatbot widget in the bottom-right corner
- Type your OTP code (received from admin out-of-band) within 5 minutes
- The chatbot will confirm and redirect you

**Attackers see:**
- A realistic corporate dashboard
- An AI chatbot that gives normal corporate responses to normal questions
- When they type their 6-digit OTP attempt → chatbot says "I didn't quite understand that"
- After 5 minutes → BANNED

---

## Threat Levels

| Level | Score | Colour |
|-------|-------|--------|
| NONE | 0–19 | 🟢 Green |
| LOW | 20–49 | 🟡 Yellow |
| MEDIUM | 50–79 | 🟠 Orange |
| HIGH | 80–99 | 🔴 Red |
| CRITICAL | 100+ | 🟣 Purple — **BANNED** |

---

## Architecture

```
FastAPI (Python)
    │
    ├── ban_check_middleware()
    ├── /api/chat  ← disguised OTP entry
    ├── otp_manager.py ← 5-min TTL session OTPs
    ├── logger.py  ← JSON-line logs (3 files)
    ├── _otp_expiry_watcher()  ← background thread
    │
    └── bridge.py (ctypes)
          │
          risk_engine.so (C++)
          └── RiskEngine Singleton
```

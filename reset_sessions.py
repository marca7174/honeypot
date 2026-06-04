"""
reset_sessions.py - Reset all tracked sessions and threat status
"""

import sys
sys.path.insert(0, '.')

from bridge_python_fallback import RiskEngine

# Get the singleton instance
engine = RiskEngine.get_instance()

# Clear all sessions
print("\n🔄 Resetting Session Data...\n")
print(f"   Current tracked IPs: {len(engine.active_sessions)}")

if engine.active_sessions:
    print(f"   Clearing: {', '.join(engine.active_sessions.keys())}")
    engine.active_sessions.clear()

print(f"   Active sessions after reset: {len(engine.active_sessions)}")
print("\n✅ All sessions have been cleared!")
print("🎯 You can now log in again with valid credentials.\n")

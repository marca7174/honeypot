# 🔄 RESET BUTTON — Visual Guide

## Step-by-Step Screenshots Description

### Step 1: Admin Dashboard
```
┌─────────────────────────────────────────────────────────────────┐
│ ◈ DIGITAL MIRROR v3    [DASHBOARD] [LOGS] [SESSION API]         │
│                                              [🔄 RESET] [◆ LIVE] │
└─────────────────────────────────────────────────────────────────┘
           ↑↑↑ RESET BUTTON IS HERE IN TOP-RIGHT ↑↑↑
```

The button appears in the top navigation bar on the right side, with an orange color to indicate administrative action.

---

### Step 2: Click the Reset Button
```
When you click the 🔄 RESET button:

┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  ⚠️ Reset ALL tracked sessions and threat data?                 │
│     This cannot be undone.                                       │
│                                                                   │
│                        [OK]  [Cancel]                            │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

A confirmation dialog appears asking for confirmation.

---

### Step 3: Processing
```
While resetting:

┌─────────────────────────────────────────────────────────────────┐
│ ◈ DIGITAL MIRROR v3    [DASHBOARD] [LOGS] [SESSION API]         │
│                                         [⏳ Resetting...] [◆ LIVE]│
└─────────────────────────────────────────────────────────────────┘

The button shows a loading state with text "⏳ Resetting..."
```

---

### Step 4: Success
```
After reset completes:

┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  ✅ Success! Reset 5 tracked sessions.                           │
│                                                                   │
│                          [OK]                                    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

Then the page auto-refreshes showing:
```

---

### Step 5: Fresh Data
```
After refresh, the dashboard shows cleared sessions:

┌─────────────────────────────────────────────────────────────────┐
│  Total Sessions: 0        Employees: 0        Threats: 0         │
│  Banned: 0                Active OTPs: 0       Critical: 0        │
│                                                                   │
│  ┌─ All Sessions (auto-refreshes) ──────────────────────────┐   │
│  │  IP | Identity | Threat | Risk Score | Last Action | Time   │
│  │  [No sessions yet]                                         │   │
│  └────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

All data is cleared and ready for fresh testing!

---

## Button Appearance

### Normal State (Not Hovering)
```
┌──────────────┐
│ 🔄 RESET     │
└──────────────┘
Orange border, orange text, transparent background
Cursor: pointer
```

### Hover State (Mouse Over)
```
╔══════════════╗
║ 🔄 RESET     ║ ← Glows with orange shadow
╚══════════════╝
Orange border, white text, orange background
Cursor: pointer
Box-shadow with orange glow
```

### Loading State (During Reset)
```
┌──────────────────┐
│ ⏳ Resetting... │
└──────────────────┘
Grayed out, not clickable
Cursor: not-allowed
```

### Completed
```
┌──────────────┐
│ 🔄 RESET     │ ← Returns to normal state
└──────────────┘
Ready to use again
```

---

## Keyboard Shortcut (Future Enhancement)

While the current version requires clicking, future updates could add:
- Alt+R to open reset confirmation
- Tab navigation support
- Escape key to cancel

---

## Mobile / Responsive

On smaller screens:
- Button stays visible in the nav bar
- Text may be abbreviated to just "🔄"
- Touch-friendly size maintained
- Modal is centered on screen

---

## Accessibility Features

✓ Clear confirmation dialog (prevents accidental resets)  
✓ Visual feedback during processing  
✓ Success/error messages  
✓ High contrast orange color  
✓ Keyboard focus support  
✓ Descriptive title attribute  

---

## Error Scenarios

### Network Error
```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  ❌ Error: Network request failed                                │
│                                                                   │
│                          [OK]                                    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Not Authenticated
```
The endpoint requires sysadmin login. If not logged in:
- Reset request returns 401 Unauthorized
- Error message displayed
- Button re-enabled for retry
```

### Server Error
```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  ❌ Reset failed: Internal server error                          │
│                                                                   │
│                          [OK]                                    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Real Usage Timeline

```
T+0s   → Click 🔄 RESET button
T+0.1s → Confirmation dialog appears
T+0.5s → Click OK, button shows "⏳ Resetting..."
T+1s   → Server processes reset API call
T+1.2s → Success alert: "✅ Success! Reset X tracked sessions"
T+1.5s → Page auto-refreshes
T+2s   → Dashboard shows fresh empty data
T+3s   → Ready for new testing
```

---

## Pro Tips

1. **Before testing attacks**: Click RESET to start fresh
2. **Between test cycles**: Quick reset instead of server restart
3. **In logs**: Each reset is logged as SESSIONS_RESET event
4. **No data loss**: Logs are preserved, only sessions cleared
5. **Audit trail**: Admin can see who reset what and when

---

## Integration with Workflow

```
┌─────────────────────────────┐
│  Test invalid login         │
│  (marks as threat)          │
└──────────────┬──────────────┘
               │
┌──────────────v──────────────┐
│  Try valid login            │
│  (still blocked by threat)  │
└──────────────┬──────────────┘
               │
┌──────────────v──────────────┐
│  Click 🔄 RESET button      │
│  (clears threat status)     │
└──────────────┬──────────────┘
               │
┌──────────────v──────────────┐
│  Try valid login again      │
│  (SUCCESS! ✅)              │
└─────────────────────────────┘
```

---

**Happy testing with your new Reset button!** 🎉

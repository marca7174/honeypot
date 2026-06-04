# 🔄 Reset Button — Admin Panel Feature

## What's New

Your admin dashboard now has a **RESET button** in the top-right corner that lets you instantly clear all tracked sessions and threat data **without restarting the server**.

---

## How to Use

### 1. **Access the Admin Panel**
   - Go to: `http://127.0.0.1:8000/sysadmin/dashboard`
   - Login with:
     - Username: `sysadmin`
     - Password: `Str0ngAdm1nP@ss!`

### 2. **Click the Reset Button**
   - Look in the top-right corner of the dashboard
   - You'll see a red button: **🔄 RESET**
   - Click it

### 3. **Confirm the Action**
   - A confirmation dialog will appear:
     ```
     ⚠️ Reset ALL tracked sessions and threat data? This cannot be undone.
     ```
   - Click **OK** to confirm
   - Click **Cancel** to abort

### 4. **Watch the Reset Happen**
   - The button will show: **⏳ Resetting...**
   - An alert will confirm: **✅ Success! Reset X tracked sessions.**
   - The page will auto-refresh with the cleared data

---

## What Gets Reset

When you click RESET, the following are cleared:

✓ All tracked IP sessions  
✓ All risk scores  
✓ All threat levels  
✓ All ban statuses  
✓ All OTP failures  
✓ All 2FA failures  
✓ All session history  

---

## What You Can Now Do

After resetting:
1. **Test threats again** - You can retry invalid logins without being blocked
2. **Fresh start** - All IPs are marked as "UNKNOWN" again
3. **Resume testing** - Valid users can log in without restrictions

---

## Example Workflow

```
1. Try invalid login → Gets marked as threat
2. Try valid login → Still blocked (threat status remembered)
3. Click 🔄 RESET button → All sessions cleared
4. Try valid login again → ✅ Works! (threat status gone)
```

---

## Technical Details

- **Endpoint**: `POST /sysadmin/api/reset-sessions`
- **Authentication**: Requires sysadmin login
- **Response**: 
  ```json
  {
    "ok": true,
    "message": "Reset X tracked sessions",
    "sessions_cleared": X
  }
  ```
- **Side Effects**: 
  - Only clears risk engine sessions
  - Does NOT delete logs (preserved in logger)
  - Does NOT affect OTP history
  - Changes are logged as `SESSIONS_RESET` event

---

## Advantages Over Manual Reset

| Method | Steps | Speed | Need Restart |
|--------|-------|-------|--------------|
| Manual (`reset_sessions.py`) | 3-4 | 5+ seconds | ✅ Yes |
| Admin Panel Button | 2-3 | < 1 second | ❌ No |

---

## Button Styling

The reset button features:
- **Color**: Orange (#ff6b35) - indicates administrative action
- **Location**: Top-right of admin panel, next to "LIVE SURVEILLANCE"
- **Hover Effect**: Glows with orange shadow when you hover
- **Disabled State**: Grayed out while resetting
- **Responsive**: Works on all screen sizes

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Button doesn't respond | Make sure you're logged in as sysadmin |
| Reset failed error | Check browser console (F12) for details |
| Page doesn't refresh | Try manually refreshing with F5 |
| Button missing | Clear browser cache and reload |

---

**Enjoy your streamlined admin experience!** 🎉

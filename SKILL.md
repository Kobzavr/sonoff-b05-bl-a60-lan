---
name: sonoff-lamp
description: "Local LAN control for Sonoff B05-BL-A60 (UIID 136 / BL602) smart Wi-Fi LED bulb (on/off, toggle, white brightness & color temp, RGB color, scenes, status, custom detached morning sunrise alarm)."
version: 1.4.0
author: Kobzavr
license: MIT
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [smart-home, sonoff, lamp, light, bulb, ewelink, lan, b05-bl-a60, bl602, sunrise, morning]
    category: productivity
    requires_toolsets: [terminal]
---

# Sonoff B05-BL-A60 Smart Lamp Skill

Direct local LAN control for the **Sonoff B05-BL-A60** (`UIID 136`, controller `Bouffalo Lab BL602`) RGBCW smart bulb over Wi-Fi (eWeLink LAN Mode protocol on TCP port `8081` with AES-128-CBC encryption via `cryptography` and mDNS discovery on UDP port `5353`) with zero cloud dependency during operation.

## Path & Shell Compatibility (Bash / Git Bash / PowerShell / CMD)

When invoking `sonoff_bulb.py` on Windows (whether inside Git Bash/MSYS, PowerShell, or CMD) or Linux/macOS, always use **forward slashes** in the quoted path (e.g. `"C:/path/to/scripts/sonoff_bulb.py"` or `"/path/to/scripts/sonoff_bulb.py"`). Forward slashes work universally across both POSIX shells (Git Bash) and native Windows `python.exe`:

```bash
BULB="C:/Users/<username>/AppData/Local/hermes/skills/productivity/sonoff-lamp/scripts/sonoff_bulb.py"
```

* **Important Note on Confirmation:** When any control command (`on`, `off`, `toggle`, `white`, `rgb`, `effect`, `morning`) returns a JSON object with `"error": 0` or `"ok": true`, that is the **direct HTTP response from the bulb (`:8081`)** confirming the command was accepted and executed. **Do not** run a separate `status` command right after a control command (during the 500ms hardware dimming transition `slowlyDimmed: 500`, the single-core BL602 chip is busy updating PWM). Call `status` only when the user explicitly asks for the current bulb state.

## CLI Command Reference

### 1. Custom Sunrise Wake-Up Mode (`morning`) — for Alarms & Cronjobs

Spawns a **detached background worker process** and **exits immediately** (returning a JSON object with `pid` and `run_id`), so the AI agent or cronjob is never blocked.
* **Default behavior (`--ramp 30`, leaves bulb ON when complete):**
  1. **Phase 1 (First 20% of duration, e.g. 0–6 min — "Dawn"):** Turns the bulb on at `1%` brightness in deep red/amber (`RGB 255, 20, 0`) and smoothly transitions to golden-orange (`12%`).
  2. **Phase 2 (Remaining 80% of duration, e.g. 6–30 min — "Sunrise"):** Switches to the white LEDs and follows a non-linear perceptual gamma curve ($\gamma \approx 1.5$), stepping every `--step 30` seconds from `10%` warm candle light (`2000K`, `ct=0`) up to `--target-br 100` (`100%`) energizing morning daylight (`~5400K`, `--target-ct 75`).
  3. **Completion:** Upon reaching `100%` at 30 minutes, **the bulb stays ON** and the background worker exits cleanly. (Optionally pass `--auto-off <minutes>` if auto-shutoff after sunrise is desired).
* **Smart Cancellation:** Any manual command (`off`, `on`, `white`, `rgb`, `effect`, `toggle`) automatically stops any running background `morning` worker so it never overrides a manual user action.

```bash
# Start default 30-minute sunrise in the background (leaves bulb ON at 100%)
python "$BULB" morning

# Start custom sunrise (e.g. 20-minute ramp, 20s step interval, 90% target brightness)
python "$BULB" morning --ramp 20 --step 20 --target-br 90

# Check status of the running background sunrise (phase, step, progress %)
python "$BULB" morning --status

# Stop the background sunrise worker (leaves light at its current level)
python "$BULB" morning --stop
```

### 2. Turn ON / OFF / Toggle (`on`, `off`, `toggle`)

```bash
# Turn light ON
python "$BULB" on

# Turn light OFF (also cancels any running morning sunrise routine)
python "$BULB" off

# Toggle state (reads current state via mDNS and switches ON <-> OFF)
python "$BULB" toggle
```

### 3. White Light: Brightness & Color Temperature (`white`)

Standard white illumination mode (`ltype: "white"`). Automatically turns the bulb on if it was off.
* `--br <1..100>` — Brightness percentage (default `100`).
* `--ct <0..100>` — Color temperature scale from `0` (warmest 2000K) to `100` (coolest 6500K).
* `--kelvin <2000..6500>` — Color temperature in Kelvin (`2000` = candle warm, `3000` = soft warm, `4200` = neutral daylight, `6500` = cool white). Automatically converted to `--ct`.

```bash
# Warm cozy evening light (40% brightness, 2700K)
python "$BULB" white --br 40 --kelvin 2700

# Bright neutral daylight for work (100% brightness, 5000K)
python "$BULB" white --br 100 --kelvin 5000

# Dim warm light (15% brightness, ct 0)
python "$BULB" white --br 15 --ct 0
```

### 4. RGB Color Mode (`rgb`)

Sets RGB color (`R G B` each `0..255`) and brightness (`--br 1..100`).

```bash
# Red at 80% brightness
python "$BULB" rgb 255 0 0 --br 80

# Deep blue / neon cyan at 100%
python "$BULB" rgb 0 120 255 --br 100

# Purple / cyberpunk at 90%
python "$BULB" rgb 180 0 255 --br 90

# Emerald green at 70%
python "$BULB" rgb 0 255 100 --br 70

# Sunset orange at 60%
python "$BULB" rgb 255 80 0 --br 60
```

### 5. Built-In Hardware Scenes & Effects (`effect`)

Available scene names:
* `bright` — Full bright white (`100%`)
* `read` — Reading mode (`60%`)
* `goodNight` — Pre-sleep warm dim (`25%`)
* `nightLight` — Nightlight (`5%`)
* `party` — Dynamic party color cycling
* `leisure` — Relaxing blue ambiance
* `soft` — Soft green glow
* `colorful` — Smooth RGB cycle

```bash
python "$BULB" effect nightLight
python "$BULB" effect party
```

### 6. Query Bulb Status (`status`)

Queries the bulb over local mDNS (`5353/UDP`) and decrypts its state (`switch`, `ltype`, brightness, RGB/CT values, firmware version, and `morning_routine` status if running):

```bash
python "$BULB" status
```

### 7. Local HTTP REST API & Web UI (`serve`) and Setup (`discover`, `login`, `set-key`)

```bash
# Start local HTTP REST API and Web Control Panel on port 8000
python "$BULB" serve --port 8000

# Auto-discover bulb IP and deviceid on LAN via mDNS
python "$BULB" discover

# One-time login to eWeLink Cloud to fetch devicekey into bulb_config.json
python "$BULB" login -u <email_or_phone> -p <password>
```

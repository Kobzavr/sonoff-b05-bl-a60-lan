---
name: sonoff-lamp
description: "Control room/bedroom smart light and lamp: turn light on/off/toggle, adjust brightness, warm/cool white temperature, RGB color, nightlight, scenes, and morning sunrise alarm."
version: 1.5.0
author: Kobzavr
license: MIT
platforms: [windows, linux, macos]
metadata:
  hermes:
    tags: [light, lamp, bulb, lighting, bedroom, brightness, color, rgb, nightlight, sunrise, morning, alarm, sonoff]
    category: productivity
    requires_toolsets: [terminal]
---

# Smart Light Control (`sonoff-lamp`)

Use this skill whenever the user asks to turn the **light** or **lamp** on/off, dim or brighten the room, change white warmth/temperature, set an RGB color, turn on nightlight/scenes, or trigger/schedule the morning sunrise wake-up routine.

## Script Path

Because the agent terminal starts in the session's working directory (not inside the skill folder), always invoke the script using its full path (forward slashes work across Git Bash, PowerShell, CMD, Linux, and macOS):

```bash
BULB="${HERMES_HOME:-$HOME/.hermes}/skills/productivity/sonoff-lamp/scripts/sonoff_bulb.py"
# Or on Windows with explicit path:
# BULB="C:/Users/<username>/AppData/Local/hermes/skills/productivity/sonoff-lamp/scripts/sonoff_bulb.py"
```

> **Rule:** A response containing `{"error": 0}` or `{"ok": true}` confirms the bulb executed the command. Do not run `status` immediately after a control command.

## Commands (User Intent → CLI Call)

### 1. Turn Light ON / OFF / Toggle
```bash
python "$BULB" on
python "$BULB" off
python "$BULB" toggle
```

### 2. White Light & Brightness (`white`)
Automatically turns the bulb on if it was off.
- `--br <1..100>` — Brightness % (default `100`)
- `--kelvin <2000..6500>` — Color temp in Kelvin (`2000` candle, `2700` warm, `4200` neutral, `6500` cool daylight)
- `--ct <0..100>` — Color temp scale (`0` warmest, `100` coolest)

```bash
# Warm evening light at 40%
python "$BULB" white --br 40 --kelvin 2700

# Full bright daylight
python "$BULB" white --br 100 --kelvin 5000

# Dim warm light at 15%
python "$BULB" white --br 15 --ct 0
```

### 3. RGB Color (`rgb R G B --br <1..100>`)
`R G B` values `0..255`:
```bash
python "$BULB" rgb 255 0 0 --br 80     # Red
python "$BULB" rgb 0 120 255 --br 100  # Blue
python "$BULB" rgb 180 0 255 --br 90   # Purple
python "$BULB" rgb 0 255 100 --br 70   # Green
python "$BULB" rgb 255 80 0 --br 60    # Orange
```

### 4. Scenes / Presets (`effect`)
Available effects: `nightLight` (5%), `read` (60%), `goodNight` (25%), `bright` (100%), `party`, `leisure`, `soft`, `colorful`.
```bash
python "$BULB" effect nightLight
python "$BULB" effect party
```

### 5. Morning Sunrise Routine (`morning`)
Spawns a detached background process and exits immediately. Smoothly ramps over 30 minutes from `1%` red/amber dawn to `100%` morning white daylight and **leaves the bulb ON**. Any manual command (`off`, `white`, `rgb`) automatically cancels the running sunrise.
```bash
python "$BULB" morning                 # Default 30-min sunrise
python "$BULB" morning --ramp 20       # Custom 20-min sunrise
python "$BULB" morning --status        # Check sunrise progress
python "$BULB" morning --stop          # Stop sunrise at current level
```

### 6. Check Current State (`status`)
Only call when the user explicitly asks if the light is on or what state it is in:
```bash
python "$BULB" status
```

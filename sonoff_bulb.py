#!/usr/bin/env python3
"""
Local LAN Controller, Key Extractor & REST API Server for Sonoff B05-BL-A60 (UIID 136 / Bouffalo Lab BL602).
Works 100% locally over Wi-Fi (port 8081 + mDNS 5353) once `devicekey` is saved in bulb_config.json.
Includes detached background `morning` sunrise wake-up routine.

Protocol reverse-engineering credits: AlexxIT/SonoffLAN (https://github.com/AlexxIT/SonoffLAN)
License: MIT
"""

import argparse
import base64
import getpass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "bulb_config.json"
MORNING_PID_PATH = SCRIPT_DIR / "morning_state.json"
MORNING_LOG_PATH = SCRIPT_DIR / "morning.log"

DEFAULT_CONFIG = {
    "ip": "",
    "port": 8081,
    "deviceid": "",
    "devicekey": "",
    "name": "Sonoff B05-BL-A60",
    "uiid": 136,
}

# eWeLink Cloud v2 public client ID (can be overridden via EWELINK_APP_ID / EWELINK_APP_SECRET env vars)
APP_ID = os.environ.get("EWELINK_APP_ID", "R8Oq3y0eSZSYdKccHlrQzT1ACCOUT9Gv")
_APP_KEY_OBF = "ayw/bwsxYx0CPA8yERs0ayksNBEtKhs2IgIxFzsoKC8="
CLOUD_APIS = {
    "eu": "https://eu-apia.coolkit.cc",
    "us": "https://us-apia.coolkit.cc",
    "as": "https://as-apia.coolkit.cc",
    "cn": "https://cn-apia.coolkit.cn",
}


def _sign_cloud_payload(data: bytes) -> str:
    secret = os.environ.get("EWELINK_APP_SECRET", "").encode("utf-8") or bytes(
        b ^ 0x5A for b in base64.b64decode(_APP_KEY_OBF)
    )
    return base64.b64encode(hmac.new(secret, data, hashlib.sha256).digest()).decode(
        "utf-8"
    )

B05_EFFECTS = {
    "bright": {"r": 255, "g": 255, "b": 255, "br": 100},
    "goodNight": {"r": 254, "g": 254, "b": 126, "br": 25},
    "read": {"r": 255, "g": 255, "b": 255, "br": 60},
    "nightLight": {"r": 255, "g": 242, "b": 226, "br": 5},
    "party": {"r": 254, "g": 132, "b": 0, "br": 45, "tf": 1, "sp": 1},
    "leisure": {"r": 0, "g": 40, "b": 254, "br": 55, "tf": 1, "sp": 1},
    "soft": {"r": 38, "g": 254, "b": 0, "br": 20, "tf": 1, "sp": 1},
    "colorful": {"r": 255, "g": 0, "b": 0, "br": 100, "tf": 1, "sp": 1},
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            return {**DEFAULT_CONFIG, **cfg}
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# AES-128-CBC Local Encryption / Decryption (via `cryptography`)
# ---------------------------------------------------------------------------


def encrypt_lan_payload(payload: dict, devicekey: str) -> dict:
    plaintext = json.dumps(payload["data"], separators=(",", ":")).encode(
        "utf-8"
    )
    key = hashlib.md5(devicekey.encode("utf-8")).digest()
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    payload["encrypt"] = True
    payload["data"] = base64.b64encode(ciphertext).decode("utf-8")
    payload["iv"] = base64.b64encode(iv).decode("utf-8")
    return payload


def decrypt_lan_data(data_b64: str, iv_b64: str, devicekey: str) -> dict:
    ciphertext = base64.b64decode(data_b64)
    key = hashlib.md5(devicekey.encode("utf-8")).digest()
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(padded) + unpadder.finalize()
    raw = raw.rstrip(b"\x02")
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# mDNS Local Discovery & State Reader
# ---------------------------------------------------------------------------


def _get_local_ip(target_ip: str = "") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip or "8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


def parse_mdns_txt(packet: bytes) -> dict:
    """Extract key=value TXT strings from raw mDNS packet."""
    props = {}
    keys = (
        "txtvers=",
        "id=",
        "type=",
        "apivers=",
        "encrypt=",
        "iv=",
        "seq=",
        "data1=",
        "data2=",
        "data3=",
        "data4=",
    )
    i = 0
    n = len(packet)
    while i < n:
        ln = packet[i]
        if 4 <= ln <= 255 and i + 1 + ln <= n:
            chunk = packet[i + 1 : i + 1 + ln]
            try:
                s = chunk.decode("ascii")
                if s.startswith(keys):
                    k, v = s.split("=", 1)
                    props[k] = v
                    i += 1 + ln
                    continue
            except UnicodeDecodeError:
                pass
        i += 1
    return props


def query_mdns_bulb(bulb_ip: str = "", deviceid: str = "", timeout: float = 5.0) -> dict:
    """Query the bulb over mDNS (port 5353) using both multicast and unicast sockets."""
    local_ip = _get_local_ip(bulb_ip)
    sockets = []

    try:
        s_mcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s_mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_mcast.bind(("", 5353))
        if local_ip != "0.0.0.0":
            mreq = struct.pack(
                "4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(local_ip)
            )
            s_mcast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            s_mcast.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip)
            )
        s_mcast.setblocking(False)
        sockets.append(s_mcast)
    except Exception:
        pass

    try:
        s_ucast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s_ucast.bind((local_ip if local_ip != "0.0.0.0" else "", 0))
        if local_ip != "0.0.0.0":
            s_ucast.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip)
            )
        s_ucast.setblocking(False)
        sockets.append(s_ucast)
    except Exception:
        pass

    q_ptr_qm = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_ewelink\x04_tcp\x05local\x00\x00\xff\x00\x01"
    q_ptr_qu = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_ewelink\x04_tcp\x05local\x00\x00\xff\x80\x01"
    queries = [q_ptr_qm, q_ptr_qu]

    if deviceid:
        inst = f"eWeLink_{deviceid}".encode("ascii")
        q_txt_qu = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + bytes([len(inst)])
            + inst
            + b"\x08_ewelink\x04_tcp\x05local\x00\x00\xff\x80\x01"
        )
        q_txt_qm = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + bytes([len(inst)])
            + inst
            + b"\x08_ewelink\x04_tcp\x05local\x00\x00\xff\x00\x01"
        )
        queries.extend([q_txt_qu, q_txt_qm])

    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            for sock in sockets:
                for q in queries:
                    try:
                        sock.sendto(q, ("224.0.0.251", 5353))
                        if bulb_ip:
                            sock.sendto(q, (bulb_ip, 5353))
                    except Exception:
                        pass

            rlist, _, _ = select.select(sockets, [], [], 0.6)
            for ready_sock in rlist:
                try:
                    while True:
                        data, addr = ready_sock.recvfrom(4096)
                        if (bulb_ip and addr[0] == bulb_ip) or (
                            b"eWeLink_" in data and len(data) > 100
                        ):
                            props = parse_mdns_txt(data)
                            if "id" in props:
                                if not deviceid or props["id"] == deviceid:
                                    props["_ip"] = addr[0]
                                    return props
                except BlockingIOError:
                    pass
    finally:
        for sock in sockets:
            sock.close()
    return {}


def get_bulb_status(cfg: dict) -> dict:
    """Read and decrypt the bulb's current state via mDNS."""
    props = query_mdns_bulb(cfg.get("ip", ""), cfg.get("deviceid", ""))
    if not props:
        return {"online": False, "error": "No mDNS response from bulb"}

    raw_data = "".join(
        props.get(f"data{i}", "") for i in range(1, 5)
    )
    result = {
        "online": True,
        "name": cfg.get("name", "Sonoff B05-BL-A60"),
        "ip": props.get("_ip", cfg.get("ip")),
        "deviceid": props.get("id", cfg.get("deviceid")),
        "type": props.get("type"),
        "seq": props.get("seq"),
        "encrypted": props.get("encrypt") == "true",
    }

    if result["encrypted"] and raw_data and "iv" in props:
        if cfg.get("devicekey"):
            try:
                result["state"] = decrypt_lan_data(
                    raw_data, props["iv"], cfg["devicekey"]
                )
            except Exception as e:
                result["decrypt_error"] = str(e)
        else:
            result["note"] = (
                "State is encrypted. Run `python sonoff_bulb.py login` once to fetch devicekey."
            )
    elif raw_data:
        try:
            result["state"] = json.loads(raw_data)
        except Exception:
            result["raw_data"] = raw_data

    morning_info = get_morning_status()
    if morning_info.get("running"):
        result["morning_routine"] = morning_info

    return result


# ---------------------------------------------------------------------------
# Background Morning Sunrise Process Management
# ---------------------------------------------------------------------------


def _is_pid_running(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000,
            ).decode("utf-8", errors="ignore")
            return str(pid) in out
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def get_morning_status() -> dict:
    if not MORNING_PID_PATH.exists():
        return {"running": False}
    try:
        with open(MORNING_PID_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        pid = data.get("pid")
        if _is_pid_running(pid):
            data["running"] = True
            data["elapsed_minutes"] = round((time.time() - data.get("started_at", time.time())) / 60, 1)
            return data
        else:
            MORNING_PID_PATH.unlink(missing_ok=True)
            return {"running": False}
    except Exception:
        return {"running": False}


def stop_morning_routine() -> dict:
    """Stop any running background morning sunrise process."""
    if not MORNING_PID_PATH.exists():
        return {"stopped": False, "reason": "No morning routine was running"}
    try:
        with open(MORNING_PID_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        pid = data.get("pid")
        MORNING_PID_PATH.unlink(missing_ok=True)
        if pid and _is_pid_running(pid) and pid != os.getpid():
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=0x08000000,
                )
            else:
                os.kill(pid, signal.SIGTERM)
            return {"stopped": True, "killed_pid": pid}
        return {"stopped": False, "reason": "Process already finished"}
    except Exception as e:
        MORNING_PID_PATH.unlink(missing_ok=True)
        return {"stopped": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Local LAN HTTP Command Sender (Port 8081)
# ---------------------------------------------------------------------------


def send_lan_command(
    cfg: dict, command: str, params: dict, retries: int = 8
) -> dict:
    """
    Send encrypted command directly to http://<ip>:8081/zeroconf/<command>.
    For B05-BL-A60 (UIID 136):
      - command='switch'   with params={'switch': 'on'|'off'}
      - command='dimmable' with params={'ltype': 'white'|'color'|..., ...}
    """
    if not cfg.get("devicekey"):
        raise RuntimeError(
            "Missing `devicekey` in bulb_config.json! Run `python sonoff_bulb.py login` first."
        )
    if not cfg.get("ip"):
        raise RuntimeError(
            "Missing `ip` in bulb_config.json! Run `python sonoff_bulb.py discover` or `login` first."
        )

    payload = {
        "sequence": str(int(time.time() * 1000)),
        "deviceid": cfg["deviceid"],
        "selfApikey": "123",
        "data": params,
    }
    encrypted_payload = encrypt_lan_payload(payload, cfg["devicekey"])
    body = json.dumps(encrypted_payload, separators=(",", ":")).encode("utf-8")
    url = f"http://{cfg['ip']}:{cfg.get('port', 8081)}/zeroconf/{command}"

    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Connection": "close",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                if (
                    resp_json.get("error") == 0
                    and "data" in resp_json
                    and "iv" in resp_json
                    and resp_json["data"]
                ):
                    try:
                        resp_json["decrypted"] = decrypt_lan_data(
                            resp_json["data"],
                            resp_json["iv"],
                            cfg["devicekey"],
                        )
                    except Exception:
                        pass
                return resp_json
        except (ConnectionResetError, urllib.error.URLError) as e:
            last_err = e
            time.sleep(0.12)
        except Exception as e:
            last_err = e
            break

    raise RuntimeError(f"LAN request to {url} failed: {last_err}")


# ---------------------------------------------------------------------------
# High-level B05-BL-A60 (UIID 136) Controls
# ---------------------------------------------------------------------------


def clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(round(val))))


def turn_on(cfg: dict, cancel_morning: bool = True) -> dict:
    if cancel_morning:
        stop_morning_routine()
    return send_lan_command(cfg, "switch", {"switch": "on"})


def turn_off(cfg: dict, cancel_morning: bool = True) -> dict:
    if cancel_morning:
        stop_morning_routine()
    return send_lan_command(cfg, "switch", {"switch": "off"})


def toggle_bulb(cfg: dict) -> dict:
    stop_morning_routine()
    status = get_bulb_status(cfg)
    current_switch = status.get("state", {}).get("switch", "off")
    new_switch = "off" if current_switch == "on" else "on"
    res = send_lan_command(cfg, "switch", {"switch": new_switch})
    res["new_state"] = new_switch
    return res


def set_white(
    cfg: dict,
    br: int = 100,
    ct: int = 50,
    kelvin: int = None,
    cancel_morning: bool = True,
) -> dict:
    """
    Set White mode on B05-BL-A60 (UIID 136).
    - br: Brightness 1..100
    - ct: Color temperature 0..100 (0 = warm 2000K, 100 = cold 6500K)
    - kelvin: Optional color temperature in Kelvin (2000..6500), overrides ct if given
    """
    if cancel_morning:
        stop_morning_routine()
    if kelvin is not None:
        ct = round((clamp(kelvin, 2000, 6500) - 2000) / (6500 - 2000) * 100)
    br = clamp(br, 1, 100)
    ct = clamp(ct, 0, 100)

    turn_on(cfg, cancel_morning=False)
    params = {
        "ltype": "white",
        "white": {"br": br, "ct": ct},
    }
    return send_lan_command(cfg, "dimmable", params)


def set_rgb(
    cfg: dict,
    r: int,
    g: int,
    b: int,
    br: int = 100,
    cancel_morning: bool = True,
) -> dict:
    """
    Set RGB Color mode on B05-BL-A60 (UIID 136).
    - r, g, b: 0..255
    - br: Brightness 1..100
    """
    if cancel_morning:
        stop_morning_routine()
    r = clamp(r, 0, 255)
    g = clamp(g, 0, 255)
    b = clamp(b, 0, 255)
    br = clamp(br, 1, 100)

    turn_on(cfg, cancel_morning=False)
    params = {
        "ltype": "color",
        "color": {"br": br, "r": r, "g": g, "b": b},
    }
    return send_lan_command(cfg, "dimmable", params)


def set_effect(cfg: dict, effect_name: str, cancel_morning: bool = True) -> dict:
    """Set built-in scene/effect on B05-BL-A60."""
    if cancel_morning:
        stop_morning_routine()
    if effect_name not in B05_EFFECTS:
        valid = ", ".join(B05_EFFECTS.keys())
        raise ValueError(f"Unknown effect '{effect_name}'. Valid effects: {valid}")
    turn_on(cfg, cancel_morning=False)
    params = {
        "ltype": effect_name,
        effect_name: B05_EFFECTS[effect_name],
    }
    return send_lan_command(cfg, "dimmable", params)


# ---------------------------------------------------------------------------
# Morning Sunrise Routine (Background Worker & Spawner)
# ---------------------------------------------------------------------------


def start_morning_detached(
    ramp_minutes: float = 30.0,
    auto_off_minutes: float = 0.0,
    step_seconds: int = 30,
    target_br: int = 100,
    target_ct: int = 75,
) -> dict:
    """
    Spawn a detached background process that runs the sunrise ramp over `ramp_minutes`,
    leaves the bulb ON at target brightness/temperature, and exits cleanly.
    Returns immediately so the calling agent/cron never hangs.
    """
    stop_morning_routine()

    run_id = f"{int(time.time() * 1000)}"
    state_info = {
        "run_id": run_id,
        "pid": None,
        "started_at": time.time(),
        "started_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ramp_minutes": ramp_minutes,
        "auto_off_minutes": auto_off_minutes,
        "leave_on": auto_off_minutes <= 0,
        "step_seconds": step_seconds,
        "target_br": target_br,
        "target_ct": target_ct,
        "phase": "starting",
    }
    with open(MORNING_PID_PATH, "w", encoding="utf-8") as f:
        json.dump(state_info, f, indent=2, ensure_ascii=False)

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_morning-worker",
        "--run-id",
        run_id,
        "--ramp",
        str(ramp_minutes),
        "--auto-off",
        str(auto_off_minutes),
        "--step",
        str(step_seconds),
        "--target-br",
        str(target_br),
        "--target-ct",
        str(target_ct),
    ]

    log_file = open(MORNING_LOG_PATH, "w", encoding="utf-8")
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_file,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        # DETACHED_PROCESS (0x08) | CREATE_NEW_PROCESS_GROUP (0x200) | CREATE_NO_WINDOW (0x08000000)
        kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    log_file.close()

    for _ in range(8):
        time.sleep(0.05)
        try:
            with open(MORNING_PID_PATH, "r", encoding="utf-8") as f:
                cur = json.load(f)
            if cur.get("pid"):
                state_info = cur
                break
        except Exception:
            pass
    else:
        state_info["pid"] = proc.pid

    return {
        "ok": True,
        "action": "morning_sunrise_started",
        **state_info,
    }


def _update_morning_state(run_id: str, **updates) -> bool:
    """Update morning_state.json using run_id and record real worker os.getpid()."""
    if not MORNING_PID_PATH.exists():
        return False
    try:
        with open(MORNING_PID_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("run_id") != run_id:
            return False
        data["pid"] = os.getpid()
        data.update(updates)
        with open(MORNING_PID_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def run_morning_worker(
    cfg: dict,
    run_id: str,
    ramp_minutes: float = 30.0,
    auto_off_minutes: float = 0.0,
    step_seconds: int = 30,
    target_br: int = 100,
    target_ct: int = 75,
) -> None:
    """
    Biological Sunrise Simulation:
    - Phase 1 (0%..20% of ramp time, e.g. first 6 min):
      Deep red/amber dawn glow using RGB LEDs:
      (255, 20, 0) @ 1% -> (255, 130, 15) @ 12%
    - Phase 2 (20%..100% of ramp time, e.g. 6..30 min):
      Warm candle white (ct=0 / 2000K, br=10%) -> Energizing morning sun (ct=target_ct / ~5400K, br=target_br)
      using a smooth perceptual curve (gamma ~ 1.5) so early minutes are gentle.
    - Leaves the bulb ON at 100% when finished (unless --auto-off > 0 is explicitly specified).
    """
    ramp_sec = max(10.0, ramp_minutes * 60.0)
    auto_off_sec = max(0.0, auto_off_minutes * 60.0)
    step_sec = max(5, int(step_seconds))
    total_steps = max(1, int(round(ramp_sec / step_sec)))

    print(
        f"[*] Morning sunrise worker started (PID={os.getpid()}, run_id={run_id}): "
        f"ramp={ramp_minutes}m ({total_steps} steps), leave_on={auto_off_sec <= 0}"
    )
    sys.stdout.flush()

    try:
        for step in range(total_steps + 1):
            if not _update_morning_state(
                run_id,
                current_step=step,
                total_steps=total_steps,
                progress_pct=round(step / total_steps * 100, 1),
            ):
                print("[!] Morning routine cancelled externally. Exiting.")
                return

            progress = step / total_steps  # 0.0 .. 1.0

            if progress < 0.20:
                p1 = progress / 0.20
                r = 255
                g = clamp(20 + p1 * 110, 0, 255)
                b = clamp(p1 * 15, 0, 255)
                br = clamp(1 + p1 * 11, 1, 100)
                _update_morning_state(
                    run_id, phase="dawn_rgb", current_br=br, current_rgb=[r, g, b]
                )
                try:
                    set_rgb(cfg, r, g, b, br=br, cancel_morning=False)
                    print(f"[{time.strftime('%H:%M:%S')}] Step {step}/{total_steps} (dawn_rgb): rgb=({r},{g},{b}), br={br}%")
                except Exception as e:
                    print(f"[!] Step {step} RGB error: {e}")
            else:
                p2 = (progress - 0.20) / 0.80
                curved = p2 ** 1.5
                br = clamp(10 + curved * (target_br - 10), 1, target_br)
                ct = clamp((p2 ** 1.2) * target_ct, 0, 100)
                _update_morning_state(
                    run_id, phase="sunrise_white", current_br=br, current_ct=ct
                )
                try:
                    set_white(cfg, br=br, ct=ct, cancel_morning=False)
                    print(f"[{time.strftime('%H:%M:%S')}] Step {step}/{total_steps} (sunrise_white): br={br}%, ct={ct}%")
                except Exception as e:
                    print(f"[!] Step {step} White error: {e}")

            sys.stdout.flush()
            if step < total_steps:
                for _ in range(step_sec):
                    if not MORNING_PID_PATH.exists():
                        return
                    time.sleep(1)

        print(f"[*] Sunrise ramp complete ({ramp_minutes}m). Bulb stays ON at {target_br}%.")
        sys.stdout.flush()

        if auto_off_sec > 0:
            _update_morning_state(run_id, phase="waiting_auto_off", progress_pct=100.0)
            for _ in range(int(auto_off_sec)):
                if not MORNING_PID_PATH.exists():
                    return
                time.sleep(1)
            if _update_morning_state(run_id, phase="completed_auto_off"):
                turn_off(cfg, cancel_morning=False)
    finally:
        try:
            if MORNING_PID_PATH.exists():
                with open(MORNING_PID_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("run_id") == run_id:
                    MORNING_PID_PATH.unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# One-Time Cloud Login to Fetch `devicekey`
# ---------------------------------------------------------------------------


def cloud_fetch_devices(
    username: str, password: str, country_code: str = "+7", region: str = "eu"
) -> list[dict]:
    payload = {"password": password, "countryCode": country_code}
    if "@" in username:
        payload["email"] = username
    elif username.startswith("+"):
        payload["phoneNumber"] = username
    else:
        payload["phoneNumber"] = "+" + username

    data = json.dumps(payload).encode("utf-8")
    sig = _sign_cloud_payload(data)

    headers = {
        "Authorization": f"Sign {sig}",
        "Content-Type": "application/json",
        "X-CK-Appid": APP_ID,
    }

    def post_login(reg: str) -> dict:
        url = f"{CLOUD_APIS[reg]}/v2/user/login"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    resp = post_login(region)
    if resp.get("error") == 10004 and "region" in resp.get("data", {}):
        region = resp["data"]["region"]
        print(f"[*] Switching to account region: {region}")
        resp = post_login(region)

    if resp.get("error") != 0:
        raise RuntimeError(
            f"eWeLink Cloud login error ({resp.get('error')}): {resp.get('msg')}"
        )

    token = resp["data"]["at"]
    auth_headers = {
        "Authorization": f"Bearer {token}",
        "X-CK-Appid": APP_ID,
    }

    family_ids = [None]
    try:
        fam_req = urllib.request.Request(
            f"{CLOUD_APIS[region]}/v2/family", headers=auth_headers, method="GET"
        )
        with urllib.request.urlopen(fam_req, timeout=10) as fam_resp:
            fam_data = json.loads(fam_resp.read().decode("utf-8"))
            family_ids = [
                f["id"] for f in fam_data.get("data", {}).get("familyList", [])
            ] or [None]
    except Exception:
        pass

    devices = []
    seen_ids = set()
    for fid in family_ids:
        q = f"?num=0&familyid={fid}" if fid else "?num=0"
        thing_req = urllib.request.Request(
            f"{CLOUD_APIS[region]}/v2/device/thing{q}",
            headers=auth_headers,
            method="GET",
        )
        with urllib.request.urlopen(thing_req, timeout=10) as thing_resp:
            thing_data = json.loads(thing_resp.read().decode("utf-8"))
            for item in thing_data.get("data", {}).get("thingList", []):
                item_data = item.get("itemData", {})
                did = item_data.get("deviceid")
                if did and did not in seen_ids:
                    seen_ids.add(did)
                    devices.append(item_data)

    return devices


# ---------------------------------------------------------------------------
# Built-in Local HTTP API Server & Web UI
# ---------------------------------------------------------------------------

WEB_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sonoff B05-BL-A60 Local Control</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; display: flex; justify-content: center; }
    .container { max-width: 480px; width: 100%; background: var(--card); border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
    h1 { font-size: 1.35rem; margin-top: 0; display: flex; justify-content: space-between; align-items: center; }
    .badge { font-size: 0.75rem; background: #0284c7; padding: 4px 10px; border-radius: 99px; }
    .row { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
    button { flex: 1; padding: 12px 16px; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; background: #334155; color: white; transition: 0.15s; }
    button:hover { background: #475569; }
    button.primary { background: #0284c7; }
    button.primary:hover { background: #0369a1; }
    button.sunrise { background: #f59e0b; color: #0f172a; }
    button.danger { background: #dc2626; }
    .section { border-top: 1px solid #334155; padding-top: 16px; margin-top: 16px; }
    label { display: block; font-size: 0.875rem; margin-bottom: 6px; color: #cbd5e1; }
    input[type=range], input[type=color] { width: 100%; margin-bottom: 12px; }
    input[type=color] { height: 44px; border: none; border-radius: 8px; background: none; cursor: pointer; }
    pre { background: #0f172a; padding: 12px; border-radius: 8px; font-size: 0.8rem; overflow-x: auto; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Sonoff B05-BL-A60 <span class="badge">LAN Direct</span></h1>
    <div class="row">
      <button class="primary" onclick="api('/api/on', {})">TURN ON</button>
      <button class="sunrise" onclick="api('/api/morning', {})">🌅 SUNRISE (30m)</button>
      <button class="danger" onclick="api('/api/off', {})">TURN OFF</button>
    </div>

    <div class="section">
      <label>White Mode: Brightness (<span id="wBrVal">80</span>%) &amp; Color Temp (<span id="wCtVal">50</span>%)</label>
      <input type="range" id="wBr" min="1" max="100" value="80" oninput="wBrVal.innerText=this.value" onchange="sendWhite()">
      <input type="range" id="wCt" min="0" max="100" value="50" oninput="wCtVal.innerText=this.value" onchange="sendWhite()">
      <button onclick="sendWhite()">Apply White</button>
    </div>

    <div class="section">
      <label>RGB Color &amp; Brightness (<span id="cBrVal">100</span>%)</label>
      <input type="color" id="rgbPicker" value="#ff6600" onchange="sendColor()">
      <input type="range" id="cBr" min="1" max="100" value="100" oninput="cBrVal.innerText=this.value" onchange="sendColor()">
      <button onclick="sendColor()">Apply Color</button>
    </div>

    <div class="section">
      <label>Scenes / Effects</label>
      <div class="row">
        <button onclick="api('/api/effect', {effect:'bright'})">Bright</button>
        <button onclick="api('/api/effect', {effect:'read'})">Read</button>
        <button onclick="api('/api/effect', {effect:'nightLight'})">Night</button>
        <button onclick="api('/api/effect', {effect:'party'})">Party</button>
      </div>
    </div>

    <div class="section">
      <label>Bulb Status <button style="padding:4px 8px;font-size:0.75rem;float:right" onclick="refreshStatus()">Refresh</button></label>
      <pre id="statusBox">Loading...</pre>
    </div>
  </div>

  <script>
    async function api(path, body) {
      const res = await fetch(path, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
      const data = await res.json();
      document.getElementById('statusBox').innerText = JSON.stringify(data, null, 2);
    }
    function sendWhite() {
      api('/api/white', {
        br: parseInt(document.getElementById('wBr').value),
        ct: parseInt(document.getElementById('wCt').value)
      });
    }
    function sendColor() {
      const hex = document.getElementById('rgbPicker').value;
      const r = parseInt(hex.slice(1,3), 16);
      const g = parseInt(hex.slice(3,5), 16);
      const b = parseInt(hex.slice(5,7), 16);
      const br = parseInt(document.getElementById('cBr').value);
      api('/api/color', {r, g, b, br});
    }
    async function refreshStatus() {
      const res = await fetch('/api/status');
      const data = await res.json();
      document.getElementById('statusBox').innerText = JSON.stringify(data, null, 2);
    }
    refreshStatus();
  </script>
</body>
</html>
"""


class BulbAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        cfg = load_config()
        if parsed.path == "/":
            body = WEB_UI_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/status":
            self._send_json(200, get_bulb_status(cfg))
        elif parsed.path == "/api/on":
            try:
                self._send_json(200, {"ok": True, "response": turn_on(cfg)})
            except Exception as e:
                self._send_json(500, {"ok": False, "error": str(e)})
        elif parsed.path == "/api/off":
            try:
                self._send_json(200, {"ok": True, "response": turn_off(cfg)})
            except Exception as e:
                self._send_json(500, {"ok": False, "error": str(e)})
        elif parsed.path == "/api/toggle":
            try:
                self._send_json(200, {"ok": True, "response": toggle_bulb(cfg)})
            except Exception as e:
                self._send_json(500, {"ok": False, "error": str(e)})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8") or "{}")
        except Exception:
            body = {}

        cfg = load_config()
        try:
            if parsed.path == "/api/on":
                res = turn_on(cfg)
            elif parsed.path == "/api/off":
                res = turn_off(cfg)
            elif parsed.path == "/api/toggle":
                res = toggle_bulb(cfg)
            elif parsed.path == "/api/morning":
                if body.get("stop"):
                    res = stop_morning_routine()
                else:
                    res = start_morning_detached(
                        ramp_minutes=body.get("ramp", 30.0),
                        auto_off_minutes=body.get("auto_off", 0.0),
                        step_seconds=body.get("step", 30),
                        target_br=body.get("target_br", 100),
                        target_ct=body.get("target_ct", 75),
                    )
            elif parsed.path == "/api/white":
                res = set_white(
                    cfg,
                    br=body.get("br", 100),
                    ct=body.get("ct", 50),
                    kelvin=body.get("kelvin"),
                )
            elif parsed.path == "/api/color":
                res = set_rgb(
                    cfg,
                    r=body.get("r", 255),
                    g=body.get("g", 255),
                    b=body.get("b", 255),
                    br=body.get("br", 100),
                )
            elif parsed.path == "/api/effect":
                res = set_effect(cfg, body.get("effect", "bright"))
            elif parsed.path == "/api/control":
                state = str(body.get("state", "on")).lower()
                if state == "off":
                    res = turn_off(cfg)
                elif state == "toggle":
                    res = toggle_bulb(cfg)
                elif state == "morning":
                    res = start_morning_detached(
                        ramp_minutes=body.get("ramp", 30.0),
                        auto_off_minutes=body.get("auto_off", 0.0),
                        step_seconds=body.get("step", 30),
                    )
                elif "effect" in body:
                    res = set_effect(cfg, body["effect"])
                elif "r" in body or "rgb" in body:
                    rgb = body.get(
                        "rgb",
                        [body.get("r", 255), body.get("g", 255), body.get("b", 255)],
                    )
                    res = set_rgb(cfg, rgb[0], rgb[1], rgb[2], br=body.get("br", 100))
                elif "br" in body or "ct" in body or "kelvin" in body:
                    res = set_white(
                        cfg,
                        br=body.get("br", 100),
                        ct=body.get("ct", 50),
                        kelvin=body.get("kelvin"),
                    )
                else:
                    res = turn_on(cfg)
            else:
                self._send_json(404, {"ok": False, "error": "Unknown endpoint"})
                return

            self._send_json(200, {"ok": True, "response": res})
        except Exception as e:
            self._send_json(500, {"ok": False, "error": str(e)})


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Sonoff B05-BL-A60 (UIID 136 / BL602) Local LAN Controller & HTTP API"
    )
    sub = parser.add_subparsers(dest="cmd")

    # discover
    sub.add_parser(
        "discover",
        help="Scan local network via mDNS (_ewelink._tcp.local) to find bulb IP and deviceid",
    )

    # login
    p_login = sub.add_parser(
        "login", help="One-time login to eWeLink Cloud to fetch devicekey"
    )
    p_login.add_argument("-u", "--username", help="eWeLink email or phone number")
    p_login.add_argument("-p", "--password", help="eWeLink password")
    p_login.add_argument(
        "-c", "--country", default="+7", help="Country code (default: +7)"
    )
    p_login.add_argument(
        "-r", "--region", default="eu", choices=["eu", "us", "as", "cn"]
    )

    # set-key
    p_key = sub.add_parser("set-key", help="Manually set devicekey and IP in bulb_config.json")
    p_key.add_argument("devicekey", help="Your 16-char UUID devicekey")
    p_key.add_argument("--ip", help="Bulb IPv4 address on LAN")
    p_key.add_argument("--deviceid", help="10-character eWeLink deviceid")

    # status
    sub.add_parser("status", help="Read bulb status via local mDNS")

    # on / off / toggle
    sub.add_parser("on", help="Turn bulb ON via LAN")
    sub.add_parser("off", help="Turn bulb OFF via LAN")
    sub.add_parser("toggle", help="Toggle bulb ON/OFF state via LAN")

    # morning (detached sunrise alarm)
    p_morning = sub.add_parser(
        "morning",
        help="Start detached background sunrise wake-up routine (30m ramp 1%%->100%%, stays ON)",
    )
    p_morning.add_argument(
        "--ramp",
        type=float,
        default=30.0,
        help="Minutes to ramp brightness from 1%% to 100%% (default: 30)",
    )
    p_morning.add_argument(
        "--auto-off",
        type=float,
        default=0.0,
        help="Optional minutes after ramp before turning off (default: 0 = leave ON)",
    )
    p_morning.add_argument(
        "--step",
        type=int,
        default=30,
        help="Seconds between brightness updates (default: 30)",
    )
    p_morning.add_argument(
        "--target-br",
        type=int,
        default=100,
        help="Final brightness 1..100 (default: 100)",
    )
    p_morning.add_argument(
        "--target-ct",
        type=int,
        default=75,
        help="Final white color temperature 0..100 (default: 75 ~ 5400K daylight)",
    )
    p_morning.add_argument(
        "--stop",
        action="store_true",
        help="Stop any currently running background morning routine",
    )
    p_morning.add_argument(
        "--status",
        action="store_true",
        help="Check status of the background morning routine",
    )

    # internal hidden worker command
    p_worker = sub.add_parser("_morning-worker")
    p_worker.add_argument("--run-id", required=True)
    p_worker.add_argument("--ramp", type=float, default=30.0)
    p_worker.add_argument("--auto-off", type=float, default=0.0)
    p_worker.add_argument("--step", type=int, default=30)
    p_worker.add_argument("--target-br", type=int, default=100)
    p_worker.add_argument("--target-ct", type=int, default=75)

    # white
    p_white = sub.add_parser("white", help="Set white mode (brightness & color temp)")
    p_white.add_argument("--br", type=int, default=100, help="Brightness 1..100")
    p_white.add_argument(
        "--ct", type=int, default=50, help="Color Temp 0..100 (0=warm, 100=cold)"
    )
    p_white.add_argument(
        "--kelvin", type=int, help="Color Temp in Kelvin (2000..6500)"
    )

    # rgb
    p_rgb = sub.add_parser("rgb", help="Set RGB color mode")
    p_rgb.add_argument("r", type=int, help="Red 0..255")
    p_rgb.add_argument("g", type=int, help="Green 0..255")
    p_rgb.add_argument("b", type=int, help="Blue 0..255")
    p_rgb.add_argument("--br", type=int, default=100, help="Brightness 1..100")

    # effect
    p_eff = sub.add_parser(
        "effect", help=f"Set scene effect ({', '.join(B05_EFFECTS.keys())})"
    )
    p_eff.add_argument("name", choices=list(B05_EFFECTS.keys()))

    # serve
    p_serve = sub.add_parser("serve", help="Start local REST API & Web UI server")
    p_serve.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8000, help="Bind port (default 8000)")

    args = parser.parse_args()
    cfg = load_config()

    if args.cmd == "discover":
        print("[*] Scanning local network via mDNS (_ewelink._tcp.local)...")
        props = query_mdns_bulb(timeout=5.0)
        if not props:
            print("[-] No eWeLink LAN devices responded on mDNS.")
            sys.exit(1)
        cfg["ip"] = props.get("_ip", cfg.get("ip", ""))
        cfg["deviceid"] = props.get("id", cfg.get("deviceid", ""))
        save_config(cfg)
        print(f"[+] Discovered bulb at {cfg['ip']} (deviceid={cfg['deviceid']}) and saved to {CONFIG_PATH}!")
        print(json.dumps(props, indent=2, ensure_ascii=False))

    elif args.cmd == "login":
        username = args.username or input("eWeLink Email or Phone: ").strip()
        password = args.password or getpass.getpass("eWeLink Password: ").strip()
        print("[*] Connecting to eWeLink Cloud API v2 to retrieve devicekey...")
        devices = cloud_fetch_devices(username, password, args.country, args.region)
        if not devices:
            print("[-] No devices found in this account.")
            sys.exit(1)

        print(f"[+] Found {len(devices)} device(s):")
        matched = None
        for d in devices:
            did = d.get("deviceid")
            dkey = d.get("devicekey")
            name = d.get("name")
            model = d.get("productModel")
            uiid = d.get("extra", {}).get("uiid")
            print(f"    - {name} ({model}, uiid={uiid}) | id={did} | devicekey={dkey}")
            if (cfg.get("deviceid") and did == cfg.get("deviceid")) or uiid == 136:
                matched = d

        if not matched:
            matched = devices[0]

        cfg["deviceid"] = matched["deviceid"]
        cfg["devicekey"] = matched["devicekey"]
        cfg["name"] = matched.get("name", cfg["name"])
        cfg["uiid"] = matched.get("extra", {}).get("uiid", 136)

        # Auto-discover IP via mDNS if not set yet
        if not cfg.get("ip"):
            print("[*] Discovering bulb IP on local network via mDNS...")
            props = query_mdns_bulb(deviceid=cfg["deviceid"], timeout=4.0)
            if props.get("_ip"):
                cfg["ip"] = props["_ip"]
                print(f"[+] Found bulb IP: {cfg['ip']}")

        save_config(cfg)
        print(f"\n[+] Saved configuration and devicekey to {CONFIG_PATH}!")
        if cfg.get("ip"):
            print(json.dumps(get_bulb_status(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "set-key":
        cfg["devicekey"] = args.devicekey.strip()
        if args.ip:
            cfg["ip"] = args.ip.strip()
        if args.deviceid:
            cfg["deviceid"] = args.deviceid.strip()
        save_config(cfg)
        print(f"[+] Saved to {CONFIG_PATH}!")
        if cfg.get("ip"):
            print(json.dumps(get_bulb_status(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "status" or args.cmd is None:
        print(json.dumps(get_bulb_status(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "on":
        print(json.dumps(turn_on(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "off":
        print(json.dumps(turn_off(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "toggle":
        print(json.dumps(toggle_bulb(cfg), indent=2, ensure_ascii=False))

    elif args.cmd == "morning":
        if args.stop:
            print(json.dumps(stop_morning_routine(), indent=2, ensure_ascii=False))
        elif args.status:
            print(json.dumps(get_morning_status(), indent=2, ensure_ascii=False))
        else:
            res = start_morning_detached(
                ramp_minutes=args.ramp,
                auto_off_minutes=args.auto_off,
                step_seconds=args.step,
                target_br=args.target_br,
                target_ct=args.target_ct,
            )
            print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.cmd == "_morning-worker":
        run_morning_worker(
            cfg,
            run_id=args.run_id,
            ramp_minutes=args.ramp,
            auto_off_minutes=args.auto_off,
            step_seconds=args.step,
            target_br=args.target_br,
            target_ct=args.target_ct,
        )

    elif args.cmd == "white":
        print(
            json.dumps(
                set_white(cfg, br=args.br, ct=args.ct, kelvin=args.kelvin),
                indent=2,
                ensure_ascii=False,
            )
        )

    elif args.cmd == "rgb":
        print(
            json.dumps(
                set_rgb(cfg, args.r, args.g, args.b, br=args.br),
                indent=2,
                ensure_ascii=False,
            )
        )

    elif args.cmd == "effect":
        print(json.dumps(set_effect(cfg, args.name), indent=2, ensure_ascii=False))

    elif args.cmd == "serve":
        print(f"[*] Starting Local Bulb API & Web UI on http://{args.host}:{args.port}")
        print(f"    Web UI:   http://localhost:{args.port}/")
        print(f"    Status:   GET  http://localhost:{args.port}/api/status")
        print(f"    Control:  POST http://localhost:{args.port}/api/control")
        server = ThreadingHTTPServer((args.host, args.port), BulbAPIHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping server.")
            server.server_close()


if __name__ == "__main__":
    main()

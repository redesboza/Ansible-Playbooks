#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TP-Link Omada/JetStream - Find MAC in address-table via CLI over SSH

Command:
  enable (sin contraseña)
  sh mac address-table address <MAC>

Usage:
  find_mac_tplink.py <host> <login_user> <login_pass> <port> <mac>

Example:
  find_mac_tplink.py 172.16.45.46 ansible 'PASS' 11110 00:12:33:16:6b:5a
"""

import sys
import re
import time
import select
import paramiko

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ERR_RE = re.compile(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error|failed|unknown|incomplete|incorrect)")

def log(msg: str):
    print(msg, flush=True)

def clean_text(s: str) -> str:
    if not s:
        return ""
    s = ANSI_RE.sub("", s)
    s = s.replace("\r", "")
    return s

def has_error(text: str) -> bool:
    return bool(ERR_RE.search(clean_text(text or "")))

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "")).strip("_")

def normalize_mac(mac: str) -> str:
    m = (mac or "").strip().lower()
    # Accept formats with -, :, . (Cisco)
    m = m.replace("-", ":")
    if "." in m:
        # 0012.3316.6b5a -> 00:12:33:16:6b:5a
        m = re.sub(r"[^0-9a-f]", "", m)
        if len(m) == 12:
            m = ":".join([m[i:i+2] for i in range(0, 12, 2)])
        return m
    # If plain 12 hex
    m2 = re.sub(r"[^0-9a-f]", "", m)
    if len(m2) == 12 and ":" not in m:
        return ":".join([m2[i:i+2] for i in range(0, 12, 2)])
    return m

def ch_read(channel, session_path: str, timeout=1.0, max_bytes=65535):
    buf = ""
    r, _, _ = select.select([channel], [], [], timeout)
    if r:
        data = channel.recv(max_bytes)
        if data:
            buf = data.decode("utf-8", errors="ignore")
            with open(session_path, "a", encoding="utf-8") as f:
                f.write(buf)
    return buf

def ch_drain(channel, session_path: str, seconds=1.2):
    out = ""
    end = time.time() + seconds
    while time.time() < end:
        out += ch_read(channel, session_path, timeout=0.4)
    return out

def ch_send(channel, cmd: str):
    channel.send(cmd + "\r")

def run(host: str, login_user: str, login_pass: str, port: int, mac: str):
    session_path = f"/tmp/tplink_findmac_{sanitize_filename(host)}_{port}_{int(time.time())}.log"
    mac_n = normalize_mac(mac)

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(
        hostname=host,
        port=port,
        username=login_user,
        password=login_pass,
        look_for_keys=False,
        allow_agent=False,
        timeout=60,
        banner_timeout=60,
        auth_timeout=60,
    )

    transport = cli.get_transport()
    if transport:
        transport.set_keepalive(10)

    ch = cli.invoke_shell(width=200, height=60)
    time.sleep(0.8)
    ch_drain(ch, session_path, seconds=2.0)

    # ENTER
    ch_send(ch, "")
    ch_drain(ch, session_path, seconds=1.0)

    # enable + ENTER (sin contraseña)
    log("[+] enable (sin contraseña)")
    ch_send(ch, "enable")
    ch_drain(ch, session_path, seconds=0.8)
    ch_send(ch, "")
    ch_drain(ch, session_path, seconds=1.2)

    cmd = f"sh mac address-table address {mac_n}"
    log("[+] " + cmd)
    ch_send(ch, cmd)

    out = ch_drain(ch, session_path, seconds=2.5)
    # a veces demora un poco más
    out += ch_drain(ch, session_path, seconds=1.5)

    txt = clean_text(out).strip()

    if has_error(out):
        raise RuntimeError("El switch reportó error.\nSalida:\n" + (txt[-2000:] if txt else "(vacío)"))

    # Quitar eco del comando repetido (si aparece)
    # Dejamos solo lo útil.
    lines = [l for l in txt.splitlines() if l.strip() != ""]
    # Eliminar líneas que sean exactamente el comando o parte del prompt-eco
    filtered = []
    for l in lines:
        if cmd in l:
            continue
        filtered.append(l)

    result = "\n".join(filtered).strip() or txt or "(sin salida)"

    log("[RESULT]\n" + result)
    log(f"[INFO] session_log: {session_path}")

    ch_send(ch, "exit")
    ch_drain(ch, session_path, seconds=0.5)
    cli.close()

def main():
    if len(sys.argv) < 6:
        print(
            "Uso:\n  find_mac_tplink.py <host> <login_user> <login_pass> <port> <mac>\n",
            file=sys.stderr,
        )
        sys.exit(2)

    host = sys.argv[1]
    login_user = sys.argv[2]
    login_pass = sys.argv[3]
    port = int(sys.argv[4])
    mac = sys.argv[5]

    try:
        log(f"[+] Conectando por SSH: {login_user}@{host}:{port}")
        run(host, login_user, login_pass, port, mac)
        sys.exit(0)
    except Exception as e:
        log(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

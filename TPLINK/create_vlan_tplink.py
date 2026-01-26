#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TP-Link Omada/JetStream - Create VLAN via CLI over SSH

Steps:
  - SSH login (username/password)
  - ENTER
  - enable + ENTER (sin contraseña)
  - configure
  - vlan <VLAN_ID>
  - name <VLAN_NAME>
  - exit (optional)

Usage:
  create_vlan_tplink.py <host> <login_user> <login_pass> <port> <vlan_id> <vlan_name>
"""

import sys
import re
import time
import select
import paramiko

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ERR_RE = re.compile(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error|failed|unknown|incomplete|incorrect|already exists)")

def log(msg: str):
    print(msg, flush=True)

def clean_text(s: str) -> str:
    if not s:
        return ""
    s = ANSI_RE.sub("", s)
    return s.replace("\r", "\n")

def has_error(text: str) -> bool:
    return bool(ERR_RE.search(clean_text(text or "")))

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "")).strip("_")

def sanitize_vlan_name(name: str) -> str:
    # Keep it simple for CLI: letters, numbers, dash, underscore
    n = (name or "").strip()
    n = re.sub(r"[^A-Za-z0-9_-]+", "_", n)
    return n[:32] if n else "VLAN"

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

def run(host: str, login_user: str, login_pass: str, port: int, vlan_id: int, vlan_name: str):
    session_path = f"/tmp/tplink_vlan_{sanitize_filename(host)}_{port}_{int(time.time())}.log"
    vlan_name = sanitize_vlan_name(vlan_name)

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

    # configure
    log("[+] configure")
    ch_send(ch, "configure")
    out_cfg = ch_drain(ch, session_path, seconds=1.5)
    if has_error(out_cfg):
        raise RuntimeError("Error entrando a 'configure'.\nSalida:\n" + (clean_text(out_cfg)[-1500:] if out_cfg else "(vacío)"))

    # vlan <id>
    cmd_vlan = f"vlan {vlan_id}"
    log("[+] " + cmd_vlan)
    ch_send(ch, cmd_vlan)
    out_vlan = ch_drain(ch, session_path, seconds=1.5)
    if has_error(out_vlan):
        raise RuntimeError("Error creando/entrando a VLAN.\nSalida:\n" + clean_text(out_vlan)[-2000:])

    # name <name>
    cmd_name = f"name {vlan_name}"
    log("[+] " + cmd_name)
    ch_send(ch, cmd_name)
    out_name = ch_drain(ch, session_path, seconds=1.5)
    if has_error(out_name):
        raise RuntimeError("Error asignando nombre a VLAN.\nSalida:\n" + clean_text(out_name)[-2000:])

    # exit (back)
    ch_send(ch, "exit")
    ch_drain(ch, session_path, seconds=0.8)

    cli.close()

    log(f"[OK] VLAN {vlan_id} creada/actualizada con nombre '{vlan_name}' (si no hubo error).") 
    log(f"[INFO] session_log: {session_path}")

def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n  create_vlan_tplink.py <host> <login_user> <login_pass> <port> <vlan_id> <vlan_name>\n",
            file=sys.stderr,
        )
        sys.exit(2)

    host = sys.argv[1]
    login_user = sys.argv[2]
    login_pass = sys.argv[3]
    port = int(sys.argv[4])
    vlan_id = int(sys.argv[5])
    vlan_name = sys.argv[6]

    try:
        log(f"[+] Conectando por SSH: {login_user}@{host}:{port}")
        run(host, login_user, login_pass, port, vlan_id, vlan_name)
        sys.exit(0)
    except Exception as e:
        log(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

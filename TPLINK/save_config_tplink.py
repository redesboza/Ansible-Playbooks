#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TP-Link Omada/JetStream - Save config (running -> startup) via CLI over SSH

Steps (matches your manual flow):
  - SSH login (username/password)
  - ENTER
  - enable + ENTER (sin contraseña)
  - copy running-config startup-config
  - exit

Usage:
  save_config_tplink.py <host> <login_user> <login_pass> <port>
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

def clean_for_match(s: str) -> str:
    if not s:
        return ""
    s = ANSI_RE.sub("", s)
    return s.replace("\r", "\n")

def has_error(text: str) -> bool:
    return bool(ERR_RE.search(clean_for_match(text or "")))

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "")).strip("_")

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
    # TP-Link suele responder mejor con CR en shells interactivos
    channel.send(cmd + "\r")

def run(host: str, login_user: str, login_pass: str, port: int):
    session_path = f"/tmp/tplink_save_{sanitize_filename(host)}_{port}_{int(time.time())}.log"

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

    # save running -> startup
    cmd_save = "copy running-config startup-config"
    log("[+] " + cmd_save)
    ch_send(ch, cmd_save)
    out_save = ch_drain(ch, session_path, seconds=3.0)

    if out_save.strip():
        log("[OUT] " + clean_for_match(out_save).strip())

    if has_error(out_save):
        raise RuntimeError("El switch reportó error al guardar configuración.\nSalida:\n" + clean_for_match(out_save)[-2000:])

    # exit
    ch_send(ch, "exit")
    ch_drain(ch, session_path, seconds=0.8)

    cli.close()

    log("[OK] Comando de guardado ejecutado (si no hubo error).") 
    log(f"[INFO] session_log: {session_path}")

def main():
    if len(sys.argv) < 5:
        print(
            "Uso:\n  save_config_tplink.py <host> <login_user> <login_pass> <port>\n",
            file=sys.stderr,
        )
        sys.exit(2)

    host = sys.argv[1]
    login_user = sys.argv[2]
    login_pass = sys.argv[3]
    port = int(sys.argv[4])

    try:
        log(f"[+] Conectando por SSH: {login_user}@{host}:{port}")
        run(host, login_user, login_pass, port)
        sys.exit(0)
    except Exception as e:
        log(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

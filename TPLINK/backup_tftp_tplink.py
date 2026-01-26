#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import time
import select
from datetime import datetime

import paramiko


def log(msg: str):
    print(msg, flush=True)


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


def parse_host_ip(tag: str, fallback_ip: str):
    raw = (tag or "").strip()
    if "__" in raw:
        h, ip = raw.split("__", 1)
        return (h.strip() or "HOST", ip.strip() or fallback_ip)

    m = re.match(r"^(.*)_(\d{1,3}(?:\.\d{1,3}){3})$", raw)
    if m:
        return (m.group(1).strip() or "HOST", m.group(2).strip() or fallback_ip)

    return (raw if raw else "HOST", fallback_ip)


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")  # limpia ANSI para matching
OK_RE = re.compile(r"(?i)backup user config file ok|backup.*ok")
ERR_RE = re.compile(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error|timed out|timeout|unreachable|failed)")


def clean_for_match(s: str) -> str:
    if not s:
        return ""
    s = ANSI_RE.sub("", s)
    return s.replace("\r", "\n")


def has_error(text: str) -> bool:
    return bool(ERR_RE.search(clean_for_match(text)))


def backup_ok(text: str) -> bool:
    return bool(OK_RE.search(clean_for_match(text)))


def ch_read(channel, session_path: str, timeout=1.0, max_bytes=65535):
    """Lee del channel con select (más confiable que recv_ready)."""
    buf = ""
    r, _, _ = select.select([channel], [], [], timeout)
    if r:
        data = channel.recv(max_bytes)
        if data:
            buf = data.decode("utf-8", errors="ignore")
            with open(session_path, "a", encoding="utf-8") as f:
                f.write(buf)
    return buf


def ch_drain(channel, session_path: str, seconds=1.5):
    out = ""
    end = time.time() + seconds
    while time.time() < end:
        out += ch_read(channel, session_path, timeout=0.4)
    return out


def ch_send(channel, cmd: str):
    # IMPORTANTE: TP-Link suele responder mejor con \r
    channel.send(cmd + "\r")


def wait_ok_or_error(channel, session_path: str, timeout=240):
    buf = ""
    end = time.time() + timeout
    while time.time() < end:
        buf += ch_read(channel, session_path, timeout=0.8)
        if backup_ok(buf) or has_error(buf):
            break
    return buf


def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n"
            "  backup_tftp_tplink.py <host> <user> <pass> <port> <tftp_server> <inventory_tag>\n",
            file=sys.stderr,
        )
        sys.exit(2)

    host = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4])
    tftp_server = sys.argv[5]
    inv_tag = sys.argv[6]

    hostname, ip = parse_host_ip(inv_tag, host)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = sanitize_filename(f"{hostname}_{ip}_{ts}.cfg")
    session_path = f"/tmp/tplink_backup_{sanitize_filename(hostname)}_{sanitize_filename(ip)}_{ts}.log"

    cli = None
    try:
        log(f"[+] Conectando por SSH: {user}@{host}:{port}")

        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
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

        # 0) drenar banners/logs
        ch_drain(ch, session_path, seconds=2.0)

        # 1) ENTER (como tú haces manual)
        ch_send(ch, "")
        ch_drain(ch, session_path, seconds=1.0)

        # 2) enable + ENTER (sin contraseña)
        log("[+] enable (sin contraseña)")
        ch_send(ch, "enable")
        ch_drain(ch, session_path, seconds=0.8)
        ch_send(ch, "")  # ENTER
        ch_drain(ch, session_path, seconds=1.2)

        # 3) comando exacto de backup (igual al manual)
        cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
        log("[+] " + cmd_bkp)
        ch_send(ch, cmd_bkp)

        # 4) esperar OK real
        out = wait_ok_or_error(ch, session_path, timeout=240)
        out += ch_drain(ch, session_path, seconds=1.5)

        if out.strip():
            log("[OUT] " + out.strip().replace("\r", ""))

        if has_error(out):
            raise RuntimeError("El switch reportó error durante backup a TFTP.\nSalida:\n" + (clean_for_match(out)[-2000:] if out else "(vacío)"))

        if not backup_ok(out):
            raise RuntimeError("NO se confirmó 'Backup ... OK'.\nSalida del switch:\n" + (clean_for_match(out)[-2000:] if out else "(vacío)"))

        log("[OK] Backup confirmado por el switch.")
        log(f"[INFO] Archivo esperado en TFTP: {filename}")
        log(f"[INFO] session_log: {session_path}")
        sys.exit(0)

    except Exception as e:
        log(f"[ERROR] {e}")
        log(f"[INFO] session_log: {session_path}")
        sys.exit(1)

    finally:
        try:
            if cli:
                cli.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

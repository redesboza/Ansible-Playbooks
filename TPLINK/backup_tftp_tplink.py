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


# Detectores
OK_RE = re.compile(r"(?i)backup user config file ok|backup.*ok")
ERR_RE = re.compile(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error|timed out|timeout|unreachable|failed)")
PROMPT_RE = re.compile(r"(?m)[^\r\n]*[>#]\s*$")


def has_error(text: str) -> bool:
    return bool(ERR_RE.search(text or ""))


def backup_ok(text: str) -> bool:
    return bool(OK_RE.search(text or ""))


def ch_read(channel, session_path: str, timeout=1.0, max_bytes=65535):
    """
    Lee del channel usando select (más confiable que recv_ready en algunos equipos).
    Retorna lo leído (puede ser vacío).
    """
    buf = ""
    r, _, _ = select.select([channel], [], [], timeout)
    if r:
        try:
            data = channel.recv(max_bytes)
            if data:
                buf = data.decode("utf-8", errors="ignore")
                with open(session_path, "a", encoding="utf-8") as f:
                    f.write(buf)
        except Exception:
            pass
    return buf


def ch_drain(channel, session_path: str, seconds=1.5):
    """Drena todo lo que llegue durante X segundos."""
    out = ""
    end = time.time() + seconds
    while time.time() < end:
        out += ch_read(channel, session_path, timeout=0.4)
    return out


def ch_send(channel, cmd: str):
    channel.send(cmd + "\n")


def cmd_collect(channel, session_path: str, cmd: str, collect_seconds=3.0):
    """
    Envía comando y recolecta salida por X segundos sin depender del prompt.
    """
    log(f"[CMD] {cmd}")
    ch_send(channel, cmd)
    return ch_drain(channel, session_path, seconds=collect_seconds)


def wait_for_ok_or_error(channel, session_path: str, timeout=240):
    """
    Espera hasta ver OK o ERROR en la salida.
    """
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

        # Keepalive (evita que el canal “se duerma”)
        transport = cli.get_transport()
        if transport:
            transport.set_keepalive(10)

        ch = cli.invoke_shell(width=200, height=60)
        time.sleep(0.8)

        # 1) Drenar banner/logs iniciales
        ch_drain(ch, session_path, seconds=2.0)

        # 2) “Despertar” prompt: enviar ENTER varias veces (no exigimos verlo)
        for _ in range(3):
            ch_send(ch, "")
            time.sleep(0.3)
            ch_drain(ch, session_path, seconds=0.8)

        # 3) enable sin contraseña (enable + ENTER)
        log("[+] enable (sin contraseña)")
        ch_send(ch, "enable")
        time.sleep(0.4)
        ch_send(ch, "")
        ch_drain(ch, session_path, seconds=1.5)

        # 4) Desactivar paginación si soporta (no falla si no existe)
        cmd_collect(ch, session_path, "terminal length 0", collect_seconds=1.2)

        # 5) Guardar config (recolectar salida unos segundos)
        out1 = cmd_collect(ch, session_path, "copy running-config startup-config", collect_seconds=4.0)
        if out1.strip():
            log("[OUT] " + out1.strip().replace("\r", ""))
        if has_error(out1):
            raise RuntimeError("Error en 'copy running-config startup-config'.\nSalida:\n" + (out1[-2000:] if out1 else "(vacío)"))

        # 6) Backup TFTP (comando exacto)
        cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
        log("[+] " + cmd_bkp)
        ch_send(ch, cmd_bkp)

        # 7) Esperar OK real del switch
        out2 = wait_for_ok_or_error(ch, session_path, timeout=240)
        # drenar un poco más por si el OK llega al final
        out2 += ch_drain(ch, session_path, seconds=1.5)

        if out2.strip():
            log("[OUT] " + out2.strip().replace("\r", ""))

        if has_error(out2):
            raise RuntimeError("El switch reportó error durante backup a TFTP.\nSalida:\n" + (out2[-2000:] if out2 else "(vacío)"))

        if not backup_ok(out2):
            raise RuntimeError("NO se confirmó 'Backup ... OK'.\nSalida del switch:\n" + (out2[-2000:] if out2 else "(vacío)"))

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

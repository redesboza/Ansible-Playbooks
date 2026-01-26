#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import time
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


PROMPT_RE = re.compile(r"(?m)[^\r\n]*[>#]\s*$")
OK_RE_1 = re.compile(r"(?i)backup user config file ok")
OK_RE_2 = re.compile(r"(?i)backup.*ok")
ERR_RE = re.compile(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error|timed out|timeout|unreachable|failed)")


def has_error(text: str) -> bool:
    return bool(ERR_RE.search(text or ""))


def backup_ok(text: str) -> bool:
    t = text or ""
    return bool(OK_RE_1.search(t)) or bool(OK_RE_2.search(t))


def p_drain(shell, seconds=0.8):
    """Lee todo lo disponible durante X segundos (sin bloquear)."""
    buf = ""
    end = time.time() + seconds
    while time.time() < end:
        while shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", errors="ignore")
        time.sleep(0.1)
    return buf


def p_wait_for(shell, pattern: re.Pattern, timeout=30, poll=0.2):
    """Espera hasta ver pattern en el buffer, devuelve lo que haya."""
    buf = ""
    end = time.time() + timeout
    while time.time() < end:
        while shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", errors="ignore")
        if pattern.search(buf):
            return buf
        time.sleep(poll)
    return buf


def p_send(shell, cmd: str):
    shell.send(cmd + "\n")


def p_cmd(shell, cmd: str, session_path: str, timeout=60):
    """Ejecuta comando, espera prompt y loguea todo."""
    log(f"[CMD] {cmd}")
    p_send(shell, cmd)
    out = p_wait_for(shell, PROMPT_RE, timeout=timeout)
    if out:
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(out)
    return out


def run_backup(host, user, password, port, tftp_server, filename, session_path):
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

    shell = cli.invoke_shell(width=200, height=60)
    time.sleep(0.8)

    # Limpia banners/logs iniciales
    first = p_drain(shell, seconds=1.5)
    if first:
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(first)

    # Forzar prompt
    shell.send("\n")
    out = p_wait_for(shell, PROMPT_RE, timeout=30)
    if out:
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(out)

    if not PROMPT_RE.search(out or ""):
        # insistir por si hay logs
        extra = ""
        for _ in range(6):
            shell.send("\n")
            time.sleep(0.4)
            extra += p_drain(shell, seconds=0.8)
            if PROMPT_RE.search(extra):
                break
        if extra:
            with open(session_path, "a", encoding="utf-8") as f:
                f.write(extra)
        out = (out or "") + extra

    if not PROMPT_RE.search(out or ""):
        raise RuntimeError("No se detectó prompt (>,#). Última salida:\n" + (out[-2000:] if out else "(vacío)"))

    # enable sin contraseña
    log("[+] enable (sin contraseña)")
    p_send(shell, "enable")
    time.sleep(0.3)
    p_send(shell, "")  # ENTER
    en_out = p_wait_for(shell, PROMPT_RE, timeout=30)
    if en_out:
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(en_out)

    # Evitar paginación (si el equipo lo soporta)
    p_send(shell, "terminal length 0")
    tl = p_drain(shell, seconds=0.7)
    if tl:
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(tl)

    # 1) Guardar config
    out1 = p_cmd(shell, "copy running-config startup-config", session_path=session_path, timeout=120)
    if out1.strip():
        log("[OUT] " + out1.strip().replace("\r", ""))
    if has_error(out1):
        raise RuntimeError("Error en 'copy running-config startup-config'. Salida:\n" + (out1[-2000:] if out1 else "(vacío)"))

    # 2) Backup a TFTP (comando exacto)
    cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    log("[+] " + cmd_bkp)
    p_send(shell, cmd_bkp)

    # Esperar explícitamente OK / error (hasta 4 minutos)
    buf = ""
    end = time.time() + 240
    while time.time() < end:
        chunk = p_drain(shell, seconds=0.8)
        if chunk:
            buf += chunk
            with open(session_path, "a", encoding="utf-8") as f:
                f.write(chunk)

        if backup_ok(buf):
            break
        if has_error(buf):
            break

    if buf.strip():
        log("[OUT] " + buf.strip().replace("\r", ""))

    if has_error(buf):
        raise RuntimeError("El switch reportó error durante backup a TFTP.\nSalida:\n" + (buf[-2000:] if buf else "(vacío)"))

    if not backup_ok(buf):
        raise RuntimeError("NO se confirmó 'Backup ... OK'.\nSalida del switch:\n" + (buf[-2000:] if buf else "(vacío)"))

    log("[OK] Backup confirmado por el switch.")
    cli.close()


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

    try:
        log(f"[+] Conectando por SSH: {user}@{host}:{port}")
        run_backup(host, user, password, port, tftp_server, filename, session_path)
        log(f"[INFO] Archivo esperado en TFTP: {filename}")
        log(f"[INFO] session_log: {session_path}")
        sys.exit(0)
    except Exception as e:
        log(f"[ERROR] {e}")
        log(f"[INFO] session_log: {session_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()

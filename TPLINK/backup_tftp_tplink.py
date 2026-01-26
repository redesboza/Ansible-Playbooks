#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import time
from datetime import datetime
import pexpect


def log(msg: str):
    print(msg, flush=True)


def sanitize_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')


def parse_host_ip(tag: str, fallback_ip: str):
    """
    Acepta:
      - HOST__IP
      - HOST_IP (si termina en IPv4)
      - solo HOST
    """
    raw = (tag or "").strip()

    if "__" in raw:
        h, ip = raw.split("__", 1)
        return (h.strip() or "HOST", ip.strip() or fallback_ip)

    m = re.match(r"^(.*)_(\d{1,3}(?:\.\d{1,3}){3})$", raw)
    if m:
        return (m.group(1).strip() or "HOST", m.group(2).strip() or fallback_ip)

    return (raw if raw else "HOST", fallback_ip)


def prompt_any():
    # Detecta ...> o ...# incluso si viene pegado (sin ^)
    return re.compile(r'(?m)[^\r\n]*[>#]\s*$')


def login_ssh(host, user, password, port):
    # NO cambiamos tu autenticación: solo mejoramos estabilidad de sesión con -tt
    ssh_cmd = (
        f"ssh -tt -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password "
        f"-o PubkeyAuthentication=no "
        f"-p {port} {user}@{host}"
    )

    log(f"[+] Conectando por SSH: {user}@{host}:{port}")
    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=35)
    child.delaybeforesend = 0.05

    patterns = [
        re.compile(r'(?i)are you sure you want to continue connecting'),  # 0
        re.compile(r'(?i)login as:\s*$'),                                 # 1
        re.compile(r'(?i)user\s*name\s*:\s*$'),                            # 2
        re.compile(r'(?i)username\s*:\s*$'),                               # 3
        re.compile(r'(?i)login\s*:\s*$'),                                  # 4
        re.compile(r'(?i)password\s*:\s*$'),                               # 5
        prompt_any(),                                                     # 6
        pexpect.TIMEOUT,                                                  # 7
        pexpect.EOF                                                       # 8
    ]

    # tolera banners/logging antes del prompt
    for _ in range(35):
        idx = child.expect(patterns, timeout=35)

        if idx == 0:
            child.sendline("yes")
            continue
        if idx in (1, 2, 3, 4):
            child.sendline(user)
            continue
        if idx == 5:
            child.sendline(password)
            continue
        if idx == 6:
            log("[+] Login OK, prompt detectado.")
            return child
        if idx == 7:
            child.sendline("")
            continue
        if idx == 8:
            raise RuntimeError("EOF durante login (conexión cerrada).")

    raise RuntimeError("Timeout durante login (no apareció prompt/credenciales).")


def send_cmd(child, cmd: str):
    log(f"[CMD] {cmd}")
    child.sendline(cmd)


def wait_for_backup_ok(child, timeout=260) -> bool:
    """
    Tu TP-Link imprime:
      - Start to backup user config file......
      - Backup user config file OK.
    Así que confirmamos por texto, NO por prompt.
    """
    patterns = [
        re.compile(r'(?i)start to backup'),                # 0
        re.compile(r'(?i)backup user config file ok'),     # 1
        re.compile(r'(?i)backup.*ok'),                      # 2 (genérico)
        re.compile(r'(?i)(denied|insufficient|not allowed|invalid|error|unrecognized)'),  # 3
        prompt_any(),                                       # 4 (si aparece, ok)
        pexpect.TIMEOUT,                                    # 5
        pexpect.EOF                                         # 6
    ]

    saw_start = False
    start = time.time()

    while (time.time() - start) < timeout:
        idx = child.expect(patterns, timeout=30)

        if idx == 0:
            saw_start = True
            continue

        if idx in (1, 2):
            return True

        if idx == 3:
            return False

        if idx == 4:
            # si ya vimos "start to backup", seguimos esperando "OK"
            if saw_start:
                continue
            # si no vimos start, no concluye nada
            continue

        if idx == 5:
            continue

        if idx == 6:
            raise RuntimeError("EOF durante backup (sesión cerrada).")

    return False


def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n"
            "  backup_tftp_tplink.py <host> <user> <pass> <port> <tftp_server> <inventory_tag>\n",
            file=sys.stderr
        )
        sys.exit(2)

    host = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    port = sys.argv[4]
    tftp_server = sys.argv[5]
    inv_tag = sys.argv[6]

    hostname, ip = parse_host_ip(inv_tag, host)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = sanitize_filename(f"{hostname}_{ip}_{ts}.cfg")

    child = None
    try:
        child = login_ssh(host, user, password, port)

        # enable: tu caso es SIN contraseña -> enable + Enter
        # No esperamos prompt (tu equipo a veces no reimprime)
        log("[+] Enviando enable (sin contraseña) ...")
        child.sendline("enable")
        child.sendline("")
        time.sleep(0.8)

        # (Opcional) write memory
        send_cmd(child, "copy running-config startup-config")
        time.sleep(0.8)

        # Backup TFTP (comando exacto)
        cmd_backup = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        send_cmd(child, cmd_backup)

        ok = wait_for_backup_ok(child, timeout=260)
        if not ok:
            raise RuntimeError("No se detectó 'Backup user config file OK.' en la salida del equipo.")

        log("[OK] Backup completado (confirmado por salida OK).")
        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")

        child.sendline("exit")
        sys.exit(0)

    except Exception as e:
        log(f"[ERROR] {e}")
        if child is not None:
            try:
                log("[DEBUG] Última salida recibida:")
                log(child.before[-1200:] if child.before else "(vacío)")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()

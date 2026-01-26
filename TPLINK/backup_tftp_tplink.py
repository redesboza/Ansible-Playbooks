#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime
import pexpect


def sanitize_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')


def log(msg: str):
    print(msg, flush=True)


def prompt_any():
    # Detecta ...> o ...# incluso si viene pegado (sin ^)
    return re.compile(r'(?m)[^\r\n]*[>#]\s*$')


def prompt_privileged():
    return re.compile(r'(?m)[^\r\n]*#\s*$')


def parse_host_ip(tag: str, fallback_ip: str):
    """
    Acepta:
      - HOST__IP
      - HOST_IP (si al final hay una IPv4)
      - solo HOST
    """
    raw = (tag or "").strip()

    if "__" in raw:
        h, ip = raw.split("__", 1)
        return (h.strip() or "HOST", ip.strip() or fallback_ip)

    m = re.match(r"^(.*)_(\d{1,3}(?:\.\d{1,3}){3})$", raw)
    if m:
        h = m.group(1).strip() or "HOST"
        ip = m.group(2).strip() or fallback_ip
        return (h, ip)

    return (raw if raw else "HOST", fallback_ip)


def login_ssh(host, user, password, port):
    # CLAVE: -tt fuerza pseudo-tty (muchos switches lo necesitan para CLI/prompt estable)
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

    # Loop largo para banners/logging
    for _ in range(30):
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
            # banner largo: enviamos ENTER y seguimos
            child.sendline("")
            continue
        if idx == 8:
            raise RuntimeError("EOF durante login (conexión cerrada).")

    raise RuntimeError("Timeout durante login (no apareció prompt/credenciales).")


def enter_enable(child):
    """
    No esperamos prompt con ENTER vacío (algunos TP-Link no redibujan).
    Hacemos enable directo y esperamos #.
    """
    any_p = prompt_any()
    priv_p = prompt_privileged()

    log("[+] Ejecutando enable (sin contraseña) para asegurar modo privilegiado (#)...")
    child.sendline("enable")

    patterns = [
        priv_p,                                  # 0 -> quedó en #
        re.compile(r'(?i)password\s*:\s*$'),      # 1 -> si pide password
        any_p,                                    # 2 -> volvió a prompt (puede ser > o #)
        pexpect.TIMEOUT,                          # 3
        pexpect.EOF                               # 4
    ]

    idx = child.expect(patterns, timeout=35)

    if idx == 0:
        log("[+] Enable OK (#).")
        return

    if idx == 1:
        # tu caso: sin password -> ENTER vacío
        log("  ↳ Password en enable detectado, enviando ENTER vacío.")
        child.sendline("")
        child.expect(priv_p, timeout=35)
        log("[+] Enable OK (#).")
        return

    if idx == 2:
        # Puede que ya esté en # o siga en >
        after = (child.after or "").strip()
        if after.endswith("#"):
            log("[+] Ya estabas en modo privilegiado (#).")
            return

        # Si sigue en ">", reintento con ENTER + enable
        log("[WARN] Aún no está en # (parece '>'). Reintentando enable...")
        child.sendline("")          # a veces “despierta” el prompt
        child.sendline("enable")

        idx2 = child.expect([priv_p, re.compile(r'(?i)password\s*:\s*$'), any_p, pexpect.TIMEOUT, pexpect.EOF], timeout=35)
        if idx2 == 0:
            log("[+] Enable OK (#).")
            return
        if idx2 == 1:
            child.sendline("")
            child.expect(priv_p, timeout=35)
            log("[+] Enable OK (#).")
            return
        # Si vuelve any_p otra vez, verificamos si es #
        if idx2 == 2 and (child.after or "").strip().endswith("#"):
            log("[+] Enable OK (#).")
            return

        raise RuntimeError("No fue posible entrar a modo privilegiado (#) con enable.")

    if idx == 3:
        # Si no hubo salida, hacemos un último intento
        log("[WARN] No hubo salida tras enable (timeout). Enviando ENTER y reintentando...")
        child.sendline("")
        child.sendline("enable")
        idx3 = child.expect([priv_p, re.compile(r'(?i)password\s*:\s*$'), any_p, pexpect.TIMEOUT, pexpect.EOF], timeout=35)
        if idx3 == 0:
            log("[+] Enable OK (#).")
            return
        if idx3 == 1:
            child.sendline("")
            child.expect(priv_p, timeout=35)
            log("[+] Enable OK (#).")
            return
        if idx3 == 2 and (child.after or "").strip().endswith("#"):
            log("[+] Enable OK (#).")
            return
        raise RuntimeError("Timeout ejecutando enable (sin ver prompt #).")

    raise RuntimeError("EOF ejecutando enable.")


def handle_common_interactives(child, timeout=50):
    any_p = prompt_any()
    patterns = [
        any_p,                                                   # 0
        re.compile(r'(?i)\(y/n\)\??\s*$'),                        # 1
        re.compile(r'(?i)\([yY]/[nN]\)\??\s*$'),                  # 2
        re.compile(r'(?i)are you sure.*\?\s*$'),                  # 3
        re.compile(r'(?i)confirm\??\s*$'),                        # 4
        pexpect.TIMEOUT,                                          # 5
        pexpect.EOF                                               # 6
    ]

    for _ in range(10):
        idx = child.expect(patterns, timeout=timeout)
        if idx == 0:
            return True
        if idx in (1, 2, 3, 4):
            log("  ↳ Confirmación detectada, respondiendo 'y'")
            child.sendline("y")
            continue
        if idx == 5:
            return False
        if idx == 6:
            raise RuntimeError("EOF: sesión SSH terminó inesperadamente.")
    return False


def send_command_wait_prompt(child, cmd, timeout=220):
    log(f"[CMD] {cmd}")
    child.sendline(cmd)

    ok = handle_common_interactives(child, timeout=50)
    if ok:
        return True

    idx = child.expect([prompt_any(), pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx == 0:
        return True
    if idx == 1:
        raise RuntimeError(f"Timeout esperando prompt tras ejecutar: {cmd}")
    raise RuntimeError("EOF: la sesión terminó mientras se esperaba el prompt.")


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

        # Paso crítico
        enter_enable(child)

        # write memory
        log("[+] Guardando configuración: copy running-config startup-config")
        send_command_wait_prompt(child, "copy running-config startup-config", timeout=140)

        # backup
        log(f"[+] Enviando startup-config a TFTP {tftp_server} filename {backup_filename}")
        cmd_backup = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        send_command_wait_prompt(child, cmd_backup, timeout=260)

        log("[OK] Backup completado.")
        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")

        child.sendline("exit")
        try:
            child.expect(pexpect.EOF, timeout=10)
        except Exception:
            pass

        sys.exit(0)

    except Exception as e:
        log(f"[ERROR] {e}")
        if child is not None:
            try:
                log("[DEBUG] Última salida recibida:")
                log(child.before[-1400:] if child.before else "(vacío)")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()

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
    # TP-Link: HOST> o HOST#
    return re.compile(r'(?m)^[^\r\n]*[>#]\s*$')


def prompt_privileged():
    # TP-Link privilegiado: HOST#
    return re.compile(r'(?m)^[^\r\n]*#\s*$')


def login_ssh(host, user, password, port):
    ssh_cmd = (
        f"ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password "
        f"-o PubkeyAuthentication=no "
        f"-p {port} {user}@{host}"
    )

    log(f"[+] Conectando por SSH: {user}@{host}:{port}")
    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=25)
    child.delaybeforesend = 0.05

    # NO se modifica autenticación: mismos prompts
    patterns = [
        re.compile(r'(?i)are you sure you want to continue connecting'),  # 0
        re.compile(r'(?i)login as:\s*$'),                                 # 1
        re.compile(r'(?i)user(name)?\s*:\s*$'),                            # 2
        re.compile(r'(?i)password\s*:\s*$'),                               # 3
        prompt_any(),                                                     # 4
        pexpect.TIMEOUT,                                                  # 5
        pexpect.EOF                                                       # 6
    ]

    for _ in range(12):
        idx = child.expect(patterns, timeout=25)

        if idx == 0:
            child.sendline("yes")
            continue
        if idx == 1:
            child.sendline(user)
            continue
        if idx == 2:
            child.sendline(user)
            continue
        if idx == 3:
            child.sendline(password)
            continue
        if idx == 4:
            log("[+] Login OK, prompt detectado.")
            return child
        if idx == 5:
            raise RuntimeError("Timeout durante login (no apareció prompt/credenciales).")
        if idx == 6:
            raise RuntimeError("EOF durante login (conexión cerrada).")

    raise RuntimeError("No se logró llegar al prompt luego del login.")


def enter_enable(child):
    """
    TP-Link: ejecutar 'enable' + Enter (sin contraseña) para pasar de '>' a '#'.
    """
    any_prompt = prompt_any()
    priv_prompt = prompt_privileged()

    # Asegura prompt
    child.sendline("")
    child.expect(any_prompt, timeout=20)
    last = (child.after or "").strip()

    if last.endswith("#"):
        log("[+] Ya estás en modo privilegiado (#).")
        return

    log("[+] Ejecutando enable (sin contraseña) para pasar a # ...")
    child.sendline("enable")

    patterns = [
        priv_prompt,                                 # 0
        re.compile(r'(?i)password\s*:\s*$'),         # 1 (si llegara a pedir)
        any_prompt,                                  # 2 (se quedó en >)
        pexpect.TIMEOUT,                             # 3
        pexpect.EOF                                  # 4
    ]

    idx = child.expect(patterns, timeout=25)

    if idx == 0:
        log("[+] Enable OK (#).")
        return

    if idx == 1:
        # tu caso: sin contraseña -> ENTER vacío
        log("  ↳ Password en enable detectado, enviando ENTER vacío.")
        child.sendline("")
        child.expect(priv_prompt, timeout=25)
        log("[+] Enable OK (#).")
        return

    if idx == 2:
        # reintento 1 vez
        log("[WARN] No subió a # tras enable, reintentando una vez…")
        child.sendline("enable")
        idx2 = child.expect([priv_prompt, re.compile(r'(?i)password\s*:\s*$'), pexpect.TIMEOUT, pexpect.EOF], timeout=25)
        if idx2 == 0:
            log("[+] Enable OK (#).")
            return
        if idx2 == 1:
            child.sendline("")
            child.expect(priv_prompt, timeout=25)
            log("[+] Enable OK (#).")
            return
        raise RuntimeError("No fue posible entrar a modo privilegiado (#) con enable.")

    if idx == 3:
        raise RuntimeError("Timeout ejecutando enable.")
    raise RuntimeError("EOF ejecutando enable.")


def handle_common_interactives(child, timeout=40):
    """
    Responde confirmaciones comunes y vuelve al prompt.
    """
    any_prompt = prompt_any()
    patterns = [
        any_prompt,                                                   # 0
        re.compile(r'(?i)\(y/n\)\??\s*$'),                             # 1
        re.compile(r'(?i)\([yY]/[nN]\)\??\s*$'),                       # 2
        re.compile(r'(?i)are you sure.*\?\s*$'),                       # 3
        re.compile(r'(?i)confirm\??\s*$'),                             # 4
        pexpect.TIMEOUT,                                               # 5
        pexpect.EOF                                                    # 6
    ]

    for _ in range(6):
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


def send_command_wait_prompt(child, cmd, timeout=60):
    log(f"[CMD] {cmd}")
    child.sendline(cmd)

    ok = handle_common_interactives(child, timeout=min(timeout, 40))
    if ok:
        return True

    idx = child.expect([prompt_any(), pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx == 0:
        return True
    if idx == 1:
        raise RuntimeError(f"Timeout esperando prompt tras ejecutar: {cmd}")
    raise RuntimeError("EOF: la sesión terminó mientras se esperaba el prompt.")


def parse_host_ip(tag: str, fallback_ip: str):
    """
    Espera tag como: inventory_hostname__ansible_host
    Ej: CAMARAS-MANTA__192.168.10.5
    """
    raw = (tag or "").strip()
    if "__" in raw:
        h, ip = raw.split("__", 1)
        h = h.strip() or "HOST"
        ip = ip.strip() or fallback_ip
        return h, ip
    # si no viene con "__", usamos lo que tengamos
    return raw if raw else "HOST", fallback_ip


def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n"
            "  backup_tftp_tplink.py <host> <user> <pass> <port> <tftp_server> <inventory_hostname__ansible_host>\n",
            file=sys.stderr
        )
        sys.exit(2)

    host = sys.argv[1]          # ansible_host
    user = sys.argv[2]
    password = sys.argv[3]
    port = sys.argv[4]
    tftp_server = sys.argv[5]
    inv_tag = sys.argv[6]       # inventory_hostname__ansible_host

    hostname, ip = parse_host_ip(inv_tag, host)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # filename requerido: basado en hostname + ip (y timestamp para no pisar)
    backup_filename = sanitize_filename(f"{hostname}_{ip}_{ts}.cfg")

    child = None
    try:
        child = login_ssh(host, user, password, port)

        # IMPORTANTE: enable sin contraseña
        enter_enable(child)

        # Guardar config (write memory)
        log("[+] Guardando configuración: copy running-config startup-config")
        send_command_wait_prompt(child, "copy running-config startup-config", timeout=80)

        # Backup exacto TP-Link
        log(f"[+] Enviando startup-config a TFTP {tftp_server} filename {backup_filename}")
        cmd_backup = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        send_command_wait_prompt(child, cmd_backup, timeout=180)

        log("[OK] Backup completado (según retorno al prompt).")
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
                log(child.before[-1200:] if child.before else "(vacío)")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()

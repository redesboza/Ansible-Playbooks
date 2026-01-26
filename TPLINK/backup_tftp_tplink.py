#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import time
from datetime import datetime

# Netmiko (ya instalado en tu EE)
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Fallback Paramiko (viene como dependencia de Netmiko)
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


PROMPT_RE = re.compile(r"(?m)[^\r\n]*[>#]\s*$")  # prompt tolerante


def backup_ok(text: str) -> bool:
    return bool(re.search(r"(?i)backup.*ok", text or ""))


def has_error(text: str) -> bool:
    return bool(re.search(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error)", text or ""))


# -------------------------
# Fallback: Paramiko shell
# -------------------------
def p_read(shell, wait=0.4, max_loops=50):
    """Lee del canal paramiko sin bloquear."""
    data = ""
    for _ in range(max_loops):
        time.sleep(wait)
        while shell.recv_ready():
            data += shell.recv(65535).decode("utf-8", errors="ignore")
        if data:
            break
    return data


def p_send(shell, cmd, wait=0.4):
    shell.send(cmd + "\n")
    time.sleep(wait)
    return p_read(shell, wait=wait)


def p_wait_prompt(shell, timeout=25):
    """Asegura que aparece algún prompt >/# (en TP-Link a veces hay que mandar ENTER)."""
    end = time.time() + timeout
    buf = ""
    # manda enters hasta que haya prompt
    while time.time() < end:
        shell.send("\n")
        time.sleep(0.4)
        buf += p_read(shell, wait=0.2, max_loops=10)
        if PROMPT_RE.search(buf):
            return buf
    return buf  # devuelve lo último aunque no haya prompt


def run_paramiko(host, user, password, port, tftp_server, backup_filename):
    log("[*] Fallback: usando Paramiko (porque Netmiko no detectó prompt).")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    cli.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=40,
        banner_timeout=60,
        auth_timeout=60,
    )

    shell = cli.invoke_shell(width=200, height=60)
    time.sleep(0.8)
    _ = p_read(shell, wait=0.2, max_loops=20)  # limpia banners/logs

    # Forzar que aparezca prompt
    p_wait_prompt(shell, timeout=25)

    # enable (sin contraseña): enable + ENTER
    log("[+] enable (sin contraseña)")
    p_send(shell, "enable", wait=0.4)
    p_send(shell, "", wait=0.6)

    # Guardar config
    log("[+] copy running-config startup-config")
    out1 = p_send(shell, "copy running-config startup-config", wait=0.8)
    out1 += p_read(shell, wait=0.5, max_loops=30)
    if out1.strip():
        log("[OUT] " + out1.strip().replace("\r", ""))
    if has_error(out1):
        raise RuntimeError("Error ejecutando: copy running-config startup-config")

    # Backup TFTP
    cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
    log("[+] " + cmd_bkp)
    p_send(shell, cmd_bkp, wait=0.8)

    # Esperar mensaje OK (tu evidencia real)
    buf = ""
    end = time.time() + 180
    while time.time() < end:
        buf += p_read(shell, wait=0.6, max_loops=10)
        if buf:
            # imprimir incremental (opcional)
            pass
        if backup_ok(buf):
            break
        if has_error(buf):
            break

    if buf.strip():
        log("[OUT] " + buf.strip().replace("\r", ""))

    if has_error(buf):
        raise RuntimeError("Error ejecutando backup a TFTP")
    if not backup_ok(buf):
        log("[WARN] No vi 'Backup ... OK' explícito. Si el TFTP recibió el archivo, está OK.")

    cli.close()


# -------------------------
# Netmiko main
# -------------------------
def run_netmiko(host, user, password, port, tftp_server, backup_filename):
    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": user,
        "password": password,
        "port": port,
        "secret": "",
        "fast_cli": False,
        "conn_timeout": 60,
        "banner_timeout": 60,
        "auth_timeout": 60,
        "global_delay_factor": 2,
    }

    log(f"[+] Conectando por SSH (Netmiko): {user}@{host}:{port}")
    conn = ConnectHandler(**device)  # <-- aquí es donde te está fallando
    log("[+] Login OK.")

    # Forzar prompt (a veces hay que dar ENTER)
    conn.write_channel("\n")
    time.sleep(0.4)
    _ = conn.read_channel()

    # enable sin contraseña
    conn.write_channel("enable\n")
    time.sleep(0.4)
    conn.write_channel("\n")
    time.sleep(0.6)
    _ = conn.read_channel()

    # Guardar config (tolerante)
    out1 = conn.send_command_timing("copy running-config startup-config", strip_prompt=False, strip_command=False)
    if out1.strip():
        log("[OUT] " + out1.strip())
    if has_error(out1):
        raise RuntimeError("Error ejecutando: copy running-config startup-config")

    # Backup
    cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
    out2 = conn.send_command_timing(cmd_bkp, strip_prompt=False, strip_command=False, max_loops=400)
    if out2.strip():
        log("[OUT] " + out2.strip())
    if has_error(out2):
        raise RuntimeError("Error ejecutando backup a TFTP")

    if not backup_ok(out2):
        log("[WARN] No vi 'Backup ... OK' explícito. Si el TFTP recibió el archivo, está OK.")

    conn.disconnect()


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
    backup_filename = sanitize_filename(f"{hostname}_{ip}_{ts}.cfg")

    try:
        # 1) Intentar Netmiko
        run_netmiko(host, user, password, port, tftp_server, backup_filename)
        log("[OK] Terminado con Netmiko.")
        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")
        sys.exit(0)

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        log(f"[WARN] Netmiko conexión/autenticación: {e}")
        # si es auth real, no sirve reintentar con paramiko (pero lo intentamos igual si quieres)
        try:
            run_paramiko(host, user, password, port, tftp_server, backup_filename)
            log("[OK] Terminado con Paramiko.")
            log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")
            sys.exit(0)
        except Exception as e2:
            log(f"[ERROR] Fallback Paramiko falló: {e2}")
            sys.exit(1)

    except Exception as e:
        # Este es tu caso: Pattern not detected (#|>)
        msg = str(e) or ""
        log(f"[WARN] Netmiko falló: {msg}")

        try:
            run_paramiko(host, user, password, port, tftp_server, backup_filename)
            log("[OK] Terminado con Paramiko.")
            log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")
            sys.exit(0)
        except Exception as e2:
            log(f"[ERROR] Fallback Paramiko falló: {e2}")
            sys.exit(1)


if __name__ == "__main__":
    main()

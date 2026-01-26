#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import time
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


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


# Prompt MUY tolerante: cualquier cosa que termine en ">" o "#"
PROMPT_PATTERN = r"(?m)[^\r\n]*[>#]\s*$"


def flush_channel(conn, seconds=1.0):
    """Limpia banners/logs iniciales que rompen detección de prompt."""
    end = time.time() + seconds
    data = ""
    while time.time() < end:
        chunk = conn.read_channel()
        if chunk:
            data += chunk
        time.sleep(0.1)
    return data


def send_timing(conn, cmd, delay=0.3):
    """Envia comando sin depender del prompt automático."""
    conn.write_channel(cmd + "\n")
    time.sleep(delay)
    return conn.read_channel() or ""


def ensure_enable(conn):
    """
    enable sin contraseña:
      enable
      <ENTER>
    No asumimos que el prompt se reimprime.
    """
    log("[+] Enviando enable (sin contraseña)...")
    send_timing(conn, "enable", delay=0.4)
    out = send_timing(conn, "", delay=0.6)
    # a veces requiere otro enter
    out += send_timing(conn, "", delay=0.4)
    return out


def run_cmd_wait_prompt(conn, cmd, read_timeout=120):
    """
    Ejecuta comando y espera a ver algo que parezca prompt (>,#) usando pattern flexible.
    También tolera que TP-Link imprima logs durante la ejecución.
    """
    log(f"[CMD] {cmd}")
    out = conn.send_command(
        cmd,
        expect_string=PROMPT_PATTERN,
        read_timeout=read_timeout,
        strip_prompt=False,
        strip_command=False,
        cmd_verify=False,   # importante en equipos que "ecoan" raro
    )
    return (out or "").strip()


def backup_ok(text: str) -> bool:
    return bool(re.search(r"(?i)backup.*ok", text or "")) or bool(re.search(r"(?i)backup user config file ok", text or ""))


def has_error(text: str) -> bool:
    return bool(re.search(r"(?i)(denied|insufficient|not allowed|invalid|unrecognized|error)", text or ""))


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

    # Session log para depurar (AWX lo imprime si lo catéas al final; aquí solo lo guardamos)
    session_log = f"/tmp/netmiko_{sanitize_filename(hostname)}_{sanitize_filename(ip)}.log"

    device = {
        "device_type": "cisco_ios",  # funciona bien para prompt/enable genérico
        "host": host,
        "username": user,
        "password": password,
        "port": port,
        "secret": "",                 # enable sin contraseña
        "fast_cli": False,
        "global_delay_factor": 2,
        "conn_timeout": 60,
        "banner_timeout": 60,
        "auth_timeout": 60,
        "session_log": session_log,
    }

    conn = None
    try:
        log(f"[+] Conectando por SSH (Netmiko): {user}@{host}:{port}")
        conn = ConnectHandler(**device)

        # Limpiar banners/logs
        flush_data = flush_channel(conn, seconds=1.2)
        if flush_data.strip():
            log("[INFO] Limpieza inicial (banners/logs detectados).")

        # Garantizar que estamos en CLI: mandar ENTER y esperar prompt flexible
        conn.write_channel("\n")
        conn.read_until_pattern(pattern=PROMPT_PATTERN, read_timeout=30)

        # enable sin password
        ensure_enable(conn)

        # Asegurar prompt luego de enable (sin confiar en automático)
        conn.write_channel("\n")
        conn.read_until_pattern(pattern=PROMPT_PATTERN, read_timeout=30)

        # 1) Guardar config
        out1 = run_cmd_wait_prompt(conn, "copy running-config startup-config", read_timeout=120)
        if out1:
            log(f"[OUT] {out1}")
        if has_error(out1):
            raise RuntimeError("Error ejecutando: copy running-config startup-config")

        # 2) Backup a TFTP (comando exacto)
        cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        out2 = run_cmd_wait_prompt(conn, cmd_bkp, read_timeout=240)
        if out2:
            log(f"[OUT] {out2}")
        if has_error(out2):
            raise RuntimeError("Error ejecutando backup a TFTP")

        if backup_ok(out2):
            log("[OK] Backup completado (confirmado por 'Backup ... OK').")
        else:
            log("[WARN] No vi 'Backup ... OK' explícito. Si el TFTP recibió el archivo, está OK.")

        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")
        log(f"[INFO] session_log: {session_log}")

        try:
            conn.disconnect()
        except Exception:
            pass

        sys.exit(0)

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        log(f"[ERROR] Netmiko conexión/autenticación: {e}")
        log("[TIP] Si sigue fallando por prompt, revisa el session_log en /tmp dentro del EE.")
        sys.exit(1)
    except Exception as e:
        log(f"[ERROR] {e}")
        sys.exit(1)
    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()

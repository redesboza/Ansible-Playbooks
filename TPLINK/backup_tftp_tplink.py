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


def is_privileged(prompt: str) -> bool:
    return (prompt or "").strip().endswith("#")


def ensure_enable(conn) -> str:
    """
    TP-Link: entra en '>' y con enable + ENTER (sin contraseña) pasa a '#'.
    En algunos equipos no re-imprime prompt rápido, por eso usamos timing.
    """
    prompt = conn.find_prompt()
    log(f"[INFO] Prompt inicial: {prompt.strip()}")

    if is_privileged(prompt):
        return prompt

    log("[+] Enviando enable (sin contraseña)...")
    out = conn.send_command_timing("enable", strip_prompt=False, strip_command=False)
    # Si pide password, enviamos ENTER vacío
    if re.search(r"(?i)password", out or ""):
        out2 = conn.send_command_timing("", strip_prompt=False, strip_command=False)
        out = (out or "") + "\n" + (out2 or "")
    else:
        # muchos TP-Link requieren un ENTER adicional aunque no pidan nada
        conn.send_command_timing("", strip_prompt=False, strip_command=False)

    # Reintento de prompt
    try:
        prompt = conn.find_prompt()
    except Exception:
        prompt = ""

    if is_privileged(prompt):
        log(f"[INFO] Prompt tras enable: {prompt.strip()}")
        return prompt

    # Último intento suave
    conn.send_command_timing("enable", strip_prompt=False, strip_command=False)
    conn.send_command_timing("", strip_prompt=False, strip_command=False)
    try:
        prompt = conn.find_prompt()
    except Exception:
        prompt = ""

    log(f"[INFO] Prompt tras enable (2do intento): {prompt.strip()}")
    return prompt


def run_cmd_timing(conn, cmd: str, timeout_loops=300, delay_factor=2) -> str:
    """
    Ejecuta comando tolerando CLIs que no reimprimen prompt.
    Además responde confirmaciones comunes.
    """
    log(f"[CMD] {cmd}")
    out = conn.send_command_timing(
        cmd,
        strip_prompt=False,
        strip_command=False,
        delay_factor=delay_factor,
        max_loops=timeout_loops,
    ) or ""

    # Confirmaciones típicas
    if re.search(r"(?i)\(y/n\)", out) or re.search(r"(?i)confirm", out) or re.search(r"(?i)are you sure", out):
        out2 = conn.send_command_timing("y", strip_prompt=False, strip_command=False) or ""
        out = out + "\n" + out2

    # Si pide "filename" o algo similar (por si acaso)
    if re.search(r"(?i)filename", out) and "tftp" in cmd.lower():
        # ya enviamos filename en el comando, pero por seguridad mandamos ENTER
        out2 = conn.send_command_timing("", strip_prompt=False, strip_command=False) or ""
        out = out + "\n" + out2

    return out.strip()


def has_error(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"(?i)(denied|insufficient|not allowed|invalid input|unrecognized|error)", text))


def backup_ok(text: str) -> bool:
    if not text:
        return False
    # Basado en tu salida real: "Backup user config file OK."
    return bool(re.search(r"(?i)backup.*ok", text)) or bool(re.search(r"(?i)backup user config file ok", text))


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

    # TP-Link no siempre está en device_type de netmiko, el más estable aquí es cisco_ios (para prompt/enable)
    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": user,
        "password": password,
        "port": port,
        "secret": "",        # enable sin contraseña
        "fast_cli": False,
        "conn_timeout": 40,
        "banner_timeout": 60,
        "auth_timeout": 40,
    }

    conn = None
    try:
        log(f"[+] Conectando por SSH (Netmiko): {user}@{host}:{port}")
        conn = ConnectHandler(**device)
        log("[+] Login OK.")

        prompt = ensure_enable(conn)
        if not is_privileged(prompt):
            log("[WARN] No pude confirmar '#', pero continúo (algunos TP-Link no reimprimen prompt).")

        # 1) Guardar config
        out1 = run_cmd_timing(conn, "copy running-config startup-config", timeout_loops=250, delay_factor=2)
        if out1:
            log(f"[OUT] {out1}")
        if has_error(out1):
            raise RuntimeError("Error ejecutando: copy running-config startup-config")

        # 2) Backup a TFTP (comando exacto)
        cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
        out2 = run_cmd_timing(conn, cmd_bkp, timeout_loops=400, delay_factor=3)
        if out2:
            log(f"[OUT] {out2}")
        if has_error(out2):
            raise RuntimeError("Error ejecutando backup a TFTP")

        # Confirmación por texto OK (tu evidencia real)
        if not backup_ok(out2):
            # algunos equipos no imprimen mucho, damos un pequeño margen
            time.sleep(1)
            # no hacemos show porque puede variar; solo avisamos warning
            log("[WARN] No vi 'Backup ... OK' explícito. Si el TFTP recibió el archivo, está OK.")

        log("[OK] Proceso terminado.")
        log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")

        try:
            conn.disconnect()
        except Exception:
            pass

        sys.exit(0)

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        log(f"[ERROR] Netmiko conexión/autenticación: {e}")
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetmikoTimeoutException, NetmikoAuthenticationException


def log(msg: str):
    print(msg, flush=True)


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


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
        return (m.group(1).strip() or "HOST", m.group(2).strip() or fallback_ip)

    return (raw if raw else "HOST", fallback_ip)


def ensure_enable(conn) -> str:
    """
    En TP-Link: entra en '>' y con enable (sin contraseña) sube a '#'.
    Netmiko enable() manda enable y luego secret (aquí vacío -> Enter).
    """
    prompt = conn.find_prompt()
    if prompt.strip().endswith("#"):
        return prompt

    # Si está en '>' intentamos enable sin secret
    try:
        conn.enable()  # secret = "" (definido en el handler)
    except Exception:
        # fallback manual (por si el device_type no usa enable() bien)
        conn.write_channel("enable\n")
        conn.write_channel("\n")

    # Re-chequear prompt
    prompt = conn.find_prompt()
    if not prompt.strip().endswith("#"):
        # 2do intento, timing
        conn.write_channel("enable\n")
        conn.write_channel("\n")
        prompt = conn.find_prompt()

    return prompt


def run_cmd(conn, cmd: str, expect_prompt=True, delay_factor=2):
    """
    Usa send_command_timing para tolerar equipos que no reimprimen prompt rápido.
    """
    out = conn.send_command_timing(
        cmd,
        strip_prompt=False,
        strip_command=False,
        delay_factor=delay_factor,
        max_loops=300,
    )
    if expect_prompt:
        # Forzar lectura de prompt al final (si aplica)
        try:
            _ = conn.find_prompt()
        except Exception:
            pass
    return out or ""


def main():
    if len(sys.argv) < 7:
        print(
            "Uso:\n"
            "  backup_tftp_tplink.py <host> <user> <pass> <port> <tftp_server> <inventory_tag>\n"
            "Ej:\n"
            "  backup_tftp_tplink.py 172.16.45.46 ansible 'Pass' 11110 192.168.57.11 CAMARAS-MANTA_172.16.45.46\n",
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

    # Netmiko device_type:
    # En muchos entornos TP-Link funciona bien con un "base" tipo cisco para prompt/enable.
    # Intentamos primero tipo TP-Link (si está disponible), y si falla, fallback a cisco_ios.
    candidates = ["tp_link_jetstream", "tplink_jetstream", "cisco_ios"]

    last_err = None

    for dtype in candidates:
        try:
            log(f"[+] Conectando por SSH (Netmiko) {user}@{host}:{port} device_type={dtype}")

            conn = ConnectHandler(
                device_type=dtype,
                host=host,
                username=user,
                password=password,
                port=port,
                secret="",                 # enable sin contraseña -> Enter
                fast_cli=False,            # más estable en switches “lentos”
                banner_timeout=60,
                auth_timeout=40,
                conn_timeout=40,
                session_log=None,
            )

            log("[+] Login OK.")
            prompt_before = conn.find_prompt()
            log(f"[INFO] Prompt inicial: {prompt_before.strip()}")

            prompt_after = ensure_enable(conn)
            log(f"[INFO] Prompt tras enable: {prompt_after.strip()}")

            if not prompt_after.strip().endswith("#"):
                log("[WARN] No pude confirmar #, pero continuaré con los comandos (TP-Link a veces no reimprime).")

            # 1) Write memory equivalente
            cmd_save = "copy running-config startup-config"
            log(f"[CMD] {cmd_save}")
            out1 = run_cmd(conn, cmd_save, delay_factor=2)
            if out1.strip():
                log(f"[OUT] {out1.strip()}")

            # 2) Backup startup-config a TFTP (comando exacto validado)
            cmd_bkp = f"copy startup-config tftp ip-address {tftp_server} filename {backup_filename}"
            log(f"[CMD] {cmd_bkp}")
            out2 = run_cmd(conn, cmd_bkp, delay_factor=3)
            if out2.strip():
                log(f"[OUT] {out2.strip()}")

            # Validación suave: TP-Link típicamente devuelve “Backup ... OK”
            combined = (out1 + "\n" + out2).lower()
            if ("backup" in combined and "ok" in combined) or ("start to backup" in combined) or ("ok" in combined):
                log("[OK] Backup completado (según salida del equipo).")
            else:
                # no siempre imprime mucho; si no hay error explícito, igual lo dejamos pasar
                if any(x in combined for x in ["denied", "insufficient", "invalid", "error", "unrecognized", "not allowed"]):
                    raise RuntimeError("El equipo devolvió un error al ejecutar los comandos.")
                log("[OK] Backup ejecutado (sin error explícito).")

            log(f"[INFO] Archivo esperado en TFTP: {backup_filename}")
            try:
                conn.disconnect()
            except Exception:
                pass

            sys.exit(0)

        except (NetmikoTimeoutException, NetmikoAuthenticationException, RuntimeError) as e:
            last_err = e
            log(f"[WARN] Falló con device_type={dtype}: {e}")
            continue
        except Exception as e:
            last_err = e
            log(f"[WARN] Error inesperado con device_type={dtype}: {e}")
            continue

    log(f"[ERROR] No se pudo completar con ningún device_type. Último error: {last_err}")
    sys.exit(1)


if __name__ == "__main__":
    main()

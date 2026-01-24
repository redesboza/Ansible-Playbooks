#!/usr/bin/env python3
import sys
import socket
import time
import re
from datetime import datetime

import paramiko

"""
TP-Link - Backup startup-config to TFTP vía Paramiko (sin depender de /usr/bin/ssh)

Uso:
  python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>
"""

if len(sys.argv) != 7:
    print("❌ Uso: python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>")
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = int(sys.argv[4])
tftp_server  = sys.argv[5]
basename     = sys.argv[6]

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"{basename}_{ts}.cfg"

def clean(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", s)

def tcp_precheck(ip, p, timeout=5):
    try:
        sock = socket.create_connection((ip, p), timeout=timeout)
        sock.close()
        return True, ""
    except Exception as e:
        return False, str(e)

def read_channel(chan, wait=0.3, max_reads=20):
    """Lee output del canal por un rato."""
    out = ""
    for _ in range(max_reads):
        time.sleep(wait)
        while chan.recv_ready():
            out += chan.recv(65535).decode("utf-8", errors="ignore")
    return out

def send_and_wait(chan, cmd, expect_regex=None, timeout=20, send_newline=True):
    """Envía comando y espera regex (si se define)."""
    if send_newline:
        chan.send(cmd + "\n")
    else:
        chan.send(cmd)

    buf = ""
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(0.2)
        while chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", errors="ignore")

        if expect_regex and re.search(expect_regex, buf, re.M):
            return buf
        # si no hay regex, devolvemos algo de salida luego de un rato
        if not expect_regex and len(buf) > 0:
            return buf

    return buf  # timeout

print(f"🔎 Precheck TCP {host}:{port} ...")
ok, err = tcp_precheck(host, port)
if not ok:
    print(f"❌ No puedo abrir TCP a {host}:{port} desde AWX/EE. Causa: {err}")
    sys.exit(1)
print("✅ Puerto accesible desde el Execution Environment.")

print(f"🔐 Conectando por SSH v2 (Paramiko) a {host}:{port} como {ssh_user}...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # ✅ Forzar KEX compatibles con el switch (según lo que oferta)
    # Their offer: group1-sha1, group14-sha256, group16-sha512
    # Usamos primero group14-sha256, luego group16-sha512, y al final group1-sha1 como último recurso.
    sec_opts = paramiko.Transport((host, port))
    sec_opts.connect(username=ssh_user, password=ssh_password)

    # Nota: Transport ya conectado, pero queremos controlar KEX:
    # Paramiko permite modificar security_options ANTES de start_client en algunos casos.
    # Como ya conectó, si quieres 100% control, hacemos conexión manual:
    sec_opts.close()

    sock = socket.create_connection((host, port), timeout=8)
    transport = paramiko.Transport(sock)
    so = transport.get_security_options()
    so.kex = [
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group1-sha1",
    ]
    # hostkey típicas
    so.key_types = ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]

    transport.start_client(timeout=12)
    transport.auth_password(username=ssh_user, password=ssh_password, timeout=12)

    chan = transport.open_session()
    chan.get_pty(width=200, height=50)
    chan.invoke_shell()

    # estabilizar prompt (banners, etc.)
    chan.send("\n")
    out = read_channel(chan, wait=0.3, max_reads=15)

    # Si pide "Press any key/Enter"
    if re.search(r"Press any key|Press Enter|continue", out, re.I):
        chan.send("\n")
        out += read_channel(chan, wait=0.3, max_reads=10)

    # Intentar detectar prompt
    # TPLink suele terminar en ">" o "#"
    if not re.search(r"[>#\]]\s*$", out, re.M):
        # forzar prompt
        chan.send("\n")
        out += read_channel(chan, wait=0.3, max_reads=10)

    # ---- enable si no hay # ----
    if not re.search(r"#\s*$", out, re.M):
        chan.send("enable\n")
        out2 = read_channel(chan, wait=0.3, max_reads=10)
        if re.search(r"[Pp]assword", out2):
            chan.send(ssh_password + "\n")
            out2 += read_channel(chan, wait=0.3, max_reads=10)
        out += out2

    # paginación off
    chan.send("terminal length 0\n")
    out += read_channel(chan, wait=0.2, max_reads=8)

    # ---- comando backup ----
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    chan.send(cmd + "\n")

    buf = ""
    t0 = time.time()
    done = False
    while time.time() - t0 < 120:  # hasta 2 min por el tftp
        time.sleep(0.25)
        while chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", errors="ignore")

        # confirmaciones típicas
        if re.search(r"\(Y/N\)|\[Y/N\]|confirm|Are you sure", buf, re.I):
            chan.send("Y\n")
            buf = ""
            continue

        if re.search(r"Destination filename|filename", buf, re.I):
            chan.send(filename + "\n")
            buf = ""
            continue

        if re.search(r"Remote host|ip-address|Address or name of remote host", buf, re.I):
            chan.send(tftp_server + "\n")
            buf = ""
            continue

        # fin por prompt
        if re.search(r"[>#\]]\s*$", buf, re.M):
            done = True
            break

        # errores
        if re.search(r"%\s*Error|Error:|Invalid|Failed|Timed out|TFTP", buf, re.I):
            print("❌ Error reportado por el switch durante copy:")
            print(clean(buf))
            transport.close()
            sys.exit(1)

    if done:
        print("✅ Backup finalizado (regresó a prompt).")
    else:
        print("⚠️ No confirmé fin del copy (no volvió al prompt). Revisa TFTP y conectividad.")
        print("📌 Última salida:")
        print(clean(buf))

    # salir
    try:
        chan.send("exit\n")
        time.sleep(0.3)
    except Exception:
        pass

    transport.close()
    sys.exit(0)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link (Paramiko): {e}")
    sys.exit(1)

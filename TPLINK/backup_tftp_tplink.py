#!/usr/bin/env python3
import sys
import socket
import time
import re
from datetime import datetime

import paramiko

"""
TP-Link (JetStream/Omada) - Backup startup-config a TFTP vía Paramiko
(no depende de /usr/bin/ssh del EE)

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

def read_until(chan, patterns, timeout=20):
    """
    Lee del canal hasta que aparezca alguno de los regex en patterns o timeout.
    Retorna: (matched_index o -1, buffer)
    """
    buf = ""
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(0.2)
        while chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", errors="ignore")

        for idx, pat in enumerate(patterns):
            if re.search(pat, buf, re.M | re.I):
                return idx, buf
    return -1, buf

def send_and_read(chan, cmd, wait=0.2, reads=10):
    chan.send(cmd + "\n")
    buf = ""
    for _ in range(reads):
        time.sleep(wait)
        while chan.recv_ready():
            buf += chan.recv(65535).decode("utf-8", errors="ignore")
    return buf

# Prompts comunes
PROMPT_REGEX = [
    r"#\s*$",
    r">\s*$",
    r"\]\s*$",
    r"\S+#\s*$",
    r"\S+>\s*$",
    r"\S+\]\s*$",
]

print(f"🔎 Precheck TCP {host}:{port} ...")
ok, err = tcp_precheck(host, port)
if not ok:
    print(f"❌ No puedo abrir TCP a {host}:{port} desde AWX/EE. Causa: {err}")
    sys.exit(1)
print("✅ Puerto accesible desde el Execution Environment.")

print(f"🔐 Conectando por SSH v2 (Paramiko) a {host}:{port} como {ssh_user}...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

try:
    # Socket con timeout (controla cuelgues)
    sock = socket.create_connection((host, port), timeout=10)

    transport = paramiko.Transport(sock)

    # Forzar KEX según lo que ofrece tu TP-Link (visto en el error)
    so = transport.get_security_options()
    so.kex = [
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group1-sha1",
    ]
    so.key_types = ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]

    transport.start_client(timeout=12)

    # ✅ IMPORTANTE: tu paramiko no acepta timeout= en auth_password()
    transport.auth_password(username=ssh_user, password=ssh_password)

    # Shell interactivo
    chan = transport.open_session()
    chan.get_pty(width=200, height=50)
    chan.invoke_shell()

    # Asentar sesión (banners / enter / paginación)
    chan.send("\n")
    _, buf = read_until(chan, PROMPT_REGEX + [r"Press any key", r"Press Enter", r"--More--"], timeout=12)

    if re.search(r"Press any key|Press Enter", buf, re.I):
        chan.send("\n")
        _, buf2 = read_until(chan, PROMPT_REGEX + [r"--More--"], timeout=12)
        buf += buf2

    if re.search(r"--More--", buf, re.I):
        chan.send(" ")
        _, buf2 = read_until(chan, PROMPT_REGEX, timeout=12)
        buf += buf2

    # Asegurar prompt
    idx, buf3 = read_until(chan, PROMPT_REGEX, timeout=12)
    if idx == -1:
        chan.send("\n")
        idx, buf3 = read_until(chan, PROMPT_REGEX, timeout=12)
    buf += buf3

    if idx == -1:
        print("❌ No pude estabilizar el prompt luego de autenticar.")
        print("📌 Salida recibida:")
        print(clean(buf))
        transport.close()
        sys.exit(1)

    # Enable si no hay '#'
    if not re.search(r"#\s*$", buf, re.M):
        chan.send("enable\n")
        k, out = read_until(chan, [r"[Pp]assword", r"#\s*$"] + PROMPT_REGEX, timeout=10)

        if re.search(r"[Pp]assword", out):
            chan.send(ssh_password + "\n")
            _, out2 = read_until(chan, PROMPT_REGEX, timeout=12)
            out += out2

        buf += out

    # Desactivar paginación (si aplica)
    send_and_read(chan, "terminal length 0", reads=6)

    # Ejecutar backup
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    chan.send(cmd + "\n")

    # Esperar confirmaciones / prompt final
    final_buf = ""
    t0 = time.time()
    while time.time() - t0 < 150:  # 2.5 min por si TFTP demora
        time.sleep(0.25)
        while chan.recv_ready():
            final_buf += chan.recv(65535).decode("utf-8", errors="ignore")

        # Confirmaciones típicas
        if re.search(r"\(Y/N\)|\[Y/N\]|confirm|Are you sure", final_buf, re.I):
            chan.send("Y\n")
            final_buf = ""
            continue

        if re.search(r"Destination filename.*:\s*$", final_buf, re.I | re.M):
            chan.send(filename + "\n")
            final_buf = ""
            continue

        if re.search(r"Remote host.*:\s*$|Address or name of remote host.*:\s*$", final_buf, re.I | re.M):
            chan.send(tftp_server + "\n")
            final_buf = ""
            continue

        # Errores
        if re.search(r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP", final_buf, re.I):
            print("❌ Error reportado por el switch durante copy:")
            print(clean(final_buf))
            transport.close()
            sys.exit(1)

        # Terminó si vuelve a prompt
        if re.search(r"[>#\]]\s*$", final_buf, re.M):
            print("✅ Backup finalizado (regresó a prompt).")
            break
    else:
        print("⚠️ No confirmé fin del copy (no volvió al prompt).")
        print("📌 Última salida:")
        print(clean(final_buf))

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

#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
import time
from datetime import datetime

VERSION = "TPLINK_BACKUP_TFTP_v2026-01-26_01"

if len(sys.argv) != 7:
    print("❌ Uso: python3 backup_tftp_tplink.py <host> <ssh_user> <ssh_password> <port> <tftp_server> <backup_basename>", flush=True)
    sys.exit(1)

host         = sys.argv[1]
ssh_user     = sys.argv[2]
ssh_password = sys.argv[3]
port         = sys.argv[4]
tftp_server  = sys.argv[5]
basename     = sys.argv[6]

ts = datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"{basename}_{ts}.cfg"

def tcp_ok(ip, p):
    try:
        s = socket.create_connection((ip, int(p)), timeout=5)
        s.close()
        return True
    except:
        return False

def clean(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", s)

PROMPTS = [
    r"#\s*$",
    r">\s*$",
    r"\]\s*$",
]

LOGIN_PATTERNS = [
    r"Are you sure you want to continue connecting \(yes/no\)\?",
    r"login as:",
    r"User Name:",
    r"Username:",
    r"[Pp]assword:\s*$",
    r"Press any key.*",
    r"--More--",
] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF]

print(f"🧩 Script: {VERSION}", flush=True)
print(f"🔎 Precheck TCP {host}:{port} ...", flush=True)
if not tcp_ok(host, port):
    print(f"❌ No hay conectividad TCP desde el EE hacia {host}:{port}", flush=True)
    sys.exit(1)
print("✅ Puerto accesible desde el Execution Environment.", flush=True)

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...", flush=True)
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}", flush=True)

# ✅ MISMA autenticación que ya te funcionó (NO la cambio)
ssh_cmd = (
    f"ssh -tt "
    f"-o StrictHostKeyChecking=no "
    f"-o UserKnownHostsFile=/dev/null "
    f"-o PreferredAuthentications=password,keyboard-interactive "
    f"-o PubkeyAuthentication=no "
    f"-o HostKeyAlgorithms=ssh-rsa "
    f"-o KexAlgorithms=diffie-hellman-group14-sha256 "
    f"-p {port} {ssh_user}@{host}"
)

child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=25)
child.delaybeforesend = 0.05

try:
    # 🔥 Muchos TP-Link no muestran nada hasta ENTER
    time.sleep(0.2)
    child.sendline("")

    # ---- LOGIN LOOP ----
    while True:
        i = child.expect(LOGIN_PATTERNS, timeout=25)

        if i == 0:
            child.sendline("yes")
        elif i in (1, 2, 3):
            child.sendline(ssh_user)
        elif i == 4:
            child.sendline(ssh_password)
        elif i == 5:
            child.sendline("")
        elif i == 6:
            child.send(" ")
        elif i in (7, 8, 9):
            # prompt encontrado
            break
        elif i == 10:
            # TIMEOUT: re-intenta “despertar” CLI
            child.sendline("")
            continue
        else:
            print("❌ EOF durante login. Salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)

    # refrescar prompt (por banners)
    child.sendline("")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=10)

    # Intento apagar logs en pantalla (si el comando existe)
    child.sendline("terminal no monitor")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=5)

    # ---- ENABLE (si aplica) ----
    # Si no está en '#', intento enable (misma clave como en tus ciscos)
    if not re.search(r"#\s*$", child.after or ""):
        child.sendline("enable")
        k = child.expect([r"[Pp]assword:\s*$"] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        if k == 0:
            child.sendline(ssh_password)
            child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=15)

    # quitar paginación
    child.sendline("terminal length 0")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=8)

    # ---- COPY ----
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}", flush=True)
    child.sendline(cmd)

    copy_patterns = [
        r"\(Y/N\)|\[Y/N\]|\(y/n\)|\[y/n\]|confirm|Are you sure",
        r"Destination filename.*:\s*$",
        r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
        r"TFTP.*server.*:\s*$|Server IP.*:\s*$",
        r"Press any key.*|Press Enter.*",
        r"--More--",
        r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
    ] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF]

    t0 = time.time()
    while time.time() - t0 < 120:
        j = child.expect(copy_patterns, timeout=10)

        # volvió a prompt => OK
        if j >= 7 and j <= 9:
            print("✅ Backup finalizado (regresó a prompt).", flush=True)
            child.sendline("exit")
            child.close()
            sys.exit(0)

        if j == 0:
            child.sendline("Y")
        elif j == 1:
            child.sendline(filename)
        elif j == 2:
            child.sendline(tftp_server)
        elif j == 3:
            child.sendline(tftp_server)
        elif j == 4:
            child.sendline("")
        elif j == 5:
            child.send(" ")
        elif j == 6:
            print("❌ El equipo reportó error durante el copy:", flush=True)
            print(clean(child.before), flush=True)
            child.close(force=True)
            sys.exit(1)
        elif j == 11:
            print("❌ EOF durante copy. Última salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)
        # TIMEOUT => sigue esperando

    print("❌ Timeout general ejecutando copy (120s). Última salida:", flush=True)
    print(clean(child.before), flush=True)
    child.close(force=True)
    sys.exit(1)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link: {e}", flush=True)
    try:
        child.close(force=True)
    except:
        pass
    sys.exit(1)

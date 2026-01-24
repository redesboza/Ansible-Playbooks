#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
from datetime import datetime

"""
TP-Link (JetStream/Omada) - Backup startup-config a TFTP

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

print(f"🔎 Precheck TCP {host}:{port} ...")
try:
    sock = socket.create_connection((host, port), timeout=5)
    sock.close()
    print("✅ Puerto accesible desde el Execution Environment.")
except Exception as e:
    print(f"❌ No puedo abrir TCP a {host}:{port} desde AWX/EE. Causa: {e}")
    sys.exit(1)

print(f"🔐 Conectando por SSH v2 a {host}:{port} como {ssh_user}...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

# KEX correcto según lo que ofrece el switch
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

child = pexpect.spawn(ssh_cmd, timeout=35, encoding="utf-8")

PROMPT_PATTERNS = [r"#\s*$", r">\s*$", r"\]\s*$"]  # '#', '>', ']' (TP-Link)

def expect_prompt(timeout=25):
    child.timeout = timeout
    return child.expect(PROMPT_PATTERNS)

def is_privileged(idx: int) -> bool:
    return idx == 0  # '#'

try:
    # ---- LOGIN ----
    while True:
        i = child.expect([
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"login as:",
            r"User Name:",
            r"Username:",
            r"User:",
            r"[Pp]assword:\s*$",                       # Password:
            r".*'s password:\s*$",                     # ansible@ip's password:
            r"Permission denied",
            r"Unable to negotiate.*no matching key exchange method found",
            r"no matching host key type found",
            r"no matching cipher found",
            r"no matching MAC found",
            r"Connection refused",
            r"No route to host",
            r"Connection timed out",
            r"Connection closed",
            r"Could not resolve hostname",
            r"--More--",
            r"Press any key to continue",
            r"#\s*$",
            r">\s*$",
            r"\]\s*$",
            pexpect.EOF,
            pexpect.TIMEOUT,
        ])

        if i == 0:
            child.sendline("yes")
        elif i in (1, 2, 3, 4):
            child.sendline(ssh_user)
        elif i in (5, 6):
            child.sendline(ssh_password)
        elif i == 7:
            print("❌ Permission denied (usuario/clave incorrectos o AAA).")
            print(clean(child.before))
            sys.exit(1)
        elif i in (8, 9, 10, 11):
            print("❌ Fallo de negociación SSH. Detalle:")
            print(clean(child.before + (child.after or "")))
            sys.exit(1)
        elif i in (12, 13, 14, 15, 16):
            print("❌ Fallo de red/SSH. Detalle:")
            print(clean(child.before + (child.after or "")))
            sys.exit(1)
        elif i == 17:
            child.send(" ")
        elif i == 18:
            child.sendline("")
        elif i in (19, 20, 21):
            break
        elif i == 22:
            print("❌ El proceso SSH terminó (EOF) antes de mostrar prompt.")
            print("📌 Salida del ssh:")
            print(clean(child.before))
            sys.exit(1)
        else:
            print("❌ Timeout esperando prompt/login.")
            print(clean(child.before))
            sys.exit(1)

    # refrescar prompt por banners/logs
    child.sendline("")
    pidx = expect_prompt(timeout=20)

    # ---- ENABLE (si aplica) ----
    if not is_privileged(pidx):
        child.sendline("enable")
        k = child.expect([r"[Pp]assword:\s*$", r".*'s password:\s*$", r"#\s*$", r">\s*$", r"\]\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        if k in (0, 1):
            child.sendline(ssh_password)
            child.expect([r"#\s*$", r">\s*$", r"\]\s*$", pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        child.sendline("")
        pidx = expect_prompt(timeout=12)

    if not is_privileged(pidx):
        print("⚠️ No quedé en modo privilegiado (#). Igual intentaré el copy, pero puede fallar por permisos.")

    # paginación off (si existe)
    child.sendline("terminal length 0")
    child.expect(PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=8)

    # ---- COPY ----
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    child.sendline(cmd)

    for _ in range(30):
        j = child.expect([
            r"\(Y/N\)|\[(Y/N)\]|\(y/n\)|\[(y/n)\]|confirm|Are you sure.*\?",
            r"Destination filename.*:\s*$",
            r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
            r"#\s*$",
            r">\s*$",
            r"\]\s*$",
            pexpect.TIMEOUT,
            pexpect.EOF,
        ], timeout=75)

        if j in (4, 5, 6):
            print("✅ Backup finalizado (regresó a prompt).")
            break

        if j == 0:
            child.sendline("Y")
        elif j == 1:
            child.sendline(filename)
        elif j == 2:
            child.sendline(tftp_server)
        elif j == 3:
            print("❌ Error reportado por el switch durante copy:")
            print(clean(child.before))
            sys.exit(1)
        elif j == 8:
            print("❌ EOF durante copy. Salida:")
            print(clean(child.before))
            sys.exit(1)
        else:
            continue
    else:
        print("⚠️ No confirmé fin del copy (no volvió al prompt). Revisa el servidor TFTP y conectividad.")

    child.sendline("exit")
    child.close()
    sys.exit(0)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link: {e}")
    try:
        child.close(force=True)
    except Exception:
        pass
    sys.exit(1)

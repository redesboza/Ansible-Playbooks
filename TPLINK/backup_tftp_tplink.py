#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
from datetime import datetime

"""
TP-Link - Backup startup-config a TFTP (con timeout de progreso)
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

def tcp_ok(ip, p):
    try:
        s = socket.create_connection((ip, p), timeout=5)
        s.close()
        return True
    except:
        return False

print(f"🔎 Precheck TCP {host}:{port} ...")
if not tcp_ok(host, port):
    print(f"❌ No hay conectividad TCP desde EE hacia {host}:{port}")
    sys.exit(1)
print("✅ Puerto accesible desde el Execution Environment.")

print(f"🔐 Conectando a {host}:{port} como {ssh_user} (ssh v2)...")
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}")

PROMPTS = [r"#\s*$", r">\s*$", r"\]\s*$", r"\S+#\s*$", r"\S+>\s*$", r"\S+\]\s*$"]

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

child = pexpect.spawn(ssh_cmd, timeout=25, encoding="utf-8")

def expect_any(patterns, timeout=25):
    child.timeout = timeout
    return child.expect(patterns)

try:
    # --- LOGIN (mismo esquema que ya te funciona) ---
    while True:
        i = expect_any([
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"[Pp]assword:\s*$",
            r".*'s password:\s*$",
        ] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF], timeout=25)

        if i == 0:
            child.sendline("yes")
        elif i in (1, 2):
            child.sendline(ssh_password)
        elif i < 3 + len(PROMPTS):
            break
        elif i == 3 + len(PROMPTS):  # TIMEOUT
            child.sendline("")
            continue
        else:  # EOF
            print("❌ EOF durante login. Salida:")
            print(clean(child.before))
            sys.exit(1)

    # Asentar prompt
    child.sendline("")
    expect_any(PROMPTS, timeout=20)

    # Enable (si no hay #)
    if not re.search(r"#\s*$", child.after or "", re.M):
        child.sendline("enable")
        j = expect_any([r"[Pp]assword:\s*$", r".*'s password:\s*$"] + PROMPTS, timeout=12)
        if j in (0, 1):
            child.sendline(ssh_password)
            expect_any(PROMPTS, timeout=15)

    # Paginación off
    child.sendline("terminal length 0")
    expect_any(PROMPTS + [pexpect.TIMEOUT], timeout=8)

    # --- COPY con control de progreso ---
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}")
    child.sendline(cmd)

    # Si en X segundos no cambia nada, abortamos
    overall_timeout = 120          # total 2 minutos
    no_progress_timeout = 25       # si 25s sin nueva salida -> sospecha TFTP colgado
    last_len = 0

    t0 = datetime.now().timestamp()
    last_progress = datetime.now().timestamp()

    while datetime.now().timestamp() - t0 < overall_timeout:
        k = expect_any([
            r"\(Y/N\)|\[Y/N\]|confirm|Are you sure",
            r"Destination filename.*:\s*$",
            r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
            r"Press any key.*|Press Enter.*",
            r"--More--",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
        ] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF], timeout=8)

        # Capturar buffer para ver si hay avance
        current = (child.before or "") + (child.after or "")
        clen = len(current)

        if clen != last_len:
            last_progress = datetime.now().timestamp()
            last_len = clen

        # Si no hay progreso por X segundos -> colgado
        if datetime.now().timestamp() - last_progress > no_progress_timeout:
            print("❌ COPY parece COLGADO (sin progreso).")
            print("📌 Esto suele ser TFTP bloqueado o esperando respuesta del servidor.")
            print("📌 Última salida vista:")
            print(clean(child.before))
            child.close(force=True)
            sys.exit(1)

        # Volvió a prompt => OK
        if k >= 6 and k < 6 + len(PROMPTS):
            print("✅ Backup finalizado (regresó a prompt).")
            child.sendline("exit")
            child.close()
            sys.exit(0)

        if k == 0:
            child.sendline("Y")
        elif k == 1:
            child.sendline(filename)
        elif k == 2:
            child.sendline(tftp_server)
        elif k == 3:
            child.sendline("")
        elif k == 4:
            child.send(" ")
        elif k == 5:
            print("❌ Error reportado por el switch durante copy:")
            print(clean(child.before))
            child.close(force=True)
            sys.exit(1)
        elif k == 6 + len(PROMPTS) + 1:  # EOF
            print("❌ EOF durante copy. Última salida:")
            print(clean(child.before))
            sys.exit(1)
        # TIMEOUT -> sigue loop

    print("❌ Timeout general ejecutando copy (2 min).")
    print("📌 Última salida:")
    print(clean(child.before))
    child.close(force=True)
    sys.exit(1)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link: {e}")
    try:
        child.close(force=True)
    except:
        pass
    sys.exit(1)

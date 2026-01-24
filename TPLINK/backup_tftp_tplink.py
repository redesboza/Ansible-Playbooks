#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
import time
from datetime import datetime

"""
TP-Link - Backup startup-config a TFTP
- Mantiene autenticación pexpect (la que ya te funcionó)
- Controla cuelgues: timeout total + timeout sin progreso
"""

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

def clean(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", s)

def tcp_ok(ip, p):
    try:
        s = socket.create_connection((ip, int(p)), timeout=5)
        s.close()
        return True
    except:
        return False

PROMPT_PATTERNS = [r"#\s*$", r">\s*$", r"\]\s*$", r"\$\s*$"]  # por si algún modelo raro

def expect_any(child, patterns, timeout=15):
    child.timeout = timeout
    return child.expect(patterns)

print(f"🔎 Precheck TCP {host}:{port} ...", flush=True)
if not tcp_ok(host, port):
    print(f"❌ No hay conectividad TCP desde EE hacia {host}:{port}", flush=True)
    sys.exit(1)
print("✅ Puerto accesible desde el Execution Environment.", flush=True)

print(f"🔐 Conectando a {host}:{port} como {ssh_user}...", flush=True)
print(f"📦 Backup startup-config a TFTP: {tftp_server}  archivo: {filename}", flush=True)

# ✅ Conservamos la autenticación “segura” que ya te funcionó (ssh-rsa + kex)
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
child.delaybeforesend = 0.05

def is_privileged(last_prompt_text: str) -> bool:
    return bool(re.search(r"#\s*$", last_prompt_text or "", re.M))

try:
    # -------------------------
    # LOGIN (MISMA LÓGICA)
    # -------------------------
    while True:
        i = expect_any(child, [
            r"Are you sure you want to continue connecting \(yes/no\)\?",
            r"login as:",
            r"User Name:",
            r"Username:",
            r"[Pp]assword:\s*$",
            r"Press any key.*",
            r"--More--",
        ] + PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=25)

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
        elif i < 7 + len(PROMPT_PATTERNS):
            # llegó a prompt
            break
        elif i == 7 + len(PROMPT_PATTERNS):
            # timeout: mandar enter para “despertar” prompt
            child.sendline("")
            continue
        else:
            print("❌ EOF durante login. Salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)

    # refrescar prompt
    child.sendline("")
    expect_any(child, PROMPT_PATTERNS, timeout=20)

    # enable si no hay #
    last = child.after or ""
    if not is_privileged(last):
        child.sendline("enable")
        j = expect_any(child, [r"[Pp]assword:\s*$"] + PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        if j == 0:
            child.sendline(ssh_password)
            expect_any(child, PROMPT_PATTERNS, timeout=15)

    # paginación off (si existe)
    child.sendline("terminal length 0")
    expect_any(child, PROMPT_PATTERNS + [pexpect.TIMEOUT], timeout=8)

    # -------------------------
    # COPY con control de CUELGUE
    # -------------------------
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}", flush=True)
    child.sendline(cmd)

    overall_timeout = 120        # total máximo
    no_progress_timeout = 20     # si 20s sin nueva salida => abortar

    t0 = time.time()
    last_progress = time.time()
    last_snapshot = ""

    while time.time() - t0 < overall_timeout:
        k = expect_any(child, [
            r"\(Y/N\)|\[Y/N\]|\(y/n\)|\[y/n\]|confirm|Are you sure",
            r"Destination filename.*:\s*$",
            r"Remote host.*:\s*$|Address or name of remote host.*:\s*$",
            r"TFTP.*server.*:\s*$|Server IP.*:\s*$",
            r"Press any key.*|Press Enter.*",
            r"--More--",
            r"%\s*Error|Error:|Invalid|Failed|No such|Timed out|TFTP",
        ] + PROMPT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF], timeout=8)

        snap = (child.before or "") + (child.after or "")
        if snap != last_snapshot:
            last_snapshot = snap
            last_progress = time.time()

        # sin progreso -> típicamente TFTP bloqueado o esperando respuesta
        if time.time() - last_progress > no_progress_timeout:
            print("❌ COPY parece COLGADO (sin progreso).", flush=True)
            print("📌 Esto suele ser TFTP bloqueado/ruta/ACL/firewall o el switch esperando respuesta del servidor.", flush=True)
            print("📌 Última salida:", flush=True)
            print(clean(child.before), flush=True)
            child.close(force=True)
            sys.exit(1)

        # volvió a prompt => OK
        if k >= 7 and k < 7 + len(PROMPT_PATTERNS):
            print("✅ Backup finalizado (regresó a prompt).", flush=True)
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
            child.sendline(tftp_server)
        elif k == 4:
            child.sendline("")
        elif k == 5:
            child.send(" ")
        elif k == 6:
            print("❌ Error reportado por el switch durante copy:", flush=True)
            print(clean(child.before), flush=True)
            child.close(force=True)
            sys.exit(1)
        elif k == 7 + len(PROMPT_PATTERNS) + 1:  # EOF
            print("❌ EOF durante copy. Última salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)
        # TIMEOUT => sigue loop

    print("❌ Timeout general ejecutando copy (120s).", flush=True)
    print("📌 Última salida:", flush=True)
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

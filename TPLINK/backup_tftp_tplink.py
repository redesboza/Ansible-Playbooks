#!/usr/bin/env python3
import pexpect
import sys
import re
import socket
import time
from datetime import datetime

VERSION = "TPLINK_BACKUP_TFTP_INLINE_v2026-01-26_04"

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

# ✅ MISMA autenticación que ya te funciona (NO la cambio)
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

child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=30)
child.delaybeforesend = 0.05

try:
    time.sleep(0.2)
    child.sendline("")

    # -------- LOGIN LOOP --------
    while True:
        i = child.expect(LOGIN_PATTERNS, timeout=30)

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
            break
        elif i == 10:
            child.sendline("")
            continue
        else:
            print("❌ EOF durante login. Salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)

    # refrescar prompt
    child.sendline("")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=10)

    # apagar logs en pantalla si existe
    child.sendline("terminal no monitor")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=6)

    # -------- ENABLE (si aplica) --------
    # Si no estamos en '#', hacemos enable. Muchos TP-Link no piden pass; por si acaso lo soportamos.
    if not re.search(r"#\s*$", child.after or ""):
        child.sendline("enable")
        k = child.expect([r"[Pp]assword:\s*$"] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        if k == 0:
            child.sendline(ssh_password)
            child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=20)

    # quitar paginación (si soporta)
    child.sendline("terminal length 0")
    child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=8)

    # -------- COMANDO EXACTO (inline) --------
    cmd = f"copy startup-config tftp ip-address {tftp_server} filename {filename}"
    print(f"▶️ Ejecutando: {cmd}", flush=True)
    child.sendline(cmd)

    # Esperamos los textos que TU equipo muestra
    patterns = [
        r"Start to backup.*",                  # inicio
        r"Backup user config file OK\.",       # éxito
        r"Backup.*OK\.",                       # éxito alterno
        r"%\s*Error|Error:|Invalid|Failed",     # error
    ] + PROMPTS + [pexpect.TIMEOUT, pexpect.EOF]

    saw_start = False
    saw_ok = False

    t0 = time.time()
    while time.time() - t0 < 120:  # 2 minutos deberían sobrar
        j = child.expect(patterns, timeout=20)

        if j == 0:
            saw_start = True
            continue

        if j in (1, 2):
            saw_ok = True
            # esperamos que vuelva al prompt
            child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=30)
            print("✅ Backup OK (TP-Link confirmó).", flush=True)
            child.sendline("exit")
            child.close()
            sys.exit(0)

        if j == 3:
            print("❌ El equipo reportó error durante el copy:", flush=True)
            print(clean(child.before), flush=True)
            child.close(force=True)
            sys.exit(1)

        # si vuelve a prompt sin OK, igual mostramos debug
        if j in (4, 5, 6):
            if saw_start and not saw_ok:
                print("⚠️ Volvió a prompt pero no vi 'OK'. Salida previa:", flush=True)
                print(clean(child.before), flush=True)
                child.sendline("exit")
                child.close()
                sys.exit(1)
            # si no vimos nada, seguimos un poco más
            continue

        if j == 7:  # TIMEOUT
            child.sendline("")
            continue

        if j == 8:  # EOF
            print("❌ EOF durante copy. Última salida:", flush=True)
            print(clean(child.before), flush=True)
            sys.exit(1)

    print("❌ Timeout general ejecutando copy (120s). Última salida:", flush=True)
    print(clean(child.before), flush=True)
    print(f"DEBUG saw_start={saw_start} saw_ok={saw_ok}", flush=True)
    child.close(force=True)
    sys.exit(1)

except Exception as e:
    print(f"❌ Error ejecutando backup TFTP en TP-Link: {e}", flush=True)
    print("📌 DEBUG before:", flush=True)
    print(clean(getattr(child, "before", "")), flush=True)
    print("📌 DEBUG after:", flush=True)
    print(repr(getattr(child, "after", "")), flush=True)
    try:
        child.close(force=True)
    except:
        pass
    sys.exit(1)
